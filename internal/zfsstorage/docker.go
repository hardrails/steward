package zfsstorage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/hardrails/steward/internal/dsse"
)

const maxDockerResponseBytes = 1 << 20

// bindingNotCreatedError certifies that Ensure failed before sending any create
// request. Other errors are uncertain, regardless of the returned changed flag.
type bindingNotCreatedError struct{ error }

func (err bindingNotCreatedError) Unwrap() error { return err.error }

// DockerBinder exposes a fixed, local-driver named-volume lifecycle over one
// owner-selected Docker Unix socket. Container access is limited to a read-only
// reference check for offline migration; it cannot run containers or images.
type DockerBinder struct{ client *http.Client }

// CheckUnused rejects references from running AND stopped containers. It is a
// point-in-time check: operators must quiesce container creators for maintenance.
func (binder *DockerBinder) CheckUnused(ctx context.Context, handle string) error {
	if !validDockerHandle(handle) {
		return ErrBindingConflict
	}
	filters, err := json.Marshal(map[string][]string{"volume": {handle}})
	if err != nil {
		return err
	}
	query := url.Values{"all": {"1"}, "filters": {string(filters)}}
	status, raw, err := binder.call(ctx, http.MethodGet, "/v1.41/containers/json?"+query.Encode(), nil)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return dockerStatusError(status)
	}
	var containers []json.RawMessage
	if err := json.Unmarshal(raw, &containers); err != nil || containers == nil {
		return errors.New("Docker reference check returned an invalid container list")
	}
	if len(containers) != 0 {
		return ErrBindingInUse
	}
	return nil
}

func NewDockerBinder(socketPath string) (*DockerBinder, error) {
	if socketPath == "" || !filepath.IsAbs(socketPath) || filepath.Clean(socketPath) != socketPath ||
		socketPath == string(filepath.Separator) {
		return nil, errors.New("Docker volume binder requires a clean absolute Unix socket")
	}
	dialer := &net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		Proxy: nil, DisableCompression: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", socketPath)
		},
	}
	return newDockerBinder(&http.Client{
		Transport: transport, Timeout: 15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("Docker volume redirects are disabled")
		},
	}), nil
}

func newDockerBinder(client *http.Client) *DockerBinder { return &DockerBinder{client: client} }

// Ensure reports a newly created binding only after verification. An error with
// false does not prove that Docker did not commit: callers must retain the source
// dataset until exact replay or explicit, verified deletion resolves the binding.
// Only bindingNotCreatedError proves this invocation could not create a binding.
func (binder *DockerBinder) Ensure(ctx context.Context, binding Binding) (bool, error) {
	if err := validateBinding(binding); err != nil {
		return false, bindingNotCreatedError{err}
	}
	if existing, err := binder.Inspect(ctx, binding.Handle); err == nil {
		if !sameBinding(existing, binding) {
			return false, bindingNotCreatedError{ErrBindingConflict}
		}
		return false, nil
	} else if !errors.Is(err, ErrBindingNotFound) {
		return false, bindingNotCreatedError{err}
	}
	body, err := json.Marshal(struct {
		Name       string            `json:"Name"`
		Driver     string            `json:"Driver"`
		DriverOpts map[string]string `json:"DriverOpts"`
		Labels     map[string]string `json:"Labels"`
	}{
		Name: binding.Handle, Driver: "local",
		DriverOpts: map[string]string{"type": "none", "o": "bind", "device": binding.Source},
		Labels:     cloneStringMap(binding.Labels),
	})
	if err != nil {
		return false, bindingNotCreatedError{err}
	}
	status, _, err := binder.call(ctx, http.MethodPost, "/v1.41/volumes/create", body)
	if err != nil {
		return false, err
	}
	if status != http.StatusCreated {
		return false, dockerStatusError(status)
	}
	observed, err := binder.Inspect(ctx, binding.Handle)
	if err != nil {
		return false, err
	}
	if !sameBinding(observed, binding) {
		return false, ErrBindingConflict
	}
	return true, nil
}

func (binder *DockerBinder) Inspect(ctx context.Context, handle string) (Binding, error) {
	if !validDockerHandle(handle) {
		return Binding{}, ErrBindingConflict
	}
	status, raw, err := binder.call(ctx, http.MethodGet, "/v1.41/volumes/"+url.PathEscape(handle), nil)
	if err != nil {
		return Binding{}, err
	}
	if status == http.StatusNotFound {
		return Binding{}, ErrBindingNotFound
	}
	if status != http.StatusOK {
		return Binding{}, dockerStatusError(status)
	}
	var response struct {
		Name       string                     `json:"Name"`
		Driver     string                     `json:"Driver"`
		Mountpoint string                     `json:"Mountpoint"`
		CreatedAt  string                     `json:"CreatedAt"`
		Scope      string                     `json:"Scope"`
		Status     map[string]json.RawMessage `json:"Status"`
		Labels     json.RawMessage            `json:"Labels"`
		Options    json.RawMessage            `json:"Options"`
		UsageData  *struct {
			Size     int64 `json:"Size"`
			RefCount int64 `json:"RefCount"`
		} `json:"UsageData"`
	}
	// Decode the complete Engine v1.41 Volume shape. Daemon metadata does not
	// choose a source path: the exact local bind still comes from Options.device.
	if err := dsse.DecodeStrictInto(raw, maxDockerResponseBytes, &response); err != nil ||
		response.Driver != "local" || response.Scope != "local" ||
		!filepath.IsAbs(response.Mountpoint) || filepath.Clean(response.Mountpoint) != response.Mountpoint ||
		response.Mountpoint == "/" || len(response.Mountpoint) > 4096 || strings.ContainsRune(response.Mountpoint, '\x00') {
		return Binding{}, ErrBindingConflict
	}
	options, err := decodeStringMap(response.Options, 8)
	if err != nil || options["type"] != "none" || options["o"] != "bind" || len(options) != 3 {
		return Binding{}, ErrBindingConflict
	}
	labels, err := decodeStringMap(response.Labels, 16)
	if err != nil {
		return Binding{}, ErrBindingConflict
	}
	binding := Binding{Handle: response.Name, Source: options["device"], Labels: labels}
	if err := validateBinding(binding); err != nil || binding.Handle != handle {
		return Binding{}, ErrBindingConflict
	}
	return binding, nil
}

func (binder *DockerBinder) Delete(ctx context.Context, handle string) (bool, error) {
	if !validDockerHandle(handle) {
		return false, ErrBindingConflict
	}
	status, _, err := binder.call(ctx, http.MethodDelete, "/v1.41/volumes/"+url.PathEscape(handle), nil)
	if err != nil {
		return false, err
	}
	switch status {
	case http.StatusNoContent:
		return true, nil
	case http.StatusNotFound:
		return false, ErrBindingNotFound
	case http.StatusConflict:
		return false, ErrBindingInUse
	default:
		return false, dockerStatusError(status)
	}
}

func (binder *DockerBinder) call(ctx context.Context, method, path string, body []byte) (int, []byte, error) {
	if binder == nil || binder.client == nil || ctx == nil {
		return 0, nil, errors.New("Docker volume binder is not configured")
	}
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	request, err := http.NewRequestWithContext(ctx, method, "http://docker"+path, reader)
	if err != nil {
		return 0, nil, err
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Accept-Encoding", "identity")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := binder.client.Do(request)
	if err != nil {
		return 0, nil, err
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxDockerResponseBytes+1))
	if err != nil {
		return 0, nil, err
	}
	if len(raw) > maxDockerResponseBytes {
		return 0, nil, errors.New("Docker volume response exceeds 1 MiB")
	}
	return response.StatusCode, raw, nil
}

func validateBinding(binding Binding) error {
	if !validDockerHandle(binding.Handle) || binding.Source == "" || !filepath.IsAbs(binding.Source) ||
		filepath.Clean(binding.Source) != binding.Source || binding.Source == string(filepath.Separator) ||
		len(binding.Labels) != 2 {
		return ErrBindingConflict
	}
	for key, value := range binding.Labels {
		if key == "" || value == "" || len(key) > 128 || len(value) > 256 || !utf8.ValidString(key) || !utf8.ValidString(value) ||
			strings.ContainsAny(key, "\x00\r\n") || strings.ContainsAny(value, "\x00\r\n") {
			return ErrBindingConflict
		}
	}
	return nil
}

func validDockerHandle(value string) bool {
	if len(value) < 2 || len(value) > 128 || !utf8.ValidString(value) {
		return false
	}
	for _, char := range value {
		if char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' ||
			char == '.' || char == '_' || char == '-' {
			continue
		}
		return false
	}
	return true
}

func sameBinding(left, right Binding) bool {
	return left.Handle == right.Handle && left.Source == right.Source && equalLabels(left.Labels, right.Labels)
}

func cloneStringMap(input map[string]string) map[string]string {
	output := make(map[string]string, len(input))
	for key, value := range input {
		output[key] = value
	}
	return output
}

func dockerStatusError(status int) error {
	return fmt.Errorf("Docker volume API returned HTTP %d", status)
}

func decodeStringMap(raw []byte, maximum int) (map[string]string, error) {
	if len(raw) == 0 || len(raw) > maxDockerResponseBytes || maximum <= 0 {
		return nil, errors.New("invalid bounded string map")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, errors.New("string map must be an object")
	}
	result := make(map[string]string)
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		key, ok := keyToken.(string)
		if !ok || key == "" {
			return nil, errors.New("string map key is invalid")
		}
		if _, duplicate := result[key]; duplicate {
			return nil, errors.New("string map contains a duplicate key")
		}
		valueToken, err := decoder.Token()
		value, ok := valueToken.(string)
		if err != nil || !ok {
			return nil, errors.New("string map value is invalid")
		}
		result[key] = value
		if len(result) > maximum {
			return nil, errors.New("string map exceeds its entry limit")
		}
	}
	if token, err = decoder.Token(); err != nil || token != json.Delim('}') {
		return nil, errors.New("string map is unterminated")
	}
	if token, err = decoder.Token(); !errors.Is(err, io.EOF) || token != nil {
		return nil, errors.New("string map contains trailing data")
	}
	return result, nil
}
