package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/nodeclient"
	"github.com/hardrails/steward/internal/securefile"
	"github.com/hardrails/steward/internal/taskpermit"
)

const maxHermesResponseHeaders = 64 << 10

var hermesRunIDPattern = regexp.MustCompile(`^run_[a-f0-9]{32}$`)

type hermesClient struct {
	baseURL string
	token   string
	http    *http.Client
}

func hermesCommand(arguments []string, stdout io.Writer) error {
	if len(arguments) == 0 || arguments[0] != "run" {
		return errors.New("hermes command requires run")
	}
	flags := flag.NewFlagSet("hermes run", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	bundlePath := flags.String("bundle", "", "owner-only signed task bundle")
	gatewayURL := flags.String("gateway-url", "", "HTTP literal-loopback Gateway origin")
	tokenPath := flags.String("token-file", "", "owner-only Gateway bearer token")
	wait := flags.Bool("wait", false, "poll the qualified Hermes run endpoint to a terminal state")
	waitTimeout := flags.Duration("wait-timeout", 3*time.Minute, "bounded total wait time")
	pollInterval := flags.Duration("poll-interval", time.Second, "bounded status poll interval")
	if err := flags.Parse(arguments[1:]); err != nil {
		return err
	}
	if *bundlePath == "" || *gatewayURL == "" || *tokenPath == "" || flags.NArg() != 0 {
		return errors.New("hermes run requires -bundle, -gateway-url, and -token-file")
	}
	if !*wait && (flagWasVisited(flags, "wait-timeout") || flagWasVisited(flags, "poll-interval")) {
		return errors.New("-wait-timeout and -poll-interval require -wait")
	}
	if *waitTimeout < 100*time.Millisecond || *waitTimeout > 15*time.Minute {
		return errors.New("Hermes wait timeout must be from 100ms through 15m")
	}
	if *pollInterval < 10*time.Millisecond || *pollInterval > 10*time.Second || *pollInterval >= *waitTimeout {
		return errors.New("Hermes poll interval must be from 10ms through 10s and shorter than the wait timeout")
	}

	// Decode once to obtain the non-secret embedded key. Gateway independently
	// checks that key against the active, signed grant; this local check only
	// rejects a corrupt bundle before sending its one authorized request.
	raw, wire, err := readEmbeddedTaskBundle(*bundlePath)
	if err != nil {
		return err
	}
	publicRaw, err := base64.StdEncoding.DecodeString(wire.Authority.PublicKey)
	if err != nil || len(publicRaw) != ed25519.PublicKeySize || base64.StdEncoding.EncodeToString(publicRaw) != wire.Authority.PublicKey {
		return errors.New("task bundle contains an invalid embedded authority")
	}
	verified, err := decodeTaskBundle(raw, map[string]ed25519.PublicKey{wire.Authority.KeyID: ed25519.PublicKey(publicRaw)},
		timeNow().UTC(), taskpermit.MaxValidity)
	if err != nil {
		return fmt.Errorf("validate task bundle: %w", err)
	}
	if verified.Bundle.Operation.ServiceID != "hermes-api" || verified.Bundle.Operation.ID != "hermes.run" ||
		verified.Bundle.Operation.Method != http.MethodPost || verified.Bundle.Operation.Path != "/v1/runs" {
		return errors.New("task bundle does not select the qualified Hermes run operation")
	}
	client, err := newHermesClient(*gatewayURL, *tokenPath)
	if err != nil {
		return err
	}
	dispatchContext, cancel := context.WithTimeout(context.Background(), time.Duration(verified.Bundle.Operation.MaxSeconds)*time.Second)
	defer cancel()
	runID, responseRaw, err := client.dispatch(dispatchContext, verified)
	if err != nil {
		return err
	}
	if !*wait {
		_, err = stdout.Write(append(responseRaw, '\n'))
		return err
	}
	waitContext, waitCancel := context.WithTimeout(context.Background(), *waitTimeout)
	defer waitCancel()
	terminal, status, err := client.wait(waitContext, verified.Bundle.ServicePath, runID,
		verified.Bundle.Operation.MaxResponseBytes, *pollInterval)
	if err != nil {
		return err
	}
	if _, err := stdout.Write(append(terminal, '\n')); err != nil {
		return err
	}
	if status == "failed" || status == "cancelled" {
		return fmt.Errorf("Hermes run %s ended with status %s", runID, status)
	}
	return nil
}

func readEmbeddedTaskBundle(path string) ([]byte, taskBundle, error) {
	raw, err := secureReadOwnerOnly(path, maxTaskBundleBytes)
	if err != nil {
		return nil, taskBundle{}, fmt.Errorf("read task bundle: %w", err)
	}
	var bundle taskBundle
	if err := dsse.DecodeStrictInto(raw, maxTaskBundleBytes, &bundle); err != nil {
		return nil, taskBundle{}, fmt.Errorf("decode task bundle: %w", err)
	}
	return raw, bundle, nil
}

func secureReadOwnerOnly(path string, maximum int64) ([]byte, error) {
	return securefile.Read(path, maximum, securefile.OwnerOnly)
}

func newHermesClient(baseURL, tokenPath string) (*hermesClient, error) {
	parsed, err := url.Parse(baseURL)
	if err != nil || parsed.Scheme != "http" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" ||
		parsed.Path != "" || parsed.Hostname() == "" || parsed.Port() == "" {
		return nil, errors.New("Gateway URL must be an HTTP literal-loopback origin with an explicit port and no path")
	}
	address := net.ParseIP(parsed.Hostname())
	if address == nil || !address.IsLoopback() {
		return nil, errors.New("Gateway URL must use a literal loopback IP address")
	}
	token, err := nodeclient.ReadToken(tokenPath)
	if err != nil {
		return nil, fmt.Errorf("read Gateway token: %w", err)
	}
	transport := &http.Transport{
		Proxy: nil, DialContext: (&net.Dialer{Timeout: 3 * time.Second}).DialContext,
		DisableCompression: true, MaxResponseHeaderBytes: maxHermesResponseHeaders,
		ResponseHeaderTimeout: 2 * time.Minute,
	}
	return &hermesClient{
		baseURL: strings.TrimSuffix(baseURL, "/"), token: token,
		http: &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}},
	}, nil
}

func (client *hermesClient) dispatch(ctx context.Context, bundle verifiedTaskBundle) (string, []byte, error) {
	header, err := taskpermit.EncodeHeader(bundle.Permit)
	if err != nil {
		return "", nil, err
	}
	target := client.baseURL + strings.TrimSuffix(bundle.Bundle.ServicePath, "/") + bundle.Bundle.Operation.Path
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(bundle.Request))
	if err != nil {
		return "", nil, err
	}
	request.ContentLength = int64(len(bundle.Request))
	request.Header = http.Header{
		"Accept":                {"application/json"},
		"Accept-Encoding":       {"identity"},
		"Authorization":         {"Bearer " + client.token},
		"Content-Type":          {bundle.Bundle.Operation.ContentType},
		"User-Agent":            {"stewardctl"},
		"X-Steward-Task-Permit": {header},
	}
	response, raw, err := client.do(request, bundle.Bundle.Operation.MaxResponseBytes)
	if err != nil {
		return "", nil, err
	}
	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusCreated && response.StatusCode != http.StatusAccepted {
		return "", nil, hermesAPIError(response.StatusCode, raw)
	}
	if !exactJSONContentType(response.Header) || response.Header.Values("X-Steward-Task-Receipt") == nil ||
		len(response.Header.Values("X-Steward-Task-Receipt")) != 1 ||
		(response.Header.Get("X-Steward-Task-Receipt") != "recorded" && response.Header.Get("X-Steward-Task-Receipt") != "replayed") ||
		len(response.Header.Values("X-Steward-Service-Grant")) != 1 || response.Header.Get("X-Steward-Service-Grant") != "active" {
		return "", nil, errors.New("Gateway returned an invalid task receipt response")
	}
	var result struct {
		RunID string `json:"run_id"`
	}
	if err := dsse.DecodeStrictInto(raw, int(bundle.Bundle.Operation.MaxResponseBytes), &result); err != nil ||
		!hermesRunIDPattern.MatchString(result.RunID) {
		return "", nil, errors.New("Gateway returned an invalid Hermes run ID")
	}
	return result.RunID, raw, nil
}

func (client *hermesClient) wait(ctx context.Context, servicePath, runID string, maximum int64, interval time.Duration) ([]byte, string, error) {
	target := client.baseURL + strings.TrimSuffix(servicePath, "/") + "/v1/runs/" + runID
	for {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			return nil, "", err
		}
		request.Header = http.Header{
			"Accept":          {"application/json"},
			"Accept-Encoding": {"identity"},
			"Authorization":   {"Bearer " + client.token},
			"User-Agent":      {"stewardctl"},
		}
		response, raw, err := client.do(request, maximum)
		if err != nil {
			return nil, "", err
		}
		if response.StatusCode != http.StatusOK {
			return nil, "", hermesAPIError(response.StatusCode, raw)
		}
		if !jsonContentType(response.Header) {
			return nil, "", errors.New("Hermes status response is not application/json")
		}
		status, err := hermesStatus(raw, int(maximum), runID)
		if err != nil {
			return nil, "", err
		}
		switch status {
		case "completed", "failed", "cancelled":
			return raw, status, nil
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, "", fmt.Errorf("wait for Hermes run %s: %w", runID, ctx.Err())
		case <-timer.C:
		}
	}
}

func (client *hermesClient) do(request *http.Request, maximum int64) (*http.Response, []byte, error) {
	if maximum < 1 || maximum > maxTaskResponseBytes {
		return nil, nil, errors.New("invalid Hermes response limit")
	}
	response, err := client.http.Do(request)
	if err != nil {
		return nil, nil, err
	}
	defer response.Body.Close()
	encodings := response.Header.Values("Content-Encoding")
	if response.ContentLength > maximum || len(encodings) > 1 ||
		len(encodings) == 1 && !strings.EqualFold(strings.TrimSpace(encodings[0]), "identity") {
		return nil, nil, errors.New("Hermes response encoding or length is outside the bundle policy")
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, maximum+1))
	if err != nil || int64(len(raw)) > maximum {
		return nil, nil, errors.New("Hermes response exceeds the bundle policy")
	}
	return response, raw, nil
}

func hermesStatus(raw []byte, maximum int, expectedRunID string) (string, error) {
	wrapper := make([]byte, 0, len(raw)+10)
	wrapper = append(wrapper, `{"value":`...)
	wrapper = append(wrapper, raw...)
	wrapper = append(wrapper, '}')
	var decoded struct {
		Value json.RawMessage `json:"value"`
	}
	if err := dsse.DecodeStrictInto(wrapper, maximum+10, &decoded); err != nil {
		return "", errors.New("Hermes status response is invalid or ambiguous JSON")
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(decoded.Value, &object); err != nil || object == nil {
		return "", errors.New("Hermes status response is not a JSON object")
	}
	var runID string
	if err := json.Unmarshal(object["run_id"], &runID); err != nil || runID != expectedRunID ||
		!hermesRunIDPattern.MatchString(runID) {
		return "", errors.New("Hermes status response does not match the dispatched run ID")
	}
	var status string
	if err := json.Unmarshal(object["status"], &status); err != nil || !taskIdentifier(status) {
		return "", errors.New("Hermes status response has no bounded status")
	}
	switch status {
	case "queued", "running", "completed", "failed", "cancelled":
		return status, nil
	default:
		return "", fmt.Errorf("Hermes status response has unsupported status %q", status)
	}
}

func exactJSONContentType(header http.Header) bool {
	return len(header.Values("Content-Type")) == 1 && header.Get("Content-Type") == "application/json"
}

func jsonContentType(header http.Header) bool {
	values := header.Values("Content-Type")
	if len(values) != 1 {
		return false
	}
	mediaType, _, err := mime.ParseMediaType(values[0])
	return err == nil && mediaType == "application/json"
}

func hermesAPIError(status int, raw []byte) error {
	var payload struct {
		Code    string `json:"error"`
		Message string `json:"message"`
	}
	if err := dsse.DecodeStrictInto(raw, int(maxTaskResponseBytes), &payload); err != nil ||
		!taskIdentifier(payload.Code) || len(payload.Message) == 0 || len(payload.Message) > 4096 || containsTerminalControl(payload.Message) {
		return fmt.Errorf("Gateway HTTP %d returned an invalid error response", status)
	}
	return fmt.Errorf("Gateway HTTP %d %s: %s", status, payload.Code, strconv.QuoteToASCII(payload.Message))
}

func containsTerminalControl(value string) bool {
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return true
		}
	}
	return false
}
