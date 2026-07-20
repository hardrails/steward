package storagebackend

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/hardrails/steward/internal/dsse"
)

type Client struct {
	baseURL string
	token   string
	http    *http.Client
}

type APIError struct {
	Status  int
	Code    string
	Message string
}

func (err *APIError) Error() string {
	return fmt.Sprintf("storage backend HTTP %d %s: %s", err.Status, err.Code, err.Message)
}

func (err *APIError) Is(target error) bool {
	switch err.Code {
	case "invalid_request":
		return target == ErrInvalid
	case "not_found":
		return target == ErrNotFound
	case "conflict":
		return target == ErrConflict
	case "in_use":
		return target == ErrInUse
	case "capacity_exceeded":
		return target == ErrCapacity
	case "unsupported":
		return target == ErrUnsupported
	case "unavailable":
		return target == ErrUnavailable
	default:
		return false
	}
}

// NewUnixClient creates a bounded HTTP client for one owner-selected Unix
// socket. HTTP redirects and ambient proxy configuration are disabled so the
// local bearer cannot be forwarded to another endpoint.
func NewUnixClient(socketPath, token string) (*Client, error) {
	if socketPath == "" || !filepath.IsAbs(socketPath) || filepath.Clean(socketPath) != socketPath ||
		socketPath == string(filepath.Separator) || !validToken(token) {
		return nil, errors.New("storage backend client requires a clean absolute socket and bounded bearer")
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", socketPath)
		},
		DisableCompression: true,
	}
	return newClient("http://steward-storage", token, &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("storage backend redirects are disabled")
		},
	}), nil
}

func newClient(baseURL, token string, httpClient *http.Client) *Client {
	return &Client{baseURL: strings.TrimSuffix(baseURL, "/"), token: token, http: httpClient}
}

func (client *Client) Capabilities(ctx context.Context) (Capabilities, error) {
	var result Capabilities
	if err := client.call(ctx, http.MethodGet, "/v1/capabilities", nil, &result); err != nil {
		return Capabilities{}, err
	}
	if err := result.Validate(); err != nil {
		return Capabilities{}, errors.New("storage backend capabilities response is invalid")
	}
	return result, nil
}

func (client *Client) InspectVolume(ctx context.Context, scope VolumeScope) (Volume, error) {
	if err := scope.Validate(); err != nil {
		return Volume{}, err
	}
	var result Volume
	if err := client.call(ctx, http.MethodPost, "/v1/volumes/inspect", scope, &result); err != nil {
		return Volume{}, err
	}
	if err := result.Validate(); err != nil || result.Scope() != scope {
		return Volume{}, errors.New("storage backend volume response is invalid or out of scope")
	}
	return result, nil
}

func (client *Client) CreateVolume(ctx context.Context, request CreateVolumeRequest) (Volume, bool, error) {
	if err := request.Validate(); err != nil {
		return Volume{}, false, err
	}
	return client.volumeMutation(ctx, "/v1/volumes/create", request, request.Volume.Scope())
}

func (client *Client) DeleteVolume(ctx context.Context, request DeleteVolumeRequest) (Volume, bool, error) {
	if err := request.Validate(); err != nil {
		return Volume{}, false, err
	}
	return client.volumeMutation(ctx, "/v1/volumes/delete", request, request.Volume)
}

func (client *Client) InspectSnapshot(ctx context.Context, scope SnapshotScope) (Snapshot, error) {
	if err := scope.Validate(); err != nil {
		return Snapshot{}, err
	}
	var result Snapshot
	if err := client.call(ctx, http.MethodPost, "/v1/snapshots/inspect", scope, &result); err != nil {
		return Snapshot{}, err
	}
	if err := result.Validate(); err != nil || result.Scope() != scope {
		return Snapshot{}, errors.New("storage backend snapshot response is invalid or out of scope")
	}
	return result, nil
}

func (client *Client) CreateSnapshot(ctx context.Context, request CreateSnapshotRequest) (Snapshot, bool, error) {
	if err := request.Validate(); err != nil {
		return Snapshot{}, false, err
	}
	var response mutationResponse
	if err := client.call(ctx, http.MethodPost, "/v1/snapshots/create", request, &response); err != nil {
		return Snapshot{}, false, err
	}
	if response.Snapshot == nil || response.Volume != nil || response.Snapshot.Validate() != nil ||
		response.Snapshot.Scope() != (SnapshotScope{
			SnapshotID: request.SnapshotID, TenantID: request.Source.TenantID,
			SourceVolumeID: request.Source.VolumeID, SourceLineageID: request.Source.LineageID,
			Generation: request.Source.Generation,
		}) {
		return Snapshot{}, false, errors.New("storage backend snapshot mutation response is invalid or out of scope")
	}
	return *response.Snapshot, response.Changed, nil
}

func (client *Client) CloneVolume(ctx context.Context, request CloneVolumeRequest) (Volume, bool, error) {
	if err := request.Validate(); err != nil {
		return Volume{}, false, err
	}
	return client.volumeMutation(ctx, "/v1/snapshots/clone", request, request.Volume.Scope())
}

func (client *Client) DeleteSnapshot(ctx context.Context, request DeleteSnapshotRequest) (Snapshot, bool, error) {
	if err := request.Validate(); err != nil {
		return Snapshot{}, false, err
	}
	var response mutationResponse
	if err := client.call(ctx, http.MethodPost, "/v1/snapshots/delete", request, &response); err != nil {
		return Snapshot{}, false, err
	}
	if response.Snapshot == nil || response.Volume != nil || response.Snapshot.Validate() != nil ||
		response.Snapshot.Scope() != request.Snapshot {
		return Snapshot{}, false, errors.New("storage backend snapshot mutation response is invalid or out of scope")
	}
	return *response.Snapshot, response.Changed, nil
}

func (client *Client) volumeMutation(ctx context.Context, path string, request any, scope VolumeScope) (Volume, bool, error) {
	var response mutationResponse
	if err := client.call(ctx, http.MethodPost, path, request, &response); err != nil {
		return Volume{}, false, err
	}
	if response.Volume == nil || response.Snapshot != nil || response.Volume.Validate() != nil ||
		response.Volume.Scope() != scope {
		return Volume{}, false, errors.New("storage backend volume mutation response is invalid or out of scope")
	}
	return *response.Volume, response.Changed, nil
}

func (client *Client) call(ctx context.Context, method, path string, input, output any) error {
	var body io.Reader
	if input != nil {
		raw, err := json.Marshal(input)
		if err != nil {
			return err
		}
		if len(raw) > MaxWireBytes {
			return errors.New("storage backend request exceeds 64 KiB")
		}
		body = bytes.NewReader(raw)
	}
	request, err := http.NewRequestWithContext(ctx, method, client.baseURL+path, body)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+client.token)
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Accept-Encoding", "identity")
	if input != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := client.http.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	mediaType, _, mediaErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if mediaErr != nil || mediaType != "application/json" {
		return errors.New("storage backend response does not use application/json")
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, MaxWireBytes+1))
	if err != nil {
		return err
	}
	if len(raw) > MaxWireBytes {
		return errors.New("storage backend response exceeds 64 KiB")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		var failure wireError
		if err := dsse.DecodeStrictInto(raw, MaxWireBytes, &failure); err != nil ||
			failure.Error == "" || failure.Message == "" {
			return fmt.Errorf("storage backend HTTP %d returned an invalid error", response.StatusCode)
		}
		return &APIError{Status: response.StatusCode, Code: failure.Error, Message: failure.Message}
	}
	if err := dsse.DecodeStrictInto(raw, MaxWireBytes, output); err != nil {
		return errors.New("storage backend response is invalid")
	}
	return nil
}
