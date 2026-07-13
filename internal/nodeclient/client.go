// Package nodeclient is the bounded loopback client shared by stewardctl and
// steward-mcp. It deliberately drives the public Executor API rather than
// creating another lifecycle implementation.
package nodeclient

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/securefile"
)

const maxWireBytes = 1 << 20

type Client struct {
	baseURL string
	token   string
	http    *http.Client
}

type State struct {
	RuntimeRef        string          `json:"runtime_ref"`
	Status            string          `json:"status"`
	CapsuleDigest     string          `json:"capsule_digest,omitempty"`
	PolicyDigest      string          `json:"policy_digest,omitempty"`
	Generation        uint64          `json:"generation,omitempty"`
	EvidenceKeyID     string          `json:"evidence_key_id,omitempty"`
	GrantID           string          `json:"grant_id,omitempty"`
	ServicePath       string          `json:"service_path,omitempty"`
	ServiceID         string          `json:"service_id,omitempty"`
	TaskAuthorities   []TaskAuthority `json:"task_authorities,omitempty"`
	Logs              string          `json:"logs,omitempty"`
	EgressProxy       string          `json:"egress_proxy,omitempty"`
	EgressRouteIDs    []string        `json:"egress_route_ids,omitempty"`
	ConnectorURL      string          `json:"connector_url,omitempty"`
	ConnectorIDs      []string        `json:"connector_ids,omitempty"`
	RoutePolicyDigest string          `json:"route_policy_digest,omitempty"`
}

// TaskAuthority is the public half of a tenant task-signing key returned by
// Executor. It is duplicated here to keep the bounded loopback client below
// Gateway in the package graph; Gateway already uses nodeclient for safe file
// reads and importing Gateway here would create a cycle.
type TaskAuthority struct {
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key"`
}

type EgressStats struct {
	Allowed         uint64 `json:"allowed"`
	Denied          uint64 `json:"denied"`
	BytesFromAgent  uint64 `json:"bytes_from_agent"`
	BytesToAgent    uint64 `json:"bytes_to_agent"`
	LastDestination string `json:"last_destination,omitempty"`
	LastDecision    string `json:"last_decision,omitempty"`
	LastObservedAt  string `json:"last_observed_at,omitempty"`
}

type StatePurge struct {
	TenantID   string `json:"tenant_id"`
	NodeID     string `json:"node_id"`
	LineageID  string `json:"lineage_id"`
	Generation uint64 `json:"generation"`
}

type APIError struct {
	Status  int
	Code    string
	Message string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("executor HTTP %d %s: %s", e.Status, e.Code, e.Message)
}

func New(baseURL, token string) (*Client, error) {
	parsed, err := url.Parse(baseURL)
	if err != nil || parsed.Scheme != "http" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "" {
		return nil, errors.New("node URL must be an HTTP loopback origin with no path")
	}
	host := parsed.Hostname()
	if host != "localhost" {
		address := net.ParseIP(host)
		if address == nil || !address.IsLoopback() {
			return nil, errors.New("node URL must resolve syntactically to localhost or a loopback IP")
		}
	}
	if parsed.Port() == "" {
		return nil, errors.New("node URL must include an explicit port")
	}
	if strings.TrimSpace(token) == "" || len(token) > 4096 {
		return nil, errors.New("node token must be non-empty and at most 4096 bytes")
	}
	transport := &http.Transport{
		Proxy: nil,
		DialContext: (&net.Dialer{
			Timeout: 3 * time.Second,
		}).DialContext,
		DisableCompression: true,
	}
	return &Client{
		baseURL: strings.TrimSuffix(baseURL, "/"), token: token,
		http: &http.Client{Transport: transport, Timeout: 30 * time.Second},
	}, nil
}

func NewFromTokenFile(baseURL, tokenPath string) (*Client, error) {
	token, err := ReadToken(tokenPath)
	if err != nil {
		return nil, err
	}
	return New(baseURL, token)
}

func (c *Client) Admit(ctx context.Context, capsule []byte, intent admission.InstanceIntent) (State, error) {
	if len(capsule) == 0 || len(capsule) > maxWireBytes/2 {
		return State{}, errors.New("capsule is empty or exceeds 512 KiB")
	}
	body := struct {
		Capsule string                   `json:"capsule_dsse_base64"`
		Intent  admission.InstanceIntent `json:"intent"`
	}{Capsule: base64.StdEncoding.EncodeToString(capsule), Intent: intent}
	var state State
	if err := c.do(ctx, http.MethodPost, "/v1/admissions", body, &state); err != nil {
		return State{}, err
	}
	return state, nil
}

func (c *Client) Status(ctx context.Context, runtimeRef string) (State, error) {
	var state State
	if err := c.do(ctx, http.MethodGet, "/v1/workloads/"+runtimeRef, nil, &state); err != nil {
		return State{}, err
	}
	return state, nil
}

func (c *Client) Logs(ctx context.Context, runtimeRef string) (State, error) {
	var state State
	if err := c.do(ctx, http.MethodGet, "/v1/workloads/"+runtimeRef+"/logs", nil, &state); err != nil {
		return State{}, err
	}
	return state, nil
}

func (c *Client) EgressStats(ctx context.Context, runtimeRef string) (EgressStats, error) {
	var stats EgressStats
	if err := c.do(ctx, http.MethodGet, "/v1/workloads/"+runtimeRef+"/egress", nil, &stats); err != nil {
		return EgressStats{}, err
	}
	return stats, nil
}

func (c *Client) Start(ctx context.Context, runtimeRef string) (State, error) {
	var state State
	if err := c.do(ctx, http.MethodPost, "/v1/workloads/"+runtimeRef+"/start", nil, &state); err != nil {
		return State{}, err
	}
	return state, nil
}

func (c *Client) Stop(ctx context.Context, runtimeRef string) (State, error) {
	var state State
	if err := c.do(ctx, http.MethodPost, "/v1/workloads/"+runtimeRef+"/stop", nil, &state); err != nil {
		return State{}, err
	}
	return state, nil
}

func (c *Client) Destroy(ctx context.Context, runtimeRef string) error {
	return c.do(ctx, http.MethodDelete, "/v1/workloads/"+runtimeRef, nil, nil)
}

func (c *Client) PurgeState(ctx context.Context, request StatePurge) error {
	return c.do(ctx, http.MethodPost, "/v1/state/purge", request, nil)
}

func (c *Client) do(ctx context.Context, method, path string, body, output any) error {
	if !validRuntimePath(path) {
		return errors.New("invalid node API path")
	}
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		if len(raw) > maxWireBytes {
			return errors.New("node request exceeds 1 MiB")
		}
		reader = bytes.NewReader(raw)
	}
	request, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := c.http.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxWireBytes+1))
	if err != nil {
		return err
	}
	if len(raw) > maxWireBytes {
		return errors.New("node response exceeds 1 MiB")
	}
	if response.StatusCode >= 400 {
		var payload struct {
			Code    string `json:"error"`
			Message string `json:"message"`
		}
		if json.Unmarshal(raw, &payload) != nil || payload.Code == "" || payload.Message == "" {
			return &APIError{Status: response.StatusCode, Code: "invalid_error", Message: "node returned an invalid error response"}
		}
		return &APIError{Status: response.StatusCode, Code: payload.Code, Message: payload.Message}
	}
	if output == nil {
		if response.StatusCode != http.StatusNoContent && len(bytes.TrimSpace(raw)) != 0 {
			return errors.New("node returned an unexpected response body")
		}
		return nil
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return fmt.Errorf("decode node response: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("node response contains multiple JSON values")
	}
	return nil
}

func ReadToken(path string) (string, error) {
	raw, err := securefile.Read(path, 4096, securefile.OwnerOnly)
	if err != nil {
		return "", err
	}
	token := strings.TrimSpace(string(raw))
	if token == "" {
		return "", errors.New("node token must not be empty")
	}
	for index := 0; index < len(token); index++ {
		if token[index] < 0x21 || token[index] > 0x7e {
			return "", errors.New("node token must contain only visible ASCII without internal whitespace")
		}
	}
	return token, nil
}

func ReadBounded(path string, limit int64) ([]byte, error) {
	return securefile.Read(path, limit, securefile.Regular)
}

func validRuntimePath(path string) bool {
	if path == "/v1/admissions" || path == "/v1/state/purge" {
		return true
	}
	const prefix = "/v1/workloads/executor-"
	if !strings.HasPrefix(path, prefix) {
		return false
	}
	rest := strings.TrimPrefix(path, prefix)
	if separator := strings.IndexByte(rest, '/'); separator >= 0 {
		suffix := rest[separator:]
		if suffix != "/start" && suffix != "/stop" && suffix != "/logs" && suffix != "/egress" {
			return false
		}
		rest = rest[:separator]
	}
	if len(rest) != 64 {
		return false
	}
	for _, char := range rest {
		if char < '0' || char > '9' && char < 'a' || char > 'f' {
			return false
		}
	}
	return true
}
