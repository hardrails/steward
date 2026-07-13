// Package controlclient is the bounded HTTPS client shared by stewardctl control
// commands. It accepts plaintext only for literal loopback development targets
// and never follows redirects with an operator or enrollment bearer.
package controlclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
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

	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/securefile"
)

const maxWireBytes = 1 << 20

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

func (e *APIError) Error() string {
	return fmt.Sprintf("control HTTP %d %s: %s", e.Status, e.Code, e.Message)
}

type Tenant struct {
	TenantID string `json:"tenant_id"`
	State    string `json:"state,omitempty"`
	Created  string `json:"created_at,omitempty"`
}

type Enrollment struct {
	EnrollmentID    string   `json:"enrollment_id"`
	EnrollmentToken string   `json:"enrollment_token"`
	NodeID          string   `json:"node_id"`
	TenantIDs       []string `json:"tenant_ids,omitempty"`
	ExpiresAt       string   `json:"expires_at"`
}

// DecodeEnrollmentCapability strictly decodes an enrollment capability read
// from an owner-only file. Strict decoding keeps a secret-bearing file from
// acquiring ambiguous meaning through duplicate or unknown fields.
func DecodeEnrollmentCapability(raw []byte) (Enrollment, error) {
	var enrollment Enrollment
	if err := dsse.DecodeStrictInto(raw, 64<<10, &enrollment); err != nil {
		return Enrollment{}, fmt.Errorf("decode enrollment capability: %w", err)
	}
	if enrollment.EnrollmentID == "" || enrollment.EnrollmentToken == "" || enrollment.NodeID == "" || enrollment.ExpiresAt == "" {
		return Enrollment{}, errors.New("enrollment capability is incomplete")
	}
	return enrollment, nil
}

type NodeCredential struct {
	Version    int    `json:"version"`
	Scope      string `json:"scope,omitempty"`
	TenantID   string `json:"tenant_id,omitempty"`
	NodeID     string `json:"node_id"`
	Credential string `json:"credential"`
}

type Command struct {
	CommandID          string `json:"command_id"`
	DeliveryID         string `json:"delivery_id,omitempty"`
	TenantID           string `json:"tenant_id"`
	NodeID             string `json:"node_id"`
	CommandDigest      string `json:"command_digest"`
	State              string `json:"state"`
	DeliveryGeneration uint64 `json:"delivery_generation,omitempty"`
	LeaseExpiresAt     string `json:"lease_expires_at,omitempty"`
	ReportedStatus     string `json:"reported_status,omitempty"`
	ErrorCode          string `json:"error_code,omitempty"`
}

func New(baseURL, token string, caPEM []byte) (*Client, error) {
	parsed, err := url.Parse(baseURL)
	if err != nil || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" ||
		parsed.Path != "" || parsed.Host == "" || (parsed.Scheme != "https" && parsed.Scheme != "http") {
		return nil, errors.New("control URL must be an absolute HTTPS origin with no path")
	}
	if parsed.Port() == "" {
		return nil, errors.New("control URL must include an explicit port")
	}
	if parsed.Scheme == "http" && !loopbackHost(parsed.Hostname()) {
		return nil, errors.New("remote control URL must use HTTPS")
	}
	if strings.ContainsAny(token, "\r\n\x00") || len(token) > 4096 {
		return nil, errors.New("control token is invalid or exceeds 4096 bytes")
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if len(caPEM) > 0 {
		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, errors.New("control CA file contains no certificates")
		}
		tlsConfig.RootCAs = pool
	}
	transport := &http.Transport{
		Proxy: nil,
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSClientConfig:     tlsConfig,
		TLSHandshakeTimeout: 5 * time.Second,
		DisableCompression:  true,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("control redirects are disabled")
		},
	}
	return &Client{baseURL: strings.TrimSuffix(baseURL, "/"), token: token, http: client}, nil
}

func NewFromFiles(baseURL, tokenPath, caPath string) (*Client, error) {
	var token string
	if tokenPath != "" {
		raw, err := securefile.Read(tokenPath, 4096, securefile.OwnerOnly)
		if err != nil {
			return nil, fmt.Errorf("read control token: %w", err)
		}
		token = strings.TrimSpace(string(raw))
		if token == "" {
			return nil, errors.New("control token file is empty")
		}
	}
	var ca []byte
	if caPath != "" {
		var err error
		ca, err = securefile.Read(caPath, maxWireBytes, securefile.TrustFile)
		if err != nil {
			return nil, fmt.Errorf("read control CA: %w", err)
		}
	}
	return New(baseURL, token, ca)
}

func (c *Client) CreateTenant(ctx context.Context, tenantID string) (Tenant, error) {
	var tenant Tenant
	err := c.do(ctx, http.MethodPost, "/v1/tenants", struct {
		TenantID string `json:"tenant_id"`
	}{TenantID: tenantID}, &tenant, true)
	return tenant, err
}

func (c *Client) CreateEnrollment(ctx context.Context, nodeID string, tenantIDs []string, ttl time.Duration) (Enrollment, error) {
	var enrollment Enrollment
	err := c.do(ctx, http.MethodPost, "/v1/enrollments", struct {
		NodeID     string   `json:"node_id"`
		TenantIDs  []string `json:"tenant_ids"`
		TTLSeconds int64    `json:"ttl_seconds"`
	}{NodeID: nodeID, TenantIDs: tenantIDs, TTLSeconds: int64(ttl / time.Second)}, &enrollment, true)
	return enrollment, err
}

func (c *Client) Enroll(ctx context.Context, enrollmentToken, requestID string) (NodeCredential, error) {
	var credential NodeCredential
	err := c.do(ctx, http.MethodPost, "/v1/enroll", struct {
		EnrollmentToken string `json:"enrollment_token"`
		RequestID       string `json:"request_id"`
	}{EnrollmentToken: enrollmentToken, RequestID: requestID}, &credential, false)
	return credential, err
}

func (c *Client) SubmitCommand(ctx context.Context, tenantID, nodeID string, commandDSSE []byte) (Command, error) {
	var command Command
	path := "/v1/tenants/" + url.PathEscape(tenantID) + "/nodes/" + url.PathEscape(nodeID) + "/commands"
	err := c.do(ctx, http.MethodPost, path, struct {
		CommandDSSEBase64 string `json:"command_dsse_base64"`
	}{CommandDSSEBase64: base64.StdEncoding.EncodeToString(commandDSSE)}, &command, true)
	return command, err
}

func (c *Client) GetCommand(ctx context.Context, tenantID, nodeID, commandID string) (Command, error) {
	var command Command
	path := "/v1/tenants/" + url.PathEscape(tenantID) + "/nodes/" + url.PathEscape(nodeID) +
		"/commands/" + url.PathEscape(commandID)
	err := c.do(ctx, http.MethodGet, path, nil, &command, true)
	return command, err
}

func (c *Client) do(ctx context.Context, method, path string, body, output any, authenticated bool) error {
	if !strings.HasPrefix(path, "/v1/") || strings.Contains(path, "//") || strings.ContainsAny(path, "\r\n\x00") {
		return errors.New("invalid control API path")
	}
	if authenticated && c.token == "" {
		return errors.New("control operator token is required")
	}
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		if len(raw) > maxWireBytes {
			return errors.New("control request exceeds 1 MiB")
		}
		reader = bytes.NewReader(raw)
	}
	request, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return err
	}
	request.Header.Set("Accept", "application/json")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if authenticated {
		request.Header.Set("Authorization", "Bearer "+c.token)
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
		return errors.New("control response exceeds 1 MiB")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		var api struct {
			Error   string `json:"error"`
			Message string `json:"message"`
		}
		if err := json.Unmarshal(raw, &api); err != nil || api.Error == "" || api.Message == "" {
			return fmt.Errorf("control HTTP %d returned an invalid error body", response.StatusCode)
		}
		return &APIError{Status: response.StatusCode, Code: api.Error, Message: api.Message}
	}
	if output == nil {
		if len(bytes.TrimSpace(raw)) != 0 {
			return errors.New("control response unexpectedly contained a body")
		}
		return nil
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return fmt.Errorf("decode control response: %w", err)
	}
	if err := ensureEOF(decoder); err != nil {
		return fmt.Errorf("decode control response: %w", err)
	}
	return nil
}

func ensureEOF(decoder *json.Decoder) error {
	var extra any
	err := decoder.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("response contains trailing JSON")
	}
	return err
}

func loopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
