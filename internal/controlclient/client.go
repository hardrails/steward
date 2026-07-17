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
	"mime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/controlstore"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/securefile"
)

const (
	maxWireBytes             = 1 << 20
	maxOperationsCursorBytes = 4096
)

type Client struct {
	baseURL string
	token   string
	http    *http.Client
}

type APIError struct {
	Status     int
	Code       string
	Message    string
	RetryAfter time.Duration
}

func (e *APIError) Error() string {
	if e.RetryAfter > 0 {
		return fmt.Sprintf(
			"control HTTP %d %s: %s (retry after %s)",
			e.Status, e.Code, e.Message, e.RetryAfter,
		)
	}
	return fmt.Sprintf("control HTTP %d %s: %s", e.Status, e.Code, e.Message)
}

type Tenant struct {
	TenantID string `json:"tenant_id"`
	State    string `json:"state,omitempty"`
	Created  string `json:"created_at,omitempty"`
}

type TenantList struct {
	Tenants   []Tenant `json:"tenants"`
	NextAfter string   `json:"next_after,omitempty"`
}

type Operator struct {
	CredentialID string `json:"credential_id"`
	Role         string `json:"role"`
	TenantID     string `json:"tenant_id,omitempty"`
	Token        string `json:"token"`
	CreatedAt    string `json:"created_at"`
}

type Enrollment struct {
	ControllerInstanceID string   `json:"controller_instance_id"`
	EnrollmentID         string   `json:"enrollment_id"`
	EnrollmentToken      string   `json:"enrollment_token"`
	NodeID               string   `json:"node_id"`
	TenantIDs            []string `json:"tenant_ids,omitempty"`
	ExpiresAt            string   `json:"expires_at"`
}

// DecodeEnrollmentCapability strictly decodes an enrollment capability read
// from an owner-only file. Strict decoding keeps a secret-bearing file from
// acquiring ambiguous meaning through duplicate or unknown fields.
func DecodeEnrollmentCapability(raw []byte) (Enrollment, error) {
	var enrollment Enrollment
	if err := dsse.DecodeStrictInto(raw, 64<<10, &enrollment); err != nil {
		return Enrollment{}, fmt.Errorf("decode enrollment capability: %w", err)
	}
	if enrollment.ControllerInstanceID == "" || enrollment.EnrollmentID == "" || enrollment.EnrollmentToken == "" ||
		enrollment.NodeID == "" || enrollment.ExpiresAt == "" {
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
	CommandID                       string         `json:"command_id"`
	DeliveryID                      string         `json:"delivery_id,omitempty"`
	TenantID                        string         `json:"tenant_id"`
	NodeID                          string         `json:"node_id"`
	CommandDigest                   string         `json:"command_digest"`
	CommandKind                     string         `json:"command_kind,omitempty"`
	SignedRuntimeRef                string         `json:"signed_runtime_ref,omitempty"`
	SignedClaimGeneration           uint64         `json:"signed_claim_generation,omitempty"`
	SignedInstanceGeneration        uint64         `json:"signed_instance_generation,omitempty"`
	State                           string         `json:"state"`
	DeliveryProtocol                int            `json:"delivery_protocol,omitempty"`
	DeliveryGeneration              uint64         `json:"delivery_generation,omitempty"`
	LeaseExpiresAt                  string         `json:"lease_expires_at,omitempty"`
	TerminalStatus                  string         `json:"terminal_status,omitempty"`
	ReportedStatus                  string         `json:"reported_status,omitempty"`
	ErrorCode                       string         `json:"error_code,omitempty"`
	ClaimGeneration                 *uint64        `json:"claim_generation,omitempty"`
	AdmissionProjectionState        string         `json:"admission_projection_state,omitempty"`
	ActivationCanaryProjectionState string         `json:"activation_canary_projection_state,omitempty"`
	Result                          *CommandResult `json:"result,omitempty"`
}

type CommandResult struct {
	RuntimeRef       string                                            `json:"runtime_ref,omitempty"`
	Error            string                                            `json:"error,omitempty"`
	Replayed         bool                                              `json:"replayed,omitempty"`
	Absent           bool                                              `json:"absent,omitempty"`
	Admission        *controlprotocol.ExecutorAdmissionProjectionV1    `json:"admission,omitempty"`
	ActivationCanary *controlprotocol.ExecutorActivationCanaryResultV1 `json:"activation_canary,omitempty"`
}

type Node struct {
	NodeID       string   `json:"node_id"`
	TenantIDs    []string `json:"tenant_ids"`
	Capabilities []string `json:"capabilities"`
	State        string   `json:"state"`
	CreatedAt    string   `json:"created_at"`
	LastSeenAt   string   `json:"last_seen_at,omitempty"`
	RevokedAt    string   `json:"revoked_at,omitempty"`
}

type NodeList struct {
	Nodes     []Node `json:"nodes"`
	NextAfter string `json:"next_after,omitempty"`
}

type NodeRevocation struct {
	NodeID             string `json:"node_id"`
	RevokedCredentials int    `json:"revoked_credentials"`
}

type NodeCredentialRevocation struct {
	CredentialID string `json:"credential_id"`
	NodeID       string `json:"node_id"`
	Revoked      bool   `json:"revoked"`
}

// EvidenceCaptureArmInput binds one short-lived controller capture to an exact
// activation. The node identity is supplied separately as the API route.
type EvidenceCaptureArmInput struct {
	CaptureID             string
	RequestID             string
	TenantID              string
	RuntimeRef            string
	Generation            uint64
	ActivationID          string
	ActivationBeginDigest string
	TTL                   time.Duration
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
	if len(token) > 4096 || token != strings.TrimSpace(token) || strings.ContainsAny(token, " \t\r\n\x00") {
		return nil, errors.New("control token is invalid or exceeds 4096 bytes")
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13}
	if len(caPEM) > 0 {
		// An explicit private CA is a trust replacement, not an addition to the
		// host's public Web PKI. This keeps a public CA (or a compromised system
		// root set) from authenticating a controller when the operator supplied a
		// sovereign trust root deliberately.
		pool := x509.NewCertPool()
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

func (c *Client) ListTenants(ctx context.Context, after string, limit int) (TenantList, error) {
	var tenants TenantList
	path, err := paginatedPath("/v1/tenants", after, limit)
	if err != nil {
		return TenantList{}, err
	}
	err = c.do(ctx, http.MethodGet, path, nil, &tenants, true)
	return tenants, err
}

func (c *Client) IssueOperator(ctx context.Context, requestID, role, tenantID string) (Operator, error) {
	var operator Operator
	err := c.do(ctx, http.MethodPost, "/v1/operators", struct {
		RequestID string `json:"request_id"`
		Role      string `json:"role"`
		TenantID  string `json:"tenant_id,omitempty"`
	}{RequestID: requestID, Role: role, TenantID: tenantID}, &operator, true)
	return operator, err
}

func (c *Client) RevokeOperator(ctx context.Context, credentialID string) error {
	return c.do(ctx, http.MethodDelete, "/v1/operators/"+url.PathEscape(credentialID), nil, nil, true)
}

func (c *Client) CreateEnrollment(ctx context.Context, requestID, nodeID string, tenantIDs []string, ttl time.Duration) (Enrollment, error) {
	if ttl < time.Second || ttl > 24*time.Hour || ttl%time.Second != 0 {
		return Enrollment{}, errors.New("enrollment lifetime must be whole seconds between 1 second and 24 hours")
	}
	var enrollment Enrollment
	err := c.do(ctx, http.MethodPost, "/v1/enrollments", struct {
		RequestID  string   `json:"request_id"`
		NodeID     string   `json:"node_id"`
		TenantIDs  []string `json:"tenant_ids"`
		TTLSeconds int64    `json:"ttl_seconds"`
	}{RequestID: requestID, NodeID: nodeID, TenantIDs: tenantIDs, TTLSeconds: int64(ttl / time.Second)}, &enrollment, true)
	return enrollment, err
}

func (c *Client) ListNodes(ctx context.Context, tenantID, after string, limit int) (NodeList, error) {
	path, err := paginatedPath("/v1/tenants/"+url.PathEscape(tenantID)+"/nodes", after, limit)
	if err != nil {
		return NodeList{}, err
	}
	var nodes NodeList
	err = c.do(ctx, http.MethodGet, path, nil, &nodes, true)
	return nodes, err
}

func (c *Client) GetNode(ctx context.Context, tenantID, nodeID string) (Node, error) {
	var node Node
	path := "/v1/tenants/" + url.PathEscape(tenantID) + "/nodes/" + url.PathEscape(nodeID)
	err := c.do(ctx, http.MethodGet, path, nil, &node, true)
	return node, err
}

func (c *Client) RevokeNode(ctx context.Context, nodeID string) (NodeRevocation, error) {
	var revocation NodeRevocation
	err := c.do(ctx, http.MethodDelete, "/v1/nodes/"+url.PathEscape(nodeID), nil, &revocation, true)
	return revocation, err
}

func (c *Client) RevokeNodeCredential(ctx context.Context, credentialID string) (NodeCredentialRevocation, error) {
	var revocation NodeCredentialRevocation
	err := c.do(ctx, http.MethodDelete, "/v1/node-credentials/"+url.PathEscape(credentialID), nil, &revocation, true)
	return revocation, err
}

func (c *Client) Enroll(ctx context.Context, enrollmentToken, requestID string, proof controlprotocol.ExecutorEvidenceIdentityProofV1) (NodeCredential, error) {
	if err := proof.Validate(); err != nil {
		return NodeCredential{}, fmt.Errorf("validate executor evidence identity proof: %w", err)
	}
	var credential NodeCredential
	err := c.do(ctx, http.MethodPost, "/v1/enroll", struct {
		EnrollmentToken       string                                          `json:"enrollment_token"`
		RequestID             string                                          `json:"request_id"`
		EvidenceIdentityProof controlprotocol.ExecutorEvidenceIdentityProofV1 `json:"evidence_identity_proof"`
	}{
		EnrollmentToken: enrollmentToken, RequestID: requestID, EvidenceIdentityProof: proof,
	}, &credential, false)
	return credential, err
}

func (c *Client) SubmitCommand(ctx context.Context, tenantID, nodeID string, commandDSSE []byte) (Command, error) {
	var command Command
	path := "/v1/tenants/" + url.PathEscape(tenantID) + "/nodes/" + url.PathEscape(nodeID) + "/commands"
	err := c.do(ctx, http.MethodPost, path, struct {
		CommandDSSEBase64 string `json:"command_dsse_base64"`
	}{CommandDSSEBase64: base64.StdEncoding.EncodeToString(commandDSSE)}, &command, true)
	if err == nil {
		err = validateCommandProjections(command)
	}
	return command, err
}

func (c *Client) GetCommand(ctx context.Context, tenantID, nodeID, commandID string) (Command, error) {
	var command Command
	path := "/v1/tenants/" + url.PathEscape(tenantID) + "/nodes/" + url.PathEscape(nodeID) +
		"/commands/" + url.PathEscape(commandID)
	err := c.do(ctx, http.MethodGet, path, nil, &command, true)
	if err == nil {
		err = validateCommandProjections(command)
	}
	return command, err
}

func validateCommandProjections(command Command) error {
	if err := validateCommandAdmissionProjection(command); err != nil {
		return err
	}
	return validateCommandActivationCanaryProjection(command)
}

func validateCommandAdmissionProjection(command Command) error {
	var projection *controlprotocol.ExecutorAdmissionProjectionV1
	if command.Result != nil {
		projection = command.Result.Admission
	}
	switch command.AdmissionProjectionState {
	case "":
		if projection != nil {
			return errors.New("control command returned an admission projection without its state")
		}
		if command.CommandKind == "admit" && command.TerminalStatus == controlprotocol.ExecutorStatusDone {
			return errors.New("control command omitted the admission projection state for a successful admit")
		}
		return nil
	case "missing":
		if command.CommandKind != "admit" || command.TerminalStatus != controlprotocol.ExecutorStatusDone ||
			command.Result == nil || projection != nil ||
			(command.DeliveryProtocol != controlprotocol.ExecutorProtocolV3 &&
				command.DeliveryProtocol != controlprotocol.ExecutorProtocolV4) {
			return errors.New("control command returned an inconsistent missing admission projection")
		}
		return nil
	case "present":
		if command.CommandKind != "admit" || command.TerminalStatus != controlprotocol.ExecutorStatusDone ||
			command.DeliveryProtocol != controlprotocol.ExecutorProtocolV4 || projection == nil ||
			command.Result == nil || command.Result.RuntimeRef != projection.RuntimeRef ||
			!commandProjectionRuntimeMatches(command.SignedRuntimeRef, projection.RuntimeRef) ||
			command.SignedClaimGeneration == 0 || command.ClaimGeneration == nil ||
			*command.ClaimGeneration != command.SignedClaimGeneration ||
			command.SignedInstanceGeneration == 0 ||
			projection.Generation != command.SignedInstanceGeneration {
			return errors.New("control command returned an inconsistent admission projection")
		}
		if err := projection.Validate(); err != nil {
			return fmt.Errorf("validate control command admission projection: %w", err)
		}
		expectedStatus := "stopped"
		if projection.Status == "running" {
			expectedStatus = "running"
		}
		if command.ReportedStatus != expectedStatus {
			return errors.New("control command admission projection conflicts with reported status")
		}
		return nil
	default:
		return errors.New("control command returned an unknown admission projection state")
	}
}

func validateCommandActivationCanaryProjection(command Command) error {
	var projection *controlprotocol.ExecutorActivationCanaryResultV1
	if command.Result != nil {
		projection = command.Result.ActivationCanary
	}
	switch command.ActivationCanaryProjectionState {
	case "":
		if projection != nil {
			return errors.New("control command returned an activation canary projection without its state")
		}
		if command.CommandKind == "activation-canary" &&
			command.TerminalStatus == controlprotocol.ExecutorStatusDone {
			return errors.New("control command omitted the activation canary projection state for a successful canary")
		}
		return nil
	case "missing":
		if command.CommandKind != "activation-canary" ||
			command.TerminalStatus != controlprotocol.ExecutorStatusDone ||
			command.DeliveryProtocol != controlprotocol.ExecutorProtocolV4 ||
			command.Result == nil || projection != nil {
			return errors.New("control command returned an inconsistent missing activation canary projection")
		}
		return nil
	case "present":
		if command.CommandKind != "activation-canary" ||
			command.TerminalStatus != controlprotocol.ExecutorStatusDone ||
			command.ReportedStatus != "running" ||
			command.DeliveryProtocol != controlprotocol.ExecutorProtocolV4 || projection == nil ||
			command.Result == nil ||
			!commandProjectionRuntimeMatches(command.SignedRuntimeRef, command.Result.RuntimeRef) ||
			command.SignedClaimGeneration == 0 || command.ClaimGeneration == nil ||
			*command.ClaimGeneration != command.SignedClaimGeneration ||
			command.SignedInstanceGeneration == 0 {
			return errors.New("control command returned an inconsistent activation canary projection")
		}
		if err := projection.Validate(); err != nil {
			return fmt.Errorf("validate control command activation canary projection: %w", err)
		}
		return nil
	default:
		return errors.New("control command returned an unknown activation canary projection state")
	}
}

func commandProjectionRuntimeMatches(signedRuntimeRef, executorRuntimeRef string) bool {
	if !validExecutorRuntimeRef(executorRuntimeRef) {
		return false
	}
	if validExecutorRuntimeRef(signedRuntimeRef) {
		return signedRuntimeRef == executorRuntimeRef
	}
	// A protocol-4 uplink command signs a routable uplink:v2 tuple. The
	// controller validates the tuple against the node report and exposes the
	// distinct opaque Executor runtime here; callers that need stronger binding
	// (such as rollout) reconstruct and verify the exact prepared activation.
	return strings.HasPrefix(signedRuntimeRef, "uplink:v2:")
}

func (c *Client) GetOperationsSummary(ctx context.Context, tenantID string) (controlstore.OperationsSummary, error) {
	path, err := operationsPath("/v1/operations/summary", map[string]string{"tenant_id": tenantID}, nil, "", 0)
	if err != nil {
		return controlstore.OperationsSummary{}, err
	}
	var summary controlstore.OperationsSummary
	err = c.do(ctx, http.MethodGet, path, nil, &summary, true)
	return summary, err
}

func (c *Client) ListAttention(ctx context.Context, tenantID, reason, cursor string, limit int) (controlstore.AttentionPage, error) {
	path, err := operationsPath(
		"/v1/operations/attention",
		map[string]string{"tenant_id": tenantID, "reason": reason}, nil, cursor, limit,
	)
	if err != nil {
		return controlstore.AttentionPage{}, err
	}
	var page controlstore.AttentionPage
	err = c.do(ctx, http.MethodGet, path, nil, &page, true)
	return page, err
}

func (c *Client) ListCommandInventory(ctx context.Context, tenantID, nodeID, state, terminalStatus, cursor string, limit int) (controlstore.CommandInventoryPage, error) {
	if terminalStatus != "" && state != string(controlstore.CommandTerminal) {
		return controlstore.CommandInventoryPage{}, errors.New("control operations terminal_status requires state=terminal")
	}
	path, err := operationsPath(
		"/v1/operations/commands",
		map[string]string{
			"tenant_id": tenantID, "node_id": nodeID, "state": state, "terminal_status": terminalStatus,
		},
		nil, cursor, limit,
	)
	if err != nil {
		return controlstore.CommandInventoryPage{}, err
	}
	var page controlstore.CommandInventoryPage
	err = c.do(ctx, http.MethodGet, path, nil, &page, true)
	return page, err
}

func (c *Client) ListCredentialInventory(ctx context.Context, tenantID, kind, role, nodeID string, revoked *bool, cursor string, limit int) (controlstore.CredentialInventoryPage, error) {
	if role != "" && nodeID != "" ||
		kind == "node" && role != "" ||
		kind == "operator" && nodeID != "" {
		return controlstore.CredentialInventoryPage{}, errors.New("control operations credential filters are incompatible")
	}
	path, err := operationsPath(
		"/v1/operations/credentials",
		map[string]string{"tenant_id": tenantID, "kind": kind, "role": role, "node_id": nodeID},
		revoked, cursor, limit,
	)
	if err != nil {
		return controlstore.CredentialInventoryPage{}, err
	}
	var page controlstore.CredentialInventoryPage
	err = c.do(ctx, http.MethodGet, path, nil, &page, true)
	return page, err
}

// InspectExecutorEvidence returns the controller's validated online witness
// state for one node.
func (c *Client) InspectExecutorEvidence(ctx context.Context, nodeID string) (controlprotocol.ExecutorEvidenceInspectionV1, error) {
	path, err := executorEvidencePath(nodeID, "")
	if err != nil {
		return controlprotocol.ExecutorEvidenceInspectionV1{}, err
	}
	var inspection controlprotocol.ExecutorEvidenceInspectionV1
	if err := c.do(ctx, http.MethodGet, path, nil, &inspection, true); err != nil {
		return controlprotocol.ExecutorEvidenceInspectionV1{}, err
	}
	if err := inspection.Validate(); err != nil {
		return controlprotocol.ExecutorEvidenceInspectionV1{}, fmt.Errorf("validate control evidence inspection: %w", err)
	}
	return inspection, nil
}

// ExportExecutorEvidence returns a validated, independently signed witness
// export suitable for later offline verification.
func (c *Client) ExportExecutorEvidence(ctx context.Context, nodeID string) (controlprotocol.ExecutorEvidenceExportV1, error) {
	path, err := executorEvidencePath(nodeID, "/export")
	if err != nil {
		return controlprotocol.ExecutorEvidenceExportV1{}, err
	}
	var export controlprotocol.ExecutorEvidenceExportV1
	if err := c.do(ctx, http.MethodGet, path, nil, &export, true); err != nil {
		return controlprotocol.ExecutorEvidenceExportV1{}, err
	}
	if err := export.Validate(); err != nil {
		return controlprotocol.ExecutorEvidenceExportV1{}, fmt.Errorf("validate control evidence export: %w", err)
	}
	return export, nil
}

// ArmExecutorEvidenceCapture reserves a bounded controller-side range before
// an activation command is submitted. Exact retries return the same capture
// without extending its absolute expiry.
func (c *Client) ArmExecutorEvidenceCapture(
	ctx context.Context,
	nodeID string,
	input EvidenceCaptureArmInput,
) (controlstore.EvidenceCapture, error) {
	path, err := evidenceCapturePath(nodeID, "", "")
	if err != nil {
		return controlstore.EvidenceCapture{}, err
	}
	if input.TTL < controlstore.MinEvidenceCaptureTTL ||
		input.TTL > controlstore.MaxEvidenceCaptureTTL ||
		input.TTL%time.Second != 0 {
		return controlstore.EvidenceCapture{},
			errors.New("evidence capture lifetime must be whole seconds between 1 second and 1 hour")
	}
	if !validEvidenceRouteIdentity(input.CaptureID, 128) ||
		!validEvidenceRouteIdentity(input.RequestID, 128) ||
		!validEvidenceRouteIdentity(input.TenantID, 128) ||
		!validEvidenceRouteIdentity(input.ActivationID, 128) ||
		!controlprotocol.ValidSHA256Digest(input.ActivationBeginDigest) ||
		!validExecutorRuntimeRef(input.RuntimeRef) ||
		input.Generation == 0 {
		return controlstore.EvidenceCapture{},
			errors.New("evidence capture target identity is invalid")
	}
	var capture controlstore.EvidenceCapture
	err = c.do(ctx, http.MethodPost, path, struct {
		CaptureID             string `json:"capture_id"`
		RequestID             string `json:"request_id"`
		TenantID              string `json:"tenant_id"`
		RuntimeRef            string `json:"runtime_ref"`
		Generation            uint64 `json:"generation"`
		ActivationID          string `json:"activation_id"`
		ActivationBeginDigest string `json:"activation_begin_digest"`
		TTLSeconds            int64  `json:"ttl_seconds"`
	}{
		CaptureID: input.CaptureID, RequestID: input.RequestID,
		TenantID: input.TenantID, RuntimeRef: input.RuntimeRef,
		Generation: input.Generation, ActivationID: input.ActivationID,
		ActivationBeginDigest: input.ActivationBeginDigest,
		TTLSeconds:            int64(input.TTL / time.Second),
	}, &capture, true)
	if err != nil {
		return controlstore.EvidenceCapture{}, err
	}
	if err := validateEvidenceCaptureResponse(capture, nodeID, input.CaptureID); err != nil {
		return controlstore.EvidenceCapture{}, err
	}
	armedAt, armedErr := time.Parse(time.RFC3339Nano, capture.ArmedAt)
	expiresAt, expiresErr := time.Parse(time.RFC3339Nano, capture.ExpiresAt)
	if capture.RequestID != input.RequestID || capture.TenantID != input.TenantID ||
		capture.RuntimeRef != input.RuntimeRef || capture.Generation != input.Generation ||
		capture.ActivationID != input.ActivationID ||
		capture.ActivationBeginDigest != input.ActivationBeginDigest ||
		armedErr != nil || expiresErr != nil || expiresAt.Sub(armedAt) != input.TTL {
		return controlstore.EvidenceCapture{},
			errors.New("control evidence capture arm response changed the requested binding")
	}
	return capture, nil
}

func (c *Client) GetExecutorEvidenceCapture(
	ctx context.Context,
	nodeID, captureID string,
) (controlstore.EvidenceCapture, error) {
	path, err := evidenceCapturePath(nodeID, captureID, "")
	if err != nil {
		return controlstore.EvidenceCapture{}, err
	}
	var capture controlstore.EvidenceCapture
	if err := c.do(ctx, http.MethodGet, path, nil, &capture, true); err != nil {
		return controlstore.EvidenceCapture{}, err
	}
	if err := validateEvidenceCaptureResponse(capture, nodeID, captureID); err != nil {
		return controlstore.EvidenceCapture{}, err
	}
	return capture, nil
}

func (c *Client) DeleteExecutorEvidenceCapture(
	ctx context.Context,
	nodeID, captureID string,
) error {
	path, err := evidenceCapturePath(nodeID, captureID, "")
	if err != nil {
		return err
	}
	return c.do(ctx, http.MethodDelete, path, nil, nil, true)
}

func (c *Client) SealExecutorEvidenceCapture(
	ctx context.Context,
	nodeID, captureID, canaryCommandID string,
) (controlstore.EvidenceCapture, error) {
	path, err := evidenceCapturePath(nodeID, captureID, "/seal")
	if err != nil {
		return controlstore.EvidenceCapture{}, err
	}
	if !validEvidenceRouteIdentity(canaryCommandID, 256) {
		return controlstore.EvidenceCapture{},
			errors.New("activation canary command identity is invalid")
	}
	var capture controlstore.EvidenceCapture
	if err := c.do(ctx, http.MethodPost, path, struct {
		CanaryCommandID string `json:"canary_command_id"`
	}{CanaryCommandID: canaryCommandID}, &capture, true); err != nil {
		return controlstore.EvidenceCapture{}, err
	}
	if err := validateEvidenceCaptureResponse(capture, nodeID, captureID); err != nil {
		return controlstore.EvidenceCapture{}, err
	}
	if capture.State != controlstore.EvidenceCaptureSealed ||
		capture.CanaryCommandID != canaryCommandID {
		return controlstore.EvidenceCapture{},
			errors.New("control evidence capture seal response changed the requested binding")
	}
	return capture, nil
}

func (c *Client) ExportExecutorEvidenceCapture(
	ctx context.Context,
	nodeID, captureID string,
) (controlprotocol.ControllerEvidenceCaptureV1, error) {
	path, err := evidenceCapturePath(nodeID, captureID, "/export")
	if err != nil {
		return controlprotocol.ControllerEvidenceCaptureV1{}, err
	}
	var export controlprotocol.ControllerEvidenceCaptureV1
	if err := c.do(ctx, http.MethodGet, path, nil, &export, true); err != nil {
		return controlprotocol.ControllerEvidenceCaptureV1{}, err
	}
	if err := export.Validate(); err != nil {
		return controlprotocol.ControllerEvidenceCaptureV1{},
			fmt.Errorf("validate control evidence capture export: %w", err)
	}
	if export.Statement.NodeID != nodeID ||
		export.Statement.CaptureID != captureID {
		return controlprotocol.ControllerEvidenceCaptureV1{},
			errors.New("control evidence capture export changed route identity")
	}
	return export, nil
}

func validateEvidenceCaptureResponse(
	capture controlstore.EvidenceCapture,
	nodeID, captureID string,
) error {
	if capture.NodeID != nodeID || capture.CaptureID != captureID {
		return errors.New("control evidence capture response changed route identity")
	}
	if err := capture.Validate(); err != nil {
		return fmt.Errorf("validate control evidence capture response: %w", err)
	}
	return nil
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
		if !jsonContentType(response.Header.Get("Content-Type")) {
			return fmt.Errorf("control HTTP %d returned a non-JSON error", response.StatusCode)
		}
		var api struct {
			Error   string `json:"error"`
			Message string `json:"message"`
		}
		if err := dsse.DecodeStrictInto(raw, maxWireBytes, &api); err != nil || api.Error == "" || api.Message == "" {
			return fmt.Errorf("control HTTP %d returned an invalid error body", response.StatusCode)
		}
		retryAfter, err := retryAfterDuration(response.Header.Values("Retry-After"))
		if err != nil {
			return fmt.Errorf("control HTTP %d returned an invalid Retry-After header: %w", response.StatusCode, err)
		}
		return &APIError{
			Status: response.StatusCode, Code: api.Error, Message: api.Message,
			RetryAfter: retryAfter,
		}
	}
	if output == nil {
		if len(bytes.TrimSpace(raw)) != 0 {
			return errors.New("control response unexpectedly contained a body")
		}
		return nil
	}
	if !jsonContentType(response.Header.Get("Content-Type")) {
		return errors.New("control success response is not application/json")
	}
	if err := dsse.DecodeStrictInto(raw, maxWireBytes, output); err != nil {
		return fmt.Errorf("decode control response: %w", err)
	}
	return nil
}

func executorEvidencePath(nodeID, suffix string) (string, error) {
	if !validEvidenceRouteIdentity(nodeID, 128) {
		return "", errors.New("control evidence node identity is invalid")
	}
	return "/v1/nodes/" + url.PathEscape(nodeID) + "/evidence" + suffix, nil
}

func evidenceCapturePath(nodeID, captureID, suffix string) (string, error) {
	path, err := executorEvidencePath(nodeID, "/captures")
	if err != nil {
		return "", err
	}
	if captureID == "" {
		if suffix != "" {
			return "", errors.New("control evidence capture identity is required")
		}
		return path, nil
	}
	if !validEvidenceRouteIdentity(captureID, 128) {
		return "", errors.New("control evidence capture identity is invalid")
	}
	if suffix != "" && suffix != "/seal" && suffix != "/export" {
		return "", errors.New("control evidence capture route suffix is invalid")
	}
	return path + "/" + url.PathEscape(captureID) + suffix, nil
}

func validEvidenceRouteIdentity(value string, maximum int) bool {
	if value == "" || len(value) > maximum || !utf8.ValidString(value) ||
		strings.TrimSpace(value) != value || strings.ContainsAny(value, "\r\n\x00") {
		return false
	}
	for index, character := range value {
		if character >= 'A' && character <= 'Z' ||
			character >= 'a' && character <= 'z' ||
			character >= '0' && character <= '9' ||
			index > 0 && (character == '.' || character == '_' || character == '-') {
			continue
		}
		return false
	}
	return true
}

func validExecutorRuntimeRef(value string) bool {
	const prefix = "executor-"
	if !strings.HasPrefix(value, prefix) || len(value) != len(prefix)+64 {
		return false
	}
	for _, character := range strings.TrimPrefix(value, prefix) {
		if character < '0' || character > '9' && character < 'a' || character > 'f' {
			return false
		}
	}
	return true
}

func paginatedPath(path, after string, limit int) (string, error) {
	if len(after) > 128 || strings.ContainsAny(after, "\r\n\x00") || limit < 0 || limit > 500 {
		return "", errors.New("control pagination is outside its bounds")
	}
	query := url.Values{}
	if after != "" {
		query.Set("after", after)
	}
	if limit != 0 {
		query.Set("limit", fmt.Sprint(limit))
	}
	if encoded := query.Encode(); encoded != "" {
		return path + "?" + encoded, nil
	}
	return path, nil
}

func operationsPath(path string, fields map[string]string, revoked *bool, cursor string, limit int) (string, error) {
	if limit < 0 || limit > controlstore.MaxInventoryPageLimit {
		return "", errors.New("control operations pagination is outside its bounds")
	}
	query := url.Values{}
	for name, value := range fields {
		if value == "" {
			continue
		}
		maximum := 128
		if name == "state" || name == "terminal_status" || name == "kind" || name == "role" || name == "reason" {
			maximum = 64
		}
		if err := validateOperationsQueryValue(name, value, maximum); err != nil {
			return "", err
		}
		query.Set(name, value)
	}
	if cursor != "" {
		if err := validateOperationsCursor(cursor); err != nil {
			return "", err
		}
		query.Set("cursor", cursor)
	}
	if limit != 0 {
		query.Set("limit", strconv.Itoa(limit))
	}
	if revoked != nil {
		query.Set("revoked", strconv.FormatBool(*revoked))
	}
	if encoded := query.Encode(); encoded != "" {
		return path + "?" + encoded, nil
	}
	return path, nil
}

func validateOperationsQueryValue(name, value string, maximum int) error {
	if value == "" || len(value) > maximum || !utf8.ValidString(value) ||
		value != strings.TrimSpace(value) || strings.ContainsAny(value, "\r\n\x00") {
		return fmt.Errorf("control operations %s filter is invalid or exceeds %d bytes", name, maximum)
	}
	return nil
}

func validateOperationsCursor(cursor string) error {
	if err := validateOperationsQueryValue(
		"cursor", cursor, base64.RawURLEncoding.EncodedLen(maxOperationsCursorBytes),
	); err != nil {
		return err
	}
	raw, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil || len(raw) == 0 || len(raw) > maxOperationsCursorBytes ||
		base64.RawURLEncoding.EncodeToString(raw) != cursor {
		return errors.New("control operations cursor is not canonical bounded base64url")
	}
	return nil
}

func jsonContentType(value string) bool {
	mediaType, _, err := mime.ParseMediaType(value)
	return err == nil && mediaType == "application/json"
}

func retryAfterDuration(values []string) (time.Duration, error) {
	if len(values) == 0 {
		return 0, nil
	}
	if len(values) != 1 {
		return 0, errors.New("Retry-After must contain exactly one value")
	}
	value := values[0]
	if value == "" || len(value) > 1 && value[0] == '0' {
		return 0, errors.New("Retry-After must be canonical positive delta-seconds")
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return 0, errors.New("Retry-After must be canonical positive delta-seconds")
		}
	}
	seconds, err := strconv.Atoi(value)
	if err != nil || seconds < 1 || seconds > 3600 {
		return 0, errors.New("Retry-After delta-seconds must be between 1 and 3600")
	}
	return time.Duration(seconds) * time.Second, nil
}

func loopbackHost(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
