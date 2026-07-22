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
	"math"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/controlstore"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/poolmembership"
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
	NodeID         string                           `json:"node_id"`
	TenantIDs      []string                         `json:"tenant_ids"`
	Capabilities   []string                         `json:"capabilities"`
	State          string                           `json:"state"`
	CreatedAt      string                           `json:"created_at"`
	LastSeenAt     string                           `json:"last_seen_at,omitempty"`
	RevokedAt      string                           `json:"revoked_at,omitempty"`
	Scheduling     *controlstore.NodeScheduling     `json:"scheduling,omitempty"`
	Placement      controlstore.NodePlacement       `json:"placement"`
	Drain          *controlstore.NodeDrain          `json:"drain,omitempty"`
	PoolMembership *controlstore.NodePoolMembership `json:"pool_membership,omitempty"`
}

type NodePlacementChange struct {
	Node    Node `json:"node"`
	Changed bool `json:"changed"`
}

type NodeDrainChange struct {
	Node    Node `json:"node"`
	Changed bool `json:"changed"`
}

type OperationalFreezeChange struct {
	Status  controlstore.OperationalFreezeStatus `json:"status"`
	Changed bool                                 `json:"changed"`
}

type TenantResourceQuotaChange struct {
	Status  controlstore.TenantResourceQuotaStatus `json:"status"`
	Changed bool                                   `json:"changed"`
}

type SnapshotQuarantineChange struct {
	Status  controlstore.SnapshotQuarantineStatus `json:"status"`
	Changed bool                                  `json:"changed"`
}

type NodeList struct {
	Nodes     []Node `json:"nodes"`
	NextAfter string `json:"next_after,omitempty"`
}

type DeploymentApply struct {
	Generation       uint64
	ExpectedRevision uint64
	AgentName        string
	BundleDigest     string
	CapsuleDSSE      []byte
	DelegationDSSE   []byte
	DisruptionBudget *controlstore.DeploymentDisruptionBudget
	Fork             *controlstore.DeploymentFork
}

type Deployment struct {
	TenantID            string                                  `json:"tenant_id"`
	DeploymentID        string                                  `json:"deployment_id"`
	Generation          uint64                                  `json:"generation"`
	Revision            uint64                                  `json:"revision"`
	AgentName           string                                  `json:"agent_name"`
	BundleDigest        string                                  `json:"bundle_digest"`
	CapsuleDigest       string                                  `json:"capsule_digest"`
	DelegationDigest    string                                  `json:"delegation_digest"`
	DelegationID        string                                  `json:"delegation_id"`
	ControllerKeyID     string                                  `json:"controller_key_id"`
	ClaimGeneration     uint64                                  `json:"claim_generation"`
	AllowedNodeIDs      []string                                `json:"allowed_node_ids"`
	DelegationExpiresAt string                                  `json:"delegation_expires_at"`
	DesiredState        controlstore.DeploymentDesiredState     `json:"desired_state"`
	DisruptionBudget    controlstore.DeploymentDisruptionBudget `json:"disruption_budget"`
	Phase               controlstore.DeploymentPhase            `json:"phase"`
	Instances           []controlstore.DeploymentInstance       `json:"instances"`
	Rollout             *DeploymentRollout                      `json:"rollout,omitempty"`
	Fork                *controlstore.DeploymentFork            `json:"fork,omitempty"`
	CreatedAt           string                                  `json:"created_at"`
	UpdatedAt           string                                  `json:"updated_at"`
}

type DeploymentRollout struct {
	SourceGeneration       uint64 `json:"source_generation"`
	SourceAgentName        string `json:"source_agent_name"`
	SourceBundleDigest     string `json:"source_bundle_digest"`
	SourceCapsuleDigest    string `json:"source_capsule_digest"`
	SourceDelegationDigest string `json:"source_delegation_digest"`
	StartedAt              string `json:"started_at"`
	PausedAt               string `json:"paused_at,omitempty"`
}

type DeploymentList struct {
	Deployments []Deployment `json:"deployments"`
	NextAfter   string       `json:"next_after,omitempty"`
}

type InstanceEventList struct {
	Events    []controlstore.InstanceEvent `json:"events"`
	NextAfter string                       `json:"next_after,omitempty"`
}

type TaskProjectionList struct {
	Tasks     []controlstore.TaskProjection `json:"tasks"`
	NextAfter string                        `json:"next_after,omitempty"`
}

type TaskRequestList struct {
	Tasks     []controlstore.TaskRequest `json:"tasks"`
	NextAfter string                     `json:"next_after,omitempty"`
}

type NodePoolList struct {
	NodePools []controlstore.NodePoolStatus `json:"node_pools"`
	NextAfter string                        `json:"next_after,omitempty"`
}

type NodePoolApply struct {
	ExpectedRevision          uint64
	TenantIDs                 []string
	Architecture              string
	MinNodes                  int
	DesiredNodes              int
	MaxNodes                  int
	MembershipKeyID           string
	MembershipPublicKeyBase64 string
}

type NodePoolMembershipBinding struct {
	NodeID     string                           `json:"node_id"`
	Membership *controlstore.NodePoolMembership `json:"membership"`
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

func (c *Client) ApplyDeployment(
	ctx context.Context,
	tenantID, deploymentID string,
	input DeploymentApply,
) (Deployment, error) {
	path, err := deploymentPath(tenantID, deploymentID)
	if err != nil {
		return Deployment{}, err
	}
	var deployment Deployment
	err = c.do(ctx, http.MethodPut, path, struct {
		Generation           uint64                                   `json:"generation"`
		ExpectedRevision     uint64                                   `json:"expected_revision,omitempty"`
		AgentName            string                                   `json:"agent_name"`
		BundleDigest         string                                   `json:"bundle_digest"`
		CapsuleDSSEBase64    string                                   `json:"capsule_dsse_base64"`
		DelegationDSSEBase64 string                                   `json:"delegation_dsse_base64"`
		DisruptionBudget     *controlstore.DeploymentDisruptionBudget `json:"disruption_budget,omitempty"`
		Fork                 *controlstore.DeploymentFork             `json:"fork,omitempty"`
	}{
		Generation: input.Generation, ExpectedRevision: input.ExpectedRevision,
		AgentName: input.AgentName, BundleDigest: input.BundleDigest,
		CapsuleDSSEBase64:    base64.StdEncoding.EncodeToString(input.CapsuleDSSE),
		DelegationDSSEBase64: base64.StdEncoding.EncodeToString(input.DelegationDSSE),
		DisruptionBudget:     input.DisruptionBudget,
		Fork:                 input.Fork,
	}, &deployment, true)
	if err != nil {
		return Deployment{}, err
	}
	if err := validateDeploymentResponse(deployment, tenantID, deploymentID); err != nil {
		return Deployment{}, err
	}
	if deployment.Generation != input.Generation || deployment.AgentName != input.AgentName ||
		deployment.BundleDigest != input.BundleDigest || deployment.CapsuleDigest != dsse.Digest(input.CapsuleDSSE) ||
		deployment.DelegationDigest != dsse.Digest(input.DelegationDSSE) {
		return Deployment{}, errors.New("control deployment response changed the requested binding")
	}
	expectedBudget := controlstore.DeploymentDisruptionBudget{MaxUnavailable: 1}
	if input.DisruptionBudget != nil {
		expectedBudget = *input.DisruptionBudget
	}
	if deployment.DisruptionBudget != expectedBudget {
		return Deployment{}, errors.New("control deployment response changed the requested disruption budget")
	}
	if !deploymentForkResponseEqual(deployment.Fork, input.Fork) {
		return Deployment{}, errors.New("control deployment response changed the requested fork")
	}
	return deployment, nil
}

func (c *Client) SetDeploymentRolloutPaused(
	ctx context.Context,
	tenantID, deploymentID string,
	expectedRevision uint64,
	paused bool,
) (Deployment, error) {
	path, err := deploymentPath(tenantID, deploymentID)
	if err != nil {
		return Deployment{}, err
	}
	var deployment Deployment
	err = c.do(ctx, http.MethodPut, path+"/rollout", struct {
		ExpectedRevision uint64 `json:"expected_revision"`
		Paused           bool   `json:"paused"`
	}{ExpectedRevision: expectedRevision, Paused: paused}, &deployment, true)
	if err != nil {
		return Deployment{}, err
	}
	if err := validateDeploymentResponse(deployment, tenantID, deploymentID); err != nil {
		return Deployment{}, err
	}
	if deployment.Rollout == nil || (deployment.Rollout.PausedAt != "") != paused {
		return Deployment{}, errors.New("control deployment response changed the requested rollout state")
	}
	return deployment, nil
}

func deploymentForkResponseEqual(left, right *controlstore.DeploymentFork) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func (c *Client) GetDeployment(ctx context.Context, tenantID, deploymentID string) (Deployment, error) {
	path, err := deploymentPath(tenantID, deploymentID)
	if err != nil {
		return Deployment{}, err
	}
	var deployment Deployment
	if err := c.do(ctx, http.MethodGet, path, nil, &deployment, true); err != nil {
		return Deployment{}, err
	}
	if err := validateDeploymentResponse(deployment, tenantID, deploymentID); err != nil {
		return Deployment{}, err
	}
	return deployment, nil
}

func (c *Client) ListDeployments(
	ctx context.Context,
	tenantID, after string,
	limit int,
) (DeploymentList, error) {
	collection, err := deploymentPath(tenantID, "")
	if err != nil {
		return DeploymentList{}, err
	}
	path, err := paginatedPath(collection, after, limit)
	if err != nil {
		return DeploymentList{}, err
	}
	var page DeploymentList
	if err := c.do(ctx, http.MethodGet, path, nil, &page, true); err != nil {
		return DeploymentList{}, err
	}
	if page.Deployments == nil {
		return DeploymentList{}, errors.New("control deployment page omitted its collection")
	}
	previous := ""
	for _, deployment := range page.Deployments {
		if err := validateDeploymentResponse(deployment, tenantID, deployment.DeploymentID); err != nil {
			return DeploymentList{}, err
		}
		if previous != "" && previous >= deployment.DeploymentID {
			return DeploymentList{}, errors.New("control deployment page is not canonical")
		}
		previous = deployment.DeploymentID
	}
	if page.NextAfter != "" && (len(page.Deployments) == 0 || page.NextAfter != previous) {
		return DeploymentList{}, errors.New("control deployment page cursor is inconsistent")
	}
	return page, nil
}

func (c *Client) ListInstanceEvents(
	ctx context.Context,
	tenantID, after string,
	limit int,
) (InstanceEventList, error) {
	if !validOperationsIdentifier(tenantID, 128, false) || limit <= 0 || limit > 100 {
		return InstanceEventList{}, errors.New("instance event list requires a tenant and limit from 1 to 100")
	}
	path, err := paginatedPath("/v1/tenants/"+url.PathEscape(tenantID)+"/instance-events", after, limit)
	if err != nil {
		return InstanceEventList{}, err
	}
	var page InstanceEventList
	if err := c.do(ctx, http.MethodGet, path, nil, &page, true); err != nil {
		return InstanceEventList{}, err
	}
	if page.Events == nil || len(page.Events) > limit {
		return InstanceEventList{}, errors.New("control instance event page is invalid")
	}
	for _, retained := range page.Events {
		parsed, parseErr := time.Parse(time.RFC3339Nano, retained.ReceivedAt)
		if retained.Event.TenantID != tenantID || retained.Event.Validate() != nil || parseErr != nil ||
			parsed.Format(time.RFC3339Nano) != retained.ReceivedAt {
			return InstanceEventList{}, errors.New("control instance event page contains an invalid event")
		}
	}
	if page.NextAfter != "" && (len(page.Events) == 0 || page.NextAfter != page.Events[len(page.Events)-1].Event.EventID) {
		return InstanceEventList{}, errors.New("control instance event page cursor is inconsistent")
	}
	return page, nil
}

func (c *Client) ListTaskProjections(
	ctx context.Context,
	tenantID, after string,
	limit int,
) (TaskProjectionList, error) {
	if !validOperationsIdentifier(tenantID, 128, false) || limit <= 0 || limit > 100 {
		return TaskProjectionList{}, errors.New("task list requires a tenant and limit from 1 to 100")
	}
	path, err := paginatedPath("/v1/tenants/"+url.PathEscape(tenantID)+"/tasks", after, limit)
	if err != nil {
		return TaskProjectionList{}, err
	}
	var page TaskProjectionList
	if err := c.do(ctx, http.MethodGet, path, nil, &page, true); err != nil {
		return TaskProjectionList{}, err
	}
	if page.Tasks == nil || len(page.Tasks) > limit {
		return TaskProjectionList{}, errors.New("control task page is invalid")
	}
	for index, projection := range page.Tasks {
		if projection.TenantID != tenantID || projection.Validate() != nil {
			return TaskProjectionList{}, errors.New("control task page contains an invalid projection")
		}
		if index > 0 {
			previous := page.Tasks[index-1]
			previousAt, _ := time.Parse(time.RFC3339Nano, previous.LastObservedAt)
			projectionAt, _ := time.Parse(time.RFC3339Nano, projection.LastObservedAt)
			if previousAt.Before(projectionAt) ||
				previous.LastObservedAt == projection.LastObservedAt && previous.ProjectionID <= projection.ProjectionID {
				return TaskProjectionList{}, errors.New("control task page is not canonical")
			}
		}
	}
	if page.NextAfter != "" && (len(page.Tasks) == 0 || page.NextAfter != page.Tasks[len(page.Tasks)-1].ProjectionID) {
		return TaskProjectionList{}, errors.New("control task page cursor is inconsistent")
	}
	return page, nil
}

func (c *Client) SubmitTaskRequest(
	ctx context.Context,
	tenantID, taskPermit string,
	requestBody []byte,
) (controlstore.TaskRequest, error) {
	if !validOperationsIdentifier(tenantID, 128, false) || taskPermit == "" ||
		len(requestBody) == 0 || int64(len(requestBody)) > 64<<10 {
		return controlstore.TaskRequest{}, errors.New("async task submission requires a tenant, permit, and request of at most 64 KiB")
	}
	var task controlstore.TaskRequest
	err := c.do(ctx, http.MethodPost, "/v1/tenants/"+url.PathEscape(tenantID)+"/task-requests", struct {
		TaskPermit    string `json:"task_permit"`
		RequestBase64 string `json:"request_base64"`
	}{TaskPermit: taskPermit, RequestBase64: base64.StdEncoding.EncodeToString(requestBody)}, &task, true)
	if err != nil {
		return controlstore.TaskRequest{}, err
	}
	if task.TenantID != tenantID || task.Validate() != nil {
		return controlstore.TaskRequest{}, errors.New("control async task response is invalid")
	}
	return task, nil
}

func (c *Client) ListTaskRequests(ctx context.Context, tenantID, after string, limit int) (TaskRequestList, error) {
	if !validOperationsIdentifier(tenantID, 128, false) || limit <= 0 || limit > 100 {
		return TaskRequestList{}, errors.New("async task list requires a tenant and limit from 1 to 100")
	}
	path, err := paginatedPath("/v1/tenants/"+url.PathEscape(tenantID)+"/task-requests", after, limit)
	if err != nil {
		return TaskRequestList{}, err
	}
	var page TaskRequestList
	if err := c.do(ctx, http.MethodGet, path, nil, &page, true); err != nil {
		return TaskRequestList{}, err
	}
	if page.Tasks == nil || len(page.Tasks) > limit {
		return TaskRequestList{}, errors.New("control async task page is invalid")
	}
	for index, task := range page.Tasks {
		if task.TenantID != tenantID || task.Validate() != nil {
			return TaskRequestList{}, errors.New("control async task page contains an invalid task")
		}
		if index > 0 {
			previous := page.Tasks[index-1]
			previousAt, _ := time.Parse(time.RFC3339Nano, previous.CreatedAt)
			currentAt, _ := time.Parse(time.RFC3339Nano, task.CreatedAt)
			if previousAt.Before(currentAt) || previous.CreatedAt == task.CreatedAt && previous.TaskID <= task.TaskID {
				return TaskRequestList{}, errors.New("control async task page is not canonical")
			}
		}
	}
	if page.NextAfter != "" && (len(page.Tasks) == 0 || page.NextAfter != page.Tasks[len(page.Tasks)-1].TaskID) {
		return TaskRequestList{}, errors.New("control async task page cursor is inconsistent")
	}
	return page, nil
}

func (c *Client) GetTaskRequest(ctx context.Context, tenantID, taskID string) (controlstore.TaskRequest, error) {
	path, err := taskRequestPath(tenantID, taskID)
	if err != nil {
		return controlstore.TaskRequest{}, err
	}
	var task controlstore.TaskRequest
	if err := c.do(ctx, http.MethodGet, path, nil, &task, true); err != nil {
		return controlstore.TaskRequest{}, err
	}
	if task.TenantID != tenantID || task.TaskID != taskID || task.Validate() != nil {
		return controlstore.TaskRequest{}, errors.New("control async task response is invalid")
	}
	return task, nil
}

type TaskResult struct {
	TaskID        string `json:"task_id"`
	ResultDigest  string `json:"result_digest"`
	ResponseBytes int64  `json:"response_bytes"`
	ResultBase64  string `json:"result_base64"`
}

func (c *Client) GetTaskResult(ctx context.Context, tenantID, taskID string) ([]byte, TaskResult, error) {
	path, err := taskRequestPath(tenantID, taskID)
	if err != nil {
		return nil, TaskResult{}, err
	}
	var result TaskResult
	if err := c.do(ctx, http.MethodGet, path+"/result", nil, &result, true); err != nil {
		return nil, TaskResult{}, err
	}
	raw, err := base64.StdEncoding.DecodeString(result.ResultBase64)
	if err != nil || result.TaskID != taskID || len(raw) == 0 ||
		len(raw) > controlprotocol.MaxExecutorTaskResultBytes ||
		base64.StdEncoding.EncodeToString(raw) != result.ResultBase64 ||
		int64(len(raw)) != result.ResponseBytes || dsse.Digest(raw) != result.ResultDigest {
		return nil, TaskResult{}, errors.New("control async task result is invalid")
	}
	return raw, result, nil
}

func (c *Client) CancelTaskRequest(ctx context.Context, tenantID, taskID string) (controlstore.TaskRequest, error) {
	path, err := taskRequestPath(tenantID, taskID)
	if err != nil {
		return controlstore.TaskRequest{}, err
	}
	var task controlstore.TaskRequest
	if err := c.do(ctx, http.MethodDelete, path, nil, &task, true); err != nil {
		return controlstore.TaskRequest{}, err
	}
	if task.TenantID != tenantID || task.TaskID != taskID || task.Validate() != nil || task.CancelRequestedAt == "" {
		return controlstore.TaskRequest{}, errors.New("control async task cancellation response is invalid")
	}
	return task, nil
}

func taskRequestPath(tenantID, taskID string) (string, error) {
	if !validOperationsIdentifier(tenantID, 128, false) || !validOperationsIdentifier(taskID, 128, false) {
		return "", errors.New("async task identity is invalid")
	}
	return "/v1/tenants/" + url.PathEscape(tenantID) + "/task-requests/" + url.PathEscape(taskID), nil
}

func (c *Client) ListNodePools(ctx context.Context, after string, limit int) (NodePoolList, error) {
	if limit <= 0 || limit > 500 {
		return NodePoolList{}, errors.New("node pool list limit must be between 1 and 500")
	}
	path, err := paginatedPath("/v1/node-pools", after, limit)
	if err != nil {
		return NodePoolList{}, err
	}
	var page NodePoolList
	if err := c.do(ctx, http.MethodGet, path, nil, &page, true); err != nil {
		return NodePoolList{}, err
	}
	if page.NodePools == nil || len(page.NodePools) > limit {
		return NodePoolList{}, errors.New("control node pool page is invalid")
	}
	previous := ""
	for _, status := range page.NodePools {
		if status.Validate() != nil || previous != "" && previous >= status.Pool.ID {
			return NodePoolList{}, errors.New("control node pool page contains an invalid status")
		}
		previous = status.Pool.ID
	}
	if page.NextAfter != "" && (len(page.NodePools) == 0 || page.NextAfter != previous) {
		return NodePoolList{}, errors.New("control node pool page cursor is inconsistent")
	}
	return page, nil
}

func (c *Client) GetNodePool(ctx context.Context, poolID string) (controlstore.NodePoolStatus, error) {
	if !validOperationsIdentifier(poolID, 128, false) {
		return controlstore.NodePoolStatus{}, errors.New("node pool identity is invalid")
	}
	var status controlstore.NodePoolStatus
	if err := c.do(ctx, http.MethodGet, "/v1/node-pools/"+url.PathEscape(poolID), nil, &status, true); err != nil {
		return controlstore.NodePoolStatus{}, err
	}
	if status.Pool.ID != poolID || status.Validate() != nil {
		return controlstore.NodePoolStatus{}, errors.New("control node pool response is invalid")
	}
	return status, nil
}

func (c *Client) ApplyNodePool(
	ctx context.Context,
	poolID string,
	input NodePoolApply,
) (controlstore.NodePoolStatus, error) {
	if !validOperationsIdentifier(poolID, 128, false) {
		return controlstore.NodePoolStatus{}, errors.New("node pool identity is invalid")
	}
	var status controlstore.NodePoolStatus
	err := c.do(ctx, http.MethodPut, "/v1/node-pools/"+url.PathEscape(poolID), struct {
		ExpectedRevision          uint64   `json:"expected_revision"`
		TenantIDs                 []string `json:"tenant_ids"`
		Architecture              string   `json:"architecture,omitempty"`
		MinNodes                  int      `json:"min_nodes"`
		DesiredNodes              int      `json:"desired_nodes"`
		MaxNodes                  int      `json:"max_nodes"`
		MembershipKeyID           string   `json:"membership_key_id,omitempty"`
		MembershipPublicKeyBase64 string   `json:"membership_public_key_base64,omitempty"`
	}{
		ExpectedRevision: input.ExpectedRevision, TenantIDs: input.TenantIDs,
		Architecture: input.Architecture, MinNodes: input.MinNodes,
		DesiredNodes: input.DesiredNodes, MaxNodes: input.MaxNodes,
		MembershipKeyID: input.MembershipKeyID, MembershipPublicKeyBase64: input.MembershipPublicKeyBase64,
	}, &status, true)
	if err != nil {
		return controlstore.NodePoolStatus{}, err
	}
	if status.Pool.ID != poolID || status.Validate() != nil {
		return controlstore.NodePoolStatus{}, errors.New("control node pool response is invalid")
	}
	return status, nil
}

func (c *Client) BindNodePoolMembership(ctx context.Context, envelope json.RawMessage) (NodePoolMembershipBinding, error) {
	if len(envelope) == 0 || len(envelope) > 64<<10 {
		return NodePoolMembershipBinding{}, errors.New("node-pool membership envelope is invalid")
	}
	statement, err := poolmembership.Inspect(envelope)
	if err != nil {
		return NodePoolMembershipBinding{}, errors.New("node-pool membership envelope is invalid")
	}
	var binding NodePoolMembershipBinding
	if err := c.do(ctx, http.MethodPut, "/executor-uplink/pool-membership", struct {
		Membership json.RawMessage `json:"membership"`
	}{Membership: envelope}, &binding, true); err != nil {
		return NodePoolMembershipBinding{}, err
	}
	if binding.NodeID != statement.NodeID || binding.Membership == nil ||
		binding.Membership.PoolID != statement.PoolID ||
		binding.Membership.PoolMembershipGeneration != statement.PoolMembershipGeneration ||
		binding.Membership.PoolCreatedAt != statement.PoolCreatedAt ||
		binding.Membership.Architecture != statement.Architecture ||
		binding.Membership.BootIdentitySHA256 != statement.BootIdentitySHA256 ||
		binding.Membership.SchedulingPolicySHA256 != statement.SchedulingPolicySHA256 ||
		binding.Membership.IssuedAt != statement.IssuedAt || binding.Membership.NotAfter != statement.NotAfter ||
		binding.Membership.Digest != dsse.Digest(envelope) ||
		binding.Membership.EnvelopeBase64 != base64.StdEncoding.EncodeToString(envelope) ||
		!envelopeHasKeyID(envelope, binding.Membership.KeyID) {
		return NodePoolMembershipBinding{}, errors.New("control node-pool membership response is invalid")
	}
	return binding, nil
}

func envelopeHasKeyID(raw []byte, keyID string) bool {
	if keyID == "" {
		return false
	}
	envelope, err := dsse.Parse(raw)
	if err != nil {
		return false
	}
	for _, signature := range envelope.Signatures {
		if signature.KeyID == keyID {
			return true
		}
	}
	return false
}

func (c *Client) DeleteNodePool(ctx context.Context, poolID string, expectedRevision uint64) error {
	if !validOperationsIdentifier(poolID, 128, false) || expectedRevision == 0 {
		return errors.New("node pool deletion requires an identity and nonzero revision")
	}
	return c.do(ctx, http.MethodDelete, "/v1/node-pools/"+url.PathEscape(poolID), struct {
		ExpectedRevision uint64 `json:"expected_revision"`
	}{ExpectedRevision: expectedRevision}, nil, true)
}

func (c *Client) RemoveDeployment(
	ctx context.Context,
	tenantID, deploymentID string,
	expectedRevision uint64,
) (Deployment, error) {
	path, err := deploymentPath(tenantID, deploymentID)
	if err != nil {
		return Deployment{}, err
	}
	if expectedRevision == 0 {
		return Deployment{}, errors.New("deployment removal requires a positive expected revision")
	}
	var deployment Deployment
	if err := c.do(ctx, http.MethodDelete, path, struct {
		ExpectedRevision uint64 `json:"expected_revision"`
	}{ExpectedRevision: expectedRevision}, &deployment, true); err != nil {
		return Deployment{}, err
	}
	if err := validateDeploymentResponse(deployment, tenantID, deploymentID); err != nil {
		return Deployment{}, err
	}
	if deployment.DesiredState != controlstore.DeploymentAbsent {
		return Deployment{}, errors.New("control deployment removal did not retain absent desired state")
	}
	return deployment, nil
}

func (c *Client) RevokeNode(ctx context.Context, nodeID string) (NodeRevocation, error) {
	var revocation NodeRevocation
	err := c.do(ctx, http.MethodDelete, "/v1/nodes/"+url.PathEscape(nodeID), nil, &revocation, true)
	return revocation, err
}

func (c *Client) GetTenantResourceQuota(
	ctx context.Context,
	tenantID string,
) (controlstore.TenantResourceQuotaStatus, error) {
	path, err := tenantResourceQuotaPath(tenantID)
	if err != nil {
		return controlstore.TenantResourceQuotaStatus{}, err
	}
	var status controlstore.TenantResourceQuotaStatus
	if err := c.do(ctx, http.MethodGet, path, nil, &status, true); err != nil {
		return controlstore.TenantResourceQuotaStatus{}, err
	}
	if err := validateTenantResourceQuotaStatus(status, tenantID); err != nil {
		return controlstore.TenantResourceQuotaStatus{}, err
	}
	return status, nil
}

func (c *Client) ChangeTenantResourceQuota(
	ctx context.Context,
	tenantID string,
	action controlstore.TenantQuotaAction,
	expectedRevision uint64,
	resources controlprotocol.ExecutorSchedulingResourcesV1,
) (TenantResourceQuotaChange, error) {
	path, err := tenantResourceQuotaPath(tenantID)
	if err != nil {
		return TenantResourceQuotaChange{}, err
	}
	var change TenantResourceQuotaChange
	if err := c.do(ctx, http.MethodPut, path, struct {
		Action           controlstore.TenantQuotaAction                `json:"action"`
		ExpectedRevision uint64                                        `json:"expected_revision"`
		Resources        controlprotocol.ExecutorSchedulingResourcesV1 `json:"resources"`
	}{Action: action, ExpectedRevision: expectedRevision, Resources: resources}, &change, true); err != nil {
		return TenantResourceQuotaChange{}, err
	}
	if err := validateTenantResourceQuotaStatus(change.Status, tenantID); err != nil {
		return TenantResourceQuotaChange{}, err
	}
	return change, nil
}

func (c *Client) GetOperationalFreeze(
	ctx context.Context,
	tenantID string,
) (controlstore.OperationalFreezeStatus, error) {
	path, err := operationalFreezePath(tenantID)
	if err != nil {
		return controlstore.OperationalFreezeStatus{}, err
	}
	var status controlstore.OperationalFreezeStatus
	if err := c.do(ctx, http.MethodGet, path, nil, &status, true); err != nil {
		return controlstore.OperationalFreezeStatus{}, err
	}
	if err := validateOperationalFreezeStatus(status, tenantID); err != nil {
		return controlstore.OperationalFreezeStatus{}, err
	}
	return status, nil
}

func (c *Client) ChangeOperationalFreeze(
	ctx context.Context,
	tenantID string,
	action controlstore.OperationalFreezeAction,
	expectedRevision uint64,
	reason string,
) (OperationalFreezeChange, error) {
	path, err := operationalFreezePath(tenantID)
	if err != nil {
		return OperationalFreezeChange{}, err
	}
	var change OperationalFreezeChange
	if err := c.do(ctx, http.MethodPut, path, struct {
		Action           controlstore.OperationalFreezeAction `json:"action"`
		ExpectedRevision uint64                               `json:"expected_revision"`
		Reason           string                               `json:"reason,omitempty"`
	}{Action: action, ExpectedRevision: expectedRevision, Reason: reason}, &change, true); err != nil {
		return OperationalFreezeChange{}, err
	}
	if err := validateOperationalFreezeStatus(change.Status, tenantID); err != nil {
		return OperationalFreezeChange{}, err
	}
	return change, nil
}

func (c *Client) GetSnapshotQuarantine(
	ctx context.Context,
	tenantID, nodeID, snapshotID string,
) (controlstore.SnapshotQuarantineStatus, error) {
	path, err := snapshotQuarantinePath(tenantID, nodeID, snapshotID)
	if err != nil {
		return controlstore.SnapshotQuarantineStatus{}, err
	}
	var status controlstore.SnapshotQuarantineStatus
	if err := c.do(ctx, http.MethodGet, path, nil, &status, true); err != nil {
		return controlstore.SnapshotQuarantineStatus{}, err
	}
	if err := validateSnapshotQuarantineStatus(status, tenantID, nodeID, snapshotID); err != nil {
		return controlstore.SnapshotQuarantineStatus{}, err
	}
	return status, nil
}

func (c *Client) ChangeSnapshotQuarantine(
	ctx context.Context,
	tenantID, nodeID, snapshotID string,
	action controlstore.SnapshotQuarantineAction,
	expectedRevision uint64,
	reason string,
) (SnapshotQuarantineChange, error) {
	path, err := snapshotQuarantinePath(tenantID, nodeID, snapshotID)
	if err != nil {
		return SnapshotQuarantineChange{}, err
	}
	var change SnapshotQuarantineChange
	if err := c.do(ctx, http.MethodPut, path, struct {
		Action           controlstore.SnapshotQuarantineAction `json:"action"`
		ExpectedRevision uint64                                `json:"expected_revision"`
		Reason           string                                `json:"reason,omitempty"`
	}{Action: action, ExpectedRevision: expectedRevision, Reason: reason}, &change, true); err != nil {
		return SnapshotQuarantineChange{}, err
	}
	if err := validateSnapshotQuarantineStatus(change.Status, tenantID, nodeID, snapshotID); err != nil {
		return SnapshotQuarantineChange{}, err
	}
	return change, nil
}

func (c *Client) ChangeNodePlacement(
	ctx context.Context,
	nodeID string,
	action controlstore.NodePlacementAction,
	reason string,
) (NodePlacementChange, error) {
	var change NodePlacementChange
	err := c.do(ctx, http.MethodPost, "/v1/nodes/"+url.PathEscape(nodeID)+"/placement", struct {
		Action controlstore.NodePlacementAction `json:"action"`
		Reason string                           `json:"reason,omitempty"`
	}{Action: action, Reason: reason}, &change, true)
	return change, err
}

func (c *Client) StartNodeDrain(ctx context.Context, nodeID, requestID, reason string) (NodeDrainChange, error) {
	var change NodeDrainChange
	err := c.do(ctx, http.MethodPut, "/v1/nodes/"+url.PathEscape(nodeID)+"/drain", struct {
		RequestID string `json:"request_id"`
		Reason    string `json:"reason"`
	}{RequestID: requestID, Reason: reason}, &change, true)
	if err == nil && (change.Node.NodeID != nodeID || change.Node.Drain == nil ||
		change.Node.Drain.RequestID != requestID || change.Node.Drain.State != controlstore.NodeDrainActive) {
		return NodeDrainChange{}, errors.New("control node drain response changed the requested binding")
	}
	return change, err
}

func (c *Client) CancelNodeDrain(ctx context.Context, nodeID, requestID string) (NodeDrainChange, error) {
	var change NodeDrainChange
	err := c.do(ctx, http.MethodDelete, "/v1/nodes/"+url.PathEscape(nodeID)+"/drain", struct {
		RequestID string `json:"request_id"`
	}{RequestID: requestID}, &change, true)
	if err == nil && (change.Node.NodeID != nodeID || change.Node.Drain == nil ||
		change.Node.Drain.RequestID != requestID || change.Node.Drain.State != controlstore.NodeDrainCancelled) {
		return NodeDrainChange{}, errors.New("control node drain cancellation response changed the requested binding")
	}
	return change, err
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
	return c.listAttention(ctx, tenantID, reason, "", cursor, limit)
}

func (c *Client) ListAttentionForResource(ctx context.Context, tenantID, resourceID, cursor string, limit int) (controlstore.AttentionPage, error) {
	return c.listAttention(ctx, tenantID, "", resourceID, cursor, limit)
}

func (c *Client) listAttention(ctx context.Context, tenantID, reason, resourceID, cursor string, limit int) (controlstore.AttentionPage, error) {
	path, err := operationsPath(
		"/v1/operations/attention",
		map[string]string{"tenant_id": tenantID, "reason": reason, "resource_id": resourceID}, nil, cursor, limit,
	)
	if err != nil {
		return controlstore.AttentionPage{}, err
	}
	var page controlstore.AttentionPage
	err = c.do(ctx, http.MethodGet, path, nil, &page, true)
	return page, err
}

// ListIncidentTimeline returns Steward's metadata-only projection of current
// incident-relevant facts. It is retained state, not an append-only audit log.
func (c *Client) ListIncidentTimeline(
	ctx context.Context,
	tenantID, nodeID, kind, severity, cursor string,
	limit int,
) (controlstore.IncidentTimelinePage, error) {
	if kind != "" && kind != string(controlstore.IncidentContainment) &&
		kind != string(controlstore.IncidentEvidence) && kind != string(controlstore.IncidentAccess) &&
		kind != string(controlstore.IncidentWorkload) {
		return controlstore.IncidentTimelinePage{}, errors.New("control incident timeline kind is invalid")
	}
	if severity != "" && severity != string(controlstore.IncidentInfo) &&
		severity != string(controlstore.IncidentWarning) && severity != string(controlstore.IncidentCritical) {
		return controlstore.IncidentTimelinePage{}, errors.New("control incident timeline severity is invalid")
	}
	path, err := operationsPath(
		"/v1/operations/timeline",
		map[string]string{
			"tenant_id": tenantID, "node_id": nodeID, "kind": kind, "severity": severity,
		},
		nil, cursor, limit,
	)
	if err != nil {
		return controlstore.IncidentTimelinePage{}, err
	}
	var page controlstore.IncidentTimelinePage
	if err := c.do(ctx, http.MethodGet, path, nil, &page, true); err != nil {
		return controlstore.IncidentTimelinePage{}, err
	}
	if err := validateIncidentTimelinePage(page, tenantID, nodeID, kind, severity, limit); err != nil {
		return controlstore.IncidentTimelinePage{}, err
	}
	return page, nil
}

func validateIncidentTimelinePage(
	page controlstore.IncidentTimelinePage,
	tenantID, nodeID, kind, severity string,
	limit int,
) error {
	maximum := limit
	if maximum == 0 {
		maximum = 100
	}
	if page.Events == nil || len(page.Events) > maximum {
		return errors.New("control incident timeline returned an invalid page size")
	}
	if page.NextCursor != "" {
		if err := validateOperationsCursor(page.NextCursor); err != nil {
			return err
		}
	}
	seen := make(map[string]struct{}, len(page.Events))
	previous := time.Time{}
	previousID := ""
	for _, event := range page.Events {
		when, err := time.Parse(time.RFC3339Nano, event.OccurredAt)
		if err != nil || when.Format(time.RFC3339Nano) != event.OccurredAt {
			return errors.New("control incident timeline returned a non-canonical timestamp")
		}
		if !previous.IsZero() && (when.After(previous) || when.Equal(previous) && event.ID <= previousID) {
			return errors.New("control incident timeline is not newest-first")
		}
		previous, previousID = when, event.ID
		if !strings.HasPrefix(event.ID, "incident-") || len(event.ID) != len("incident-")+64 ||
			!isLowerHex(event.ID[len("incident-"):]) {
			return errors.New("control incident timeline returned an invalid event ID")
		}
		if _, duplicate := seen[event.ID]; duplicate {
			return errors.New("control incident timeline returned a duplicate event")
		}
		seen[event.ID] = struct{}{}
		if event.Action == "" || event.Kind != controlstore.IncidentContainment && event.Kind != controlstore.IncidentEvidence &&
			event.Kind != controlstore.IncidentAccess && event.Kind != controlstore.IncidentWorkload ||
			event.Severity != controlstore.IncidentInfo && event.Severity != controlstore.IncidentWarning &&
				event.Severity != controlstore.IncidentCritical ||
			event.Scope != "site" && event.Scope != "tenant" ||
			event.Scope == "site" && event.TenantID != "" ||
			event.Scope == "tenant" && event.TenantID == "" {
			return errors.New("control incident timeline returned an invalid classification")
		}
		if !validOperationsIdentifier(event.TenantID, 128, event.Scope == "site") ||
			!validOperationsIdentifier(event.NodeID, 128, true) || !validIncidentAction(event.Action) {
			return errors.New("control incident timeline returned invalid identity metadata")
		}
		for _, field := range []struct {
			name    string
			value   string
			maximum int
		}{
			{"resource_id", event.ResourceID, 512},
			{"reason", event.Reason, 1024},
			{"status", event.Status, 512},
		} {
			if field.value != "" {
				if err := validateOperationsQueryValue(field.name, field.value, field.maximum); err != nil {
					return err
				}
			}
		}
		if tenantID != "" && event.Scope != "site" && event.TenantID != tenantID ||
			nodeID != "" && event.NodeID != nodeID ||
			kind != "" && string(event.Kind) != kind ||
			severity != "" && string(event.Severity) != severity {
			return errors.New("control incident timeline returned an event outside the requested scope")
		}
	}
	return nil
}

func validOperationsIdentifier(value string, maximum int, optional bool) bool {
	if value == "" {
		return optional
	}
	if len(value) > maximum {
		return false
	}
	for index, character := range []byte(value) {
		if character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' ||
			character >= '0' && character <= '9' || index > 0 &&
			(character == '.' || character == '_' || character == '-') {
			continue
		}
		return false
	}
	return true
}

func validIncidentAction(value string) bool {
	if value == "" || len(value) > 128 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, character := range []byte(value[1:]) {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '_' {
			continue
		}
		return false
	}
	return true
}

func isLowerHex(value string) bool {
	for _, character := range value {
		if character < '0' || character > '9' {
			if character < 'a' || character > 'f' {
				return false
			}
		}
	}
	return true
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

func (c *Client) ListAgentInventory(ctx context.Context, tenantID, nodeID, status, cursor string, limit int) (controlstore.AgentInventoryPage, error) {
	path, err := operationsPath(
		"/v1/operations/agents",
		map[string]string{"tenant_id": tenantID, "node_id": nodeID, "status": status},
		nil, cursor, limit,
	)
	if err != nil {
		return controlstore.AgentInventoryPage{}, err
	}
	var page controlstore.AgentInventoryPage
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
	if (!strings.HasPrefix(path, "/v1/") && path != "/executor-uplink/pool-membership") ||
		strings.Contains(path, "//") || strings.ContainsAny(path, "\r\n\x00") {
		return errors.New("invalid control API path")
	}
	if authenticated && c.token == "" {
		return errors.New("control bearer token is required")
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

func deploymentPath(tenantID, deploymentID string) (string, error) {
	if !validEvidenceRouteIdentity(tenantID, 128) {
		return "", errors.New("control deployment tenant identity is invalid")
	}
	path := "/v1/tenants/" + url.PathEscape(tenantID) + "/deployments"
	if deploymentID == "" {
		return path, nil
	}
	if !validEvidenceRouteIdentity(deploymentID, 128) {
		return "", errors.New("control deployment identity is invalid")
	}
	return path + "/" + url.PathEscape(deploymentID), nil
}

func operationalFreezePath(tenantID string) (string, error) {
	if tenantID == "" {
		return "/v1/operations/freeze", nil
	}
	if !validEvidenceRouteIdentity(tenantID, 128) {
		return "", errors.New("control freeze tenant identity is invalid")
	}
	return "/v1/tenants/" + url.PathEscape(tenantID) + "/freeze", nil
}

func tenantResourceQuotaPath(tenantID string) (string, error) {
	if !validEvidenceRouteIdentity(tenantID, 128) {
		return "", errors.New("control quota tenant identity is invalid")
	}
	return "/v1/tenants/" + url.PathEscape(tenantID) + "/quota", nil
}

func snapshotQuarantinePath(tenantID, nodeID, snapshotID string) (string, error) {
	if !validEvidenceRouteIdentity(tenantID, 128) || !validEvidenceRouteIdentity(nodeID, 128) ||
		!validEvidenceRouteIdentity(snapshotID, 128) {
		return "", errors.New("control snapshot quarantine identity is invalid")
	}
	return "/v1/tenants/" + url.PathEscape(tenantID) + "/nodes/" + url.PathEscape(nodeID) +
		"/snapshots/" + url.PathEscape(snapshotID) + "/quarantine", nil
}

func validateSnapshotQuarantineStatus(
	status controlstore.SnapshotQuarantineStatus,
	tenantID, nodeID, snapshotID string,
) error {
	if status.TenantID != tenantID || status.NodeID != nodeID || status.SnapshotID != snapshotID ||
		status.Blocked != (status.Record != nil && status.Record.Quarantined) {
		return errors.New("control snapshot quarantine response changed route identity or effective state")
	}
	if status.Record == nil {
		return nil
	}
	record := status.Record
	if record.TenantID != tenantID || record.NodeID != nodeID || record.SnapshotID != snapshotID ||
		record.Revision == 0 || record.ChangedAt == "" ||
		record.Quarantined && (record.Reason == "" || len(record.Reason) > 256 ||
			strings.TrimSpace(record.Reason) != record.Reason || !utf8.ValidString(record.Reason) ||
			strings.ContainsAny(record.Reason, "\r\n\x00")) ||
		!record.Quarantined && record.Reason != "" {
		return errors.New("control snapshot quarantine response contains an invalid record")
	}
	changed, err := time.Parse(time.RFC3339Nano, record.ChangedAt)
	if err != nil || record.ChangedAt != changed.UTC().Format(time.RFC3339Nano) {
		return errors.New("control snapshot quarantine response contains an invalid timestamp")
	}
	return nil
}

func validateTenantResourceQuotaStatus(status controlstore.TenantResourceQuotaStatus, tenantID string) error {
	if status.TenantID != tenantID || !validNonnegativeSchedulingResources(status.Usage) {
		return errors.New("control quota response has an invalid tenant or usage")
	}
	expectedOverQuota := false
	if status.Quota != nil {
		quota := status.Quota
		if quota.Revision == 0 || quota.ChangedAt == "" {
			return errors.New("control quota response has an invalid retained quota")
		}
		if _, err := time.Parse(time.RFC3339Nano, quota.ChangedAt); err != nil {
			return errors.New("control quota response has an invalid retained quota")
		}
		if quota.Enabled {
			if !validPositiveSchedulingResources(quota.Resources) {
				return errors.New("control quota response has an invalid retained quota")
			}
			expectedOverQuota = schedulingResourcesExceed(status.Usage, quota.Resources)
		} else if quota.Resources != (controlprotocol.ExecutorSchedulingResourcesV1{}) {
			return errors.New("control quota response has an invalid retained quota")
		}
	}
	// A true server signal is conservative: it can also mean resource
	// accounting overflowed before producing a complete usage total. A false
	// signal is safe only when the returned usage independently stays within
	// every enabled limit.
	if expectedOverQuota && !status.OverQuota {
		return errors.New("control quota response has inconsistent usage state")
	}
	return nil
}

func validNonnegativeSchedulingResources(resources controlprotocol.ExecutorSchedulingResourcesV1) bool {
	return resources.MemoryBytes >= 0 && resources.CPUMillis >= 0 && resources.PIDs >= 0 && resources.Workloads >= 0
}

func validPositiveSchedulingResources(resources controlprotocol.ExecutorSchedulingResourcesV1) bool {
	return resources.MemoryBytes > 0 && resources.CPUMillis > 0 &&
		resources.CPUMillis <= math.MaxInt64/1_000_000 && resources.PIDs > 0 && resources.Workloads > 0
}

func schedulingResourcesExceed(
	used, maximum controlprotocol.ExecutorSchedulingResourcesV1,
) bool {
	return used.MemoryBytes > maximum.MemoryBytes || used.CPUMillis > maximum.CPUMillis ||
		used.PIDs > maximum.PIDs || used.Workloads > maximum.Workloads
}

func validateOperationalFreezeStatus(status controlstore.OperationalFreezeStatus, tenantID string) error {
	if tenantID == "" && status.Tenant != nil ||
		status.Site != nil && !validOperationalFreezeRecord(*status.Site, controlstore.OperationalFreezeSite, "") ||
		status.Tenant != nil && !validOperationalFreezeRecord(*status.Tenant, controlstore.OperationalFreezeTenant, tenantID) {
		return errors.New("control freeze response has an invalid scope or record")
	}
	var expected *controlstore.OperationalFreeze
	if status.Site != nil && status.Site.Frozen {
		expected = status.Site
	} else if status.Tenant != nil && status.Tenant.Frozen {
		expected = status.Tenant
	}
	if expected == nil && status.Effective != nil || expected != nil && (status.Effective == nil || *status.Effective != *expected) {
		return errors.New("control freeze response has an inconsistent effective gate")
	}
	return nil
}

func validOperationalFreezeRecord(
	record controlstore.OperationalFreeze,
	scope controlstore.OperationalFreezeScope,
	tenantID string,
) bool {
	if record.Scope != scope || record.TenantID != tenantID || record.Revision == 0 || record.ChangedAt == "" {
		return false
	}
	if _, err := time.Parse(time.RFC3339Nano, record.ChangedAt); err != nil {
		return false
	}
	return record.Frozen && record.Reason != "" || !record.Frozen && record.Reason == ""
}

func validateDeploymentResponse(deployment Deployment, tenantID, deploymentID string) error {
	if deployment.TenantID != tenantID || deployment.DeploymentID != deploymentID ||
		!validEvidenceRouteIdentity(deployment.TenantID, 128) ||
		!validEvidenceRouteIdentity(deployment.DeploymentID, 128) ||
		!validEvidenceRouteIdentity(deployment.AgentName, 128) ||
		!controlprotocol.ValidSHA256Digest(deployment.BundleDigest) ||
		!controlprotocol.ValidSHA256Digest(deployment.CapsuleDigest) ||
		!controlprotocol.ValidSHA256Digest(deployment.DelegationDigest) ||
		!validEvidenceRouteIdentity(deployment.DelegationID, 128) ||
		!validEvidenceRouteIdentity(deployment.ControllerKeyID, 256) ||
		deployment.Generation == 0 || deployment.Revision == 0 || deployment.ClaimGeneration == 0 ||
		deployment.AllowedNodeIDs == nil || deployment.Instances == nil {
		return errors.New("control deployment response identity is invalid")
	}
	if deployment.DisruptionBudget.MaxUnavailable < 0 ||
		deployment.DisruptionBudget.MaxUnavailable > len(deployment.Instances) {
		return errors.New("control deployment response disruption budget is invalid")
	}
	sourceCapsuleDigest := ""
	rolloutStarted := time.Time{}
	if deployment.Rollout != nil {
		rollout := deployment.Rollout
		if rollout.SourceGeneration == 0 || rollout.SourceGeneration >= deployment.Generation ||
			!validEvidenceRouteIdentity(rollout.SourceAgentName, 128) ||
			!controlprotocol.ValidSHA256Digest(rollout.SourceBundleDigest) ||
			!controlprotocol.ValidSHA256Digest(rollout.SourceCapsuleDigest) ||
			!controlprotocol.ValidSHA256Digest(rollout.SourceDelegationDigest) {
			return errors.New("control deployment response rollout is invalid")
		}
		var err error
		rolloutStarted, err = time.Parse(time.RFC3339Nano, rollout.StartedAt)
		if err != nil {
			return errors.New("control deployment response rollout timestamp is invalid")
		}
		if rollout.PausedAt != "" {
			paused, err := time.Parse(time.RFC3339Nano, rollout.PausedAt)
			if err != nil || paused.Before(rolloutStarted) {
				return errors.New("control deployment response rollout pause is invalid")
			}
		}
		sourceCapsuleDigest = rollout.SourceCapsuleDigest
	}
	for index, nodeID := range deployment.AllowedNodeIDs {
		if !validEvidenceRouteIdentity(nodeID, 128) || index > 0 && deployment.AllowedNodeIDs[index-1] >= nodeID {
			return errors.New("control deployment response node scope is not canonical")
		}
	}
	for index, instance := range deployment.Instances {
		if !validEvidenceRouteIdentity(instance.InstanceID, 256) ||
			!validEvidenceRouteIdentity(instance.LineageID, 256) || instance.Generation == 0 ||
			index > 0 && deployment.Instances[index-1].InstanceID >= instance.InstanceID {
			return errors.New("control deployment response instance set is not canonical")
		}
		if instance.Placement != nil && !validDeploymentPlacement(*instance.Placement, instance.NodeID) {
			return errors.New("control deployment response placement decision is invalid")
		}
		if instance.Rollout != nil {
			if deployment.Rollout == nil ||
				instance.Rollout.Stage != "draining" && instance.Rollout.Stage != "deploying" {
				return errors.New("control deployment response instance rollout is invalid")
			}
			started, err := time.Parse(time.RFC3339Nano, instance.Rollout.StartedAt)
			if err != nil || started.Before(rolloutStarted) {
				return errors.New("control deployment response instance rollout timestamp is invalid")
			}
		}
		if instance.Intent != nil {
			if err := instance.Intent.Validate(admission.AuthenticatedIdentity{
				TenantID: instance.Intent.TenantID,
				NodeID:   instance.Intent.NodeID,
			}); err != nil || instance.Intent.TenantID != deployment.TenantID ||
				instance.Intent.NodeID != instance.NodeID || instance.Intent.InstanceID != instance.InstanceID ||
				instance.Intent.LineageID != instance.LineageID || instance.Intent.Generation != instance.Generation ||
				instance.Intent.CapsuleDigest != deployment.CapsuleDigest &&
					instance.Intent.CapsuleDigest != sourceCapsuleDigest {
				return errors.New("control deployment response instance intent is invalid")
			}
		}
		if instance.Admission != nil {
			if instance.Intent == nil || instance.Admission.Validate() != nil ||
				instance.Admission.Generation != instance.Generation ||
				instance.Admission.CapsuleDigest != instance.Intent.CapsuleDigest {
				return errors.New("control deployment response admission projection is invalid")
			}
		}
		switch instance.Phase {
		case controlstore.DeploymentInstancePending, controlstore.DeploymentInstanceCloning,
			controlstore.DeploymentInstanceCloned, controlstore.DeploymentInstanceAdmitting,
			controlstore.DeploymentInstanceStarting, controlstore.DeploymentInstanceRunning,
			controlstore.DeploymentInstanceStopping, controlstore.DeploymentInstanceDestroying,
			controlstore.DeploymentInstancePurging, controlstore.DeploymentInstanceRemoved,
			controlstore.DeploymentInstanceFailed:
		default:
			return errors.New("control deployment response instance phase is invalid")
		}
	}
	created, createdErr := time.Parse(time.RFC3339Nano, deployment.CreatedAt)
	updated, updatedErr := time.Parse(time.RFC3339Nano, deployment.UpdatedAt)
	expires, expiresErr := time.Parse(time.RFC3339Nano, deployment.DelegationExpiresAt)
	if createdErr != nil || updatedErr != nil || expiresErr != nil || updated.Before(created) || !expires.After(created) {
		return errors.New("control deployment response timestamps are invalid")
	}
	if deployment.Fork != nil {
		fork := deployment.Fork
		sourceAllowed := false
		for _, nodeID := range deployment.AllowedNodeIDs {
			if nodeID == fork.SourceNodeID {
				sourceAllowed = true
			}
		}
		if len(deployment.Instances) != 1 || !validEvidenceRouteIdentity(fork.SnapshotID, 128) ||
			!validEvidenceRouteIdentity(fork.SourceLineageID, 256) ||
			!validEvidenceRouteIdentity(fork.SourceNodeID, 128) || !sourceAllowed ||
			fork.SourceLineageID == deployment.Instances[0].LineageID || deployment.Rollout != nil {
			return errors.New("control deployment response fork is invalid")
		}
		if fork.ExpiresAt != "" {
			forkExpiry, err := time.Parse(time.RFC3339Nano, fork.ExpiresAt)
			if err != nil || !forkExpiry.After(created) || forkExpiry.After(created.Add(30*24*time.Hour)) ||
				forkExpiry.Add(controlstore.MinDeploymentForkCleanupWindow).After(expires) {
				return errors.New("control deployment response fork expiry is invalid")
			}
		}
	}
	if deployment.DesiredState != controlstore.DeploymentRunning &&
		deployment.DesiredState != controlstore.DeploymentAbsent {
		return errors.New("control deployment response desired state is invalid")
	}
	switch deployment.Phase {
	case controlstore.DeploymentPending, controlstore.DeploymentReconciling, controlstore.DeploymentReady,
		controlstore.DeploymentStopping, controlstore.DeploymentRemoved, controlstore.DeploymentDegraded:
		return nil
	default:
		return errors.New("control deployment response phase is invalid")
	}
}

func validDeploymentPlacement(placement controlstore.DeploymentPlacementDecision, nodeID string) bool {
	if placement.NodeID != nodeID || !validEvidenceRouteIdentity(placement.NodeID, 128) ||
		placement.PreferredLabelMatches == nil || len(placement.PreferredLabelMatches) > 32 ||
		placement.PreferredLabelCount < len(placement.PreferredLabelMatches) || placement.PreferredLabelCount > 32 ||
		placement.SameDeploymentInSpreadDomain < 0 || placement.AssignedWorkloads < 0 {
		return false
	}
	if _, err := time.Parse(time.RFC3339Nano, placement.DecidedAt); err != nil {
		return false
	}
	if placement.ImageConfigDigest == "" {
		if placement.ImageLocal || placement.ImageLocalityReported {
			return false
		}
	} else if !controlprotocol.ValidSHA256Digest(placement.ImageConfigDigest) ||
		placement.ImageLocal && !placement.ImageLocalityReported {
		return false
	}
	for index, key := range placement.PreferredLabelMatches {
		if !controlprotocol.ValidSchedulingAttribute(key) ||
			index > 0 && placement.PreferredLabelMatches[index-1] >= key {
			return false
		}
	}
	if placement.SpreadBy == "" {
		return placement.SpreadValue == "" && !placement.SpreadLabelPresent &&
			placement.SameDeploymentInSpreadDomain == 0
	}
	return controlprotocol.ValidSchedulingAttribute(placement.SpreadBy) &&
		(placement.SpreadLabelPresent && controlprotocol.ValidSchedulingAttribute(placement.SpreadValue) ||
			!placement.SpreadLabelPresent && placement.SpreadValue == "")
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
