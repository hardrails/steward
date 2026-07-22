package mcpserver

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/controlauth"
	"github.com/hardrails/steward/internal/controlclient"
	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/controlstore"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/taskpermit"
)

// maxControlCommandBytes leaves room for the canonical base64 value and its
// JSON field inside the control API's 1 MiB request limit. It still covers the
// largest valid single-signature Executor command envelope.
const maxControlCommandBytes = 720 << 10

// Control is the non-secret-bearing part of Steward's public control-plane
// client. Operator and enrollment credential issuance are intentionally not
// reachable through MCP.
type Control interface {
	ListTenants(context.Context, string, int) (controlclient.TenantList, error)
	CreateTenant(context.Context, string) (controlclient.Tenant, error)
	ListNodes(context.Context, string, string, int) (controlclient.NodeList, error)
	ListInstanceEvents(context.Context, string, string, int) (controlclient.InstanceEventList, error)
	ListTaskProjections(context.Context, string, string, int) (controlclient.TaskProjectionList, error)
	ListTaskRequests(context.Context, string, string, int) (controlclient.TaskRequestList, error)
	GetTaskRequest(context.Context, string, string) (controlstore.TaskRequest, error)
	SubmitTaskRequest(context.Context, string, string, []byte) (controlstore.TaskRequest, error)
	CancelTaskRequest(context.Context, string, string) (controlstore.TaskRequest, error)
	ListNodePools(context.Context, string, int) (controlclient.NodePoolList, error)
	GetNodePool(context.Context, string) (controlstore.NodePoolStatus, error)
	GetNode(context.Context, string, string) (controlclient.Node, error)
	RevokeNode(context.Context, string) (controlclient.NodeRevocation, error)
	SubmitCommand(context.Context, string, string, []byte) (controlclient.Command, error)
	GetCommand(context.Context, string, string, string) (controlclient.Command, error)
	GetOperationsSummary(context.Context, string) (controlstore.OperationsSummary, error)
	ListAttention(context.Context, string, string, string, int) (controlstore.AttentionPage, error)
	ListIncidentTimeline(context.Context, string, string, string, string, string, int) (controlstore.IncidentTimelinePage, error)
	ListAgentInventory(context.Context, string, string, string, string, int) (controlstore.AgentInventoryPage, error)
	ListCommandInventory(context.Context, string, string, string, string, string, int) (controlstore.CommandInventoryPage, error)
	ListCredentialInventory(context.Context, string, string, string, string, *bool, string, int) (controlstore.CredentialInventoryPage, error)
	InspectExecutorEvidence(context.Context, string) (controlprotocol.ExecutorEvidenceInspectionV1, error)
}

type controlListArgs struct {
	After string `json:"after,omitempty"`
	Limit int    `json:"limit,omitempty"`
}

type controlTenantCreateArgs struct {
	TenantID                  string `json:"tenant_id"`
	AcknowledgeTenantCreation bool   `json:"acknowledge_tenant_creation"`
}

type controlNodeListArgs struct {
	TenantID string `json:"tenant_id"`
	After    string `json:"after,omitempty"`
	Limit    int    `json:"limit,omitempty"`
}

type controlEventListArgs struct {
	TenantID string `json:"tenant_id"`
	After    string `json:"after,omitempty"`
	Limit    int    `json:"limit,omitempty"`
}

type controlTaskListArgs struct {
	TenantID string `json:"tenant_id"`
	After    string `json:"after,omitempty"`
	Limit    int    `json:"limit,omitempty"`
}

type controlTaskRequestStatusArgs struct {
	TenantID string `json:"tenant_id"`
	TaskID   string `json:"task_id"`
}

type controlTaskRequestSubmitArgs struct {
	TenantID                  string `json:"tenant_id"`
	TaskPermit                string `json:"task_permit"`
	RequestBase64             string `json:"request_base64"`
	AcknowledgeTaskSubmission bool   `json:"acknowledge_task_submission"`
}

type controlTaskRequestCancelArgs struct {
	TenantID                    string `json:"tenant_id"`
	TaskID                      string `json:"task_id"`
	AcknowledgeTaskCancellation bool   `json:"acknowledge_task_cancellation"`
}

type controlNodeStatusArgs struct {
	TenantID string `json:"tenant_id"`
	NodeID   string `json:"node_id"`
}

type controlNodePoolStatusArgs struct {
	PoolID string `json:"pool_id"`
}

type controlNodeRevokeArgs struct {
	NodeID                    string `json:"node_id"`
	AcknowledgeNodeRevocation bool   `json:"acknowledge_node_revocation"`
}

type controlCommandSubmitArgs struct {
	TenantID                     string `json:"tenant_id"`
	NodeID                       string `json:"node_id"`
	CommandDSSEBase64            string `json:"command_dsse_base64"`
	AcknowledgeCommandSubmission bool   `json:"acknowledge_command_submission"`
}

type controlCommandStatusArgs struct {
	TenantID  string `json:"tenant_id"`
	NodeID    string `json:"node_id"`
	CommandID string `json:"command_id"`
}

type controlOperationsSummaryArgs struct {
	TenantID string `json:"tenant_id,omitempty"`
}

type controlAttentionListArgs struct {
	TenantID string `json:"tenant_id,omitempty"`
	Reason   string `json:"reason,omitempty"`
	Cursor   string `json:"cursor,omitempty"`
	Limit    int    `json:"limit,omitempty"`
}

type controlIncidentTimelineArgs struct {
	TenantID string `json:"tenant_id,omitempty"`
	NodeID   string `json:"node_id,omitempty"`
	Kind     string `json:"kind,omitempty"`
	Severity string `json:"severity,omitempty"`
	Cursor   string `json:"cursor,omitempty"`
	Limit    int    `json:"limit,omitempty"`
}

type controlCommandListArgs struct {
	TenantID       string `json:"tenant_id,omitempty"`
	NodeID         string `json:"node_id,omitempty"`
	State          string `json:"state,omitempty"`
	TerminalStatus string `json:"terminal_status,omitempty"`
	Cursor         string `json:"cursor,omitempty"`
	Limit          int    `json:"limit,omitempty"`
}

type controlAgentListArgs struct {
	TenantID string `json:"tenant_id,omitempty"`
	NodeID   string `json:"node_id,omitempty"`
	Status   string `json:"status,omitempty"`
	Cursor   string `json:"cursor,omitempty"`
	Limit    int    `json:"limit,omitempty"`
}

type controlCredentialListArgs struct {
	TenantID string `json:"tenant_id,omitempty"`
	Kind     string `json:"kind,omitempty"`
	Role     string `json:"role,omitempty"`
	NodeID   string `json:"node_id,omitempty"`
	Revoked  string `json:"revoked,omitempty"`
	Cursor   string `json:"cursor,omitempty"`
	Limit    int    `json:"limit,omitempty"`
}

type controlEvidenceStatusArgs struct {
	NodeID string `json:"node_id"`
}

type controlEvidenceStatusResult struct {
	ProtocolVersion      int                                      `json:"protocol_version"`
	ControllerInstanceID string                                   `json:"controller_instance_id"`
	ControlNodeID        string                                   `json:"control_node_id"`
	ReceiptIdentity      *controlEvidenceReceiptIdentity          `json:"receipt_identity,omitempty"`
	Status               controlprotocol.ExecutorEvidenceStatusV1 `json:"status"`
}

type controlEvidenceReceiptIdentity struct {
	EnrollmentID    string `json:"enrollment_id"`
	Stream          string `json:"stream"`
	ReceiptNodeID   string `json:"receipt_node_id"`
	ReceiptEpoch    uint64 `json:"receipt_epoch"`
	PublicKeySHA256 string `json:"public_key_sha256"`
}

func (s *Server) callControlTool(ctx context.Context, name string, raw []byte) (any, error) {
	switch name {
	case "steward_control_tenant_list":
		var arguments controlListArgs
		if decodeArguments(raw, &arguments) != nil || !validControlPage(arguments.After, arguments.Limit) {
			return nil, errors.New("steward_control_tenant_list accepts only an optional bounded after cursor and limit")
		}
		result, err := s.control.ListTenants(ctx, arguments.After, arguments.Limit)
		if err != nil {
			return nil, controlFailure("tenant list", err)
		}
		return result, nil
	case "steward_control_tenant_create":
		var arguments controlTenantCreateArgs
		if decodeArguments(raw, &arguments) != nil || !validControlIdentifier(arguments.TenantID, 128) || !arguments.AcknowledgeTenantCreation {
			return nil, errors.New("steward_control_tenant_create requires tenant_id and acknowledge_tenant_creation=true")
		}
		result, err := s.control.CreateTenant(ctx, arguments.TenantID)
		if err != nil {
			return nil, controlFailure("tenant creation", err)
		}
		return result, nil
	case "steward_control_event_list":
		var arguments controlEventListArgs
		if decodeArguments(raw, &arguments) != nil || !validControlIdentifier(arguments.TenantID, 128) ||
			!validControlEventCursor(arguments.After) || !validControlPage(arguments.After, arguments.Limit) || arguments.Limit > 100 {
			return nil, errors.New("steward_control_event_list requires tenant_id and accepts only a bounded event cursor and limit up to 100")
		}
		limit := arguments.Limit
		if limit == 0 {
			limit = 100
		}
		result, err := s.control.ListInstanceEvents(ctx, arguments.TenantID, arguments.After, limit)
		if err != nil {
			return nil, controlFailure("instance event list", err)
		}
		return result, nil
	case "steward_control_task_list":
		var arguments controlTaskListArgs
		if decodeArguments(raw, &arguments) != nil || !validControlIdentifier(arguments.TenantID, 128) ||
			!validControlTaskCursor(arguments.After) || !validControlPage(arguments.After, arguments.Limit) || arguments.Limit > 100 {
			return nil, errors.New("steward_control_task_list requires tenant_id and accepts only a bounded task projection cursor and limit up to 100")
		}
		limit := arguments.Limit
		if limit == 0 {
			limit = 100
		}
		result, err := s.control.ListTaskProjections(ctx, arguments.TenantID, arguments.After, limit)
		if err != nil {
			return nil, controlFailure("task projection list", err)
		}
		return result, nil
	case "steward_control_task_request_list":
		var arguments controlTaskListArgs
		if decodeArguments(raw, &arguments) != nil || !validControlIdentifier(arguments.TenantID, 128) ||
			!validControlPage(arguments.After, arguments.Limit) || arguments.Limit > 100 {
			return nil, errors.New("steward_control_task_request_list requires tenant_id and accepts only a bounded task ID cursor and limit up to 100")
		}
		limit := arguments.Limit
		if limit == 0 {
			limit = 100
		}
		result, err := s.control.ListTaskRequests(ctx, arguments.TenantID, arguments.After, limit)
		if err != nil {
			return nil, controlFailure("task request list", err)
		}
		return result, nil
	case "steward_control_task_request_status":
		var arguments controlTaskRequestStatusArgs
		if decodeArguments(raw, &arguments) != nil || !validControlIdentifier(arguments.TenantID, 128) ||
			!validControlIdentifier(arguments.TaskID, 128) {
			return nil, errors.New("steward_control_task_request_status requires tenant_id and task_id")
		}
		result, err := s.control.GetTaskRequest(ctx, arguments.TenantID, arguments.TaskID)
		if err != nil {
			return nil, controlFailure("task request status", err)
		}
		return result, nil
	case "steward_control_task_request_submit":
		var arguments controlTaskRequestSubmitArgs
		if decodeArguments(raw, &arguments) != nil || !validControlIdentifier(arguments.TenantID, 128) ||
			!arguments.AcknowledgeTaskSubmission {
			return nil, errors.New("steward_control_task_request_submit requires tenant_id, task_permit, request_base64, and acknowledge_task_submission=true")
		}
		permit, err := taskpermit.DecodeHeader(arguments.TaskPermit)
		if err != nil {
			return nil, errors.New("task_permit must be one canonical bounded task permit")
		}
		if _, err := taskpermit.InspectUnverified(permit); err != nil {
			return nil, errors.New("task_permit must be one canonical bounded task permit")
		}
		request, err := decodeControlTaskRequest(arguments.RequestBase64)
		if err != nil {
			return nil, err
		}
		result, err := s.control.SubmitTaskRequest(ctx, arguments.TenantID, arguments.TaskPermit, request)
		if err != nil {
			return nil, controlFailure("task request submission", err)
		}
		return result, nil
	case "steward_control_task_request_cancel":
		var arguments controlTaskRequestCancelArgs
		if decodeArguments(raw, &arguments) != nil || !validControlIdentifier(arguments.TenantID, 128) ||
			!validControlIdentifier(arguments.TaskID, 128) || !arguments.AcknowledgeTaskCancellation {
			return nil, errors.New("steward_control_task_request_cancel requires tenant_id, task_id, and acknowledge_task_cancellation=true")
		}
		result, err := s.control.CancelTaskRequest(ctx, arguments.TenantID, arguments.TaskID)
		if err != nil {
			return nil, controlFailure("task request cancellation", err)
		}
		return result, nil
	case "steward_control_node_list":
		var arguments controlNodeListArgs
		if decodeArguments(raw, &arguments) != nil || !validControlIdentifier(arguments.TenantID, 128) ||
			!validControlPage(arguments.After, arguments.Limit) {
			return nil, errors.New("steward_control_node_list requires tenant_id and accepts only a bounded after cursor and limit")
		}
		result, err := s.control.ListNodes(ctx, arguments.TenantID, arguments.After, arguments.Limit)
		if err != nil {
			return nil, controlFailure("node list", err)
		}
		return result, nil
	case "steward_control_node_status":
		var arguments controlNodeStatusArgs
		if decodeArguments(raw, &arguments) != nil || !validControlIdentifier(arguments.TenantID, 128) ||
			!validControlIdentifier(arguments.NodeID, 128) {
			return nil, errors.New("steward_control_node_status requires tenant_id and node_id")
		}
		result, err := s.control.GetNode(ctx, arguments.TenantID, arguments.NodeID)
		if err != nil {
			return nil, controlFailure("node status", err)
		}
		return result, nil
	case "steward_control_node_pool_list":
		var arguments controlListArgs
		if decodeArguments(raw, &arguments) != nil || !validControlPage(arguments.After, arguments.Limit) {
			return nil, errors.New("steward_control_node_pool_list accepts only an optional bounded after cursor and limit")
		}
		limit := arguments.Limit
		if limit == 0 {
			limit = 100
		}
		result, err := s.control.ListNodePools(ctx, arguments.After, limit)
		if err != nil {
			return nil, controlFailure("node pool list", err)
		}
		return result, nil
	case "steward_control_node_pool_status":
		var arguments controlNodePoolStatusArgs
		if decodeArguments(raw, &arguments) != nil || !validControlIdentifier(arguments.PoolID, 128) {
			return nil, errors.New("steward_control_node_pool_status requires pool_id")
		}
		result, err := s.control.GetNodePool(ctx, arguments.PoolID)
		if err != nil {
			return nil, controlFailure("node pool status", err)
		}
		return result, nil
	case "steward_control_node_revoke":
		var arguments controlNodeRevokeArgs
		if decodeArguments(raw, &arguments) != nil || !validControlIdentifier(arguments.NodeID, 128) || !arguments.AcknowledgeNodeRevocation {
			return nil, errors.New("steward_control_node_revoke requires node_id and acknowledge_node_revocation=true")
		}
		result, err := s.control.RevokeNode(ctx, arguments.NodeID)
		if err != nil {
			return nil, controlFailure("node revocation", err)
		}
		return result, nil
	case "steward_control_command_submit":
		var arguments controlCommandSubmitArgs
		if decodeArguments(raw, &arguments) != nil || !validControlIdentifier(arguments.TenantID, 128) ||
			!validControlIdentifier(arguments.NodeID, 128) || !arguments.AcknowledgeCommandSubmission {
			return nil, errors.New("steward_control_command_submit requires tenant_id, node_id, command_dsse_base64, and acknowledge_command_submission=true")
		}
		command, err := decodeControlCommand(arguments.CommandDSSEBase64)
		if err != nil {
			return nil, err
		}
		result, err := s.control.SubmitCommand(ctx, arguments.TenantID, arguments.NodeID, command)
		if err != nil {
			return nil, controlFailure("command submission", err)
		}
		return result, nil
	case "steward_control_command_status":
		var arguments controlCommandStatusArgs
		if decodeArguments(raw, &arguments) != nil || !validControlIdentifier(arguments.TenantID, 128) ||
			!validControlIdentifier(arguments.NodeID, 128) || !validControlIdentifier(arguments.CommandID, 256) {
			return nil, errors.New("steward_control_command_status requires tenant_id, node_id, and command_id")
		}
		result, err := s.control.GetCommand(ctx, arguments.TenantID, arguments.NodeID, arguments.CommandID)
		if err != nil {
			return nil, controlFailure("command status", err)
		}
		return result, nil
	case "steward_control_operations_summary":
		var arguments controlOperationsSummaryArgs
		if decodeArguments(raw, &arguments) != nil ||
			!validOptionalControlIdentifier(arguments.TenantID, 128) {
			return nil, errors.New("steward_control_operations_summary accepts only an optional bounded tenant_id")
		}
		result, err := s.control.GetOperationsSummary(ctx, arguments.TenantID)
		if err != nil {
			return nil, controlFailure("operations summary", err)
		}
		return result, nil
	case "steward_control_attention_list":
		var arguments controlAttentionListArgs
		if decodeArguments(raw, &arguments) != nil ||
			!validOptionalControlIdentifier(arguments.TenantID, 128) ||
			!validControlAttentionReason(arguments.Reason) ||
			!validControlInventoryPage(arguments.Cursor, arguments.Limit) {
			return nil, errors.New("steward_control_attention_list accepts only bounded tenant_id, reason, cursor, and limit")
		}
		result, err := s.control.ListAttention(
			ctx, arguments.TenantID, arguments.Reason, arguments.Cursor, arguments.Limit,
		)
		if err != nil {
			return nil, controlFailure("attention list", err)
		}
		return result, nil
	case "steward_control_incident_timeline":
		var arguments controlIncidentTimelineArgs
		if decodeArguments(raw, &arguments) != nil ||
			!validOptionalControlIdentifier(arguments.TenantID, 128) ||
			!validOptionalControlIdentifier(arguments.NodeID, 128) ||
			!validControlIncidentKind(arguments.Kind) ||
			!validControlIncidentSeverity(arguments.Severity) ||
			!validControlInventoryPage(arguments.Cursor, arguments.Limit) {
			return nil, errors.New("steward_control_incident_timeline accepts only bounded tenant, node, category, severity, cursor, and limit")
		}
		result, err := s.control.ListIncidentTimeline(
			ctx, arguments.TenantID, arguments.NodeID, arguments.Kind,
			arguments.Severity, arguments.Cursor, arguments.Limit,
		)
		if err != nil {
			return nil, controlFailure("incident timeline", err)
		}
		return result, nil
	case "steward_control_command_list":
		var arguments controlCommandListArgs
		if decodeArguments(raw, &arguments) != nil ||
			!validOptionalControlIdentifier(arguments.TenantID, 128) ||
			!validOptionalControlIdentifier(arguments.NodeID, 128) ||
			!validControlCommandState(arguments.State) ||
			!validControlTerminalStatus(arguments.TerminalStatus) ||
			(arguments.TerminalStatus != "" && arguments.State != string(controlstore.CommandTerminal)) ||
			!validControlInventoryPage(arguments.Cursor, arguments.Limit) {
			return nil, errors.New("steward_control_command_list accepts bounded tenant, node, state, terminal status, cursor, and limit; terminal_status requires state=terminal")
		}
		result, err := s.control.ListCommandInventory(
			ctx, arguments.TenantID, arguments.NodeID, arguments.State,
			arguments.TerminalStatus, arguments.Cursor, arguments.Limit,
		)
		if err != nil {
			return nil, controlFailure("command list", err)
		}
		return result, nil
	case "steward_control_agent_list":
		var arguments controlAgentListArgs
		if decodeArguments(raw, &arguments) != nil ||
			!validOptionalControlIdentifier(arguments.TenantID, 128) ||
			!validOptionalControlIdentifier(arguments.NodeID, 128) ||
			!validControlAgentStatus(arguments.Status) ||
			!validControlInventoryPage(arguments.Cursor, arguments.Limit) {
			return nil, errors.New("steward_control_agent_list accepts only bounded tenant, node, observed status, cursor, and limit")
		}
		result, err := s.control.ListAgentInventory(
			ctx, arguments.TenantID, arguments.NodeID, arguments.Status,
			arguments.Cursor, arguments.Limit,
		)
		if err != nil {
			return nil, controlFailure("agent list", err)
		}
		return result, nil
	case "steward_control_credential_list":
		var arguments controlCredentialListArgs
		if decodeArguments(raw, &arguments) != nil {
			return nil, errors.New("steward_control_credential_list accepts bounded tenant, kind, role, node, revoked, cursor, and limit; role and node filters cannot be combined")
		}
		revoked, revokedErr := parseControlRevoked(arguments.Revoked)
		if !validOptionalControlIdentifier(arguments.TenantID, 128) ||
			!validControlCredentialKind(arguments.Kind) ||
			!validControlCredentialRole(arguments.Role) ||
			!validOptionalControlIdentifier(arguments.NodeID, 128) ||
			(arguments.Kind == string(controlauth.KindNode) && arguments.Role != "") ||
			(arguments.Kind == string(controlauth.KindOperator) && arguments.NodeID != "") ||
			(arguments.Role != "" && arguments.NodeID != "") ||
			revokedErr != nil ||
			!validControlInventoryPage(arguments.Cursor, arguments.Limit) {
			return nil, errors.New("steward_control_credential_list accepts bounded tenant, kind, role, node, revoked, cursor, and limit; role and node filters cannot be combined")
		}
		result, err := s.control.ListCredentialInventory(
			ctx, arguments.TenantID, arguments.Kind, arguments.Role, arguments.NodeID,
			revoked, arguments.Cursor, arguments.Limit,
		)
		if err != nil {
			return nil, controlFailure("credential list", err)
		}
		return result, nil
	case "steward_control_evidence_status":
		var arguments controlEvidenceStatusArgs
		if decodeArguments(raw, &arguments) != nil || !validControlIdentifier(arguments.NodeID, 128) {
			return nil, errors.New("steward_control_evidence_status requires node_id")
		}
		result, err := s.control.InspectExecutorEvidence(ctx, arguments.NodeID)
		if err != nil {
			return nil, controlFailure("evidence status", err)
		}
		if err := result.Validate(); err != nil {
			return nil, controlFailure("evidence status", err)
		}
		projected := controlEvidenceStatusResult{
			ProtocolVersion: result.ProtocolVersion, ControllerInstanceID: result.ControllerInstanceID,
			ControlNodeID: result.ControlNodeID, Status: result.Status,
		}
		if result.IdentityProof != nil {
			claim := result.IdentityProof.Claim
			projected.ReceiptIdentity = &controlEvidenceReceiptIdentity{
				EnrollmentID: claim.EnrollmentID, Stream: claim.Stream, ReceiptNodeID: claim.ReceiptNodeID,
				ReceiptEpoch: claim.ReceiptEpoch, PublicKeySHA256: claim.PublicKeySHA256,
			}
		}
		return projected, nil
	default:
		return nil, errors.New("unknown control-plane tool")
	}
}

func decodeControlCommand(value string) ([]byte, error) {
	if value == "" || len(value) > base64.StdEncoding.EncodedLen(maxControlCommandBytes) {
		return nil, errors.New("command_dsse_base64 is empty or exceeds its bound")
	}
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(raw) == 0 || len(raw) > maxControlCommandBytes || base64.StdEncoding.EncodeToString(raw) != value {
		return nil, errors.New("command_dsse_base64 must be canonical bounded standard base64")
	}
	envelope, err := dsse.Parse(raw)
	if err != nil || envelope.PayloadType != admission.CommandPayloadType {
		return nil, errors.New("command_dsse_base64 must contain one strict Executor command DSSE envelope")
	}
	return raw, nil
}

func decodeControlTaskRequest(value string) ([]byte, error) {
	if value == "" || len(value) > base64.StdEncoding.EncodedLen(int(taskpermit.MaxRequestBytes)) {
		return nil, errors.New("request_base64 is empty or exceeds its bound")
	}
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(raw) == 0 || int64(len(raw)) > taskpermit.MaxRequestBytes ||
		base64.StdEncoding.EncodeToString(raw) != value {
		return nil, errors.New("request_base64 must be canonical bounded standard base64")
	}
	return raw, nil
}

func validControlPage(after string, limit int) bool {
	return (after == "" || validControlIdentifier(after, 128)) && limit >= 0 && limit <= 500
}

func validControlEventCursor(after string) bool {
	return validControlDigestCursor(after, "event-")
}

func validControlTaskCursor(after string) bool {
	return validControlDigestCursor(after, "task-")
}

func validControlDigestCursor(after, prefix string) bool {
	if after == "" {
		return true
	}
	if len(after) != len(prefix)+64 || !strings.HasPrefix(after, prefix) {
		return false
	}
	for _, character := range strings.TrimPrefix(after, prefix) {
		if character < '0' || character > '9' && character < 'a' || character > 'f' {
			return false
		}
	}
	return true
}

func validControlInventoryPage(cursor string, limit int) bool {
	if limit < 0 || limit > controlstore.MaxInventoryPageLimit {
		return false
	}
	if cursor == "" {
		return true
	}
	if len(cursor) > base64.RawURLEncoding.EncodedLen(4096) ||
		strings.ContainsAny(cursor, "\r\n\x00") {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(cursor)
	return err == nil && len(raw) > 0 && len(raw) <= 4096 &&
		base64.RawURLEncoding.EncodeToString(raw) == cursor
}

func validOptionalControlIdentifier(value string, maximum int) bool {
	return value == "" || validControlIdentifier(value, maximum)
}

func validControlIncidentKind(value string) bool {
	switch controlstore.IncidentKind(value) {
	case "", controlstore.IncidentContainment, controlstore.IncidentEvidence,
		controlstore.IncidentAccess, controlstore.IncidentWorkload:
		return true
	default:
		return false
	}
}

func validControlIncidentSeverity(value string) bool {
	switch controlstore.IncidentSeverity(value) {
	case "", controlstore.IncidentInfo, controlstore.IncidentWarning, controlstore.IncidentCritical:
		return true
	default:
		return false
	}
}

func validControlAttentionReason(value string) bool {
	switch controlstore.AttentionReason(value) {
	case "", controlstore.AttentionNodeNeverSeen, controlstore.AttentionNodeStale,
		controlstore.AttentionEvidenceUnwitnessed, controlstore.AttentionEvidenceStale,
		controlstore.AttentionRollbackDetected, controlstore.AttentionEquivocationDetected,
		controlstore.AttentionCommandPendingOverdue, controlstore.AttentionCommandLeaseExpired,
		controlstore.AttentionCommandFailed, controlstore.AttentionCommandOutcomeUnknown,
		controlstore.AttentionCapacityWarning:
		return true
	default:
		return false
	}
}

func validControlCommandState(value string) bool {
	switch controlstore.CommandState(value) {
	case "", controlstore.CommandPending, controlstore.CommandLeased, controlstore.CommandTerminal:
		return true
	default:
		return false
	}
}

func validControlAgentStatus(value string) bool {
	switch value {
	case "", "unknown", "provisioning", "running", "stopped", "hibernated":
		return true
	default:
		return false
	}
}

func validControlTerminalStatus(value string) bool {
	switch value {
	case "", controlprotocol.ExecutorStatusDone, controlprotocol.ExecutorStatusFailed,
		controlprotocol.ExecutorStatusRejected, controlprotocol.ExecutorStatusOutcomeUnknown:
		return true
	default:
		return false
	}
}

func validControlCredentialKind(value string) bool {
	switch controlauth.CredentialKind(value) {
	case "", controlauth.KindOperator, controlauth.KindNode:
		return true
	default:
		return false
	}
}

func validControlCredentialRole(value string) bool {
	switch controlauth.Role(value) {
	case "", controlauth.RoleSiteAdmin, controlauth.RoleTenantOperator:
		return true
	default:
		return false
	}
}

func parseControlRevoked(value string) (*bool, error) {
	switch value {
	case "", "any":
		return nil, nil
	case "true":
		revoked := true
		return &revoked, nil
	case "false":
		revoked := false
		return &revoked, nil
	default:
		return nil, errors.New("revoked filter must be any, true, or false")
	}
}

func validControlIdentifier(value string, maximum int) bool {
	if maximum < 1 || len(value) < 1 || len(value) > maximum || strings.TrimSpace(value) != value {
		return false
	}
	for index, character := range value {
		if character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' ||
			character >= '0' && character <= '9' || index > 0 && (character == '.' || character == '_' || character == '-') {
			continue
		}
		return false
	}
	return true
}

// controlFailure excludes the controller's error code and message because
// both crossed an authenticated but still untrusted network boundary. Only
// bounded transport classification reaches the model-visible tool result.
func controlFailure(operation string, err error) error {
	var apiError *controlclient.APIError
	if errors.As(err, &apiError) && apiError.Status >= 400 && apiError.Status <= 599 {
		return fmt.Errorf("Steward control-plane %s failed: HTTP %d", operation, apiError.Status)
	}
	if errors.Is(err, context.Canceled) {
		return fmt.Errorf("Steward control-plane %s was canceled", operation)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("Steward control-plane %s reached its deadline", operation)
	}
	return fmt.Errorf("Steward control-plane %s failed validation or transport", operation)
}

func controlTools() []any {
	id128 := map[string]any{"type": "string", "minLength": 1, "maxLength": 128, "pattern": "^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"}
	id256 := map[string]any{"type": "string", "minLength": 1, "maxLength": 256, "pattern": "^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$"}
	pageProperties := func() map[string]any {
		return map[string]any{
			"after": map[string]any{"type": "string", "maxLength": 128, "pattern": "^$|^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"},
			"limit": map[string]any{"type": "integer", "minimum": 0, "maximum": 500},
		}
	}
	inventoryProperties := func() map[string]any {
		return map[string]any{
			"cursor": map[string]any{
				"type": "string", "maxLength": base64.RawURLEncoding.EncodedLen(4096),
				"pattern": "^[A-Za-z0-9_-]*$", "description": "Opaque continuation cursor returned by the same operation and filters.",
			},
			"limit": map[string]any{
				"type": "integer", "minimum": 0, "maximum": controlstore.MaxInventoryPageLimit,
				"description": "Maximum results. Zero or omission uses the controller default.",
			},
		}
	}
	optionalTenant := map[string]any{
		"type": "string", "minLength": 1, "maxLength": 128,
		"pattern":     "^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$",
		"description": "Optional tenant projection. Omit for the credential's default site-wide or tenant scope.",
	}
	return []any{
		tool("steward_control_tenant_list", "List tenants", "List the tenants visible to the configured control-plane operator credential.",
			map[string]any{"type": "object", "additionalProperties": false, "properties": pageProperties()}, true, false, true, false),
		tool("steward_control_tenant_create", "Create tenant", "Create one durable tenant. acknowledge_tenant_creation is a model-visible safety acknowledgment, not authority; the configured site-admin credential authorizes the operation.",
			map[string]any{"type": "object", "additionalProperties": false,
				"required":   []string{"tenant_id", "acknowledge_tenant_creation"},
				"properties": map[string]any{"tenant_id": id128, "acknowledge_tenant_creation": map[string]any{"type": "boolean", "const": true}}},
			false, false, true, false),
		tool("steward_control_node_list", "List tenant nodes", "List bounded node inventory visible within one tenant.",
			map[string]any{"type": "object", "additionalProperties": false, "required": []string{"tenant_id"},
				"properties": mergeControlProperties(pageProperties(), "tenant_id", id128)}, true, false, true, false),
		tool("steward_control_node_status", "Inspect tenant node", "Read one node's bounded inventory and liveness metadata within a tenant.",
			map[string]any{"type": "object", "additionalProperties": false, "required": []string{"tenant_id", "node_id"},
				"properties": map[string]any{"tenant_id": id128, "node_id": id128}}, true, false, true, false),
		tool("steward_control_node_pool_list", "List node-pool capacity", "List site-admin-only provider-neutral capacity observations. Pool membership is operational metadata and never grants workload authority.",
			map[string]any{"type": "object", "additionalProperties": false, "properties": pageProperties()}, true, false, true, false),
		tool("steward_control_node_pool_status", "Inspect node-pool capacity", "Read one site-admin-only capacity observation, exact scale-out deficit, and post-drain empty-node scale-in candidates. This tool performs no provider action.",
			map[string]any{"type": "object", "additionalProperties": false, "required": []string{"pool_id"},
				"properties": map[string]any{"pool_id": id128}}, true, false, true, false),
		tool("steward_control_event_list", "List agent events", "List recent untrusted agent status and finding events with Gateway-derived workload identity. Events are telemetry, not command authority or signed evidence.",
			map[string]any{"type": "object", "additionalProperties": false, "required": []string{"tenant_id"},
				"properties": map[string]any{
					"tenant_id": id128,
					"after":     map[string]any{"type": "string", "maxLength": 70, "pattern": "^$|^event-[a-f0-9]{64}$"},
					"limit":     map[string]any{"type": "integer", "minimum": 0, "maximum": 100},
				}}, true, false, true, false),
		tool("steward_control_task_list", "List fleet tasks", "List bounded task progress projected from recent untrusted agent events. Terminal conflicts are preserved as conditions; projections are neither command authority nor proof of correct work.",
			map[string]any{"type": "object", "additionalProperties": false, "required": []string{"tenant_id"},
				"properties": map[string]any{
					"tenant_id": id128,
					"after":     map[string]any{"type": "string", "maxLength": 69, "pattern": "^$|^task-[a-f0-9]{64}$"},
					"limit":     map[string]any{"type": "integer", "minimum": 0, "maximum": 100},
				}}, true, false, true, false),
		tool("steward_control_task_request_list", "List submitted tasks", "List metadata for canonical tasks submitted through Control. Prompts, signed permits, and result bodies are excluded.",
			map[string]any{"type": "object", "additionalProperties": false, "required": []string{"tenant_id"},
				"properties": map[string]any{
					"tenant_id": id128, "after": id128,
					"limit": map[string]any{"type": "integer", "minimum": 0, "maximum": 100},
				}}, true, false, true, false),
		tool("steward_control_task_request_status", "Inspect submitted task", "Read canonical task delivery, deadline, cancellation, uncertainty, and content-addressed result metadata without returning prompt or result bytes.",
			map[string]any{"type": "object", "additionalProperties": false, "required": []string{"tenant_id", "task_id"},
				"properties": map[string]any{"tenant_id": id128, "task_id": id128}}, true, false, true, false),
		tool("steward_control_task_request_submit", "Submit signed task", "Queue an exact tenant-signed task and request after acknowledge_task_submission=true. The acknowledgement is model-visible intent, not authority; Gateway verifies the permit before dispatch.",
			map[string]any{"type": "object", "additionalProperties": false,
				"required": []string{"tenant_id", "task_permit", "request_base64", "acknowledge_task_submission"},
				"properties": map[string]any{
					"tenant_id":                   id128,
					"task_permit":                 map[string]any{"type": "string", "minLength": 1, "maxLength": base64.RawURLEncoding.EncodedLen(taskpermit.MaxEnvelopeBytes)},
					"request_base64":              map[string]any{"type": "string", "minLength": 4, "maxLength": base64.StdEncoding.EncodedLen(int(taskpermit.MaxRequestBytes))},
					"acknowledge_task_submission": map[string]any{"type": "boolean", "const": true},
				}}, false, true, true, true),
		tool("steward_control_task_request_cancel", "Cancel submitted task", "Cancel queued work or record cancellation intent for work that may already be running. acknowledge_task_cancellation=true does not prove a dispatched task stopped.",
			map[string]any{"type": "object", "additionalProperties": false,
				"required": []string{"tenant_id", "task_id", "acknowledge_task_cancellation"},
				"properties": map[string]any{
					"tenant_id": id128, "task_id": id128,
					"acknowledge_task_cancellation": map[string]any{"type": "boolean", "const": true},
				}}, false, true, true, false),
		tool("steward_control_node_revoke", "Revoke node", "Permanently disable one node and its retained credentials. acknowledge_node_revocation is a model-visible safety acknowledgment, not authority.",
			map[string]any{"type": "object", "additionalProperties": false, "required": []string{"node_id", "acknowledge_node_revocation"},
				"properties": map[string]any{"node_id": id128, "acknowledge_node_revocation": map[string]any{"type": "boolean", "const": true}}},
			false, true, true, false),
		tool("steward_control_command_submit", "Submit signed command", "Queue exact signed Executor command bytes for one tenant node. acknowledge_command_submission is a model-visible safety acknowledgment, not authority; the node verifies the signature before execution.",
			map[string]any{"type": "object", "additionalProperties": false,
				"required": []string{"tenant_id", "node_id", "command_dsse_base64", "acknowledge_command_submission"},
				"properties": map[string]any{
					"tenant_id": id128, "node_id": id128,
					"command_dsse_base64":            map[string]any{"type": "string", "minLength": 4, "maxLength": base64.StdEncoding.EncodedLen(maxControlCommandBytes), "description": "Canonical standard-base64 encoding of the exact signed DSSE JSON bytes."},
					"acknowledge_command_submission": map[string]any{"type": "boolean", "const": true},
				}}, false, true, true, true),
		tool("steward_control_command_status", "Inspect signed command", "Read durable delivery and terminal-report metadata for one exact signed command.",
			map[string]any{"type": "object", "additionalProperties": false, "required": []string{"tenant_id", "node_id", "command_id"},
				"properties": map[string]any{"tenant_id": id128, "node_id": id128, "command_id": id256}}, true, false, true, false),
		tool("steward_control_operations_summary", "Inspect fleet operations", "Read bounded capacity, command, evidence, and derived attention totals for the configured operator scope or one tenant projection. This does not acknowledge findings or grant authority.",
			map[string]any{"type": "object", "additionalProperties": false,
				"properties": map[string]any{"tenant_id": optionalTenant}}, true, false, true, false),
		tool("steward_control_attention_list", "List action-required facts", "List bounded derived attention facts for the configured operator scope or one tenant projection. Findings are read-only and remain governed by their underlying node, evidence, command, or capacity state.",
			map[string]any{"type": "object", "additionalProperties": false,
				"properties": mergeControlProperties(
					mergeControlProperties(inventoryProperties(), "tenant_id", optionalTenant),
					"reason", map[string]any{"type": "string", "enum": controlAttentionReasonValues()},
				)}, true, false, true, false),
		tool("steward_control_incident_timeline", "Read current incident facts", "List the newest current retained containment, evidence, access, and failed-workload facts for the configured operator scope or one tenant projection. Metadata only; this is not a complete audit log and does not acknowledge or remediate anything.",
			map[string]any{"type": "object", "additionalProperties": false,
				"properties": mergeControlProperties(
					mergeControlProperties(
						mergeControlProperties(
							mergeControlProperties(inventoryProperties(), "tenant_id", optionalTenant),
							"node_id", id128,
						),
						"kind", map[string]any{"type": "string", "enum": []string{
							"containment", "evidence", "access", "workload",
						}},
					),
					"severity", map[string]any{"type": "string", "enum": []string{
						"info", "warning", "critical",
					}},
				)}, true, false, true, false),
		tool("steward_control_command_list", "List command inventory", "List bounded command delivery metadata without signed command bytes, terminal result text, or retry side effects.",
			map[string]any{"type": "object", "additionalProperties": false,
				"properties": mergeControlProperties(
					mergeControlProperties(
						mergeControlProperties(
							mergeControlProperties(inventoryProperties(), "tenant_id", optionalTenant),
							"node_id", id128,
						),
						"state", map[string]any{"type": "string", "enum": []string{"pending", "leased", "terminal"}},
					),
					"terminal_status", map[string]any{"type": "string", "enum": []string{
						controlprotocol.ExecutorStatusDone, controlprotocol.ExecutorStatusFailed,
						controlprotocol.ExecutorStatusRejected, controlprotocol.ExecutorStatusOutcomeUnknown,
					}},
				)}, true, false, true, false),
		tool("steward_control_agent_list", "List observed agents", "List bounded, non-secret runtime observations derived from signed Executor activity. This reads observed state and does not schedule, retry, or mutate workloads.",
			map[string]any{"type": "object", "additionalProperties": false,
				"properties": mergeControlProperties(
					mergeControlProperties(
						mergeControlProperties(inventoryProperties(), "tenant_id", optionalTenant),
						"node_id", id128,
					),
					"status", map[string]any{"type": "string", "enum": []string{
						"unknown", "provisioning", "running", "stopped", "hibernated",
					}},
				)}, true, false, true, false),
		tool("steward_control_credential_list", "List credential inventory", "List bounded non-secret credential metadata. Bearer values, token MACs, and reproducible credential material are never returned.",
			map[string]any{"type": "object", "additionalProperties": false,
				"properties": mergeControlProperties(
					mergeControlProperties(
						mergeControlProperties(
							mergeControlProperties(
								mergeControlProperties(inventoryProperties(), "tenant_id", optionalTenant),
								"kind", map[string]any{"type": "string", "enum": []string{"operator", "node"}},
							),
							"role", map[string]any{"type": "string", "enum": []string{"site_admin", "tenant_operator"}},
						),
						"node_id", id128,
					),
					"revoked", map[string]any{"type": "string", "enum": []string{"any", "true", "false"}},
				)}, true, false, true, false),
		tool("steward_control_evidence_status", "Inspect Executor evidence", "Read the controller's bounded last-good Executor receipt checkpoint and any sticky rollback or equivocation finding for one node. Requires a site-admin control-plane credential.",
			map[string]any{"type": "object", "additionalProperties": false, "required": []string{"node_id"},
				"properties": map[string]any{"node_id": id128}}, true, false, true, false),
	}
}

func controlAttentionReasonValues() []string {
	return []string{
		string(controlstore.AttentionNodeNeverSeen),
		string(controlstore.AttentionNodeStale),
		string(controlstore.AttentionEvidenceUnwitnessed),
		string(controlstore.AttentionEvidenceStale),
		string(controlstore.AttentionRollbackDetected),
		string(controlstore.AttentionEquivocationDetected),
		string(controlstore.AttentionCommandPendingOverdue),
		string(controlstore.AttentionCommandLeaseExpired),
		string(controlstore.AttentionCommandFailed),
		string(controlstore.AttentionCommandOutcomeUnknown),
		string(controlstore.AttentionCapacityWarning),
	}
}

func mergeControlProperties(properties map[string]any, name string, value any) map[string]any {
	properties[name] = value
	return properties
}
