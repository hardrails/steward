package mcpserver

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/controlclient"
	"github.com/hardrails/steward/internal/dsse"
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
	GetNode(context.Context, string, string) (controlclient.Node, error)
	RevokeNode(context.Context, string) (controlclient.NodeRevocation, error)
	SubmitCommand(context.Context, string, string, []byte) (controlclient.Command, error)
	GetCommand(context.Context, string, string, string) (controlclient.Command, error)
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

type controlNodeStatusArgs struct {
	TenantID string `json:"tenant_id"`
	NodeID   string `json:"node_id"`
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

func validControlPage(after string, limit int) bool {
	return (after == "" || validControlIdentifier(after, 128)) && limit >= 0 && limit <= 500
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
	}
}

func mergeControlProperties(properties map[string]any, name string, value any) map[string]any {
	properties[name] = value
	return properties
}
