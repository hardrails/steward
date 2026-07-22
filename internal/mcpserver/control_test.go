package mcpserver

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/controlauth"
	"github.com/hardrails/steward/internal/controlclient"
	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/controlstore"
	"github.com/hardrails/steward/internal/dsse"
)

type fakeControl struct {
	calls      []string
	command    []byte
	inspection controlprotocol.ExecutorEvidenceInspectionV1
	err        error
}

func (control *fakeControl) ListTenants(_ context.Context, after string, limit int) (controlclient.TenantList, error) {
	control.calls = append(control.calls, "tenant-list:"+after+":"+strconv.Itoa(limit))
	return controlclient.TenantList{Tenants: []controlclient.Tenant{{TenantID: "tenant-a", State: "active"}}}, control.err
}

func (control *fakeControl) CreateTenant(_ context.Context, tenantID string) (controlclient.Tenant, error) {
	control.calls = append(control.calls, "tenant-create:"+tenantID)
	return controlclient.Tenant{TenantID: tenantID, State: "active"}, control.err
}

func (control *fakeControl) ListNodes(_ context.Context, tenantID, after string, limit int) (controlclient.NodeList, error) {
	control.calls = append(control.calls, "node-list:"+tenantID+":"+after+":"+strconv.Itoa(limit))
	return controlclient.NodeList{Nodes: []controlclient.Node{{NodeID: "node-a", TenantIDs: []string{tenantID}, State: "active"}}}, control.err
}

func (control *fakeControl) ListInstanceEvents(_ context.Context, tenantID, after string, limit int) (controlclient.InstanceEventList, error) {
	control.calls = append(control.calls, "event-list:"+tenantID+":"+after+":"+strconv.Itoa(limit))
	return controlclient.InstanceEventList{Events: []controlstore.InstanceEvent{}}, control.err
}

func (control *fakeControl) ListTaskProjections(_ context.Context, tenantID, after string, limit int) (controlclient.TaskProjectionList, error) {
	control.calls = append(control.calls, "task-list:"+tenantID+":"+after+":"+strconv.Itoa(limit))
	return controlclient.TaskProjectionList{Tasks: []controlstore.TaskProjection{}}, control.err
}

func (control *fakeControl) GetNode(_ context.Context, tenantID, nodeID string) (controlclient.Node, error) {
	control.calls = append(control.calls, "node-status:"+tenantID+":"+nodeID)
	return controlclient.Node{NodeID: nodeID, TenantIDs: []string{tenantID}, State: "active"}, control.err
}

func (control *fakeControl) RevokeNode(_ context.Context, nodeID string) (controlclient.NodeRevocation, error) {
	control.calls = append(control.calls, "node-revoke:"+nodeID)
	return controlclient.NodeRevocation{NodeID: nodeID, RevokedCredentials: 1}, control.err
}

func (control *fakeControl) SubmitCommand(_ context.Context, tenantID, nodeID string, command []byte) (controlclient.Command, error) {
	control.calls = append(control.calls, "command-submit:"+tenantID+":"+nodeID)
	control.command = append([]byte(nil), command...)
	return controlclient.Command{CommandID: "command-a", TenantID: tenantID, NodeID: nodeID, State: "pending"}, control.err
}

func (control *fakeControl) GetCommand(_ context.Context, tenantID, nodeID, commandID string) (controlclient.Command, error) {
	control.calls = append(control.calls, "command-status:"+tenantID+":"+nodeID+":"+commandID)
	return controlclient.Command{CommandID: commandID, TenantID: tenantID, NodeID: nodeID, State: "terminal"}, control.err
}

func (control *fakeControl) GetOperationsSummary(_ context.Context, tenantID string) (controlstore.OperationsSummary, error) {
	control.calls = append(control.calls, "operations-summary:"+tenantID)
	return controlstore.OperationsSummary{
		GeneratedAt: "2026-07-16T12:00:00Z",
		TenantID:    tenantID,
		Capacity: []controlstore.CapacityUsage{{
			Resource: controlstore.CapacityNodes, Used: 1, Limit: 10,
		}},
		Commands: controlstore.CommandSummary{Total: 1, Pending: 1},
		Evidence: controlstore.EvidenceSummary{Nodes: 1, ActiveNodes: 1, Witnessed: 1, Current: 1},
		Attention: controlstore.AttentionSummary{
			Total: 1, Warnings: 1,
			Counts: []controlstore.AttentionCount{{
				Reason: controlstore.AttentionNodeStale, Severity: controlstore.AttentionWarning, Count: 1,
			}},
		},
	}, control.err
}

func (control *fakeControl) ListAttention(_ context.Context, tenantID, reason, cursor string, limit int) (controlstore.AttentionPage, error) {
	control.calls = append(
		control.calls, "attention-list:"+tenantID+":"+reason+":"+cursor+":"+strconv.Itoa(limit),
	)
	return controlstore.AttentionPage{
		Items: []controlstore.AttentionItem{{
			ID: "attention-a", Reason: controlstore.AttentionReason(reason),
			Severity: controlstore.AttentionWarning, Resource: controlstore.AttentionResourceNode,
			TenantID: tenantID, NodeID: "node-a", Since: "2026-07-16T11:55:00Z",
		}},
		NextCursor: "next-attention",
	}, control.err
}

func (control *fakeControl) ListIncidentTimeline(
	_ context.Context, tenantID, nodeID, kind, severity, cursor string, limit int,
) (controlstore.IncidentTimelinePage, error) {
	control.calls = append(
		control.calls,
		"incident-timeline:"+tenantID+":"+nodeID+":"+kind+":"+severity+":"+cursor+":"+strconv.Itoa(limit),
	)
	return controlstore.IncidentTimelinePage{
		Events: []controlstore.IncidentEvent{{
			ID:         "incident-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			OccurredAt: "2026-07-16T11:56:00Z", Kind: controlstore.IncidentKind(kind),
			Action: "node_quarantined", Severity: controlstore.IncidentSeverity(severity),
			Scope: "tenant", TenantID: tenantID, NodeID: nodeID,
		}},
		NextCursor: "next-incident",
	}, control.err
}

func (control *fakeControl) ListCommandInventory(
	_ context.Context, tenantID, nodeID, state, terminalStatus, cursor string, limit int,
) (controlstore.CommandInventoryPage, error) {
	control.calls = append(
		control.calls,
		"command-list:"+tenantID+":"+nodeID+":"+state+":"+terminalStatus+":"+cursor+":"+strconv.Itoa(limit),
	)
	return controlstore.CommandInventoryPage{
		Commands: []controlstore.CommandMetadata{{
			TenantID: tenantID, NodeID: nodeID, ID: "command-a", DeliveryID: "delivery-a",
			Digest: "sha256:" + strings.Repeat("a", 64), State: controlstore.CommandState(state),
			DeliveryGeneration: 1, CreatedAt: "2026-07-16T11:00:00Z",
			TerminalStatus: terminalStatus, CompletedAt: "2026-07-16T11:01:00Z",
		}},
		NextCursor: "next-command",
	}, control.err
}

func (control *fakeControl) ListAgentInventory(
	_ context.Context, tenantID, nodeID, status, cursor string, limit int,
) (controlstore.AgentInventoryPage, error) {
	control.calls = append(
		control.calls,
		"agent-list:"+tenantID+":"+nodeID+":"+status+":"+cursor+":"+strconv.Itoa(limit),
	)
	return controlstore.AgentInventoryPage{
		Agents: []controlstore.AgentMetadata{{
			TenantID: tenantID, NodeID: nodeID,
			RuntimeRef:         "executor-" + strings.Repeat("a", 64),
			InstanceGeneration: 1, ObservedStatus: status,
			LatestCommandID: "command-a", LatestCommandKind: "start",
			LatestCommandState: "terminal", LatestTerminalStatus: "done",
			CreatedAt: "2026-07-16T11:00:00Z", UpdatedAt: "2026-07-16T11:01:00Z",
		}},
		NextCursor: "next-agent",
	}, control.err
}

func (control *fakeControl) ListCredentialInventory(
	_ context.Context, tenantID, kind, role, nodeID string, revoked *bool, cursor string, limit int,
) (controlstore.CredentialInventoryPage, error) {
	revokedFilter := "any"
	revokedValue := false
	if revoked != nil {
		revokedValue = *revoked
		revokedFilter = strconv.FormatBool(*revoked)
	}
	control.calls = append(
		control.calls,
		"credential-list:"+tenantID+":"+kind+":"+role+":"+nodeID+":"+revokedFilter+":"+cursor+":"+strconv.Itoa(limit),
	)
	return controlstore.CredentialInventoryPage{
		Credentials: []controlstore.CredentialMetadata{{
			ID: "credential-a", Kind: controlauth.CredentialKind(kind), Role: controlauth.Role(role),
			TenantID: tenantID, NodeID: nodeID, RequestID: "request-a",
			CreatedAt: "2026-07-16T10:00:00Z", Revoked: revokedValue,
		}},
		NextCursor: "next-credential",
	}, control.err
}

func (control *fakeControl) InspectExecutorEvidence(_ context.Context, nodeID string) (controlprotocol.ExecutorEvidenceInspectionV1, error) {
	control.calls = append(control.calls, "evidence-status:"+nodeID)
	return control.inspection, control.err
}

func TestMCPControlToolsAreOptionalAndAccuratelyAnnotated(t *testing.T) {
	controlOnly, err := NewConfigured(Config{Control: &fakeControl{}, Version: "v1"})
	if err != nil {
		t.Fatal(err)
	}
	listed := controlOnly.configuredTools()
	if len(listed) != 16 {
		t.Fatalf("control-only tool count=%d", len(listed))
	}
	raw := string(mustJSON(t, listed))
	for _, name := range []string{
		"steward_control_tenant_list", "steward_control_tenant_create", "steward_control_node_list",
		"steward_control_node_status", "steward_control_node_revoke", "steward_control_command_submit",
		"steward_control_event_list", "steward_control_task_list",
		"steward_control_command_status", "steward_control_operations_summary",
		"steward_control_attention_list", "steward_control_command_list",
		"steward_control_incident_timeline",
		"steward_control_agent_list",
		"steward_control_credential_list", "steward_control_evidence_status",
	} {
		if !strings.Contains(raw, name) {
			t.Fatalf("control tool list omitted %s: %s", name, raw)
		}
	}
	for _, forbidden := range []string{"steward_admit", "steward_task_submit", "operator_issue", "enrollment_create"} {
		if strings.Contains(raw, forbidden) {
			t.Fatalf("control-only tool list exposed %s: %s", forbidden, raw)
		}
	}
	for _, acknowledgment := range []string{"acknowledge_tenant_creation", "acknowledge_node_revocation", "acknowledge_command_submission"} {
		if !strings.Contains(raw, acknowledgment) {
			t.Fatalf("control tool list omitted %s", acknowledgment)
		}
	}

	definitions := make(map[string]map[string]any)
	for _, candidate := range listed {
		definition := candidate.(map[string]any)
		definitions[definition["name"].(string)] = definition
	}
	requireAnnotations(t, definitions["steward_control_tenant_list"], true, false, true, false)
	requireAnnotations(t, definitions["steward_control_tenant_create"], false, false, true, false)
	requireAnnotations(t, definitions["steward_control_node_revoke"], false, true, true, false)
	requireAnnotations(t, definitions["steward_control_command_submit"], false, true, true, true)
	requireAnnotations(t, definitions["steward_control_operations_summary"], true, false, true, false)
	requireAnnotations(t, definitions["steward_control_attention_list"], true, false, true, false)
	requireAnnotations(t, definitions["steward_control_incident_timeline"], true, false, true, false)
	requireAnnotations(t, definitions["steward_control_event_list"], true, false, true, false)
	requireAnnotations(t, definitions["steward_control_task_list"], true, false, true, false)
	requireAnnotations(t, definitions["steward_control_command_list"], true, false, true, false)
	requireAnnotations(t, definitions["steward_control_agent_list"], true, false, true, false)
	requireAnnotations(t, definitions["steward_control_credential_list"], true, false, true, false)
	requireAnnotations(t, definitions["steward_control_evidence_status"], true, false, true, false)
	for toolName, acknowledgment := range map[string]string{
		"steward_control_tenant_create":  "acknowledge_tenant_creation",
		"steward_control_node_revoke":    "acknowledge_node_revocation",
		"steward_control_command_submit": "acknowledge_command_submission",
	} {
		schema := definitions[toolName]["inputSchema"].(map[string]any)
		properties := schema["properties"].(map[string]any)
		acknowledgmentSchema := properties[acknowledgment].(map[string]any)
		if acknowledgmentSchema["const"] != true {
			t.Fatalf("%s does not require %s=true: %#v", toolName, acknowledgment, acknowledgmentSchema)
		}
	}
	for _, toolName := range []string{
		"steward_control_operations_summary", "steward_control_attention_list",
		"steward_control_incident_timeline",
		"steward_control_event_list", "steward_control_task_list",
		"steward_control_agent_list", "steward_control_command_list", "steward_control_credential_list",
	} {
		schema := definitions[toolName]["inputSchema"].(map[string]any)
		properties := schema["properties"].(map[string]any)
		for property := range properties {
			if strings.HasPrefix(property, "acknowledge_") {
				t.Fatalf("read-only %s unexpectedly requires %s", toolName, property)
			}
		}
	}

	combined, err := NewConfigured(Config{Node: &fakeNode{}, Control: &fakeControl{}, Version: "v1"})
	if err != nil {
		t.Fatal(err)
	}
	combinedRaw := string(mustJSON(t, combined.configuredTools()))
	if !strings.Contains(combinedRaw, "steward_admit") || !strings.Contains(combinedRaw, "steward_control_tenant_list") || strings.Contains(combinedRaw, "steward_task_submit") {
		t.Fatalf("combined surface mismatch: %s", combinedRaw)
	}
	if _, rpcErr := controlOnly.callTool(context.Background(), json.RawMessage(`{"name":"steward_status","arguments":{"runtime_ref":"`+runtimeRef()+`"}}`)); rpcErr == nil || !strings.Contains(rpcErr.Message, "unknown tool") {
		t.Fatalf("controller-only node call error=%#v", rpcErr)
	}
}

func TestMCPControlToolsCallOnlyBoundedPublicOperations(t *testing.T) {
	control := &fakeControl{inspection: testControlEvidenceInspection(t)}
	server, err := NewConfigured(Config{Control: control, Version: "v1"})
	if err != nil {
		t.Fatal(err)
	}
	command := testControlCommand(t)
	calls := []struct {
		name      string
		arguments map[string]any
	}{
		{name: "steward_control_tenant_list", arguments: map[string]any{"after": "tenant-0", "limit": 25}},
		{name: "steward_control_tenant_create", arguments: map[string]any{"tenant_id": "tenant-a", "acknowledge_tenant_creation": true}},
		{name: "steward_control_node_list", arguments: map[string]any{"tenant_id": "tenant-a", "after": "node-0", "limit": 50}},
		{name: "steward_control_node_status", arguments: map[string]any{"tenant_id": "tenant-a", "node_id": "node-a"}},
		{name: "steward_control_node_revoke", arguments: map[string]any{"node_id": "node-a", "acknowledge_node_revocation": true}},
		{name: "steward_control_command_submit", arguments: map[string]any{
			"tenant_id": "tenant-a", "node_id": "node-a", "command_dsse_base64": base64.StdEncoding.EncodeToString(command),
			"acknowledge_command_submission": true,
		}},
		{name: "steward_control_command_status", arguments: map[string]any{"tenant_id": "tenant-a", "node_id": "node-a", "command_id": "command-a"}},
		{name: "steward_control_evidence_status", arguments: map[string]any{"node_id": "node-a"}},
	}
	for _, call := range calls {
		result := callMCPControlTool(t, server, call.name, call.arguments)
		if controlToolIsError(result) {
			t.Fatalf("%s failed: %#v", call.name, result)
		}
		if call.name == "steward_control_evidence_status" {
			raw := string(mustJSON(t, result))
			if !strings.Contains(raw, `"state":"current"`) || !strings.Contains(raw, `"public_key_sha256"`) ||
				strings.Contains(raw, `"public_key_base64"`) || strings.Contains(raw, `"signature_base64"`) {
				t.Fatalf("unsafe or incomplete model-visible evidence status=%s", raw)
			}
		}
	}
	attentionCursor := base64.RawURLEncoding.EncodeToString([]byte("attention-v1\x00attention-a"))
	incidentCursor := base64.RawURLEncoding.EncodeToString([]byte("incident-timeline-v1\x00incident-a"))
	agentCursor := base64.RawURLEncoding.EncodeToString([]byte("agent-v1\x00agent-a"))
	commandCursor := base64.RawURLEncoding.EncodeToString([]byte("command-v1\x00command-a"))
	credentialCursor := base64.RawURLEncoding.EncodeToString([]byte("credential-v1\x00credential-a"))
	eventCursor := "event-" + strings.Repeat("a", 64)
	taskCursor := "task-" + strings.Repeat("a", 64)
	directCalls := []struct {
		name      string
		arguments map[string]any
	}{
		{
			name: "steward_control_operations_summary",
			arguments: map[string]any{
				"tenant_id": "tenant-a",
			},
		},
		{
			name: "steward_control_attention_list",
			arguments: map[string]any{
				"tenant_id": "tenant-a", "reason": "node_stale",
				"cursor": attentionCursor, "limit": 25,
			},
		},
		{
			name: "steward_control_incident_timeline",
			arguments: map[string]any{
				"tenant_id": "tenant-a", "node_id": "node-a", "kind": "containment",
				"severity": "critical", "cursor": incidentCursor, "limit": 20,
			},
		},
		{
			name: "steward_control_event_list",
			arguments: map[string]any{
				"tenant_id": "tenant-a", "after": eventCursor, "limit": 25,
			},
		},
		{
			name: "steward_control_task_list",
			arguments: map[string]any{
				"tenant_id": "tenant-a", "after": taskCursor, "limit": 25,
			},
		},
		{
			name: "steward_control_agent_list",
			arguments: map[string]any{
				"tenant_id": "tenant-a", "node_id": "node-a", "status": "running",
				"cursor": agentCursor, "limit": 40,
			},
		},
		{
			name: "steward_control_command_list",
			arguments: map[string]any{
				"tenant_id": "tenant-a", "node_id": "node-a", "state": "terminal",
				"terminal_status": "failed", "cursor": commandCursor, "limit": 50,
			},
		},
		{
			name: "steward_control_credential_list",
			arguments: map[string]any{
				"tenant_id": "tenant-a", "kind": "operator", "role": "tenant_operator",
				"revoked": "false", "cursor": credentialCursor, "limit": 10,
			},
		},
	}
	for _, call := range directCalls {
		result, err := callDirectMCPControlTool(t, server, call.name, call.arguments)
		if err != nil {
			t.Fatalf("%s failed: %v", call.name, err)
		}
		raw := string(mustJSON(t, result))
		if call.name == "steward_control_command_list" &&
			(strings.Contains(raw, `"command_dsse"`) || strings.Contains(raw, `"result"`) ||
				strings.Contains(raw, `"runtime_ref"`) || strings.Contains(raw, `"reported_status"`) ||
				strings.Contains(raw, `"error_code"`)) {
			t.Fatalf("command inventory leaked secret-bearing fields: %s", raw)
		}
		if call.name == "steward_control_credential_list" &&
			(strings.Contains(raw, `"token"`) || strings.Contains(raw, `"token_mac"`) ||
				strings.Contains(raw, `"credential"`)) {
			t.Fatalf("credential inventory leaked secret-bearing fields: %s", raw)
		}
	}
	wantCalls := []string{
		"tenant-list:tenant-0:25", "tenant-create:tenant-a", "node-list:tenant-a:node-0:50",
		"node-status:tenant-a:node-a", "node-revoke:node-a", "command-submit:tenant-a:node-a",
		"command-status:tenant-a:node-a:command-a",
		"evidence-status:node-a",
		"operations-summary:tenant-a",
		"attention-list:tenant-a:node_stale:" + attentionCursor + ":25",
		"incident-timeline:tenant-a:node-a:containment:critical:" + incidentCursor + ":20",
		"event-list:tenant-a:" + eventCursor + ":25",
		"task-list:tenant-a:" + taskCursor + ":25",
		"agent-list:tenant-a:node-a:running:" + agentCursor + ":40",
		"command-list:tenant-a:node-a:terminal:failed:" + commandCursor + ":50",
		"credential-list:tenant-a:operator:tenant_operator::false:" + credentialCursor + ":10",
	}
	if strings.Join(control.calls, "|") != strings.Join(wantCalls, "|") {
		t.Fatalf("calls=%#v", control.calls)
	}
	if !bytes.Equal(control.command, command) {
		t.Fatal("MCP did not preserve exact signed command bytes")
	}
}

func TestMCPControlOperationsRejectInvalidAndAmbiguousFilters(t *testing.T) {
	control := &fakeControl{}
	server, _ := NewConfigured(Config{Control: control, Version: "v1"})
	validCursor := base64.RawURLEncoding.EncodeToString([]byte("cursor-v1\x00item-a"))
	tests := []struct {
		name      string
		tool      string
		arguments map[string]any
	}{
		{name: "summary unknown field", tool: "steward_control_operations_summary", arguments: map[string]any{"unexpected": true}},
		{name: "summary invalid tenant", tool: "steward_control_operations_summary", arguments: map[string]any{"tenant_id": "-tenant"}},
		{name: "attention reason", tool: "steward_control_attention_list", arguments: map[string]any{"reason": "not-a-reason"}},
		{name: "attention cursor", tool: "steward_control_attention_list", arguments: map[string]any{"cursor": "%%%"}},
		{name: "attention negative limit", tool: "steward_control_attention_list", arguments: map[string]any{"limit": -1}},
		{name: "attention oversized limit", tool: "steward_control_attention_list", arguments: map[string]any{"limit": 501}},
		{name: "incident kind", tool: "steward_control_incident_timeline", arguments: map[string]any{"kind": "unknown"}},
		{name: "incident severity", tool: "steward_control_incident_timeline", arguments: map[string]any{"severity": "urgent"}},
		{name: "incident node", tool: "steward_control_incident_timeline", arguments: map[string]any{"node_id": "-node"}},
		{name: "incident cursor", tool: "steward_control_incident_timeline", arguments: map[string]any{"cursor": validCursor + "="}},
		{name: "agent status", tool: "steward_control_agent_list", arguments: map[string]any{"status": "destroyed"}},
		{name: "agent node", tool: "steward_control_agent_list", arguments: map[string]any{"node_id": "-node"}},
		{name: "agent cursor", tool: "steward_control_agent_list", arguments: map[string]any{"cursor": validCursor + "="}},
		{name: "event tenant", tool: "steward_control_event_list", arguments: map[string]any{}},
		{name: "event cursor", tool: "steward_control_event_list", arguments: map[string]any{"tenant_id": "tenant-a", "after": "event-invalid"}},
		{name: "event cursor alphabet", tool: "steward_control_event_list", arguments: map[string]any{"tenant_id": "tenant-a", "after": "event-" + strings.Repeat("G", 64)}},
		{name: "event limit", tool: "steward_control_event_list", arguments: map[string]any{"tenant_id": "tenant-a", "limit": 101}},
		{name: "task tenant", tool: "steward_control_task_list", arguments: map[string]any{}},
		{name: "task cursor", tool: "steward_control_task_list", arguments: map[string]any{"tenant_id": "tenant-a", "after": "task-invalid"}},
		{name: "task cursor alphabet", tool: "steward_control_task_list", arguments: map[string]any{"tenant_id": "tenant-a", "after": "task-" + strings.Repeat("G", 64)}},
		{name: "task limit", tool: "steward_control_task_list", arguments: map[string]any{"tenant_id": "tenant-a", "limit": 101}},
		{name: "command state", tool: "steward_control_command_list", arguments: map[string]any{"state": "running"}},
		{name: "command terminal without state", tool: "steward_control_command_list", arguments: map[string]any{"terminal_status": "failed"}},
		{name: "command terminal status", tool: "steward_control_command_list", arguments: map[string]any{"state": "terminal", "terminal_status": "running"}},
		{name: "command node", tool: "steward_control_command_list", arguments: map[string]any{"node_id": "-node"}},
		{name: "command cursor", tool: "steward_control_command_list", arguments: map[string]any{"cursor": validCursor + "="}},
		{name: "credential kind", tool: "steward_control_credential_list", arguments: map[string]any{"kind": "enrollment"}},
		{name: "credential role", tool: "steward_control_credential_list", arguments: map[string]any{"role": "owner"}},
		{name: "credential revoked", tool: "steward_control_credential_list", arguments: map[string]any{"revoked": "yes"}},
		{name: "credential role and node", tool: "steward_control_credential_list", arguments: map[string]any{"role": "tenant_operator", "node_id": "node-a"}},
		{name: "node credential with role", tool: "steward_control_credential_list", arguments: map[string]any{"kind": "node", "role": "tenant_operator"}},
		{name: "operator credential with node", tool: "steward_control_credential_list", arguments: map[string]any{"kind": "operator", "node_id": "node-a"}},
		{name: "credential unknown field", tool: "steward_control_credential_list", arguments: map[string]any{"unexpected": true}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if result, err := callDirectMCPControlTool(t, server, test.tool, test.arguments); err == nil {
				t.Fatalf("invalid input succeeded: %#v", result)
			}
		})
	}
	result, err := server.callControlTool(
		context.Background(),
		"steward_control_command_list",
		[]byte(`{"tenant_id":"tenant-a","tenant_id":"tenant-b"}`),
	)
	if err == nil || result != nil {
		t.Fatalf("duplicate argument accepted: result=%#v error=%v", result, err)
	}
	if len(control.calls) != 0 {
		t.Fatalf("invalid calls reached controller: %#v", control.calls)
	}
}

func TestMCPControlMutationsRequireExplicitAcknowledgments(t *testing.T) {
	control := &fakeControl{}
	server, _ := NewConfigured(Config{Control: control, Version: "v1"})
	command := testControlCommand(t)
	for _, call := range []struct {
		name      string
		arguments map[string]any
	}{
		{name: "steward_control_tenant_create", arguments: map[string]any{"tenant_id": "tenant-a", "acknowledge_tenant_creation": false}},
		{name: "steward_control_node_revoke", arguments: map[string]any{"node_id": "node-a", "acknowledge_node_revocation": false}},
		{name: "steward_control_command_submit", arguments: map[string]any{
			"tenant_id": "tenant-a", "node_id": "node-a", "command_dsse_base64": base64.StdEncoding.EncodeToString(command),
			"acknowledge_command_submission": false,
		}},
	} {
		result := callMCPControlTool(t, server, call.name, call.arguments)
		if !controlToolIsError(result) {
			t.Fatalf("unacknowledged %s succeeded: %#v", call.name, result)
		}
	}
	if len(control.calls) != 0 {
		t.Fatalf("unacknowledged mutations reached controller: %#v", control.calls)
	}
}

func TestMCPControlRejectsAmbiguousIdentifiersAndCommandBytes(t *testing.T) {
	control := &fakeControl{}
	server, _ := NewConfigured(Config{Control: control, Version: "v1"})
	command := testControlCommand(t)
	validSubmit := map[string]any{
		"tenant_id": "tenant-a", "node_id": "node-a", "command_dsse_base64": base64.StdEncoding.EncodeToString(command),
		"acknowledge_command_submission": true,
	}
	for _, test := range []struct {
		name      string
		tool      string
		arguments map[string]any
	}{
		{name: "unknown field", tool: "steward_control_tenant_list", arguments: map[string]any{"unexpected": true}},
		{name: "invalid cursor", tool: "steward_control_tenant_list", arguments: map[string]any{"after": " bad"}},
		{name: "oversized page", tool: "steward_control_node_list", arguments: map[string]any{"tenant_id": "tenant-a", "limit": 501}},
		{name: "invalid node", tool: "steward_control_node_status", arguments: map[string]any{"tenant_id": "tenant-a", "node_id": "-node"}},
		{name: "missing evidence node", tool: "steward_control_evidence_status", arguments: map[string]any{}},
		{name: "invalid evidence node", tool: "steward_control_evidence_status", arguments: map[string]any{"node_id": "-node"}},
		{name: "unknown evidence argument", tool: "steward_control_evidence_status", arguments: map[string]any{"node_id": "node-a", "unexpected": true}},
		{name: "malformed base64", tool: "steward_control_command_submit", arguments: replaceControlArgument(validSubmit, "command_dsse_base64", "%%%")},
		{name: "noncanonical base64", tool: "steward_control_command_submit", arguments: replaceControlArgument(validSubmit, "command_dsse_base64", base64.StdEncoding.EncodeToString(command)+"\n")},
		{name: "not DSSE", tool: "steward_control_command_submit", arguments: replaceControlArgument(validSubmit, "command_dsse_base64", base64.StdEncoding.EncodeToString([]byte(`{"not":"dsse"}`)))},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := callMCPControlTool(t, server, test.tool, test.arguments)
			if !controlToolIsError(result) {
				t.Fatalf("invalid input succeeded: %#v", result)
			}
		})
	}
	if _, err := decodeControlCommand(strings.Repeat("A", base64.StdEncoding.EncodedLen(maxControlCommandBytes)+1)); err == nil {
		t.Fatal("oversized command base64 accepted")
	}
	duplicate, rpcErr := server.callTool(context.Background(), json.RawMessage(
		`{"name":"steward_control_tenant_create","arguments":{"tenant_id":"tenant-a","tenant_id":"tenant-b","acknowledge_tenant_creation":true}}`,
	))
	if rpcErr == nil || rpcErr.Code != -32602 || duplicate != nil {
		t.Fatalf("duplicate argument accepted: result=%#v rpcErr=%#v", duplicate, rpcErr)
	}
	if len(control.calls) != 0 {
		t.Fatalf("invalid calls reached controller: %#v", control.calls)
	}
}

func TestMCPControlFailuresAreBoundedAndRedacted(t *testing.T) {
	control := &fakeControl{err: &controlclient.APIError{Status: http.StatusServiceUnavailable, Code: "sensitive_code", Message: strings.Repeat("sensitive-agent-output", 500)}}
	server, _ := NewConfigured(Config{Control: control, Version: "v1"})
	result := callMCPControlTool(t, server, "steward_control_tenant_list", map[string]any{})
	raw := string(mustJSON(t, result))
	if !controlToolIsError(result) || !strings.Contains(raw, "HTTP 503") || strings.Contains(raw, "sensitive_code") || strings.Contains(raw, "sensitive-agent-output") || len(raw) > 1024 {
		t.Fatalf("API failure projection=%s", raw)
	}
	control.err = errors.New(strings.Repeat("transport-secret", 1000))
	result = callMCPControlTool(t, server, "steward_control_tenant_list", map[string]any{})
	raw = string(mustJSON(t, result))
	if !controlToolIsError(result) || !strings.Contains(raw, "failed validation or transport") || strings.Contains(raw, "transport-secret") || len(raw) > 1024 {
		t.Fatalf("transport failure projection=%s", raw)
	}

	control.err = &controlclient.APIError{
		Status: http.StatusForbidden, Code: "sensitive_evidence_code",
		Message: strings.Repeat("sensitive-evidence-body", 500),
	}
	result = callMCPControlTool(t, server, "steward_control_evidence_status", map[string]any{"node_id": "node-a"})
	raw = string(mustJSON(t, result))
	if !controlToolIsError(result) || !strings.Contains(raw, "HTTP 403") ||
		strings.Contains(raw, "sensitive_evidence_code") || strings.Contains(raw, "sensitive-evidence-body") || len(raw) > 1024 {
		t.Fatalf("evidence API failure projection=%s", raw)
	}

	control.err = &controlclient.APIError{
		Status: http.StatusBadGateway, Code: "sensitive_operations_code",
		Message: strings.Repeat("sensitive-operations-body", 500),
	}
	directResult, directErr := callDirectMCPControlTool(
		t, server, "steward_control_operations_summary", map[string]any{"tenant_id": "tenant-a"},
	)
	if directErr == nil || directResult != nil ||
		!strings.Contains(directErr.Error(), "HTTP 502") ||
		strings.Contains(directErr.Error(), "sensitive_operations_code") ||
		strings.Contains(directErr.Error(), "sensitive-operations-body") ||
		len(directErr.Error()) > 1024 {
		t.Fatalf("operations API failure projection=(%#v, %v)", directResult, directErr)
	}
}

func TestMCPControlEvidenceStatusRevalidatesModelVisibleOutput(t *testing.T) {
	control := &fakeControl{inspection: controlprotocol.ExecutorEvidenceInspectionV1{
		ProtocolVersion:      controlprotocol.ExecutorEvidenceProtocolV1,
		ControllerInstanceID: strings.Repeat("sensitive-invalid-controller", 100),
		ControlNodeID:        "node-a",
		Status:               controlprotocol.ExecutorEvidenceStatusV1{State: controlprotocol.ExecutorEvidenceStatusUnwitnessed},
	}}
	server, _ := NewConfigured(Config{Control: control, Version: "v1"})
	result := callMCPControlTool(t, server, "steward_control_evidence_status", map[string]any{"node_id": "node-a"})
	raw := string(mustJSON(t, result))
	if !controlToolIsError(result) || !strings.Contains(raw, "failed validation or transport") ||
		strings.Contains(raw, "sensitive-invalid-controller") || len(raw) > 1024 {
		t.Fatalf("invalid evidence projection=%s", raw)
	}
}

func TestMCPControlOnlyInitializationDescribesItsExactSurface(t *testing.T) {
	server, _ := NewConfigured(Config{Control: &fakeControl{}, Version: "v1"})
	input := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`,
	}, "\n") + "\n"
	var output bytes.Buffer
	if err := server.Serve(context.Background(), strings.NewReader(input), &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	raw := output.String()
	if !strings.Contains(raw, "Steward Control Plane Operations") || !strings.Contains(raw, "never issues operator or enrollment secrets") ||
		!strings.Contains(raw, "steward_control_command_submit") ||
		!strings.Contains(raw, "steward_control_operations_summary") ||
		!strings.Contains(raw, "steward_control_attention_list") ||
		!strings.Contains(raw, "steward_control_agent_list") ||
		!strings.Contains(raw, "steward_control_command_list") ||
		!strings.Contains(raw, "steward_control_credential_list") ||
		!strings.Contains(raw, "steward_control_evidence_status") ||
		strings.Contains(raw, "steward_admit") || strings.Contains(raw, "steward_task_submit") {
		t.Fatalf("control-only initialization=%s", raw)
	}
}

func callMCPControlTool(t *testing.T, server *Server, name string, arguments map[string]any) any {
	t.Helper()
	rawArguments, err := json.Marshal(arguments)
	if err != nil {
		t.Fatal(err)
	}
	rawCall, err := json.Marshal(toolCall{Name: name, Arguments: rawArguments})
	if err != nil {
		t.Fatal(err)
	}
	result, rpcErr := server.callTool(context.Background(), rawCall)
	if rpcErr != nil {
		t.Fatalf("%s RPC error=%#v", name, rpcErr)
	}
	return result
}

func callDirectMCPControlTool(t *testing.T, server *Server, name string, arguments map[string]any) (any, error) {
	t.Helper()
	rawArguments, err := json.Marshal(arguments)
	if err != nil {
		t.Fatal(err)
	}
	return server.callControlTool(context.Background(), name, rawArguments)
}

func controlToolIsError(result any) bool {
	value, ok := result.(map[string]any)
	if !ok {
		return true
	}
	isError, _ := value["isError"].(bool)
	return isError
}

func requireAnnotations(t *testing.T, definition map[string]any, readOnly, destructive, idempotent, openWorld bool) {
	t.Helper()
	if definition == nil {
		t.Fatal("missing tool definition")
	}
	annotations, ok := definition["annotations"].(map[string]any)
	if !ok || annotations["readOnlyHint"] != readOnly || annotations["destructiveHint"] != destructive ||
		annotations["idempotentHint"] != idempotent || annotations["openWorldHint"] != openWorld {
		t.Fatalf("annotations=%#v", annotations)
	}
}

func testControlCommand(t *testing.T) []byte {
	t.Helper()
	envelope := dsse.Envelope{
		PayloadType: admission.CommandPayloadType,
		Payload:     base64.StdEncoding.EncodeToString([]byte(`{"schema_version":"steward.executor-command.v2"}`)),
		Signatures: []dsse.Signature{{
			KeyID: "operator-key", Sig: base64.StdEncoding.EncodeToString(make([]byte, 64)),
		}},
	}
	raw, err := dsse.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func testControlEvidenceInspection(t *testing.T) controlprotocol.ExecutorEvidenceInspectionV1 {
	t.Helper()
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	public := private.Public().(ed25519.PublicKey)
	claim, err := controlprotocol.NewExecutorEvidenceIdentityClaimV1(
		"controller-a", "enrollment-a", "node-a", "node-a", 1, public,
	)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := controlprotocol.SignExecutorEvidenceIdentityClaimV1(claim, private)
	if err != nil {
		t.Fatal(err)
	}
	inspection := controlprotocol.ExecutorEvidenceInspectionV1{
		ProtocolVersion:      controlprotocol.ExecutorEvidenceProtocolV1,
		ControllerInstanceID: "controller-a",
		ControlNodeID:        "node-a",
		IdentityProof:        &proof,
		Status: controlprotocol.ExecutorEvidenceStatusV1{
			State: controlprotocol.ExecutorEvidenceStatusCurrent,
			Head: &controlprotocol.ExecutorEvidenceHeadV1{
				Stream: controlprotocol.ExecutorEvidenceStreamV1, ReceiptNodeID: "node-a", ReceiptEpoch: 1,
				ChainHash: "sha256:" + strings.Repeat("0", 64), PublicKeySHA256: claim.PublicKeySHA256,
			},
			WitnessedAt: "2026-07-16T01:02:03Z",
		},
	}
	if err := inspection.Validate(); err != nil {
		t.Fatal(err)
	}
	return inspection
}

func replaceControlArgument(source map[string]any, name string, value any) map[string]any {
	result := make(map[string]any, len(source))
	for key, existing := range source {
		result[key] = existing
	}
	result[name] = value
	return result
}
