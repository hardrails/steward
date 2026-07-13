package mcpserver

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/controlclient"
	"github.com/hardrails/steward/internal/dsse"
)

type fakeControl struct {
	calls   []string
	command []byte
	err     error
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

func TestMCPControlToolsAreOptionalAndAccuratelyAnnotated(t *testing.T) {
	controlOnly, err := NewConfigured(Config{Control: &fakeControl{}, Version: "v1"})
	if err != nil {
		t.Fatal(err)
	}
	listed := controlOnly.configuredTools()
	if len(listed) != 7 {
		t.Fatalf("control-only tool count=%d", len(listed))
	}
	raw := string(mustJSON(t, listed))
	for _, name := range []string{
		"steward_control_tenant_list", "steward_control_tenant_create", "steward_control_node_list",
		"steward_control_node_status", "steward_control_node_revoke", "steward_control_command_submit",
		"steward_control_command_status",
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
	control := &fakeControl{}
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
	}
	for _, call := range calls {
		result := callMCPControlTool(t, server, call.name, call.arguments)
		if controlToolIsError(result) {
			t.Fatalf("%s failed: %#v", call.name, result)
		}
	}
	wantCalls := []string{
		"tenant-list:tenant-0:25", "tenant-create:tenant-a", "node-list:tenant-a:node-0:50",
		"node-status:tenant-a:node-a", "node-revoke:node-a", "command-submit:tenant-a:node-a",
		"command-status:tenant-a:node-a:command-a",
	}
	if strings.Join(control.calls, "|") != strings.Join(wantCalls, "|") {
		t.Fatalf("calls=%#v", control.calls)
	}
	if !bytes.Equal(control.command, command) {
		t.Fatal("MCP did not preserve exact signed command bytes")
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
		!strings.Contains(raw, "steward_control_command_submit") || strings.Contains(raw, "steward_admit") || strings.Contains(raw, "steward_task_submit") {
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

func replaceControlArgument(source map[string]any, name string, value any) map[string]any {
	result := make(map[string]any, len(source))
	for key, existing := range source {
		result[key] = existing
	}
	result[name] = value
	return result
}
