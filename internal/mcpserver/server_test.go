package mcpserver

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/nodeclient"
)

type fakeNode struct {
	calls     []string
	destroyed string
	err       error
	logs      string
}

type deadlineObservation struct {
	deadline time.Time
	observed time.Time
	ok       bool
}

type deadlineNode struct {
	fakeNode
	observations []deadlineObservation
}

func (n *deadlineNode) observe(ctx context.Context) {
	deadline, ok := ctx.Deadline()
	n.observations = append(n.observations, deadlineObservation{
		deadline: deadline,
		observed: time.Now(),
		ok:       ok,
	})
}

func (n *deadlineNode) Admit(ctx context.Context, capsule []byte, intent admission.InstanceIntent) (nodeclient.State, error) {
	n.observe(ctx)
	return n.fakeNode.Admit(ctx, capsule, intent)
}

func (n *deadlineNode) Status(ctx context.Context, runtimeRef string) (nodeclient.State, error) {
	n.observe(ctx)
	return n.fakeNode.Status(ctx, runtimeRef)
}

func (n *deadlineNode) PurgeState(ctx context.Context, request nodeclient.StatePurge) error {
	n.observe(ctx)
	return n.fakeNode.PurgeState(ctx, request)
}

func (n *fakeNode) Admit(_ context.Context, _ []byte, intent admission.InstanceIntent) (nodeclient.State, error) {
	n.calls = append(n.calls, "admit:"+intent.InstanceID)
	return nodeclient.State{RuntimeRef: runtimeRef(), Status: "created", Generation: intent.Generation}, nil
}
func (n *fakeNode) Status(context.Context, string) (nodeclient.State, error) {
	n.calls = append(n.calls, "status")
	return nodeclient.State{RuntimeRef: runtimeRef(), Status: "running"}, n.err
}
func (n *fakeNode) Logs(context.Context, string) (nodeclient.State, error) {
	n.calls = append(n.calls, "logs")
	logs := n.logs
	if logs == "" {
		logs = "hello"
	}
	return nodeclient.State{RuntimeRef: runtimeRef(), Status: "running", Logs: logs}, nil
}
func (n *fakeNode) EgressStats(context.Context, string) (nodeclient.EgressStats, error) {
	n.calls = append(n.calls, "egress")
	return nodeclient.EgressStats{Allowed: 2, Denied: 1}, n.err
}
func (n *fakeNode) Start(context.Context, string) (nodeclient.State, error) {
	n.calls = append(n.calls, "start")
	return nodeclient.State{RuntimeRef: runtimeRef(), Status: "running"}, nil
}
func (n *fakeNode) Stop(context.Context, string) (nodeclient.State, error) {
	n.calls = append(n.calls, "stop")
	return nodeclient.State{RuntimeRef: runtimeRef(), Status: "exited"}, nil
}
func (n *fakeNode) Destroy(_ context.Context, ref string) error {
	n.calls = append(n.calls, "destroy")
	n.destroyed = ref
	return nil
}
func (n *fakeNode) PurgeState(_ context.Context, request nodeclient.StatePurge) error {
	n.calls = append(n.calls, "purge:"+request.LineageID)
	return nil
}

func TestMCPInitializeListAndCallTools(t *testing.T) {
	node := &fakeNode{}
	server, err := New(node, "v1.3.0")
	if err != nil {
		t.Fatal(err)
	}
	input := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"steward_status","arguments":{"runtime_ref":"` + runtimeRef() + `"}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"steward_destroy","arguments":{"runtime_ref":"` + runtimeRef() + `"}}}`,
	}, "\n") + "\n"
	var output, logs bytes.Buffer
	if err := server.Serve(context.Background(), strings.NewReader(input), &output, &logs); err != nil {
		t.Fatal(err)
	}
	if logs.Len() != 0 {
		t.Fatalf("unexpected stderr: %s", logs.String())
	}
	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(lines) != 4 {
		t.Fatalf("responses=%d output=%s", len(lines), output.String())
	}
	var initialize map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &initialize); err != nil {
		t.Fatal(err)
	}
	result, ok := initialize["result"].(map[string]any)
	if !ok {
		t.Fatalf("initialize response=%s; all output=%s", lines[0], output.String())
	}
	if result["protocolVersion"] != ProtocolVersion {
		t.Fatalf("initialize=%#v", initialize)
	}
	if !strings.Contains(lines[1], "steward_admit") || !strings.Contains(lines[2], `\"status\":\"running\"`) {
		t.Fatalf("unexpected output: %s", output.String())
	}
	if node.destroyed != runtimeRef() {
		t.Fatalf("destroyed=%q", node.destroyed)
	}
}

func TestMCPAdmitAndProtocolErrors(t *testing.T) {
	node := &fakeNode{}
	server, _ := New(node, "v1.3.0")
	intent, _ := json.Marshal(admission.InstanceIntent{TenantID: "tenant", NodeID: "node", InstanceID: "agent", Generation: 2})
	arguments, _ := json.Marshal(map[string]string{
		"capsule_dsse_base64": base64.StdEncoding.EncodeToString([]byte("capsule")),
		"intent_json":         string(intent),
	})
	input := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`,
		`{"jsonrpc":"2.0","id":2,"method":"initialize","params":{"protocolVersion":"old","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"steward_admit","arguments":` + string(arguments) + `}}`,
		`{"jsonrpc":"2.0","id":4,"method":"unknown"}`,
		`not-json`,
	}, "\n") + "\n"
	var output bytes.Buffer
	if err := server.Serve(context.Background(), strings.NewReader(input), &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `"code":-32002`) || !strings.Contains(output.String(), `"code":-32601`) || !strings.Contains(output.String(), `"code":-32700`) {
		t.Fatalf("missing protocol errors: %s", output.String())
	}
	if len(node.calls) != 1 || node.calls[0] != "admit:agent" {
		t.Fatalf("calls=%#v", node.calls)
	}
}

func TestMCPAllLifecycleToolsAndToolFailures(t *testing.T) {
	node := &fakeNode{}
	server, _ := New(node, "v1.3.0")
	ref := runtimeRef()
	input := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"steward_logs","arguments":{"runtime_ref":"` + ref + `"}}}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"steward_start","arguments":{"runtime_ref":"` + ref + `"}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"steward_stop","arguments":{"runtime_ref":"` + ref + `"}}}`,
		`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"steward_purge_state","arguments":{"tenant_id":"tenant","node_id":"node","lineage_id":"lineage","generation":1}}}`,
		`{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"steward_status","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"missing","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":8,"method":"initialize","params":{}}`,
		`{"jsonrpc":"2.0","id":{},"method":"ping"}`,
	}, "\n") + "\n"
	var output bytes.Buffer
	if err := server.Serve(context.Background(), strings.NewReader(input), &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"logs", "start", "stop", "purge:lineage"} {
		if !strings.Contains(strings.Join(node.calls, ","), want) {
			t.Fatalf("missing call %q in %#v", want, node.calls)
		}
	}
	if !strings.Contains(output.String(), `"isError":true`) || !strings.Contains(output.String(), `"code":-32602`) || !strings.Contains(output.String(), `"code":-32600`) {
		t.Fatalf("missing tool errors: %s", output.String())
	}
	node.err = errors.New(strings.Repeat("sensitive", 600))
	result, rpcErr := server.callTool(context.Background(), json.RawMessage(`{"name":"steward_status","arguments":{"runtime_ref":"`+ref+`"}}`))
	if rpcErr != nil || !strings.Contains(string(mustJSON(t, result)), `"isError":true`) || len(string(mustJSON(t, result))) > 5000 {
		t.Fatalf("bounded tool failure result=%#v rpcErr=%#v", result, rpcErr)
	}
}

func TestMCPNodeToolsUseBoundedOperationContexts(t *testing.T) {
	node := &deadlineNode{}
	server, err := New(node, "v1")
	if err != nil {
		t.Fatal(err)
	}
	intent, err := json.Marshal(admission.InstanceIntent{
		TenantID: "tenant", NodeID: "node", InstanceID: "agent", Generation: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	admitArguments, err := json.Marshal(map[string]string{
		"capsule_dsse_base64": base64.StdEncoding.EncodeToString([]byte("capsule")),
		"intent_json":         string(intent),
	})
	if err != nil {
		t.Fatal(err)
	}
	calls := []json.RawMessage{
		json.RawMessage(`{"name":"steward_admit","arguments":` + string(admitArguments) + `}`),
		json.RawMessage(`{"name":"steward_status","arguments":{"runtime_ref":"` + runtimeRef() + `"}}`),
		json.RawMessage(`{"name":"steward_purge_state","arguments":{"tenant_id":"tenant","node_id":"node","lineage_id":"lineage","generation":1}}`),
	}
	for _, call := range calls {
		result, rpcErr := server.callTool(context.Background(), call)
		if rpcErr != nil || strings.Contains(string(mustJSON(t, result)), `"isError":true`) {
			t.Fatalf("call=%s result=%#v rpcErr=%#v", call, result, rpcErr)
		}
	}
	if len(node.observations) != len(calls) {
		t.Fatalf("observations=%d want=%d", len(node.observations), len(calls))
	}
	for index, observation := range node.observations {
		remaining := observation.deadline.Sub(observation.observed)
		if !observation.ok || remaining <= nodeOperationTimeout-time.Second || remaining > nodeOperationTimeout {
			t.Fatalf("observation %d deadline_ok=%t remaining=%s", index, observation.ok, remaining)
		}
	}
}

func TestMCPNodeToolsPreserveEarlierCallerDeadline(t *testing.T) {
	node := &deadlineNode{}
	server, err := New(node, "v1")
	if err != nil {
		t.Fatal(err)
	}
	parentDeadline := time.Now().Add(2 * time.Second)
	ctx, cancel := context.WithDeadline(context.Background(), parentDeadline)
	defer cancel()
	result, rpcErr := server.callTool(ctx, json.RawMessage(`{"name":"steward_status","arguments":{"runtime_ref":"`+runtimeRef()+`"}}`))
	if rpcErr != nil || strings.Contains(string(mustJSON(t, result)), `"isError":true`) {
		t.Fatalf("result=%#v rpcErr=%#v", result, rpcErr)
	}
	if len(node.observations) != 1 {
		t.Fatalf("observations=%d want=1", len(node.observations))
	}
	if !node.observations[0].ok || !node.observations[0].deadline.Equal(parentDeadline) {
		t.Fatalf("deadline_ok=%t deadline=%s want=%s", node.observations[0].ok, node.observations[0].deadline, parentDeadline)
	}
}

func TestMCPConstructionCancellationAndOversizedInput(t *testing.T) {
	if _, err := New(nil, "v1"); err == nil {
		t.Fatal("expected nil node error")
	}
	if _, err := New(&fakeNode{}, " "); err == nil {
		t.Fatal("expected empty version error")
	}
	server, _ := New(&fakeNode{}, "v1")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := server.Serve(ctx, strings.NewReader("{}\n"), &bytes.Buffer{}, &bytes.Buffer{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel error=%v", err)
	}
	var logs bytes.Buffer
	err := server.Serve(context.Background(), strings.NewReader(strings.Repeat("x", maxMessageBytes+1)), &bytes.Buffer{}, &logs)
	if err == nil || !strings.Contains(logs.String(), "exceeds 1 MiB") {
		t.Fatalf("oversized err=%v logs=%q", err, logs.String())
	}
	if err := server.Serve(context.Background(), nil, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("expected nil stream error")
	}
}

func TestMCPValidationAndArgumentFailures(t *testing.T) {
	server, _ := New(&fakeNode{}, "v1")
	input := strings.Join([]string{
		` `,
		`{"jsonrpc":"1.0","id":"bad","method":"ping"}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`,
		`{"jsonrpc":"2.0","id":2,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":3,"method":"ping"}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{}}`,
	}, "\n") + "\n"
	var output bytes.Buffer
	if err := server.Serve(context.Background(), strings.NewReader(input), &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"code":-32600`, `"code":-32602`, `"id":3`} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("missing %s in %s", want, output.String())
		}
	}
	for _, raw := range []string{
		`{"name":"steward_admit","arguments":{}}`,
		`{"name":"steward_admit","arguments":{"capsule_dsse_base64":"%%%","intent_json":"{}"}}`,
		`{"name":"steward_admit","arguments":{"capsule_dsse_base64":"eA==","intent_json":"not-json"}}`,
		`{"name":"steward_purge_state","arguments":{}}`,
		`{"name":"steward_logs","arguments":{}}`,
	} {
		result, rpcErr := server.callTool(context.Background(), json.RawMessage(raw))
		if rpcErr != nil || !strings.Contains(string(mustJSON(t, result)), `"isError":true`) {
			t.Fatalf("raw=%s result=%#v rpcErr=%#v", raw, result, rpcErr)
		}
	}
	if _, rpcErr := server.callTool(context.Background(), json.RawMessage(`{}`)); rpcErr == nil {
		t.Fatal("malformed tool call accepted")
	}
	if validID(json.RawMessage(`[]`)) || !validID(json.RawMessage(`"id"`)) {
		t.Fatal("ID validation mismatch")
	}
	if string(normalizedID(json.RawMessage(`"id"`))) != `"id"` || string(normalizedID(json.RawMessage(`{}`))) != "null" {
		t.Fatal("ID normalization mismatch")
	}
}

func TestMCPLogsPreserveValidNearLimitNodeOutput(t *testing.T) {
	node := &fakeNode{logs: strings.Repeat("x", 950<<10)}
	server, _ := New(node, "v1")
	result, rpcErr := server.callTool(context.Background(), json.RawMessage(`{"name":"steward_logs","arguments":{"runtime_ref":"`+runtimeRef()+`"}}`))
	if rpcErr != nil {
		t.Fatal(rpcErr)
	}
	raw := string(mustJSON(t, result))
	if strings.Contains(raw, `"isError":true`) || !strings.Contains(raw, strings.Repeat("x", 1024)) {
		t.Fatal("valid near-limit logs were rejected")
	}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func runtimeRef() string { return "executor-" + strings.Repeat("a", 64) }
