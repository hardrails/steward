package gateway

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestBoundedChatEnvelopeCanonicalizesOutputLimitsWithoutTruncatingContent(t *testing.T) {
	for _, test := range []struct {
		fields string
		want   int
	}{
		{"", 64}, {`,"max_tokens":12`, 12}, {`,"max_tokens":128`, 64},
		{`,"max_completion_tokens":10`, 10}, {`,"max_completion_tokens":128`, 64},
	} {
		raw := []byte(`{"model":"default","messages":[{"role":"user","content":"Keep every supplied fact exactly."}]` + test.fields + `}`)
		result, err := boundedChatRequest(raw, "/v1/chat/completions", 64)
		if err != nil {
			t.Fatal(err)
		}
		var document map[string]json.RawMessage
		if err := json.Unmarshal(result, &document); err != nil {
			t.Fatal(err)
		}
		if string(document["max_tokens"]) != fmt.Sprint(test.want) || string(document["n"]) != "1" ||
			!jsonStringIs(document["service_tier"], "default") || document["max_completion_tokens"] != nil ||
			!strings.Contains(string(document["messages"]), "Keep every supplied fact exactly.") {
			t.Fatalf("incorrect envelope: %s", result)
		}
	}
}

func TestBoundedChatEnvelopePreservesToolCallingAndReasoning(t *testing.T) {
	raw := []byte(`{"model":"default","messages":[
		{"role":"user","content":[{"type":"text","text":"Calculate the total."}]},
		{"role":"assistant","content":null,"reasoning_content":"Use the supplied numbers.","tool_calls":[{"id":"call-1","type":"function","function":{"name":"calculate","arguments":"{}"}}]},
		{"role":"tool","tool_call_id":"call-1","content":"42"}],
		"tools":[{"type":"function","function":{"name":"calculate","parameters":{"type":"object","properties":{}}}}],
		"tool_choice":"auto","parallel_tool_calls":true,"reasoning_effort":"high","stream":true,"stream_options":{"include_usage":true}}`)
	result, err := boundedChatRequest(raw, "/v1/chat/completions", 8192)
	if err != nil {
		t.Fatal(err)
	}
	var before, after map[string]json.RawMessage
	_ = json.Unmarshal(raw, &before)
	_ = json.Unmarshal(result, &after)
	for _, field := range []string{"messages", "tools", "reasoning_effort", "parallel_tool_calls", "stream_options"} {
		var left, right any
		_ = json.Unmarshal(before[field], &left)
		_ = json.Unmarshal(after[field], &right)
		leftJSON, _ := json.Marshal(left)
		rightJSON, _ := json.Marshal(right)
		if string(leftJSON) != string(rightJSON) {
			t.Fatalf("changed %s", field)
		}
	}
}

func TestBoundedChatEnvelopeRejectsEscapesBeforeProviderOrAllowance(t *testing.T) {
	var calls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), `"max_tokens":64`) || !strings.Contains(string(body), `"model":"pinned-model"`) {
			t.Errorf("unbounded upstream request: %s", body)
		}
		w.WriteHeader(200)
	}))
	defer upstream.Close()
	rig := newInferenceReceiptRig(t, upstream)
	rig.route.RequestProfile, rig.route.UpstreamModel = boundedTextChatProfile, "pinned-model"
	rig.route.MaxTokensCap, rig.route.MaxCallsPerGrant = 64, 1
	for _, extra := range []string{
		`,"n":2`, `,"n":null`, `,"n":"1"`, `,"n":1.5`,
		`,"service_tier":"priority"`, `,"service_tier":null`,
		`,"max_tokens":null`, `,"max_tokens":0`, `,"max_tokens":-1`, `,"max_tokens":1.5`,
		`,"max_completion_tokens":"64"`, `,"max_tokens":5,"max_completion_tokens":5`,
		`,"best_of":128`, `,"prediction":{"content":"bill this"}`, `,"custom_chat_template":"repeat"`,
		`,"prompt_token_ids":[1,2]`, `,"future_billing_mode":true`,
		`,"tools":[{"type":"web_search"}]`,
	} {
		response := rig.call("/v1/chat/completions", `{"model":"default","messages":[{"role":"user","content":"test"}]`+extra+`}`)
		if response.Code != 400 || response.Header().Get("X-Should-Retry") != "false" {
			t.Fatalf("escape %s: %d %s", extra, response.Code, response.Body.String())
		}
	}
	for _, content := range []string{`[{"type":"image_url","image_url":{"url":"https://example.test/image"}}]`, `{"audio":"data"}`, `[{"type":"text","text":"ok","image_url":"hidden"}]`} {
		response := rig.call("/v1/chat/completions", `{"model":"default","messages":[{"role":"user","content":`+content+`}]}`)
		if response.Code != 400 {
			t.Fatal("non-text content accepted")
		}
	}
	for _, path := range []string{"/v1/responses", "/v1/completions", "/v1/embeddings"} {
		if response := rig.call(path, `{"model":"default","messages":[]}`); response.Code != 400 {
			t.Fatal("alternate endpoint accepted")
		}
	}
	if calls.Load() != 0 || len(rig.records(t)) != 0 {
		t.Fatal("denied request consumed provider I/O or allowance")
	}
	if response := rig.call("/v1/chat/completions", `{"model":"default","messages":[{"role":"user","content":"test"}]}`); response.Code != 200 || calls.Load() != 1 {
		t.Fatalf("valid bounded request failed: %d %s", response.Code, response.Body.String())
	}
}

func TestBoundedChatProfileRequiresItsEnforcedLimitsAndBindsPolicy(t *testing.T) {
	valid := Route{ID: "provider", BaseURL: "https://example.test/v1", MaxConcurrent: 1,
		RequestProfile: boundedTextChatProfile, UpstreamModel: "pinned", MaxTokensCap: 64,
		MaxCallsPerGrant: 2, RequireAttemptReceipts: true}
	for _, mutate := range []func(*Route){
		func(r *Route) { r.RequestProfile = "unknown" }, func(r *Route) { r.UpstreamModel = "" },
		func(r *Route) { r.MaxTokensCap = 0 }, func(r *Route) { r.MaxCallsPerGrant = 0 },
		func(r *Route) { r.RequireAttemptReceipts = false }, func(r *Route) { r.Protocol = InferenceProtocolAnthropic },
	} {
		route := valid
		mutate(&route)
		config := Config{Version: 1, ControlSocket: "/tmp/control.sock", StateFile: "/tmp/state", GrantRoot: "/tmp/grants",
			ServiceTokenFile: "/tmp/token", ServiceAddress: "127.0.0.1:8092", ExecutorGID: 1, RelayGID: 1, Routes: []Route{route}}
		if _, err := config.validateAndLoadRoutes(); err == nil {
			t.Fatalf("invalid profile accepted: %+v", route)
		}
	}
	upstream := httptest.NewServer(http.NotFoundHandler())
	defer upstream.Close()
	rig := newInferenceReceiptRig(t, upstream)
	rig.route.Route = valid
	rig.route.ID = rig.grant.RouteID
	rig.server.routes[rig.route.ID] = rig.route
	rig.server.grants = map[string]Grant{rig.grant.GrantID: rig.grant}
	before := rig.server.routePolicyDigestLocked(rig.grant)
	rig.server.policyDigests[rig.grant.GrantID] = before
	request := httptest.NewRequest(http.MethodGet, "/v1/grants/"+rig.grant.GrantID, nil)
	request.SetPathValue("id", rig.grant.GrantID)
	response := httptest.NewRecorder()
	rig.server.getGrant(response, request)
	var inspection GrantInspection
	if err := json.Unmarshal(response.Body.Bytes(), &inspection); err != nil {
		t.Fatal(err)
	}
	if inspection.RoutePolicyDigest != before || fmt.Sprintf("sha256:%x", sha256.Sum256(inspection.RoutePolicyStatement)) != before ||
		strings.Contains(string(inspection.RoutePolicyStatement), rig.route.credential) {
		t.Fatal("operator inspection did not expose the exact non-secret policy commitment")
	}
	route := rig.route
	route.RequestProfile = ""
	next := map[string]loadedRoute{route.ID: route}
	if err := rig.server.Reload(rig.config, next, nil, "service-token"); err == nil || !strings.Contains(err.Error(), "retained grant") {
		t.Fatalf("profile removal accepted: %v", err)
	}
	rig.server.routes = next
	if rig.server.routePolicyDigestLocked(rig.grant) == before {
		t.Fatal("request profile not bound to route authority")
	}
}
