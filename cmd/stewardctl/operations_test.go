package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStatusComposesControlAndNodeIntoOperatorLanguage(t *testing.T) {
	runtimeRef := "executor-" + strings.Repeat("a", 64)
	control := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer control-secret" {
			t.Fatalf("control authorization = %q", request.Header.Get("Authorization"))
		}
		switch request.URL.Path {
		case "/v1/operations/summary":
			writer.Header().Set("Content-Type", "application/json")
			_, _ = writer.Write([]byte(`{"generated_at":"2026-07-22T00:00:00Z","tenant_id":"tenant-a","capacity":[],"commands":{"total":1,"pending":1,"leased":0,"terminal":0,"done":0,"failed":0,"rejected":0,"outcome_unknown":0},"evidence":{"nodes":1,"active_nodes":1,"witnessed":1,"unwitnessed":0,"current":1,"stale":0,"rollback_detected":0,"equivocation_detected":0},"attention":{"total":1,"warnings":1,"critical":0,"counts":[]}}`))
		case "/v1/operations/attention":
			writer.Header().Set("Content-Type", "application/json")
			_, _ = writer.Write([]byte(`{"items":[{"id":"finding-a","reason":"node_stale","severity":"warning","resource":"node","tenant_id":"tenant-a","node_id":"node-a","title":"Node report is stale","explanation":"The node stopped reporting.","impact":"Placement is blocked.","next_step":"Run the node doctor."}]}`))
		default:
			http.NotFound(writer, request)
		}
	}))
	defer control.Close()
	node := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v1/readiness" || request.Header.Get("Authorization") != "Bearer node-secret" {
			t.Fatalf("node request = %s auth %q", request.URL.Path, request.Header.Get("Authorization"))
		}
		writer.WriteHeader(http.StatusServiceUnavailable)
		_, _ = writer.Write([]byte(`{"status":"degraded","secure_admission":true,"last_attempt":"2026-07-22T00:00:00Z","reconciliation":{"ready":false,"checked":1,"changed":0,"revoked":0,"failures":[{"runtime_ref":"` + runtimeRef + `","code":"workload_missing","message":"untrusted backend detail must not be printed"}]}}`))
	}))
	defer node.Close()
	writeOperationsContext(t, control.URL, node.URL)

	var output bytes.Buffer
	if err := run([]string{"status"}, &output, &bytes.Buffer{}); err != nil {
		t.Fatalf("status: %v", err)
	}
	for _, expected := range []string{
		"Steward: ATTENTION", "Control: 1 attention", "Executor: degraded",
		"Node report is stale", "Signed workload is missing", "stewardctl recover RUNTIME_REF",
	} {
		if !strings.Contains(output.String(), expected) {
			t.Fatalf("status output missing %q: %s", expected, output.String())
		}
	}
	if strings.Contains(output.String(), "untrusted backend detail") {
		t.Fatalf("status exposed backend message: %s", output.String())
	}
}

func TestExplainFiltersOneExactResource(t *testing.T) {
	control := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/v1/operations/summary":
			writer.Header().Set("Content-Type", "application/json")
			_, _ = writer.Write([]byte(`{"generated_at":"2026-07-22T00:00:00Z","tenant_id":"tenant-a","capacity":[],"commands":{},"evidence":{},"attention":{"total":2,"warnings":2,"critical":0,"counts":[]}}`))
		case "/v1/operations/attention":
			writer.Header().Set("Content-Type", "application/json")
			_, _ = writer.Write([]byte(`{"items":[{"id":"a","reason":"node_stale","severity":"warning","resource":"node","node_id":"node-a","title":"A","explanation":"A cause","impact":"A impact","next_step":"A next"},{"id":"b","reason":"node_stale","severity":"warning","resource":"node","node_id":"node-b","title":"B","explanation":"B cause","impact":"B impact","next_step":"B next"}]}`))
		default:
			http.NotFound(writer, request)
		}
	}))
	defer control.Close()
	writeOperationsControlContext(t, control.URL)

	var output bytes.Buffer
	if err := run([]string{"explain", "node-b"}, &output, &bytes.Buffer{}); err != nil {
		t.Fatalf("explain: %v", err)
	}
	if !strings.Contains(output.String(), "B cause") || strings.Contains(output.String(), "A cause") {
		t.Fatalf("filtered explain output = %s", output.String())
	}
}

func TestExplainFindsResourceAfterFirstAttentionPage(t *testing.T) {
	nextCursor := base64.RawURLEncoding.EncodeToString([]byte("attention-page-two"))
	control := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/v1/operations/summary":
			writer.Header().Set("Content-Type", "application/json")
			_, _ = writer.Write([]byte(`{"generated_at":"2026-07-22T00:00:00Z","tenant_id":"tenant-a","capacity":[],"commands":{},"evidence":{},"attention":{"total":2,"warnings":2,"critical":0,"counts":[]}}`))
		case "/v1/operations/attention":
			writer.Header().Set("Content-Type", "application/json")
			if request.URL.Query().Get("cursor") == "" {
				_, _ = writer.Write([]byte(`{"items":[{"id":"a","reason":"node_stale","severity":"warning","resource":"node","node_id":"node-a","title":"A","explanation":"A cause","impact":"A impact","next_step":"A next"}],"next_cursor":"` + nextCursor + `"}`))
				return
			}
			if request.URL.Query().Get("cursor") != nextCursor {
				t.Fatalf("attention cursor = %q", request.URL.Query().Get("cursor"))
			}
			_, _ = writer.Write([]byte(`{"items":[{"id":"b","reason":"node_stale","severity":"warning","resource":"node","node_id":"node-b","title":"B","explanation":"B cause","impact":"B impact","next_step":"B next"}]}`))
		default:
			http.NotFound(writer, request)
		}
	}))
	defer control.Close()
	writeOperationsControlContext(t, control.URL)

	var output bytes.Buffer
	if err := run([]string{"explain", "node-b"}, &output, &bytes.Buffer{}); err != nil {
		t.Fatalf("explain later finding: %v", err)
	}
	if !strings.Contains(output.String(), "B cause") || strings.Contains(output.String(), "A cause") ||
		strings.Contains(output.String(), "more attention findings") {
		t.Fatalf("paged explain output = %s", output.String())
	}
}

func TestRecoverRequiresPreviewAndExecutorRechecksApply(t *testing.T) {
	runtimeRef := "executor-" + strings.Repeat("a", 64)
	deletes := 0
	node := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/v1/readiness":
			writer.WriteHeader(http.StatusServiceUnavailable)
			_, _ = writer.Write([]byte(`{"status":"degraded","secure_admission":true,"reconciliation":{"ready":false,"checked":1,"changed":0,"revoked":0,"failures":[{"runtime_ref":"` + runtimeRef + `","code":"workload_missing","message":"missing"}]}}`))
		case request.Method == http.MethodDelete && request.URL.Path == "/v1/workloads/"+runtimeRef:
			deletes++
			writer.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer node.Close()
	writeOperationsNodeContext(t, node.URL)

	var preview bytes.Buffer
	if err := run([]string{"recover", runtimeRef}, &preview, &bytes.Buffer{}); err != nil {
		t.Fatalf("preview recovery: %v", err)
	}
	if deletes != 0 || !strings.Contains(preview.String(), "Safe:     true") || !strings.Contains(preview.String(), "Applied:  false") {
		t.Fatalf("preview deletes=%d output=%s", deletes, preview.String())
	}
	var applied bytes.Buffer
	if err := run([]string{"recover", runtimeRef, "--apply"}, &applied, &bytes.Buffer{}); err != nil {
		t.Fatalf("apply recovery: %v", err)
	}
	if deletes != 1 || !strings.Contains(applied.String(), "Applied:  true") {
		t.Fatalf("apply deletes=%d output=%s", deletes, applied.String())
	}
}

func TestRecoverRejectsAmbiguousStateWithoutMutation(t *testing.T) {
	runtimeRef := "executor-" + strings.Repeat("a", 64)
	deletes := 0
	node := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodDelete {
			deletes++
		}
		writer.WriteHeader(http.StatusServiceUnavailable)
		_, _ = writer.Write([]byte(`{"status":"degraded","secure_admission":true,"reconciliation":{"ready":false,"checked":1,"changed":0,"revoked":0,"failures":[{"runtime_ref":"` + runtimeRef + `","code":"journal_pending","message":"pending"}]}}`))
	}))
	defer node.Close()
	writeOperationsNodeContext(t, node.URL)

	var output bytes.Buffer
	err := run([]string{"recover", runtimeRef, "--apply"}, &output, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "cannot currently prove") || deletes != 0 || !strings.Contains(output.String(), "Safe:     false") {
		t.Fatalf("ambiguous recovery deletes=%d output=%s error=%v", deletes, output.String(), err)
	}
}

func TestOperatorStatusJSONKeepsSourceFailureMachineReadable(t *testing.T) {
	status := collectOperatorStatus(operatorConnections{
		contextName:  "site-a",
		controlURL:   "https://control.invalid",
		controlToken: filepath.Join(t.TempDir(), "missing.token"),
	}, "")
	if status.State != "unavailable" || len(status.SourceErrors) != 1 {
		t.Fatalf("unavailable status = %#v", status)
	}
	var output bytes.Buffer
	if err := writeOperatorStatus(&output, status, "json", false); err != nil {
		t.Fatal(err)
	}
	var decoded operatorStatus
	if err := json.Unmarshal(output.Bytes(), &decoded); err != nil {
		t.Fatalf("decode status JSON: %v", err)
	}
	if decoded.SchemaVersion != operatorStatusSchema || decoded.Context != "site-a" || decoded.State != "unavailable" {
		t.Fatalf("decoded status = %#v", decoded)
	}
}

func TestOperatorConnectionValidationFailsClosed(t *testing.T) {
	tests := []struct {
		name      string
		arguments []string
		want      string
	}{
		{name: "duplicate context opt out", arguments: []string{"-no-context", "--no-context"}, want: "only once"},
		{name: "invalid output", arguments: []string{"-no-context", "-control-url", "https://control.example", "-token-file", "/token", "-output", "yaml"}, want: "output must"},
		{name: "watch too fast", arguments: []string{"-no-context", "-control-url", "https://control.example", "-token-file", "/token", "-watch", "999ms"}, want: "watch must"},
		{name: "missing token", arguments: []string{"-no-context", "-control-url", "https://control.example"}, want: "requires both"},
		{name: "no connection", arguments: []string{"-no-context"}, want: "no Control or node"},
		{name: "positional status argument", arguments: []string{"-no-context", "-control-url", "https://control.example", "-token-file", "/token", "extra"}, want: "only named flags"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := parseOperatorConnections("status", test.arguments, true)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want substring %q", err, test.want)
			}
		})
	}
	_, _, err := parseExplainConnections([]string{
		"-no-context", "-control-url", "https://control.example", "-token-file", "/token", "node-a", "node-b",
	})
	if err == nil || !strings.Contains(err.Error(), "at most one") {
		t.Fatalf("explain positional error = %v", err)
	}
}

func TestRecoverArgumentNormalizationAcceptsFlagsOnEitherSide(t *testing.T) {
	arguments, err := normalizeRecoverArguments([]string{"runtime-a", "--output=json", "--apply", "--node-url", "http://127.0.0.1:8090"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"--output=json", "--apply", "--node-url", "http://127.0.0.1:8090", "runtime-a"}
	if strings.Join(arguments, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("normalized arguments = %q, want %q", arguments, want)
	}
	for _, test := range []struct {
		arguments []string
		want      string
	}{
		{arguments: []string{"runtime-a", "--output"}, want: "requires a value"},
		{arguments: []string{"runtime-a", "--force"}, want: "unknown recover option"},
	} {
		if _, err := normalizeRecoverArguments(test.arguments); err == nil || !strings.Contains(err.Error(), test.want) {
			t.Fatalf("normalize %q error = %v, want substring %q", test.arguments, err, test.want)
		}
	}
}

func TestNodeFailureGuidanceCoversEveryFailureClass(t *testing.T) {
	tests := []struct {
		code     string
		critical bool
	}{
		{code: "workload_missing"},
		{code: "workload_drift", critical: true},
		{code: "workload_identity_drift", critical: true},
		{code: "journal_pending", critical: true},
		{code: "journal_ambiguous", critical: true},
		{code: "journal_unavailable", critical: true},
		{code: "evidence_ambiguous", critical: true},
		{code: "evidence_unavailable", critical: true},
		{code: "workload_inspect", critical: true},
		{code: "verification_ambiguous", critical: true},
		{code: "repair_ambiguous", critical: true},
		{code: "lease_cleanup_ambiguous", critical: true},
		{code: "secure_admission_unavailable", critical: true},
		{code: "record_limit", critical: true},
		{code: "operation_identity"},
		{code: "invalid_context"},
		{code: "context_done"},
		{code: "reconciliation_failed"},
	}
	for _, test := range tests {
		t.Run(test.code, func(t *testing.T) {
			title, explanation, impact, nextStep, blocked, critical := nodeFailureGuidance(test.code)
			if title == "" || explanation == "" || impact == "" || nextStep == "" || len(blocked) == 0 {
				t.Fatalf("incomplete guidance for %s", test.code)
			}
			if critical != test.critical {
				t.Fatalf("critical = %t, want %t", critical, test.critical)
			}
		})
	}
	title, explanation, impact, nextStep, blocked, critical := nodeFailureGuidance("future_failure")
	if title != "" || explanation != "" || impact != "" || nextStep != "" || len(blocked) == 0 || !critical {
		t.Fatalf("unknown guidance = %q %q %q %q %q %t", title, explanation, impact, nextStep, blocked, critical)
	}
}

func writeOperationsContext(t *testing.T, controlURL, nodeURL string) {
	t.Helper()
	directory := t.TempDir()
	controlToken := filepath.Join(directory, "control.token")
	nodeToken := filepath.Join(directory, "node.token")
	writeOperationsToken(t, controlToken, "control-secret")
	writeOperationsToken(t, nodeToken, "node-secret")
	writeOperationsContextFile(t, directory, cliContext{
		Name: "test", ControlURL: controlURL, TokenFile: controlToken, TenantID: "tenant-a",
		NodeURL: nodeURL, NodeTokenFile: nodeToken,
	})
}

func writeOperationsControlContext(t *testing.T, controlURL string) {
	t.Helper()
	directory := t.TempDir()
	token := filepath.Join(directory, "control.token")
	writeOperationsToken(t, token, "control-secret")
	writeOperationsContextFile(t, directory, cliContext{Name: "test", ControlURL: controlURL, TokenFile: token, TenantID: "tenant-a"})
}

func writeOperationsNodeContext(t *testing.T, nodeURL string) {
	t.Helper()
	directory := t.TempDir()
	token := filepath.Join(directory, "node.token")
	writeOperationsToken(t, token, "node-secret")
	writeOperationsContextFile(t, directory, cliContext{Name: "test", NodeURL: nodeURL, NodeTokenFile: token})
}

func writeOperationsContextFile(t *testing.T, directory string, selected cliContext) {
	t.Helper()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "contexts.json")
	t.Setenv("STEWARD_CONTEXT_FILE", path)
	if err := writeCLIContextConfig(path, cliContextConfig{
		SchemaVersion: cliContextSchema, Current: selected.Name, Contexts: []cliContext{selected},
	}); err != nil {
		t.Fatal(err)
	}
}

func writeOperationsToken(t *testing.T, path, value string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(value+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}
