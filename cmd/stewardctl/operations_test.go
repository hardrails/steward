package main

import (
	"bytes"
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
