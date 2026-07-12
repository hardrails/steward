package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hardrails/steward/internal/admission"
)

func TestNodeCommandsUsePublicLoopbackContract(t *testing.T) {
	const runtimeRef = "executor-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer secret" {
			t.Fatal("missing bearer token")
		}
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodDelete || r.URL.Path == "/v1/state/purge" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		status := "running"
		if r.URL.Path == "/v1/admissions" {
			status = "created"
			w.WriteHeader(http.StatusCreated)
		}
		_, _ = w.Write([]byte(`{"runtime_ref":"` + runtimeRef + `","status":"` + status + `"}`))
	}))
	defer server.Close()
	directory := t.TempDir()
	tokenPath := filepath.Join(directory, "token")
	if err := os.WriteFile(tokenPath, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	common := []string{"-node-url", server.URL, "-token-file", tokenPath}
	for _, action := range []string{"status", "logs", "start", "stop", "destroy"} {
		arguments := append([]string{"node", action}, common...)
		arguments = append(arguments, "-runtime-ref", runtimeRef)
		var output bytes.Buffer
		if err := run(arguments, &output, &bytes.Buffer{}); err != nil {
			t.Fatalf("%s: %v", action, err)
		}
		if !strings.Contains(output.String(), runtimeRef) {
			t.Fatalf("%s output=%s", action, output.String())
		}
	}
	var purgeOutput bytes.Buffer
	arguments := append([]string{"node", "purge-state"}, common...)
	arguments = append(arguments, "-tenant-id", "tenant", "-node-id", "node", "-lineage-id", "lineage", "-generation", "1")
	if err := run(arguments, &purgeOutput, &bytes.Buffer{}); err != nil || !strings.Contains(purgeOutput.String(), `"purged":true`) {
		t.Fatalf("purge output=%s err=%v", purgeOutput.String(), err)
	}
	capsulePath := filepath.Join(directory, "capsule.dsse.json")
	intentPath := filepath.Join(directory, "intent.json")
	if err := os.WriteFile(capsulePath, []byte("signed-capsule"), 0o600); err != nil {
		t.Fatal(err)
	}
	intent, _ := json.Marshal(admission.InstanceIntent{TenantID: "tenant", NodeID: "node", InstanceID: "agent", Generation: 1})
	if err := os.WriteFile(intentPath, intent, 0o600); err != nil {
		t.Fatal(err)
	}
	arguments = append([]string{"node", "admit"}, common...)
	arguments = append(arguments, "-capsule", capsulePath, "-intent", intentPath)
	if err := run(arguments, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
}

func TestNodeCommandsRejectIncompleteArguments(t *testing.T) {
	for _, arguments := range [][]string{
		{"node"},
		{"node", "status"},
		{"node", "admit", "-token-file", "missing"},
		{"node", "unknown", "-token-file", "missing"},
	} {
		if err := run(arguments, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
			t.Fatalf("accepted %#v", arguments)
		}
	}
}
