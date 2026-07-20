package main

import (
	"bytes"
	"encoding/json"
	"fmt"
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
		if r.URL.Path == "/v1/state/snapshots" {
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"status":"stopped","snapshot_id":"snap","tenant_id":"tenant","source_lineage_id":"lineage","content_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","retained_bytes":0,"object_count":0,"created_at":"2026-07-20T00:00:00Z"}`))
			return
		}
		if r.URL.Path == "/v1/state/clones" {
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"status":"stopped","tenant_id":"tenant","instance_id":"fork","lineage_id":"fork-lineage","snapshot_id":"snap"}`))
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
	var positionalOutput bytes.Buffer
	positional := append([]string{"node", "status"}, common...)
	positional = append(positional, runtimeRef)
	if err := run(positional, &positionalOutput, &bytes.Buffer{}); err != nil ||
		!strings.Contains(positionalOutput.String(), runtimeRef) {
		t.Fatalf("positional runtime output=%s err=%v", positionalOutput.String(), err)
	}
	ambiguous := append([]string{"node", "status"}, common...)
	ambiguous = append(ambiguous, "-runtime-ref", runtimeRef, runtimeRef)
	if err := run(ambiguous, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("node status accepted both positional and flagged runtime references")
	}
	var purgeOutput bytes.Buffer
	arguments := append([]string{"node", "purge-state"}, common...)
	arguments = append(arguments, "-tenant-id", "tenant", "-node-id", "node", "-lineage-id", "lineage", "-generation", "1")
	if err := run(arguments, &purgeOutput, &bytes.Buffer{}); err != nil || !strings.Contains(purgeOutput.String(), `"purged":true`) {
		t.Fatalf("purge output=%s err=%v", purgeOutput.String(), err)
	}
	var snapshotOutput bytes.Buffer
	arguments = append([]string{"node", "snapshot-state"}, common...)
	arguments = append(arguments, "-tenant-id", "tenant", "-node-id", "node", "-instance-id", "source", "-lineage-id", "lineage", "-generation", "1", "-snapshot-id", "snap")
	if err := run(arguments, &snapshotOutput, &bytes.Buffer{}); err != nil || !strings.Contains(snapshotOutput.String(), `"snapshot_id":"snap"`) {
		t.Fatalf("snapshot output=%s err=%v", snapshotOutput.String(), err)
	}
	var cloneOutput bytes.Buffer
	arguments = append([]string{"node", "clone-state"}, common...)
	arguments = append(arguments, "-tenant-id", "tenant", "-node-id", "node", "-instance-id", "fork", "-lineage-id", "fork-lineage", "-generation", "1", "-snapshot-id", "snap", "-source-lineage-id", "lineage")
	if err := run(arguments, &cloneOutput, &bytes.Buffer{}); err != nil || !strings.Contains(cloneOutput.String(), `"instance_id":"fork"`) {
		t.Fatalf("clone output=%s err=%v", cloneOutput.String(), err)
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

func TestNodeWhoAmIUsesScopedCredential(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/local-principal" ||
			r.Header.Get("Authorization") != "Bearer observer-secret" {
			t.Fatalf("unexpected request %s %s auth=%q", r.Method, r.URL.Path, r.Header.Get("Authorization"))
		}
		_, _ = w.Write([]byte(`{"schema_version":"steward.executor-local-principal.v1","id":"observer","role":"observer"}`))
	}))
	defer server.Close()
	tokenPath := filepath.Join(t.TempDir(), "observer-token")
	if err := os.WriteFile(tokenPath, []byte("observer-secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := run([]string{"node", "whoami", "-node-url", server.URL, "-token-file", tokenPath}, &output, &bytes.Buffer{}); err != nil ||
		output.String() != "{\"schema_version\":\"steward.executor-local-principal.v1\",\"id\":\"observer\",\"role\":\"observer\"}\n" {
		t.Fatalf("output=%s error=%v", output.String(), err)
	}
	if err := run([]string{"node", "whoami", "-node-url", server.URL, "-token-file", tokenPath, "-runtime-ref", "unexpected"}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("node whoami accepted a workload flag")
	}
}

func TestNodeMaintenanceDrainPlansThenAppliesUnderCordon(t *testing.T) {
	const runtimeRef = "executor-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	destroyed := false
	entered := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer secret" {
			t.Fatal("missing bearer token")
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/maintenance":
			refs := `[]`
			if !destroyed {
				refs = `["` + runtimeRef + `"]`
			}
			_, _ = w.Write([]byte(`{"schema_version":"steward.executor-maintenance.v1","enabled":` + fmt.Sprint(entered) + `,"active_runtime_refs":` + refs + `,"pending_operations":0}`))
		case r.Method == http.MethodPost && r.URL.Path == "/v1/maintenance/enter":
			var request struct {
				Reason string `json:"reason"`
			}
			if json.NewDecoder(r.Body).Decode(&request) != nil || request.Reason != "kernel update" {
				t.Fatalf("enter request=%+v", request)
			}
			entered = true
			_, _ = w.Write([]byte(`{"schema_version":"steward.executor-maintenance.v1","enabled":true,"reason":"kernel update","active_runtime_refs":["` + runtimeRef + `"],"pending_operations":0}`))
		case r.Method == http.MethodDelete && r.URL.Path == "/v1/workloads/"+runtimeRef:
			if !entered {
				t.Fatal("runtime destroyed before cordon")
			}
			destroyed = true
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()
	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	common := []string{"node", "maintenance", "drain", "-node-url", server.URL, "-token-file", tokenPath}
	var plan bytes.Buffer
	if err := run(common, &plan, &bytes.Buffer{}); err != nil || !strings.Contains(plan.String(), `"applied":false`) || destroyed || entered {
		t.Fatalf("plan=%s entered=%v destroyed=%v error=%v", plan.String(), entered, destroyed, err)
	}
	var applied bytes.Buffer
	if err := run(append(common, "-apply", "-reason", "kernel update"), &applied, &bytes.Buffer{}); err != nil ||
		!strings.Contains(applied.String(), `"applied":true`) || !strings.Contains(applied.String(), runtimeRef) || !destroyed || !entered {
		t.Fatalf("applied=%s entered=%v destroyed=%v error=%v", applied.String(), entered, destroyed, err)
	}
}

func TestNodeMaintenanceStatusEnterAndExit(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/maintenance":
			_, _ = w.Write([]byte(`{"schema_version":"steward.executor-maintenance.v1","enabled":false,"active_runtime_refs":[],"pending_operations":0}`))
		case "/v1/maintenance/enter":
			_, _ = w.Write([]byte(`{"schema_version":"steward.executor-maintenance.v1","enabled":true,"reason":"inspection","active_runtime_refs":[],"pending_operations":0}`))
		case "/v1/maintenance/exit":
			_, _ = w.Write([]byte(`{"schema_version":"steward.executor-maintenance.v1","enabled":false,"active_runtime_refs":[],"pending_operations":0}`))
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()
	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		action []string
		want   string
	}{
		{action: []string{"status"}, want: `"enabled":false`},
		{action: []string{"enter", "-reason", "inspection"}, want: `"enabled":true`},
		{action: []string{"exit"}, want: `"enabled":false`},
	} {
		arguments := append([]string{"node", "maintenance"}, test.action...)
		arguments = append(arguments, "-node-url", server.URL, "-token-file", tokenPath)
		var output bytes.Buffer
		if err := run(arguments, &output, &bytes.Buffer{}); err != nil || !strings.Contains(output.String(), test.want) {
			t.Fatalf("arguments=%v output=%s error=%v", arguments, output.String(), err)
		}
	}
	if requests != 3 {
		t.Fatalf("requests=%d", requests)
	}
	for _, arguments := range [][]string{
		{"node", "maintenance"},
		{"node", "maintenance", "status", "-node-url", server.URL, "-token-file", tokenPath, "-reason", "invalid"},
		{"node", "maintenance", "enter", "-node-url", server.URL, "-token-file", tokenPath},
		{"node", "maintenance", "drain", "-node-url", server.URL, "-token-file", tokenPath, "-apply"},
		{"node", "maintenance", "exit", "-node-url", server.URL, "-token-file", tokenPath, "-apply"},
		{"node", "maintenance", "unknown", "-node-url", server.URL, "-token-file", tokenPath},
	} {
		if err := run(arguments, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
			t.Fatalf("invalid maintenance command accepted: %v", arguments)
		}
	}
}

func TestNodeMaintenanceDrainFailureKeepsCordonAndStops(t *testing.T) {
	const runtimeRef = "executor-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	entered := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/maintenance":
			_, _ = w.Write([]byte(`{"schema_version":"steward.executor-maintenance.v1","enabled":false,"active_runtime_refs":["` + runtimeRef + `"],"pending_operations":0}`))
		case r.Method == http.MethodPost && r.URL.Path == "/v1/maintenance/enter":
			entered = true
			_, _ = w.Write([]byte(`{"schema_version":"steward.executor-maintenance.v1","enabled":true,"reason":"repair","active_runtime_refs":["` + runtimeRef + `"],"pending_operations":0}`))
		case r.Method == http.MethodDelete && r.URL.Path == "/v1/workloads/"+runtimeRef:
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"error":"reconciliation_required","message":"ambiguous destroy"}`))
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()
	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := run([]string{
		"node", "maintenance", "drain", "-node-url", server.URL,
		"-token-file", tokenPath, "-reason", "repair", "-apply",
	}, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "maintenance remains enabled") ||
		!strings.Contains(err.Error(), runtimeRef) || !entered {
		t.Fatalf("entered=%v error=%v", entered, err)
	}
}
