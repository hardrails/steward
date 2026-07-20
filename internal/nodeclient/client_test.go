package nodeclient

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/admission"
)

func TestClientDrivesBoundedExecutorContract(t *testing.T) {
	const runtimeRef = "executor-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Header.Get("Authorization") != "Bearer secret" {
			t.Fatal("missing authorization")
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/admissions":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body["capsule_dsse_base64"] == "" {
				t.Fatal("invalid admission body")
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"runtime_ref":"` + runtimeRef + `","status":"created","capsule_digest":"sha256:a","policy_digest":"sha256:b","generation":1,"evidence_key_id":"key","grant_id":"grant","service_path":"/v1/services/grant","service_id":"hermes-api","task_authorities":[{"key_id":"tenant-task","public_key":"cHVibGlj"}],"connector_url":"http://steward-relay:8081","connector_ids":["tickets"],"effect_mode":"authorized","route_policy_digest":"sha256:route"}`))
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/logs"):
			_, _ = w.Write([]byte(`{"runtime_ref":"` + runtimeRef + `","status":"running","logs":"hello"}`))
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/egress"):
			_, _ = w.Write([]byte(`{"allowed":2,"denied":1,"bytes_from_agent":10,"bytes_to_agent":20,"last_destination":"example.com:443"}`))
		case r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		default:
			_, _ = w.Write([]byte(`{"runtime_ref":"` + runtimeRef + `","status":"running"}`))
		}
	}))
	defer server.Close()
	client, err := New(server.URL, "secret")
	if err != nil {
		t.Fatal(err)
	}
	state, err := client.Admit(context.Background(), []byte("capsule"), admission.InstanceIntent{TenantID: "tenant"})
	if err != nil || state.RuntimeRef != runtimeRef || state.Generation != 1 || state.RoutePolicyDigest != "sha256:route" ||
		state.ServiceID != "hermes-api" || len(state.TaskAuthorities) != 1 || state.TaskAuthorities[0].KeyID != "tenant-task" ||
		state.ConnectorURL != "http://steward-relay:8081" || len(state.ConnectorIDs) != 1 || state.ConnectorIDs[0] != "tickets" ||
		state.EffectMode != admission.EffectModeAuthorized {
		t.Fatalf("state=%#v err=%v", state, err)
	}
	for _, operation := range []func(context.Context, string) (State, error){client.Status, client.Logs, client.Start, client.Stop} {
		state, err = operation(context.Background(), runtimeRef)
		if err != nil || state.RuntimeRef != runtimeRef {
			t.Fatalf("state=%#v err=%v", state, err)
		}
	}
	stats, err := client.EgressStats(context.Background(), runtimeRef)
	if err != nil || stats.Allowed != 2 || stats.Denied != 1 || stats.BytesToAgent != 20 {
		t.Fatalf("stats=%#v err=%v", stats, err)
	}
	if err := client.Destroy(context.Background(), runtimeRef); err != nil {
		t.Fatal(err)
	}
	if requests != 7 {
		t.Fatalf("requests=%d", requests)
	}
}

func TestClientActivationAdmissionCarriesExactRuntimeIdentity(t *testing.T) {
	const runtimeRef = "executor-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const activationID = "activation-test"
	beginDigest := "sha256:" + strings.Repeat("b", 64)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Activation struct {
				SchemaVersion string `json:"schema_version"`
				ActivationID  string `json:"activation_id"`
				BeginDigest   string `json:"begin_digest"`
			} `json:"activation"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil ||
			body.Activation.SchemaVersion != activationAdmissionRequestSchema ||
			body.Activation.ActivationID != activationID ||
			body.Activation.BeginDigest != beginDigest {
			t.Fatalf("activation request=%#v err=%v", body, err)
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"runtime_ref":"` + runtimeRef +
			`","status":"created","activation_id":"` + activationID +
			`","activation_begin_digest":"` + beginDigest + `"}`))
	}))
	defer server.Close()
	client, err := New(server.URL, "secret")
	if err != nil {
		t.Fatal(err)
	}
	state, err := client.AdmitActivation(
		context.Background(), []byte("capsule"),
		admission.InstanceIntent{TenantID: "tenant"},
		activationID, beginDigest,
	)
	if err != nil || state.ActivationID != activationID ||
		state.ActivationBeginDigest != beginDigest {
		t.Fatalf("state=%#v err=%v", state, err)
	}
}

func TestClientDrivesMaintenanceContract(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Header.Get("Authorization") != "Bearer secret" {
			t.Fatal("missing authorization")
		}
		switch r.URL.Path {
		case "/v1/maintenance":
			if r.Method != http.MethodGet {
				t.Fatalf("maintenance method=%s", r.Method)
			}
			_, _ = w.Write([]byte(`{"schema_version":"steward.executor-maintenance.v1","enabled":false,"active_runtime_refs":[],"pending_operations":0}`))
		case "/v1/maintenance/enter":
			var body struct {
				Reason string `json:"reason"`
			}
			if r.Method != http.MethodPost || json.NewDecoder(r.Body).Decode(&body) != nil || body.Reason != "kernel update" {
				t.Fatalf("maintenance enter method=%s body=%+v", r.Method, body)
			}
			_, _ = w.Write([]byte(`{"schema_version":"steward.executor-maintenance.v1","enabled":true,"entered_at":"2026-07-17T00:00:00Z","reason":"kernel update","active_runtime_refs":["executor-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],"pending_operations":0}`))
		case "/v1/maintenance/exit":
			if r.Method != http.MethodPost || r.ContentLength != 0 {
				t.Fatalf("maintenance exit method=%s length=%d", r.Method, r.ContentLength)
			}
			_, _ = w.Write([]byte(`{"schema_version":"steward.executor-maintenance.v1","enabled":false,"active_runtime_refs":[],"pending_operations":0}`))
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()
	client, err := New(server.URL, "secret")
	if err != nil {
		t.Fatal(err)
	}
	if status, err := client.MaintenanceStatus(context.Background()); err != nil || status.Enabled {
		t.Fatalf("status=%+v error=%v", status, err)
	}
	if status, err := client.EnterMaintenance(context.Background(), "kernel update"); err != nil || !status.Enabled || status.Reason != "kernel update" || len(status.ActiveRuntimeRefs) != 1 {
		t.Fatalf("entered=%+v error=%v", status, err)
	}
	if status, err := client.ExitMaintenance(context.Background()); err != nil || status.Enabled {
		t.Fatalf("exited=%+v error=%v", status, err)
	}
	if requests != 3 {
		t.Fatalf("requests=%d", requests)
	}
}

func TestClientReadsLocalPrincipal(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/local-principal" ||
			r.Header.Get("Authorization") != "Bearer secret" {
			t.Fatalf("unexpected request %s %s auth=%q", r.Method, r.URL.Path, r.Header.Get("Authorization"))
		}
		_, _ = w.Write([]byte(`{"schema_version":"steward.executor-local-principal.v1","id":"operator","role":"operator"}`))
	}))
	defer server.Close()
	client, err := New(server.URL, "secret")
	if err != nil {
		t.Fatal(err)
	}
	principal, err := client.LocalPrincipal(context.Background())
	if err != nil || principal.ID != "operator" || principal.Role != "operator" ||
		principal.SchemaVersion != "steward.executor-local-principal.v1" {
		t.Fatalf("principal=%+v error=%v", principal, err)
	}
}

func TestClientRejectsUnsafeOriginsPathsAndErrors(t *testing.T) {
	for _, origin := range []string{"https://127.0.0.1:8090", "http://example.com:8090", "http://127.0.0.1", "http://127.0.0.1:8090/path"} {
		if _, err := New(origin, "secret"); err == nil {
			t.Fatalf("unsafe origin accepted: %s", origin)
		}
	}
	client, _ := New("http://127.0.0.1:1", "secret")
	if _, err := client.Status(context.Background(), "bad"); err == nil {
		t.Fatal("invalid runtime ref accepted")
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"error":"drift","message":"changed"}`))
	}))
	defer server.Close()
	client, _ = New(server.URL, "secret")
	_, err := client.Status(context.Background(), "executor-"+strings.Repeat("a", 64))
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Status != http.StatusConflict || apiErr.Code != "drift" {
		t.Fatalf("err=%v", err)
	}
}

func TestClientUsesCallerContextAsRequestCeiling(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		select {
		case <-request.Context().Done():
		case <-time.After(time.Second):
			http.Error(w, "request context was not canceled", http.StatusGatewayTimeout)
		}
	}))
	defer server.Close()
	client, err := New(server.URL, "secret")
	if err != nil {
		t.Fatal(err)
	}
	if client.http.Timeout != 0 {
		t.Fatalf("HTTP client timeout = %v, want caller context to be the only request ceiling", client.http.Timeout)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err = client.Status(ctx, "executor-"+strings.Repeat("a", 64))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Status() error = %v, want context deadline exceeded", err)
	}
}

func TestTokenAndBoundedFilePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if token, err := ReadToken(path); err != nil || token != "secret" {
		t.Fatalf("token=%q err=%v", token, err)
	}
	if _, err := ReadBounded(path, 16); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadToken(path); err == nil {
		t.Fatal("permissive token accepted")
	}
	if err := os.WriteFile(path, []byte("two words\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadToken(path); err == nil {
		t.Fatal("token with internal whitespace accepted")
	}
}

func TestBoundedReadersRejectSymlink(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "input")
	if err := os.WriteFile(path, []byte("stable"), 0o600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(directory, "symlink")
	if err := os.Symlink(path, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadBounded(symlink, 64); err == nil {
		t.Fatal("symlink accepted")
	}

}

func TestClientPurgeAndStrictResponseFailures(t *testing.T) {
	const ref = "executor-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	responses := []struct {
		status int
		body   string
	}{
		{http.StatusNoContent, ""},
		{http.StatusOK, `{"unexpected":true}`},
		{http.StatusOK, `{"runtime_ref":"` + ref + `","status":"running","unknown":true}`},
		{http.StatusOK, `{"runtime_ref":"` + ref + `"} {}`},
		{http.StatusConflict, `not-json`},
		{http.StatusOK, strings.Repeat("x", maxWireBytes+1)},
	}
	index := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/state/purge" && index == 0 {
			var purge StatePurge
			if err := json.NewDecoder(r.Body).Decode(&purge); err != nil || purge.LineageID != "lineage" {
				t.Fatalf("purge=%#v", purge)
			}
		}
		current := responses[index]
		index++
		w.WriteHeader(current.status)
		_, _ = w.Write([]byte(current.body))
	}))
	defer server.Close()
	client, _ := New(server.URL, "secret")
	if err := client.PurgeState(context.Background(), StatePurge{TenantID: "t", NodeID: "n", LineageID: "lineage", Generation: 1}); err != nil {
		t.Fatal(err)
	}
	if err := client.Destroy(context.Background(), ref); err == nil {
		t.Fatal("unexpected destroy body accepted")
	}
	if _, err := client.Status(context.Background(), ref); err == nil {
		t.Fatal("unknown response field accepted")
	}
	if _, err := client.Status(context.Background(), ref); err == nil {
		t.Fatal("multiple JSON values accepted")
	}
	if _, err := client.Status(context.Background(), ref); err == nil || !strings.Contains(err.Error(), "invalid_error") {
		t.Fatalf("malformed error=%v", err)
	}
	if _, err := client.Status(context.Background(), ref); err == nil || !strings.Contains(err.Error(), "exceeds 1 MiB") {
		t.Fatalf("oversized error=%v", err)
	}
}

func TestClientSnapshotsAndClonesThroughBoundedPublicPaths(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/state/snapshots":
			var request StateSnapshotRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil || request.SnapshotID != "snap" || request.InstanceID != "source" {
				t.Fatalf("snapshot request=%+v err=%v", request, err)
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"status":"stopped","snapshot_id":"snap","tenant_id":"tenant","source_lineage_id":"source-lineage","content_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","retained_bytes":10,"object_count":2,"created_at":"2026-07-20T00:00:00Z"}`))
		case "/v1/state/clones":
			var request StateCloneRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil || request.SnapshotID != "snap" || request.InstanceID != "fork" {
				t.Fatalf("clone request=%+v err=%v", request, err)
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"status":"stopped","tenant_id":"tenant","instance_id":"fork","lineage_id":"fork-lineage","snapshot_id":"snap"}`))
		case "/v1/state/snapshots/delete":
			var request StateSnapshotRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil || request.SnapshotID != "snap" || request.InstanceID != "source" {
				t.Fatalf("delete request=%+v err=%v", request, err)
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()
	client, _ := New(server.URL, "secret")
	snapshot, err := client.SnapshotState(context.Background(), StateSnapshotRequest{
		TenantID: "tenant", NodeID: "node", InstanceID: "source", LineageID: "source-lineage", Generation: 1, SnapshotID: "snap",
	})
	if err != nil || snapshot.ContentDigest == "" || snapshot.ObjectCount != 2 {
		t.Fatalf("snapshot=%+v err=%v", snapshot, err)
	}
	clone, err := client.CloneState(context.Background(), StateCloneRequest{
		TenantID: "tenant", NodeID: "node", InstanceID: "fork", LineageID: "fork-lineage", Generation: 1,
		SnapshotID: "snap", SourceLineageID: "source-lineage",
	})
	if err != nil || clone.InstanceID != "fork" || clone.LineageID != "fork-lineage" {
		t.Fatalf("clone=%+v err=%v", clone, err)
	}
	if err := client.DeleteStateSnapshot(context.Background(), StateSnapshotRequest{
		TenantID: "tenant", NodeID: "node", InstanceID: "source", LineageID: "source-lineage", Generation: 1, SnapshotID: "snap",
	}); err != nil {
		t.Fatal(err)
	}
}

func TestClientRejectsCapsulesTokensAndInputFiles(t *testing.T) {
	client, _ := New("http://127.0.0.1:1", "secret")
	if _, err := client.Admit(context.Background(), nil, admission.InstanceIntent{}); err == nil {
		t.Fatal("empty capsule accepted")
	}
	if _, err := client.Admit(context.Background(), make([]byte, maxWireBytes/2+1), admission.InstanceIntent{}); err == nil {
		t.Fatal("oversized capsule accepted")
	}
	for _, token := range []string{"", strings.Repeat("x", 4097)} {
		if _, err := New("http://127.0.0.1:8090", token); err == nil {
			t.Fatalf("invalid token length %d accepted", len(token))
		}
	}
	directory := t.TempDir()
	if _, err := ReadBounded(directory, 10); err == nil {
		t.Fatal("directory accepted as input")
	}
	empty := filepath.Join(directory, "empty")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadBounded(empty, 10); err == nil {
		t.Fatal("empty file accepted")
	}
	if _, err := ReadToken(empty); err == nil {
		t.Fatal("empty token accepted")
	}
	if _, err := NewFromTokenFile("http://127.0.0.1:8090", filepath.Join(directory, "missing")); err == nil {
		t.Fatal("missing token file accepted")
	}
}
