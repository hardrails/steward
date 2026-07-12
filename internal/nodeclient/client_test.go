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
			_, _ = w.Write([]byte(`{"runtime_ref":"` + runtimeRef + `","status":"created","capsule_digest":"sha256:a","policy_digest":"sha256:b","generation":1,"evidence_key_id":"key","route_policy_digest":"sha256:route"}`))
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
	if err != nil || state.RuntimeRef != runtimeRef || state.Generation != 1 || state.RoutePolicyDigest != "sha256:route" {
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
