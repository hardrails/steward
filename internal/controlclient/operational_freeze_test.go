package controlclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hardrails/steward/internal/controlstore"
)

func TestClientReadsAndChangesOperationalFreeze(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		if request.Header.Get("Authorization") != "Bearer operator" {
			t.Fatalf("authorization = %q", request.Header.Get("Authorization"))
		}
		switch request.Method + " " + request.URL.Path {
		case "GET /v1/operations/freeze":
			_, _ = writer.Write([]byte(`{"site":{"scope":"site","frozen":false,"revision":2,"changed_at":"2026-07-20T12:00:00Z"}}`))
		case "PUT /v1/tenants/tenant-a/freeze":
			var input struct {
				Action           string `json:"action"`
				ExpectedRevision uint64 `json:"expected_revision"`
				Reason           string `json:"reason"`
			}
			if err := json.NewDecoder(request.Body).Decode(&input); err != nil || input.Action != "freeze" ||
				input.ExpectedRevision != 3 || input.Reason != "incident" {
				t.Fatalf("freeze input = (%+v, %v)", input, err)
			}
			_, _ = writer.Write([]byte(`{"status":{"tenant":{"scope":"tenant","tenant_id":"tenant-a","frozen":true,"revision":4,"reason":"incident","changed_at":"2026-07-20T12:01:00Z"},"effective":{"scope":"tenant","tenant_id":"tenant-a","frozen":true,"revision":4,"reason":"incident","changed_at":"2026-07-20T12:01:00Z"}},"changed":true}`))
		default:
			t.Fatalf("unexpected request %s %s", request.Method, request.URL.Path)
		}
	}))
	defer server.Close()
	client, err := New(server.URL, "operator", nil)
	if err != nil {
		t.Fatal(err)
	}
	status, err := client.GetOperationalFreeze(context.Background(), "")
	if err != nil || status.Site == nil || status.Site.Frozen || status.Site.Revision != 2 {
		t.Fatalf("site freeze = (%+v, %v)", status, err)
	}
	change, err := client.ChangeOperationalFreeze(
		context.Background(), "tenant-a", controlstore.OperationalFreezeActionFreeze, 3, "incident",
	)
	if err != nil || !change.Changed || change.Status.Effective == nil ||
		change.Status.Effective.Scope != controlstore.OperationalFreezeTenant {
		t.Fatalf("tenant freeze = (%+v, %v)", change, err)
	}
}

func TestClientRejectsInvalidOperationalFreezeResponses(t *testing.T) {
	for _, body := range []string{
		`{"tenant":{"scope":"tenant","tenant_id":"other","frozen":true,"revision":1,"reason":"incident","changed_at":"2026-07-20T12:00:00Z"}}`,
		`{"site":{"scope":"site","frozen":true,"revision":1,"reason":"incident","changed_at":"2026-07-20T12:00:00Z"}}`,
		`{"tenant":{"scope":"tenant","tenant_id":"tenant-a","frozen":true,"revision":1,"reason":"incident","changed_at":"2026-07-20T12:00:00Z"}}`,
	} {
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			writer.Header().Set("Content-Type", "application/json")
			_, _ = writer.Write([]byte(body))
		}))
		client, err := New(server.URL, "operator", nil)
		if err != nil {
			server.Close()
			t.Fatal(err)
		}
		if _, err := client.GetOperationalFreeze(context.Background(), "tenant-a"); err == nil {
			server.Close()
			t.Fatalf("invalid freeze response accepted: %s", body)
		}
		server.Close()
	}
	if client, err := New("http://127.0.0.1:8443", "operator", nil); err != nil {
		t.Fatal(err)
	} else if _, err := client.GetOperationalFreeze(context.Background(), "bad tenant"); err == nil {
		t.Fatal("invalid freeze tenant route was accepted")
	}
}
