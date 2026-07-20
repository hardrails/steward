package controlclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hardrails/steward/internal/controlstore"
)

func TestSnapshotQuarantineClientBindsRouteAndRevision(t *testing.T) {
	revision := uint64(0)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v1/tenants/tenant-a/nodes/node-a/snapshots/snapshot-a/quarantine" ||
			request.Header.Get("Authorization") != "Bearer operator" {
			t.Fatalf("snapshot quarantine request = %s auth=%q", request.URL, request.Header.Get("Authorization"))
		}
		writer.Header().Set("Content-Type", "application/json")
		status := controlstore.SnapshotQuarantineStatus{
			TenantID: "tenant-a", NodeID: "node-a", SnapshotID: "snapshot-a",
		}
		if request.Method == http.MethodGet {
			_ = json.NewEncoder(writer).Encode(status)
			return
		}
		var input struct {
			Action           controlstore.SnapshotQuarantineAction `json:"action"`
			ExpectedRevision uint64                                `json:"expected_revision"`
			Reason           string                                `json:"reason"`
		}
		if err := json.NewDecoder(request.Body).Decode(&input); err != nil ||
			input.Action != controlstore.SnapshotQuarantineActionSet || input.ExpectedRevision != revision ||
			input.Reason != "incident" {
			t.Fatalf("snapshot quarantine input = (%+v, %v)", input, err)
		}
		revision++
		status.Blocked = true
		status.Record = &controlstore.SnapshotQuarantine{
			TenantID: "tenant-a", NodeID: "node-a", SnapshotID: "snapshot-a", Quarantined: true,
			Revision: revision, Reason: "incident", ChangedAt: "2026-07-20T12:00:00Z",
		}
		_ = json.NewEncoder(writer).Encode(SnapshotQuarantineChange{Status: status, Changed: true})
	}))
	defer server.Close()
	client, err := New(server.URL, "operator", nil)
	if err != nil {
		t.Fatal(err)
	}
	if status, err := client.GetSnapshotQuarantine(context.Background(), "tenant-a", "node-a", "snapshot-a"); err != nil || status.Record != nil {
		t.Fatalf("initial snapshot quarantine = (%+v, %v)", status, err)
	}
	change, err := client.ChangeSnapshotQuarantine(
		context.Background(), "tenant-a", "node-a", "snapshot-a",
		controlstore.SnapshotQuarantineActionSet, 0, "incident",
	)
	if err != nil || !change.Changed || !change.Status.Blocked || change.Status.Record.Revision != 1 {
		t.Fatalf("snapshot quarantine change = (%+v, %v)", change, err)
	}
}
