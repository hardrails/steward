package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/hardrails/steward/internal/controlclient"
	"github.com/hardrails/steward/internal/controlstore"
)

func TestControlSnapshotCommandsDiscoverRevisionAndChangeQuarantine(t *testing.T) {
	revision := uint64(0)
	blocked := false
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		if request.Header.Get("Authorization") != "Bearer operator-secret" ||
			request.URL.Path != "/v1/tenants/tenant-a/nodes/node-a/snapshots/snapshot-a/quarantine" {
			t.Fatalf("request = %s %s authorization %q", request.Method, request.URL.Path, request.Header.Get("Authorization"))
		}
		status := controlstore.SnapshotQuarantineStatus{
			TenantID: "tenant-a", NodeID: "node-a", SnapshotID: "snapshot-a", Blocked: blocked,
		}
		if revision > 0 {
			status.Record = &controlstore.SnapshotQuarantine{
				TenantID: "tenant-a", NodeID: "node-a", SnapshotID: "snapshot-a",
				Quarantined: blocked, Revision: revision, ChangedAt: "2026-07-20T12:00:00Z",
			}
			if blocked {
				status.Record.Reason = "incident"
			}
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
		if err := json.NewDecoder(request.Body).Decode(&input); err != nil || input.ExpectedRevision != revision {
			t.Fatalf("change input = (%+v, %v), revision %d", input, err, revision)
		}
		switch input.Action {
		case controlstore.SnapshotQuarantineActionSet:
			if input.Reason != "incident" || blocked {
				t.Fatalf("unexpected quarantine input = %+v blocked=%v", input, blocked)
			}
			blocked = true
		case controlstore.SnapshotQuarantineActionClear:
			if input.Reason != "" || !blocked {
				t.Fatalf("unexpected unquarantine input = %+v blocked=%v", input, blocked)
			}
			blocked = false
		default:
			t.Fatalf("unexpected quarantine action %q", input.Action)
		}
		revision++
		status.Blocked = blocked
		status.Record = &controlstore.SnapshotQuarantine{
			TenantID: "tenant-a", NodeID: "node-a", SnapshotID: "snapshot-a",
			Quarantined: blocked, Revision: revision, ChangedAt: "2026-07-20T12:00:00Z",
		}
		if blocked {
			status.Record.Reason = "incident"
		}
		_ = json.NewEncoder(writer).Encode(controlclient.SnapshotQuarantineChange{Status: status, Changed: true})
	}))
	defer server.Close()
	tokenPath := filepath.Join(t.TempDir(), "operator.token")
	if err := os.WriteFile(tokenPath, []byte("operator-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	common := []string{
		"-control-url", server.URL, "-token-file", tokenPath,
		"-tenant-id", "tenant-a", "-node-id", "node-a", "-snapshot-id", "snapshot-a",
	}
	var output bytes.Buffer
	if err := run(append([]string{"control", "snapshot", "quarantine"}, append(common, "-reason", "incident")...), &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	var changed controlclient.SnapshotQuarantineChange
	if err := json.Unmarshal(output.Bytes(), &changed); err != nil || !changed.Changed ||
		!changed.Status.Blocked || changed.Status.Record == nil || changed.Status.Record.Revision != 1 {
		t.Fatalf("quarantine output = (%+v, %v)", changed, err)
	}
	output.Reset()
	if err := run(append([]string{"control", "snapshot", "status"}, common...), &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	if err := run(append([]string{"control", "snapshot", "unquarantine"}, common...), &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	changed = controlclient.SnapshotQuarantineChange{}
	if err := json.Unmarshal(output.Bytes(), &changed); err != nil || !changed.Changed ||
		changed.Status.Blocked || changed.Status.Record == nil || changed.Status.Record.Revision != 2 {
		t.Fatalf("unquarantine output = (%+v, %v)", changed, err)
	}
}

func TestControlSnapshotCommandsRequireBoundedIdentityAndReason(t *testing.T) {
	if err := controlSnapshotQuarantineStatus(nil, &bytes.Buffer{}); err == nil {
		t.Fatal("snapshot status without identities succeeded")
	}
	if err := controlSnapshotQuarantineChange([]string{
		"-tenant-id", "tenant-a", "-node-id", "node-a", "-snapshot-id", "snapshot-a",
	}, &bytes.Buffer{}, controlstore.SnapshotQuarantineActionSet); err == nil {
		t.Fatal("snapshot quarantine without a reason succeeded")
	}
	if err := controlSnapshotQuarantineChange([]string{
		"-tenant-id", "tenant-a", "-node-id", "node-a", "-snapshot-id", "snapshot-a", "-reason", "unexpected",
	}, &bytes.Buffer{}, controlstore.SnapshotQuarantineActionClear); err == nil {
		t.Fatal("snapshot unquarantine with a reason succeeded")
	}
	if got := stewardctlCompletionCandidates([]string{"stewardctl", "control", "snapshot", ""}); !slicesEqual(got, []string{"quarantine", "status", "unquarantine"}) {
		t.Fatalf("snapshot completion candidates = %#v", got)
	}
}
