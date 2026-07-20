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

func TestControlFreezeCommandsDiscoverRevisionAndChangeTenantGate(t *testing.T) {
	revision := uint64(2)
	frozen := false
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		if request.Header.Get("Authorization") != "Bearer operator-secret" ||
			request.URL.Path != "/v1/tenants/tenant-a/freeze" {
			t.Fatalf("request = %s %s authorization %q", request.Method, request.URL.Path, request.Header.Get("Authorization"))
		}
		record := controlstore.OperationalFreeze{
			Scope: controlstore.OperationalFreezeTenant, TenantID: "tenant-a", Frozen: frozen,
			Revision: revision, ChangedAt: "2026-07-20T12:00:00Z",
		}
		if frozen {
			record.Reason = "incident"
		}
		if request.Method == http.MethodGet {
			status := controlstore.OperationalFreezeStatus{Tenant: &record}
			if frozen {
				status.Effective = &record
			}
			_ = json.NewEncoder(writer).Encode(status)
			return
		}
		var input struct {
			Action           controlstore.OperationalFreezeAction `json:"action"`
			ExpectedRevision uint64                               `json:"expected_revision"`
			Reason           string                               `json:"reason"`
		}
		if err := json.NewDecoder(request.Body).Decode(&input); err != nil || input.ExpectedRevision != revision {
			t.Fatalf("change input = (%+v, %v), revision %d", input, err, revision)
		}
		switch input.Action {
		case controlstore.OperationalFreezeActionFreeze:
			if input.Reason != "incident" || frozen {
				t.Fatalf("unexpected freeze input = %+v frozen=%v", input, frozen)
			}
			frozen = true
		case controlstore.OperationalFreezeActionUnfreeze:
			if input.Reason != "" || !frozen {
				t.Fatalf("unexpected unfreeze input = %+v frozen=%v", input, frozen)
			}
			frozen = false
		default:
			t.Fatalf("unexpected freeze action %q", input.Action)
		}
		revision++
		record.Frozen = frozen
		record.Revision = revision
		record.Reason = ""
		status := controlstore.OperationalFreezeStatus{Tenant: &record}
		if frozen {
			record.Reason = "incident"
			status.Tenant = &record
			status.Effective = &record
		}
		_ = json.NewEncoder(writer).Encode(controlclient.OperationalFreezeChange{Status: status, Changed: true})
	}))
	defer server.Close()
	tokenPath := filepath.Join(t.TempDir(), "operator.token")
	if err := os.WriteFile(tokenPath, []byte("operator-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	common := []string{"-control-url", server.URL, "-token-file", tokenPath, "-tenant-id", "tenant-a"}
	var output bytes.Buffer
	if err := run(append([]string{"control", "freeze", "set"}, append(common, "-reason", "incident")...), &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	var changed controlclient.OperationalFreezeChange
	if err := json.Unmarshal(output.Bytes(), &changed); err != nil || !changed.Changed ||
		changed.Status.Effective == nil || changed.Status.Effective.Revision != 3 {
		t.Fatalf("set output = (%+v, %v)", changed, err)
	}
	output.Reset()
	if err := run(append([]string{"control", "freeze", "status"}, common...), &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	if err := run(append([]string{"control", "freeze", "clear"}, common...), &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	changed = controlclient.OperationalFreezeChange{}
	if err := json.Unmarshal(output.Bytes(), &changed); err != nil || !changed.Changed ||
		changed.Status.Tenant == nil || changed.Status.Tenant.Frozen || changed.Status.Tenant.Revision != 4 {
		t.Fatalf("clear output = (%+v, %v)", changed, err)
	}
}

func TestControlFreezeCommandsRejectAmbiguousScopeAndMissingReason(t *testing.T) {
	if err := controlFreezeChange(nil, &bytes.Buffer{}, controlstore.OperationalFreezeActionFreeze); err == nil {
		t.Fatal("freeze without a reason succeeded")
	}
	if err := controlFreezeStatus([]string{"-site", "-tenant-id", "tenant-a"}, &bytes.Buffer{}); err == nil {
		t.Fatal("ambiguous site and tenant scope succeeded")
	}
}
