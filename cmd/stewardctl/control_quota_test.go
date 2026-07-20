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
	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/controlstore"
)

func TestControlQuotaCommandsDiscoverRevisionAndChangeLimit(t *testing.T) {
	revision := uint64(2)
	enabled := false
	resources := controlprotocol.ExecutorSchedulingResourcesV1{}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		if request.Header.Get("Authorization") != "Bearer operator-secret" ||
			request.URL.Path != "/v1/tenants/tenant-a/quota" {
			t.Fatalf("request = %s %s authorization %q", request.Method, request.URL.Path, request.Header.Get("Authorization"))
		}
		quota := &controlstore.TenantResourceQuota{
			Enabled: enabled, Revision: revision, Resources: resources, ChangedAt: "2026-07-20T12:00:00Z",
		}
		status := controlstore.TenantResourceQuotaStatus{TenantID: "tenant-a", Quota: quota}
		if request.Method == http.MethodGet {
			_ = json.NewEncoder(writer).Encode(status)
			return
		}
		var input struct {
			Action           controlstore.TenantQuotaAction                `json:"action"`
			ExpectedRevision uint64                                        `json:"expected_revision"`
			Resources        controlprotocol.ExecutorSchedulingResourcesV1 `json:"resources"`
		}
		if err := json.NewDecoder(request.Body).Decode(&input); err != nil || input.ExpectedRevision != revision {
			t.Fatalf("change input = (%+v, %v), revision %d", input, err, revision)
		}
		switch input.Action {
		case controlstore.TenantQuotaActionSet:
			want := controlprotocol.ExecutorSchedulingResourcesV1{
				MemoryBytes: 512 << 20, CPUMillis: 2_000, PIDs: 128, Workloads: 4,
			}
			if input.Resources != want || enabled {
				t.Fatalf("unexpected set input = %+v enabled=%v", input, enabled)
			}
			enabled, resources = true, want
		case controlstore.TenantQuotaActionClear:
			if input.Resources != (controlprotocol.ExecutorSchedulingResourcesV1{}) || !enabled {
				t.Fatalf("unexpected clear input = %+v enabled=%v", input, enabled)
			}
			enabled, resources = false, controlprotocol.ExecutorSchedulingResourcesV1{}
		default:
			t.Fatalf("unexpected quota action %q", input.Action)
		}
		revision++
		quota.Enabled, quota.Revision, quota.Resources = enabled, revision, resources
		status.Quota = quota
		_ = json.NewEncoder(writer).Encode(controlclient.TenantResourceQuotaChange{Status: status, Changed: true})
	}))
	defer server.Close()
	tokenPath := filepath.Join(t.TempDir(), "operator.token")
	if err := os.WriteFile(tokenPath, []byte("operator-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	common := []string{"-control-url", server.URL, "-token-file", tokenPath, "-tenant-id", "tenant-a"}
	var output bytes.Buffer
	if err := run(append([]string{"control", "quota", "set"}, append(common,
		"-memory-mib", "512", "-cpu-millis", "2000", "-pids", "128", "-workloads", "4")...), &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	var changed controlclient.TenantResourceQuotaChange
	if err := json.Unmarshal(output.Bytes(), &changed); err != nil || !changed.Changed ||
		changed.Status.Quota == nil || !changed.Status.Quota.Enabled || changed.Status.Quota.Revision != 3 {
		t.Fatalf("set output = (%+v, %v)", changed, err)
	}
	output.Reset()
	if err := run(append([]string{"control", "quota", "status"}, common...), &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	if err := run(append([]string{"control", "quota", "clear"}, common...), &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	changed = controlclient.TenantResourceQuotaChange{}
	if err := json.Unmarshal(output.Bytes(), &changed); err != nil || !changed.Changed ||
		changed.Status.Quota == nil || changed.Status.Quota.Enabled || changed.Status.Quota.Revision != 4 {
		t.Fatalf("clear output = (%+v, %v)", changed, err)
	}
}

func TestControlQuotaCommandsRejectIncompleteOrAmbiguousLimits(t *testing.T) {
	for _, arguments := range [][]string{
		{"-tenant-id", "tenant-a", "-memory-mib", "512", "-cpu-millis", "2000", "-pids", "128"},
		{"-tenant-id", "tenant-a", "-memory-mib", "8796093022208", "-cpu-millis", "2000", "-pids", "128", "-workloads", "4"},
	} {
		if err := controlTenantQuotaChange(arguments, &bytes.Buffer{}, controlstore.TenantQuotaActionSet); err == nil {
			t.Fatalf("invalid quota set succeeded: %v", arguments)
		}
	}
	if err := controlTenantQuotaChange([]string{"-tenant-id", "tenant-a", "-workloads", "1"}, &bytes.Buffer{}, controlstore.TenantQuotaActionClear); err == nil {
		t.Fatal("quota clear with resources succeeded")
	}
	if err := controlTenantQuotaStatus(nil, &bytes.Buffer{}); err == nil {
		t.Fatal("quota status without tenant succeeded")
	}
}
