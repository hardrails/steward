package controlclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/controlstore"
)

func TestClientReadsAndChangesTenantResourceQuota(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		if request.Header.Get("Authorization") != "Bearer operator" || request.URL.Path != "/v1/tenants/tenant-a/quota" {
			t.Fatalf("request = %s %s authorization %q", request.Method, request.URL.Path, request.Header.Get("Authorization"))
		}
		switch request.Method {
		case http.MethodGet:
			_, _ = writer.Write([]byte(`{"tenant_id":"tenant-a","quota":{"enabled":false,"revision":2,"resources":{"memory_bytes":0,"cpu_millis":0,"pids":0,"workloads":0},"changed_at":"2026-07-20T12:00:00Z"},"usage":{"memory_bytes":0,"cpu_millis":0,"pids":0,"workloads":0},"over_quota":false}`))
		case http.MethodPut:
			var input struct {
				Action           controlstore.TenantQuotaAction                `json:"action"`
				ExpectedRevision uint64                                        `json:"expected_revision"`
				Resources        controlprotocol.ExecutorSchedulingResourcesV1 `json:"resources"`
			}
			if err := json.NewDecoder(request.Body).Decode(&input); err != nil ||
				input.Action != controlstore.TenantQuotaActionSet || input.ExpectedRevision != 2 ||
				input.Resources != (controlprotocol.ExecutorSchedulingResourcesV1{
					MemoryBytes: 1 << 30, CPUMillis: 2_000, PIDs: 256, Workloads: 4,
				}) {
				t.Fatalf("quota input = (%+v, %v)", input, err)
			}
			_, _ = writer.Write([]byte(`{"status":{"tenant_id":"tenant-a","quota":{"enabled":true,"revision":3,"resources":{"memory_bytes":1073741824,"cpu_millis":2000,"pids":256,"workloads":4},"changed_at":"2026-07-20T12:01:00Z"},"usage":{"memory_bytes":0,"cpu_millis":0,"pids":0,"workloads":0},"over_quota":false},"changed":true}`))
		default:
			t.Fatalf("unexpected method %s", request.Method)
		}
	}))
	defer server.Close()
	client, err := New(server.URL, "operator", nil)
	if err != nil {
		t.Fatal(err)
	}
	status, err := client.GetTenantResourceQuota(context.Background(), "tenant-a")
	if err != nil || status.Quota == nil || status.Quota.Enabled || status.Quota.Revision != 2 {
		t.Fatalf("quota status = (%+v, %v)", status, err)
	}
	change, err := client.ChangeTenantResourceQuota(
		context.Background(), "tenant-a", controlstore.TenantQuotaActionSet, 2,
		controlprotocol.ExecutorSchedulingResourcesV1{MemoryBytes: 1 << 30, CPUMillis: 2_000, PIDs: 256, Workloads: 4},
	)
	if err != nil || !change.Changed || change.Status.Quota == nil || !change.Status.Quota.Enabled ||
		change.Status.Quota.Revision != 3 {
		t.Fatalf("quota change = (%+v, %v)", change, err)
	}
}

func TestClientRejectsInvalidTenantResourceQuotaResponses(t *testing.T) {
	for _, body := range []string{
		`{"tenant_id":"other","usage":{"memory_bytes":0,"cpu_millis":0,"pids":0,"workloads":0},"over_quota":false}`,
		`{"tenant_id":"tenant-a","usage":{"memory_bytes":-1,"cpu_millis":0,"pids":0,"workloads":0},"over_quota":false}`,
		`{"tenant_id":"tenant-a","quota":{"enabled":true,"revision":1,"resources":{"memory_bytes":1,"cpu_millis":1,"pids":1,"workloads":1},"changed_at":"invalid"},"usage":{"memory_bytes":0,"cpu_millis":0,"pids":0,"workloads":0},"over_quota":false}`,
		`{"tenant_id":"tenant-a","quota":{"enabled":false,"revision":1,"resources":{"memory_bytes":1,"cpu_millis":0,"pids":0,"workloads":0},"changed_at":"2026-07-20T12:00:00Z"},"usage":{"memory_bytes":0,"cpu_millis":0,"pids":0,"workloads":0},"over_quota":false}`,
		`{"tenant_id":"tenant-a","quota":{"enabled":true,"revision":1,"resources":{"memory_bytes":1,"cpu_millis":1,"pids":1,"workloads":1},"changed_at":"2026-07-20T12:00:00Z"},"usage":{"memory_bytes":2,"cpu_millis":0,"pids":0,"workloads":0},"over_quota":false}`,
		`{"tenant_id":"tenant-a","quota":{"enabled":true,"revision":1,"resources":{"memory_bytes":1,"cpu_millis":9223372036855,"pids":1,"workloads":1},"changed_at":"2026-07-20T12:00:00Z"},"usage":{"memory_bytes":0,"cpu_millis":0,"pids":0,"workloads":0},"over_quota":false}`,
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
		if _, err := client.GetTenantResourceQuota(context.Background(), "tenant-a"); err == nil {
			server.Close()
			t.Fatalf("invalid quota response accepted: %s", body)
		}
		server.Close()
	}
	client, err := New("http://127.0.0.1:8443", "operator", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.GetTenantResourceQuota(context.Background(), "bad tenant"); err == nil {
		t.Fatal("invalid quota tenant route was accepted")
	}
}
