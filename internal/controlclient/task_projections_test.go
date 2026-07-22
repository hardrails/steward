package controlclient

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/hardrails/steward/internal/controlstore"
)

func TestListTaskProjectionsValidatesTheCompletePage(t *testing.T) {
	projection := controlClientTaskProjection("tenant-a", "task-a", "researcher-a", 1)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || request.URL.Path != "/v1/tenants/tenant-a/tasks" ||
			request.URL.Query().Get("after") != "task-before" || request.URL.Query().Get("limit") != "1" ||
			request.Header.Get("Authorization") != "Bearer operator" {
			t.Fatalf("task request=%s %s auth=%q", request.Method, request.URL, request.Header.Get("Authorization"))
		}
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(TaskProjectionList{
			Tasks: []controlstore.TaskProjection{projection}, NextAfter: projection.ProjectionID,
		})
	}))
	defer server.Close()
	client, err := New(server.URL, "operator", nil)
	if err != nil {
		t.Fatal(err)
	}
	page, err := client.ListTaskProjections(context.Background(), "tenant-a", "task-before", 1)
	if err != nil || len(page.Tasks) != 1 || page.NextAfter != projection.ProjectionID {
		t.Fatalf("task page=(%+v, %v)", page, err)
	}
}

func TestListTaskProjectionsRejectsInvalidRequestsAndResponses(t *testing.T) {
	newer := controlClientTaskProjection("tenant-a", "task-new", "researcher-a", 1)
	older := controlClientTaskProjection("tenant-a", "task-old", "researcher-a", 1)
	older.FirstObservedAt = "2026-07-21T01:00:00Z"
	older.LastObservedAt = "2026-07-21T01:00:01Z"
	responses := []struct {
		name  string
		page  TaskProjectionList
		limit int
	}{
		{name: "omitted collection", page: TaskProjectionList{}, limit: 1},
		{name: "over limit", page: TaskProjectionList{Tasks: []controlstore.TaskProjection{newer, older}}, limit: 1},
		{name: "wrong tenant", page: TaskProjectionList{Tasks: []controlstore.TaskProjection{controlClientTaskProjection("tenant-b", "task-a", "researcher-a", 1)}}, limit: 1},
		{name: "invalid projection", page: TaskProjectionList{Tasks: []controlstore.TaskProjection{{TenantID: "tenant-a"}}}, limit: 1},
		{name: "noncanonical order", page: TaskProjectionList{Tasks: []controlstore.TaskProjection{older, newer}}, limit: 2},
		{name: "empty cursor page", page: TaskProjectionList{Tasks: []controlstore.TaskProjection{}, NextAfter: newer.ProjectionID}, limit: 1},
		{name: "wrong cursor", page: TaskProjectionList{Tasks: []controlstore.TaskProjection{newer}, NextAfter: "task-" + strings.Repeat("f", 64)}, limit: 1},
	}
	for _, test := range responses {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(writer).Encode(test.page)
			}))
			defer server.Close()
			client, err := New(server.URL, "operator", nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.ListTaskProjections(context.Background(), "tenant-a", "", test.limit); err == nil {
				t.Fatalf("invalid task page accepted: %+v", test.page)
			}
		})
	}
	client, err := New("http://127.0.0.1:1", "operator", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range []struct {
		tenant string
		limit  int
	}{{tenant: "-tenant", limit: 1}, {tenant: "tenant-a", limit: 0}, {tenant: "tenant-a", limit: 101}} {
		if _, err := client.ListTaskProjections(context.Background(), input.tenant, "", input.limit); err == nil {
			t.Fatalf("invalid request accepted: %+v", input)
		}
	}
	if _, err := client.ListTaskProjections(context.Background(), "tenant-a", "", 1); err == nil {
		t.Fatal("task transport failure accepted")
	}
	if _, err := client.ListTaskProjections(context.Background(), "tenant-a", strings.Repeat("a", 4097), 1); err == nil {
		t.Fatal("oversized task cursor accepted")
	}
}

func TestListTaskProjectionsAcceptsChronologicalFractionalOrder(t *testing.T) {
	newer := controlClientTaskProjection("tenant-a", "task-new", "researcher-a", 1)
	older := controlClientTaskProjection("tenant-a", "task-old", "researcher-a", 1)
	older.FirstObservedAt = "2026-07-21T01:00:00Z"
	older.LastObservedAt = "2026-07-21T01:00:00Z"
	newer.FirstObservedAt = "2026-07-21T01:00:00.000000001Z"
	newer.LastObservedAt = "2026-07-21T01:00:00.000000001Z"
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(TaskProjectionList{Tasks: []controlstore.TaskProjection{newer, older}})
	}))
	defer server.Close()
	client, err := New(server.URL, "operator", nil)
	if err != nil {
		t.Fatal(err)
	}
	page, err := client.ListTaskProjections(context.Background(), "tenant-a", "", 2)
	if err != nil || len(page.Tasks) != 2 {
		t.Fatalf("fractional task page=%+v err=%v", page, err)
	}
}

func controlClientTaskProjection(tenantID, taskID, instanceID string, generation uint64) controlstore.TaskProjection {
	digest := sha256.Sum256([]byte(
		"steward-task-projection-v1\x00" + tenantID + "\x00" + taskID + "\x00" + instanceID + "\x00" +
			strconv.FormatUint(generation, 10),
	))
	return controlstore.TaskProjection{
		ProjectionID: "task-" + hex.EncodeToString(digest[:]), TenantID: tenantID, TaskID: taskID,
		InstanceID: instanceID, Generation: generation, NodeID: "node-1",
		RuntimeRef: "executor-" + strings.Repeat("a", 64), RunID: "run-a",
		State: controlstore.TaskStateRunning, LatestCode: "task_progress", LatestSeverity: "info",
		HighestSeverity: "warning", LatestSummary: "Research is running.", EventCount: 2, FindingCount: 1,
		FirstObservedAt: "2026-07-21T01:00:02Z", LastObservedAt: "2026-07-21T01:00:03Z",
		LatestEventID: "event-" + strings.Repeat("b", 64), Conditions: []string{},
	}
}
