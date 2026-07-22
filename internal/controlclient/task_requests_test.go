package controlclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hardrails/steward/internal/controlstore"
)

func TestAsyncTaskClientRejectsHostileControlResponses(t *testing.T) {
	response := any(TaskRequestList{Tasks: nil})
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(response)
	}))
	defer server.Close()
	client, err := New(server.URL, "operator", nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := client.ListTaskRequests(ctx, "tenant-a", "", 1); err == nil {
		t.Fatal("nil task page was accepted")
	}

	newer := clientTaskFixture("task-b", "2026-07-22T08:00:01Z")
	older := clientTaskFixture("task-a", "2026-07-22T08:00:00Z")
	response = TaskRequestList{Tasks: []controlstore.TaskRequest{older, newer}}
	if _, err := client.ListTaskRequests(ctx, "tenant-a", "", 2); err == nil {
		t.Fatal("noncanonical task order was accepted")
	}
	response = TaskRequestList{Tasks: []controlstore.TaskRequest{newer}, NextAfter: "different"}
	if _, err := client.ListTaskRequests(ctx, "tenant-a", "", 1); err == nil {
		t.Fatal("inconsistent task cursor was accepted")
	}
	wrongTenant := newer
	wrongTenant.TenantID = "tenant-b"
	response = TaskRequestList{Tasks: []controlstore.TaskRequest{wrongTenant}}
	if _, err := client.ListTaskRequests(ctx, "tenant-a", "", 1); err == nil {
		t.Fatal("cross-tenant task page was accepted")
	}
	response = TaskRequestList{Tasks: []controlstore.TaskRequest{newer, older}, NextAfter: "task-a"}
	page, err := client.ListTaskRequests(ctx, "tenant-a", "", 2)
	if err != nil || len(page.Tasks) != 2 || page.NextAfter != "task-a" {
		t.Fatalf("canonical task page=(%+v, %v)", page, err)
	}
	response = TaskRequestList{Tasks: []controlstore.TaskRequest{}, NextAfter: "task-a"}
	if _, err := client.ListTaskRequests(ctx, "tenant-a", "", 1); err == nil {
		t.Fatal("cursor on an empty task page was accepted")
	}

	response = wrongTenant
	if _, err := client.GetTaskRequest(ctx, "tenant-a", "task-b"); err == nil {
		t.Fatal("cross-tenant task response was accepted")
	}
	response = newer
	if _, err := client.CancelTaskRequest(ctx, "tenant-a", "task-b"); err == nil {
		t.Fatal("cancellation without cancel_requested_at was accepted")
	}
	response = TaskResult{TaskID: "task-b", ResultDigest: "sha256:" + strings.Repeat("a", 64), ResponseBytes: 1, ResultBase64: "!!!!"}
	if _, _, err := client.GetTaskResult(ctx, "tenant-a", "task-b"); err == nil {
		t.Fatal("invalid result encoding was accepted")
	}
	response = wrongTenant
	if _, err := client.SubmitTaskRequest(ctx, "tenant-a", "permit", []byte("request")); err == nil {
		t.Fatal("submission with mismatched task tenant was accepted")
	}

	if _, err := client.ListTaskRequests(ctx, "bad tenant", "", 1); err == nil {
		t.Fatal("invalid list tenant was accepted")
	}
	if _, err := client.GetTaskRequest(ctx, "tenant-a", "bad task"); err == nil {
		t.Fatal("invalid task identity was accepted")
	}
	if _, err := client.SubmitTaskRequest(ctx, "tenant-a", "", nil); err == nil {
		t.Fatal("empty submission was accepted")
	}
}

func clientTaskFixture(taskID, createdAt string) controlstore.TaskRequest {
	return controlstore.TaskRequest{
		TenantID: "tenant-a", TaskID: taskID, NodeID: "node-1", InstanceID: "agent-1",
		InstanceGeneration: 1, RuntimeRef: "executor-" + strings.Repeat("a", 64),
		ServiceID: "hermes", OperationID: "hermes.run",
		RequestDigest: "sha256:" + strings.Repeat("b", 64), RequestBytes: 7,
		PermitDigest: "sha256:" + strings.Repeat("c", 64), PermitKeyID: "tenant-task",
		Deadline: "2026-07-22T08:10:00Z", State: controlstore.TaskRequestQueued,
		CreatedAt: createdAt, UpdatedAt: createdAt,
	}
}
