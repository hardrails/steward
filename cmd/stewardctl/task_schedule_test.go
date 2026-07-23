package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hardrails/steward/internal/controlclient"
	"github.com/hardrails/steward/internal/controlstore"
	"github.com/hardrails/steward/internal/schedulepermit"
)

func TestTaskScheduleCLIListsShowsAndCancels(t *testing.T) {
	schedule := taskScheduleCLIFixture()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer operator" {
			t.Fatalf("authorization=%q", request.Header.Get("Authorization"))
		}
		writer.Header().Set("Content-Type", "application/json")
		switch request.Method + " " + request.URL.Path {
		case "GET /v1/tenants/tenant-a/schedules":
			if request.URL.Query().Get("after") != "before" || request.URL.Query().Get("limit") != "1" {
				t.Fatalf("list query=%q", request.URL.RawQuery)
			}
			_ = json.NewEncoder(writer).Encode(controlclient.TaskScheduleList{
				Schedules: []controlstore.TaskSchedule{schedule},
			})
		case "GET /v1/tenants/tenant-a/schedules/research-hourly":
			_ = json.NewEncoder(writer).Encode(schedule)
		case "DELETE /v1/tenants/tenant-a/schedules/research-hourly":
			cancelled := schedule
			cancelled.State = controlstore.TaskScheduleCancelled
			cancelled.CancelledAt = "2026-07-23T12:01:00Z"
			cancelled.UpdatedAt = cancelled.CancelledAt
			_ = json.NewEncoder(writer).Encode(cancelled)
		default:
			t.Fatalf("unexpected schedule request %s %s", request.Method, request.URL.String())
		}
	}))
	defer server.Close()
	tokenPath := filepath.Join(t.TempDir(), "operator.token")
	if err := os.WriteFile(tokenPath, []byte("operator\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	common := []string{
		"-control-url", server.URL, "-token-file", tokenPath,
		"-tenant-id", "tenant-a", "-no-context",
	}
	for _, command := range []struct {
		name string
		call func([]string, *bytes.Buffer) error
		args []string
	}{
		{"list", func(arguments []string, output *bytes.Buffer) error {
			return listTaskSchedules(arguments, output)
		}, append([]string{"-after", "before", "-limit", "1"}, common...)},
		{"show", func(arguments []string, output *bytes.Buffer) error {
			return taskScheduleByID("task schedule show", arguments, output, false)
		}, append([]string{"research-hourly"}, common...)},
		{"cancel", func(arguments []string, output *bytes.Buffer) error {
			return taskScheduleByID("task schedule cancel", arguments, output, true)
		}, append([]string{"research-hourly"}, common...)},
	} {
		t.Run(command.name, func(t *testing.T) {
			var output bytes.Buffer
			if err := command.call(command.args, &output); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(output.String(), `"schedule_id":"research-hourly"`) {
				t.Fatalf("output=%s", output.String())
			}
		})
	}
}

func TestTaskScheduleCLIRejectsUnboundedOrIncompleteCreation(t *testing.T) {
	for name, arguments := range map[string][]string{
		"missing deployment": {"-no-context", "-tenant-id", "tenant-a"},
		"unbounded runs": {
			"agent-a", "-no-context", "-tenant-id", "tenant-a", "-trust", "trust",
			"-key", "key", "-key-id", "authority", "-runs", "10001", "prompt",
		},
		"repeats without interval": {
			"agent-a", "-no-context", "-tenant-id", "tenant-a", "-trust", "trust",
			"-key", "key", "-key-id", "authority", "-runs", "2", "prompt",
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := createTaskSchedule(arguments, &bytes.Buffer{}); err == nil {
				t.Fatal("invalid task schedule creation was accepted")
			}
		})
	}
	if _, _, err := promptOperation("hermes-api"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := promptOperation("unknown"); err == nil {
		t.Fatal("unknown service prompt contract was accepted")
	}
}

func taskScheduleCLIFixture() controlstore.TaskSchedule {
	statement := schedulepermit.Statement{
		SchemaVersion: schedulepermit.SchemaV1, ScheduleID: "research-hourly",
		NodeID: "node-1", TenantID: "tenant-a", InstanceID: "agent-1",
		RuntimeRef: "executor-" + strings.Repeat("a", 64),
		GrantID:    "grant-" + strings.Repeat("b", 64), Generation: 1,
		CapsuleDigest:     "sha256:" + strings.Repeat("c", 64),
		PolicyDigest:      "sha256:" + strings.Repeat("d", 64),
		RoutePolicyDigest: "sha256:" + strings.Repeat("e", 64),
		ServiceID:         "hermes-api", OperationID: "hermes.run",
		OperationPolicyDigest: "sha256:" + strings.Repeat("f", 64),
		RequestDigest:         "sha256:" + strings.Repeat("1", 64), RequestBytes: 20,
		ContentType: "application/json", StartsAt: "2026-07-23T12:05:00Z",
		IntervalSeconds: 3600, RunCount: 24, WindowSeconds: 300,
		MaxConcurrency: 1, OverlapPolicy: "skip", MissedRunPolicy: "catch_up_one",
	}
	return controlstore.TaskSchedule{
		TenantID: "tenant-a", Statement: statement,
		PermitDigest: "sha256:" + strings.Repeat("2", 64), PermitKeyID: "tenant-task",
		State: controlstore.TaskScheduleActive, NextOrdinal: 1, Runs: []controlstore.ScheduleRun{},
		CreatedAt: "2026-07-23T12:00:00Z", UpdatedAt: "2026-07-23T12:00:00Z",
	}
}
