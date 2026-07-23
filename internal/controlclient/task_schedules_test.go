package controlclient

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hardrails/steward/internal/controlstore"
	"github.com/hardrails/steward/internal/schedulepermit"
	"github.com/hardrails/steward/internal/taskpermit"
)

func TestTaskScheduleClientCreatesListsLooksUpAndCancels(t *testing.T) {
	schedule := controlClientTaskSchedule("research-hourly", "2026-07-23T14:00:00Z")
	permit := []byte("signed schedule")
	requestBody := []byte(`{"input":"research"}`)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer operator" {
			t.Errorf("authorization=%q", request.Header.Get("Authorization"))
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		switch request.Method + " " + request.URL.Path {
		case "POST /v1/tenants/tenant-a/schedules":
			var input struct {
				SchedulePermitBase64 string `json:"schedule_permit_base64"`
				RequestBase64        string `json:"request_base64"`
			}
			if err := json.NewDecoder(request.Body).Decode(&input); err != nil ||
				input.SchedulePermitBase64 != base64.StdEncoding.EncodeToString(permit) ||
				input.RequestBase64 != base64.StdEncoding.EncodeToString(requestBody) {
				t.Errorf("schedule input=%+v err=%v", input, err)
				writer.WriteHeader(http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(writer).Encode(schedule)
		case "GET /v1/tenants/tenant-a/schedules":
			if request.URL.Query().Get("after") != "before" || request.URL.Query().Get("limit") != "2" {
				t.Errorf("schedule query=%q", request.URL.RawQuery)
			}
			_ = json.NewEncoder(writer).Encode(TaskScheduleList{
				Schedules: []controlstore.TaskSchedule{schedule},
				NextAfter: schedule.Statement.ScheduleID,
			})
		case "GET /v1/tenants/tenant-a/schedules/research-hourly":
			_ = json.NewEncoder(writer).Encode(schedule)
		case "DELETE /v1/tenants/tenant-a/schedules/research-hourly":
			cancelled := schedule
			cancelled.State = controlstore.TaskScheduleCancelled
			cancelled.CancelledAt = "2026-07-23T14:01:00Z"
			cancelled.UpdatedAt = cancelled.CancelledAt
			_ = json.NewEncoder(writer).Encode(cancelled)
		default:
			t.Errorf("unexpected request %s %s", request.Method, request.URL.String())
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	client, err := New(server.URL, "operator", nil)
	if err != nil {
		t.Fatal(err)
	}
	created, err := client.CreateTaskSchedule(context.Background(), "tenant-a", permit, requestBody)
	if err != nil || created.Statement.ScheduleID != "research-hourly" {
		t.Fatalf("created=(%+v, %v)", created, err)
	}
	page, err := client.ListTaskSchedules(context.Background(), "tenant-a", "before", 2)
	if err != nil || len(page.Schedules) != 1 || page.NextAfter != "research-hourly" {
		t.Fatalf("page=(%+v, %v)", page, err)
	}
	found, err := client.GetTaskSchedule(context.Background(), "tenant-a", "research-hourly")
	if err != nil || found.Statement.ScheduleID != "research-hourly" {
		t.Fatalf("found=(%+v, %v)", found, err)
	}
	cancelled, err := client.CancelTaskSchedule(context.Background(), "tenant-a", "research-hourly")
	if err != nil || cancelled.State != controlstore.TaskScheduleCancelled {
		t.Fatalf("cancelled=(%+v, %v)", cancelled, err)
	}
}

func TestTaskScheduleClientRejectsInvalidInputsAndProjections(t *testing.T) {
	valid := controlClientTaskSchedule("schedule-a", "2026-07-23T14:00:00Z")
	mode := "nil-page"
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		switch mode {
		case "nil-page":
			_ = json.NewEncoder(writer).Encode(TaskScheduleList{})
		case "oversized-page":
			_ = json.NewEncoder(writer).Encode(TaskScheduleList{
				Schedules: []controlstore.TaskSchedule{valid, valid},
			})
		case "noncanonical-page":
			later := controlClientTaskSchedule("schedule-b", "2026-07-23T14:01:00Z")
			_ = json.NewEncoder(writer).Encode(TaskScheduleList{
				Schedules: []controlstore.TaskSchedule{valid, later},
			})
		case "bad-cursor":
			_ = json.NewEncoder(writer).Encode(TaskScheduleList{
				Schedules: []controlstore.TaskSchedule{valid}, NextAfter: "other",
			})
		case "wrong-tenant":
			changed := valid
			changed.TenantID = "tenant-b"
			_ = json.NewEncoder(writer).Encode(changed)
		case "active-cancel":
			_ = json.NewEncoder(writer).Encode(valid)
		default:
			writer.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer server.Close()
	client, err := New(server.URL, "operator", nil)
	if err != nil {
		t.Fatal(err)
	}
	for name, call := range map[string]func() error{
		"create tenant": func() error {
			_, err := client.CreateTaskSchedule(context.Background(), "-tenant", []byte("permit"), []byte("{}"))
			return err
		},
		"create permit": func() error {
			_, err := client.CreateTaskSchedule(context.Background(), "tenant-a", nil, []byte("{}"))
			return err
		},
		"create request": func() error {
			_, err := client.CreateTaskSchedule(context.Background(), "tenant-a", []byte("permit"), nil)
			return err
		},
		"list tenant": func() error {
			_, err := client.ListTaskSchedules(context.Background(), "-tenant", "", 1)
			return err
		},
		"list limit": func() error {
			_, err := client.ListTaskSchedules(context.Background(), "tenant-a", "", 101)
			return err
		},
		"get identity": func() error {
			_, err := client.GetTaskSchedule(context.Background(), "tenant-a", "bad id")
			return err
		},
		"cancel identity": func() error {
			_, err := client.CancelTaskSchedule(context.Background(), "tenant-a", "bad id")
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := call(); err == nil {
				t.Fatal("invalid client input was accepted")
			}
		})
	}
	for _, selected := range []string{"nil-page", "oversized-page", "noncanonical-page", "bad-cursor"} {
		mode = selected
		limit := 1
		if selected == "noncanonical-page" {
			limit = 2
		}
		if _, err := client.ListTaskSchedules(context.Background(), "tenant-a", "", limit); err == nil {
			t.Fatalf("%s projection was accepted", selected)
		}
	}
	mode = "wrong-tenant"
	if _, err := client.CreateTaskSchedule(context.Background(), "tenant-a", []byte("permit"), []byte("{}")); err == nil {
		t.Fatal("wrong-tenant create projection was accepted")
	}
	if _, err := client.GetTaskSchedule(context.Background(), "tenant-a", "schedule-a"); err == nil {
		t.Fatal("wrong-tenant lookup projection was accepted")
	}
	mode = "active-cancel"
	if _, err := client.CancelTaskSchedule(context.Background(), "tenant-a", "schedule-a"); err == nil {
		t.Fatal("active cancellation projection was accepted")
	}
}

func controlClientTaskSchedule(id, createdAt string) controlstore.TaskSchedule {
	request := []byte(`{"input":"research"}`)
	statement := schedulepermit.Statement{
		SchemaVersion: schedulepermit.SchemaV1, ScheduleID: id,
		NodeID: "node-1", TenantID: "tenant-a", InstanceID: "agent-1",
		RuntimeRef: "executor-" + strings.Repeat("a", 64),
		GrantID:    "grant-" + strings.Repeat("b", 64), Generation: 1,
		CapsuleDigest:         "sha256:" + strings.Repeat("c", 64),
		PolicyDigest:          "sha256:" + strings.Repeat("d", 64),
		RoutePolicyDigest:     "sha256:" + strings.Repeat("e", 64),
		ServiceID:             "hermes-api",
		OperationID:           "hermes.run",
		OperationPolicyDigest: "sha256:" + strings.Repeat("f", 64),
		RequestDigest:         taskpermit.RequestDigest(request), RequestBytes: int64(len(request)),
		ContentType: "application/json", StartsAt: "2026-07-23T14:05:00Z",
		IntervalSeconds: 3600, RunCount: 2, WindowSeconds: 300,
		MaxConcurrency: 1, OverlapPolicy: "skip", MissedRunPolicy: "skip",
	}
	return controlstore.TaskSchedule{
		TenantID: "tenant-a", Statement: statement,
		PermitDigest: "sha256:" + strings.Repeat("1", 64), PermitKeyID: "tenant-task",
		State: controlstore.TaskScheduleActive, NextOrdinal: 1,
		Runs: []controlstore.ScheduleRun{}, CreatedAt: createdAt, UpdatedAt: createdAt,
	}
}
