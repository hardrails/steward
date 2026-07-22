package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hardrails/steward/internal/controlclient"
	"github.com/hardrails/steward/internal/controlstore"
	"github.com/hardrails/steward/internal/dsse"
)

func TestAsyncTaskCLIListsGetsCancelsAndStoresResult(t *testing.T) {
	task := asyncTaskCLIFixture("task-a", controlstore.TaskRequestQueued)
	result := []byte(`{"answer":"bounded"}`)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer operator" {
			t.Fatalf("authorization=%q", request.Header.Get("Authorization"))
		}
		writer.Header().Set("Content-Type", "application/json")
		switch request.Method + " " + request.URL.Path {
		case "GET /v1/tenants/tenant-a/task-requests":
			if request.URL.Query().Get("after") != "task-before" || request.URL.Query().Get("limit") != "1" {
				t.Fatalf("list query=%q", request.URL.RawQuery)
			}
			_ = json.NewEncoder(writer).Encode(controlclient.TaskRequestList{Tasks: []controlstore.TaskRequest{task}})
		case "GET /v1/tenants/tenant-a/task-requests/task-a":
			_ = json.NewEncoder(writer).Encode(task)
		case "DELETE /v1/tenants/tenant-a/task-requests/task-a":
			cancelled := task
			cancelled.State = controlstore.TaskRequestCancelled
			cancelled.CancelRequestedAt = "2026-07-22T08:00:01Z"
			cancelled.UpdatedAt = cancelled.CancelRequestedAt
			cancelled.TerminalAt = cancelled.CancelRequestedAt
			_ = json.NewEncoder(writer).Encode(cancelled)
		case "GET /v1/tenants/tenant-a/task-requests/task-a/result":
			_ = json.NewEncoder(writer).Encode(controlclient.TaskResult{
				TaskID: "task-a", ResultDigest: dsse.Digest(result), ResponseBytes: int64(len(result)),
				ResultBase64: base64.StdEncoding.EncodeToString(result),
			})
		default:
			t.Fatalf("unexpected async task request %s %s", request.Method, request.URL.String())
		}
	}))
	defer server.Close()

	directory := t.TempDir()
	tokenPath := filepath.Join(directory, "operator.token")
	if err := os.WriteFile(tokenPath, []byte("operator\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	common := []string{"-control-url", server.URL, "-token-file", tokenPath, "-tenant-id", "tenant-a", "-no-context"}
	commands := []struct {
		name string
		call func([]string, *bytes.Buffer) error
		args []string
	}{
		{name: "list", call: func(args []string, output *bytes.Buffer) error { return listAsyncTasks(args, output) }, args: append([]string{"-after", "task-before", "-limit", "1"}, common...)},
		{name: "get", call: func(args []string, output *bytes.Buffer) error { return getAsyncTask(args, output) }, args: append([]string{"task-a"}, common...)},
		{name: "cancel", call: func(args []string, output *bytes.Buffer) error { return cancelAsyncTask(args, output) }, args: append([]string{"task-a"}, common...)},
	}
	for _, command := range commands {
		t.Run(command.name, func(t *testing.T) {
			var output bytes.Buffer
			if err := command.call(command.args, &output); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(output.String(), `"task_id":"task-a"`) {
				t.Fatalf("output=%s", output.String())
			}
		})
	}
	resultPath := filepath.Join(directory, "result.json")
	var output bytes.Buffer
	if err := getAsyncTaskResult(append([]string{"task-a", "-out", resultPath}, common...), &output); err != nil {
		t.Fatal(err)
	}
	stored, err := os.ReadFile(resultPath)
	if err != nil || string(stored) != string(result) {
		t.Fatalf("stored result=%q err=%v", stored, err)
	}
	info, err := os.Stat(resultPath)
	if err != nil || info.Mode().Perm() != 0o600 || !strings.Contains(output.String(), `"result_path":`) {
		t.Fatalf("result metadata=%s mode=%v err=%v", output.String(), info.Mode(), err)
	}
}

func TestAsyncTaskCLIRejectsIncompleteArguments(t *testing.T) {
	for name, call := range map[string]func() error{
		"enqueue": func() error { return enqueueTask([]string{"-no-context"}, &bytes.Buffer{}) },
		"list":    func() error { return listAsyncTasks([]string{"-no-context", "-limit", "0"}, &bytes.Buffer{}) },
		"get":     func() error { return getAsyncTask([]string{"-no-context", "-tenant-id", "tenant-a"}, &bytes.Buffer{}) },
		"result":  func() error { return getAsyncTaskResult([]string{"-no-context", "task-a"}, &bytes.Buffer{}) },
		"cancel": func() error {
			return cancelAsyncTask([]string{"-no-context", "-tenant-id", "tenant-a"}, &bytes.Buffer{})
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := call(); err == nil {
				t.Fatal("incomplete async task arguments were accepted")
			}
		})
	}
}

func TestAsyncTaskContextInjectsEveryAvailableDefaultAndHonorsOverrides(t *testing.T) {
	fixture := newTaskCLIFixture(t)
	if err := os.Chmod(fixture.directory, 0o700); err != nil {
		t.Fatal(err)
	}
	tokenPath := filepath.Join(fixture.directory, "operator.token")
	gatewayTokenPath := filepath.Join(fixture.directory, "gateway.token")
	for path, content := range map[string]string{tokenPath: "operator\n", gatewayTokenPath: "gateway\n"} {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	contextPath := filepath.Join(fixture.directory, "contexts.json")
	t.Setenv("STEWARD_CONTEXT_FILE", contextPath)
	config := cliContextConfig{
		SchemaVersion: cliContextSchema, Current: "fleet",
		Contexts: []cliContext{{
			Name: "fleet", ControlURL: "https://control.example", TokenFile: tokenPath,
			GatewayURL: "http://127.0.0.1:1", GatewayTokenFile: gatewayTokenPath,
			ServiceTrustFile: fixture.trustPath, TaskKeyFile: fixture.privatePath,
			TaskKeyID: fixture.keyID, TenantID: "tenant-a",
		}},
	}
	if err := writeCLIContextConfig(contextPath, config); err != nil {
		t.Fatal(err)
	}
	hydrated, err := applyAsyncTaskContext([]string{"-tenant-id", "override", "-limit", "1"})
	if err != nil {
		t.Fatal(err)
	}
	for _, pair := range [][]string{
		{"-control-url", "https://control.example"}, {"-token-file", tokenPath},
		{"-trust", fixture.trustPath}, {"-key", fixture.privatePath}, {"-key-id", fixture.keyID},
		{"-tenant-id", "override"},
	} {
		if !adjacentArguments(hydrated, pair[0], pair[1]) {
			t.Fatalf("hydrated arguments %v missing %v", hydrated, pair)
		}
	}
	if strings.Contains(strings.Join(hydrated, " "), "tenant-a") {
		t.Fatalf("context overrode explicit tenant: %v", hydrated)
	}
}

func asyncTaskCLIFixture(taskID, state string) controlstore.TaskRequest {
	return controlstore.TaskRequest{
		TenantID: "tenant-a", TaskID: taskID, NodeID: "node-1", InstanceID: "agent-1",
		InstanceGeneration: 1, RuntimeRef: "executor-" + strings.Repeat("a", 64),
		ServiceID: "hermes", OperationID: "hermes.run",
		RequestDigest: "sha256:" + strings.Repeat("b", 64), RequestBytes: 20,
		PermitDigest: "sha256:" + strings.Repeat("c", 64), PermitKeyID: "tenant-task",
		Deadline: "2026-07-22T08:10:00Z", State: state,
		CreatedAt: "2026-07-22T08:00:00Z", UpdatedAt: "2026-07-22T08:00:00Z",
	}
}
