package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
)

func TestCLIContextDrivesARealControlCommand(t *testing.T) {
	type observedRequest struct {
		method        string
		target        string
		authorization string
	}
	observed := make(chan observedRequest, 1)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		observed <- observedRequest{request.Method, request.URL.String(), request.Header.Get("Authorization")}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"tenants":[]}`))
	}))
	defer server.Close()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	tokenPath := filepath.Join(directory, "operator.token")
	if err := os.WriteFile(tokenPath, []byte("operator-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("STEWARD_CONTEXT_FILE", filepath.Join(directory, "contexts.json"))
	if err := contextCommand([]string{
		"set", "test", "-control-url", server.URL, "-token-file", tokenPath,
	}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := run([]string{"control", "tenant", "list"}, &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(output.String()) != `{"tenants":[]}` {
		t.Fatalf("output=%s", output.String())
	}
	request := <-observed
	if request.method != http.MethodGet || !strings.HasPrefix(request.target, "/v1/tenants?") ||
		request.authorization != "Bearer operator-secret" {
		t.Fatalf("request=%s %s authorization=%q", request.method, request.target, request.authorization)
	}
}

func TestCLIContextShortensScopedControlCommandsWithoutStoringBearer(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	contextPath := filepath.Join(directory, "contexts.json")
	tokenPath := filepath.Join(directory, "operator.token")
	if err := os.WriteFile(tokenPath, []byte("operator-secret-value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("STEWARD_CONTEXT_FILE", contextPath)
	t.Setenv("STEWARD_CONTEXT", "")

	var output bytes.Buffer
	if err := contextCommand([]string{
		"set", "production",
		"-control-url", "http://127.0.0.1:8443",
		"-token-file", tokenPath,
		"-tenant-id", "tenant-a",
		"-node-id", "node-a",
	}, &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `"name":"production"`) || strings.Contains(output.String(), "operator-secret-value") {
		t.Fatalf("context output leaked or omitted context metadata: %s", output.String())
	}
	raw, err := os.ReadFile(contextPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "operator-secret-value") || !strings.Contains(string(raw), tokenPath) {
		t.Fatalf("context file must contain only the token path, not its value: %s", raw)
	}
	info, err := os.Stat(contextPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("context mode=%v", info.Mode().Perm())
	}

	hydrated, err := applyCLIContext([]string{"command", "submit", "-command", "command.json"})
	if err != nil {
		t.Fatal(err)
	}
	for _, pair := range [][]string{
		{"-control-url", "http://127.0.0.1:8443"},
		{"-token-file", tokenPath},
		{"-tenant-id", "tenant-a"},
		{"-node-id", "node-a"},
	} {
		if !adjacentArguments(hydrated, pair[0], pair[1]) {
			t.Fatalf("hydrated arguments %v missing %v", hydrated, pair)
		}
	}
}

func TestCLIContextExplicitFlagsOverrideAndDestructiveIdentityStaysExplicit(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	tokenPath := filepath.Join(directory, "operator.token")
	if err := os.WriteFile(tokenPath, []byte("operator-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("STEWARD_CONTEXT_FILE", filepath.Join(directory, "contexts.json"))
	if err := contextCommand([]string{
		"set", "local", "-token-file", tokenPath, "-tenant-id", "tenant-a", "-node-id", "node-a",
	}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}

	hydrated, err := applyCLIContext([]string{
		"command", "status", "--tenant-id=tenant-b", "-node-id", "node-b", "-command-id", "command-a",
	})
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(hydrated, "tenant-a") || slices.Contains(hydrated, "node-a") {
		t.Fatalf("context overrode explicit scope: %v", hydrated)
	}

	destructive, err := applyCLIContext([]string{"node", "revoke"})
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(destructive, "node-a") {
		t.Fatalf("context injected destructive node identity: %v", destructive)
	}
	if !adjacentArguments(destructive, "-token-file", tokenPath) {
		t.Fatalf("context did not apply safe connection default: %v", destructive)
	}
	disabled, err := applyCLIContext([]string{
		"command", "status", "--no-context", "-tenant-id", "tenant-b", "-node-id", "node-b", "-command-id", "command-a",
	})
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(disabled, "--no-context") || slices.Contains(disabled, tokenPath) || slices.Contains(disabled, "tenant-a") {
		t.Fatalf("-no-context did not disable or escape preprocessing: %v", disabled)
	}
	if _, err := applyCLIContext([]string{"command", "status", "-no-context", "--no-context"}); err == nil {
		t.Fatal("duplicate -no-context flags were accepted")
	}
	for _, input := range [][]string{{"command"}, {"not-a-control-command", "status"}} {
		unchanged, err := applyCLIContext(input)
		if err != nil || !slices.Equal(unchanged, input) {
			t.Fatalf("unscoped input=%v output=%v err=%v", input, unchanged, err)
		}
	}
}

func TestCLIContextSelectionLifecycleAndEnvironmentOverride(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	contextPath := filepath.Join(directory, "contexts.json")
	tokenPath := filepath.Join(directory, "operator.token")
	if err := os.WriteFile(tokenPath, []byte("operator-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("STEWARD_CONTEXT_FILE", contextPath)
	if err := contextCommand([]string{"set", "alpha", "-token-file", tokenPath, "-tenant-id", "tenant-a"}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if err := contextCommand([]string{"set", "bravo", "-token-file", tokenPath, "-tenant-id", "tenant-b"}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if err := contextCommand([]string{"use", "alpha"}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	var listed bytes.Buffer
	if err := contextCommand([]string{"list"}, &listed); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(listed.String(), `"current":"alpha"`) ||
		!strings.Contains(listed.String(), `"name":"alpha"`) ||
		!strings.Contains(listed.String(), `"name":"bravo"`) ||
		strings.Contains(listed.String(), "operator-secret") {
		t.Fatalf("context list output=%s", listed.String())
	}
	var shown bytes.Buffer
	if err := contextCommand([]string{"show"}, &shown); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(shown.String(), `"name":"alpha"`) || !strings.Contains(shown.String(), contextPath) ||
		strings.Contains(shown.String(), "operator-secret") {
		t.Fatalf("context show output=%s", shown.String())
	}
	arguments, err := applyCLIContext([]string{"operations", "status"})
	if err != nil || !slices.Contains(arguments, "tenant-a") {
		t.Fatalf("current context arguments=%v err=%v", arguments, err)
	}
	t.Setenv("STEWARD_CONTEXT", "bravo")
	arguments, err = applyCLIContext([]string{"operations", "status"})
	if err != nil || !slices.Contains(arguments, "tenant-b") {
		t.Fatalf("environment-selected context arguments=%v err=%v", arguments, err)
	}
	t.Setenv("STEWARD_CONTEXT", "")
	if err := contextCommand([]string{"delete", "alpha"}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if _, err := applyCLIContext([]string{"operations", "status"}); err != nil {
		t.Fatalf("no selected context should preserve explicit-flag compatibility: %v", err)
	}
}

func TestCLIContextRejectsUnsafeFilesAndNames(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	tokenPath := filepath.Join(directory, "operator.token")
	if err := os.WriteFile(tokenPath, []byte("operator-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	contextPath := filepath.Join(directory, "contexts.json")
	t.Setenv("STEWARD_CONTEXT_FILE", contextPath)
	if err := contextCommand([]string{"set", "../escape", "-token-file", tokenPath}, &bytes.Buffer{}); err == nil {
		t.Fatal("unsafe context name was accepted")
	}
	if err := os.WriteFile(contextPath, []byte(`{"schema_version":"steward.cli-context.v1","contexts":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadCLIContextConfig(); err == nil || !strings.Contains(err.Error(), "owner-only") {
		t.Fatalf("unsafe context permissions error=%v", err)
	}
	if err := os.WriteFile(contextPath, []byte(`{"schema_version":"steward.cli-context.v1","contexts":[],"unexpected":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(contextPath, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadCLIContextConfig(); err == nil || !strings.Contains(err.Error(), "decode CLI context file") {
		t.Fatalf("unknown context field error=%v", err)
	}
	if err := os.Remove(contextPath); err != nil {
		t.Fatal(err)
	}
	if err := contextCommand([]string{"show"}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "no Steward CLI context") {
		t.Fatalf("unselected context show error=%v", err)
	}
}

func TestCLIContextRejectsUnsafeLockAndInvalidLifecycleRequests(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	tokenPath := filepath.Join(directory, "operator.token")
	if err := os.WriteFile(tokenPath, []byte("operator-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	contextPath := filepath.Join(directory, "contexts.json")
	t.Setenv("STEWARD_CONTEXT_FILE", contextPath)
	if err := os.WriteFile(contextPath+".lock", nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := contextCommand([]string{"set", "unsafe", "-token-file", tokenPath}, &bytes.Buffer{}); err == nil ||
		!strings.Contains(err.Error(), "owner-only regular file") {
		t.Fatalf("unsafe lock error=%v", err)
	}
	if err := os.Chmod(contextPath+".lock", 0o600); err != nil {
		t.Fatal(err)
	}
	if err := contextCommand([]string{"set", "safe", "-token-file", tokenPath}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if err := contextCommand([]string{"set", "safe", "-tenant-id", "tenant-a"}, &bytes.Buffer{}); err != nil {
		t.Fatalf("update existing context: %v", err)
	}
	t.Setenv("STEWARD_CONTEXT", "missing")
	if _, err := applyCLIContext([]string{"operations", "status"}); err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("unknown selected context error=%v", err)
	}
	t.Setenv("STEWARD_CONTEXT", "")
	for name, arguments := range map[string][]string{
		"unknown action": {"unknown"},
		"missing use":    {"use", "missing"},
		"show arguments": {"show", "extra"},
		"list arguments": {"list", "extra"},
		"missing delete": {"delete", "missing"},
	} {
		t.Run(name, func(t *testing.T) {
			if err := contextCommand(arguments, &bytes.Buffer{}); err == nil {
				t.Fatalf("context request %v succeeded", arguments)
			}
		})
	}
}

func TestCLIContextConcurrentWritersRetainEveryContext(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	tokenPath := filepath.Join(directory, "operator.token")
	if err := os.WriteFile(tokenPath, []byte("operator-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("STEWARD_CONTEXT_FILE", filepath.Join(directory, "contexts.json"))

	const writers = 12
	start := make(chan struct{})
	errorsByWriter := make(chan error, writers)
	var group sync.WaitGroup
	for index := 0; index < writers; index++ {
		name := "context-" + strconv.Itoa(index)
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			errorsByWriter <- contextCommand([]string{"set", name, "-token-file", tokenPath}, &bytes.Buffer{})
		}()
	}
	close(start)
	group.Wait()
	close(errorsByWriter)
	for err := range errorsByWriter {
		if err != nil {
			t.Fatal(err)
		}
	}
	config, _, err := loadCLIContextConfig()
	if err != nil {
		t.Fatal(err)
	}
	if len(config.Contexts) != writers {
		t.Fatalf("concurrent context count=%d want=%d", len(config.Contexts), writers)
	}
	lockInfo, err := os.Stat(filepath.Join(directory, "contexts.json.lock"))
	if err != nil {
		t.Fatal(err)
	}
	if lockInfo.Mode().Perm() != 0o600 {
		t.Fatalf("context lock mode=%v", lockInfo.Mode().Perm())
	}
}

func adjacentArguments(arguments []string, name, value string) bool {
	for index := 0; index+1 < len(arguments); index++ {
		if arguments[index] == name && arguments[index+1] == value {
			return true
		}
	}
	return false
}
