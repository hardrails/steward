package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunVersionTokenAndEmptySession(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"-version"}, strings.NewReader(""), &stdout, &stderr); code != 0 || !strings.Contains(stdout.String(), "steward-mcp") {
		t.Fatalf("version code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	stderr.Reset()
	if code := run(context.Background(), nil, strings.NewReader(""), &stdout, &stderr); code != 2 || !strings.Contains(stderr.String(), "token-file is required") {
		t.Fatalf("missing token code=%d stderr=%q", code, stderr.String())
	}
	token := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(token, []byte("node-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stderr.Reset()
	if code := run(context.Background(), []string{"-token-file", token}, strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("empty session code=%d stderr=%q", code, stderr.String())
	}
	if code := run(context.Background(), []string{"-bad-flag"}, strings.NewReader(""), &stdout, &stderr); code != 2 {
		t.Fatalf("invalid flag code=%d", code)
	}
}

func TestRunRegistersTaskToolsOnlyWithCompleteGatewayConfiguration(t *testing.T) {
	directory := t.TempDir()
	nodeToken := filepath.Join(directory, "node.token")
	gatewayToken := filepath.Join(directory, "gateway.token")
	for path, value := range map[string]string{nodeToken: "node-secret\n", gatewayToken: "gateway-secret\n"} {
		if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	resultDirectory := filepath.Join(directory, "results")
	if err := os.Mkdir(resultDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	input := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`,
	}, "\n") + "\n"

	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"-token-file", nodeToken}, strings.NewReader(input), &stdout, &stderr); code != 0 {
		t.Fatalf("node-only code=%d stderr=%q", code, stderr.String())
	}
	if strings.Contains(stdout.String(), "steward_task_submit") {
		t.Fatalf("node-only MCP exposed task tools: %s", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := run(context.Background(), []string{
		"-token-file", nodeToken,
		"-gateway-url", "http://127.0.0.1:8091",
		"-gateway-token-file", gatewayToken,
		"-task-result-dir", resultDirectory,
	}, strings.NewReader(input), &stdout, &stderr); code != 0 {
		t.Fatalf("task-enabled code=%d stderr=%q", code, stderr.String())
	}
	for _, name := range []string{"steward_task_submit", "steward_task_status", "steward_task_observe"} {
		if !strings.Contains(stdout.String(), name) {
			t.Fatalf("task-enabled MCP omitted %s: %s", name, stdout.String())
		}
	}
	if !strings.Contains(stdout.String(), "acknowledge_external_effects") ||
		!strings.Contains(stdout.String(), "not proof of human approval") ||
		strings.Contains(stdout.String(), "confirm_irreversible") || strings.Contains(stdout.String(), "result_name") {
		t.Fatalf("task-enabled MCP exposed stale or unsafe task arguments: %s", stdout.String())
	}

	for _, partial := range [][]string{
		{"-token-file", nodeToken, "-gateway-url", "http://127.0.0.1:8091"},
		{"-token-file", nodeToken, "-gateway-token-file", gatewayToken},
		{"-token-file", nodeToken, "-task-result-dir", resultDirectory},
	} {
		stdout.Reset()
		stderr.Reset()
		if code := run(context.Background(), partial, strings.NewReader(""), &stdout, &stderr); code != 2 ||
			!strings.Contains(stderr.String(), "must be configured together") {
			t.Fatalf("partial config=%#v code=%d stderr=%q", partial, code, stderr.String())
		}
	}
	stdout.Reset()
	stderr.Reset()
	if code := run(context.Background(), []string{
		"-token-file", nodeToken,
		"-gateway-url", "http://localhost:8091",
		"-gateway-token-file", gatewayToken,
		"-task-result-dir", resultDirectory,
	}, strings.NewReader(""), &stdout, &stderr); code != 2 || !strings.Contains(stderr.String(), "literal-loopback") {
		t.Fatalf("nonliteral Gateway code=%d stderr=%q", code, stderr.String())
	}

	unsafeResultDirectory := filepath.Join(directory, "unsafe-results")
	if err := os.Mkdir(unsafeResultDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(unsafeResultDirectory, "unexpected"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := run(context.Background(), []string{
		"-token-file", nodeToken,
		"-gateway-url", "http://127.0.0.1:8091",
		"-gateway-token-file", gatewayToken,
		"-task-result-dir", unsafeResultDirectory,
	}, strings.NewReader(""), &stdout, &stderr); code != 2 || !strings.Contains(stderr.String(), "unexpected entry") {
		t.Fatalf("unsafe result directory code=%d stderr=%q", code, stderr.String())
	}
}
