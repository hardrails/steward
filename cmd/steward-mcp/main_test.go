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
