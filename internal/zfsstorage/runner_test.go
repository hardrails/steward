package zfsstorage

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExecRunnerBoundsOutputAndRetainsCommandFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "zfs")
	script := `#!/bin/sh
case "$1" in
  ok) printf 'dataset-value' ;;
  fail) printf 'cannot open dataset' >&2; exit 3 ;;
  stdout-overflow) /usr/bin/head -c 1048577 /dev/zero ;;
  stderr-overflow) /usr/bin/head -c 1048577 /dev/zero >&2 ;;
esac
`
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	runner := ExecRunner{Path: path}
	output, err := runner.Run(context.Background(), "ok")
	if err != nil || string(output) != "dataset-value" {
		t.Fatalf("successful command = (%q, %v)", output, err)
	}
	if _, err := runner.Run(nil, "ok"); err == nil {
		t.Fatal("nil command context was accepted")
	}
	_, err = runner.Run(context.Background(), "fail")
	var commandErr *CommandError
	if !errors.As(err, &commandErr) || commandErr.Stderr != "cannot open dataset" ||
		!strings.Contains(commandErr.Error(), "zfs fail failed") || commandErr.Unwrap() == nil {
		t.Fatalf("command failure = %#v", err)
	}
	for _, operation := range []string{"stdout-overflow", "stderr-overflow"} {
		if _, err := runner.Run(context.Background(), operation); err == nil ||
			!strings.Contains(err.Error(), "exceeded 1 MiB") {
			t.Fatalf("%s error = %v", operation, err)
		}
	}
	buffer := &boundedBuffer{remaining: 4}
	_, _ = buffer.Write([]byte("abcdef"))
	if string(buffer.Bytes()) != "abcd" || !buffer.overflow {
		t.Fatalf("bounded bytes = %q overflow=%v", buffer.Bytes(), buffer.overflow)
	}
}

func TestExecRunnerRejectsUnsafeBinaryPaths(t *testing.T) {
	for _, path := range []string{"", "zfs", "/usr/bin/not-zfs", "/usr/bin/../bin/zfs"} {
		if err := (ExecRunner{Path: path}).Validate(); err == nil {
			t.Fatalf("unsafe runner path accepted: %q", path)
		}
		if _, err := (ExecRunner{Path: path}).Run(context.Background(), "list"); err == nil {
			t.Fatalf("unsafe runner executed: %q", path)
		}
	}
}
