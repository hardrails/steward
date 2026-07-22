package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/controlauth"
	"github.com/hardrails/steward/internal/controlbackup"
	"github.com/hardrails/steward/internal/controlstore"
	"github.com/hardrails/steward/internal/controlwitness"
)

func TestControlBackupCommandsCreateVerifyPreviewAndRestore(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "state")
	store, err := controlstore.Initialize(state, controlstore.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := controlauth.InitializeKey(filepath.Join(state, "auth.key")); err != nil {
		t.Fatal(err)
	}
	for _, prefix := range []string{"witness", "controller"} {
		if _, _, err := controlwitness.Initialize(
			filepath.Join(state, prefix+".private.pem"), filepath.Join(state, prefix+".public.pem"),
		); err != nil {
			t.Fatal(err)
		}
	}
	archive := filepath.Join(root, "control.tar")
	restored := filepath.Join(root, "restored")
	originalNow := timeNow
	timeNow = func() time.Time { return time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC) }
	t.Cleanup(func() { timeNow = originalNow })

	commands := [][]string{
		{"control", "backup", "create", "-state-dir", state, "-out", archive, "-no-context"},
		{"control", "backup", "verify", "-in", archive, "-no-context"},
		{"control", "backup", "restore", "-in", archive, "-state-dir", restored, "-no-context"},
	}
	for _, command := range commands {
		var output bytes.Buffer
		if err := run(command, &output, io.Discard); err != nil {
			t.Fatalf("%v: %v", command, err)
		}
		var report struct {
			SchemaVersion string `json:"schema_version"`
			Status        string `json:"status"`
			Applied       bool   `json:"applied"`
		}
		if err := json.Unmarshal(output.Bytes(), &report); err != nil ||
			report.SchemaVersion != controlbackup.ReportSchemaV1 || report.Status != "verified" || report.Applied {
			t.Fatalf("%v output=%s err=%v", command, output.String(), err)
		}
	}
	if _, err := os.Stat(restored); !os.IsNotExist(err) {
		t.Fatalf("preview created restore destination: %v", err)
	}
	var applied bytes.Buffer
	if err := run([]string{
		"control", "backup", "restore", "-in", archive, "-state-dir", restored, "-apply", "-no-context",
	}, &applied, io.Discard); err != nil {
		t.Fatal(err)
	}
	var report struct {
		Applied     bool   `json:"applied"`
		Destination string `json:"destination"`
	}
	if err := json.Unmarshal(applied.Bytes(), &report); err != nil || !report.Applied || report.Destination != restored {
		t.Fatalf("applied output=%s err=%v", applied.String(), err)
	}
	reopened, err := controlstore.Open(restored, controlstore.DefaultLimits())
	if err != nil {
		t.Fatalf("open CLI-restored state: %v", err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestControlBackupCommandsRejectIncompleteArguments(t *testing.T) {
	for _, command := range [][]string{
		{"control", "backup", "create", "-no-context"},
		{"control", "backup", "verify", "-no-context"},
		{"control", "backup", "restore", "-no-context"},
		{"control", "backup", "unknown", "-no-context"},
	} {
		if err := run(command, io.Discard, io.Discard); err == nil {
			t.Fatalf("invalid command accepted: %v", command)
		}
	}
}
