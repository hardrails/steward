package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMigrationScopeIsExactBoundedAndOwnerOnly(t *testing.T) {
	valid := `{"volume_id":"volume","tenant_id":"tenant","lineage_id":"lineage","generation":1}`
	for _, scenario := range []string{"valid", "unknown", "duplicate", "missing", "loose", "symlink", "oversized"} {
		t.Run(scenario, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "scope.json")
			raw := valid
			switch scenario {
			case "unknown":
				raw = strings.TrimSuffix(raw, "}") + `,"path":"/other"}`
			case "duplicate":
				raw = strings.TrimSuffix(raw, "}") + `,"generation":2}`
			case "missing":
				raw = `{"volume_id":"volume"}`
			case "oversized":
				raw += strings.Repeat(" ", maxConfigSize)
			}
			if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
				t.Fatal(err)
			}
			if scenario == "loose" {
				if err := os.Chmod(path, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "symlink" {
				link := path + ".link"
				if err := os.Symlink(path, link); err != nil {
					t.Fatal(err)
				}
				path = link
			}
			scope, err := readMigrationScope(path)
			if (err == nil) != (scenario == "valid") {
				t.Fatalf("scope=%+v error=%v", scope, err)
			}
		})
	}
	for _, path := range []string{"relative", "/", "/tmp/../scope"} {
		if _, err := readMigrationScope(path); err == nil {
			t.Fatalf("unsafe scope path accepted: %s", path)
		}
	}
}

func TestMigrationCannotCombineWithOnlineOrScratchChecks(t *testing.T) {
	for _, flag := range []string{"-check-config", "-check-packaged-config", "-check-backend"} {
		var stdout, stderr bytes.Buffer
		status := run(context.Background(), []string{"-migrate-volume-access", "/scope.json", flag}, &stdout, &stderr)
		if status != 2 || !strings.Contains(stderr.String(), "mutually exclusive") {
			t.Fatalf("status=%d stderr=%s", status, stderr.String())
		}
	}
}
