package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hardrails/steward/internal/secretmaterial"
)

func TestSecretMaterializationCheck(t *testing.T) {
	root := filepath.Join(t.TempDir(), "secrets")
	tenantRoot := filepath.Join(root, "tenant-a")
	if err := os.MkdirAll(tenantRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	const secret = "inference-key-123456"
	if err := os.WriteFile(filepath.Join(tenantRoot, "inference-primary"), []byte(secret), 0o600); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(t.TempDir(), "manifest.json")
	manifest := secretmaterial.Manifest{SchemaVersion: secretmaterial.ManifestSchemaV1, Bindings: []secretmaterial.Binding{{
		TenantID: "tenant-a", SecretID: "inference-primary", Purpose: secretmaterial.PurposeInference,
	}}}
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	if err := secretCommand([]string{"materialization", "check", "-manifest", manifestPath, "-root", root}, &stdout); err != nil {
		t.Fatalf("secretCommand: %v", err)
	}
	if strings.Contains(stdout.String(), secret) || strings.Contains(stdout.String(), root) || !strings.Contains(stdout.String(), `"ready":true`) {
		t.Fatalf("unsafe or incomplete report: %s", stdout.String())
	}
	if err := secretCommand([]string{"materialization", "check", "-manifest", manifestPath, "-root", root, "-status-root", filepath.Join(t.TempDir(), "status")}, io.Discard); err == nil || !strings.Contains(err.Error(), "schema v1 does not support -status-root") {
		t.Fatalf("V1 check did not reject explicit status root: %v", err)
	}
}

func TestSecretCommandRejectsIncompleteInvocation(t *testing.T) {
	for _, arguments := range [][]string{nil, {"check"}, {"materialization"}, {"materialization", "check"}, {"materialization", "prepare"}, {"openbao", "compile"}} {
		if err := secretCommand(arguments, io.Discard); err == nil {
			t.Fatalf("secretCommand(%q) unexpectedly succeeded", arguments)
		}
	}
}

func TestSecretMaterializationPrepareAndEpochCheck(t *testing.T) {
	root := filepath.Join(t.TempDir(), "secrets")
	statusRoot := filepath.Join(t.TempDir(), "status")
	for _, path := range []string{root, statusRoot} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	manifest := secretmaterial.Manifest{SchemaVersion: secretmaterial.ManifestSchemaV2, Bindings: []secretmaterial.Binding{{
		TenantID: "tenant-a", SecretID: "inference-primary", Purpose: secretmaterial.PurposeInference, ExpectedEpoch: 7,
	}}}
	manifestPath := writeSecretJSON(t, "manifest.json", manifest)
	var stdout bytes.Buffer
	arguments := []string{"-manifest", manifestPath, "-root", root, "-status-root", statusRoot}
	if err := secretCommand(append([]string{"materialization", "prepare"}, arguments...), &stdout); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if !strings.Contains(stdout.String(), `"prepared":true`) {
		t.Fatalf("prepare output: %s", stdout.String())
	}
	if err := os.WriteFile(filepath.Join(root, "tenant-a", "inference-primary"), []byte("inference-key-123456"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(statusRoot, "tenant-a", "inference-primary.epoch"), []byte("7"), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	if err := secretCommand(append([]string{"materialization", "check"}, arguments...), &stdout); err != nil {
		t.Fatalf("check: %v", err)
	}
	if strings.Contains(stdout.String(), "inference-key-123456") || !strings.Contains(stdout.String(), `"observed_epoch":7`) || !strings.Contains(stdout.String(), `"ready":true`) {
		t.Fatalf("unsafe or incomplete epoch report: %s", stdout.String())
	}
}

func writeSecretJSON(t *testing.T, name string, value any) string {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
