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
}

func TestSecretCommandRejectsIncompleteInvocation(t *testing.T) {
	for _, arguments := range [][]string{nil, {"check"}, {"materialization"}, {"materialization", "check"}} {
		if err := secretCommand(arguments, io.Discard); err == nil {
			t.Fatalf("secretCommand(%q) unexpectedly succeeded", arguments)
		}
	}
}
