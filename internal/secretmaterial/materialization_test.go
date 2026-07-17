package secretmaterial

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckReturnsSecretFreeReadiness(t *testing.T) {
	root := materializationRoot(t)
	first := installSecret(t, root, "tenant-a", "inference-primary", "inference-key-123456")
	second := installSecret(t, root, "tenant-b", "tickets", "connector-key-654321")
	manifest := Manifest{SchemaVersion: ManifestSchemaV1, Bindings: []Binding{
		{TenantID: "tenant-a", SecretID: "inference-primary", Purpose: PurposeInference},
		{TenantID: "tenant-b", SecretID: "tickets", Purpose: PurposeConnector},
	}}

	report, err := Check(root, manifest)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !report.Ready || report.SchemaVersion != ReportSchemaV1 || len(report.Bindings) != 2 {
		t.Fatalf("unexpected report: %#v", report)
	}
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		"inference-key-123456", "connector-key-654321", root, first, second,
		`"bytes"`, `"epoch"`, "digest", "hash",
	} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("report contains forbidden secret-derived or path value %q: %s", forbidden, raw)
		}
	}
}

func TestManifestValidationRejectsAmbiguousBindings(t *testing.T) {
	valid := Binding{TenantID: "tenant-a", SecretID: "inference-primary", Purpose: PurposeInference}
	tests := []struct {
		name     string
		manifest Manifest
	}{
		{"schema", Manifest{SchemaVersion: "steward.secret-materialization.v2", Bindings: []Binding{valid}}},
		{"empty", Manifest{SchemaVersion: ManifestSchemaV1}},
		{"tenant path", Manifest{SchemaVersion: ManifestSchemaV1, Bindings: []Binding{{TenantID: "../tenant", SecretID: valid.SecretID, Purpose: valid.Purpose}}}},
		{"secret path", Manifest{SchemaVersion: ManifestSchemaV1, Bindings: []Binding{{TenantID: valid.TenantID, SecretID: "a/b", Purpose: valid.Purpose}}}},
		{"purpose", Manifest{SchemaVersion: ManifestSchemaV1, Bindings: []Binding{{TenantID: valid.TenantID, SecretID: valid.SecretID, Purpose: "workload"}}}},
		{"duplicate", Manifest{SchemaVersion: ManifestSchemaV1, Bindings: []Binding{valid, valid}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.manifest.Validate(); err == nil {
				t.Fatal("Validate accepted an invalid manifest")
			}
		})
	}
}

func TestLoadManifestIsStrictAndRejectsWritableMetadata(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "manifest.json")
	valid := `{"schema_version":"steward.secret-materialization.v1","bindings":[{"tenant_id":"tenant-a","secret_id":"inference","purpose":"inference"}]}`
	if err := os.WriteFile(path, []byte(valid), 0o600); err != nil {
		t.Fatal(err)
	}
	manifest, err := LoadManifest(path)
	if err != nil || len(manifest.Bindings) != 1 {
		t.Fatalf("LoadManifest valid: manifest=%#v err=%v", manifest, err)
	}
	if err := os.WriteFile(path, []byte(strings.TrimSuffix(valid, "}")+`,"unknown":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadManifest(path); err == nil || !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("LoadManifest unknown field error = %v", err)
	}
	if err := os.WriteFile(path, []byte(valid), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o622); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadManifest(path); err == nil {
		t.Fatal("LoadManifest accepted group-writable metadata")
	}
}

func TestCheckRejectsUnsafeMaterializationShapes(t *testing.T) {
	validManifest := func(tenant, secret string) Manifest {
		return Manifest{SchemaVersion: ManifestSchemaV1, Bindings: []Binding{{
			TenantID: tenant, SecretID: secret, Purpose: PurposeInference,
		}}}
	}
	t.Run("relative root", func(t *testing.T) {
		if _, err := Check("relative", validManifest("tenant-a", "key")); err == nil {
			t.Fatal("Check accepted a relative root")
		}
	})
	t.Run("root permissions", func(t *testing.T) {
		root := materializationRoot(t)
		if err := os.Chmod(root, 0o750); err != nil {
			t.Fatal(err)
		}
		if _, err := Check(root, validManifest("tenant-a", "key")); err == nil {
			t.Fatal("Check accepted a group-accessible root")
		}
	})
	t.Run("tenant permissions", func(t *testing.T) {
		root := materializationRoot(t)
		installSecret(t, root, "tenant-a", "key", "abcdefghijkl")
		if err := os.Chmod(filepath.Join(root, "tenant-a"), 0o750); err != nil {
			t.Fatal(err)
		}
		if _, err := Check(root, validManifest("tenant-a", "key")); err == nil {
			t.Fatal("Check accepted a group-accessible tenant directory")
		}
	})
	t.Run("secret permissions", func(t *testing.T) {
		root := materializationRoot(t)
		path := installSecret(t, root, "tenant-a", "key", "abcdefghijkl")
		if err := os.Chmod(path, 0o640); err != nil {
			t.Fatal(err)
		}
		if _, err := Check(root, validManifest("tenant-a", "key")); err == nil {
			t.Fatal("Check accepted a group-readable secret")
		}
	})
	t.Run("secret symlink", func(t *testing.T) {
		root := materializationRoot(t)
		original := installSecret(t, root, "tenant-a", "original", "abcdefghijkl")
		if err := os.Symlink(filepath.Base(original), filepath.Join(root, "tenant-a", "key")); err != nil {
			t.Fatal(err)
		}
		if _, err := Check(root, validManifest("tenant-a", "key")); err == nil {
			t.Fatal("Check accepted a secret symlink")
		}
	})
	t.Run("hard link", func(t *testing.T) {
		root := materializationRoot(t)
		original := installSecret(t, root, "tenant-a", "original", "abcdefghijkl")
		if err := os.Link(original, filepath.Join(root, "tenant-a", "key")); err != nil {
			t.Fatal(err)
		}
		if _, err := Check(root, validManifest("tenant-a", "key")); err == nil {
			t.Fatal("Check accepted a multiply linked secret")
		}
	})
	t.Run("newline", func(t *testing.T) {
		root := materializationRoot(t)
		installSecret(t, root, "tenant-a", "key", "abcdefghijkl\n")
		if _, err := Check(root, validManifest("tenant-a", "key")); err == nil || !strings.Contains(err.Error(), "visible ASCII") {
			t.Fatalf("Check newline error = %v", err)
		}
	})
	t.Run("too short", func(t *testing.T) {
		root := materializationRoot(t)
		installSecret(t, root, "tenant-a", "key", "short")
		if _, err := Check(root, validManifest("tenant-a", "key")); err == nil {
			t.Fatal("Check accepted a short secret")
		}
	})
}

func materializationRoot(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "materialized")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	return root
}

func installSecret(t *testing.T, root, tenant, secret, value string) string {
	t.Helper()
	directory := filepath.Join(root, tenant)
	if err := os.Mkdir(directory, 0o700); err != nil && !os.IsExist(err) {
		t.Fatal(err)
	}
	path := filepath.Join(directory, secret)
	if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
