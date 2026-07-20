package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/dsse"
)

func TestSiteInitCreatesAndVerifiesSeparatedAuthorityPackage(t *testing.T) {
	parent := t.TempDir()
	directory := filepath.Join(parent, "site-a")
	var initialized bytes.Buffer
	if err := siteCommand([]string{
		"init", directory,
		"-site-id", "site-a",
		"-tenant-id", "tenant-a",
		"-repository", "registry.internal/agents",
		"-service-id", "hermes-api",
		"-connector-id", "github-issues",
		"-control-server-names", "control.internal,10.0.0.5",
	}, &initialized); err != nil {
		t.Fatal(err)
	}
	var summary sitePackageSummary
	if err := json.Unmarshal(initialized.Bytes(), &summary); err != nil {
		t.Fatal(err)
	}
	if summary.Directory != directory || summary.SiteID != "site-a" || summary.TenantID != "tenant-a" ||
		summary.PolicyDigest == "" || summary.RootPublicSHA256 == "" || summary.FileCount != 19 {
		t.Fatalf("unexpected site summary: %#v", summary)
	}
	for _, check := range []struct {
		path string
		mode os.FileMode
	}{
		{"private/site-root.private.pem", 0o600},
		{"private/tenant-command.private.pem", 0o600},
		{"private/tenant-action.private.pem", 0o600},
		{"public/site-root.public", 0o644},
		{"public/site-policy.dsse.json", 0o644},
		{"public/control-ca.pem", 0o644},
		{"inventory.dsse.json", 0o644},
	} {
		info, err := os.Stat(filepath.Join(directory, check.path))
		if err != nil {
			t.Fatalf("stat %s: %v", check.path, err)
		}
		if info.Mode().Perm() != check.mode {
			t.Fatalf("%s mode=%v", check.path, info.Mode().Perm())
		}
	}

	root, err := readPublicKey(filepath.Join(directory, "public", "site-root.public"))
	if err != nil {
		t.Fatal(err)
	}
	policyRaw, err := os.ReadFile(filepath.Join(directory, "public", "site-policy.dsse.json"))
	if err != nil {
		t.Fatal(err)
	}
	payload, _, err := dsse.Verify(policyRaw, admission.PolicyPayloadType, map[string]ed25519.PublicKey{"site-root-1": root})
	if err != nil {
		t.Fatal(err)
	}
	var policy admission.SitePolicy
	if err := json.Unmarshal(payload, &policy); err != nil {
		t.Fatal(err)
	}
	if err := policy.Validate(); err != nil {
		t.Fatal(err)
	}
	if policy.Publishers[0].AllowedRepositories[0] != "registry.internal/agents" ||
		policy.Tenants[0].AuthorizedEffects == nil ||
		policy.Tenants[0].AuthorizedEffects.Mode != admission.AuthorizedEffectsRequired ||
		policy.Tenants[0].AuthorizedEffects.Keys[0].ConnectorIDs[0] != "github-issues" {
		t.Fatalf("unexpected generated policy: %#v", policy)
	}
	inventoryRaw, err := os.ReadFile(filepath.Join(directory, "inventory.dsse.json"))
	if err != nil {
		t.Fatal(err)
	}
	inventoryPayload, _, err := dsse.Verify(inventoryRaw, sitePackagePayloadType, map[string]ed25519.PublicKey{"site-root-1": root})
	if err != nil {
		t.Fatal(err)
	}
	var inventory sitePackageInventory
	if err := json.Unmarshal(inventoryPayload, &inventory); err != nil {
		t.Fatal(err)
	}
	wrongClassification := inventory
	wrongClassification.Files = append([]sitePackageFile(nil), inventory.Files...)
	wrongClassification.Files[0].Classification = "public-trust"
	if err := validateSiteInventory(wrongClassification); err == nil || !strings.Contains(err.Error(), "outside the package contract") {
		t.Fatalf("invalid custody classification error=%v", err)
	}
	missingRequired := inventory
	missingRequired.Files = append([]sitePackageFile(nil), inventory.Files[1:]...)
	if err := validateSiteInventory(missingRequired); err == nil || !strings.Contains(err.Error(), "missing required file") {
		t.Fatalf("missing required file error=%v", err)
	}

	var verified bytes.Buffer
	if err := siteCommand([]string{"verify", directory}, &verified); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(verified.String(), summary.PolicyDigest) {
		t.Fatalf("verification summary does not bind policy: %s", verified.String())
	}

	pinned := filepath.Join(parent, "pinned-root.public")
	if err := os.WriteFile(pinned, []byte(base64.StdEncoding.EncodeToString(root)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := siteCommand([]string{"verify", directory, "-site-root-public-key", pinned}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
}

func TestSiteVerifyRejectsMutationModeChangesAndUnsignedFiles(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(t *testing.T, directory string)
		want   string
	}{
		{
			name: "content",
			mutate: func(t *testing.T, directory string) {
				t.Helper()
				path := filepath.Join(directory, "public", "control-ca.pem")
				if err := os.WriteFile(path, []byte("replaced\n"), 0o644); err != nil {
					t.Fatal(err)
				}
			},
			want: "digest does not match",
		},
		{
			name: "mode",
			mutate: func(t *testing.T, directory string) {
				t.Helper()
				if err := os.Chmod(filepath.Join(directory, "private", "tenant-task.private.pem"), 0o644); err != nil {
					t.Fatal(err)
				}
			},
			want: "mode is 0644",
		},
		{
			name: "unsigned file",
			mutate: func(t *testing.T, directory string) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(directory, "public", "extra"), []byte("unexpected"), 0o644); err != nil {
					t.Fatal(err)
				}
			},
			want: "unsigned file",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := filepath.Join(t.TempDir(), "site")
			if err := siteCommand([]string{"init", directory}, &bytes.Buffer{}); err != nil {
				t.Fatal(err)
			}
			test.mutate(t, directory)
			err := siteCommand([]string{"verify", directory}, &bytes.Buffer{})
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("verify error=%v, want %q", err, test.want)
			}
		})
	}
}

func TestSiteInitDryRunAndValidationAreNonDestructive(t *testing.T) {
	parent := t.TempDir()
	directory := filepath.Join(parent, "planned")
	var output bytes.Buffer
	if err := siteCommand([]string{"init", directory, "-dry-run"}, &output); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(directory); !os.IsNotExist(err) {
		t.Fatalf("dry run created output: %v", err)
	}
	var summary sitePackageSummary
	if err := json.Unmarshal(output.Bytes(), &summary); err != nil || !summary.DryRun || summary.FileCount != 17 {
		t.Fatalf("dry-run summary=%#v err=%v", summary, err)
	}
	if err := siteCommand([]string{"init", directory, "-repository", "https://invalid/repository", "-dry-run"}, &bytes.Buffer{}); err == nil {
		t.Fatal("invalid repository was accepted")
	}
	if _, err := os.Stat(directory); !os.IsNotExist(err) {
		t.Fatalf("invalid init left output: %v", err)
	}
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := siteCommand([]string{"init", directory}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("existing directory error=%v", err)
	}
}

func TestSiteCommandRejectsIncompleteAndAmbiguousInputs(t *testing.T) {
	for _, test := range []struct {
		arguments []string
		want      string
	}{
		{arguments: nil, want: "site requires init, verify, or node"},
		{arguments: []string{"unknown"}, want: "site requires init, verify, or node"},
		{arguments: []string{"init"}, want: "exactly one output directory"},
		{arguments: []string{"init", "one", "two"}, want: "exactly one output directory"},
		{arguments: []string{"init", "site", "-site-id", "invalid site", "-dry-run"}, want: "identity is invalid"},
		{arguments: []string{"init", "site", "-authorized-effects", "disabled", "-dry-run"}, want: "required or optional"},
		{arguments: []string{"init", "site", "-authorized-effects", "optional", "-dry-run"}, want: "requires -connector-id"},
		{arguments: []string{"init", "site", "-control-server-names", "", "-dry-run"}, want: "requires 1 to 64"},
		{arguments: []string{"verify"}, want: "exactly one package directory"},
	} {
		err := siteCommand(test.arguments, &bytes.Buffer{})
		if err == nil || !strings.Contains(err.Error(), test.want) {
			t.Fatalf("site %v error=%v, want %q", test.arguments, err, test.want)
		}
	}
	if validSiteSHA256("sha256:"+strings.Repeat("z", 64)) || validSiteSHA256("sha256:abcd") {
		t.Fatal("malformed SHA-256 value was accepted")
	}
	if got := sitePositionalLast([]string{"-dry-run", "site"}); len(got) != 2 || got[0] != "-dry-run" {
		t.Fatalf("flag-first arguments changed: %v", got)
	}
}

func TestSiteInventoryRequiresCompleteActionKeyPair(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "site")
	if err := siteCommand([]string{"init", directory, "-connector-id", "issues"}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	root, err := readPublicKey(filepath.Join(directory, "public", "site-root.public"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(directory, "inventory.dsse.json"))
	if err != nil {
		t.Fatal(err)
	}
	payload, _, err := dsse.Verify(raw, sitePackagePayloadType, map[string]ed25519.PublicKey{"site-root-1": root})
	if err != nil {
		t.Fatal(err)
	}
	var inventory sitePackageInventory
	if err := json.Unmarshal(payload, &inventory); err != nil {
		t.Fatal(err)
	}
	for index, file := range inventory.Files {
		if file.Path == "public/tenant-action.public" {
			inventory.Files = append(inventory.Files[:index], inventory.Files[index+1:]...)
			break
		}
	}
	if err := validateSiteInventory(inventory); err == nil || !strings.Contains(err.Error(), "both tenant action key files") {
		t.Fatalf("incomplete action key pair error=%v", err)
	}
}
