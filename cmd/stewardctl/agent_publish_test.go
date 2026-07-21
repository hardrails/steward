package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/agentapp"
	"github.com/hardrails/steward/internal/dsse"
)

func TestAgentPublishJoinsBundleArchiveAndSignedSiteAuthority(t *testing.T) {
	directory := t.TempDir()
	archive, manifestDigest, configDigest, _ := writeImageImportArchive(t, directory)
	siteDirectory := filepath.Join(directory, "site")
	if err := siteCommand([]string{
		"init", siteDirectory, "-site-id", "site-a", "-tenant-id", "tenant-a",
		"-repository", "registry.example/agent",
	}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	bundlePath := filepath.Join(directory, "agent.bundle.json")
	bundle := publishedAgentBundle(t, "hermes", "registry.example/agent@"+manifestDigest)
	raw, err := agentapp.MarshalCanonical(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bundlePath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	capsulePath := filepath.Join(directory, "capsule.dsse.json")
	var output bytes.Buffer
	if err := agentCommand([]string{
		"publish", siteDirectory, "-bundle", bundlePath, "-archive", archive, "-out", capsulePath,
	}, &output); err != nil {
		t.Fatal(err)
	}
	var summary agentPublishSummary
	if err := json.Unmarshal(output.Bytes(), &summary); err != nil {
		t.Fatal(err)
	}
	if summary.AgentName != "workspace-auditor" || summary.Runtime != "hermes" || summary.Capsule != capsulePath ||
		summary.CapsuleDigest == "" || summary.ManifestDigest != manifestDigest || summary.ConfigDigest != configDigest ||
		summary.Platform != "linux/amd64/v1" {
		t.Fatalf("publish summary = %+v", summary)
	}
	capsuleRaw, err := os.ReadFile(capsulePath)
	if err != nil {
		t.Fatal(err)
	}
	verifiedSite, err := verifySitePackage(siteDirectory, "")
	if err != nil {
		t.Fatal(err)
	}
	policyRaw, err := os.ReadFile(filepath.Join(siteDirectory, "public", "site-policy.dsse.json"))
	if err != nil {
		t.Fatal(err)
	}
	verified, err := admission.VerifyCapsuleForImport(
		capsuleRaw, policyRaw, map[string]ed25519.PublicKey{"site-root-1": verifiedSite.rootKey},
		timeNow().UTC(), admission.DefaultProfiles(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Capsule.Profile.ID != "hermes-v1" || verified.Capsule.Image.ManifestDigest != manifestDigest ||
		verified.Capsule.Image.ConfigDigest != configDigest || !verified.Capsule.Capabilities.State ||
		!verified.Capsule.Capabilities.Inference || !verified.Capsule.Capabilities.Service ||
		verified.Capsule.Service.ID != "hermes-api" || verified.Capsule.Service.Port != 8766 ||
		strings.Join(verified.Capsule.Command, " ") != "serve" || verified.Capsule.State.Path != "/opt/data" {
		t.Fatalf("verified capsule = %+v", verified.Capsule)
	}
	if summary.CapsuleDigest != dsse.Digest(capsuleRaw) {
		t.Fatalf("summary digest = %q, want %q", summary.CapsuleDigest, dsse.Digest(capsuleRaw))
	}
}

func TestAgentPublishRejectsBundleArchiveIdentityMismatch(t *testing.T) {
	directory := t.TempDir()
	archive, _, _, _ := writeImageImportArchive(t, directory)
	siteDirectory := filepath.Join(directory, "site")
	if err := siteCommand([]string{
		"init", siteDirectory, "-repository", "registry.example/agent",
	}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	bundle := publishedAgentBundle(t, "hermes", "registry.example/agent@sha256:"+strings.Repeat("f", 64))
	bundleRaw, err := agentapp.MarshalCanonical(bundle)
	if err != nil {
		t.Fatal(err)
	}
	bundlePath := filepath.Join(directory, "agent.bundle.json")
	if err := os.WriteFile(bundlePath, bundleRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	err = agentCommand([]string{
		"publish", siteDirectory, "-bundle", bundlePath, "-archive", archive,
		"-out", filepath.Join(directory, "capsule.dsse.json"),
	}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "does not match the inspected archive") {
		t.Fatalf("identity mismatch error = %v", err)
	}
}

func publishedAgentBundle(t *testing.T, runtime, image string) agentapp.Bundle {
	t.Helper()
	contract := map[string]string{"hermes": "steward.hermes-agent.v1"}[runtime]
	definition := agentapp.Definition{
		Schema: agentapp.DefinitionSchema, Name: "workspace-auditor",
		Runtime: agentapp.Runtime{Engine: runtime, Image: image, AdapterContract: contract},
		Model:   agentapp.Model{Route: "local/default"}, Skills: []string{"workspace-audit"},
		Resources: agentapp.Resources{CPUMillis: 1000, MemoryMiB: 1024, DiskMiB: 2048, PIDs: 256},
		Placement: agentapp.Placement{Architectures: []string{"amd64"}, Isolation: "hardened"},
		State:     agentapp.State{Persistent: true}, Lifetime: agentapp.Lifetime{Mode: "service"},
	}
	bundle, err := agentapp.Build(definition, nil)
	if err != nil {
		t.Fatal(err)
	}
	return bundle
}
