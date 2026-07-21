package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/agentapp"
	"github.com/hardrails/steward/internal/dsse"
)

func TestAgentAuthorizeBuildsExactFiniteControllerDelegation(t *testing.T) {
	directory := t.TempDir()
	archive, manifestDigest, _, _ := writeImageImportArchive(t, directory)
	siteDirectory := filepath.Join(directory, "site")
	if err := siteCommand([]string{
		"init", siteDirectory, "-site-id", "site-a", "-tenant-id", "tenant-a",
		"-repository", "registry.example/agent",
	}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	bundle := publishedAgentBundle(t, "hermes", "registry.example/agent@"+manifestDigest)
	bundleRaw, err := agentapp.MarshalCanonical(bundle)
	if err != nil {
		t.Fatal(err)
	}
	bundlePath := filepath.Join(directory, "agent.bundle.json")
	if err := os.WriteFile(bundlePath, bundleRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	capsulePath := filepath.Join(directory, "capsule.dsse.json")
	if err := agentPublish([]string{
		siteDirectory, "-bundle", bundlePath, "-archive", archive, "-out", capsulePath,
	}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	controller, err := newSiteKey()
	if err != nil {
		t.Fatal(err)
	}
	controllerPath := filepath.Join(directory, "controller.public.pem")
	if err := os.WriteFile(controllerPath, encodeSitePublicKey(controller.public), 0o644); err != nil {
		t.Fatal(err)
	}
	delegationPath := filepath.Join(directory, "delegation.dsse.json")
	arguments := []string{
		siteDirectory, "-bundle", bundlePath, "-capsule", capsulePath,
		"-controller-public-key", controllerPath, "-node-ids", "node-b,node-a",
		"-out", delegationPath,
	}
	var output bytes.Buffer
	if err := agentAuthorize(arguments, &output); err != nil {
		t.Fatal(err)
	}
	if err := agentAuthorize(arguments, &bytes.Buffer{}); err == nil {
		t.Fatal("existing controller delegation was replaced")
	}
	var summary agentAuthorizeSummary
	if err := json.Unmarshal(output.Bytes(), &summary); err != nil {
		t.Fatal(err)
	}
	if summary.AgentName != "workspace-auditor" || summary.Deployment != "workspace-auditor-deployment" ||
		summary.TenantID != "tenant-a" || !slices.Equal(summary.NodeIDs, []string{"node-a", "node-b"}) ||
		summary.InstanceID != "workspace-auditor" || summary.LineageID == "" || summary.Generation != 1 ||
		summary.ClaimGeneration != 1 || summary.Delegation != delegationPath || summary.DelegationDigest == "" ||
		summary.ExpiresAt == "" {
		t.Fatalf("authorization summary = %+v", summary)
	}
	raw, err := os.ReadFile(delegationPath)
	if err != nil {
		t.Fatal(err)
	}
	verifiedSite, err := verifySitePackage(siteDirectory, "")
	if err != nil {
		t.Fatal(err)
	}
	verified, err := admission.VerifyCommandDelegation(raw, verifiedSite.policy, timeNow().UTC())
	if err != nil {
		t.Fatal(err)
	}
	statement := verified.Statement
	if !slices.Equal(statement.Operations, []string{"admit", "destroy", "renew", "start", "stop"}) ||
		!slices.Equal(statement.NodeIDs, []string{"node-a", "node-b"}) || len(statement.Instances) != 1 ||
		statement.Instances[0].LineageID != summary.LineageID || statement.Admission == nil ||
		statement.Admission.CapsuleDigest == "" || statement.Admission.Resources.MemoryBytes != 1024<<20 ||
		!statement.Admission.Capabilities.State || !statement.Admission.Capabilities.Inference ||
		!statement.Admission.Capabilities.Service || statement.Admission.ServiceID != "hermes-api" ||
		statement.Admission.InferenceRouteID != "local" || statement.Admission.ModelAlias != "default" ||
		statement.Admission.Placement == nil || statement.Admission.Placement.RequiredIsolation != "gvisor" {
		t.Fatalf("verified delegation = %+v", statement)
	}
	decodedController, err := base64PublicKey(statement.ControllerPublicKey)
	if err != nil || !slices.Equal(decodedController, controller.public) {
		t.Fatalf("controller binding = %x, %v", decodedController, err)
	}
	if summary.DelegationDigest != dsse.Digest(raw) {
		t.Fatalf("summary digest = %q, want %q", summary.DelegationDigest, dsse.Digest(raw))
	}
}

func base64PublicKey(value string) (ed25519.PublicKey, error) {
	decoded, err := decodePublicKey([]byte(value))
	if err != nil {
		return nil, err
	}
	return decoded, nil
}
