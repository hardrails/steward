package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/evidence"
)

func TestKeygenCapsuleSignAndVerify(t *testing.T) {
	directory := t.TempDir()
	privateKey := filepath.Join(directory, "private.pem")
	publicKey := filepath.Join(directory, "public.key")
	var output bytes.Buffer
	if err := run([]string{"keygen", "-private-out", privateKey, "-public-out", publicKey, "-key-id", "publisher-1"}, &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	capsule := admission.ProfileCapsule{SchemaVersion: admission.SchemaV1, CapsuleID: "capsule-a", PublisherKeyID: "publisher-1", Profile: admission.ProfileRef{ID: "generic-v1", Version: "v1"}, Image: admission.ImageIdentity{Repository: "registry.example/agent", ManifestDigest: digest('a'), ConfigDigest: digest('b'), Platform: admission.Platform{OS: "linux", Architecture: "amd64"}}, Command: []string{"/agent"}, Resources: admission.ResourceLimits{MemoryBytes: 1, CPUMillis: 1, PIDs: 1}, State: admission.StateShape{SchemaVersion: "v1", Path: "/state"}}
	payload, err := json.Marshal(capsule)
	if err != nil {
		t.Fatal(err)
	}
	payloadPath := filepath.Join(directory, "capsule.json")
	if err := os.WriteFile(payloadPath, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	envelopePath := filepath.Join(directory, "capsule.dsse.json")
	if err := run([]string{"capsule", "sign", "-in", payloadPath, "-out", envelopePath, "-key", privateKey, "-key-id", "publisher-1"}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	if err := run([]string{"capsule", "verify", "-in", envelopePath, "-public-key", publicKey, "-key-id", "publisher-1"}, &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if string(bytes.TrimSpace(output.Bytes())) != string(payload) {
		t.Fatalf("unexpected verified payload: %s", output.String())
	}
}

func TestEvidenceVerify(t *testing.T) {
	directory := t.TempDir()
	privatePath := filepath.Join(directory, "private.pem")
	publicPath := filepath.Join(directory, "public.key")
	if err := run([]string{"keygen", "-private-out", privatePath, "-public-out", publicPath}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	privateKey, err := readPrivateKey(privatePath)
	if err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(directory, "evidence.bin")
	log, err := evidence.Open(logPath, privateKey, "node-a", 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(evidence.Event{
		Type: evidence.AdmissionAllow, TenantID: "tenant-a", RuntimeRef: "executor-a",
		CapsuleDigest: digest('a'), PolicyDigest: digest('b'), Generation: 1,
		GrantID: "workload", Outcome: evidence.Allowed,
	}); err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := run([]string{"evidence", "verify", "-in", logPath, "-public-key", publicPath, "-node-id", "node-a"}, &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if got := output.String(); got != "valid evidence chain: node=node-a epoch=1 sequence=1\n" {
		t.Fatalf("output=%q", got)
	}
}

func TestCommandValidationRejectsIncompleteAndUnknownOperations(t *testing.T) {
	for _, arguments := range [][]string{
		nil,
		{"unknown"},
		{"capsule"},
		{"capsule", "unknown"},
		{"policy"},
		{"keygen"},
		{"keygen", "-private-out", "private.pem", "-public-out", "public.key", "extra"},
		{"evidence"},
		{"evidence", "verify"},
		{"capsule", "sign"},
		{"capsule", "verify"},
	} {
		if err := run(arguments, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
			t.Fatalf("arguments %#v unexpectedly accepted", arguments)
		}
	}
	if err := validatePayload([]byte(`{}`), "unsupported"); err == nil {
		t.Fatal("unsupported payload type accepted")
	}
	if err := validatePayload([]byte(`not-json`), admission.CapsulePayloadType); err == nil {
		t.Fatal("malformed capsule accepted")
	}
	if err := validatePayload([]byte(`not-json`), admission.PolicyPayloadType); err == nil {
		t.Fatal("malformed policy accepted")
	}
}

func digest(char rune) string { return "sha256:" + string(bytes.Repeat([]byte(string(char)), 64)) }
