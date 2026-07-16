package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/agentrelease"
	"github.com/hardrails/steward/internal/dsse"
)

func TestAgentReleaseLimitationsRejectInvalidValuesWithoutMutation(t *testing.T) {
	limitations := agentReleaseLimitations{"Qualified only on linux amd64."}
	for _, value := range []string{
		" \t ",
		strings.Repeat("x", 513),
	} {
		before := append(agentReleaseLimitations(nil), limitations...)
		if err := limitations.Set(value); err == nil {
			t.Fatalf("invalid limitation %q was accepted", value)
		}
		if strings.Join(limitations, "\x00") != strings.Join(before, "\x00") {
			t.Fatalf("invalid limitation mutated values: %#v", limitations)
		}
	}

	for len(limitations) < 8 {
		if err := limitations.Set("Additional bounded limitation."); err != nil {
			t.Fatalf("fill limitations: %v", err)
		}
	}
	if err := limitations.Set("Ninth limitation."); err == nil {
		t.Fatal("ninth limitation was accepted")
	}
}

func TestAgentReleaseIssueReportsEachTrustedInputBoundary(t *testing.T) {
	fixture := newAgentReleaseCLIFixture(t)
	missing := filepath.Join(fixture.directory, "missing")
	corruptCapsule := filepath.Join(fixture.directory, "corrupt-capsule.json")
	if err := os.WriteFile(corruptCapsule, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name       string
		flag       string
		value      string
		wantError  string
		positional string
	}{
		{name: "private key", flag: "-key", value: missing, wantError: "read publisher private key"},
		{name: "capsule read", flag: "-capsule", value: missing, wantError: "read capsule envelope"},
		{name: "capsule verification", flag: "-capsule", value: corruptCapsule, wantError: "verify capsule publisher"},
		{name: "skill manifest", flag: "-skill-manifest", value: missing, wantError: "read skill manifest"},
		{name: "qualification evidence", flag: "-qualification-evidence", value: missing, wantError: "read qualification evidence"},
		{name: "archive inspection", flag: "-archive", value: missing, wantError: "inspect release archive"},
		{name: "unexpected positional argument", positional: "extra", wantError: "agent-release issue requires"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			arguments := append([]string(nil), fixture.issueArguments()...)
			if test.flag != "" {
				arguments[argumentValueIndex(t, arguments, test.flag)] = test.value
			}
			if test.positional != "" {
				arguments = append(arguments, test.positional)
			}
			err := run(arguments, &bytes.Buffer{}, &bytes.Buffer{})
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("error = %v, want containing %q", err, test.wantError)
			}
			if _, statErr := os.Stat(fixture.outputPath); !os.IsNotExist(statErr) {
				t.Fatalf("failed issue left output behind: %v", statErr)
			}
		})
	}

	if err := run(
		[]string{"agent-release", "issue", "-unknown"},
		&bytes.Buffer{}, &bytes.Buffer{},
	); err == nil {
		t.Fatal("unknown issue flag was accepted")
	}
}

func TestAgentReleaseVerifyReportsEachTrustBoundary(t *testing.T) {
	fixture := newAgentReleaseCLIFixture(t)
	if err := run(fixture.issueArguments(), &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatalf("issue fixture release: %v", err)
	}

	missing := filepath.Join(fixture.directory, "missing")
	invalidPublic := filepath.Join(fixture.directory, "invalid.public")
	if err := os.WriteFile(invalidPublic, []byte("not an Ed25519 public key"), 0o600); err != nil {
		t.Fatal(err)
	}
	invalidRelease := filepath.Join(fixture.directory, "invalid-release.json")
	if err := os.WriteFile(invalidRelease, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		flag      string
		value     string
		wantError string
	}{
		{name: "release read", flag: "-in", value: missing, wantError: "read agent release"},
		{name: "public key read", flag: "-public-key", value: missing, wantError: "read publisher public key"},
		{name: "public key shape", flag: "-public-key", value: invalidPublic, wantError: "public key is not base64 Ed25519"},
		{name: "release envelope", flag: "-in", value: invalidRelease, wantError: "invalid agent release"},
		{name: "publisher key ID", flag: "-key-id", value: "publisher-b", wantError: "invalid agent release"},
		{name: "archive read", flag: "-archive", value: missing, wantError: "verify release archive"},
	}
	base := []string{
		"agent-release", "verify",
		"-in", fixture.outputPath,
		"-public-key", fixture.publicKeyPath,
		"-key-id", "publisher-a",
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			arguments := append([]string(nil), base...)
			if test.flag == "-archive" {
				arguments = append(arguments, test.flag, test.value)
			} else {
				arguments[argumentValueIndex(t, arguments, test.flag)] = test.value
			}
			err := run(arguments, &bytes.Buffer{}, &bytes.Buffer{})
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("error = %v, want containing %q", err, test.wantError)
			}
		})
	}

	if err := run(
		[]string{"agent-release", "verify", "-unknown"},
		&bytes.Buffer{}, &bytes.Buffer{},
	); err == nil {
		t.Fatal("unknown verify flag was accepted")
	}
}

func TestOpenReleaseCapsuleRejectsMalformedSignedContent(t *testing.T) {
	fixture := newAgentReleaseCLIFixture(t)
	privateKey, err := readPrivateKey(fixture.privateKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := readPublicKey(fixture.publicKeyPath)
	if err != nil {
		t.Fatal(err)
	}

	invalidCapsule := fixture.capsule(t)
	invalidCapsule.Resources.MemoryBytes = 0
	wrongPublisher := fixture.capsule(t)
	wrongPublisher.PublisherKeyID = "publisher-b"

	tests := []struct {
		name      string
		raw       []byte
		wantError string
	}{
		{name: "invalid envelope", raw: []byte("{}"), wantError: "verify capsule publisher"},
		{
			name:      "invalid payload JSON",
			raw:       signAgentReleaseTestPayload(t, admission.CapsulePayloadType, []byte("{"), "publisher-a", privateKey),
			wantError: "decode capsule",
		},
		{
			name:      "invalid capsule contract",
			raw:       signAgentReleaseTestJSON(t, admission.CapsulePayloadType, invalidCapsule, "publisher-a", privateKey),
			wantError: "validate capsule",
		},
		{
			name:      "publisher field mismatch",
			raw:       signAgentReleaseTestJSON(t, admission.CapsulePayloadType, wrongPublisher, "publisher-a", privateKey),
			wantError: "capsule publisher key ID does not match",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := openReleaseCapsule(test.raw, "publisher-a", publicKey, fixture.now)
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("error = %v, want containing %q", err, test.wantError)
			}
		})
	}
}

func TestAgentReleaseEnvelopeTamperNeverProducesVerificationOutput(t *testing.T) {
	fixture := newAgentReleaseCLIFixture(t)
	if err := run(fixture.issueArguments(), &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatalf("issue fixture release: %v", err)
	}
	raw, err := os.ReadFile(fixture.outputPath)
	if err != nil {
		t.Fatal(err)
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatal(err)
	}
	envelope["payloadType"] = json.RawMessage(`"application/vnd.steward.agent-release.tampered+json"`)
	tampered, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	tamperedPath := filepath.Join(fixture.directory, "tampered-release.json")
	if err := os.WriteFile(tamperedPath, tampered, 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout bytes.Buffer
	err = run([]string{
		"agent-release", "verify",
		"-in", tamperedPath,
		"-public-key", fixture.publicKeyPath,
		"-key-id", "publisher-a",
	}, &stdout, &bytes.Buffer{})
	if !errors.Is(err, agentrelease.ErrInvalid) {
		t.Fatalf("tampered envelope error = %v, want ErrInvalid", err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("tampered envelope produced trusted output: %q", stdout.Bytes())
	}
}

func signAgentReleaseTestJSON(
	t *testing.T,
	payloadType string,
	value any,
	keyID string,
	privateKey ed25519.PrivateKey,
) []byte {
	t.Helper()
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return signAgentReleaseTestPayload(t, payloadType, payload, keyID, privateKey)
}

func signAgentReleaseTestPayload(
	t *testing.T,
	payloadType string,
	payload []byte,
	keyID string,
	privateKey ed25519.PrivateKey,
) []byte {
	t.Helper()
	envelope, err := dsse.Sign(payloadType, payload, keyID, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := dsse.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
