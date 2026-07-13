package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/executoruplink"
)

func TestExecutorCommandIssueAndVerify(t *testing.T) {
	directory := t.TempDir()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	privatePath := filepath.Join(directory, "command.pem")
	publicPath := filepath.Join(directory, "command.pub")
	payloadPath := filepath.Join(directory, "payload.json")
	commandPath := filepath.Join(directory, "command.dsse.json")
	if err := os.WriteFile(privatePath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(publicPath, []byte(base64.StdEncoding.EncodeToString(public)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(payloadPath, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	previousNow := timeNow
	timeNow = func() time.Time { return time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC) }
	t.Cleanup(func() { timeNow = previousNow })

	arguments := []string{
		"executor-command", "issue", "-command-id", "start-agent-1", "-tenant-id", "tenant-a",
		"-node-id", "node-1", "-instance-id", "agent-1", "-kind", "start",
		"-instance-generation", "3", "-sequence", "4", "-payload", payloadPath,
		"-key", privatePath, "-key-id", "tenant-command", "-out", commandPath,
	}
	var issued bytes.Buffer
	if err := run(arguments, &issued, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	envelopeRaw, err := os.ReadFile(commandPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(issued.String()) != dsse.Digest(envelopeRaw) {
		t.Fatalf("issue output=%q", issued.String())
	}
	payload, _, err := dsse.Verify(envelopeRaw, admission.CommandPayloadType,
		map[string]ed25519.PublicKey{"tenant-command": public})
	if err != nil {
		t.Fatal(err)
	}
	var statement admission.CommandStatement
	if err := dsse.DecodeStrictInto(payload, maxArtifactBytes, &statement); err != nil {
		t.Fatal(err)
	}
	wantRef, err := executoruplink.RuntimeRefV2("tenant-a", "node-1", "agent-1")
	if err != nil {
		t.Fatal(err)
	}
	if statement.RuntimeRef != wantRef || statement.CommandSequence != 4 || statement.InstanceGeneration != 3 ||
		statement.Kind != "start" || string(statement.Payload) != `{}` {
		t.Fatalf("statement=%#v", statement)
	}
	var verified bytes.Buffer
	if err := run([]string{"executor-command", "verify", "-in", commandPath, "-public-key", publicPath,
		"-key-id", "tenant-command"}, &verified, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	var projected admission.CommandStatement
	if err := json.Unmarshal(verified.Bytes(), &projected); err != nil || projected.CommandID != statement.CommandID {
		t.Fatalf("verified=%s error=%v", verified.Bytes(), err)
	}
}

func TestExecutorCommandIssueRejectsUnsafeInputs(t *testing.T) {
	if err := executorCommand(nil, &bytes.Buffer{}); err == nil {
		t.Fatal("missing executor command action accepted")
	}
	if err := executorCommand([]string{"unknown"}, &bytes.Buffer{}); err == nil {
		t.Fatal("unknown executor command action accepted")
	}
	if err := issueExecutorCommand(nil, &bytes.Buffer{}); err == nil {
		t.Fatal("incomplete executor command accepted")
	}
	if err := validateArbitraryCommandPayload([]byte(`{"a":1,"a":2}`)); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate payload error=%v", err)
	}
	if err := validateArbitraryCommandPayload([]byte(`{} {}`)); err == nil {
		t.Fatal("trailing payload accepted")
	}
}
