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

func TestExecutorCommandDelegationIssueVerifyAndEmbed(t *testing.T) {
	directory := t.TempDir()
	tenantPublic, tenantPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	controllerPublic, controllerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tenantPrivatePath := filepath.Join(directory, "tenant.pem")
	tenantPublicPath := filepath.Join(directory, "tenant.pub")
	controllerPrivatePath := filepath.Join(directory, "controller.pem")
	controllerPublicPath := filepath.Join(directory, "controller.pub")
	writeAgentPrivateKey(t, tenantPrivatePath, tenantPrivate)
	writeAgentPrivateKey(t, controllerPrivatePath, controllerPrivate)
	for path, public := range map[string]ed25519.PublicKey{
		tenantPublicPath: tenantPublic, controllerPublicPath: controllerPublic,
	} {
		if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(public)+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	instancesPath := filepath.Join(directory, "instances.json")
	templatePath := filepath.Join(directory, "admission.json")
	delegationPath := filepath.Join(directory, "delegation.dsse.json")
	payloadPath := filepath.Join(directory, "payload.json")
	commandPath := filepath.Join(directory, "command.dsse.json")
	if err := os.WriteFile(instancesPath, []byte(`{"instances":[
  {"instance_id":"agent-1","lineage_id":"lineage-1","min_instance_generation":1,"max_instance_generation":2}
]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(templatePath, []byte(`{
  "capsule_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "resources":{"memory_bytes":536870912,"cpu_millis":500,"pids":64},
  "capabilities":{"state":false,"inference":false,"service":false,"egress":false,"connector":false},
  "state_disposition":"none"
}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(payloadPath, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	previousNow := timeNow
	timeNow = func() time.Time { return time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC) }
	t.Cleanup(func() { timeNow = previousNow })

	var issued bytes.Buffer
	if err := run([]string{
		"executor-command", "delegation", "issue",
		"-delegation-id", "deployment-1", "-tenant-id", "tenant-a",
		"-controller-public-key", controllerPublicPath, "-controller-key-id", "controller-1",
		"-operations", "start,admit", "-node-ids", "node-2,node-1",
		"-instances", instancesPath, "-admission-template", templatePath,
		"-key", tenantPrivatePath, "-key-id", "tenant-command", "-out", delegationPath,
	}, &issued, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	delegationRaw, err := os.ReadFile(delegationPath)
	if err != nil || strings.TrimSpace(issued.String()) != dsse.Digest(delegationRaw) {
		t.Fatalf("delegation issue = %q, %v", issued.String(), err)
	}
	var verified bytes.Buffer
	if err := run([]string{
		"executor-command", "delegation", "verify", "-in", delegationPath,
		"-public-key", tenantPublicPath, "-key-id", "tenant-command",
	}, &verified, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	var delegation admission.CommandDelegation
	if err := json.Unmarshal(verified.Bytes(), &delegation); err != nil ||
		strings.Join(delegation.Operations, ",") != "admit,start" ||
		strings.Join(delegation.NodeIDs, ",") != "node-1,node-2" ||
		len(delegation.Instances) != 1 || delegation.Admission == nil {
		t.Fatalf("verified delegation = %#v, %v", delegation, err)
	}

	if err := run([]string{
		"executor-command", "issue", "-command-id", "start-agent-1",
		"-tenant-id", "tenant-a", "-node-id", "node-1", "-instance-id", "agent-1",
		"-kind", "start", "-instance-generation", "1", "-sequence", "1",
		"-payload", payloadPath, "-delegation", delegationPath,
		"-key", controllerPrivatePath, "-key-id", "controller-1", "-out", commandPath,
	}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	commandRaw, err := os.ReadFile(commandPath)
	if err != nil {
		t.Fatal(err)
	}
	commandPayload, _, err := dsse.Verify(commandRaw, admission.CommandPayloadType,
		map[string]ed25519.PublicKey{"controller-1": controllerPublic})
	if err != nil {
		t.Fatal(err)
	}
	var command admission.CommandStatement
	if err := dsse.DecodeStrictInto(commandPayload, maxArtifactBytes, &command); err != nil ||
		command.AuthorizationContextDigest != dsse.Digest(delegationRaw) ||
		command.DelegationDSSEBase64 != base64.StdEncoding.EncodeToString(delegationRaw) {
		t.Fatalf("embedded delegation command = %#v, %v", command, err)
	}
}
