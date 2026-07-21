package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/connectorledger"
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
	output.Reset()
	if err := run([]string{"capsule", "check-profile", "-in", payloadPath}, &output, &bytes.Buffer{}); err != nil ||
		!strings.Contains(output.String(), `"state_path":"/state"`) {
		t.Fatalf("profile check output=%s err=%v", output.String(), err)
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

	output.Reset()
	if err := run([]string{"evidence", "verify", "-in", logPath, "-public-key", publicPath, "-node-id", "node-a", "-json"}, &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	var verified struct {
		Valid bool               `json:"valid"`
		Head  evidenceHeadOutput `json:"head"`
	}
	if err := json.Unmarshal(output.Bytes(), &verified); err != nil {
		t.Fatal(err)
	}
	if !verified.Valid || verified.Head.Sequence != 1 || verified.Head.NodeID != "node-a" || len(verified.Head.ChainHash) != 71 {
		t.Fatalf("unexpected machine-readable verification: %#v", verified)
	}
	if err := run([]string{"evidence", "verify", "-in", logPath, "-public-key", publicPath, "-node-id", "node-a", "-expected-sequence", "1", "-expected-chain-hash", verified.Head.ChainHash}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"evidence", "verify", "-in", logPath, "-public-key", publicPath, "-node-id", "node-a", "-expected-sequence", "2"}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("evidence rollback expectation mismatch was accepted")
	}

	output.Reset()
	if err := run([]string{"evidence", "export", "-in", logPath, "-public-key", publicPath, "-node-id", "node-a", "-expected-chain-hash", verified.Head.ChainHash}, &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSpace(output.Bytes()), []byte("\n"))
	if len(lines) != 2 {
		t.Fatalf("expected receipt and head lines, got %q", output.String())
	}
	var receipt evidenceRecordOutput
	if err := json.Unmarshal(lines[0], &receipt); err != nil {
		t.Fatal(err)
	}
	if receipt.Kind != "receipt" || receipt.Event != "admission_allow" || receipt.Outcome != "allowed" || receipt.ChainHash != verified.Head.ChainHash {
		t.Fatalf("unexpected portable receipt: %#v", receipt)
	}
	if receipt.Format != evidence.ExportFormat || receipt.SignedFrame == "" {
		t.Fatalf("portable receipt does not retain its signed proof: %#v", receipt)
	}
	var exportedHead struct {
		Kind string             `json:"kind"`
		Head evidenceHeadOutput `json:"head"`
	}
	if err := json.Unmarshal(lines[1], &exportedHead); err != nil {
		t.Fatal(err)
	}
	if exportedHead.Kind != "head" || exportedHead.Head != verified.Head {
		t.Fatalf("unexpected portable head: %#v", exportedHead)
	}
	exportPath := filepath.Join(directory, "receipts.ndjson")
	if err := os.WriteFile(exportPath, output.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	if err := run([]string{"evidence", "verify", "-in", exportPath, "-public-key", publicPath, "-node-id", "node-a", "-json"}, &output, &bytes.Buffer{}); err != nil {
		t.Fatalf("verify portable export: %v", err)
	}
	var portableVerified struct {
		Valid bool               `json:"valid"`
		Head  evidenceHeadOutput `json:"head"`
	}
	if err := json.Unmarshal(output.Bytes(), &portableVerified); err != nil {
		t.Fatal(err)
	}
	if !portableVerified.Valid || portableVerified.Head != verified.Head {
		t.Fatalf("portable verification=%#v want head %#v", portableVerified, verified.Head)
	}
}

func TestConnectorEvidenceVerify(t *testing.T) {
	directory := t.TempDir()
	privatePath := filepath.Join(directory, "private.pem")
	publicPath := filepath.Join(directory, "public.pem")
	if err := run([]string{"keygen", "-private-out", privatePath, "-public-out", publicPath}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	privateKey, err := readPrivateKey(privatePath)
	if err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(directory, "connector-receipts.ndjson")
	log, err := connectorledger.Open(logPath, privateKey, "node-a/gateway", 2)
	if err != nil {
		t.Fatal(err)
	}
	taskDigest, _ := connectorledger.TaskDigest("task-0123456789abcdef")
	head, err := log.Begin(connectorledger.Event{
		Phase: connectorledger.Authorize, Outcome: connectorledger.Allowed, TenantID: "tenant-a",
		RuntimeRef: "executor-" + strings.Repeat("a", 64), CapsuleDigest: digest('b'), PolicyDigest: digest('c'),
		RoutePolicyDigest: digest('e'), Generation: 3, GrantID: "grant-" + strings.Repeat("d", 64), ConnectorID: "ticketing",
		OperationID: "create-ticket", TaskDigest: taskDigest, RequestBytes: 19,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}

	var output bytes.Buffer
	arguments := []string{"evidence", "verify", "-kind", "connector", "-in", logPath, "-public-key", publicPath,
		"-node-id", "node-a/gateway", "-epoch", "2", "-expected-sequence", "1", "-expected-chain-hash", head.ChainHash}
	if err := run(arguments, &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if got := output.String(); got != "valid connector evidence chain: node=node-a/gateway epoch=2 sequence=1\n" {
		t.Fatalf("output=%q", got)
	}
	output.Reset()
	arguments = append(arguments, "-json")
	if err := run(arguments, &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	var verified struct {
		Valid bool               `json:"valid"`
		Kind  string             `json:"kind"`
		Head  evidenceHeadOutput `json:"head"`
	}
	if err := json.Unmarshal(output.Bytes(), &verified); err != nil {
		t.Fatal(err)
	}
	if !verified.Valid || verified.Kind != "connector" || verified.Head.ChainHash != head.ChainHash || verified.Head.KeyID != head.KeyID {
		t.Fatalf("verified=%#v", verified)
	}
	if err := run([]string{"evidence", "export", "-kind", "connector", "-in", logPath, "-public-key", publicPath, "-node-id", "node-a/gateway"}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("connector evidence export was accepted")
	}
	if err := run([]string{"evidence", "verify", "-kind", "unknown", "-in", logPath, "-public-key", publicPath, "-node-id", "node-a/gateway"}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("unknown evidence kind was accepted")
	}
}

func TestEvidenceExportProofRejectsTamperSignatureTruncationAndRollback(t *testing.T) {
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
	for sequence, kind := range []evidence.EventType{evidence.AdmissionAllow, evidence.LifecycleStart} {
		outcome := evidence.Allowed
		if sequence == 1 {
			outcome = evidence.Committed
		}
		if _, err := log.Append(evidence.Event{
			Type: kind, TenantID: "tenant-a", RuntimeRef: "executor-a",
			CapsuleDigest: digest('a'), PolicyDigest: digest('b'), Generation: 1,
			GrantID: "workload", Outcome: outcome,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}

	var nativeResult bytes.Buffer
	if err := run([]string{"evidence", "verify", "-in", logPath, "-public-key", publicPath, "-node-id", "node-a", "-json"}, &nativeResult, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	var verified struct {
		Valid bool               `json:"valid"`
		Head  evidenceHeadOutput `json:"head"`
	}
	if err := json.Unmarshal(nativeResult.Bytes(), &verified); err != nil {
		t.Fatal(err)
	}

	var exported bytes.Buffer
	if err := run([]string{"evidence", "export", "-in", logPath, "-public-key", publicPath, "-node-id", "node-a"}, &exported, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSuffix(exported.Bytes(), []byte("\n")), []byte("\n"))
	if len(lines) != 3 {
		t.Fatalf("export lines=%d want two receipts and head: %q", len(lines), exported.String())
	}
	var first, second evidenceRecordOutput
	if err := json.Unmarshal(lines[0], &first); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(lines[1], &second); err != nil {
		t.Fatal(err)
	}
	type headLine struct {
		Format string             `json:"format"`
		Kind   string             `json:"kind"`
		Head   evidenceHeadOutput `json:"head"`
	}
	var final headLine
	if err := json.Unmarshal(lines[2], &final); err != nil {
		t.Fatal(err)
	}
	if first.Format != evidence.ExportFormat || second.Format != evidence.ExportFormat || final.Format != evidence.ExportFormat {
		t.Fatal("export format marker is missing")
	}

	writeInput := func(t *testing.T, name string, raw []byte) string {
		t.Helper()
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	verifyInput := func(path string, extra ...string) error {
		arguments := []string{"evidence", "verify", "-in", path, "-public-key", publicPath, "-node-id", "node-a"}
		arguments = append(arguments, extra...)
		return run(arguments, &bytes.Buffer{}, &bytes.Buffer{})
	}
	marshalLines := func(t *testing.T, values ...any) []byte {
		t.Helper()
		var output bytes.Buffer
		encoder := json.NewEncoder(&output)
		for _, value := range values {
			if err := encoder.Encode(value); err != nil {
				t.Fatal(err)
			}
		}
		return output.Bytes()
	}

	t.Run("signature", func(t *testing.T) {
		mutated := first
		frame, err := base64.StdEncoding.DecodeString(mutated.SignedFrame)
		if err != nil {
			t.Fatal(err)
		}
		frame[len(frame)-1] ^= 1
		mutated.SignedFrame = base64.StdEncoding.EncodeToString(frame)
		path := writeInput(t, "bad-signature.ndjson", marshalLines(t, mutated, second, final))
		if err := verifyInput(path); err == nil || !strings.Contains(err.Error(), "signature") {
			t.Fatalf("signature tamper error=%v", err)
		}
	})

	t.Run("readable projection", func(t *testing.T) {
		mutated := first
		mutated.TenantID = "tenant-b"
		path := writeInput(t, "bad-projection.ndjson", marshalLines(t, mutated, second, final))
		if err := verifyInput(path); err == nil || !strings.Contains(err.Error(), "does not match its signed frame") {
			t.Fatalf("projection tamper error=%v", err)
		}
	})

	t.Run("strict JSON", func(t *testing.T) {
		duplicate := strings.Replace(string(lines[0]), `{"format":`, `{"kind":"receipt","format":`, 1)
		raw := []byte(duplicate + "\n" + string(lines[1]) + "\n" + string(lines[2]) + "\n")
		path := writeInput(t, "duplicate.ndjson", raw)
		if err := verifyInput(path); err == nil || !strings.Contains(err.Error(), "duplicate JSON field") {
			t.Fatalf("duplicate-field error=%v", err)
		}
	})

	t.Run("byte truncation", func(t *testing.T) {
		raw := exported.Bytes()
		path := writeInput(t, "truncated.ndjson", raw[:len(raw)-1])
		if err := verifyInput(path); err == nil || !strings.Contains(err.Error(), "truncated") {
			t.Fatalf("truncation error=%v", err)
		}
	})

	t.Run("signed suffix removed", func(t *testing.T) {
		path := writeInput(t, "missing-suffix.ndjson", marshalLines(t, first, final))
		if err := verifyInput(path); err == nil || !strings.Contains(err.Error(), "final head") {
			t.Fatalf("suffix-removal error=%v", err)
		}
	})

	t.Run("external checkpoint detects a valid prefix", func(t *testing.T) {
		prefixHead := final
		prefixHead.Head.Sequence = first.Sequence
		prefixHead.Head.ChainHash = first.ChainHash
		path := writeInput(t, "valid-prefix.ndjson", marshalLines(t, first, prefixHead))
		if err := verifyInput(path); err != nil {
			t.Fatalf("a cryptographically valid prefix should require an external checkpoint to detect: %v", err)
		}
		err := verifyInput(path, "-expected-sequence", "2", "-expected-chain-hash", verified.Head.ChainHash)
		if err == nil || !strings.Contains(err.Error(), "rollback detected") {
			t.Fatalf("checkpoint error=%v", err)
		}
		err = verifyInput(path, "-expected-chain-hash", verified.Head.ChainHash)
		if err == nil || !strings.Contains(err.Error(), "checkpoint mismatch") {
			t.Fatalf("chain-hash checkpoint error=%v", err)
		}
	})
}

func TestCommandValidationRejectsIncompleteAndUnknownOperations(t *testing.T) {
	for _, arguments := range [][]string{
		{"unknown"},
		{"capsule"},
		{"capsule", "unknown"},
		{"policy"},
		{"keygen"},
		{"keygen", "-private-out", "private.pem", "-public-out", "public.key", "extra"},
		{"evidence"},
		{"evidence", "verify"},
		{"evidence", "export"},
		{"image"},
		{"image", "inspect"},
		{"image", "import"},
		{"image", "unknown"},
		{"capsule", "sign"},
		{"capsule", "verify"},
	} {
		if err := run(arguments, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
			t.Fatalf("arguments %#v unexpectedly accepted", arguments)
		}
	}
	if err := run(nil, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatalf("root help failed: %v", err)
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
