package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/controlstore"
	"github.com/hardrails/steward/internal/controlwitness"
	"github.com/hardrails/steward/internal/evidence"
)

func TestControlEvidenceCaptureLifecycleAndCanonicalExport(t *testing.T) {
	armed, sealed, export := stewardctlEvidenceCaptureFixtures(t)
	secret := "capture-site-admin-secret"
	requestNumber := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requestNumber++
		if request.Header.Get("Authorization") != "Bearer "+secret {
			t.Fatalf("authorization=%q", request.Header.Get("Authorization"))
		}
		writer.Header().Set("Content-Type", "application/json")
		switch requestNumber {
		case 1:
			if request.Method != http.MethodPost || request.URL.Path != "/v1/nodes/node-1/evidence/captures" {
				t.Fatalf("arm request=%s %s", request.Method, request.URL.Path)
			}
			var input struct {
				CaptureID             string `json:"capture_id"`
				RequestID             string `json:"request_id"`
				TenantID              string `json:"tenant_id"`
				RuntimeRef            string `json:"runtime_ref"`
				Generation            uint64 `json:"generation"`
				ActivationID          string `json:"activation_id"`
				ActivationBeginDigest string `json:"activation_begin_digest"`
				TTLSeconds            int64  `json:"ttl_seconds"`
			}
			if err := json.NewDecoder(request.Body).Decode(&input); err != nil ||
				input.CaptureID != armed.CaptureID || input.RequestID != armed.RequestID ||
				input.TenantID != armed.TenantID || input.RuntimeRef != armed.RuntimeRef ||
				input.Generation != armed.Generation || input.ActivationID != armed.ActivationID ||
				input.ActivationBeginDigest != armed.ActivationBeginDigest ||
				input.TTLSeconds != 60 {
				t.Fatalf("arm input=%+v err=%v", input, err)
			}
			writer.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(writer).Encode(armed)
		case 2:
			if request.Method != http.MethodGet || request.URL.Path != "/v1/nodes/node-1/evidence/captures/capture-1" {
				t.Fatalf("status request=%s %s", request.Method, request.URL.Path)
			}
			_ = json.NewEncoder(writer).Encode(armed)
		case 3:
			if request.Method != http.MethodPost || request.URL.Path != "/v1/nodes/node-1/evidence/captures/capture-1/seal" {
				t.Fatalf("seal request=%s %s", request.Method, request.URL.Path)
			}
			var input struct {
				CanaryCommandID string `json:"canary_command_id"`
			}
			if err := json.NewDecoder(request.Body).Decode(&input); err != nil || input.CanaryCommandID != sealed.CanaryCommandID {
				t.Fatalf("seal input=%+v err=%v", input, err)
			}
			_ = json.NewEncoder(writer).Encode(sealed)
		case 4:
			if request.Method != http.MethodGet || request.URL.Path != "/v1/nodes/node-1/evidence/captures/capture-1/export" {
				t.Fatalf("export request=%s %s", request.Method, request.URL.Path)
			}
			_ = json.NewEncoder(writer).Encode(export)
		case 5:
			if request.Method != http.MethodDelete || request.URL.Path != "/v1/nodes/node-1/evidence/captures/capture-1" {
				t.Fatalf("delete request=%s %s", request.Method, request.URL.Path)
			}
			writer.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected request %d", requestNumber)
		}
	}))
	defer server.Close()

	directory := t.TempDir()
	tokenPath := filepath.Join(directory, "site-admin.token")
	if err := os.WriteFile(tokenPath, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	common := []string{
		"-control-url", server.URL,
		"-token-file", tokenPath,
		"-node-id", armed.NodeID,
		"-capture-id", armed.CaptureID,
	}
	var allOutput bytes.Buffer
	runAndCapture := func(arguments []string) []byte {
		t.Helper()
		var output bytes.Buffer
		if err := run(arguments, &output, &bytes.Buffer{}); err != nil {
			t.Fatal(err)
		}
		allOutput.Write(output.Bytes())
		return output.Bytes()
	}

	armArguments := append([]string{"control", "evidence-capture", "arm"}, common...)
	armArguments = append(armArguments,
		"-request-id", armed.RequestID,
		"-tenant-id", armed.TenantID,
		"-runtime-ref", armed.RuntimeRef,
		"-generation", "9",
		"-activation-id", armed.ActivationID,
		"-activation-begin-digest", armed.ActivationBeginDigest,
		"-ttl", "1m",
	)
	var projected controlstore.EvidenceCapture
	if err := json.Unmarshal(runAndCapture(armArguments), &projected); err != nil || projected.State != controlstore.EvidenceCaptureArmed {
		t.Fatalf("arm output=%+v err=%v", projected, err)
	}

	statusArguments := append([]string{"control", "evidence-capture", "status"}, common...)
	if err := json.Unmarshal(runAndCapture(statusArguments), &projected); err != nil || projected.CaptureID != armed.CaptureID {
		t.Fatalf("status output=%+v err=%v", projected, err)
	}

	sealArguments := append([]string{"control", "evidence-capture", "seal"}, common...)
	sealArguments = append(sealArguments, "-canary-command-id", sealed.CanaryCommandID)
	if err := json.Unmarshal(runAndCapture(sealArguments), &projected); err != nil || projected.State != controlstore.EvidenceCaptureSealed {
		t.Fatalf("seal output=%+v err=%v", projected, err)
	}

	exportPath := filepath.Join(directory, "capture.json")
	exportArguments := append([]string{"control", "evidence-capture", "export"}, common...)
	exportArguments = append(exportArguments, "-out", exportPath)
	var exportOutput controlEvidenceCaptureExportOutput
	if err := json.Unmarshal(runAndCapture(exportArguments), &exportOutput); err != nil {
		t.Fatal(err)
	}
	if exportOutput.NodeID != armed.NodeID || exportOutput.CaptureID != armed.CaptureID ||
		exportOutput.Output != exportPath || exportOutput.FrameCount != export.Statement.FrameCount ||
		exportOutput.FramesDigest != export.Statement.FramesDigest ||
		exportOutput.WitnessPublicKeySHA256 != export.WitnessPublicKeySHA256 ||
		exportOutput.ActivationBeginDigest != export.Statement.ActivationBeginDigest ||
		exportOutput.ActivationCheckpointDigest != export.Statement.ActivationCheckpointDigest {
		t.Fatalf("export output=%+v", exportOutput)
	}
	canonical, err := json.Marshal(export)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(exportPath)
	if err != nil || !bytes.Equal(raw, append(canonical, '\n')) {
		t.Fatalf("export bytes changed: equal=%t err=%v", bytes.Equal(raw, append(canonical, '\n')), err)
	}
	decoded, err := controlprotocol.DecodeControllerEvidenceCaptureV1(raw)
	if err != nil || decoded.SignatureBase64 != export.SignatureBase64 {
		t.Fatalf("decode exported capture=%+v err=%v", decoded, err)
	}
	info, err := os.Stat(exportPath)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("export mode=%v err=%v", info, err)
	}

	deleteArguments := append([]string{"control", "evidence-capture", "delete"}, common...)
	var deleted controlEvidenceCaptureDeleteOutput
	if err := json.Unmarshal(runAndCapture(deleteArguments), &deleted); err != nil ||
		!deleted.Deleted || deleted.NodeID != armed.NodeID || deleted.CaptureID != armed.CaptureID {
		t.Fatalf("delete output=%+v err=%v", deleted, err)
	}
	if strings.Contains(allOutput.String(), secret) {
		t.Fatal("site-admin bearer was written to stdout")
	}
	if requestNumber != 5 {
		t.Fatalf("requests=%d, want 5", requestNumber)
	}
}

func TestControlEvidenceCaptureRejectsInvalidFlagsBeforeNetwork(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		requests++
	}))
	defer server.Close()
	tokenPath := filepath.Join(t.TempDir(), "site-admin.token")
	if err := os.WriteFile(tokenPath, []byte("secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	validArm := captureCLIArmArguments(server.URL, tokenPath)
	tests := map[string][]string{
		"missing ttl":        captureCLIRemoveFlag(validArm, "-ttl"),
		"subsecond ttl":      captureCLIReplaceFlag(validArm, "-ttl", "500ms"),
		"oversized ttl":      captureCLIReplaceFlag(validArm, "-ttl", "1h1s"),
		"invalid node":       captureCLIReplaceFlag(validArm, "-node-id", "node/1"),
		"invalid capture":    captureCLIReplaceFlag(validArm, "-capture-id", "-capture"),
		"invalid request":    captureCLIReplaceFlag(validArm, "-request-id", "request 1"),
		"invalid tenant":     captureCLIReplaceFlag(validArm, "-tenant-id", " tenant-1"),
		"invalid runtime":    captureCLIReplaceFlag(validArm, "-runtime-ref", "executor-not-a-digest"),
		"zero generation":    captureCLIReplaceFlag(validArm, "-generation", "0"),
		"invalid activation": captureCLIReplaceFlag(validArm, "-activation-id", "activation/1"),
		"positional input":   append(append([]string(nil), validArm...), "unexpected"),
		"invalid status": {
			"control", "evidence-capture", "status", "-control-url", server.URL,
			"-token-file", tokenPath, "-node-id", "node-1", "-capture-id", "capture/1",
		},
		"invalid canary": {
			"control", "evidence-capture", "seal", "-control-url", server.URL,
			"-token-file", tokenPath, "-node-id", "node-1", "-capture-id", "capture-1",
			"-canary-command-id", "canary/1",
		},
		"invalid output path": {
			"control", "evidence-capture", "export", "-control-url", server.URL,
			"-token-file", tokenPath, "-node-id", "node-1", "-capture-id", "capture-1",
			"-out", "../capture.json",
		},
		"delete positional input": {
			"control", "evidence-capture", "delete", "-control-url", server.URL,
			"-token-file", tokenPath, "-node-id", "node-1", "-capture-id", "capture-1", "unexpected",
		},
	}
	for name, arguments := range tests {
		t.Run(name, func(t *testing.T) {
			if err := run(arguments, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
				t.Fatal("invalid capture command was accepted")
			}
		})
	}
	if requests != 0 {
		t.Fatalf("invalid flags triggered %d control requests", requests)
	}
	if err := controlCommand([]string{"evidence-capture", "unknown"}, &bytes.Buffer{}); err == nil {
		t.Fatal("unknown evidence-capture action was accepted")
	}
	if err := controlUsageError(); err == nil || !strings.Contains(err.Error(), "evidence-capture arm|status|seal|export|verify|delete") {
		t.Fatalf("control usage error=%v", err)
	}
	var stderr bytes.Buffer
	if err := run(nil, &bytes.Buffer{}, &stderr); err == nil ||
		!strings.Contains(stderr.String(), "evidence|evidence-capture") {
		t.Fatalf("root usage=%q err=%v", stderr.String(), err)
	}
}

func TestControlEvidenceCaptureVerifyOfflineWithPinnedWitness(t *testing.T) {
	capture, witnessPublicPath := stewardctlVerifiableEvidenceCaptureFixture(t)
	directory := t.TempDir()
	input := filepath.Join(directory, "capture.json")
	raw, err := json.Marshal(capture)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(input, append(raw, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	if err := run([]string{
		"control", "evidence-capture", "verify",
		"-in", input, "-witness-public-key", witnessPublicPath,
	}, &stdout, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	var output controlEvidenceCaptureVerificationOutput
	if err := json.Unmarshal(stdout.Bytes(), &output); err != nil {
		t.Fatal(err)
	}
	if !output.Verified || output.CaptureID != capture.Statement.CaptureID ||
		output.NodeID != capture.Statement.NodeID || output.ActivationID != capture.Statement.ActivationID ||
		output.FinalSequence != capture.Statement.FinalHead.Sequence ||
		output.FinalChainHash != capture.Statement.FinalHead.ChainHash ||
		output.ActivationBeginSequence != capture.Statement.ActivationBeginSequence ||
		output.ActivationBeginDigest != capture.Statement.ActivationBeginDigest ||
		output.ActivationCheckpointSequence == 0 ||
		output.ActivationCheckpointDigest != capture.Statement.ActivationCheckpointDigest ||
		output.WitnessPublicKeySHA256 != capture.WitnessPublicKeySHA256 ||
		output.ExecutorReceiptPublicKeySHA256 != capture.Statement.FinalHead.PublicKeySHA256 {
		t.Fatalf("verification output=%+v", output)
	}
	if strings.Contains(stdout.String(), capture.WitnessPublicKeyBase64) ||
		strings.Contains(stdout.String(), capture.SignatureBase64) {
		t.Fatal("verification stdout exposed signed artifact material")
	}
}

func TestControlEvidenceCaptureVerifyRejectsHostileFilesAndArguments(t *testing.T) {
	capture, witnessPublicPath := stewardctlVerifiableEvidenceCaptureFixture(t)
	directory := t.TempDir()
	validRaw, err := json.Marshal(capture)
	if err != nil {
		t.Fatal(err)
	}
	write := func(name string, raw []byte, mode os.FileMode) string {
		t.Helper()
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, raw, mode); err != nil {
			t.Fatal(err)
		}
		return path
	}
	verify := func(input, public string) error {
		t.Helper()
		return run([]string{
			"control", "evidence-capture", "verify", "-in", input,
			"-witness-public-key", public,
		}, &bytes.Buffer{}, &bytes.Buffer{})
	}

	tampered := append([]byte(nil), validRaw...)
	needle := []byte(capture.SignatureBase64)
	index := bytes.Index(tampered, needle)
	if index < 0 {
		t.Fatal("fixture signature not found in JSON")
	}
	if tampered[index] == 'A' {
		tampered[index] = 'B'
	} else {
		tampered[index] = 'A'
	}
	if err := verify(write("tampered.json", tampered, 0o600), witnessPublicPath); err == nil {
		t.Fatal("tampered capture was accepted")
	}

	duplicate := bytes.Replace(validRaw, []byte(`{"payload_type":`), []byte(`{"payload_type":"duplicate","payload_type":`), 1)
	if bytes.Equal(duplicate, validRaw) {
		t.Fatal("duplicate-field mutation did not change JSON")
	}
	if err := verify(write("duplicate.json", duplicate, 0o600), witnessPublicPath); err == nil ||
		!strings.Contains(err.Error(), "duplicate JSON field") {
		t.Fatalf("duplicate-field error=%v", err)
	}

	worldReadable := write("world-readable.json", validRaw, 0o644)
	if err := verify(worldReadable, witnessPublicPath); err == nil || !strings.Contains(err.Error(), "permission policy") {
		t.Fatalf("world-readable input error=%v", err)
	}

	target := write("target.json", validRaw, 0o600)
	symlink := filepath.Join(directory, "capture-link.json")
	if err := os.Symlink(target, symlink); err != nil {
		t.Fatal(err)
	}
	if err := verify(symlink, witnessPublicPath); err == nil {
		t.Fatal("symlink capture input was accepted")
	}

	oversized := bytes.Repeat([]byte{'x'}, controlprotocol.MaxControllerEvidenceCaptureJSONBytes+1)
	if err := verify(write("oversized.json", oversized, 0o600), witnessPublicPath); err == nil ||
		!strings.Contains(err.Error(), "bounded") {
		t.Fatalf("oversized input error=%v", err)
	}

	wrongDirectory := filepath.Join(directory, "wrong-witness")
	if err := os.Mkdir(wrongDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	_, _, err = controlwitness.Initialize(
		filepath.Join(wrongDirectory, "private.pem"),
		filepath.Join(wrongDirectory, "public.pem"),
	)
	if err != nil {
		t.Fatal(err)
	}
	wrongPublic := filepath.Join(wrongDirectory, "public.pem")
	if err := verify(target, wrongPublic); err == nil || !strings.Contains(err.Error(), "trusted witness key") {
		t.Fatalf("wrong witness error=%v", err)
	}

	for _, arguments := range [][]string{
		{"evidence-capture", "verify"},
		{"evidence-capture", "verify", "-in", target},
		{"evidence-capture", "verify", "-witness-public-key", witnessPublicPath},
		{"evidence-capture", "verify", "-in", target, "-witness-public-key", witnessPublicPath, "extra"},
	} {
		if err := controlCommand(arguments, &bytes.Buffer{}); err == nil {
			t.Fatalf("incomplete verify command accepted: %#v", arguments)
		}
	}
}

func TestControlEvidenceCaptureExportRefusesExistingOutputAndAPIErrors(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		requests++
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusServiceUnavailable)
		_, _ = writer.Write([]byte(`{"error":"capture_capacity","message":"capture capacity is full"}`))
	}))
	defer server.Close()
	directory := t.TempDir()
	tokenPath := filepath.Join(directory, "site-admin.token")
	if err := os.WriteFile(tokenPath, []byte("secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	base := []string{
		"control", "evidence-capture", "export", "-control-url", server.URL,
		"-token-file", tokenPath, "-node-id", "node-1", "-capture-id", "capture-1",
	}
	occupied := filepath.Join(directory, "occupied.json")
	if err := os.WriteFile(occupied, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	arguments := append(append([]string(nil), base...), "-out", occupied)
	if err := run(arguments, &bytes.Buffer{}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("existing output error=%v", err)
	}
	if raw, err := os.ReadFile(occupied); err != nil || string(raw) != "keep" {
		t.Fatalf("occupied output=%q err=%v", raw, err)
	}

	target := filepath.Join(directory, "target.json")
	if err := os.WriteFile(target, []byte("target"), 0o600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(directory, "capture-link.json")
	if err := os.Symlink(target, symlink); err != nil {
		t.Fatal(err)
	}
	arguments = append(append([]string(nil), base...), "-out", symlink)
	if err := run(arguments, &bytes.Buffer{}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("symlink output error=%v", err)
	}
	if raw, err := os.ReadFile(target); err != nil || string(raw) != "target" {
		t.Fatalf("symlink target=%q err=%v", raw, err)
	}
	if requests != 0 {
		t.Fatalf("pre-existing output triggered %d control requests", requests)
	}

	failedPath := filepath.Join(directory, "failed.json")
	arguments = append(append([]string(nil), base...), "-out", failedPath)
	var stdout bytes.Buffer
	err := run(arguments, &stdout, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "capture_capacity") {
		t.Fatalf("API error=%v", err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("API error wrote stdout=%q", stdout.String())
	}
	if _, statErr := os.Lstat(failedPath); !os.IsNotExist(statErr) {
		t.Fatalf("API error created output: %v", statErr)
	}
	if requests != 1 {
		t.Fatalf("API error requests=%d, want 1", requests)
	}
}

func stewardctlEvidenceCaptureFixtures(t *testing.T) (
	controlstore.EvidenceCapture,
	controlstore.EvidenceCapture,
	controlprotocol.ControllerEvidenceCaptureV1,
) {
	t.Helper()
	receiptPublic, receiptPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	witnessPublic, witnessPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if receiptPublic.Equal(witnessPublic) {
		t.Fatal("test generated identical purpose-separated keys")
	}
	claim, err := controlprotocol.NewExecutorEvidenceIdentityClaimV1(
		"controller-1", "enrollment-1", "node-1", "node-1", 1, receiptPublic,
	)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := controlprotocol.SignExecutorEvidenceIdentityClaimV1(claim, receiptPrivate)
	if err != nil {
		t.Fatal(err)
	}
	frames := [][]byte{
		captureCLIFrame("signed-activation-begin-frame"),
		captureCLIFrame("signed-activation-checkpoint-frame"),
	}
	baseline := controlprotocol.ExecutorEvidenceHeadV1{
		Stream: controlprotocol.ExecutorEvidenceStreamV1, ReceiptNodeID: "node-1", ReceiptEpoch: 1,
		Sequence: 4, ChainHash: captureCLIDigest('1'), PublicKeySHA256: claim.PublicKeySHA256,
	}
	final := baseline
	final.Sequence += uint64(len(frames))
	final.ChainHash = captureCLIDigest('2')
	statement := controlprotocol.ControllerEvidenceCaptureStatementV1{
		ProtocolVersion:      controlprotocol.ControllerEvidenceCaptureProtocolV1,
		ControllerInstanceID: "controller-1", CaptureID: "capture-1", NodeID: "node-1",
		TenantID: "tenant-1", RuntimeRef: "executor-" + strings.Repeat("a", 64), Generation: 9,
		ActivationID: "activation-1", CanaryCommandID: "canary-command-1",
		ActivationBeginDigest: captureCLIDigest('6'), ActivationBeginSequence: baseline.Sequence + 1,
		ActivationCheckpointDigest: captureCLIDigest('3'), CapsuleDigest: captureCLIDigest('4'),
		PolicyDigest: captureCLIDigest('5'), IdentityProof: proof, BaselineHead: baseline, FinalHead: final,
		FrameCount: uint32(len(frames)), FramesDigest: controlprotocol.ControllerEvidenceCaptureFramesDigestV1(frames),
		ArmedAt: "2026-07-16T12:00:00Z", ObservedAt: "2026-07-16T12:01:00Z",
		SealedAt: "2026-07-16T12:02:00Z", ExportedAt: "2026-07-16T12:03:00Z",
	}
	export, err := controlprotocol.SignControllerEvidenceCaptureV1(statement, frames, witnessPrivate)
	if err != nil {
		t.Fatal(err)
	}
	armed := controlstore.EvidenceCapture{
		CaptureID: statement.CaptureID, RequestID: "request-1", NodeID: statement.NodeID,
		TenantID: statement.TenantID, RuntimeRef: statement.RuntimeRef, Generation: statement.Generation,
		ActivationID: statement.ActivationID, ActivationBeginDigest: statement.ActivationBeginDigest,
		State:        controlstore.EvidenceCaptureArmed,
		BaselineHead: baseline, FinalHead: baseline, ArmedAt: statement.ArmedAt,
		ExpiresAt: "2026-07-16T12:01:00Z",
	}
	sealed := armed
	sealed.State = controlstore.EvidenceCaptureSealed
	sealed.FinalHead = final
	sealed.FrameCount = len(frames)
	sealed.CapturedBytes = len(frames[0]) + len(frames[1])
	sealed.ActivationBeginSequence = statement.ActivationBeginSequence
	sealed.CapsuleDigest = statement.CapsuleDigest
	sealed.PolicyDigest = statement.PolicyDigest
	sealed.ActivationCheckpointDigest = statement.ActivationCheckpointDigest
	sealed.CanaryCommandID = statement.CanaryCommandID
	sealed.ObservedAt = statement.ObservedAt
	sealed.SealedAt = statement.SealedAt
	if err := armed.Validate(); err != nil {
		t.Fatalf("armed fixture: %v", err)
	}
	if err := sealed.Validate(); err != nil {
		t.Fatalf("sealed fixture: %v", err)
	}
	return armed, sealed, export
}

func stewardctlVerifiableEvidenceCaptureFixture(t *testing.T) (
	controlprotocol.ControllerEvidenceCaptureV1,
	string,
) {
	t.Helper()
	receiptPublic, receiptPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	runtimeRef := "executor-" + strings.Repeat("a", 64)
	checkpointDigest := captureCLIDigest('3')
	logPath := filepath.Join(t.TempDir(), "executor-evidence.log")
	log, err := evidence.Open(logPath, receiptPrivate, "node-1", 1)
	if err != nil {
		t.Fatal(err)
	}
	event := evidence.Event{
		Type: evidence.ActivationBegin, TenantID: "tenant-1", RuntimeRef: runtimeRef,
		CapsuleDigest: captureCLIDigest('4'), PolicyDigest: captureCLIDigest('5'),
		Generation: 9, GrantID: "activation-1", Outcome: evidence.Allowed,
		MetadataHash: captureCLIDigest('6'),
	}
	beginReceipt, err := log.AppendActivationBegin(event)
	if err != nil {
		t.Fatal(err)
	}
	event.Type = evidence.ActivationCheckpoint
	event.Outcome = evidence.Committed
	event.MetadataHash = checkpointDigest
	if _, err := log.AppendActivationCheckpoint(event); err != nil {
		t.Fatal(err)
	}
	delta, err := log.ExportDelta(evidence.Coordinate{})
	if err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	claim, err := controlprotocol.NewExecutorEvidenceIdentityClaimV1(
		"controller-1", "enrollment-1", "node-1", "node-1", 1, receiptPublic,
	)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := controlprotocol.SignExecutorEvidenceIdentityClaimV1(claim, receiptPrivate)
	if err != nil {
		t.Fatal(err)
	}
	var zeroHash [32]byte
	baseline := controlprotocol.ExecutorEvidenceHeadV1{
		Stream: controlprotocol.ExecutorEvidenceStreamV1, ReceiptNodeID: "node-1", ReceiptEpoch: 1,
		Sequence: 0, ChainHash: "sha256:" + hex.EncodeToString(zeroHash[:]),
		PublicKeySHA256: claim.PublicKeySHA256,
	}
	final := controlprotocol.ExecutorEvidenceHeadV1{
		Stream: controlprotocol.ExecutorEvidenceStreamV1, ReceiptNodeID: delta.Head.NodeID,
		ReceiptEpoch: delta.Head.Epoch, Sequence: delta.Head.Sequence,
		ChainHash:       "sha256:" + hex.EncodeToString(delta.Head.ChainHash[:]),
		PublicKeySHA256: claim.PublicKeySHA256,
	}
	witnessDirectory := filepath.Join(t.TempDir(), "witness")
	if err := os.Mkdir(witnessDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	witnessPrivatePath := filepath.Join(witnessDirectory, "witness.private.pem")
	witnessPublicPath := filepath.Join(witnessDirectory, "witness.public.pem")
	witnessPrivate, _, err := controlwitness.Initialize(witnessPrivatePath, witnessPublicPath)
	if err != nil {
		t.Fatal(err)
	}
	statement := controlprotocol.ControllerEvidenceCaptureStatementV1{
		ProtocolVersion:      controlprotocol.ControllerEvidenceCaptureProtocolV1,
		ControllerInstanceID: "controller-1", CaptureID: "capture-1", NodeID: "node-1",
		TenantID: event.TenantID, RuntimeRef: runtimeRef, Generation: event.Generation,
		ActivationID: event.GrantID, CanaryCommandID: "canary-command-1",
		ActivationBeginDigest: captureCLIDigest('6'), ActivationBeginSequence: beginReceipt.Sequence,
		ActivationCheckpointDigest: checkpointDigest, CapsuleDigest: event.CapsuleDigest,
		PolicyDigest: event.PolicyDigest, IdentityProof: proof, BaselineHead: baseline,
		FinalHead: final, FrameCount: uint32(len(delta.Frames)),
		FramesDigest: controlprotocol.ControllerEvidenceCaptureFramesDigestV1(delta.Frames),
		ArmedAt:      "2026-07-16T12:00:00Z", ObservedAt: "2026-07-16T12:01:00Z",
		SealedAt: "2026-07-16T12:02:00Z", ExportedAt: "2026-07-16T12:03:00Z",
	}
	capture, err := controlprotocol.SignControllerEvidenceCaptureV1(statement, delta.Frames, witnessPrivate)
	if err != nil {
		t.Fatal(err)
	}
	return capture, witnessPublicPath
}

func captureCLIArmArguments(controlURL, tokenPath string) []string {
	return []string{
		"control", "evidence-capture", "arm", "-control-url", controlURL, "-token-file", tokenPath,
		"-node-id", "node-1", "-capture-id", "capture-1", "-request-id", "request-1",
		"-tenant-id", "tenant-1", "-runtime-ref", "executor-" + strings.Repeat("a", 64),
		"-generation", "1", "-activation-id", "activation-1",
		"-activation-begin-digest", captureCLIDigest('6'), "-ttl", "1m",
	}
}

func captureCLIReplaceFlag(arguments []string, name, value string) []string {
	clone := append([]string(nil), arguments...)
	for index := 0; index < len(clone)-1; index++ {
		if clone[index] == name {
			clone[index+1] = value
			return clone
		}
	}
	return clone
}

func captureCLIRemoveFlag(arguments []string, name string) []string {
	clone := append([]string(nil), arguments...)
	for index := 0; index < len(clone)-1; index++ {
		if clone[index] == name {
			return append(clone[:index:index], clone[index+2:]...)
		}
	}
	return clone
}

func captureCLIFrame(payload string) []byte {
	frame := make([]byte, 4, 4+len(payload))
	binary.BigEndian.PutUint32(frame, uint32(len(payload)))
	return append(frame, payload...)
}

func captureCLIDigest(character byte) string {
	return "sha256:" + strings.Repeat(string(character), 64)
}
