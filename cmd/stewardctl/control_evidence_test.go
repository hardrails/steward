package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/controlwitness"
	"github.com/hardrails/steward/internal/securefile"
)

func TestControlEvidenceStatusExportAndOfflineVerify(t *testing.T) {
	inspection, export, witnessPublicPath := stewardctlEvidenceFixtures(t)
	inspectionRaw, err := json.Marshal(inspection)
	if err != nil {
		t.Fatal(err)
	}
	exportRaw, err := json.Marshal(export)
	if err != nil {
		t.Fatal(err)
	}
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests++
		if request.Method != http.MethodGet || request.Header.Get("Authorization") != "Bearer admin-secret" {
			t.Fatalf("request method=%q authorization=%q", request.Method, request.Header.Get("Authorization"))
		}
		writer.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/v1/nodes/node-1/evidence":
			_, _ = writer.Write(inspectionRaw)
		case "/v1/nodes/node-1/evidence/export":
			_, _ = writer.Write(exportRaw)
		default:
			t.Fatalf("path=%q", request.URL.Path)
		}
	}))
	defer server.Close()
	directory := t.TempDir()
	tokenPath := filepath.Join(directory, "site-admin.token")
	if err := os.WriteFile(tokenPath, []byte("admin-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	common := []string{"-control-url", server.URL, "-token-file", tokenPath, "-node-id", "node-1"}
	var output bytes.Buffer
	if err := run(append([]string{"control", "evidence", "status"}, common...), &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	decodedInspection, err := controlprotocol.DecodeExecutorEvidenceInspectionV1(output.Bytes())
	if err != nil || decodedInspection.Status.Head == nil || decodedInspection.Status.Head.Sequence != 7 {
		t.Fatalf("status output=%s err=%v", output.Bytes(), err)
	}

	exportPath := filepath.Join(directory, "evidence-export.json")
	output.Reset()
	exportArguments := append([]string{"control", "evidence", "export"}, common...)
	exportArguments = append(exportArguments, "-out", exportPath)
	if err := run(exportArguments, &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(output.String()) != exportPath {
		t.Fatalf("export output=%q", output.String())
	}
	exportedRaw, err := securefile.Read(exportPath, controlprotocol.MaxExecutorEvidenceJSONBytes, securefile.OwnerOnly)
	if err != nil {
		t.Fatal(err)
	}
	decodedExport, err := controlprotocol.DecodeExecutorEvidenceExportV1(exportedRaw)
	if err != nil || decodedExport.SignatureBase64 != export.SignatureBase64 {
		t.Fatalf("export=%+v err=%v", decodedExport, err)
	}
	if info, err := os.Stat(exportPath); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("export mode=%v err=%v", info, err)
	}

	output.Reset()
	if err := run([]string{
		"control", "evidence", "verify", "-in", exportPath, "-witness-public-key", witnessPublicPath,
	}, &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	var verified controlEvidenceVerification
	if err := json.Unmarshal(output.Bytes(), &verified); err != nil {
		t.Fatal(err)
	}
	if !verified.Verified || verified.ControllerInstanceID != "controller-1" || verified.ControlNodeID != "node-1" ||
		verified.State != controlprotocol.ExecutorEvidenceStatusCurrent || verified.Sequence == nil || *verified.Sequence != 7 ||
		verified.WitnessPublicKeySHA256 != export.WitnessPublicKeySHA256 {
		t.Fatalf("verification output=%+v", verified)
	}
	if requests != 2 {
		t.Fatalf("online request count=%d, want 2; offline verify reached the controller", requests)
	}
}

func TestControlEvidenceExportNeverOverwritesOrFollowsOutputSymlinks(t *testing.T) {
	_, export, _ := stewardctlEvidenceFixtures(t)
	exportRaw, err := json.Marshal(export)
	if err != nil {
		t.Fatal(err)
	}
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		requests++
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write(exportRaw)
	}))
	defer server.Close()
	directory := t.TempDir()
	tokenPath := filepath.Join(directory, "site-admin.token")
	if err := os.WriteFile(tokenPath, []byte("admin-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	base := []string{
		"-control-url", server.URL, "-token-file", tokenPath, "-node-id", "node-1",
	}
	occupied := filepath.Join(directory, "occupied.json")
	if err := os.WriteFile(occupied, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	arguments := append([]string{"control", "evidence", "export"}, base...)
	arguments = append(arguments, "-out", occupied)
	if err := run(arguments, &bytes.Buffer{}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("existing output error=%v", err)
	}
	raw, err := os.ReadFile(occupied)
	if err != nil || string(raw) != "keep" {
		t.Fatalf("occupied output=%q err=%v", raw, err)
	}

	target := filepath.Join(directory, "target.json")
	if err := os.WriteFile(target, []byte("target"), 0o600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(directory, "export-link.json")
	if err := os.Symlink(target, symlink); err != nil {
		t.Fatal(err)
	}
	arguments = append([]string{"control", "evidence", "export"}, base...)
	arguments = append(arguments, "-out", symlink)
	if err := run(arguments, &bytes.Buffer{}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("symlink output error=%v", err)
	}
	raw, err = os.ReadFile(target)
	if err != nil || string(raw) != "target" {
		t.Fatalf("symlink target=%q err=%v", raw, err)
	}
	if requests != 0 {
		t.Fatalf("pre-existing output triggered %d controller requests", requests)
	}
}

func TestControlEvidenceVerifyRejectsWrongKeyTamperAndAmbiguousInput(t *testing.T) {
	_, export, witnessPublicPath := stewardctlEvidenceFixtures(t)
	directory := t.TempDir()
	validRaw, err := json.Marshal(export)
	if err != nil {
		t.Fatal(err)
	}
	validPath := filepath.Join(directory, "valid.json")
	if err := os.WriteFile(validPath, validRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	wrongDirectory := filepath.Join(directory, "wrong")
	if err := os.Mkdir(wrongDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	wrongPublicPath := filepath.Join(wrongDirectory, "witness.public.pem")
	if _, _, err := controlwitness.Initialize(filepath.Join(wrongDirectory, "witness.private.pem"), wrongPublicPath); err != nil {
		t.Fatal(err)
	}
	if err := controlEvidenceVerify([]string{
		"-in", validPath, "-witness-public-key", wrongPublicPath,
	}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "trusted witness key") {
		t.Fatalf("wrong-key error=%v", err)
	}

	tamperedRaw := bytes.Replace(validRaw, []byte(`"sequence":7`), []byte(`"sequence":6`), 1)
	if bytes.Equal(tamperedRaw, validRaw) {
		t.Fatal("test export did not contain the expected sequence")
	}
	tamperedPath := filepath.Join(directory, "tampered.json")
	if err := os.WriteFile(tamperedPath, tamperedRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := controlEvidenceVerify([]string{
		"-in", tamperedPath, "-witness-public-key", witnessPublicPath,
	}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("tamper error=%v", err)
	}

	duplicateRaw := strings.Replace(string(validRaw), `{"payload_type":`, `{"payload_type":"duplicate","payload_type":`, 1)
	duplicatePath := filepath.Join(directory, "duplicate.json")
	if err := os.WriteFile(duplicatePath, []byte(duplicateRaw), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := controlEvidenceVerify([]string{
		"-in", duplicatePath, "-witness-public-key", witnessPublicPath,
	}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "duplicate JSON field") {
		t.Fatalf("ambiguous input error=%v", err)
	}
}

func TestControlEvidenceUsageRequiresExactInputs(t *testing.T) {
	for _, arguments := range [][]string{
		{"evidence", "status"},
		{"evidence", "export", "-node-id", "node-1"},
		{"evidence", "verify", "-in", "/tmp/export.json"},
		{"evidence", "unknown"},
	} {
		if err := controlCommand(arguments, &bytes.Buffer{}); err == nil {
			t.Fatalf("incomplete command accepted: %#v", arguments)
		}
	}
	var stderr bytes.Buffer
	if err := run(nil, &bytes.Buffer{}, &stderr); err == nil ||
		!strings.Contains(stderr.String(), "control pki|tenant|operator|enrollment|node|command|evidence") {
		t.Fatalf("root usage=%q err=%v", stderr.String(), err)
	}
	if err := controlUsageError(); err == nil || !strings.Contains(err.Error(), "evidence status|export|verify") {
		t.Fatalf("control usage error=%v", err)
	}
}

func stewardctlEvidenceFixtures(t *testing.T) (controlprotocol.ExecutorEvidenceInspectionV1, controlprotocol.ExecutorEvidenceExportV1, string) {
	t.Helper()
	receiptPublic, receiptPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
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
	head := controlprotocol.ExecutorEvidenceHeadV1{
		Stream: controlprotocol.ExecutorEvidenceStreamV1, ReceiptNodeID: "node-1", ReceiptEpoch: 1,
		Sequence: 7, ChainHash: "sha256:" + strings.Repeat("a", 64), PublicKeySHA256: claim.PublicKeySHA256,
	}
	status := controlprotocol.ExecutorEvidenceStatusV1{
		State: controlprotocol.ExecutorEvidenceStatusCurrent, Head: &head, WitnessedAt: "2026-07-16T01:02:03Z",
	}
	inspection := controlprotocol.ExecutorEvidenceInspectionV1{
		ProtocolVersion: controlprotocol.ExecutorEvidenceProtocolV1, ControllerInstanceID: "controller-1",
		ControlNodeID: "node-1", IdentityProof: &proof, Status: status,
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
	export, err := controlprotocol.SignExecutorEvidenceExportV1(controlprotocol.ExecutorEvidenceExportStatementV1{
		ProtocolVersion: controlprotocol.ExecutorEvidenceProtocolV1, ControllerInstanceID: "controller-1",
		ControlNodeID: "node-1", IdentityProof: proof, Status: status, ExportedAt: "2026-07-16T01:03:00Z",
	}, witnessPrivate)
	if err != nil {
		t.Fatal(err)
	}
	return inspection, export, witnessPublicPath
}
