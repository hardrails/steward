package controlprotocol

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"
)

func TestExecutorEvidenceEnrollmentProofBindsCompleteIdentity(t *testing.T) {
	public, private := executorEvidenceTestKey(t)
	claim, err := NewExecutorEvidenceIdentityClaimV1(
		"controller-a", "enrollment-a", "node-a", "node-a", 7, public,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(claim.PublicKeySHA256) != len("sha256:")+64 {
		t.Fatalf("public key digest %q is not full SHA-256", claim.PublicKeySHA256)
	}
	proof, err := SignExecutorEvidenceIdentityClaimV1(claim, private)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := VerifyExecutorEvidenceIdentityProofV1(proof)
	if err != nil || !verified.Equal(public) {
		t.Fatalf("verify enrollment proof key=%x err=%v", verified, err)
	}
	raw, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeExecutorEvidenceIdentityProofV1(raw)
	if err != nil || decoded.Claim.PublicKeySHA256 != claim.PublicKeySHA256 {
		t.Fatalf("decode enrollment proof=%+v err=%v", decoded, err)
	}

	mutations := map[string]func(*ExecutorEvidenceIdentityProofV1){
		"controller":   func(value *ExecutorEvidenceIdentityProofV1) { value.Claim.ControllerInstanceID = "controller-b" },
		"enrollment":   func(value *ExecutorEvidenceIdentityProofV1) { value.Claim.EnrollmentID = "enrollment-b" },
		"control node": func(value *ExecutorEvidenceIdentityProofV1) { value.Claim.ControlNodeID = "node-b" },
		"stream":       func(value *ExecutorEvidenceIdentityProofV1) { value.Claim.Stream = "gateway" },
		"receipt node": func(value *ExecutorEvidenceIdentityProofV1) { value.Claim.ReceiptNodeID = "node-b" },
		"epoch":        func(value *ExecutorEvidenceIdentityProofV1) { value.Claim.ReceiptEpoch++ },
		"public key": func(value *ExecutorEvidenceIdentityProofV1) {
			other, _ := executorEvidenceTestKey(t)
			value.Claim.PublicKeyBase64 = base64.StdEncoding.EncodeToString(other)
			value.Claim.PublicKeySHA256 = ExecutorEvidencePublicKeySHA256(other)
		},
		"digest": func(value *ExecutorEvidenceIdentityProofV1) {
			value.Claim.PublicKeySHA256 = evidenceTestDigest("b")
		},
		"signature": func(value *ExecutorEvidenceIdentityProofV1) {
			value.SignatureBase64 = mutateEvidenceSignature(t, value.SignatureBase64)
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			candidate := proof
			mutate(&candidate)
			if _, err := VerifyExecutorEvidenceIdentityProofV1(candidate); err == nil {
				t.Fatal("mutated enrollment proof was accepted")
			}
		})
	}

	noncanonical := proof
	noncanonical.Claim.PublicKeyBase64 = base64.RawStdEncoding.EncodeToString(public)
	if err := noncanonical.Validate(); err == nil {
		t.Fatal("non-canonical public key base64 was accepted")
	}
	_, otherPrivate := executorEvidenceTestKey(t)
	if _, err := SignExecutorEvidenceIdentityClaimV1(claim, otherPrivate); err == nil {
		t.Fatal("a non-matching private key signed the enrollment claim")
	}
}

func TestExecutorEvidenceHeadProofIsChallengeBound(t *testing.T) {
	public, private := executorEvidenceTestKey(t)
	challenge := evidenceTestChallenge(t, 1)
	claim, err := NewExecutorEvidenceHeadClaimV1(
		"controller-a", "node-a", "node-a", 7, 11, evidenceTestDigest("a"), challenge, public,
	)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := SignExecutorEvidenceHeadClaimV1(claim, private)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyExecutorEvidenceHeadProofV1(proof, public); err != nil {
		t.Fatal(err)
	}
	if proof.Claim.Head().Sequence != 11 {
		t.Fatalf("head projection=%+v", proof.Claim.Head())
	}

	mutations := map[string]func(*ExecutorEvidenceHeadProofV1){
		"controller":   func(value *ExecutorEvidenceHeadProofV1) { value.Claim.ControllerInstanceID = "controller-b" },
		"control node": func(value *ExecutorEvidenceHeadProofV1) { value.Claim.ControlNodeID = "node-b" },
		"receipt node": func(value *ExecutorEvidenceHeadProofV1) { value.Claim.ReceiptNodeID = "node-b" },
		"epoch":        func(value *ExecutorEvidenceHeadProofV1) { value.Claim.ReceiptEpoch++ },
		"sequence":     func(value *ExecutorEvidenceHeadProofV1) { value.Claim.Sequence++ },
		"chain hash":   func(value *ExecutorEvidenceHeadProofV1) { value.Claim.ChainHash = evidenceTestDigest("b") },
		"key digest":   func(value *ExecutorEvidenceHeadProofV1) { value.Claim.PublicKeySHA256 = evidenceTestDigest("b") },
		"challenge":    func(value *ExecutorEvidenceHeadProofV1) { value.Claim.Challenge = evidenceTestChallenge(t, 2) },
		"signature": func(value *ExecutorEvidenceHeadProofV1) {
			value.SignatureBase64 = mutateEvidenceSignature(t, value.SignatureBase64)
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			candidate := proof
			mutate(&candidate)
			if err := VerifyExecutorEvidenceHeadProofV1(candidate, public); err == nil {
				t.Fatal("mutated head proof was accepted")
			}
		})
	}
	otherPublic, _ := executorEvidenceTestKey(t)
	if err := VerifyExecutorEvidenceHeadProofV1(proof, otherPublic); err == nil {
		t.Fatal("head proof verified with a different key")
	}

	identityClaim, err := NewExecutorEvidenceIdentityClaimV1(
		"controller-a", "enrollment-a", "node-a", "node-a", 7, public,
	)
	if err != nil {
		t.Fatal(err)
	}
	enrollmentStatement, err := ExecutorEvidenceIdentityProofStatementV1(identityClaim)
	if err != nil {
		t.Fatal(err)
	}
	headStatement, err := ExecutorEvidenceHeadProofStatementV1(claim)
	if err != nil {
		t.Fatal(err)
	}
	if string(enrollmentStatement) == string(headStatement) {
		t.Fatal("enrollment and head proofs share a signing statement")
	}
}

func TestExecutorEvidenceReportLimitsAndStrictDecode(t *testing.T) {
	public, private := executorEvidenceTestKey(t)
	headClaim, err := NewExecutorEvidenceHeadClaimV1(
		"controller-a", "node-a", "node-a", 1, 1, evidenceTestDigest("a"), evidenceTestChallenge(t, 1), public,
	)
	if err != nil {
		t.Fatal(err)
	}
	headProof, err := SignExecutorEvidenceHeadClaimV1(headClaim, private)
	if err != nil {
		t.Fatal(err)
	}
	frame := evidenceTestFrame(32)
	report := ExecutorEvidenceReportV1{
		ProtocolVersion: ExecutorEvidenceProtocolV1, HeadProof: headProof,
		SignedFramesBase64: []string{base64.StdEncoding.EncodeToString(frame)},
	}
	if err := report.Validate(); err != nil {
		t.Fatal(err)
	}
	decodedFrames, err := report.DecodeFrames()
	if err != nil || len(decodedFrames) != 1 || string(decodedFrames[0]) != string(frame) {
		t.Fatalf("decoded frames=%d err=%v", len(decodedFrames), err)
	}

	noExtension := report
	noExtension.SignedFramesBase64 = nil
	if err := noExtension.Validate(); err != nil {
		t.Fatalf("challenge-bound no-extension report is invalid: %v", err)
	}

	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeExecutorEvidenceReportV1(raw); err != nil {
		t.Fatal(err)
	}
	for name, candidate := range map[string][]byte{
		"duplicate": []byte(strings.Replace(string(raw), `"protocol_version":1`, `"protocol_version":1,"protocol_version":1`, 1)),
		"unknown":   []byte(strings.TrimSuffix(string(raw), "}") + `,"unexpected":true}`),
		"trailing":  append(append([]byte(nil), raw...), []byte(` {}`)...),
		"oversized": append(append([]byte(nil), raw...), make([]byte, MaxExecutorEvidenceJSONBytes)...),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeExecutorEvidenceReportV1(candidate); err == nil {
				t.Fatal("ambiguous or oversized report was accepted")
			}
		})
	}

	tooMany := report
	tooMany.SignedFramesBase64 = make([]string, MaxExecutorEvidenceFrames+1)
	for index := range tooMany.SignedFramesBase64 {
		tooMany.SignedFramesBase64[index] = base64.StdEncoding.EncodeToString(frame)
	}
	if err := tooMany.Validate(); err == nil {
		t.Fatal("too many frames were accepted")
	}

	tooLarge := report
	tooLarge.SignedFramesBase64 = make([]string, 11)
	maxFrame := evidenceTestFrame(64 << 10)
	for index := range tooLarge.SignedFramesBase64 {
		tooLarge.SignedFramesBase64[index] = base64.StdEncoding.EncodeToString(maxFrame)
	}
	if err := tooLarge.Validate(); err == nil {
		t.Fatal("decoded frame bytes over the aggregate limit were accepted")
	}

	badPrefix := append([]byte(nil), frame...)
	binary.BigEndian.PutUint32(badPrefix[:4], uint32(len(badPrefix)))
	badFrame := report
	badFrame.SignedFramesBase64 = []string{base64.StdEncoding.EncodeToString(badPrefix)}
	if err := badFrame.Validate(); err == nil {
		t.Fatal("frame with a mismatched length prefix was accepted")
	}

	noncanonical := report
	paddedFrame := evidenceTestFrame(31)
	noncanonical.SignedFramesBase64 = []string{base64.RawStdEncoding.EncodeToString(paddedFrame)}
	if err := noncanonical.Validate(); err == nil {
		t.Fatal("non-canonical frame base64 was accepted")
	}
}

func TestExecutorEvidenceStatusEnforcesFindingSemantics(t *testing.T) {
	public, _ := executorEvidenceTestKey(t)
	head := ExecutorEvidenceHeadV1{
		Stream: ExecutorEvidenceStreamV1, ReceiptNodeID: "node-a", ReceiptEpoch: 1,
		Sequence: 5, ChainHash: evidenceTestDigest("a"), PublicKeySHA256: ExecutorEvidencePublicKeySHA256(public),
	}
	const witnessed = "2026-07-16T01:02:03Z"
	if err := (ExecutorEvidenceStatusV1{State: ExecutorEvidenceStatusUnwitnessed}).Validate(); err != nil {
		t.Fatal(err)
	}
	if err := (ExecutorEvidenceStatusV1{
		State: ExecutorEvidenceStatusCurrent, Head: &head, WitnessedAt: witnessed,
	}).Validate(); err != nil {
		t.Fatal(err)
	}
	invalidNonEmptyHead := head
	invalidNonEmptyHead.ChainHash = evidenceTestDigest("0")
	if err := invalidNonEmptyHead.Validate(); err == nil {
		t.Fatal("non-empty head with the zero chain hash was accepted")
	}

	rollbackHead := head
	rollbackHead.Sequence = 3
	rollbackHead.ChainHash = evidenceTestDigest("b")
	rollback := ExecutorEvidenceStatusV1{
		State: ExecutorEvidenceStatusRollbackDetected, Head: &head, WitnessedAt: witnessed,
		Finding: &ExecutorEvidenceFindingV1{
			Kind: ExecutorEvidenceFindingRollback, DetectedAt: "2026-07-16T01:03:00Z", ObservedHead: rollbackHead,
		},
	}
	if err := rollback.Validate(); err != nil {
		t.Fatal(err)
	}

	forkHead := head
	forkHead.ChainHash = evidenceTestDigest("b")
	equivocation := ExecutorEvidenceStatusV1{
		State: ExecutorEvidenceStatusEquivocationDetected, Head: &head, WitnessedAt: witnessed,
		Finding: &ExecutorEvidenceFindingV1{
			Kind: ExecutorEvidenceFindingEquivocation, DetectedAt: "2026-07-16T01:03:00Z", ObservedHead: forkHead,
		},
	}
	if err := equivocation.Validate(); err != nil {
		t.Fatal(err)
	}

	for name, candidate := range map[string]ExecutorEvidenceStatusV1{
		"unwitnessed with head": {
			State: ExecutorEvidenceStatusUnwitnessed, Head: &head,
		},
		"rollback not lower": {
			State: ExecutorEvidenceStatusRollbackDetected, Head: &head, WitnessedAt: witnessed,
			Finding: &ExecutorEvidenceFindingV1{
				Kind: ExecutorEvidenceFindingRollback, DetectedAt: "2026-07-16T01:03:00Z", ObservedHead: head,
			},
		},
		"equivocation identical": {
			State: ExecutorEvidenceStatusEquivocationDetected, Head: &head, WitnessedAt: witnessed,
			Finding: &ExecutorEvidenceFindingV1{
				Kind: ExecutorEvidenceFindingEquivocation, DetectedAt: "2026-07-16T01:03:00Z", ObservedHead: head,
			},
		},
		"finding predates head": {
			State: ExecutorEvidenceStatusRollbackDetected, Head: &head, WitnessedAt: witnessed,
			Finding: &ExecutorEvidenceFindingV1{
				Kind: ExecutorEvidenceFindingRollback, DetectedAt: "2026-07-16T01:00:00Z", ObservedHead: rollbackHead,
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := candidate.Validate(); err == nil {
				t.Fatal("invalid status was accepted")
			}
		})
	}
}

func TestExecutorEvidenceExportUsesDedicatedTrustedWitnessKey(t *testing.T) {
	receiptPublic, receiptPrivate := executorEvidenceTestKey(t)
	identityClaim, err := NewExecutorEvidenceIdentityClaimV1(
		"controller-a", "enrollment-a", "node-a", "node-a", 1, receiptPublic,
	)
	if err != nil {
		t.Fatal(err)
	}
	identityProof, err := SignExecutorEvidenceIdentityClaimV1(identityClaim, receiptPrivate)
	if err != nil {
		t.Fatal(err)
	}
	head := ExecutorEvidenceHeadV1{
		Stream: ExecutorEvidenceStreamV1, ReceiptNodeID: "node-a", ReceiptEpoch: 1,
		Sequence: 9, ChainHash: evidenceTestDigest("a"), PublicKeySHA256: identityClaim.PublicKeySHA256,
	}
	statement := ExecutorEvidenceExportStatementV1{
		ProtocolVersion: ExecutorEvidenceProtocolV1, ControllerInstanceID: "controller-a",
		ControlNodeID: "node-a", IdentityProof: identityProof,
		Status: ExecutorEvidenceStatusV1{
			State: ExecutorEvidenceStatusCurrent, Head: &head, WitnessedAt: "2026-07-16T01:02:03Z",
		},
		ExportedAt: "2026-07-16T01:03:00Z",
	}
	witnessPublic, witnessPrivate := executorEvidenceTestKey(t)
	export, err := SignExecutorEvidenceExportV1(statement, witnessPrivate)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyExecutorEvidenceExportV1(export, witnessPublic); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(export)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeExecutorEvidenceExportV1(raw)
	if err != nil || decoded.WitnessPublicKeySHA256 != ExecutorEvidencePublicKeySHA256(witnessPublic) {
		t.Fatalf("decode export=%+v err=%v", decoded, err)
	}

	otherPublic, _ := executorEvidenceTestKey(t)
	if err := VerifyExecutorEvidenceExportV1(export, otherPublic); err == nil {
		t.Fatal("export verified with an untrusted witness key")
	}
	tampered := export
	tampered.Statement.Status.Head = &ExecutorEvidenceHeadV1{
		Stream: head.Stream, ReceiptNodeID: head.ReceiptNodeID, ReceiptEpoch: head.ReceiptEpoch,
		Sequence: head.Sequence, ChainHash: evidenceTestDigest("b"), PublicKeySHA256: head.PublicKeySHA256,
	}
	if err := tampered.Validate(); err == nil {
		t.Fatal("tampered witness statement was accepted")
	}
	wrongType := export
	wrongType.PayloadType = executorEvidenceHeadProofPayloadTypeV1
	if err := wrongType.Validate(); err == nil {
		t.Fatal("purpose-confused export payload type was accepted")
	}
	if _, err := SignExecutorEvidenceExportV1(statement, receiptPrivate); err == nil {
		t.Fatal("receipt key was reused as the controller witness key")
	}
}

func TestExecutorEvidencePollAndChallengeValidation(t *testing.T) {
	public, _ := executorEvidenceTestKey(t)
	challenge := evidenceTestChallenge(t, 1)
	request := ExecutorEvidencePollRequestV1{
		ProtocolVersion: ExecutorEvidenceProtocolV1, ControllerInstanceID: "controller-a",
		ControlNodeID: "node-a", Stream: ExecutorEvidenceStreamV1, ReceiptNodeID: "node-a",
		ReceiptEpoch: 1, PublicKeySHA256: ExecutorEvidencePublicKeySHA256(public),
	}
	response := ExecutorEvidencePollResponseV1{
		ProtocolVersion: ExecutorEvidenceProtocolV1, Challenge: challenge,
		Status: ExecutorEvidenceStatusV1{State: ExecutorEvidenceStatusUnwitnessed},
	}
	reportResponse := ExecutorEvidenceReportResponseV1{
		ProtocolVersion: ExecutorEvidenceProtocolV1,
		Status:          ExecutorEvidenceStatusV1{State: ExecutorEvidenceStatusUnwitnessed},
	}
	if err := request.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := response.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := reportResponse.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, fixture := range []struct {
		value  any
		decode func([]byte) error
	}{
		{request, func(raw []byte) error { _, err := DecodeExecutorEvidencePollRequestV1(raw); return err }},
		{response, func(raw []byte) error { _, err := DecodeExecutorEvidencePollResponseV1(raw); return err }},
		{reportResponse, func(raw []byte) error { _, err := DecodeExecutorEvidenceReportResponseV1(raw); return err }},
	} {
		raw, err := json.Marshal(fixture.value)
		if err != nil {
			t.Fatal(err)
		}
		if err := fixture.decode(raw); err != nil {
			t.Fatal(err)
		}
	}
	rawChallenge, err := DecodeExecutorEvidenceChallengeV1(challenge)
	if err != nil || len(rawChallenge) != 32 {
		t.Fatalf("challenge bytes=%d err=%v", len(rawChallenge), err)
	}
	for _, invalid := range []string{
		"", challenge + "=", base64.StdEncoding.EncodeToString(make([]byte, 32)),
		base64.RawURLEncoding.EncodeToString(make([]byte, 31)),
	} {
		if _, err := DecodeExecutorEvidenceChallengeV1(invalid); err == nil {
			t.Fatalf("invalid challenge %q was accepted", invalid)
		}
	}
}

func executorEvidenceTestKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return public, private
}

func evidenceTestChallenge(t *testing.T, fill byte) string {
	t.Helper()
	value, err := EncodeExecutorEvidenceChallengeV1(bytesOf(fill, 32))
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func evidenceTestDigest(fill string) string {
	return "sha256:" + strings.Repeat(fill, 64)
}

func evidenceTestFrame(envelopeBytes int) []byte {
	frame := make([]byte, 4+envelopeBytes)
	binary.BigEndian.PutUint32(frame[:4], uint32(envelopeBytes))
	for index := 4; index < len(frame); index++ {
		frame[index] = byte(index)
	}
	return frame
}

func mutateEvidenceSignature(t *testing.T, encoded string) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	raw[0] ^= 0xff
	return base64.StdEncoding.EncodeToString(raw)
}

func bytesOf(value byte, count int) []byte {
	raw := make([]byte, count)
	for index := range raw {
		raw[index] = value
	}
	return raw
}
