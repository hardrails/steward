package controlcapture

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/evidence"
)

type captureVerifierFixture struct {
	capture          controlprotocol.ControllerEvidenceCaptureV1
	frames           [][]byte
	witnessPublic    ed25519.PublicKey
	witnessPrivate   ed25519.PrivateKey
	receiptPublic    ed25519.PublicKey
	receiptPrivate   ed25519.PrivateKey
	begin            evidence.VerifiedReceipt
	checkpoint       evidence.VerifiedReceipt
	checkpointDigest string
}

func TestVerifyV1ReplaysExactFramesAndPermitsUnrelatedTenants(t *testing.T) {
	fixture := newCaptureVerifierFixture(t)
	result, err := VerifyV1(fixture.capture, fixture.witnessPublic)
	if err != nil {
		t.Fatal(err)
	}
	if result.Statement != fixture.capture.Statement ||
		result.FinalHead.Sequence != fixture.capture.Statement.FinalHead.Sequence ||
		result.FinalHead.ChainHash != fixture.checkpointChainFinal(t) ||
		result.Begin.Receipt != fixture.begin.Receipt ||
		result.Checkpoint.Receipt != fixture.checkpoint.Receipt {
		t.Fatalf("verified result=%#v", result)
	}
	if result.Checkpoint.Receipt.TenantID != "tenant-a" ||
		result.Checkpoint.Receipt.Type != evidence.ActivationCheckpoint ||
		result.Checkpoint.Receipt.Outcome != evidence.Committed ||
		result.Checkpoint.Receipt.ErrorCode != "" ||
		result.Checkpoint.Receipt.MetadataHash != fixture.checkpointDigest {
		t.Fatalf("checkpoint=%#v", result.Checkpoint.Receipt)
	}

	raw, err := json.Marshal(fixture.capture)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := VerifyJSONV1(raw, fixture.witnessPublic)
	if err != nil || decoded.Checkpoint.Receipt != result.Checkpoint.Receipt {
		t.Fatalf("verify JSON result=%#v err=%v", decoded, err)
	}

	otherPublic, _ := captureVerifierKey(t)
	if _, err := VerifyV1(fixture.capture, otherPublic); err == nil {
		t.Fatal("offline verification accepted an unpinned controller witness key")
	}
}

func TestVerifyV1RejectsMutationRemovalInsertionReorderingAndSubstitution(t *testing.T) {
	fixture := newCaptureVerifierFixture(t)
	foreignFrame := foreignCaptureFrame(t)
	tests := map[string]func() controlprotocol.ControllerEvidenceCaptureV1{
		"mutation": func() controlprotocol.ControllerEvidenceCaptureV1 {
			frames := cloneCaptureFrames(fixture.frames)
			frames[0][len(frames[0])-1] ^= 1
			return fixture.resign(t, fixture.capture.Statement, frames)
		},
		"removal": func() controlprotocol.ControllerEvidenceCaptureV1 {
			frames := cloneCaptureFrames(fixture.frames)
			frames = append(frames[:1], frames[2:]...)
			return fixture.resignWithCount(t, fixture.capture.Statement, frames)
		},
		"insertion": func() controlprotocol.ControllerEvidenceCaptureV1 {
			frames := cloneCaptureFrames(fixture.frames)
			frames = append(frames, nil)
			copy(frames[2:], frames[1:])
			frames[1] = append([]byte(nil), frames[0]...)
			return fixture.resignWithCount(t, fixture.capture.Statement, frames)
		},
		"reordering": func() controlprotocol.ControllerEvidenceCaptureV1 {
			frames := cloneCaptureFrames(fixture.frames)
			frames[0], frames[1] = frames[1], frames[0]
			return fixture.resign(t, fixture.capture.Statement, frames)
		},
		"substitution": func() controlprotocol.ControllerEvidenceCaptureV1 {
			frames := cloneCaptureFrames(fixture.frames)
			frames[0] = append([]byte(nil), foreignFrame...)
			return fixture.resign(t, fixture.capture.Statement, frames)
		},
	}
	for name, build := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := build()
			if err := controlprotocol.VerifyControllerEvidenceCaptureV1(candidate, fixture.witnessPublic); err != nil {
				t.Fatalf("trusted controller signature should remain valid: %v", err)
			}
			if _, err := VerifyV1(candidate, fixture.witnessPublic); err == nil {
				t.Fatal("offline verifier accepted changed native evidence")
			}
		})
	}
}

func TestVerifyV1RequiresExactHeadsEnrollmentAndCheckpoint(t *testing.T) {
	fixture := newCaptureVerifierFixture(t)

	t.Run("baseline substitution", func(t *testing.T) {
		statement := fixture.capture.Statement
		statement.BaselineHead.ChainHash = captureVerifierDigest("a")
		candidate := fixture.resign(t, statement, fixture.frames)
		if _, err := VerifyV1(candidate, fixture.witnessPublic); err == nil {
			t.Fatal("substituted baseline was accepted")
		}
	})

	t.Run("final substitution", func(t *testing.T) {
		statement := fixture.capture.Statement
		statement.FinalHead.ChainHash = captureVerifierDigest("b")
		candidate := fixture.resign(t, statement, fixture.frames)
		if _, err := VerifyV1(candidate, fixture.witnessPublic); err == nil {
			t.Fatal("substituted final head was accepted")
		}
	})

	t.Run("enrollment substitution", func(t *testing.T) {
		otherPublic, otherPrivate := captureVerifierKey(t)
		claim, err := controlprotocol.NewExecutorEvidenceIdentityClaimV1(
			"controller-a", "enrollment-other", "node-a", "node-a", 1, otherPublic,
		)
		if err != nil {
			t.Fatal(err)
		}
		proof, err := controlprotocol.SignExecutorEvidenceIdentityClaimV1(claim, otherPrivate)
		if err != nil {
			t.Fatal(err)
		}
		statement := fixture.capture.Statement
		statement.IdentityProof = proof
		statement.BaselineHead.PublicKeySHA256 = controlprotocol.ExecutorEvidencePublicKeySHA256(otherPublic)
		statement.FinalHead.PublicKeySHA256 = statement.BaselineHead.PublicKeySHA256
		candidate := fixture.resign(t, statement, fixture.frames)
		if _, err := VerifyV1(candidate, fixture.witnessPublic); err == nil {
			t.Fatal("substituted enrollment receipt key was accepted")
		}
	})

	t.Run("wrong checkpoint digest", func(t *testing.T) {
		statement := fixture.capture.Statement
		statement.ActivationCheckpointDigest = captureVerifierDigest("c")
		candidate := fixture.resign(t, statement, fixture.frames)
		if _, err := VerifyV1(candidate, fixture.witnessPublic); err == nil {
			t.Fatal("conflicting target checkpoint was accepted")
		}
	})

	t.Run("wrong checkpoint target", func(t *testing.T) {
		statement := fixture.capture.Statement
		statement.TenantID = "tenant-missing"
		candidate := fixture.resign(t, statement, fixture.frames)
		if _, err := VerifyV1(candidate, fixture.witnessPublic); err == nil {
			t.Fatal("capture without a matching target checkpoint was accepted")
		}
	})

	t.Run("checkpoint outside capture window", func(t *testing.T) {
		checkpoint := fixture.checkpoint
		checkpointHead := controlprotocol.ExecutorEvidenceHeadV1{
			Stream:          controlprotocol.ExecutorEvidenceStreamV1,
			ReceiptNodeID:   checkpoint.Receipt.NodeID,
			ReceiptEpoch:    checkpoint.Receipt.Epoch,
			Sequence:        checkpoint.Receipt.Sequence,
			ChainHash:       captureVerifierHash(checkpoint.ChainHash),
			PublicKeySHA256: controlprotocol.ExecutorEvidencePublicKeySHA256(fixture.receiptPublic),
		}
		checkpointIndex := -1
		for index, frame := range fixture.frames {
			if string(frame) == string(checkpoint.Frame) {
				checkpointIndex = index
				break
			}
		}
		if checkpointIndex < 0 || checkpointIndex+1 >= len(fixture.frames) {
			t.Fatal("fixture does not contain a post-checkpoint frame")
		}
		statement := fixture.capture.Statement
		statement.BaselineHead = checkpointHead
		if err := statement.Validate(); err == nil {
			t.Fatal("capture whose signed activation pair precedes its baseline was accepted")
		}
	})
}

func TestVerifyV1RejectsSignedLifecycleInvalidationThroughFinalHead(t *testing.T) {
	fixture := newCaptureVerifierFixtureWithSuffix(t, func(log *evidence.Log, target evidence.Event) {
		invalidating := target
		invalidating.Type = evidence.LifecycleDestroy
		invalidating.Outcome = evidence.Committed
		invalidating.ErrorCode = ""
		invalidating.MetadataHash = captureVerifierDigest("8")
		if _, err := log.Append(invalidating); err != nil {
			t.Fatal(err)
		}
	})
	if _, err := VerifyV1(fixture.capture, fixture.witnessPublic); err == nil ||
		!strings.Contains(err.Error(), "lifecycle-invalidating") {
		t.Fatalf("signed lifecycle invalidation error = %v", err)
	}
}

func newCaptureVerifierFixture(t *testing.T) captureVerifierFixture {
	return newCaptureVerifierFixtureWithSuffix(t, nil)
}

func newCaptureVerifierFixtureWithSuffix(
	t *testing.T,
	afterCheckpoint func(*evidence.Log, evidence.Event),
) captureVerifierFixture {
	t.Helper()
	receiptPublic, receiptPrivate := captureVerifierKey(t)
	witnessPublic, witnessPrivate := captureVerifierKey(t)
	path := filepath.Join(t.TempDir(), "executor-evidence.log")
	log, err := evidence.Open(path, receiptPrivate, "node-a", 1)
	if err != nil {
		t.Fatal(err)
	}

	baselineEvent := captureVerifierEvent(evidence.AdmissionAllow, "tenant-baseline", "baseline-runtime")
	if _, err := log.Append(baselineEvent); err != nil {
		t.Fatal(err)
	}
	baselineDelta, err := log.ExportDelta(evidence.Coordinate{})
	if err != nil {
		t.Fatal(err)
	}
	baseline := baselineDelta.Head

	crossTenant := captureVerifierEvent(evidence.InferenceAuthorize, "tenant-b", "runtime-b")
	if _, err := log.Append(crossTenant); err != nil {
		t.Fatal(err)
	}
	target := captureVerifierEvent(
		evidence.ActivationBegin,
		"tenant-a",
		"executor-"+strings.Repeat("1", 64),
	)
	target.Generation = 7
	target.GrantID = "activation-a"
	target.Outcome = evidence.Allowed
	target.ErrorCode = ""
	target.MetadataHash = captureVerifierDigest("6")
	beginReceipt, err := log.AppendActivationBegin(target)
	if err != nil {
		t.Fatal(err)
	}
	unrelated := captureVerifierEvent(evidence.JournalCommit, "tenant-a", "other-runtime")
	if _, err := log.Append(unrelated); err != nil {
		t.Fatal(err)
	}
	checkpointDigest := captureVerifierDigest("7")
	target.Type = evidence.ActivationCheckpoint
	target.Outcome = evidence.Committed
	target.MetadataHash = checkpointDigest
	checkpointReceipt, err := log.AppendActivationCheckpoint(target)
	if err != nil {
		t.Fatal(err)
	}
	if afterCheckpoint != nil {
		afterCheckpoint(log, target)
	}
	after := captureVerifierEvent(evidence.InferenceTerminal, "tenant-c", "runtime-c")
	after.Outcome = evidence.Failed
	if _, err := log.Append(after); err != nil {
		t.Fatal(err)
	}
	delta, err := log.ExportDelta(evidence.Coordinate{
		Sequence: baseline.Sequence, ChainHash: baseline.ChainHash,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	var begin evidence.VerifiedReceipt
	var checkpoint evidence.VerifiedReceipt
	if _, err := evidence.VerifyRecords(path, receiptPublic, "node-a", 1, func(record evidence.VerifiedReceipt) error {
		if record.Receipt.Sequence == beginReceipt.Sequence {
			begin = record
		}
		if record.Receipt.Sequence == checkpointReceipt.Sequence {
			checkpoint = record
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if begin.Receipt.Sequence == 0 || checkpoint.Receipt.Sequence == 0 {
		t.Fatal("activation marker frames were not recovered")
	}

	claim, err := controlprotocol.NewExecutorEvidenceIdentityClaimV1(
		"controller-a", "enrollment-a", "node-a", "node-a", 1, receiptPublic,
	)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := controlprotocol.SignExecutorEvidenceIdentityClaimV1(claim, receiptPrivate)
	if err != nil {
		t.Fatal(err)
	}
	statement := controlprotocol.ControllerEvidenceCaptureStatementV1{
		ProtocolVersion:            controlprotocol.ControllerEvidenceCaptureProtocolV1,
		ControllerInstanceID:       "controller-a",
		CaptureID:                  "capture-a",
		NodeID:                     "node-a",
		TenantID:                   target.TenantID,
		RuntimeRef:                 target.RuntimeRef,
		Generation:                 target.Generation,
		ActivationID:               target.GrantID,
		CanaryCommandID:            "canary-command-a",
		ActivationBeginDigest:      captureVerifierDigest("6"),
		ActivationBeginSequence:    beginReceipt.Sequence,
		ActivationCheckpointDigest: checkpointDigest,
		CapsuleDigest:              target.CapsuleDigest,
		PolicyDigest:               target.PolicyDigest,
		IdentityProof:              proof,
		BaselineHead:               captureVerifierProtocolHead(baseline, receiptPublic),
		FinalHead:                  captureVerifierProtocolHead(delta.Head, receiptPublic),
		FrameCount:                 uint32(len(delta.Frames)),
		FramesDigest:               controlprotocol.ControllerEvidenceCaptureFramesDigestV1(delta.Frames),
		ArmedAt:                    "2026-07-01T00:00:00Z",
		ObservedAt:                 "2026-07-01T00:01:00Z",
		SealedAt:                   "2026-07-01T00:02:00Z",
		ExportedAt:                 "2026-07-01T00:03:00Z",
	}
	capture, err := controlprotocol.SignControllerEvidenceCaptureV1(
		statement, delta.Frames, witnessPrivate,
	)
	if err != nil {
		t.Fatal(err)
	}
	return captureVerifierFixture{
		capture: capture, frames: cloneCaptureFrames(delta.Frames),
		witnessPublic: witnessPublic, witnessPrivate: witnessPrivate,
		receiptPublic: receiptPublic, receiptPrivate: receiptPrivate,
		begin:      begin,
		checkpoint: checkpoint, checkpointDigest: checkpointDigest,
	}
}

func (fixture captureVerifierFixture) resign(
	t *testing.T,
	statement controlprotocol.ControllerEvidenceCaptureStatementV1,
	frames [][]byte,
) controlprotocol.ControllerEvidenceCaptureV1 {
	t.Helper()
	statement.FrameCount = uint32(len(frames))
	statement.FramesDigest = controlprotocol.ControllerEvidenceCaptureFramesDigestV1(frames)
	capture, err := controlprotocol.SignControllerEvidenceCaptureV1(
		statement, frames, fixture.witnessPrivate,
	)
	if err != nil {
		t.Fatal(err)
	}
	return capture
}

func (fixture captureVerifierFixture) resignWithCount(
	t *testing.T,
	statement controlprotocol.ControllerEvidenceCaptureStatementV1,
	frames [][]byte,
) controlprotocol.ControllerEvidenceCaptureV1 {
	t.Helper()
	statement.FrameCount = uint32(len(frames))
	statement.FinalHead.Sequence = statement.BaselineHead.Sequence + uint64(len(frames))
	statement.FramesDigest = controlprotocol.ControllerEvidenceCaptureFramesDigestV1(frames)
	return fixture.resign(t, statement, frames)
}

func (fixture captureVerifierFixture) checkpointChainFinal(t *testing.T) [32]byte {
	t.Helper()
	value, err := decodeCaptureChainHash(fixture.capture.Statement.FinalHead.ChainHash)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func captureVerifierProtocolHead(head evidence.Head, public ed25519.PublicKey) controlprotocol.ExecutorEvidenceHeadV1 {
	return controlprotocol.ExecutorEvidenceHeadV1{
		Stream:          controlprotocol.ExecutorEvidenceStreamV1,
		ReceiptNodeID:   head.NodeID,
		ReceiptEpoch:    head.Epoch,
		Sequence:        head.Sequence,
		ChainHash:       captureVerifierHash(head.ChainHash),
		PublicKeySHA256: controlprotocol.ExecutorEvidencePublicKeySHA256(public),
	}
}

func captureVerifierEvent(kind evidence.EventType, tenantID, runtimeRef string) evidence.Event {
	return evidence.Event{
		Type: kind, TenantID: tenantID, RuntimeRef: runtimeRef,
		CapsuleDigest: captureVerifierDigest("1"),
		PolicyDigest:  captureVerifierDigest("2"),
		Generation:    1,
		GrantID:       "grant-a",
		Outcome:       evidence.Committed,
		ErrorCode:     "",
		MetadataHash:  captureVerifierDigest("3"),
	}
}

func foreignCaptureFrame(t *testing.T) []byte {
	t.Helper()
	_, private := captureVerifierKey(t)
	path := filepath.Join(t.TempDir(), "foreign.log")
	log, err := evidence.Open(path, private, "foreign-node", 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(captureVerifierEvent(evidence.AdmissionAllow, "tenant-a", "runtime-a")); err != nil {
		t.Fatal(err)
	}
	delta, err := log.ExportDelta(evidence.Coordinate{})
	if err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	return append([]byte(nil), delta.Frames[0]...)
}

func captureVerifierKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return public, private
}

func captureVerifierHash(value [32]byte) string {
	return "sha256:" + hex.EncodeToString(value[:])
}

func captureVerifierDigest(character string) string {
	return "sha256:" + strings.Repeat(character, 64)
}

func cloneCaptureFrames(frames [][]byte) [][]byte {
	clone := make([][]byte, len(frames))
	for index, frame := range frames {
		clone[index] = append([]byte(nil), frame...)
	}
	return clone
}
