package activation

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/evidence"
)

const MaxExecutorDeltaBytes = 16 << 20

// ErrEvidenceInvalid marks a semantic contradiction in immutable activation
// evidence. Callers may treat it as action-required instead of retrying
// forever. Missing or not-yet-durable source data is deliberately not wrapped.
var ErrEvidenceInvalid = errors.New("activation evidence is semantically invalid")

func invalidEvidence(err error) error {
	return fmt.Errorf("%w: %v", ErrEvidenceInvalid, err)
}

// ExecutorEvidenceRequestV1 identifies the exact runtime admission whose
// receipt slice must be anchored between two independently signed controller
// witness exports.
type ExecutorEvidenceRequestV1 struct {
	Binding                    BindingV1
	RuntimeRef                 string
	StateRuntimeRef            string
	CapsuleDigest              string
	RoutePolicyDigest          string
	GrantID                    string
	ActivationBeginDigest      string
	ActivationCheckpointDigest string
	BaselineWitness            []byte
	FinalWitness               []byte
	WitnessPublicKey           ed25519.PublicKey
}

// ExecutorEvidenceResultV1 is portable: Delta contains the original signed
// native frames, Coordinate is the final receipt head, and Witness is the
// separately signed controller assertion over that same head.
type ExecutorEvidenceResultV1 struct {
	Delta      []byte
	Coordinate ReceiptCoordinateV1
	Witness    WitnessCoordinateV1
}

// CollectExecutorEvidenceV1 fully verifies a local Executor evidence log,
// extracts the exact signed frames after the baseline through the final
// controller checkpoint, then re-verifies that portable slice.
func CollectExecutorEvidenceV1(
	request ExecutorEvidenceRequestV1,
	evidenceLogPath string,
) (ExecutorEvidenceResultV1, error) {
	return CollectExecutorEvidenceV1Context(
		context.Background(), request, evidenceLogPath,
	)
}

// CollectExecutorEvidenceV1Context is CollectExecutorEvidenceV1 with bounded
// cancellation checks before trust verification, during every receipt visit,
// and before portable-delta verification.
func CollectExecutorEvidenceV1Context(
	ctx context.Context,
	request ExecutorEvidenceRequestV1,
	evidenceLogPath string,
) (ExecutorEvidenceResultV1, error) {
	if err := activationContextError(ctx); err != nil {
		return ExecutorEvidenceResultV1{}, err
	}
	exports, err := verifyExecutorWitnessPair(request)
	if err != nil {
		return ExecutorEvidenceResultV1{}, invalidEvidence(err)
	}
	if err := activationContextError(ctx); err != nil {
		return ExecutorEvidenceResultV1{}, err
	}
	if evidenceLogPath == "" {
		return ExecutorEvidenceResultV1{}, errors.New("executor evidence log path is required")
	}
	info, err := os.Lstat(evidenceLogPath)
	if err != nil {
		return ExecutorEvidenceResultV1{}, fmt.Errorf("inspect executor evidence log: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 ||
		info.Size() < 0 || info.Size() > evidence.MaxLogBytes {
		return ExecutorEvidenceResultV1{}, errors.New("executor evidence log must be a bounded owner-only regular file")
	}

	baselineHead := *exports.baseline.Statement.Status.Head
	finalHead := *exports.final.Statement.Status.Head
	var delta []byte
	baselineMatched := baselineHead.Sequence == 0
	finalMatched := false
	complete, err := evidence.VerifyRecords(
		evidenceLogPath, exports.receiptPublic,
		finalHead.ReceiptNodeID, finalHead.ReceiptEpoch,
		func(record evidence.VerifiedReceipt) error {
			if err := activationContextError(ctx); err != nil {
				return err
			}
			sequence := record.Receipt.Sequence
			hash := evidenceHash(record.ChainHash)
			if sequence == baselineHead.Sequence {
				if hash != baselineHead.ChainHash {
					return invalidEvidence(errors.New("local evidence does not contain the controller baseline coordinate"))
				}
				baselineMatched = true
			}
			if sequence <= baselineHead.Sequence {
				return nil
			}
			if sequence > finalHead.Sequence {
				if executorActivationEventMatches(
					record.Receipt.Event, request.Binding,
					request.RuntimeRef, request.StateRuntimeRef,
					request.CapsuleDigest,
				) {
					return invalidEvidence(errors.New("local evidence contains activation events after the final controller witness"))
				}
				return nil
			}
			if len(delta) > MaxExecutorDeltaBytes-len(record.Frame) {
				return invalidEvidence(errors.New("executor evidence delta exceeds its portable limit"))
			}
			delta = append(delta, record.Frame...)
			if sequence == finalHead.Sequence {
				if hash != finalHead.ChainHash {
					return invalidEvidence(errors.New("local evidence does not contain the controller final coordinate"))
				}
				finalMatched = true
			}
			return nil
		},
	)
	if err != nil {
		return ExecutorEvidenceResultV1{}, fmt.Errorf("verify executor evidence log: %w", err)
	}
	if complete.Sequence < finalHead.Sequence ||
		!baselineMatched || !finalMatched {
		return ExecutorEvidenceResultV1{}, errors.New("local evidence does not contain the final controller witness coordinate")
	}
	result, err := VerifyExecutorEvidenceDeltaV1Context(ctx, request, delta)
	if err != nil {
		if errors.Is(err, context.Canceled) ||
			errors.Is(err, context.DeadlineExceeded) {
			return ExecutorEvidenceResultV1{}, err
		}
		return ExecutorEvidenceResultV1{}, invalidEvidence(err)
	}
	return result, nil
}

// VerifyExecutorEvidenceDeltaV1 authenticates the witness pair and exact
// portable frames without access to the node's complete evidence log.
func VerifyExecutorEvidenceDeltaV1(
	request ExecutorEvidenceRequestV1,
	delta []byte,
) (ExecutorEvidenceResultV1, error) {
	return VerifyExecutorEvidenceDeltaV1Context(
		context.Background(), request, delta,
	)
}

// VerifyExecutorEvidenceDeltaV1Context is
// VerifyExecutorEvidenceDeltaV1 with cancellation checks between each bounded
// receipt batch and during every matching-event visit.
func VerifyExecutorEvidenceDeltaV1Context(
	ctx context.Context,
	request ExecutorEvidenceRequestV1,
	delta []byte,
) (ExecutorEvidenceResultV1, error) {
	if err := activationContextError(ctx); err != nil {
		return ExecutorEvidenceResultV1{}, err
	}
	exports, err := verifyExecutorWitnessPair(request)
	if err != nil {
		return ExecutorEvidenceResultV1{}, err
	}
	if err := activationContextError(ctx); err != nil {
		return ExecutorEvidenceResultV1{}, err
	}
	frames, err := decodeEvidenceFrames(delta)
	if err != nil {
		return ExecutorEvidenceResultV1{}, err
	}
	baselineHead := *exports.baseline.Statement.Status.Head
	finalHead := *exports.final.Statement.Status.Head
	baselineHash, _ := decodeEvidenceHash(baselineHead.ChainHash)
	prior := evidence.Coordinate{Sequence: baselineHead.Sequence, ChainHash: baselineHash}

	var authorizationSequences []uint64
	var beginSequence, commitSequence, startSequence, checkpointSequence uint64
	pendingWorkloadOperation := ""
	pendingStatePurge := false
	for start := 0; start < len(frames); {
		if err := activationContextError(ctx); err != nil {
			return ExecutorEvidenceResultV1{}, err
		}
		end, decodedBytes := start, 0
		for end < len(frames) && end-start < evidence.MaxDeltaRecords &&
			decodedBytes <= evidence.MaxDeltaBytes-len(frames[end]) {
			decodedBytes += len(frames[end])
			end++
		}
		if end == start {
			return ExecutorEvidenceResultV1{}, errors.New("executor evidence frame exceeds the delta batch limit")
		}
		head, err := evidence.VerifyDeltaRecords(
			frames[start:end], exports.receiptPublic,
			finalHead.ReceiptNodeID, finalHead.ReceiptEpoch, prior,
			func(string) bool { return true },
			func(record evidence.VerifiedReceipt) error {
				if err := activationContextError(ctx); err != nil {
					return err
				}
				event := record.Receipt.Event
				if !executorActivationEventMatches(
					event, request.Binding, request.RuntimeRef,
					request.StateRuntimeRef, request.CapsuleDigest,
				) {
					return nil
				}
				if event.Type == evidence.ActivationBegin {
					if event.Outcome != evidence.Allowed ||
						event.ErrorCode != "" ||
						event.MetadataHash != request.ActivationBeginDigest {
						return errors.New("executor evidence contains a conflicting activation begin marker")
					}
					if beginSequence != 0 {
						return errors.New("executor evidence contains multiple matching activation begin markers")
					}
					beginSequence = record.Receipt.Sequence
					return nil
				}
				if event.Type == evidence.ActivationCheckpoint {
					if event.Outcome != evidence.Committed ||
						event.ErrorCode != "" ||
						event.MetadataHash != request.ActivationCheckpointDigest {
						return errors.New("executor evidence contains a conflicting activation checkpoint")
					}
					if checkpointSequence != 0 {
						return errors.New("executor evidence contains multiple matching activation checkpoints")
					}
					checkpointSequence = record.Receipt.Sequence
					return nil
				}
				if executorActivationInvalidatingEvent(event) {
					return errors.New("executor evidence contains a lifecycle-invalidating event for the activation")
				}
				switch event.Type {
				case evidence.AdmissionAllow:
					if event.Outcome == evidence.Allowed && event.GrantID == request.GrantID {
						authorizationSequences = append(authorizationSequences, record.Receipt.Sequence)
					}
				case evidence.JournalPrepare:
					if event.Outcome == evidence.Allowed &&
						event.GrantID == "state" {
						if pendingStatePurge {
							return errors.New("executor evidence contains multiple unresolved state-purge preparations")
						}
						pendingStatePurge = true
						return nil
					}
					if event.Outcome == evidence.Allowed &&
						event.GrantID == "workload" {
						if pendingWorkloadOperation != "" {
							return errors.New("executor evidence contains multiple unresolved workload preparations")
						}
						switch event.ErrorCode {
						case "":
							pendingWorkloadOperation = "admit"
						case "start":
							pendingWorkloadOperation = "start"
						default:
							pendingWorkloadOperation = event.ErrorCode
						}
					}
				case evidence.JournalCompensate:
					if event.Outcome == evidence.Compensated {
						if event.GrantID == "state" {
							if !pendingStatePurge {
								return errors.New("executor evidence contains state-purge compensation without a pending preparation")
							}
							pendingStatePurge = false
							return nil
						}
						if startSequence != 0 {
							return errors.New("executor evidence contains compensation after the proven runtime start")
						}
						if pendingWorkloadOperation == "" {
							return errors.New("executor evidence contains compensation without a pending workload operation")
						}
						pendingWorkloadOperation = ""
					}
				case evidence.JournalCommit:
					if event.Outcome == evidence.Committed && event.GrantID == "workload" &&
						event.MetadataHash == request.RoutePolicyDigest {
						if commitSequence != 0 {
							return errors.New("executor evidence contains multiple matching admission commits")
						}
						if pendingWorkloadOperation != "admit" {
							return errors.New("executor admission commit has no matching workload preparation")
						}
						commitSequence = record.Receipt.Sequence
						pendingWorkloadOperation = ""
					}
				case evidence.LifecycleStart:
					if event.Outcome == evidence.Committed && event.GrantID == "workload" &&
						event.MetadataHash == request.RoutePolicyDigest {
						if startSequence != 0 {
							return errors.New("executor evidence contains multiple matching lifecycle starts")
						}
						if pendingWorkloadOperation != "start" {
							return errors.New("executor runtime start has no matching workload preparation")
						}
						startSequence = record.Receipt.Sequence
						pendingWorkloadOperation = ""
					}
				}
				return nil
			},
		)
		if err != nil {
			return ExecutorEvidenceResultV1{}, fmt.Errorf("verify executor evidence delta: %w", err)
		}
		prior = evidence.Coordinate{Sequence: head.Sequence, ChainHash: head.ChainHash}
		start = end
	}
	if prior.Sequence != finalHead.Sequence ||
		evidenceHash(prior.ChainHash) != finalHead.ChainHash {
		return ExecutorEvidenceResultV1{}, errors.New("executor evidence delta does not end at the final controller witness")
	}
	authorizedAfterBeginBeforeCommit := false
	for _, sequence := range authorizationSequences {
		if sequence > beginSequence && sequence < commitSequence {
			authorizedAfterBeginBeforeCommit = true
			break
		}
	}
	if pendingWorkloadOperation != "" || pendingStatePurge {
		return ExecutorEvidenceResultV1{}, errors.New("executor evidence ends with an unresolved workload or state-purge preparation")
	}
	if beginSequence == 0 || !authorizedAfterBeginBeforeCommit ||
		commitSequence == 0 ||
		startSequence == 0 || checkpointSequence == 0 ||
		beginSequence >= commitSequence ||
		commitSequence >= startSequence || startSequence >= checkpointSequence {
		return ExecutorEvidenceResultV1{}, errors.New("executor evidence does not prove activation begin, fresh signed admission, runtime start, and the causal terminal checkpoint in order")
	}

	coordinate := ReceiptCoordinateV1{
		ReceiptNodeID: finalHead.ReceiptNodeID, ReceiptEpoch: finalHead.ReceiptEpoch,
		Sequence: finalHead.Sequence, ChainHash: finalHead.ChainHash,
		PublicKeySHA256: finalHead.PublicKeySHA256,
	}
	witness := WitnessCoordinateV1{
		ControllerInstanceID: exports.final.Statement.ControllerInstanceID,
		ControlNodeID:        exports.final.Statement.ControlNodeID,
		ReceiptNodeID:        finalHead.ReceiptNodeID, ReceiptEpoch: finalHead.ReceiptEpoch,
		Sequence: finalHead.Sequence, ChainHash: finalHead.ChainHash,
		ReceiptPublicKeySHA256: finalHead.PublicKeySHA256,
		WitnessPublicKeySHA256: exports.final.WitnessPublicKeySHA256,
		WitnessExportDigest:    dsse.Digest(request.FinalWitness),
		WitnessedAt:            exports.final.Statement.Status.WitnessedAt,
	}
	return ExecutorEvidenceResultV1{
		Delta: append([]byte(nil), delta...), Coordinate: coordinate, Witness: witness,
	}, nil
}

// VerifyExecutorWitnessPairV1 authenticates the write-once controller witness
// inputs independently of the mutable local evidence source.
func VerifyExecutorWitnessPairV1(request ExecutorEvidenceRequestV1) error {
	_, err := verifyExecutorWitnessPair(request)
	return err
}

func activationContextError(ctx context.Context) error {
	if ctx == nil {
		return errors.New("activation evidence context is required")
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

type verifiedExecutorWitnessPair struct {
	baseline      controlprotocol.ExecutorEvidenceExportV1
	final         controlprotocol.ExecutorEvidenceExportV1
	receiptPublic ed25519.PublicKey
}

func verifyExecutorWitnessPair(request ExecutorEvidenceRequestV1) (verifiedExecutorWitnessPair, error) {
	if err := request.Binding.validate(); err != nil {
		return verifiedExecutorWitnessPair{}, fmt.Errorf("executor evidence binding: %w", err)
	}
	if !runtimeRef(request.RuntimeRef) || !sha256Digest(request.CapsuleDigest) ||
		!stateRuntimeRef(request.StateRuntimeRef) ||
		!sha256Digest(request.RoutePolicyDigest) ||
		!sha256Digest(request.ActivationBeginDigest) ||
		!sha256Digest(request.ActivationCheckpointDigest) ||
		!grantIDPattern.MatchString(request.GrantID) ||
		len(request.WitnessPublicKey) != ed25519.PublicKeySize ||
		len(request.BaselineWitness) == 0 || len(request.FinalWitness) == 0 {
		return verifiedExecutorWitnessPair{}, errors.New("executor evidence request is incomplete")
	}
	baseline, err := controlprotocol.DecodeExecutorEvidenceExportV1(request.BaselineWitness)
	if err != nil {
		return verifiedExecutorWitnessPair{}, fmt.Errorf("decode baseline executor witness: %w", err)
	}
	final, err := controlprotocol.DecodeExecutorEvidenceExportV1(request.FinalWitness)
	if err != nil {
		return verifiedExecutorWitnessPair{}, fmt.Errorf("decode final executor witness: %w", err)
	}
	if err := controlprotocol.VerifyExecutorEvidenceExportV1(baseline, request.WitnessPublicKey); err != nil {
		return verifiedExecutorWitnessPair{}, fmt.Errorf("verify baseline executor witness: %w", err)
	}
	if err := controlprotocol.VerifyExecutorEvidenceExportV1(final, request.WitnessPublicKey); err != nil {
		return verifiedExecutorWitnessPair{}, fmt.Errorf("verify final executor witness: %w", err)
	}
	if baseline.Statement.Status.State != controlprotocol.ExecutorEvidenceStatusCurrent ||
		final.Statement.Status.State != controlprotocol.ExecutorEvidenceStatusCurrent ||
		baseline.Statement.Status.Head == nil || final.Statement.Status.Head == nil ||
		baseline.Statement.Status.Finding != nil || final.Statement.Status.Finding != nil {
		return verifiedExecutorWitnessPair{}, errors.New("executor witness pair must contain current finding-free checkpoints")
	}
	if baseline.Statement.ControllerInstanceID != final.Statement.ControllerInstanceID ||
		baseline.Statement.ControlNodeID != final.Statement.ControlNodeID ||
		baseline.Statement.IdentityProof != final.Statement.IdentityProof ||
		baseline.WitnessPublicKeySHA256 != final.WitnessPublicKeySHA256 {
		return verifiedExecutorWitnessPair{}, errors.New("executor witness pair changed controller, enrollment, or witness identity")
	}
	baselineHead := *baseline.Statement.Status.Head
	finalHead := *final.Statement.Status.Head
	if baselineHead.Stream != finalHead.Stream ||
		baselineHead.ReceiptNodeID != finalHead.ReceiptNodeID ||
		baselineHead.ReceiptEpoch != finalHead.ReceiptEpoch ||
		baselineHead.PublicKeySHA256 != finalHead.PublicKeySHA256 ||
		finalHead.ReceiptNodeID != request.Binding.NodeID ||
		finalHead.Sequence <= baselineHead.Sequence {
		return verifiedExecutorWitnessPair{}, errors.New("executor witness pair does not advance one bound node evidence stream")
	}
	baselineTime, _ := time.Parse(time.RFC3339Nano, baseline.Statement.ExportedAt)
	finalTime, _ := time.Parse(time.RFC3339Nano, final.Statement.ExportedAt)
	if finalTime.Before(baselineTime) {
		return verifiedExecutorWitnessPair{}, errors.New("final executor witness predates the baseline export")
	}
	receiptPublic, err := controlprotocol.VerifyExecutorEvidenceIdentityProofV1(final.Statement.IdentityProof)
	if err != nil {
		return verifiedExecutorWitnessPair{}, fmt.Errorf("verify executor receipt identity proof: %w", err)
	}
	return verifiedExecutorWitnessPair{
		baseline: baseline, final: final,
		receiptPublic: receiptPublic,
	}, nil
}

func executorActivationInvalidatingEvent(event evidence.Event) bool {
	switch event.Type {
	case evidence.LifecycleStop,
		evidence.LifecycleDestroy,
		evidence.StatePurge,
		evidence.Drift,
		evidence.Revocation:
		return event.Outcome == evidence.Committed ||
			event.Outcome == evidence.Compensated
	default:
		return false
	}
}

func executorActivationEventMatches(
	event evidence.Event,
	binding BindingV1,
	runtimeReference string,
	stateRuntimeReference string,
	capsuleDigest string,
) bool {
	expectedRuntime := runtimeReference
	if event.Type == evidence.StatePurge ||
		event.GrantID == "state" {
		expectedRuntime = stateRuntimeReference
	}
	if (event.Type == evidence.ActivationBegin ||
		event.Type == evidence.ActivationCheckpoint) &&
		event.GrantID != binding.ActivationID {
		return false
	}
	return event.TenantID == binding.TenantID &&
		event.RuntimeRef == expectedRuntime &&
		event.CapsuleDigest == capsuleDigest &&
		event.PolicyDigest == binding.PolicyDigest &&
		event.Generation == binding.Generation
}

func stateRuntimeRef(value string) bool {
	const prefix = "steward-state-"
	return strings.HasPrefix(value, prefix) &&
		lowerHex(strings.TrimPrefix(value, prefix), sha256.Size*2)
}

func decodeEvidenceFrames(raw []byte) ([][]byte, error) {
	if len(raw) == 0 || len(raw) > MaxExecutorDeltaBytes {
		return nil, errors.New("executor evidence delta is empty or oversized")
	}
	frames := make([][]byte, 0)
	for offset := 0; offset < len(raw); {
		if len(raw)-offset < 4 {
			return nil, errors.New("executor evidence delta has a truncated frame length")
		}
		length := int(binary.BigEndian.Uint32(raw[offset : offset+4]))
		if length < 1 || length > evidence.MaxEnvelopeBytes ||
			length > len(raw)-offset-4 {
			return nil, errors.New("executor evidence delta has an invalid frame length")
		}
		end := offset + 4 + length
		frames = append(frames, append([]byte(nil), raw[offset:end]...))
		offset = end
	}
	return frames, nil
}

func decodeEvidenceHash(value string) ([sha256.Size]byte, error) {
	var result [sha256.Size]byte
	if !strings.HasPrefix(value, "sha256:") {
		return result, errors.New("evidence chain hash is not SHA-256")
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	if err != nil || len(raw) != len(result) {
		return result, errors.New("evidence chain hash is not canonical")
	}
	copy(result[:], raw)
	return result, nil
}

func evidenceHash(value [sha256.Size]byte) string {
	return "sha256:" + hex.EncodeToString(value[:])
}
