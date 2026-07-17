// Package controlcapture verifies controller-sealed evidence captures without
// access to a live controller or node.
package controlcapture

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/evidence"
)

// ResultV1 retains the authenticated controller statement, exact verified
// final head, and the one qualifying activation begin/checkpoint pair.
type ResultV1 struct {
	Statement  controlprotocol.ControllerEvidenceCaptureStatementV1
	FinalHead  evidence.Head
	Begin      evidence.VerifiedReceipt
	Checkpoint evidence.VerifiedReceipt
}

// VerifyJSONV1 strictly decodes and verifies one portable capture against an
// independently pinned controller witness key.
func VerifyJSONV1(raw []byte, witnessPublic ed25519.PublicKey) (ResultV1, error) {
	capture, err := controlprotocol.DecodeControllerEvidenceCaptureV1(raw)
	if err != nil {
		return ResultV1{}, fmt.Errorf("decode controller evidence capture: %w", err)
	}
	return VerifyV1(capture, witnessPublic)
}

// VerifyV1 authenticates the controller witness and node enrollment, replays
// the exact native frames from the signed baseline, requires the replay to end
// at the exact signed final head, and finds exactly one error-free allowed begin
// followed by exactly one error-free committed checkpoint for the capture
// target. Receipts for other tenants and targets remain valid chain members and
// are deliberately ignored by the target matcher.
func VerifyV1(
	capture controlprotocol.ControllerEvidenceCaptureV1,
	witnessPublic ed25519.PublicKey,
) (ResultV1, error) {
	if err := controlprotocol.VerifyControllerEvidenceCaptureV1(capture, witnessPublic); err != nil {
		return ResultV1{}, fmt.Errorf("verify controller evidence capture witness: %w", err)
	}
	receiptPublic, err := controlprotocol.VerifyExecutorEvidenceIdentityProofV1(
		capture.Statement.IdentityProof,
	)
	if err != nil {
		return ResultV1{}, fmt.Errorf("verify controller evidence capture enrollment: %w", err)
	}
	frames, err := capture.DecodeFrames()
	if err != nil {
		return ResultV1{}, fmt.Errorf("decode controller evidence capture frames: %w", err)
	}
	baselineHash, err := decodeCaptureChainHash(capture.Statement.BaselineHead.ChainHash)
	if err != nil {
		return ResultV1{}, fmt.Errorf("decode controller evidence capture baseline: %w", err)
	}
	finalHash, err := decodeCaptureChainHash(capture.Statement.FinalHead.ChainHash)
	if err != nil {
		return ResultV1{}, fmt.Errorf("decode controller evidence capture final head: %w", err)
	}
	prior := evidence.Coordinate{
		Sequence:  capture.Statement.BaselineHead.Sequence,
		ChainHash: baselineHash,
	}

	var begin evidence.VerifiedReceipt
	var checkpoint evidence.VerifiedReceipt
	markerTarget := evidence.ActivationCaptureTarget{
		TenantID: capture.Statement.TenantID, RuntimeRef: capture.Statement.RuntimeRef,
		Generation: capture.Statement.Generation, ActivationID: capture.Statement.ActivationID,
		ActivationBeginDigest:      capture.Statement.ActivationBeginDigest,
		ActivationBeginSequence:    capture.Statement.ActivationBeginSequence,
		CapsuleDigest:              capture.Statement.CapsuleDigest,
		PolicyDigest:               capture.Statement.PolicyDigest,
		ActivationCheckpointDigest: capture.Statement.ActivationCheckpointDigest,
	}
	var markerState evidence.ActivationCaptureState
	head, err := evidence.VerifyDeltaRecords(
		frames,
		receiptPublic,
		capture.Statement.FinalHead.ReceiptNodeID,
		capture.Statement.FinalHead.ReceiptEpoch,
		prior,
		// A native evidence chain can interleave multiple tenants. Tenant
		// authorization is established by the controller-signed target, not by
		// deleting unrelated but chain-critical receipts from the export.
		func(string) bool { return true },
		func(record evidence.VerifiedReceipt) error {
			before := markerState
			var observeErr error
			markerState, observeErr = evidence.ObserveActivationCapture(
				markerTarget, markerState, record.Receipt,
			)
			if observeErr != nil {
				return observeErr
			}
			if before.ActivationBeginSequence == 0 && markerState.ActivationBeginSequence != 0 {
				begin = record
			}
			if before.ActivationCheckpointSequence == 0 &&
				markerState.ActivationCheckpointSequence != 0 {
				checkpoint = record
			}
			return nil
		},
	)
	if err != nil {
		return ResultV1{}, fmt.Errorf("replay controller evidence capture: %w", err)
	}
	final := capture.Statement.FinalHead
	if head.NodeID != final.ReceiptNodeID ||
		head.Epoch != final.ReceiptEpoch ||
		head.Sequence != final.Sequence ||
		head.ChainHash != finalHash ||
		controlprotocol.ExecutorEvidencePublicKeySHA256(receiptPublic) != final.PublicKeySHA256 {
		return ResultV1{}, errors.New("controller evidence capture replay does not end at the exact final head")
	}
	if markerState.ActivationBeginSequence != capture.Statement.ActivationBeginSequence ||
		markerState.ActivationCheckpointSequence == 0 ||
		markerState.ActivationCheckpointDigest != capture.Statement.ActivationCheckpointDigest {
		return ResultV1{}, errors.New("controller evidence capture does not contain exactly one matching target activation begin and checkpoint")
	}
	return ResultV1{
		Statement:  capture.Statement,
		FinalHead:  head,
		Begin:      begin,
		Checkpoint: checkpoint,
	}, nil
}

func decodeCaptureChainHash(value string) ([sha256.Size]byte, error) {
	var result [sha256.Size]byte
	if !strings.HasPrefix(value, "sha256:") {
		return result, errors.New("chain hash is not SHA-256")
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	if err != nil || len(raw) != len(result) || "sha256:"+hex.EncodeToString(raw) != value {
		return result, errors.New("chain hash is not canonical")
	}
	copy(result[:], raw)
	return result, nil
}
