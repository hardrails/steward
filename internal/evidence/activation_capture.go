package evidence

import (
	"errors"
	"strings"
)

// ActivationCaptureTarget is the closed identity expected in one controller
// evidence capture. Capsule, policy, checkpoint digest, and begin sequence are
// optional expectations while a live capture is waiting for its begin; an
// offline verifier supplies all of them from the signed statement.
type ActivationCaptureTarget struct {
	TenantID                   string
	RuntimeRef                 string
	Generation                 uint64
	ActivationID               string
	ActivationBeginDigest      string
	ActivationBeginSequence    uint64
	CapsuleDigest              string
	PolicyDigest               string
	ActivationCheckpointDigest string
}

// ActivationCaptureState is the bounded result of replaying signed receipts
// in order. LatestLifecycleStartSequence is retained so a later evidence batch
// cannot hide a post-start workload compensation.
type ActivationCaptureState struct {
	ActivationBeginSequence      uint64
	ActivationCheckpointSequence uint64
	LatestLifecycleStartSequence uint64
	CapsuleDigest                string
	PolicyDigest                 string
	ActivationCheckpointDigest   string
}

// ObserveActivationCapture applies one authenticated receipt to a closed
// activation capture state. Unrelated receipts are ignored. Related marker
// contradictions and lifecycle invalidations fail closed. Callers may seed a
// begin-only state from a prior bounded batch and continue replay safely.
func ObserveActivationCapture(
	target ActivationCaptureTarget,
	state ActivationCaptureState,
	receipt Receipt,
) (ActivationCaptureState, error) {
	if !validActivationCaptureTarget(target) || !validActivationCaptureState(state) ||
		receipt.Sequence == 0 {
		return ActivationCaptureState{}, errors.New("activation capture target, state, or receipt is invalid")
	}

	switch receipt.Type {
	case ActivationBegin, ActivationCheckpoint:
		if !activationCaptureMarkerRelated(receipt.Event, target) {
			return state, nil
		}
		if !activationCaptureMarkerIdentityMatches(receipt.Event, target) {
			return ActivationCaptureState{}, errors.New("activation capture contains a conflicting target marker")
		}
		if receipt.Type == ActivationBegin {
			if state.ActivationBeginSequence != 0 || state.ActivationCheckpointSequence != 0 ||
				receipt.Outcome != Allowed || receipt.ErrorCode != "" ||
				receipt.MetadataHash != target.ActivationBeginDigest ||
				!activationCaptureDigest(receipt.CapsuleDigest) ||
				!activationCaptureDigest(receipt.PolicyDigest) ||
				(target.ActivationBeginSequence != 0 &&
					receipt.Sequence != target.ActivationBeginSequence) ||
				(target.CapsuleDigest != "" && receipt.CapsuleDigest != target.CapsuleDigest) ||
				(target.PolicyDigest != "" && receipt.PolicyDigest != target.PolicyDigest) {
				return ActivationCaptureState{}, errors.New("activation capture contains a conflicting target activation begin")
			}
			state.ActivationBeginSequence = receipt.Sequence
			state.CapsuleDigest = receipt.CapsuleDigest
			state.PolicyDigest = receipt.PolicyDigest
			return state, nil
		}
		if state.ActivationBeginSequence == 0 || state.ActivationCheckpointSequence != 0 ||
			receipt.Sequence <= state.ActivationBeginSequence ||
			receipt.Outcome != Committed || receipt.ErrorCode != "" ||
			receipt.CapsuleDigest != state.CapsuleDigest ||
			receipt.PolicyDigest != state.PolicyDigest ||
			!activationCaptureDigest(receipt.MetadataHash) ||
			(target.ActivationCheckpointDigest != "" &&
				receipt.MetadataHash != target.ActivationCheckpointDigest) {
			return ActivationCaptureState{}, errors.New("activation capture contains a conflicting target checkpoint")
		}
		state.ActivationCheckpointSequence = receipt.Sequence
		state.ActivationCheckpointDigest = receipt.MetadataHash
		return state, nil
	}

	if state.ActivationBeginSequence == 0 ||
		!activationCaptureRuntimeEventMatches(receipt.Event, target, state) {
		return state, nil
	}
	switch receipt.Type {
	case LifecycleStart:
		if receipt.Outcome == Committed && receipt.GrantID == "workload" {
			state.LatestLifecycleStartSequence = receipt.Sequence
		}
	case JournalCompensate:
		if receipt.Outcome == Compensated && receipt.GrantID != "state" &&
			state.LatestLifecycleStartSequence != 0 &&
			receipt.Sequence > state.LatestLifecycleStartSequence {
			return ActivationCaptureState{}, errors.New("activation capture contains compensation after target lifecycle start")
		}
	case LifecycleStop, LifecycleDestroy, Drift, Revocation:
		if receipt.Outcome == Committed || receipt.Outcome == Compensated {
			return ActivationCaptureState{}, errors.New("activation capture contains a lifecycle-invalidating target event")
		}
	case StatePurge:
		// State purge uses a separate opaque runtime identity. Matching follows
		// the evidence log's fail-closed state scope: runtime is deliberately
		// ignored while tenant, generation, capsule, policy, and grant remain
		// exact.
		if receipt.GrantID == "state" &&
			(receipt.Outcome == Committed || receipt.Outcome == Compensated) {
			return ActivationCaptureState{}, errors.New("activation capture contains a state-invalidating target purge")
		}
	}
	return state, nil
}

func validActivationCaptureTarget(target ActivationCaptureTarget) bool {
	if !validText(target.TenantID, 128) || !validText(target.RuntimeRef, 512) ||
		target.Generation == 0 || !validText(target.ActivationID, 256) ||
		!activationCaptureDigest(target.ActivationBeginDigest) {
		return false
	}
	if (target.CapsuleDigest == "") != (target.PolicyDigest == "") {
		return false
	}
	return (target.CapsuleDigest == "" || activationCaptureDigest(target.CapsuleDigest)) &&
		(target.PolicyDigest == "" || activationCaptureDigest(target.PolicyDigest)) &&
		(target.ActivationCheckpointDigest == "" ||
			activationCaptureDigest(target.ActivationCheckpointDigest))
}

func validActivationCaptureState(state ActivationCaptureState) bool {
	if state.ActivationBeginSequence == 0 {
		return state.ActivationCheckpointSequence == 0 &&
			state.LatestLifecycleStartSequence == 0 && state.CapsuleDigest == "" &&
			state.PolicyDigest == "" && state.ActivationCheckpointDigest == ""
	}
	if !activationCaptureDigest(state.CapsuleDigest) ||
		!activationCaptureDigest(state.PolicyDigest) ||
		(state.LatestLifecycleStartSequence != 0 &&
			state.LatestLifecycleStartSequence <= state.ActivationBeginSequence) {
		return false
	}
	if state.ActivationCheckpointSequence == 0 {
		return state.ActivationCheckpointDigest == ""
	}
	return state.ActivationCheckpointSequence > state.ActivationBeginSequence &&
		activationCaptureDigest(state.ActivationCheckpointDigest)
}

func activationCaptureMarkerRelated(event Event, target ActivationCaptureTarget) bool {
	sameCoordinate := event.TenantID == target.TenantID &&
		event.RuntimeRef == target.RuntimeRef && event.Generation == target.Generation
	sameActivation := event.TenantID == target.TenantID &&
		event.GrantID == target.ActivationID
	return sameCoordinate || sameActivation
}

func activationCaptureMarkerIdentityMatches(event Event, target ActivationCaptureTarget) bool {
	return event.TenantID == target.TenantID && event.RuntimeRef == target.RuntimeRef &&
		event.Generation == target.Generation && event.GrantID == target.ActivationID
}

func activationCaptureRuntimeEventMatches(
	event Event,
	target ActivationCaptureTarget,
	state ActivationCaptureState,
) bool {
	if event.TenantID != target.TenantID || event.Generation != target.Generation ||
		event.CapsuleDigest != state.CapsuleDigest || event.PolicyDigest != state.PolicyDigest {
		return false
	}
	if event.Type == StatePurge {
		return event.GrantID == "state"
	}
	return event.RuntimeRef == target.RuntimeRef
}

func activationCaptureDigest(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, character := range strings.TrimPrefix(value, "sha256:") {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}
