package controlstore

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/hardrails/steward/internal/activationcanary"
	"github.com/hardrails/steward/internal/controlauth"
	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/evidence"
)

// EvidenceCaptureArmRequest binds one bounded capture to an exact activation
// target. TTL is compared with the originally persisted lifetime before a new
// expiry is derived, so an exact retry cannot silently extend the capture.
type EvidenceCaptureArmRequest struct {
	CaptureID             string
	RequestID             string
	NodeID                string
	TenantID              string
	RuntimeRef            string
	Generation            uint64
	ActivationID          string
	ActivationBeginDigest string
	TTL                   time.Duration
}

// EvidenceCaptureExportSnapshot is an immutable copy of one sealed capture.
// RevisionDigest lets a caller sign outside Store.mu and then confirm that the
// exact capture, rather than merely its identifier, is still retained.
type EvidenceCaptureExportSnapshot struct {
	Capture        EvidenceCapture
	IdentityProof  controlprotocol.ExecutorEvidenceIdentityProofV1
	Frames         [][]byte
	RevisionDigest string
}

// Statement constructs the complete unsigned protocol statement from one
// sealed snapshot. The caller supplies the controller identity and export time
// because signing authority deliberately lives outside the durable store.
func (snapshot EvidenceCaptureExportSnapshot) Statement(
	controllerInstanceID string,
	exportedAt time.Time,
) (controlprotocol.ControllerEvidenceCaptureStatementV1, error) {
	if exportedAt.IsZero() {
		return controlprotocol.ControllerEvidenceCaptureStatementV1{},
			errors.New("evidence capture export time is required")
	}
	statement := controlprotocol.ControllerEvidenceCaptureStatementV1{
		ProtocolVersion:            controlprotocol.ControllerEvidenceCaptureProtocolV1,
		ControllerInstanceID:       controllerInstanceID,
		CaptureID:                  snapshot.Capture.CaptureID,
		NodeID:                     snapshot.Capture.NodeID,
		TenantID:                   snapshot.Capture.TenantID,
		RuntimeRef:                 snapshot.Capture.RuntimeRef,
		Generation:                 snapshot.Capture.Generation,
		ActivationID:               snapshot.Capture.ActivationID,
		CanaryCommandID:            snapshot.Capture.CanaryCommandID,
		ActivationBeginDigest:      snapshot.Capture.ActivationBeginDigest,
		ActivationBeginSequence:    snapshot.Capture.ActivationBeginSequence,
		ActivationCheckpointDigest: snapshot.Capture.ActivationCheckpointDigest,
		CapsuleDigest:              snapshot.Capture.CapsuleDigest,
		PolicyDigest:               snapshot.Capture.PolicyDigest,
		IdentityProof:              snapshot.IdentityProof,
		BaselineHead:               snapshot.Capture.BaselineHead,
		FinalHead:                  snapshot.Capture.FinalHead,
		FrameCount:                 uint32(len(snapshot.Frames)),
		FramesDigest:               controlprotocol.ControllerEvidenceCaptureFramesDigestV1(snapshot.Frames),
		ArmedAt:                    snapshot.Capture.ArmedAt,
		ObservedAt:                 snapshot.Capture.ObservedAt,
		SealedAt:                   snapshot.Capture.SealedAt,
		ExportedAt:                 canonicalTimestamp(exportedAt),
	}
	if err := statement.Validate(); err != nil {
		return controlprotocol.ControllerEvidenceCaptureStatementV1{}, err
	}
	return statement, nil
}

func (store *Store) ArmEvidenceCapture(
	actor controlauth.Identity,
	request EvidenceCaptureArmRequest,
	now time.Time,
) (EvidenceCapture, bool, error) {
	if store == nil {
		return EvidenceCapture{}, false, ErrUnavailable
	}
	if !controlauth.IsSiteAdmin(actor) {
		return EvidenceCapture{}, false, ErrForbidden
	}
	if now.IsZero() ||
		!validRecordID(request.CaptureID, 128) || !validRecordID(request.RequestID, 128) ||
		!validRecordID(request.NodeID, 128) || !validRecordID(request.TenantID, 128) ||
		!validExecutorRuntimeRef(request.RuntimeRef) || request.Generation == 0 ||
		!validRecordID(request.ActivationID, 128) ||
		!validSHA256Digest(request.ActivationBeginDigest) ||
		request.TTL < MinEvidenceCaptureTTL || request.TTL > MaxEvidenceCaptureTTL ||
		request.TTL%time.Second != 0 {
		return EvidenceCapture{}, false, invalid("evidence capture request identity or time is invalid")
	}
	now = now.UTC()
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.availableLocked(); err != nil {
		return EvidenceCapture{}, false, err
	}
	if err := store.revalidateOperatorLocked(actor); err != nil {
		return EvidenceCapture{}, false, err
	}
	if err := store.expireEvidenceCapturesLocked(now); err != nil {
		return EvidenceCapture{}, false, err
	}
	if existing, ok := store.current.captures[request.CaptureID]; ok {
		if evidenceCaptureArmEqual(existing, request) {
			return evidenceCaptureView(existing), false, nil
		}
		return EvidenceCapture{}, false, ErrConflict
	}
	expires := canonicalTimestamp(now.Add(request.TTL))
	for _, existing := range store.current.captures {
		if existing.RequestID == request.RequestID {
			return EvidenceCapture{}, false, ErrConflict
		}
		if existing.State == EvidenceCaptureArmed && existing.NodeID == request.NodeID {
			return EvidenceCapture{}, false, ErrConflict
		}
	}
	if len(store.current.captures) >= MaxEvidenceCapturesRetained {
		return EvidenceCapture{}, false, ErrCapacityExceeded
	}
	active, reserved := evidenceCaptureUsage(store.current.captures)
	if active >= MaxEvidenceCapturesActive ||
		reserved > MaxEvidenceCaptureAggregateBytes-MaxEvidenceCaptureDecodedBytes {
		return EvidenceCapture{}, false, ErrCapacityExceeded
	}
	tenant, ok := store.current.tenants[request.TenantID]
	if !ok || !tenant.Active {
		return EvidenceCapture{}, false, ErrNotFound
	}
	node, ok := store.current.nodes[request.NodeID]
	if !ok || !node.Active || !tenantMember(node.TenantIDs, request.TenantID) || node.Evidence == nil {
		return EvidenceCapture{}, false, ErrNotFound
	}
	if node.Evidence.Finding != nil {
		return EvidenceCapture{}, false, ErrConflict
	}
	witnessedAt := node.Evidence.PinnedAt
	if node.Evidence.AdvancedAt != "" {
		witnessedAt = node.Evidence.AdvancedAt
	}
	witnessed, _ := parseTimestamp(witnessedAt)
	if now.Before(witnessed) {
		return EvidenceCapture{}, false, invalid("evidence capture time predates the witnessed node head")
	}
	head := executorEvidenceHead(*node.Evidence)
	capture := storedEvidenceCapture{
		CaptureID: request.CaptureID, RequestID: request.RequestID,
		NodeID: request.NodeID, TenantID: request.TenantID,
		RuntimeRef: request.RuntimeRef, Generation: request.Generation,
		ActivationID: request.ActivationID, ActivationBeginDigest: request.ActivationBeginDigest,
		State:        EvidenceCaptureArmed,
		BaselineHead: head, FinalHead: head,
		ArmedAt: canonicalTimestamp(now), ExpiresAt: expires,
		IdentityProof: node.Evidence.IdentityProof,
		FramesBase64:  []string{},
		Frames:        [][]byte{},
	}
	if err := store.applyMutationsLocked(captureMutation(capture)); err != nil {
		return EvidenceCapture{}, false, err
	}
	return evidenceCaptureView(capture), true, nil
}

func (store *Store) GetEvidenceCapture(
	actor controlauth.Identity,
	captureID string,
	now time.Time,
) (EvidenceCapture, bool, error) {
	if store == nil {
		return EvidenceCapture{}, false, ErrUnavailable
	}
	if !controlauth.IsSiteAdmin(actor) {
		return EvidenceCapture{}, false, ErrForbidden
	}
	if !validRecordID(captureID, 128) || now.IsZero() {
		return EvidenceCapture{}, false, invalid("evidence capture identity or observation time is invalid")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.availableLocked(); err != nil {
		return EvidenceCapture{}, false, err
	}
	if err := store.revalidateOperatorLocked(actor); err != nil {
		return EvidenceCapture{}, false, err
	}
	if err := store.expireEvidenceCapturesLocked(now.UTC()); err != nil {
		return EvidenceCapture{}, false, err
	}
	capture, ok := store.current.captures[captureID]
	if !ok {
		return EvidenceCapture{}, false, nil
	}
	return evidenceCaptureView(capture), true, nil
}

func (store *Store) DeleteEvidenceCapture(
	actor controlauth.Identity,
	nodeID string,
	captureID string,
	now time.Time,
) (bool, error) {
	if store == nil {
		return false, ErrUnavailable
	}
	if !controlauth.IsSiteAdmin(actor) {
		return false, ErrForbidden
	}
	if !validRecordID(nodeID, 128) || !validRecordID(captureID, 128) || now.IsZero() {
		return false, invalid("evidence capture identity or deletion time is invalid")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.availableLocked(); err != nil {
		return false, err
	}
	if err := store.revalidateOperatorLocked(actor); err != nil {
		return false, err
	}
	if err := store.expireEvidenceCapturesLocked(now.UTC()); err != nil {
		return false, err
	}
	capture, ok := store.current.captures[captureID]
	if !ok || capture.NodeID != nodeID {
		return false, nil
	}
	if err := store.applyMutationsLocked(mutation{Kind: mutationCaptureDelete, CaptureID: captureID}); err != nil {
		return false, err
	}
	return true, nil
}

func (store *Store) SealEvidenceCapture(
	actor controlauth.Identity,
	nodeID string,
	captureID string,
	canaryCommandID string,
	now time.Time,
) (EvidenceCapture, bool, error) {
	if store == nil {
		return EvidenceCapture{}, false, ErrUnavailable
	}
	if !controlauth.IsSiteAdmin(actor) {
		return EvidenceCapture{}, false, ErrForbidden
	}
	if !validRecordID(nodeID, 128) || !validRecordID(captureID, 128) ||
		!validRecordID(canaryCommandID, 256) || now.IsZero() {
		return EvidenceCapture{}, false, invalid("evidence capture or canary command identity is invalid")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.availableLocked(); err != nil {
		return EvidenceCapture{}, false, err
	}
	if err := store.revalidateOperatorLocked(actor); err != nil {
		return EvidenceCapture{}, false, err
	}
	if err := store.expireEvidenceCapturesLocked(now.UTC()); err != nil {
		return EvidenceCapture{}, false, err
	}
	capture, ok := store.current.captures[captureID]
	if !ok || capture.NodeID != nodeID {
		return EvidenceCapture{}, false, ErrNotFound
	}
	if capture.State == EvidenceCaptureSealed {
		if capture.CanaryCommandID == canaryCommandID {
			return evidenceCaptureView(capture), false, nil
		}
		return EvidenceCapture{}, false, ErrConflict
	}
	if capture.State != EvidenceCaptureObserved {
		return EvidenceCapture{}, false, ErrConflict
	}
	observedAt, _ := parseTimestamp(capture.ObservedAt)
	if now.Before(observedAt) {
		return EvidenceCapture{}, false, invalid("evidence capture seal predates observation")
	}
	command, ok := store.current.commands[commandKey(capture.TenantID, capture.NodeID, canaryCommandID)]
	if !ok || command.CommandKind != "activation-canary" ||
		command.DeliveryProtocol != controlprotocol.ExecutorProtocolV4 ||
		command.State != CommandTerminal || command.Terminal == nil ||
		command.Terminal.Report.Status != controlprotocol.ExecutorStatusDone ||
		command.Terminal.ActivationCanary == nil ||
		command.SignedRuntimeRef != capture.RuntimeRef ||
		command.SignedInstanceGeneration != capture.Generation {
		return EvidenceCapture{}, false, ErrConflict
	}
	result := command.Terminal.ActivationCanary
	if err := result.Validate(); err != nil || result.ActivationID != capture.ActivationID ||
		result.ActivationCheckpointDigest != capture.ActivationCheckpointDigest {
		return EvidenceCapture{}, false, ErrConflict
	}
	statement, err := parseCommandStatement(command.CommandDSSE)
	if err != nil {
		return EvidenceCapture{}, false, ErrConflict
	}
	canary, err := activationcanary.ParseCommandV1(statement.Payload)
	if err != nil || statement.TenantID != capture.TenantID || statement.NodeID != capture.NodeID ||
		statement.RuntimeRef != capture.RuntimeRef || statement.InstanceGeneration != capture.Generation ||
		canary.ActivationID != capture.ActivationID || canary.Admission.RuntimeRef != capture.RuntimeRef ||
		canary.Admission.Generation != capture.Generation ||
		canary.Admission.ActivationBeginDigest != capture.ActivationBeginDigest ||
		canary.Admission.CapsuleDigest != capture.CapsuleDigest ||
		canary.Admission.PolicyDigest != capture.PolicyDigest {
		return EvidenceCapture{}, false, ErrConflict
	}
	capture.State = EvidenceCaptureSealed
	capture.CanaryCommandID = canaryCommandID
	capture.SealedAt = canonicalTimestamp(now)
	if err := store.applyMutationsLocked(captureMutation(capture)); err != nil {
		return EvidenceCapture{}, false, err
	}
	return evidenceCaptureView(capture), true, nil
}

func (store *Store) SnapshotEvidenceCaptureExport(
	actor controlauth.Identity,
	captureID string,
	now time.Time,
) (EvidenceCaptureExportSnapshot, bool, error) {
	if store == nil {
		return EvidenceCaptureExportSnapshot{}, false, ErrUnavailable
	}
	if !controlauth.IsSiteAdmin(actor) {
		return EvidenceCaptureExportSnapshot{}, false, ErrForbidden
	}
	if !validRecordID(captureID, 128) || now.IsZero() {
		return EvidenceCaptureExportSnapshot{}, false, invalid("evidence capture identity or export time is invalid")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.availableLocked(); err != nil {
		return EvidenceCaptureExportSnapshot{}, false, err
	}
	if err := store.revalidateOperatorLocked(actor); err != nil {
		return EvidenceCaptureExportSnapshot{}, false, err
	}
	if err := store.expireEvidenceCapturesLocked(now.UTC()); err != nil {
		return EvidenceCaptureExportSnapshot{}, false, err
	}
	capture, ok := store.current.captures[captureID]
	if !ok {
		return EvidenceCaptureExportSnapshot{}, false, nil
	}
	if capture.State != EvidenceCaptureSealed {
		return EvidenceCaptureExportSnapshot{}, false, ErrConflict
	}
	digest, err := evidenceCaptureRevisionDigest(capture)
	if err != nil {
		return EvidenceCaptureExportSnapshot{}, false, ErrConflict
	}
	return EvidenceCaptureExportSnapshot{
		Capture: evidenceCaptureView(capture), IdentityProof: capture.IdentityProof,
		Frames: cloneEvidenceCaptureFrames(capture.Frames), RevisionDigest: digest,
	}, true, nil
}

func (store *Store) EvidenceCaptureSnapshotCurrent(
	actor controlauth.Identity,
	snapshot EvidenceCaptureExportSnapshot,
	now time.Time,
) (bool, error) {
	if store == nil {
		return false, ErrUnavailable
	}
	if !controlauth.IsSiteAdmin(actor) {
		return false, ErrForbidden
	}
	if !validRecordID(snapshot.Capture.CaptureID, 128) ||
		!validSHA256Digest(snapshot.RevisionDigest) || now.IsZero() {
		return false, invalid("evidence capture export snapshot is invalid")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.availableLocked(); err != nil {
		return false, err
	}
	if err := store.revalidateOperatorLocked(actor); err != nil {
		return false, err
	}
	if err := store.expireEvidenceCapturesLocked(now.UTC()); err != nil {
		return false, err
	}
	capture, ok := store.current.captures[snapshot.Capture.CaptureID]
	if !ok || capture.State != EvidenceCaptureSealed {
		return false, nil
	}
	digest, err := evidenceCaptureRevisionDigest(capture)
	return err == nil && digest == snapshot.RevisionDigest, nil
}

func evidenceCaptureArmEqual(
	capture storedEvidenceCapture,
	request EvidenceCaptureArmRequest,
) bool {
	armedAt, armedErr := parseTimestamp(capture.ArmedAt)
	expiresAt, expiresErr := parseTimestamp(capture.ExpiresAt)
	return capture.CaptureID == request.CaptureID && capture.RequestID == request.RequestID &&
		capture.NodeID == request.NodeID && capture.TenantID == request.TenantID &&
		capture.RuntimeRef == request.RuntimeRef && capture.Generation == request.Generation &&
		capture.ActivationID == request.ActivationID &&
		capture.ActivationBeginDigest == request.ActivationBeginDigest &&
		armedErr == nil && expiresErr == nil &&
		expiresAt.Sub(armedAt) == request.TTL
}

func (store *Store) expireEvidenceCapturesLocked(now time.Time) error {
	mutations := make([]mutation, 0)
	for _, retained := range store.current.captures {
		if retained.State != EvidenceCaptureArmed {
			continue
		}
		expires, _ := parseTimestamp(retained.ExpiresAt)
		if now.Before(expires) {
			continue
		}
		capture := cloneStoredEvidenceCapture(retained)
		capture.State = EvidenceCaptureExpired
		capture.ExpiredAt = canonicalTimestamp(now)
		capture.ActivationBeginSequence = 0
		capture.ActivationLatestStartSequence = 0
		capture.CapsuleDigest = ""
		capture.PolicyDigest = ""
		mutations = append(mutations, captureMutation(capture))
	}
	if len(mutations) == 0 {
		return nil
	}
	return store.applyMutationsLocked(mutations...)
}

func captureMutation(capture storedEvidenceCapture) mutation {
	cloned := cloneStoredEvidenceCapture(capture)
	return mutation{Kind: mutationCapture, Capture: &cloned}
}

func evidenceCaptureRevisionDigest(capture storedEvidenceCapture) (string, error) {
	raw, err := json.Marshal(capture)
	if err != nil {
		return "", err
	}
	return digestBytes(raw), nil
}

// evidenceCaptureMutationForReportLocked derives one capture transition from
// the same authenticated receipt summaries used to advance the durable node
// witness. It never returns an error: capture-specific contradictions become a
// failed capture and cannot reject an otherwise valid evidence report.
func (store *Store) evidenceCaptureMutationForReportLocked(
	nodeID string,
	report verifiedExecutorEvidenceReport,
	frames [][]byte,
	now time.Time,
) *mutation {
	var retained storedEvidenceCapture
	found := false
	for _, candidate := range store.current.captures {
		if candidate.NodeID == nodeID && candidate.State == EvidenceCaptureArmed {
			retained = candidate
			found = true
			break
		}
	}
	if !found {
		return nil
	}
	capture := cloneStoredEvidenceCapture(retained)
	// A controller clock rollback must not turn a capture-local timestamp into
	// an invalid mutation that rejects the otherwise authenticated node witness
	// advance. Clamp only capture metadata; the evidence receipt coordinates
	// remain the signed source of ordering truth.
	armedAt, _ := parseTimestamp(capture.ArmedAt)
	if now.Before(armedAt) {
		now = armedAt
	}
	if capture.FinalHead.Sequence != report.baseSequence ||
		capture.FinalHead.ChainHash != report.baseChainHash {
		failEvidenceCapture(&capture, EvidenceCaptureFailureCoordinate, now)
		change := captureMutation(capture)
		return &change
	}
	if report.action == executorEvidenceFinding || report.action == executorEvidenceBlocked {
		failEvidenceCapture(&capture, EvidenceCaptureFailureFinding, now)
		change := captureMutation(capture)
		return &change
	}
	if report.action != executorEvidenceAdvance {
		return nil
	}
	if len(report.receipts) != len(frames) || len(frames) == 0 {
		failEvidenceCapture(&capture, EvidenceCaptureFailureContradiction, now)
		change := captureMutation(capture)
		return &change
	}
	target := evidenceCaptureActivationTarget(capture, false)
	markerState := evidence.ActivationCaptureState{
		ActivationBeginSequence:      capture.ActivationBeginSequence,
		LatestLifecycleStartSequence: capture.ActivationLatestStartSequence,
		CapsuleDigest:                capture.CapsuleDigest,
		PolicyDigest:                 capture.PolicyDigest,
	}
	for _, receipt := range report.receipts {
		var markerErr error
		markerState, markerErr = evidence.ObserveActivationCapture(target, markerState, receipt)
		if markerErr != nil {
			failEvidenceCapture(&capture, EvidenceCaptureFailureContradiction, now)
			change := captureMutation(capture)
			return &change
		}
	}
	additionalBytes := 0
	for _, frame := range frames {
		if additionalBytes > MaxEvidenceCaptureDecodedBytes-len(frame) {
			failEvidenceCapture(&capture, EvidenceCaptureFailureOverflow, now)
			change := captureMutation(capture)
			return &change
		}
		additionalBytes += len(frame)
	}
	if len(capture.Frames) > MaxEvidenceCaptureFrames-len(frames) ||
		capture.CapturedBytes > MaxEvidenceCaptureDecodedBytes-additionalBytes {
		failEvidenceCapture(&capture, EvidenceCaptureFailureOverflow, now)
		change := captureMutation(capture)
		return &change
	}
	for _, frame := range frames {
		capture.FramesBase64 = append(
			capture.FramesBase64,
			base64.StdEncoding.EncodeToString(frame),
		)
	}
	capture.Frames = append(capture.Frames, cloneEvidenceCaptureFrames(frames)...)
	capture.FrameCount = len(capture.Frames)
	capture.CapturedBytes += additionalBytes
	capture.FinalHead = report.head
	capture.ActivationBeginSequence = markerState.ActivationBeginSequence
	capture.ActivationLatestStartSequence = markerState.LatestLifecycleStartSequence
	capture.CapsuleDigest = markerState.CapsuleDigest
	capture.PolicyDigest = markerState.PolicyDigest
	if markerState.ActivationCheckpointSequence != 0 {
		capture.State = EvidenceCaptureObserved
		capture.ActivationCheckpointDigest = markerState.ActivationCheckpointDigest
		capture.ObservedAt = canonicalTimestamp(now)
	}
	change := captureMutation(capture)
	return &change
}

func failEvidenceCapture(
	capture *storedEvidenceCapture,
	reason EvidenceCaptureFailure,
	now time.Time,
) {
	capture.State = EvidenceCaptureFailed
	capture.Failure = reason
	capture.FailedAt = canonicalTimestamp(now)
	capture.CapsuleDigest = ""
	capture.PolicyDigest = ""
	capture.ActivationBeginSequence = 0
	capture.ActivationLatestStartSequence = 0
	capture.ActivationCheckpointDigest = ""
	capture.CanaryCommandID = ""
	capture.ObservedAt = ""
	capture.SealedAt = ""
	capture.ExpiredAt = ""
}

// applyExecutorEvidenceMutationsLocked keeps an optional capture from turning
// its larger retained frame mutation into a denial of ordinary evidence
// witnessing. Capacity fallback first retains a small explicit failure, then
// atomically drops the capture if even that record cannot fit. The final
// two-step fallback deletes before applying the witness so a crash can lose
// only the optional capture, never publish an unwitnessed capture coordinate.
func (store *Store) applyExecutorEvidenceMutationsLocked(
	base []mutation,
	capture *mutation,
	now time.Time,
) error {
	if capture == nil {
		return store.applyMutationsLocked(base...)
	}
	combined := append(append([]mutation(nil), base...), *capture)
	if err := store.applyMutationsLocked(combined...); err == nil {
		return nil
	} else if !errors.Is(err, ErrCapacityExceeded) {
		return err
	}
	if capture.Capture == nil {
		return ErrCapacityExceeded
	}

	failed := cloneStoredEvidenceCapture(*capture.Capture)
	armedAt, _ := parseTimestamp(failed.ArmedAt)
	if now.Before(armedAt) {
		now = armedAt
	}
	failEvidenceCapture(&failed, EvidenceCaptureFailureCapacity, now)
	failed.FramesBase64 = []string{}
	failed.Frames = [][]byte{}
	failed.FrameCount = 0
	failed.CapturedBytes = 0
	failed.FinalHead = failed.BaselineHead
	failedMutation := captureMutation(failed)
	withFailure := append(append([]mutation(nil), base...), failedMutation)
	if err := store.applyMutationsLocked(withFailure...); err == nil {
		return nil
	} else if !errors.Is(err, ErrCapacityExceeded) {
		return err
	}

	deleteMutation := mutation{Kind: mutationCaptureDelete, CaptureID: failed.CaptureID}
	withDelete := append(append([]mutation(nil), base...), deleteMutation)
	if err := store.applyMutationsLocked(withDelete...); err == nil {
		return nil
	} else if !errors.Is(err, ErrCapacityExceeded) {
		return err
	}
	if err := store.applyMutationsLocked(deleteMutation); err != nil {
		return err
	}
	return store.applyMutationsLocked(base...)
}

func evidenceCaptureActivationTarget(
	capture storedEvidenceCapture,
	complete bool,
) evidence.ActivationCaptureTarget {
	target := evidence.ActivationCaptureTarget{
		TenantID: capture.TenantID, RuntimeRef: capture.RuntimeRef,
		Generation: capture.Generation, ActivationID: capture.ActivationID,
		ActivationBeginDigest: capture.ActivationBeginDigest,
	}
	if capture.ActivationBeginSequence != 0 {
		target.ActivationBeginSequence = capture.ActivationBeginSequence
		target.CapsuleDigest = capture.CapsuleDigest
		target.PolicyDigest = capture.PolicyDigest
	}
	if complete {
		target.ActivationCheckpointDigest = capture.ActivationCheckpointDigest
	}
	return target
}

// validateRecoveredEvidenceCaptures authenticates exact retained frames once
// after snapshot and WAL recovery converge. Live report application already
// obtains these frames from the single receipt-verification pass.
func validateRecoveredEvidenceCaptures(current state) error {
	for _, capture := range current.captures {
		if len(capture.Frames) == 0 {
			continue
		}
		public, err := controlprotocol.VerifyExecutorEvidenceIdentityProofV1(capture.IdentityProof)
		if err != nil || len(public) != ed25519.PublicKeySize {
			return errors.New("recovered evidence capture has an invalid receipt identity")
		}
		baseHash, err := decodeExecutorEvidenceHash(capture.BaselineHead.ChainHash)
		if err != nil {
			return errors.New("recovered evidence capture has an invalid baseline")
		}
		node, ok := current.nodes[capture.NodeID]
		if !ok {
			return errors.New("recovered evidence capture references a missing node")
		}
		verifyTargetMarkers := capture.State == EvidenceCaptureArmed ||
			capture.State == EvidenceCaptureObserved || capture.State == EvidenceCaptureSealed
		markerTarget := evidenceCaptureActivationTarget(
			capture,
			capture.State == EvidenceCaptureObserved || capture.State == EvidenceCaptureSealed,
		)
		var markerState evidence.ActivationCaptureState
		derived, err := evidence.VerifyDeltaRecords(
			capture.Frames,
			public,
			capture.BaselineHead.ReceiptNodeID,
			capture.BaselineHead.ReceiptEpoch,
			evidence.Coordinate{Sequence: capture.BaselineHead.Sequence, ChainHash: baseHash},
			func(tenantID string) bool { return tenantMember(node.TenantIDs, tenantID) },
			func(record evidence.VerifiedReceipt) error {
				if !verifyTargetMarkers {
					return nil
				}
				var observeErr error
				markerState, observeErr = evidence.ObserveActivationCapture(
					markerTarget, markerState, record.Receipt,
				)
				return observeErr
			},
		)
		if err != nil {
			return fmt.Errorf("recovered evidence capture frames are invalid: %w", err)
		}
		if derived.Sequence != capture.FinalHead.Sequence ||
			encodeExecutorEvidenceHash(derived.ChainHash) != capture.FinalHead.ChainHash {
			return errors.New("recovered evidence capture frames do not end at the retained head")
		}
		switch capture.State {
		case EvidenceCaptureArmed:
			if markerState.ActivationBeginSequence != capture.ActivationBeginSequence ||
				markerState.ActivationCheckpointSequence != 0 ||
				markerState.LatestLifecycleStartSequence != capture.ActivationLatestStartSequence ||
				markerState.CapsuleDigest != capture.CapsuleDigest ||
				markerState.PolicyDigest != capture.PolicyDigest {
				return errors.New("recovered armed evidence capture marker state is inconsistent")
			}
		case EvidenceCaptureObserved, EvidenceCaptureSealed:
			if markerState.ActivationBeginSequence != capture.ActivationBeginSequence ||
				markerState.ActivationCheckpointSequence == 0 ||
				markerState.LatestLifecycleStartSequence != capture.ActivationLatestStartSequence ||
				markerState.CapsuleDigest != capture.CapsuleDigest ||
				markerState.PolicyDigest != capture.PolicyDigest ||
				markerState.ActivationCheckpointDigest != capture.ActivationCheckpointDigest {
				return errors.New("recovered observed evidence capture does not contain exactly one begin and checkpoint")
			}
		}
	}
	return nil
}
