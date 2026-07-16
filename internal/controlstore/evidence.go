package controlstore

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/hardrails/steward/internal/controlauth"
	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/evidence"
)

type executorEvidenceSnapshot struct {
	credentialTenantIDs []string
	nodeTenantIDs       []string
	witness             EvidenceWitness
}

type executorEvidenceAction byte

const (
	executorEvidenceNoop executorEvidenceAction = iota
	executorEvidenceAdvance
	executorEvidenceFinding
	executorEvidenceBlocked
)

type verifiedExecutorEvidenceReport struct {
	action        executorEvidenceAction
	baseSequence  uint64
	baseChainHash string
	head          controlprotocol.ExecutorEvidenceHeadV1
	batchStart    uint64
	batchEnd      uint64
	batchDigest   string
	reason        EvidenceFindingReason
}

// PollExecutorEvidence authenticates the node and pinned receipt identity
// before minting a short-lived challenge. Steward retains only the latest
// challenge per credential in bounded memory so exact report replays do not
// repeat expensive signature verification. Polling does not mutate the durable
// checkpoint.
func (store *Store) PollExecutorEvidence(auth *controlauth.Manager, identity controlauth.NodeIdentity, request controlprotocol.ExecutorEvidencePollRequestV1, now, expiresAt time.Time) (controlprotocol.ExecutorEvidencePollResponseV1, error) {
	if store == nil || auth == nil {
		return controlprotocol.ExecutorEvidencePollResponseV1{}, ErrUnavailable
	}
	if err := request.Validate(); err != nil || now.IsZero() || !expiresAt.After(now) {
		return controlprotocol.ExecutorEvidencePollResponseV1{}, invalid("executor evidence poll or challenge lifetime is invalid")
	}
	witness, err := func() (EvidenceWitness, error) {
		store.mu.Lock()
		defer store.mu.Unlock()
		if err := store.availableLocked(); err != nil {
			return EvidenceWitness{}, err
		}
		if err := store.revalidateNodeLocked(identity); err != nil {
			return EvidenceWitness{}, err
		}
		node, ok := store.current.nodes[identity.NodeID]
		if !ok || node.Evidence == nil {
			return EvidenceWitness{}, ErrConflict
		}
		if !executorEvidencePollMatches(auth, identity, request, *node.Evidence) {
			return EvidenceWitness{}, ErrConflict
		}
		return *cloneEvidenceWitness(node.Evidence), nil
	}()
	if err != nil {
		return controlprotocol.ExecutorEvidencePollResponseV1{}, err
	}
	challenge, err := auth.MintEvidenceChallenge(identity.CredentialID, identity.NodeID, now, expiresAt)
	if err != nil {
		return controlprotocol.ExecutorEvidencePollResponseV1{}, err
	}
	challengeExpiresAt, err := auth.EvidenceChallengeExpiresAt(
		challenge, identity.CredentialID, identity.NodeID, now,
	)
	if err != nil {
		return controlprotocol.ExecutorEvidencePollResponseV1{}, err
	}
	if err := store.rememberExecutorEvidenceChallenge(identity.CredentialID, challenge, challengeExpiresAt, now); err != nil {
		return controlprotocol.ExecutorEvidencePollResponseV1{}, err
	}
	response := controlprotocol.ExecutorEvidencePollResponseV1{
		ProtocolVersion: controlprotocol.ExecutorEvidenceProtocolV1,
		Challenge:       challenge,
		Status:          executorEvidenceStatus(witness),
	}
	if err := response.Validate(); err != nil {
		return controlprotocol.ExecutorEvidencePollResponseV1{}, ErrConflict
	}
	return response, nil
}

// ApplyExecutorEvidenceReport verifies challenge freshness, receipt-key proof,
// and any signed delta outside the store mutex. It then revalidates the node and
// applies the result only if the exact copied checkpoint is still current.
func (store *Store) ApplyExecutorEvidenceReport(auth *controlauth.Manager, identity controlauth.NodeIdentity, report controlprotocol.ExecutorEvidenceReportV1, now time.Time) (controlprotocol.ExecutorEvidenceReportResponseV1, error) {
	return store.applyExecutorEvidenceReport(auth, identity, report, now, nil)
}

func (store *Store) applyExecutorEvidenceReport(auth *controlauth.Manager, identity controlauth.NodeIdentity, report controlprotocol.ExecutorEvidenceReportV1, now time.Time, afterSnapshot func()) (response controlprotocol.ExecutorEvidenceReportResponseV1, err error) {
	if store == nil || auth == nil {
		return controlprotocol.ExecutorEvidenceReportResponseV1{}, ErrUnavailable
	}
	if now.IsZero() {
		return controlprotocol.ExecutorEvidenceReportResponseV1{}, invalid("executor evidence report time is required")
	}
	if report.ProtocolVersion != controlprotocol.ExecutorEvidenceProtocolV1 {
		return controlprotocol.ExecutorEvidenceReportResponseV1{}, invalid("executor evidence report protocol version is invalid")
	}
	if len(report.SignedFramesBase64) > controlprotocol.MaxExecutorEvidenceFrames {
		return controlprotocol.ExecutorEvidenceReportResponseV1{}, invalid("executor evidence report exceeds the frame-count limit")
	}
	if err := report.HeadProof.Validate(); err != nil {
		return controlprotocol.ExecutorEvidenceReportResponseV1{}, invalidError("validate executor evidence head proof", err)
	}
	if uint32(len(report.SignedFramesBase64)) != report.HeadProof.Claim.FrameCount {
		return controlprotocol.ExecutorEvidenceReportResponseV1{}, invalid("executor evidence report frame count does not match the signed claim")
	}

	snapshot, err := store.executorEvidenceSnapshot(identity)
	if err != nil {
		return controlprotocol.ExecutorEvidenceReportResponseV1{}, err
	}
	if afterSnapshot != nil {
		afterSnapshot()
	}
	if !executorEvidenceHeadMatchesPin(auth, identity, report.HeadProof.Claim, snapshot.witness) {
		return controlprotocol.ExecutorEvidenceReportResponseV1{}, ErrConflict
	}
	challengeExpiresAt, err := auth.EvidenceChallengeExpiresAt(
		report.HeadProof.Claim.Challenge, identity.CredentialID, identity.NodeID, now,
	)
	if err != nil {
		return controlprotocol.ExecutorEvidenceReportResponseV1{}, err
	}
	reportDigest, err := executorEvidenceReportFingerprint(report)
	if err != nil {
		return controlprotocol.ExecutorEvidenceReportResponseV1{}, invalidError("fingerprint executor evidence report", err)
	}
	attempt, replayResponse, err, leader := store.beginExecutorEvidenceReport(
		identity.CredentialID, report.HeadProof.Claim.Challenge, reportDigest, challengeExpiresAt, now,
	)
	if !leader {
		if err == nil {
			return store.currentExecutorEvidenceReplayResponse(identity)
		}
		if revalidateErr := store.revalidateExecutorEvidenceIdentity(identity); revalidateErr != nil {
			return controlprotocol.ExecutorEvidenceReportResponseV1{}, revalidateErr
		}
		return replayResponse, err
	}
	if err != nil {
		return controlprotocol.ExecutorEvidenceReportResponseV1{}, err
	}
	defer func() {
		store.finishExecutorEvidenceReport(identity.CredentialID, attempt, response, err)
	}()

	frames, err := report.DecodeFrames()
	if err != nil {
		return controlprotocol.ExecutorEvidenceReportResponseV1{}, invalidError("decode executor evidence report", err)
	}
	verified, err := verifyExecutorEvidenceReport(auth, identity, report.HeadProof, frames, snapshot, now)
	if err != nil {
		return controlprotocol.ExecutorEvidenceReportResponseV1{}, err
	}

	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.availableLocked(); err != nil {
		return controlprotocol.ExecutorEvidenceReportResponseV1{}, err
	}
	if err := store.revalidateNodeLocked(identity); err != nil {
		return controlprotocol.ExecutorEvidenceReportResponseV1{}, err
	}
	node, ok := store.current.nodes[identity.NodeID]
	if !ok || node.Evidence == nil {
		return controlprotocol.ExecutorEvidenceReportResponseV1{}, ErrConflict
	}
	if executorEvidenceTimeBefore(now, node.Evidence.PinnedAt) {
		return controlprotocol.ExecutorEvidenceReportResponseV1{}, invalid("executor evidence report predates key pinning")
	}
	historicalComparedHead, historicalDetectedAt, historicalVerifiedFinding :=
		historicalExecutorEvidenceFinding(node, snapshot, verified, now)
	if executorEvidenceTimeBefore(now, node.Evidence.AdvancedAt) && !historicalVerifiedFinding {
		return controlprotocol.ExecutorEvidenceReportResponseV1{}, invalid("executor evidence report predates the retained checkpoint")
	}
	if node.Evidence.Finding != nil &&
		executorEvidenceTimeBefore(now, node.Evidence.Finding.LastObservedAt) &&
		!historicalVerifiedFinding {
		return controlprotocol.ExecutorEvidenceReportResponseV1{}, invalid("executor evidence report predates the retained finding")
	}
	if !tenantSubset(snapshot.nodeTenantIDs, node.TenantIDs) ||
		!evidenceWitnessEqual(*node.Evidence, snapshot.witness) {
		if verified.action == executorEvidenceAdvance && exactExecutorEvidenceRetry(*node.Evidence, verified) {
			return executorEvidenceReportResponse(false, *node.Evidence), nil
		}
		if historicalVerifiedFinding {
			if node.Evidence.Finding != nil {
				return executorEvidenceReportResponse(false, *node.Evidence), nil
			}
			updated := cloneNode(node)
			witness := cloneEvidenceWitness(node.Evidence)
			recordExecutorEvidenceFinding(
				witness, verified.reason, historicalComparedHead, verified.head, historicalDetectedAt,
			)
			updated.Evidence = witness
			if err := store.applyMutationsLocked(mutation{Kind: mutationNode, Node: &updated}); err != nil {
				return controlprotocol.ExecutorEvidenceReportResponseV1{}, err
			}
			return executorEvidenceReportResponse(true, *witness), nil
		}
		if (verified.action == executorEvidenceFinding || verified.action == executorEvidenceNoop) &&
			tenantSubset(snapshot.nodeTenantIDs, node.TenantIDs) &&
			evidenceWitnessCheckpointEqual(*node.Evidence, snapshot.witness) &&
			node.Evidence.Finding != nil {
			return executorEvidenceReportResponse(false, *node.Evidence), nil
		}
		if verified.action == executorEvidenceAdvance &&
			tenantSubset(snapshot.nodeTenantIDs, node.TenantIDs) &&
			evidenceWitnessPinEqual(*node.Evidence, snapshot.witness) &&
			node.Evidence.Finding == nil &&
			verified.baseSequence == snapshot.witness.Sequence &&
			verified.baseChainHash == snapshot.witness.ChainHash &&
			node.Evidence.LastBatchStart == verified.baseSequence+1 &&
			node.Evidence.Sequence == verified.head.Sequence &&
			node.Evidence.ChainHash != verified.head.ChainHash &&
			!executorEvidenceTimeBefore(now, node.Evidence.AdvancedAt) {
			updated := cloneNode(node)
			witness := cloneEvidenceWitness(node.Evidence)
			recordExecutorEvidenceFinding(
				witness, EvidenceFork, executorEvidenceHead(*node.Evidence), verified.head, now,
			)
			updated.Evidence = witness
			if err := store.applyMutationsLocked(mutation{Kind: mutationNode, Node: &updated}); err != nil {
				return controlprotocol.ExecutorEvidenceReportResponseV1{}, err
			}
			return executorEvidenceReportResponse(true, *witness), nil
		}
		return controlprotocol.ExecutorEvidenceReportResponseV1{}, ErrConflict
	}

	switch verified.action {
	case executorEvidenceNoop:
		return executorEvidenceReportResponse(false, *node.Evidence), nil
	case executorEvidenceBlocked:
		return executorEvidenceReportResponse(false, *node.Evidence), ErrConflict
	}

	updated := cloneNode(node)
	witness := cloneEvidenceWitness(node.Evidence)
	switch verified.action {
	case executorEvidenceAdvance:
		witness.Sequence = verified.head.Sequence
		witness.ChainHash = verified.head.ChainHash
		witness.AdvancedAt = canonicalTimestamp(now)
		witness.RecordsAccepted = verified.head.Sequence
		witness.LastBatchStart = verified.batchStart
		witness.LastBatchEnd = verified.batchEnd
		witness.LastBatchDigest = verified.batchDigest
	case executorEvidenceFinding:
		if witness.Finding == nil {
			recordExecutorEvidenceFinding(
				witness, verified.reason, executorEvidenceHead(*witness), verified.head, now,
			)
		}
	default:
		return controlprotocol.ExecutorEvidenceReportResponseV1{}, ErrConflict
	}
	updated.Evidence = witness
	if err := store.applyMutationsLocked(mutation{Kind: mutationNode, Node: &updated}); err != nil {
		return controlprotocol.ExecutorEvidenceReportResponseV1{}, err
	}
	return executorEvidenceReportResponse(true, *witness), nil
}

func (store *Store) revalidateExecutorEvidenceIdentity(identity controlauth.NodeIdentity) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.availableLocked(); err != nil {
		return err
	}
	return store.revalidateNodeLocked(identity)
}

func (store *Store) currentExecutorEvidenceReplayResponse(identity controlauth.NodeIdentity) (controlprotocol.ExecutorEvidenceReportResponseV1, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.availableLocked(); err != nil {
		return controlprotocol.ExecutorEvidenceReportResponseV1{}, err
	}
	if err := store.revalidateNodeLocked(identity); err != nil {
		return controlprotocol.ExecutorEvidenceReportResponseV1{}, err
	}
	node, ok := store.current.nodes[identity.NodeID]
	if !ok || node.Evidence == nil {
		return controlprotocol.ExecutorEvidenceReportResponseV1{}, ErrConflict
	}
	return executorEvidenceReportResponse(false, *node.Evidence), nil
}

func (store *Store) executorEvidenceSnapshot(identity controlauth.NodeIdentity) (executorEvidenceSnapshot, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.availableLocked(); err != nil {
		return executorEvidenceSnapshot{}, err
	}
	if err := store.revalidateNodeLocked(identity); err != nil {
		return executorEvidenceSnapshot{}, err
	}
	node, ok := store.current.nodes[identity.NodeID]
	if !ok || node.Evidence == nil {
		return executorEvidenceSnapshot{}, ErrConflict
	}
	credential, ok := store.current.credentials[identity.CredentialID]
	if !ok {
		return executorEvidenceSnapshot{}, controlauth.ErrUnauthorized
	}
	return executorEvidenceSnapshot{
		credentialTenantIDs: append([]string(nil), credential.TenantIDs...),
		nodeTenantIDs:       append([]string(nil), node.TenantIDs...),
		witness:             *cloneEvidenceWitness(node.Evidence),
	}, nil
}

func verifyExecutorEvidenceReport(auth *controlauth.Manager, identity controlauth.NodeIdentity, proof controlprotocol.ExecutorEvidenceHeadProofV1, frames [][]byte, snapshot executorEvidenceSnapshot, now time.Time) (verifiedExecutorEvidenceReport, error) {
	witness := snapshot.witness
	public, err := controlprotocol.VerifyExecutorEvidenceIdentityProofV1(witness.IdentityProof)
	if err != nil || len(public) != ed25519.PublicKeySize {
		return verifiedExecutorEvidenceReport{}, ErrConflict
	}
	if auth.InstanceID() != witness.IdentityProof.Claim.ControllerInstanceID ||
		!executorEvidenceHeadMatchesPin(auth, identity, proof.Claim, witness) {
		return verifiedExecutorEvidenceReport{}, ErrConflict
	}
	if err := auth.VerifyEvidenceChallenge(
		proof.Claim.Challenge, identity.CredentialID, identity.NodeID, now,
	); err != nil {
		return verifiedExecutorEvidenceReport{}, err
	}
	if err := controlprotocol.VerifyExecutorEvidenceHeadProofV1(proof, public); err != nil {
		return verifiedExecutorEvidenceReport{}, invalidError("verify executor evidence head proof", err)
	}
	pinnedAt, _ := parseTimestamp(witness.PinnedAt)
	if now.Before(pinnedAt) {
		return verifiedExecutorEvidenceReport{}, invalid("executor evidence report predates key pinning")
	}
	if witness.AdvancedAt != "" {
		advancedAt, _ := parseTimestamp(witness.AdvancedAt)
		if now.Before(advancedAt) {
			return verifiedExecutorEvidenceReport{}, invalid("executor evidence report predates the retained checkpoint")
		}
	}
	if witness.Finding != nil {
		lastObservedAt, _ := parseTimestamp(witness.Finding.LastObservedAt)
		if now.Before(lastObservedAt) {
			return verifiedExecutorEvidenceReport{}, invalid("executor evidence report predates the retained finding")
		}
	}

	observed := proof.Claim.Head()
	signedBase := proof.Claim.Base()
	current := executorEvidenceHead(witness)
	currentCoordinate, err := executorEvidenceCoordinate(witness)
	if err != nil {
		return verifiedExecutorEvidenceReport{}, ErrConflict
	}
	baseHash, err := decodeExecutorEvidenceHash(signedBase.ChainHash)
	if err != nil {
		return verifiedExecutorEvidenceReport{}, ErrConflict
	}
	signedCoordinate := evidence.Coordinate{Sequence: signedBase.Sequence, ChainHash: baseHash}
	verified := verifiedExecutorEvidenceReport{
		action:        executorEvidenceNoop,
		baseSequence:  signedBase.Sequence,
		baseChainHash: signedBase.ChainHash,
		head:          observed,
		batchDigest:   controlprotocol.ExecutorEvidenceFramesDigestV1(frames),
	}
	if len(frames) > 0 {
		derived, err := evidence.VerifyDelta(
			frames, public, witness.ReceiptNodeID, witness.Epoch, signedCoordinate,
			func(tenantID string) bool {
				return tenantMember(snapshot.credentialTenantIDs, tenantID) &&
					tenantMember(snapshot.nodeTenantIDs, tenantID)
			},
		)
		if err != nil {
			return verifiedExecutorEvidenceReport{}, invalidError("verify executor evidence delta", err)
		}
		if derived.Sequence != observed.Sequence || encodeExecutorEvidenceHash(derived.ChainHash) != observed.ChainHash ||
			derived.NodeID != observed.ReceiptNodeID || derived.Epoch != observed.ReceiptEpoch ||
			controlprotocol.ExecutorEvidencePublicKeySHA256(public) != observed.PublicKeySHA256 {
			return verifiedExecutorEvidenceReport{}, invalid("executor evidence delta does not derive the signed head")
		}
		verified.action = executorEvidenceAdvance
		verified.batchStart = signedBase.Sequence + 1
		verified.batchEnd = observed.Sequence
	}

	if signedCoordinate != currentCoordinate {
		if verified.action == executorEvidenceAdvance && exactExecutorEvidenceRetry(witness, verified) {
			verified.action = executorEvidenceNoop
			return verified, nil
		}
		if verifiedExecutorEvidenceFork(witness, verified) {
			verified.action = executorEvidenceFinding
			verified.reason = EvidenceFork
			return verified, nil
		}
		return verifiedExecutorEvidenceReport{}, ErrConflict
	}
	if observed.Sequence < current.Sequence {
		if len(frames) != 0 {
			return verifiedExecutorEvidenceReport{}, invalid("executor evidence rollback report must not carry delta frames")
		}
		if witness.Finding != nil {
			return verified, nil
		}
		verified.action = executorEvidenceFinding
		verified.reason = EvidenceRollback
		return verified, nil
	}
	if observed.Sequence == current.Sequence && observed.ChainHash != current.ChainHash {
		if len(frames) != 0 {
			return verifiedExecutorEvidenceReport{}, invalid("executor evidence fork report must not carry delta frames")
		}
		if witness.Finding != nil {
			return verified, nil
		}
		verified.action = executorEvidenceFinding
		verified.reason = EvidenceFork
		return verified, nil
	}
	if observed.Sequence == current.Sequence {
		if len(frames) == 0 {
			return verified, nil
		}
		return verifiedExecutorEvidenceReport{}, invalid("executor evidence report carries frames after the retained checkpoint")
	}
	if len(frames) == 0 {
		if witness.Finding != nil {
			return verified, nil
		}
		verified.action = executorEvidenceFinding
		verified.reason = EvidenceFork
		return verified, nil
	}
	if witness.Finding != nil {
		verified.action = executorEvidenceBlocked
	}
	return verified, nil
}

func verifiedExecutorEvidenceFork(witness EvidenceWitness, report verifiedExecutorEvidenceReport) bool {
	if witness.Finding != nil || report.action != executorEvidenceAdvance {
		return false
	}
	current := executorEvidenceHead(witness)
	return report.head.Sequence == current.Sequence &&
		report.head.ChainHash != witness.ChainHash
}

func executorEvidencePollMatches(auth *controlauth.Manager, identity controlauth.NodeIdentity, request controlprotocol.ExecutorEvidencePollRequestV1, witness EvidenceWitness) bool {
	claim := witness.IdentityProof.Claim
	return auth.InstanceID() == claim.ControllerInstanceID &&
		request.ControllerInstanceID == claim.ControllerInstanceID &&
		request.ControlNodeID == identity.NodeID && request.ControlNodeID == claim.ControlNodeID &&
		request.Stream == claim.Stream &&
		request.ReceiptNodeID == witness.ReceiptNodeID && request.ReceiptNodeID == claim.ReceiptNodeID &&
		request.ReceiptEpoch == witness.Epoch && request.ReceiptEpoch == claim.ReceiptEpoch &&
		request.PublicKeySHA256 == witness.PublicKeyDigest && request.PublicKeySHA256 == claim.PublicKeySHA256
}

func executorEvidenceHeadMatchesPin(auth *controlauth.Manager, identity controlauth.NodeIdentity, claim controlprotocol.ExecutorEvidenceHeadClaimV1, witness EvidenceWitness) bool {
	pinned := witness.IdentityProof.Claim
	return claim.ControllerInstanceID == auth.InstanceID() && claim.ControllerInstanceID == pinned.ControllerInstanceID &&
		claim.ControlNodeID == identity.NodeID && claim.ControlNodeID == pinned.ControlNodeID &&
		claim.Stream == pinned.Stream &&
		claim.ReceiptNodeID == witness.ReceiptNodeID && claim.ReceiptNodeID == pinned.ReceiptNodeID &&
		claim.ReceiptEpoch == witness.Epoch && claim.ReceiptEpoch == pinned.ReceiptEpoch &&
		claim.PublicKeySHA256 == witness.PublicKeyDigest && claim.PublicKeySHA256 == pinned.PublicKeySHA256
}

func executorEvidenceStatus(witness EvidenceWitness) controlprotocol.ExecutorEvidenceStatusV1 {
	head := executorEvidenceHead(witness)
	witnessedAt := witness.AdvancedAt
	if witnessedAt == "" {
		witnessedAt = witness.PinnedAt
	}
	status := controlprotocol.ExecutorEvidenceStatusV1{
		State: controlprotocol.ExecutorEvidenceStatusCurrent, Head: &head, WitnessedAt: witnessedAt,
	}
	if witness.Finding == nil {
		return status
	}
	finding := witness.Finding
	compared := controlprotocol.ExecutorEvidenceHeadV1{
		Stream: controlprotocol.ExecutorEvidenceStreamV1, ReceiptNodeID: witness.ReceiptNodeID,
		ReceiptEpoch: witness.Epoch, Sequence: finding.FirstComparedSequence,
		ChainHash: finding.FirstComparedChainHash, PublicKeySHA256: witness.PublicKeyDigest,
	}
	observed := controlprotocol.ExecutorEvidenceHeadV1{
		Stream: controlprotocol.ExecutorEvidenceStreamV1, ReceiptNodeID: witness.ReceiptNodeID,
		ReceiptEpoch: witness.Epoch, Sequence: finding.FirstSequence,
		ChainHash: finding.FirstChainHash, PublicKeySHA256: witness.PublicKeyDigest,
	}
	kind := controlprotocol.ExecutorEvidenceFindingEquivocation
	status.State = controlprotocol.ExecutorEvidenceStatusEquivocationDetected
	if finding.FirstReason == EvidenceRollback {
		kind = controlprotocol.ExecutorEvidenceFindingRollback
		status.State = controlprotocol.ExecutorEvidenceStatusRollbackDetected
	}
	status.Finding = &controlprotocol.ExecutorEvidenceFindingV1{
		Kind: kind, DetectedAt: finding.FirstObservedAt, ComparedHead: compared, ObservedHead: observed,
	}
	return status
}

func executorEvidenceHead(witness EvidenceWitness) controlprotocol.ExecutorEvidenceHeadV1 {
	return controlprotocol.ExecutorEvidenceHeadV1{
		Stream: controlprotocol.ExecutorEvidenceStreamV1, ReceiptNodeID: witness.ReceiptNodeID,
		ReceiptEpoch: witness.Epoch, Sequence: witness.Sequence,
		ChainHash: witness.ChainHash, PublicKeySHA256: witness.PublicKeyDigest,
	}
}

func executorEvidenceReportResponse(applied bool, witness EvidenceWitness) controlprotocol.ExecutorEvidenceReportResponseV1 {
	return controlprotocol.ExecutorEvidenceReportResponseV1{
		ProtocolVersion: controlprotocol.ExecutorEvidenceProtocolV1,
		Applied:         applied,
		Status:          executorEvidenceStatus(witness),
	}
}

func historicalExecutorEvidenceFinding(
	node Node,
	snapshot executorEvidenceSnapshot,
	verified verifiedExecutorEvidenceReport,
	now time.Time,
) (controlprotocol.ExecutorEvidenceHeadV1, time.Time, bool) {
	if verified.action != executorEvidenceFinding ||
		!tenantSubset(snapshot.nodeTenantIDs, node.TenantIDs) ||
		node.Evidence == nil ||
		!evidenceWitnessPinEqual(*node.Evidence, snapshot.witness) ||
		evidenceWitnessCheckpointEqual(*node.Evidence, snapshot.witness) {
		return controlprotocol.ExecutorEvidenceHeadV1{}, time.Time{}, false
	}
	snapshotHead := executorEvidenceHead(snapshot.witness)
	if verified.reason == EvidenceRollback ||
		(verified.reason == EvidenceFork &&
			verified.head.Sequence == snapshotHead.Sequence &&
			verified.head.ChainHash != snapshotHead.ChainHash) {
		return snapshotHead, now, true
	}
	if verified.reason != EvidenceFork {
		return controlprotocol.ExecutorEvidenceHeadV1{}, time.Time{}, false
	}
	currentHead := executorEvidenceHead(*node.Evidence)
	if verified.head.Sequence != currentHead.Sequence ||
		verified.head.ChainHash == currentHead.ChainHash {
		return controlprotocol.ExecutorEvidenceHeadV1{}, time.Time{}, false
	}
	advancedAt, err := parseTimestamp(node.Evidence.AdvancedAt)
	if err != nil {
		return controlprotocol.ExecutorEvidenceHeadV1{}, time.Time{}, false
	}
	if now.Before(advancedAt) {
		now = advancedAt
	}
	return currentHead, now, true
}

func recordExecutorEvidenceFinding(witness *EvidenceWitness, reason EvidenceFindingReason, compared, observed controlprotocol.ExecutorEvidenceHeadV1, now time.Time) {
	if witness.Finding != nil {
		return
	}
	timestamp := canonicalTimestamp(now)
	witness.Finding = &EvidenceFinding{
		FirstReason: reason, FirstComparedSequence: compared.Sequence, FirstComparedChainHash: compared.ChainHash,
		FirstSequence: observed.Sequence, FirstChainHash: observed.ChainHash, FirstObservedAt: timestamp,
		LastReason: reason, LastComparedSequence: compared.Sequence, LastComparedChainHash: compared.ChainHash,
		LastSequence: observed.Sequence, LastChainHash: observed.ChainHash, LastObservedAt: timestamp, Count: 1,
	}
}

func exactExecutorEvidenceRetry(witness EvidenceWitness, report verifiedExecutorEvidenceReport) bool {
	return witness.Sequence > 0 && report.head.Sequence == witness.Sequence &&
		report.head.ChainHash == witness.ChainHash &&
		report.head.ReceiptNodeID == witness.ReceiptNodeID &&
		report.head.ReceiptEpoch == witness.Epoch &&
		report.head.PublicKeySHA256 == witness.PublicKeyDigest &&
		report.batchStart == witness.LastBatchStart && report.batchEnd == witness.LastBatchEnd &&
		report.batchDigest == witness.LastBatchDigest
}

func executorEvidenceCoordinate(witness EvidenceWitness) (evidence.Coordinate, error) {
	hash, err := decodeExecutorEvidenceHash(witness.ChainHash)
	if err != nil {
		return evidence.Coordinate{}, err
	}
	return evidence.Coordinate{Sequence: witness.Sequence, ChainHash: hash}, nil
}

func evidenceWitnessEqual(left, right EvidenceWitness) bool {
	if !evidenceWitnessCheckpointEqual(left, right) {
		return false
	}
	if left.Finding == nil || right.Finding == nil {
		return left.Finding == nil && right.Finding == nil
	}
	return *left.Finding == *right.Finding
}

func evidenceWitnessCheckpointEqual(left, right EvidenceWitness) bool {
	return evidenceWitnessPinEqual(left, right) &&
		left.Sequence == right.Sequence && left.ChainHash == right.ChainHash &&
		left.AdvancedAt == right.AdvancedAt && left.RecordsAccepted == right.RecordsAccepted &&
		left.LastBatchStart == right.LastBatchStart && left.LastBatchEnd == right.LastBatchEnd &&
		left.LastBatchDigest == right.LastBatchDigest
}

func evidenceWitnessPinEqual(left, right EvidenceWitness) bool {
	return left.IdentityProof == right.IdentityProof &&
		left.ReceiptNodeID == right.ReceiptNodeID && left.Epoch == right.Epoch &&
		left.PublicKeyBase64 == right.PublicKeyBase64 && left.KeyID == right.KeyID &&
		left.PublicKeyDigest == right.PublicKeyDigest && left.PinnedAt == right.PinnedAt
}

func executorEvidenceTimeBefore(now time.Time, retained string) bool {
	if retained == "" {
		return false
	}
	value, err := parseTimestamp(retained)
	return err != nil || now.Before(value)
}

func decodeExecutorEvidenceHash(value string) ([sha256.Size]byte, error) {
	var result [sha256.Size]byte
	if !validSHA256Digest(value) {
		return result, errors.New("executor evidence chain hash is invalid")
	}
	raw, err := hex.DecodeString(value[len("sha256:"):])
	if err != nil || len(raw) != sha256.Size {
		return result, errors.New("executor evidence chain hash is invalid")
	}
	copy(result[:], raw)
	return result, nil
}

func encodeExecutorEvidenceHash(value [sha256.Size]byte) string {
	return "sha256:" + hex.EncodeToString(value[:])
}
