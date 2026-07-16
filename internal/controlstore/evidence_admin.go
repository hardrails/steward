package controlstore

import (
	"github.com/hardrails/steward/internal/controlauth"
	"github.com/hardrails/steward/internal/controlprotocol"
)

// ExecutorEvidenceInspection is the bounded, non-secret evidence state a site
// administrator may inspect for one node. IdentityProof is absent only for a
// legacy node that predates mandatory receipt-key enrollment.
type ExecutorEvidenceInspection struct {
	IdentityProof *controlprotocol.ExecutorEvidenceIdentityProofV1
	Status        controlprotocol.ExecutorEvidenceStatusV1
}

// ExecutorEvidenceSnapshot carries an inspection plus an opaque copy of the
// exact bounded witness state from which it was derived. Callers may sign the
// inspection without holding the store mutex, then use
// ExecutorEvidenceSnapshotCurrent to establish a linearization point.
type ExecutorEvidenceSnapshot struct {
	Inspection ExecutorEvidenceInspection

	nodeID    string
	witnessed bool
	witness   EvidenceWitness
}

// InspectExecutorEvidence returns the retained last-good checkpoint and any
// sticky divergence finding. Revoked nodes remain inspectable for forensics;
// tenant operators cannot read this cross-tenant site-authority view.
func (store *Store) InspectExecutorEvidence(actor controlauth.Identity, nodeID string) (ExecutorEvidenceInspection, error) {
	snapshot, err := store.SnapshotExecutorEvidence(actor, nodeID)
	return snapshot.Inspection, err
}

// SnapshotExecutorEvidence returns the retained evidence view together with an
// opaque witness copy that can later be revalidated. Revoked nodes remain
// inspectable because revocation does not erase forensic evidence.
func (store *Store) SnapshotExecutorEvidence(actor controlauth.Identity, nodeID string) (ExecutorEvidenceSnapshot, error) {
	if store == nil {
		return ExecutorEvidenceSnapshot{}, ErrUnavailable
	}
	if !controlauth.IsSiteAdmin(actor) {
		return ExecutorEvidenceSnapshot{}, ErrForbidden
	}
	if !validRecordID(nodeID, 128) {
		return ExecutorEvidenceSnapshot{}, ErrNotFound
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.availableLocked(); err != nil {
		return ExecutorEvidenceSnapshot{}, err
	}
	if err := store.revalidateOperatorLocked(actor); err != nil {
		return ExecutorEvidenceSnapshot{}, err
	}
	node, ok := store.current.nodes[nodeID]
	if !ok {
		return ExecutorEvidenceSnapshot{}, ErrNotFound
	}
	if node.Evidence == nil {
		return ExecutorEvidenceSnapshot{
			Inspection: ExecutorEvidenceInspection{
				Status: controlprotocol.ExecutorEvidenceStatusV1{State: controlprotocol.ExecutorEvidenceStatusUnwitnessed},
			},
			nodeID: nodeID,
		}, nil
	}
	witness := cloneEvidenceWitness(node.Evidence)
	proof := witness.IdentityProof
	return ExecutorEvidenceSnapshot{
		Inspection: ExecutorEvidenceInspection{IdentityProof: &proof, Status: executorEvidenceStatus(*witness)},
		nodeID:     nodeID,
		witnessed:  true,
		witness:    *witness,
	}, nil
}

// ExecutorEvidenceSnapshotCurrent reports whether snapshot still describes the
// node's exact retained evidence state. The operator credential is revalidated
// in the same critical section. A true result is the linearization point for a
// signed export; later evidence mutations are ordered after that export.
func (store *Store) ExecutorEvidenceSnapshotCurrent(actor controlauth.Identity, nodeID string, snapshot ExecutorEvidenceSnapshot) (bool, error) {
	if store == nil {
		return false, ErrUnavailable
	}
	if !controlauth.IsSiteAdmin(actor) {
		return false, ErrForbidden
	}
	if !validRecordID(nodeID, 128) {
		return false, ErrNotFound
	}
	if snapshot.nodeID != nodeID {
		return false, ErrConflict
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.availableLocked(); err != nil {
		return false, err
	}
	if err := store.revalidateOperatorLocked(actor); err != nil {
		return false, err
	}
	node, ok := store.current.nodes[nodeID]
	if !ok {
		return false, ErrNotFound
	}
	if node.Evidence == nil {
		return !snapshot.witnessed, nil
	}
	if !snapshot.witnessed {
		return false, nil
	}
	return evidenceWitnessEqual(*node.Evidence, snapshot.witness), nil
}
