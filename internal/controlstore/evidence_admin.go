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

// InspectExecutorEvidence returns the retained last-good checkpoint and any
// sticky divergence finding. Revoked nodes remain inspectable for forensics;
// tenant operators cannot read this cross-tenant site-authority view.
func (store *Store) InspectExecutorEvidence(actor controlauth.Identity, nodeID string) (ExecutorEvidenceInspection, error) {
	if store == nil {
		return ExecutorEvidenceInspection{}, ErrUnavailable
	}
	if !controlauth.IsSiteAdmin(actor) {
		return ExecutorEvidenceInspection{}, ErrForbidden
	}
	if !validRecordID(nodeID, 128) {
		return ExecutorEvidenceInspection{}, ErrNotFound
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.availableLocked(); err != nil {
		return ExecutorEvidenceInspection{}, err
	}
	if err := store.revalidateOperatorLocked(actor); err != nil {
		return ExecutorEvidenceInspection{}, err
	}
	node, ok := store.current.nodes[nodeID]
	if !ok {
		return ExecutorEvidenceInspection{}, ErrNotFound
	}
	if node.Evidence == nil {
		return ExecutorEvidenceInspection{
			Status: controlprotocol.ExecutorEvidenceStatusV1{State: controlprotocol.ExecutorEvidenceStatusUnwitnessed},
		}, nil
	}
	witness := cloneEvidenceWitness(node.Evidence)
	proof := witness.IdentityProof
	return ExecutorEvidenceInspection{IdentityProof: &proof, Status: executorEvidenceStatus(*witness)}, nil
}
