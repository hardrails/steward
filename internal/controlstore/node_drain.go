package controlstore

import (
	"strings"
	"time"

	"github.com/hardrails/steward/internal/controlauth"
)

// StartNodeDrain durably cordons a node before any instance becomes
// unavailable. RequestID makes an operator retry idempotent without allowing a
// second request to overwrite an active maintenance operation.
func (store *Store) StartNodeDrain(
	actor controlauth.Identity,
	nodeID, requestID, reason string,
	now time.Time,
) (Node, bool, error) {
	if store == nil {
		return Node{}, false, ErrUnavailable
	}
	if !controlauth.IsSiteAdmin(actor) {
		return Node{}, false, ErrForbidden
	}
	if !validRecordID(nodeID, 128) || !validRecordID(requestID, 128) ||
		now.IsZero() || !validDrainReason(reason) {
		return Node{}, false, invalid("node drain request is invalid")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.availableLocked(); err != nil {
		return Node{}, false, err
	}
	if err := store.revalidateOperatorLocked(actor); err != nil {
		return Node{}, false, err
	}
	node, found := store.current.nodes[nodeID]
	if !found {
		return Node{}, false, ErrNotFound
	}
	if !node.Active || EffectiveNodePlacement(node).Mode == NodeQuarantined {
		return Node{}, false, ErrConflict
	}
	if node.Drain != nil && node.Drain.State == NodeDrainActive {
		if node.Drain.RequestID == requestID && node.Drain.Reason == reason {
			return cloneNode(node), false, nil
		}
		return Node{}, false, ErrConflict
	}
	created, _ := parseTimestamp(node.CreatedAt)
	placement := EffectiveNodePlacement(node)
	changed, _ := parseTimestamp(placement.ChangedAt)
	if node.Drain != nil {
		updated, _ := parseTimestamp(node.Drain.UpdatedAt)
		if now.Before(updated) {
			return Node{}, false, invalid("node drain time precedes retained drain state")
		}
	}
	if now.Before(created) || now.Before(changed) {
		return Node{}, false, invalid("node drain time precedes retained node state")
	}
	updated := cloneNode(node)
	if placement.Mode == NodeSchedulable {
		updated.Placement = &NodePlacement{
			Mode: NodeCordoned, Reason: reason, ChangedAt: canonicalTimestamp(now),
		}
	}
	updated.Drain = &NodeDrain{
		RequestID: requestID, State: NodeDrainActive, Reason: reason,
		RequestedAt: canonicalTimestamp(now), UpdatedAt: canonicalTimestamp(now),
	}
	if err := store.applyMutationsLocked(mutation{Kind: mutationNode, Node: &updated}); err != nil {
		return Node{}, false, err
	}
	return cloneNode(updated), true, nil
}

// CancelNodeDrain stops the controller from beginning another move. Instances
// whose drain marker is already durable continue forward because a stop or
// destroy outcome may already be in flight and cannot safely be reversed.
func (store *Store) CancelNodeDrain(
	actor controlauth.Identity,
	nodeID, requestID string,
	now time.Time,
) (Node, bool, error) {
	if store == nil {
		return Node{}, false, ErrUnavailable
	}
	if !controlauth.IsSiteAdmin(actor) {
		return Node{}, false, ErrForbidden
	}
	if !validRecordID(nodeID, 128) || !validRecordID(requestID, 128) || now.IsZero() {
		return Node{}, false, invalid("node drain cancellation is invalid")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.availableLocked(); err != nil {
		return Node{}, false, err
	}
	if err := store.revalidateOperatorLocked(actor); err != nil {
		return Node{}, false, err
	}
	node, found := store.current.nodes[nodeID]
	if !found {
		return Node{}, false, ErrNotFound
	}
	if node.Drain == nil || node.Drain.RequestID != requestID {
		return Node{}, false, ErrConflict
	}
	if node.Drain.State == NodeDrainCancelled {
		return cloneNode(node), false, nil
	}
	if node.Drain.State != NodeDrainActive {
		return Node{}, false, ErrConflict
	}
	updatedAt, _ := parseTimestamp(node.Drain.UpdatedAt)
	if now.Before(updatedAt) {
		return Node{}, false, invalid("node drain cancellation predates retained drain state")
	}
	updated := cloneNode(node)
	updated.Drain.State = NodeDrainCancelled
	updated.Drain.UpdatedAt = canonicalTimestamp(now)
	updated.Drain.CompletedAt = canonicalTimestamp(now)
	if err := store.applyMutationsLocked(mutation{Kind: mutationNode, Node: &updated}); err != nil {
		return Node{}, false, err
	}
	return cloneNode(updated), true, nil
}

func validDrainReason(reason string) bool {
	return reason != "" && len(reason) <= 256 && strings.TrimSpace(reason) == reason &&
		boundedRetainedText(reason, 256)
}

func validNodeDrain(value NodeDrain) bool {
	if !validRecordID(value.RequestID, 128) || !validDrainReason(value.Reason) ||
		!validTimestamp(value.RequestedAt) || !validTimestamp(value.UpdatedAt) {
		return false
	}
	requested, _ := parseTimestamp(value.RequestedAt)
	updated, _ := parseTimestamp(value.UpdatedAt)
	if updated.Before(requested) {
		return false
	}
	switch value.State {
	case NodeDrainActive:
		return value.CompletedAt == ""
	case NodeDrainCompleted, NodeDrainCancelled:
		if !validTimestamp(value.CompletedAt) {
			return false
		}
		completed, _ := parseTimestamp(value.CompletedAt)
		return !completed.Before(updated)
	default:
		return false
	}
}
