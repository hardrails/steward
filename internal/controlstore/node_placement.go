package controlstore

import (
	"strings"
	"time"

	"github.com/hardrails/steward/internal/controlauth"
)

type NodePlacementAction string

const (
	NodePlacementCordon       NodePlacementAction = "cordon"
	NodePlacementUncordon     NodePlacementAction = "uncordon"
	NodePlacementQuarantine   NodePlacementAction = "quarantine"
	NodePlacementUnquarantine NodePlacementAction = "unquarantine"
)

// EffectiveNodePlacement returns a concrete view for legacy nodes whose nil
// placement state means schedulable.
func EffectiveNodePlacement(node Node) NodePlacement {
	if node.Placement == nil {
		return NodePlacement{Mode: NodeSchedulable, ChangedAt: node.CreatedAt}
	}
	return *cloneNodePlacement(node.Placement)
}

// ChangeNodePlacement applies one explicit site-admin transition. Quarantine
// may strengthen either schedulable or cordoned state. Removing quarantine is
// intentionally a distinct action from removing an ordinary cordon.
func (store *Store) ChangeNodePlacement(
	actor controlauth.Identity,
	nodeID string,
	action NodePlacementAction,
	reason string,
	now time.Time,
) (Node, bool, error) {
	if store == nil {
		return Node{}, false, ErrUnavailable
	}
	if !controlauth.IsSiteAdmin(actor) {
		return Node{}, false, ErrForbidden
	}
	if !validRecordID(nodeID, 128) || now.IsZero() || !validNodePlacementChange(action, reason) {
		return Node{}, false, invalid("node placement transition is invalid")
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
	if !node.Active {
		return Node{}, false, ErrConflict
	}
	if action == NodePlacementUncordon && node.Drain != nil && node.Drain.State == NodeDrainActive {
		return Node{}, false, ErrConflict
	}
	current := EffectiveNodePlacement(node)
	nextMode, err := placementTransition(current, action, reason)
	if err != nil {
		return Node{}, false, err
	}
	if current.Mode == nextMode && current.Reason == reason {
		return cloneNode(node), false, nil
	}
	created, _ := parseTimestamp(node.CreatedAt)
	changedAt, _ := parseTimestamp(current.ChangedAt)
	if now.Before(created) || now.Before(changedAt) {
		return Node{}, false, invalid("placement transition time precedes retained node state")
	}
	updated := cloneNode(node)
	updated.Placement = &NodePlacement{
		Mode: nextMode, Reason: reason, ChangedAt: canonicalTimestamp(now),
	}
	if action == NodePlacementUnquarantine && updated.Drain != nil && updated.Drain.State == NodeDrainActive {
		updated.Placement.Mode = NodeCordoned
		updated.Placement.Reason = updated.Drain.Reason
	}
	if nextMode == NodeSchedulable {
		updated.Placement.Reason = ""
	}
	if err := store.applyMutationsLocked(mutation{Kind: mutationNode, Node: &updated}); err != nil {
		return Node{}, false, err
	}
	return cloneNode(updated), true, nil
}

func placementTransition(current NodePlacement, action NodePlacementAction, reason string) (NodePlacementMode, error) {
	switch action {
	case NodePlacementCordon:
		if current.Mode == NodeQuarantined {
			return "", ErrConflict
		}
		if current.Mode == NodeCordoned && current.Reason != reason {
			return "", ErrConflict
		}
		return NodeCordoned, nil
	case NodePlacementQuarantine:
		if current.Mode == NodeQuarantined && current.Reason != reason {
			return "", ErrConflict
		}
		return NodeQuarantined, nil
	case NodePlacementUncordon:
		if current.Mode == NodeQuarantined {
			return "", ErrConflict
		}
		return NodeSchedulable, nil
	case NodePlacementUnquarantine:
		if current.Mode == NodeCordoned {
			return "", ErrConflict
		}
		return NodeSchedulable, nil
	default:
		return "", ErrInvalid
	}
}

func validNodePlacementChange(action NodePlacementAction, reason string) bool {
	switch action {
	case NodePlacementCordon, NodePlacementQuarantine:
		return len(reason) <= 256 && reason != "" && strings.TrimSpace(reason) == reason &&
			boundedRetainedText(reason, 256)
	case NodePlacementUncordon, NodePlacementUnquarantine:
		return reason == ""
	default:
		return false
	}
}

func validNodePlacement(value NodePlacement) bool {
	if !validTimestamp(value.ChangedAt) {
		return false
	}
	switch value.Mode {
	case NodeSchedulable:
		return value.Reason == ""
	case NodeCordoned, NodeQuarantined:
		return validNodePlacementChange(NodePlacementCordon, value.Reason)
	default:
		return false
	}
}
