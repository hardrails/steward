package controlstore

import (
	"strings"
	"time"

	"github.com/hardrails/steward/internal/controlauth"
)

const (
	MaxSnapshotQuarantines          = 4096
	MaxSnapshotQuarantinesPerTenant = 256
)

type SnapshotQuarantineAction string

const (
	SnapshotQuarantineActionSet   SnapshotQuarantineAction = "quarantine"
	SnapshotQuarantineActionClear SnapshotQuarantineAction = "clear"
)

type SnapshotQuarantineStatus struct {
	TenantID   string              `json:"tenant_id"`
	NodeID     string              `json:"node_id"`
	SnapshotID string              `json:"snapshot_id"`
	Record     *SnapshotQuarantine `json:"record,omitempty"`
	Blocked    bool                `json:"blocked"`
}

func (store *Store) InspectSnapshotQuarantine(
	actor controlauth.Identity,
	tenantID, nodeID, snapshotID string,
) (SnapshotQuarantineStatus, error) {
	if store == nil {
		return SnapshotQuarantineStatus{}, ErrUnavailable
	}
	if !controlauth.AuthorizedTenant(actor, tenantID) {
		return SnapshotQuarantineStatus{}, ErrNotFound
	}
	key := snapshotQuarantineKey(tenantID, nodeID, snapshotID)
	if key == "" {
		return SnapshotQuarantineStatus{}, ErrNotFound
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.availableLocked(); err != nil {
		return SnapshotQuarantineStatus{}, err
	}
	if err := store.revalidateOperatorLocked(actor); err != nil {
		return SnapshotQuarantineStatus{}, err
	}
	if !snapshotQuarantineTargetExists(store.current, tenantID, nodeID) {
		return SnapshotQuarantineStatus{}, ErrNotFound
	}
	return snapshotQuarantineStatus(store.current.quarantines, tenantID, nodeID, snapshotID), nil
}

func (store *Store) ChangeSnapshotQuarantine(
	actor controlauth.Identity,
	tenantID, nodeID, snapshotID string,
	action SnapshotQuarantineAction,
	expectedRevision uint64,
	reason string,
	now time.Time,
) (SnapshotQuarantineStatus, bool, error) {
	if store == nil {
		return SnapshotQuarantineStatus{}, false, ErrUnavailable
	}
	if !controlauth.AuthorizedTenant(actor, tenantID) {
		return SnapshotQuarantineStatus{}, false, ErrNotFound
	}
	key := snapshotQuarantineKey(tenantID, nodeID, snapshotID)
	if key == "" || !validSnapshotQuarantineChange(action, reason) || now.IsZero() {
		return SnapshotQuarantineStatus{}, false, invalid("snapshot quarantine transition is invalid")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.availableLocked(); err != nil {
		return SnapshotQuarantineStatus{}, false, err
	}
	if err := store.revalidateOperatorLocked(actor); err != nil {
		return SnapshotQuarantineStatus{}, false, err
	}
	if !snapshotQuarantineTargetExists(store.current, tenantID, nodeID) {
		return SnapshotQuarantineStatus{}, false, ErrNotFound
	}
	current, exists := store.current.quarantines[key]
	if !exists {
		if expectedRevision != 0 {
			return SnapshotQuarantineStatus{}, false, ErrConflict
		}
		if action == SnapshotQuarantineActionClear {
			return snapshotQuarantineStatus(store.current.quarantines, tenantID, nodeID, snapshotID), false, nil
		}
		count := 0
		for _, record := range store.current.quarantines {
			if record.TenantID == tenantID {
				count++
			}
		}
		if count >= MaxSnapshotQuarantinesPerTenant {
			return SnapshotQuarantineStatus{}, false, ErrCapacityExceeded
		}
	} else {
		if current.Revision != expectedRevision {
			return SnapshotQuarantineStatus{}, false, ErrConflict
		}
		changedAt, _ := parseTimestamp(current.ChangedAt)
		if now.Before(changedAt) {
			return SnapshotQuarantineStatus{}, false, invalid("snapshot quarantine transition predates retained state")
		}
		wantBlocked := action == SnapshotQuarantineActionSet
		if current.Quarantined == wantBlocked && current.Reason == reason {
			return snapshotQuarantineStatus(store.current.quarantines, tenantID, nodeID, snapshotID), false, nil
		}
		if current.Revision == ^uint64(0) {
			return SnapshotQuarantineStatus{}, false, ErrCapacityExceeded
		}
	}
	revision := uint64(1)
	if exists {
		revision = current.Revision + 1
	}
	updated := SnapshotQuarantine{
		TenantID: tenantID, NodeID: nodeID, SnapshotID: snapshotID,
		Quarantined: action == SnapshotQuarantineActionSet,
		Revision:    revision, Reason: reason, ChangedAt: canonicalTimestamp(now),
	}
	if err := store.applyMutationsLocked(mutation{Kind: mutationSnapshotQuarantine, Quarantine: &updated}); err != nil {
		return SnapshotQuarantineStatus{}, false, err
	}
	return snapshotQuarantineStatus(store.current.quarantines, tenantID, nodeID, snapshotID), true, nil
}

func snapshotQuarantineStatus(
	records map[string]SnapshotQuarantine,
	tenantID, nodeID, snapshotID string,
) SnapshotQuarantineStatus {
	status := SnapshotQuarantineStatus{TenantID: tenantID, NodeID: nodeID, SnapshotID: snapshotID}
	if record, ok := records[snapshotQuarantineKey(tenantID, nodeID, snapshotID)]; ok {
		copy := record
		status.Record = &copy
		status.Blocked = record.Quarantined
	}
	return status
}

func snapshotQuarantineTargetExists(current state, tenantID, nodeID string) bool {
	tenant, tenantOK := current.tenants[tenantID]
	node, nodeOK := current.nodes[nodeID]
	return tenantOK && tenant.Active && nodeOK && tenantMember(node.TenantIDs, tenantID)
}

func snapshotQuarantineKey(tenantID, nodeID, snapshotID string) string {
	if !validRecordID(tenantID, 128) || !validRecordID(nodeID, 128) || !validRecordID(snapshotID, 128) {
		return ""
	}
	return tenantID + "\x00" + nodeID + "\x00" + snapshotID
}

func validSnapshotQuarantineChange(action SnapshotQuarantineAction, reason string) bool {
	switch action {
	case SnapshotQuarantineActionSet:
		return reason != "" && len(reason) <= 256 && strings.TrimSpace(reason) == reason &&
			boundedRetainedText(reason, 256)
	case SnapshotQuarantineActionClear:
		return reason == ""
	default:
		return false
	}
}

func validSnapshotQuarantine(value SnapshotQuarantine) bool {
	if snapshotQuarantineKey(value.TenantID, value.NodeID, value.SnapshotID) == "" ||
		value.Revision == 0 || !validTimestamp(value.ChangedAt) {
		return false
	}
	if value.Quarantined {
		return validSnapshotQuarantineChange(SnapshotQuarantineActionSet, value.Reason)
	}
	return validSnapshotQuarantineChange(SnapshotQuarantineActionClear, value.Reason)
}
