package controlstore

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"time"

	"github.com/hardrails/steward/internal/controlauth"
	"github.com/hardrails/steward/internal/controlprotocol"
)

type IncidentKind string

const (
	IncidentContainment IncidentKind = "containment"
	IncidentEvidence    IncidentKind = "evidence"
	IncidentAccess      IncidentKind = "access"
	IncidentWorkload    IncidentKind = "workload"
)

type IncidentSeverity string

const (
	IncidentInfo     IncidentSeverity = "info"
	IncidentWarning  IncidentSeverity = "warning"
	IncidentCritical IncidentSeverity = "critical"
)

// IncidentEvent is a metadata-only projection of the latest retained
// containment, access, evidence, or failed-workload fact. It is not an
// append-only audit log and cannot contain command bytes, results, credentials,
// prompts, request bodies, or response bodies.
type IncidentEvent struct {
	ID         string           `json:"id"`
	OccurredAt string           `json:"occurred_at"`
	Kind       IncidentKind     `json:"kind"`
	Action     string           `json:"action"`
	Severity   IncidentSeverity `json:"severity"`
	Scope      string           `json:"scope"`
	TenantID   string           `json:"tenant_id,omitempty"`
	NodeID     string           `json:"node_id,omitempty"`
	ResourceID string           `json:"resource_id,omitempty"`
	Reason     string           `json:"reason,omitempty"`
	Status     string           `json:"status,omitempty"`
	Count      uint64           `json:"count,omitempty"`
}

type IncidentTimelineQuery struct {
	TenantID string
	NodeID   string
	Kind     IncidentKind
	Severity IncidentSeverity
	Limit    int
	Cursor   string
}

type IncidentTimelinePage struct {
	Events     []IncidentEvent `json:"events"`
	NextCursor string          `json:"next_cursor,omitempty"`
}

// ListIncidentTimeline joins current incident-relevant controller facts into
// one deterministic chronology. It performs no acknowledgement or mutation.
func (store *Store) ListIncidentTimeline(
	actor controlauth.Identity,
	query IncidentTimelineQuery,
) (IncidentTimelinePage, error) {
	if store == nil {
		return IncidentTimelinePage{}, ErrUnavailable
	}
	limit, err := normalizeInventoryLimit(query.Limit)
	if err != nil {
		return IncidentTimelinePage{}, err
	}
	if query.NodeID != "" && !validRecordID(query.NodeID, 128) ||
		query.Kind != "" && !validIncidentKind(query.Kind) ||
		query.Severity != "" && !validIncidentSeverity(query.Severity) {
		return IncidentTimelinePage{}, invalid("incident timeline filter is invalid")
	}

	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.availableLocked(); err != nil {
		return IncidentTimelinePage{}, err
	}
	if err := store.revalidateOperatorLocked(actor); err != nil {
		return IncidentTimelinePage{}, err
	}
	scope, err := store.resolveOperationsScopeLocked(actor, query.TenantID)
	if err != nil {
		return IncidentTimelinePage{}, err
	}
	cursorBinding := operationsCursorBinding(
		"incident-timeline-v1", scope, query.NodeID, string(query.Kind), string(query.Severity),
	)
	after, err := decodeOperationsCursor(cursorBinding, query.Cursor)
	if err != nil {
		return IncidentTimelinePage{}, err
	}

	events := store.incidentTimelineLocked(scope)
	filtered := events[:0]
	for _, event := range events {
		if query.NodeID != "" && event.NodeID != query.NodeID ||
			query.Kind != "" && event.Kind != query.Kind ||
			query.Severity != "" && event.Severity != query.Severity {
			continue
		}
		filtered = append(filtered, event)
	}
	sort.Slice(filtered, func(i, j int) bool {
		return incidentTimelineSortKey(filtered[i]) < incidentTimelineSortKey(filtered[j])
	})
	page := IncidentTimelinePage{Events: make([]IncidentEvent, 0, minInt(limit, len(filtered)))}
	for _, event := range filtered {
		key := incidentTimelineSortKey(event)
		if key <= after {
			continue
		}
		if len(page.Events) == limit {
			page.NextCursor = encodeOperationsCursor(
				cursorBinding, incidentTimelineSortKey(page.Events[len(page.Events)-1]),
			)
			break
		}
		page.Events = append(page.Events, event)
	}
	return page, nil
}

func (store *Store) incidentTimelineLocked(scope operationsScope) []IncidentEvent {
	events := make([]IncidentEvent, 0)
	for _, freeze := range store.current.freezes {
		if freeze.Scope == OperationalFreezeTenant && !scope.siteWide && freeze.TenantID != scope.tenantID {
			continue
		}
		action, severity := "freeze_cleared", IncidentInfo
		if freeze.Frozen {
			action, severity = "freeze_set", IncidentCritical
		}
		events = appendIncidentEvent(events, IncidentEvent{
			OccurredAt: freeze.ChangedAt, Kind: IncidentContainment, Action: action,
			Severity: severity, Scope: string(freeze.Scope), TenantID: freeze.TenantID,
			Reason: freeze.Reason, Status: fmt.Sprintf("revision:%d", freeze.Revision),
		})
	}
	for _, quarantine := range store.current.quarantines {
		if !scope.siteWide && quarantine.TenantID != scope.tenantID {
			continue
		}
		action, severity := "snapshot_cleared", IncidentInfo
		if quarantine.Quarantined {
			action, severity = "snapshot_quarantined", IncidentCritical
		}
		events = appendIncidentEvent(events, IncidentEvent{
			OccurredAt: quarantine.ChangedAt, Kind: IncidentContainment, Action: action,
			Severity: severity, Scope: "tenant", TenantID: quarantine.TenantID,
			NodeID: quarantine.NodeID, ResourceID: quarantine.SnapshotID,
			Reason: quarantine.Reason, Status: fmt.Sprintf("revision:%d", quarantine.Revision),
		})
	}
	for _, node := range store.current.nodes {
		for _, tenantID := range incidentNodeTenants(node, scope) {
			events = append(events, incidentNodeEvents(node, tenantID)...)
		}
	}
	for _, credential := range store.current.credentials {
		if !credential.Revoked {
			continue
		}
		for _, tenantID := range incidentCredentialTenants(credential, scope) {
			events = appendIncidentEvent(events, IncidentEvent{
				OccurredAt: credential.RevokedAt, Kind: IncidentAccess,
				Action: "credential_revoked", Severity: IncidentWarning,
				Scope: incidentScope(tenantID), TenantID: tenantID, NodeID: credential.NodeID,
				ResourceID: credential.ID, Status: string(credential.Kind),
			})
		}
	}
	for _, command := range store.current.commands {
		if !scope.siteWide && command.TenantID != scope.tenantID || command.Terminal == nil {
			continue
		}
		status := commandTerminalStatus(command)
		severity := IncidentSeverity("")
		switch status {
		case controlprotocol.ExecutorStatusRejected:
			severity = IncidentWarning
		case controlprotocol.ExecutorStatusFailed, controlprotocol.ExecutorStatusOutcomeUnknown:
			severity = IncidentCritical
		default:
			continue
		}
		events = appendIncidentEvent(events, IncidentEvent{
			OccurredAt: command.Terminal.CompletedAt, Kind: IncidentWorkload,
			Action: "command_" + status, Severity: severity, Scope: "tenant",
			TenantID: command.TenantID, NodeID: command.NodeID, ResourceID: command.ID,
			Status: command.CommandKind,
		})
	}
	for _, deployment := range store.current.deployments {
		if !scope.siteWide && deployment.TenantID != scope.tenantID {
			continue
		}
		for _, instance := range deployment.Instances {
			if instance.LastError == "" {
				continue
			}
			severity := IncidentWarning
			if instance.Phase == DeploymentInstanceFailed || deployment.Phase == DeploymentDegraded {
				severity = IncidentCritical
			}
			events = appendIncidentEvent(events, IncidentEvent{
				OccurredAt: instance.TransitionedAt, Kind: IncidentWorkload,
				Action: "deployment_blocked", Severity: severity, Scope: "tenant",
				TenantID: deployment.TenantID, NodeID: instance.NodeID,
				ResourceID: deployment.ID + "/" + instance.InstanceID,
				Reason:     instance.LastError, Status: string(instance.Phase),
			})
		}
	}
	return events
}

func incidentNodeEvents(node Node, tenantID string) []IncidentEvent {
	events := make([]IncidentEvent, 0, 4)
	if node.Placement != nil {
		severity := IncidentInfo
		if node.Placement.Mode == NodeCordoned {
			severity = IncidentWarning
		} else if node.Placement.Mode == NodeQuarantined {
			severity = IncidentCritical
		}
		events = appendIncidentEvent(events, IncidentEvent{
			OccurredAt: node.Placement.ChangedAt, Kind: IncidentContainment,
			Action: "node_" + string(node.Placement.Mode), Severity: severity,
			Scope: "tenant", TenantID: tenantID, NodeID: node.ID,
			Reason: node.Placement.Reason,
		})
	}
	if !node.Active && node.RevokedAt != "" {
		events = appendIncidentEvent(events, IncidentEvent{
			OccurredAt: node.RevokedAt, Kind: IncidentAccess, Action: "node_revoked",
			Severity: IncidentCritical, Scope: "tenant", TenantID: tenantID, NodeID: node.ID,
		})
	}
	if node.Drain != nil {
		severity := IncidentInfo
		if node.Drain.State == NodeDrainActive {
			severity = IncidentWarning
		} else if node.Drain.State == NodeDrainFailed {
			severity = IncidentCritical
		}
		events = appendIncidentEvent(events, IncidentEvent{
			OccurredAt: node.Drain.UpdatedAt, Kind: IncidentContainment,
			Action: "node_drain_" + string(node.Drain.State), Severity: severity,
			Scope: "tenant", TenantID: tenantID, NodeID: node.ID,
			ResourceID: node.Drain.RequestID, Reason: node.Drain.Reason,
			Status: node.Drain.FailedInstanceID,
		})
	}
	if node.Evidence != nil && node.Evidence.Finding != nil {
		finding := node.Evidence.Finding
		events = appendIncidentEvent(events, IncidentEvent{
			OccurredAt: finding.LastObservedAt, Kind: IncidentEvidence,
			Action: "evidence_" + string(finding.LastReason), Severity: IncidentCritical,
			Scope: "tenant", TenantID: tenantID, NodeID: node.ID,
			Status: fmt.Sprintf("sequence:%d", finding.LastSequence), Count: finding.Count,
		})
	}
	return events
}

func incidentNodeTenants(node Node, scope operationsScope) []string {
	if !scope.siteWide {
		if tenantMember(node.TenantIDs, scope.tenantID) {
			return []string{scope.tenantID}
		}
		return nil
	}
	return append([]string(nil), node.TenantIDs...)
}

func incidentCredentialTenants(credential controlauth.Credential, scope operationsScope) []string {
	if !credentialVisibleInScope(credential, scope) {
		return nil
	}
	if credential.Kind == controlauth.KindNode {
		if scope.siteWide {
			return append([]string(nil), credential.TenantIDs...)
		}
		return []string{scope.tenantID}
	}
	if credential.Role == controlauth.RoleTenantOperator {
		return []string{credential.TenantID}
	}
	return []string{""}
}

func appendIncidentEvent(events []IncidentEvent, event IncidentEvent) []IncidentEvent {
	event.ID = stableIncidentEventID(event)
	return append(events, event)
}

func stableIncidentEventID(event IncidentEvent) string {
	digest := sha256.New()
	_, _ = digest.Write([]byte("steward-incident-event-v1\x00"))
	for _, value := range []string{
		event.OccurredAt, string(event.Kind), event.Action, string(event.Severity), event.Scope,
		event.TenantID, event.NodeID, event.ResourceID, event.Reason, event.Status,
		fmt.Sprintf("%d", event.Count),
	} {
		_, _ = digest.Write([]byte(value))
		_, _ = digest.Write([]byte{0})
	}
	return "incident-" + hex.EncodeToString(digest.Sum(nil))
}

func incidentTimelineSortKey(event IncidentEvent) string {
	when, _ := time.Parse(time.RFC3339Nano, event.OccurredAt)
	seconds := uint64(when.Unix()) ^ (uint64(1) << 63)
	return fmt.Sprintf("%016x%08x\x00%s", ^seconds, uint32(999999999-when.Nanosecond()), event.ID)
}

func incidentScope(tenantID string) string {
	if tenantID == "" {
		return "site"
	}
	return "tenant"
}

func validIncidentKind(kind IncidentKind) bool {
	return kind == IncidentContainment || kind == IncidentEvidence ||
		kind == IncidentAccess || kind == IncidentWorkload
}

func validIncidentSeverity(severity IncidentSeverity) bool {
	return severity == IncidentInfo || severity == IncidentWarning || severity == IncidentCritical
}
