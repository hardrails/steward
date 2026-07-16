package controlstore

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"sort"
	"strings"
	"time"

	"github.com/hardrails/steward/internal/controlauth"
	"github.com/hardrails/steward/internal/controlprotocol"
)

const (
	DefaultInventoryPageLimit = 100
	MaxInventoryPageLimit     = 500
	MaxOperationsThreshold    = 365 * 24 * time.Hour
	maxOperationsCursorBytes  = 4096
)

// OperationsThresholds controls when derived operational facts require
// attention. The values are bounded so untrusted query parameters cannot
// overflow time arithmetic or silently disable findings for unreasonable
// periods.
type OperationsThresholds struct {
	NodeStaleAfter         time.Duration `json:"node_stale_after"`
	EvidenceStaleAfter     time.Duration `json:"evidence_stale_after"`
	CommandOverdueAfter    time.Duration `json:"command_overdue_after"`
	CapacityWarningPercent int           `json:"capacity_warning_percent"`
}

func DefaultOperationsThresholds() OperationsThresholds {
	return OperationsThresholds{
		NodeStaleAfter: 2 * time.Minute, EvidenceStaleAfter: 5 * time.Minute,
		CommandOverdueAfter: 5 * time.Minute, CapacityWarningPercent: 80,
	}
}

func (thresholds OperationsThresholds) Validate() error {
	for _, value := range []time.Duration{
		thresholds.NodeStaleAfter, thresholds.EvidenceStaleAfter, thresholds.CommandOverdueAfter,
	} {
		if value <= 0 || value > MaxOperationsThreshold {
			return invalid("operations freshness thresholds must be positive and at most 365 days")
		}
	}
	if thresholds.CapacityWarningPercent <= 0 || thresholds.CapacityWarningPercent > 100 {
		return invalid("capacity warning percent must be between 1 and 100")
	}
	return nil
}

// CommandInventoryQuery selects a bounded metadata-only command page. Cursor
// is opaque and is meaningful only with the same filters.
type CommandInventoryQuery struct {
	TenantID       string
	NodeID         string
	State          CommandState
	TerminalStatus string
	Limit          int
	Cursor         string
}

// CommandMetadata excludes the signed command bytes and terminal result text.
// It is safe to use in fleet inventories where payloads may contain secrets.
type CommandMetadata struct {
	TenantID           string       `json:"tenant_id"`
	NodeID             string       `json:"node_id"`
	ID                 string       `json:"id"`
	DeliveryID         string       `json:"delivery_id"`
	Digest             string       `json:"digest"`
	State              CommandState `json:"state"`
	DeliveryGeneration uint64       `json:"delivery_generation"`
	LeaseUntil         string       `json:"lease_until,omitempty"`
	CreatedAt          string       `json:"created_at"`
	TerminalStatus     string       `json:"terminal_status,omitempty"`
	ReportedStatus     string       `json:"reported_status,omitempty"`
	ErrorCode          string       `json:"error_code,omitempty"`
	CompletedAt        string       `json:"completed_at,omitempty"`
}

type CommandInventoryPage struct {
	Commands   []CommandMetadata `json:"commands"`
	NextCursor string            `json:"next_cursor,omitempty"`
}

// CredentialInventoryQuery selects durable credential metadata. Revoked is a
// tri-state filter: nil includes both active and revoked credentials.
type CredentialInventoryQuery struct {
	TenantID string
	Kind     controlauth.CredentialKind
	Role     controlauth.Role
	NodeID   string
	Revoked  *bool
	Limit    int
	Cursor   string
}

// CredentialMetadata is the non-secret half of a credential. Token MACs and
// reproducible bearer material never leave Store through this view.
type CredentialMetadata struct {
	ID        string                     `json:"id"`
	Kind      controlauth.CredentialKind `json:"kind"`
	Role      controlauth.Role           `json:"role,omitempty"`
	TenantID  string                     `json:"tenant_id,omitempty"`
	TenantIDs []string                   `json:"tenant_ids,omitempty"`
	NodeID    string                     `json:"node_id,omitempty"`
	Audience  string                     `json:"audience,omitempty"`
	RequestID string                     `json:"request_id,omitempty"`
	CreatedAt string                     `json:"created_at"`
	Revoked   bool                       `json:"revoked"`
	RevokedAt string                     `json:"revoked_at,omitempty"`
}

type CredentialInventoryPage struct {
	Credentials []CredentialMetadata `json:"credentials"`
	NextCursor  string               `json:"next_cursor,omitempty"`
}

type CapacityResource string

const (
	CapacityTenants     CapacityResource = "tenants"
	CapacityNodes       CapacityResource = "nodes"
	CapacityCredentials CapacityResource = "credentials"
	CapacityEnrollments CapacityResource = "enrollments"
	CapacityCommands    CapacityResource = "commands"
)

type CapacityUsage struct {
	Resource CapacityResource `json:"resource"`
	Used     int              `json:"used"`
	Limit    int              `json:"limit"`
	Warning  bool             `json:"warning"`
}

type CommandSummary struct {
	Total          int `json:"total"`
	Pending        int `json:"pending"`
	Leased         int `json:"leased"`
	Terminal       int `json:"terminal"`
	Done           int `json:"done"`
	Failed         int `json:"failed"`
	Rejected       int `json:"rejected"`
	OutcomeUnknown int `json:"outcome_unknown"`
}

type EvidenceSummary struct {
	Nodes                int `json:"nodes"`
	ActiveNodes          int `json:"active_nodes"`
	Witnessed            int `json:"witnessed"`
	Unwitnessed          int `json:"unwitnessed"`
	Current              int `json:"current"`
	Stale                int `json:"stale"`
	RollbackDetected     int `json:"rollback_detected"`
	EquivocationDetected int `json:"equivocation_detected"`
}

type OperationsSummary struct {
	GeneratedAt string           `json:"generated_at"`
	TenantID    string           `json:"tenant_id,omitempty"`
	Capacity    []CapacityUsage  `json:"capacity"`
	Commands    CommandSummary   `json:"commands"`
	Evidence    EvidenceSummary  `json:"evidence"`
	Attention   AttentionSummary `json:"attention"`
}

type AttentionReason string

const (
	AttentionNodeNeverSeen         AttentionReason = "node_never_seen"
	AttentionNodeStale             AttentionReason = "node_stale"
	AttentionEvidenceUnwitnessed   AttentionReason = "evidence_unwitnessed"
	AttentionEvidenceStale         AttentionReason = "evidence_stale"
	AttentionRollbackDetected      AttentionReason = "rollback_detected"
	AttentionEquivocationDetected  AttentionReason = "equivocation_detected"
	AttentionCommandPendingOverdue AttentionReason = "command_pending_overdue"
	AttentionCommandLeaseExpired   AttentionReason = "command_lease_expired"
	AttentionCommandFailed         AttentionReason = "command_failed"
	AttentionCommandOutcomeUnknown AttentionReason = "command_outcome_unknown"
	AttentionCapacityWarning       AttentionReason = "capacity_warning"
)

type AttentionSeverity string

const (
	AttentionWarning  AttentionSeverity = "warning"
	AttentionCritical AttentionSeverity = "critical"
)

type AttentionResource string

const (
	AttentionResourceNode     AttentionResource = "node"
	AttentionResourceEvidence AttentionResource = "evidence"
	AttentionResourceCommand  AttentionResource = "command"
	AttentionResourceCapacity AttentionResource = "capacity"
)

// AttentionItem is a derived fact, not mutable workflow state. ID is stable
// for the same tenant, reason, and resource identity across queries and
// controller restarts.
type AttentionItem struct {
	ID               string            `json:"id"`
	Reason           AttentionReason   `json:"reason"`
	Severity         AttentionSeverity `json:"severity"`
	Resource         AttentionResource `json:"resource"`
	TenantID         string            `json:"tenant_id,omitempty"`
	NodeID           string            `json:"node_id,omitempty"`
	CommandID        string            `json:"command_id,omitempty"`
	CapacityResource CapacityResource  `json:"capacity_resource,omitempty"`
	Since            string            `json:"since,omitempty"`
	State            string            `json:"state,omitempty"`
	Status           string            `json:"status,omitempty"`
	Used             int               `json:"used,omitempty"`
	Limit            int               `json:"limit,omitempty"`
}

type AttentionQuery struct {
	TenantID   string
	Reason     AttentionReason
	Now        time.Time
	Thresholds OperationsThresholds
	Limit      int
	Cursor     string
}

type AttentionPage struct {
	Items      []AttentionItem `json:"items"`
	NextCursor string          `json:"next_cursor,omitempty"`
}

type AttentionCount struct {
	Reason   AttentionReason   `json:"reason"`
	Severity AttentionSeverity `json:"severity"`
	Count    int               `json:"count"`
}

type AttentionSummary struct {
	Total    int              `json:"total"`
	Warnings int              `json:"warnings"`
	Critical int              `json:"critical"`
	Counts   []AttentionCount `json:"counts"`
}

// ListCommandInventory returns no command payload bytes and performs no
// reclamation, retry, or other state mutation.
func (store *Store) ListCommandInventory(actor controlauth.Identity, query CommandInventoryQuery) (CommandInventoryPage, error) {
	if store == nil {
		return CommandInventoryPage{}, ErrUnavailable
	}
	limit, err := normalizeInventoryLimit(query.Limit)
	if err != nil {
		return CommandInventoryPage{}, err
	}
	after, err := decodeOperationsCursor("command-v1", query.Cursor)
	if err != nil {
		return CommandInventoryPage{}, err
	}
	if query.NodeID != "" && !validRecordID(query.NodeID, 128) ||
		query.State != "" && !validCommandState(query.State) ||
		query.TerminalStatus != "" && !validTerminalStatus(query.TerminalStatus) {
		return CommandInventoryPage{}, invalid("command inventory filter is invalid")
	}

	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.availableLocked(); err != nil {
		return CommandInventoryPage{}, err
	}
	if err := store.revalidateOperatorLocked(actor); err != nil {
		return CommandInventoryPage{}, err
	}
	scope, err := store.resolveOperationsScopeLocked(actor, query.TenantID)
	if err != nil {
		return CommandInventoryPage{}, err
	}

	keys := make([]string, 0, len(store.current.commands))
	for key, command := range store.current.commands {
		if !scope.siteWide && command.TenantID != scope.tenantID ||
			query.NodeID != "" && command.NodeID != query.NodeID ||
			query.State != "" && command.State != query.State ||
			query.TerminalStatus != "" && commandTerminalStatus(command) != query.TerminalStatus {
			continue
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	page := CommandInventoryPage{Commands: make([]CommandMetadata, 0, minInt(limit, len(keys)))}
	for _, key := range keys {
		if key <= after {
			continue
		}
		if len(page.Commands) == limit {
			page.NextCursor = encodeOperationsCursor("command-v1", commandInventorySortKey(page.Commands[len(page.Commands)-1]))
			break
		}
		page.Commands = append(page.Commands, commandMetadata(store.current.commands[key]))
	}
	return page, nil
}

// ListCredentialInventory returns only non-secret durable metadata. A scoped
// view projects multi-tenant node credentials to the requested tenant.
func (store *Store) ListCredentialInventory(actor controlauth.Identity, query CredentialInventoryQuery) (CredentialInventoryPage, error) {
	if store == nil {
		return CredentialInventoryPage{}, ErrUnavailable
	}
	limit, err := normalizeInventoryLimit(query.Limit)
	if err != nil {
		return CredentialInventoryPage{}, err
	}
	after, err := decodeOperationsCursor("credential-v1", query.Cursor)
	if err != nil {
		return CredentialInventoryPage{}, err
	}
	if query.Kind != "" && query.Kind != controlauth.KindOperator && query.Kind != controlauth.KindNode ||
		query.Role != "" && query.Role != controlauth.RoleSiteAdmin && query.Role != controlauth.RoleTenantOperator ||
		query.NodeID != "" && !validRecordID(query.NodeID, 128) {
		return CredentialInventoryPage{}, invalid("credential inventory filter is invalid")
	}

	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.availableLocked(); err != nil {
		return CredentialInventoryPage{}, err
	}
	if err := store.revalidateOperatorLocked(actor); err != nil {
		return CredentialInventoryPage{}, err
	}
	scope, err := store.resolveOperationsScopeLocked(actor, query.TenantID)
	if err != nil {
		return CredentialInventoryPage{}, err
	}

	ids := make([]string, 0, len(store.current.credentials))
	for id, credential := range store.current.credentials {
		if !credentialVisibleInScope(credential, scope) ||
			query.Kind != "" && credential.Kind != query.Kind ||
			query.Role != "" && credential.Role != query.Role ||
			query.NodeID != "" && credential.NodeID != query.NodeID ||
			query.Revoked != nil && credential.Revoked != *query.Revoked {
			continue
		}
		ids = append(ids, id)
	}
	sort.Strings(ids)
	page := CredentialInventoryPage{Credentials: make([]CredentialMetadata, 0, minInt(limit, len(ids)))}
	for _, id := range ids {
		if id <= after {
			continue
		}
		if len(page.Credentials) == limit {
			page.NextCursor = encodeOperationsCursor("credential-v1", page.Credentials[len(page.Credentials)-1].ID)
			break
		}
		page.Credentials = append(page.Credentials, credentialMetadata(store.current.credentials[id], scope))
	}
	return page, nil
}

// OperationsSummary returns capacity, command, and evidence facts for a site
// or one exact tenant without deriving authority from those observations.
func (store *Store) OperationsSummary(actor controlauth.Identity, tenantID string, now time.Time, thresholds OperationsThresholds) (OperationsSummary, error) {
	if store == nil {
		return OperationsSummary{}, ErrUnavailable
	}
	if now.IsZero() {
		return OperationsSummary{}, invalid("operations summary time is required")
	}
	if err := thresholds.Validate(); err != nil {
		return OperationsSummary{}, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.availableLocked(); err != nil {
		return OperationsSummary{}, err
	}
	if err := store.revalidateOperatorLocked(actor); err != nil {
		return OperationsSummary{}, err
	}
	scope, err := store.resolveOperationsScopeLocked(actor, tenantID)
	if err != nil {
		return OperationsSummary{}, err
	}
	summary := OperationsSummary{
		GeneratedAt: canonicalTimestamp(now), TenantID: scope.tenantID,
		Capacity: store.capacityUsageLocked(scope, thresholds.CapacityWarningPercent),
		Commands: store.commandSummaryLocked(scope),
		Evidence: store.evidenceSummaryLocked(scope, now, thresholds),
	}
	summary.Attention = store.attentionSummaryLocked(scope, now, thresholds)
	return summary, nil
}

// ListAttention deterministically derives bounded action-required items. It
// never acknowledges findings, changes command state, or retries an effect.
func (store *Store) ListAttention(actor controlauth.Identity, query AttentionQuery) (AttentionPage, error) {
	if store == nil {
		return AttentionPage{}, ErrUnavailable
	}
	if query.Now.IsZero() {
		return AttentionPage{}, invalid("attention query time is required")
	}
	if err := query.Thresholds.Validate(); err != nil {
		return AttentionPage{}, err
	}
	if query.Reason != "" && !validAttentionReason(query.Reason) {
		return AttentionPage{}, invalid("attention reason filter is invalid")
	}
	limit, err := normalizeInventoryLimit(query.Limit)
	if err != nil {
		return AttentionPage{}, err
	}
	after, err := decodeOperationsCursor("attention-v1", query.Cursor)
	if err != nil {
		return AttentionPage{}, err
	}

	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.availableLocked(); err != nil {
		return AttentionPage{}, err
	}
	if err := store.revalidateOperatorLocked(actor); err != nil {
		return AttentionPage{}, err
	}
	scope, err := store.resolveOperationsScopeLocked(actor, query.TenantID)
	if err != nil {
		return AttentionPage{}, err
	}

	collector := &attentionCollector{
		after: after, limit: limit, reason: query.Reason,
		items: make([]AttentionItem, 0, limit),
	}
	store.emitAttentionLocked(collector, scope, query.Now, query.Thresholds)
	return collector.page(), nil
}

type attentionSink interface {
	add(AttentionItem) bool
}

func (store *Store) emitAttentionLocked(sink attentionSink, scope operationsScope, now time.Time, thresholds OperationsThresholds) {
	if scope.siteWide &&
		!store.addCapacityAttention(sink, operationsScope{siteWide: true}, thresholds.CapacityWarningPercent) {
		return
	}
	tenantIDs := []string{scope.tenantID}
	if scope.siteWide {
		tenantIDs = make([]string, 0, len(store.current.tenants))
		for tenantID := range store.current.tenants {
			tenantIDs = append(tenantIDs, tenantID)
		}
		sort.Strings(tenantIDs)
	}
	nodes := make([]Node, 0, len(store.current.nodes))
	for _, node := range store.current.nodes {
		nodes = append(nodes, node)
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })
	commandKeys := make([]string, 0, len(store.current.commands))
	for key := range store.current.commands {
		commandKeys = append(commandKeys, key)
	}
	sort.Strings(commandKeys)

	for _, tenantID := range tenantIDs {
		tenantScope := operationsScope{tenantID: tenantID}
		if !store.addCapacityAttention(sink, tenantScope, thresholds.CapacityWarningPercent) {
			return
		}
		for _, node := range nodes {
			if !tenantMember(node.TenantIDs, tenantID) {
				continue
			}
			if !store.addNodeAttention(sink, tenantID, node, now, thresholds) {
				return
			}
		}
		for _, key := range commandKeys {
			command := store.current.commands[key]
			if command.TenantID != tenantID {
				continue
			}
			if !addCommandAttention(sink, command, now, thresholds) {
				return
			}
		}
	}
}

type operationsScope struct {
	tenantID string
	siteWide bool
}

func (store *Store) resolveOperationsScopeLocked(actor controlauth.Identity, requested string) (operationsScope, error) {
	if requested != "" && !validRecordID(requested, 128) {
		return operationsScope{}, invalid("operations tenant filter is invalid")
	}
	if controlauth.IsSiteAdmin(actor) {
		if requested == "" {
			return operationsScope{siteWide: true}, nil
		}
		if _, ok := store.current.tenants[requested]; !ok {
			return operationsScope{}, ErrNotFound
		}
		return operationsScope{tenantID: requested}, nil
	}
	if actor.Role != controlauth.RoleTenantOperator || !validRecordID(actor.TenantID, 128) {
		return operationsScope{}, ErrForbidden
	}
	if requested != "" && requested != actor.TenantID {
		return operationsScope{}, ErrNotFound
	}
	if _, ok := store.current.tenants[actor.TenantID]; !ok {
		return operationsScope{}, ErrNotFound
	}
	return operationsScope{tenantID: actor.TenantID}, nil
}

func commandMetadata(command Command) CommandMetadata {
	metadata := CommandMetadata{
		TenantID: command.TenantID, NodeID: command.NodeID, ID: command.ID,
		DeliveryID: command.DeliveryID, Digest: command.Digest, State: command.State,
		DeliveryGeneration: command.DeliveryGeneration, LeaseUntil: command.LeaseUntil,
		CreatedAt: command.CreatedAt,
	}
	if command.Terminal != nil {
		metadata.TerminalStatus = command.Terminal.Report.Status
		metadata.ReportedStatus = command.Terminal.Report.ReportedStatus
		metadata.ErrorCode = command.Terminal.Report.ErrorCode
		metadata.CompletedAt = command.Terminal.CompletedAt
	}
	return metadata
}

func commandInventorySortKey(command CommandMetadata) string {
	return command.TenantID + "\x00" + command.NodeID + "\x00" + command.ID
}

func commandTerminalStatus(command Command) string {
	if command.Terminal == nil {
		return ""
	}
	return command.Terminal.Report.Status
}

func validCommandState(state CommandState) bool {
	return state == CommandPending || state == CommandLeased || state == CommandTerminal
}

func validTerminalStatus(status string) bool {
	switch status {
	case controlprotocol.ExecutorStatusDone, controlprotocol.ExecutorStatusFailed,
		controlprotocol.ExecutorStatusRejected, controlprotocol.ExecutorStatusOutcomeUnknown:
		return true
	default:
		return false
	}
}

func credentialVisibleInScope(credential controlauth.Credential, scope operationsScope) bool {
	if scope.siteWide {
		return true
	}
	switch credential.Kind {
	case controlauth.KindOperator:
		return credential.Role == controlauth.RoleTenantOperator && credential.TenantID == scope.tenantID
	case controlauth.KindNode:
		return tenantMember(credential.TenantIDs, scope.tenantID)
	default:
		return false
	}
}

func credentialMetadata(credential controlauth.Credential, scope operationsScope) CredentialMetadata {
	metadata := CredentialMetadata{
		ID: credential.ID, Kind: credential.Kind, Role: credential.Role,
		TenantID: credential.TenantID, TenantIDs: append([]string(nil), credential.TenantIDs...),
		NodeID: credential.NodeID, Audience: credential.Audience, RequestID: credential.RequestID,
		CreatedAt: credential.CreatedAt, Revoked: credential.Revoked, RevokedAt: credential.RevokedAt,
	}
	if !scope.siteWide && credential.Kind == controlauth.KindNode {
		metadata.TenantIDs = []string{scope.tenantID}
	}
	return metadata
}

func (store *Store) capacityUsageLocked(scope operationsScope, warningPercent int) []CapacityUsage {
	if scope.siteWide {
		return markCapacityWarnings([]CapacityUsage{
			{Resource: CapacityTenants, Used: len(store.current.tenants), Limit: store.limits.MaxTenants},
			{Resource: CapacityNodes, Used: len(store.current.nodes), Limit: store.limits.MaxNodes},
			{Resource: CapacityCredentials, Used: len(store.current.credentials), Limit: store.limits.MaxCredentials},
			{Resource: CapacityEnrollments, Used: len(store.current.enrollments), Limit: store.limits.MaxEnrollments},
			{Resource: CapacityCommands, Used: len(store.current.commands), Limit: store.limits.MaxCommands},
		}, warningPercent)
	}
	nodes, credentials, enrollments, commands := 0, 0, 0, 0
	for _, node := range store.current.nodes {
		if tenantMember(node.TenantIDs, scope.tenantID) {
			nodes++
		}
	}
	for _, credential := range store.current.credentials {
		if credential.Kind == controlauth.KindOperator && credential.Role == controlauth.RoleTenantOperator &&
			credential.TenantID == scope.tenantID ||
			credential.Kind == controlauth.KindNode && tenantMember(credential.TenantIDs, scope.tenantID) {
			credentials++
		}
	}
	for _, enrollment := range store.current.enrollments {
		if tenantMember(enrollment.TenantIDs, scope.tenantID) {
			enrollments++
		}
	}
	for _, command := range store.current.commands {
		if command.TenantID == scope.tenantID {
			commands++
		}
	}
	return markCapacityWarnings([]CapacityUsage{
		{Resource: CapacityNodes, Used: nodes, Limit: store.limits.MaxNodesPerTenant},
		{Resource: CapacityCredentials, Used: credentials, Limit: store.limits.MaxCredentialsPerTenant},
		{Resource: CapacityEnrollments, Used: enrollments, Limit: store.limits.MaxEnrollmentsPerTenant},
		{Resource: CapacityCommands, Used: commands, Limit: store.limits.MaxCommandsPerTenant},
	}, warningPercent)
}

func markCapacityWarnings(values []CapacityUsage, percent int) []CapacityUsage {
	for index := range values {
		values[index].Warning = capacityAtOrAbove(values[index].Used, values[index].Limit, percent)
	}
	return values
}

func capacityAtOrAbove(used, limit, percent int) bool {
	if used < 0 || limit <= 0 || percent <= 0 || percent > 100 {
		return false
	}
	whole := limit / 100 * percent
	remainder := ((limit%100)*percent + 99) / 100
	return used >= whole+remainder
}

func (store *Store) commandSummaryLocked(scope operationsScope) CommandSummary {
	var summary CommandSummary
	for _, command := range store.current.commands {
		if !scope.siteWide && command.TenantID != scope.tenantID {
			continue
		}
		summary.Total++
		switch command.State {
		case CommandPending:
			summary.Pending++
		case CommandLeased:
			summary.Leased++
		case CommandTerminal:
			summary.Terminal++
			switch commandTerminalStatus(command) {
			case controlprotocol.ExecutorStatusDone:
				summary.Done++
			case controlprotocol.ExecutorStatusFailed:
				summary.Failed++
			case controlprotocol.ExecutorStatusRejected:
				summary.Rejected++
			case controlprotocol.ExecutorStatusOutcomeUnknown:
				summary.OutcomeUnknown++
			}
		}
	}
	return summary
}

func (store *Store) evidenceSummaryLocked(scope operationsScope, now time.Time, thresholds OperationsThresholds) EvidenceSummary {
	var summary EvidenceSummary
	for _, node := range store.current.nodes {
		if !scope.siteWide && !tenantMember(node.TenantIDs, scope.tenantID) {
			continue
		}
		summary.Nodes++
		if node.Evidence != nil && node.Evidence.Finding != nil {
			for _, reason := range distinctEvidenceFindingReasons(node.Evidence.Finding) {
				switch reason {
				case EvidenceRollback:
					summary.RollbackDetected++
				case EvidenceFork:
					summary.EquivocationDetected++
				}
			}
		}
		if !node.Active {
			continue
		}
		summary.ActiveNodes++
		if node.Evidence == nil {
			summary.Unwitnessed++
			continue
		}
		summary.Witnessed++
		reportedAt, known := store.executorEvidenceReportRecencyLocked(node)
		stale := !known || elapsedThreshold(now, reportedAt, thresholds.EvidenceStaleAfter)
		if stale {
			summary.Stale++
		}
		if !stale && node.Evidence.Finding == nil {
			summary.Current++
		}
	}
	return summary
}

type attentionCollector struct {
	after   string
	limit   int
	reason  AttentionReason
	items   []AttentionItem
	lastKey string
	more    bool
}

func (collector *attentionCollector) add(item AttentionItem) bool {
	if collector.reason != "" && item.Reason != collector.reason {
		return true
	}
	key := attentionSortKey(item)
	if key <= collector.after {
		return true
	}
	if len(collector.items) == collector.limit {
		collector.more = true
		return false
	}
	collector.items = append(collector.items, item)
	collector.lastKey = key
	return true
}

type attentionCounter struct {
	total    int
	warnings int
	critical int
	counts   map[string]AttentionCount
}

func (counter *attentionCounter) add(item AttentionItem) bool {
	counter.total++
	switch item.Severity {
	case AttentionWarning:
		counter.warnings++
	case AttentionCritical:
		counter.critical++
	}
	key := string(item.Reason) + "\x00" + string(item.Severity)
	value := counter.counts[key]
	value.Reason = item.Reason
	value.Severity = item.Severity
	value.Count++
	counter.counts[key] = value
	return true
}

func (store *Store) attentionSummaryLocked(scope operationsScope, now time.Time, thresholds OperationsThresholds) AttentionSummary {
	counter := &attentionCounter{counts: make(map[string]AttentionCount)}
	store.emitAttentionLocked(counter, scope, now, thresholds)
	summary := AttentionSummary{
		Total: counter.total, Warnings: counter.warnings, Critical: counter.critical,
		Counts: make([]AttentionCount, 0, len(counter.counts)),
	}
	for _, count := range counter.counts {
		summary.Counts = append(summary.Counts, count)
	}
	sort.Slice(summary.Counts, func(i, j int) bool {
		if summary.Counts[i].Reason != summary.Counts[j].Reason {
			return summary.Counts[i].Reason < summary.Counts[j].Reason
		}
		return summary.Counts[i].Severity < summary.Counts[j].Severity
	})
	return summary
}

func (collector *attentionCollector) page() AttentionPage {
	page := AttentionPage{Items: collector.items}
	if collector.more && collector.lastKey != "" {
		page.NextCursor = encodeOperationsCursor("attention-v1", collector.lastKey)
	}
	return page
}

func (store *Store) addCapacityAttention(sink attentionSink, scope operationsScope, warningPercent int) bool {
	items := make([]AttentionItem, 0, 5)
	for _, usage := range store.capacityUsageLocked(scope, warningPercent) {
		if !usage.Warning {
			continue
		}
		item := AttentionItem{
			Reason: AttentionCapacityWarning, Severity: AttentionWarning,
			Resource: AttentionResourceCapacity, TenantID: scope.tenantID,
			CapacityResource: usage.Resource, Used: usage.Used, Limit: usage.Limit,
		}
		item.ID = stableAttentionID(item)
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool { return attentionSortKey(items[i]) < attentionSortKey(items[j]) })
	for _, item := range items {
		if !sink.add(item) {
			return false
		}
	}
	return true
}

func (store *Store) addNodeAttention(sink attentionSink, tenantID string, node Node, now time.Time, thresholds OperationsThresholds) bool {
	items := make([]AttentionItem, 0, 5)
	if node.Active {
		switch {
		case node.LastSeenAt == "" && elapsedThreshold(now, node.CreatedAt, thresholds.NodeStaleAfter):
			items = append(items, newNodeAttention(AttentionNodeNeverSeen, AttentionWarning, tenantID, node.ID, node.CreatedAt))
		case node.LastSeenAt != "" && elapsedThreshold(now, node.LastSeenAt, thresholds.NodeStaleAfter):
			items = append(items, newNodeAttention(AttentionNodeStale, AttentionWarning, tenantID, node.ID, node.LastSeenAt))
		}
		if node.Evidence == nil {
			if elapsedThreshold(now, node.CreatedAt, thresholds.EvidenceStaleAfter) {
				items = append(items, newEvidenceAttention(AttentionEvidenceUnwitnessed, AttentionWarning, tenantID, node.ID, node.CreatedAt))
			}
		} else if reportedAt, known := store.executorEvidenceReportRecencyLocked(node); !known || elapsedThreshold(now, reportedAt, thresholds.EvidenceStaleAfter) {
			items = append(items, newEvidenceAttention(
				AttentionEvidenceStale, AttentionWarning, tenantID, node.ID,
				reportedAt,
			))
		}
	}
	if node.Evidence != nil && node.Evidence.Finding != nil {
		finding := node.Evidence.Finding
		for _, retainedReason := range distinctEvidenceFindingReasons(finding) {
			reason := AttentionEquivocationDetected
			since := finding.LastObservedAt
			if retainedReason == finding.FirstReason {
				since = finding.FirstObservedAt
			}
			if retainedReason == EvidenceRollback {
				reason = AttentionRollbackDetected
			}
			items = append(items, newEvidenceAttention(
				reason, AttentionCritical, tenantID, node.ID, since,
			))
		}
	}
	sort.Slice(items, func(i, j int) bool { return attentionSortKey(items[i]) < attentionSortKey(items[j]) })
	for _, item := range items {
		if !sink.add(item) {
			return false
		}
	}
	return true
}

func addCommandAttention(sink attentionSink, command Command, now time.Time, thresholds OperationsThresholds) bool {
	var item AttentionItem
	switch command.State {
	case CommandPending:
		if !elapsedThreshold(now, command.CreatedAt, thresholds.CommandOverdueAfter) {
			return true
		}
		item = newCommandAttention(AttentionCommandPendingOverdue, AttentionWarning, command, command.CreatedAt)
	case CommandLeased:
		leaseUntil, _ := parseTimestamp(command.LeaseUntil)
		if now.Before(leaseUntil) {
			return true
		}
		item = newCommandAttention(AttentionCommandLeaseExpired, AttentionWarning, command, command.LeaseUntil)
	case CommandTerminal:
		status := commandTerminalStatus(command)
		switch status {
		case controlprotocol.ExecutorStatusFailed, controlprotocol.ExecutorStatusRejected:
			item = newCommandAttention(AttentionCommandFailed, AttentionCritical, command, command.Terminal.CompletedAt)
		case controlprotocol.ExecutorStatusOutcomeUnknown:
			item = newCommandAttention(AttentionCommandOutcomeUnknown, AttentionCritical, command, command.Terminal.CompletedAt)
		default:
			return true
		}
	default:
		return true
	}
	return sink.add(item)
}

func distinctEvidenceFindingReasons(finding *EvidenceFinding) []EvidenceFindingReason {
	if finding == nil {
		return nil
	}
	if finding.LastReason == finding.FirstReason {
		return []EvidenceFindingReason{finding.FirstReason}
	}
	return []EvidenceFindingReason{finding.FirstReason, finding.LastReason}
}

func newNodeAttention(reason AttentionReason, severity AttentionSeverity, tenantID, nodeID, since string) AttentionItem {
	item := AttentionItem{
		Reason: reason, Severity: severity, Resource: AttentionResourceNode,
		TenantID: tenantID, NodeID: nodeID, Since: since,
	}
	item.ID = stableAttentionID(item)
	return item
}

func newEvidenceAttention(reason AttentionReason, severity AttentionSeverity, tenantID, nodeID, since string) AttentionItem {
	item := AttentionItem{
		Reason: reason, Severity: severity, Resource: AttentionResourceEvidence,
		TenantID: tenantID, NodeID: nodeID, Since: since,
	}
	item.ID = stableAttentionID(item)
	return item
}

func newCommandAttention(reason AttentionReason, severity AttentionSeverity, command Command, since string) AttentionItem {
	item := AttentionItem{
		Reason: reason, Severity: severity, Resource: AttentionResourceCommand,
		TenantID: command.TenantID, NodeID: command.NodeID, CommandID: command.ID,
		Since: since, State: string(command.State), Status: commandTerminalStatus(command),
	}
	item.ID = stableAttentionID(item)
	return item
}

func stableAttentionID(item AttentionItem) string {
	digest := sha256.New()
	_, _ = digest.Write([]byte("steward-attention-v1\x00"))
	for _, value := range []string{
		string(item.Reason), string(item.Resource), item.TenantID, item.NodeID,
		item.CommandID, string(item.CapacityResource),
	} {
		_, _ = digest.Write([]byte(value))
		_, _ = digest.Write([]byte{0})
	}
	return "attention-" + hex.EncodeToString(digest.Sum(nil))
}

func attentionSortKey(item AttentionItem) string {
	resourceRank := "1"
	resourceID := item.NodeID
	switch item.Resource {
	case AttentionResourceCapacity:
		resourceRank, resourceID = "0", string(item.CapacityResource)
	case AttentionResourceCommand:
		resourceRank, resourceID = "2", item.NodeID+"\x00"+item.CommandID
	}
	return item.TenantID + "\x00" + resourceRank + "\x00" + resourceID + "\x00" +
		string(item.Reason) + "\x00" + string(item.Resource)
}

func validAttentionReason(reason AttentionReason) bool {
	switch reason {
	case AttentionNodeNeverSeen, AttentionNodeStale, AttentionEvidenceUnwitnessed,
		AttentionEvidenceStale, AttentionRollbackDetected, AttentionEquivocationDetected,
		AttentionCommandPendingOverdue, AttentionCommandLeaseExpired, AttentionCommandFailed,
		AttentionCommandOutcomeUnknown, AttentionCapacityWarning:
		return true
	default:
		return false
	}
}

func elapsedThreshold(now time.Time, since string, threshold time.Duration) bool {
	value, err := parseTimestamp(since)
	return err == nil && !now.Before(value.Add(threshold))
}

func normalizeInventoryLimit(limit int) (int, error) {
	if limit == 0 {
		return DefaultInventoryPageLimit, nil
	}
	if limit < 0 || limit > MaxInventoryPageLimit {
		return 0, invalid("inventory page limit is invalid")
	}
	return limit, nil
}

func encodeOperationsCursor(domain, key string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(domain + "\x00" + key))
}

func decodeOperationsCursor(domain, cursor string) (string, error) {
	if cursor == "" {
		return "", nil
	}
	if len(cursor) > base64.RawURLEncoding.EncodedLen(maxOperationsCursorBytes) ||
		strings.ContainsAny(cursor, "\r\n\x00") {
		return "", invalid("operations cursor is invalid")
	}
	raw, err := base64.RawURLEncoding.DecodeString(cursor)
	prefix := domain + "\x00"
	if err != nil || len(raw) > maxOperationsCursorBytes || !strings.HasPrefix(string(raw), prefix) ||
		len(raw) == len(prefix) {
		return "", invalid("operations cursor is invalid")
	}
	return string(raw[len(prefix):]), nil
}
