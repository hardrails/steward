package executoruplink

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/dsse"
)

const (
	deliveryStateReadMinVersion = 2
	deliveryStateReadMaxVersion = 3
	deliveryStateWriteVersion   = 3
	// deliveryStateVersion remains the local shorthand used by focused tests.
	deliveryStateVersion  = deliveryStateWriteVersion
	maxDeliveryStateBytes = 8 << 20
	maxDeliveryRecords    = 4096
	// Ambiguous outcomes intentionally remain until reconciliation, so one
	// verified tenant may retain only a bounded share of the node-wide ledger.
	maxDeliveryRecordsPerTenant = 32
	// Worst-case JSON growth for one tenant may consume at most one eighth of
	// the ledger. The exact whole-file reservation below independently protects
	// every accepted/executing delivery from terminal-persistence failure.
	maxDeliveryReservedBytesPerTenant = maxDeliveryStateBytes / 8
	// Compact in batches so a long-lived node does not rewrite a near-capacity
	// state file for every subsequent command.
	deliveryCompactionTarget       = maxDeliveryRecords * 3 / 4
	tenantDeliveryCompactionTarget = maxDeliveryRecordsPerTenant * 3 / 4
	deliveryCompactionTargetBytes  = maxDeliveryStateBytes * 3 / 4
)

const (
	deliveryPhaseAccepted  = "accepted"
	deliveryPhaseExecuting = "executing"
	deliveryPhaseTerminal  = "terminal"
)

type deliveryRecord struct {
	ProtocolVersion    int                                               `json:"protocol_version"`
	DeliveryID         string                                            `json:"delivery_id"`
	DeliveryGeneration uint64                                            `json:"delivery_generation"`
	SettledGeneration  uint64                                            `json:"settled_generation,omitempty"`
	TenantID           string                                            `json:"tenant_id,omitempty"`
	CommandID          string                                            `json:"command_id"`
	CommandDigest      string                                            `json:"command_digest"`
	ClaimGeneration    uint64                                            `json:"claim_generation,omitempty"`
	Phase              string                                            `json:"phase"`
	Terminal           *controlprotocol.ExecutorReportV3                 `json:"terminal,omitempty"`
	Admission          *controlprotocol.ExecutorAdmissionProjectionV1    `json:"admission,omitempty"`
	ActivationCanary   *controlprotocol.ExecutorActivationCanaryResultV1 `json:"activation_canary,omitempty"`
}

type deliveryStateFile struct {
	Version int              `json:"version"`
	NodeID  string           `json:"node_id"`
	Records []deliveryRecord `json:"records"`
}

// deliveryStateFileV2 pins the previous durable shape. Version 3 reads it
// strictly, converts every record to an explicit protocol-3 record in memory,
// and writes only version 3 on the next normal startup or state mutation.
type deliveryStateFileV2 struct {
	Version int                `json:"version"`
	NodeID  string             `json:"node_id"`
	Records []deliveryRecordV2 `json:"records"`
}

type deliveryRecordV2 struct {
	DeliveryID         string                            `json:"delivery_id"`
	DeliveryGeneration uint64                            `json:"delivery_generation"`
	SettledGeneration  uint64                            `json:"settled_generation,omitempty"`
	TenantID           string                            `json:"tenant_id,omitempty"`
	CommandID          string                            `json:"command_id"`
	CommandDigest      string                            `json:"command_digest"`
	Phase              string                            `json:"phase"`
	Terminal           *controlprotocol.ExecutorReportV3 `json:"terminal,omitempty"`
}

// DeliveryStore records the transport side of at-least-once command delivery.
// It is deliberately separate from the lifecycle fence: the tenant signature
// authorizes an operation, while this store proves whether a particular leased
// delivery may enter the local handler again.
type DeliveryStore struct {
	mu            sync.Mutex
	path          string
	nodeID        string
	formatVersion int
	records       map[string]deliveryRecord
}

// DeliveryStateFormatSummary reports the validated durable delivery-state
// format without changing recovery phases or requiring the enrolling node ID.
type DeliveryStateFormatSummary struct {
	Present       bool
	FormatVersion int
}

type deliveryDecision uint8

const (
	deliveryExecute deliveryDecision = iota + 1
	deliveryReport
	deliveryStale
)

func InitializeDeliveryStore(path, nodeID string) error {
	if path == "" || !boundedDeliveryText(nodeID, 128) {
		return errors.New("delivery state path and bounded node ID are required")
	}
	raw, err := encodeDeliveryState(nodeID, map[string]deliveryRecord{})
	if err != nil {
		return err
	}
	if err := writeExclusiveSynced(path, raw); err != nil {
		return fmt.Errorf("initialize executor delivery state %q: %w", path, err)
	}
	return nil
}

func LoadDeliveryStore(path, nodeID string) (*DeliveryStore, error) {
	if path == "" || !boundedDeliveryText(nodeID, 128) {
		return nil, errors.New("delivery state path and bounded node ID are required")
	}
	state, records, err := decodeDeliveryState(path)
	if err != nil {
		return nil, err
	}
	if state.NodeID != nodeID {
		return nil, fmt.Errorf("executor delivery state %q belongs to node %q, not %q", path, state.NodeID, nodeID)
	}
	return &DeliveryStore{
		path: path, nodeID: nodeID, formatVersion: state.Version, records: records,
	}, nil
}

// InspectDeliveryStateFormat validates the complete owner-only state file but
// never performs executing-record recovery. Upgrade checks use it before any
// release selector changes.
func InspectDeliveryStateFormat(path string) (DeliveryStateFormatSummary, error) {
	state, _, err := decodeDeliveryState(path)
	if err != nil {
		return DeliveryStateFormatSummary{}, err
	}
	return DeliveryStateFormatSummary{Present: true, FormatVersion: state.Version}, nil
}

func decodeDeliveryState(path string) (deliveryStateFile, map[string]deliveryRecord, error) {
	raw, err := readDeliveryState(path)
	if err != nil {
		return deliveryStateFile{}, nil, err
	}
	var envelope struct {
		Version int             `json:"version"`
		NodeID  string          `json:"node_id"`
		Records json.RawMessage `json:"records"`
	}
	if err := dsse.DecodeStrictInto(raw, maxDeliveryStateBytes, &envelope); err != nil {
		return deliveryStateFile{}, nil, fmt.Errorf("decode executor delivery state %q: %w", path, err)
	}
	if envelope.Version < deliveryStateReadMinVersion || envelope.Version > deliveryStateReadMaxVersion {
		return deliveryStateFile{}, nil, fmt.Errorf("executor delivery state %q has unsupported format version %d", path, envelope.Version)
	}
	var state deliveryStateFile
	switch envelope.Version {
	case 2:
		var legacy deliveryStateFileV2
		if err := dsse.DecodeStrictInto(raw, maxDeliveryStateBytes, &legacy); err != nil {
			return deliveryStateFile{}, nil, fmt.Errorf("decode executor delivery state %q: %w", path, err)
		}
		state = deliveryStateFile{
			Version: legacy.Version, NodeID: legacy.NodeID,
			Records: make([]deliveryRecord, 0, len(legacy.Records)),
		}
		for _, record := range legacy.Records {
			claimGeneration := uint64(0)
			if record.Terminal != nil {
				claimGeneration = record.Terminal.ClaimGeneration
			}
			state.Records = append(state.Records, deliveryRecord{
				ProtocolVersion: controlprotocol.ExecutorProtocolV3,
				DeliveryID:      record.DeliveryID, DeliveryGeneration: record.DeliveryGeneration,
				SettledGeneration: record.SettledGeneration, TenantID: record.TenantID,
				CommandID: record.CommandID, CommandDigest: record.CommandDigest,
				ClaimGeneration: claimGeneration, Phase: record.Phase,
				Terminal: cloneExecutorReport(record.Terminal),
			})
		}
	case deliveryStateWriteVersion:
		if err := dsse.DecodeStrictInto(raw, maxDeliveryStateBytes, &state); err != nil {
			return deliveryStateFile{}, nil, fmt.Errorf("decode executor delivery state %q: %w", path, err)
		}
	}
	if !boundedDeliveryText(state.NodeID, 128) {
		return deliveryStateFile{}, nil, fmt.Errorf("executor delivery state %q has an invalid node ID", path)
	}
	if state.Records == nil {
		return deliveryStateFile{}, nil, fmt.Errorf("executor delivery state %q is missing its records array", path)
	}
	if len(state.Records) > maxDeliveryRecords {
		return deliveryStateFile{}, nil, fmt.Errorf("executor delivery state %q has %d records, limit is %d", path, len(state.Records), maxDeliveryRecords)
	}
	records := make(map[string]deliveryRecord, len(state.Records))
	for _, record := range state.Records {
		if err := validateDeliveryRecord(record); err != nil {
			return deliveryStateFile{}, nil, fmt.Errorf("executor delivery state %q contains an invalid record: %w", path, err)
		}
		if _, exists := records[record.DeliveryID]; exists {
			return deliveryStateFile{}, nil, fmt.Errorf("executor delivery state %q contains duplicate delivery ID %q", path, record.DeliveryID)
		}
		records[record.DeliveryID] = cloneDeliveryRecord(record)
	}
	if err := ensureDeliveryTerminalCapacity(state.NodeID, records); err != nil {
		return deliveryStateFile{}, nil, fmt.Errorf("executor delivery state %q has no safe terminal reserve: %w", path, err)
	}
	return state, records, nil
}

// MigrateFormat atomically rewrites the current readable format to the only
// format this release writes. Validation-only startup deliberately skips it.
func (s *DeliveryStore) MigrateFormat() error {
	if s == nil {
		return errors.New("executor delivery state is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.formatVersion == deliveryStateWriteVersion {
		return nil
	}
	return s.persistLocked(cloneDeliveryRecords(s.records))
}

// PrepareProtocol prevents an explicit protocol selection from silently
// sending retained reports through another wire version. Acknowledged done or
// rejected records are already safe compaction candidates and may be removed
// during normal startup; all other cross-version state blocks startup.
func (s *DeliveryStore) PrepareProtocol(protocolVersion int, validateOnly bool) error {
	if s == nil || protocolVersion != controlprotocol.ExecutorProtocolV3 &&
		protocolVersion != controlprotocol.ExecutorProtocolV4 {
		return errors.New("executor delivery protocol selection is invalid")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	next := cloneDeliveryRecords(s.records)
	changed := false
	for id, record := range next {
		if record.ProtocolVersion == protocolVersion {
			continue
		}
		if record.Phase == deliveryPhaseTerminal && record.Terminal != nil &&
			record.SettledGeneration == record.DeliveryGeneration &&
			(record.Terminal.Status == controlprotocol.ExecutorStatusDone ||
				record.Terminal.Status == controlprotocol.ExecutorStatusRejected) {
			delete(next, id)
			changed = true
			continue
		}
		return fmt.Errorf(
			"executor delivery state retains protocol %d record %q; drain or reconcile it before selecting protocol %d",
			record.ProtocolVersion,
			record.DeliveryID,
			protocolVersion,
		)
	}
	if !changed || validateOnly {
		return nil
	}
	return s.persistLocked(next)
}

func (s *DeliveryStore) NodeID() string {
	return s.nodeID
}

// UnacknowledgedReports returns a deterministic, bounded batch of terminal
// reports whose control-plane acknowledgement has not been persisted locally.
// Callers must drain these reports before accepting more work: the controller
// may have stored a report even when its HTTP response was lost, in which case
// that terminal command will never be leased again to trigger a retry.
func (s *DeliveryStore) UnacknowledgedReports(limit int) ([]controlprotocol.ExecutorReportV3, bool, error) {
	if s == nil || limit <= 0 || limit > controlprotocol.MaxExecutorDeliveries {
		return nil, false, errors.New("unacknowledged delivery report limit is invalid")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	ids := make([]string, 0)
	for id, record := range s.records {
		if record.ProtocolVersion == controlprotocol.ExecutorProtocolV3 &&
			record.Phase == deliveryPhaseTerminal && record.Terminal != nil &&
			record.SettledGeneration != record.DeliveryGeneration {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	more := len(ids) > limit
	if more {
		ids = ids[:limit]
	}
	reports := make([]controlprotocol.ExecutorReportV3, 0, len(ids))
	for _, id := range ids {
		reports = append(reports, *cloneExecutorReport(s.records[id].Terminal))
	}
	return reports, more, nil
}

// UnacknowledgedReportsV4 returns only retained protocol-4 records. Protocol
// selection is prepared before polling, so finding another version here would
// indicate an internal state transition error rather than a downgrade signal.
func (s *DeliveryStore) UnacknowledgedReportsV4(limit int) ([]controlprotocol.ExecutorReportV4, bool, error) {
	if s == nil || limit <= 0 || limit > controlprotocol.MaxExecutorDeliveries {
		return nil, false, errors.New("unacknowledged delivery report limit is invalid")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	ids := make([]string, 0)
	for id, record := range s.records {
		if record.ProtocolVersion == controlprotocol.ExecutorProtocolV4 &&
			record.Phase == deliveryPhaseTerminal && record.Terminal != nil &&
			record.SettledGeneration != record.DeliveryGeneration {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	more := len(ids) > limit
	if more {
		ids = ids[:limit]
	}
	reports := make([]controlprotocol.ExecutorReportV4, 0, len(ids))
	for _, id := range ids {
		report, err := executorReportV4FromRecord(s.records[id])
		if err != nil {
			return nil, false, err
		}
		reports = append(reports, report)
	}
	return reports, more, nil
}

// RecoverExecuting turns every pre-crash executing record into an explicit
// ambiguous terminal result. Accepted records are safe to resume because the
// executing transition is fsynced immediately before the local handler call.
func (s *DeliveryStore) RecoverExecuting() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := cloneDeliveryRecords(s.records)
	changed := false
	for id, record := range next {
		if record.Phase != deliveryPhaseExecuting {
			continue
		}
		report := outcomeUnknownReport(record)
		record.Phase = deliveryPhaseTerminal
		record.Terminal = &report
		next[id] = record
		changed = true
	}
	if !changed {
		return nil
	}
	return s.persistLocked(next)
}

func (s *DeliveryStore) Accept(delivery controlprotocol.ExecutorDeliveryV3, tenantID string) (deliveryDecision, *controlprotocol.ExecutorReportV3, error) {
	if err := delivery.Validate(); err != nil {
		return 0, nil, err
	}
	decision, terminal, err := s.acceptDelivery(delivery, tenantID, controlprotocol.ExecutorProtocolV3, 0)
	if terminal == nil {
		return decision, nil, err
	}
	return decision, cloneExecutorReport(terminal.Terminal), err
}

func (s *DeliveryStore) AcceptV4(
	delivery controlprotocol.ExecutorDeliveryV4,
	tenantID string,
	claimGeneration uint64,
) (deliveryDecision, *controlprotocol.ExecutorReportV4, error) {
	if err := delivery.Validate(); err != nil {
		return 0, nil, err
	}
	if claimGeneration == 0 {
		return 0, nil, errors.New("verified protocol-4 delivery claim generation is required")
	}
	decision, terminal, err := s.acceptDelivery(
		executorDeliveryV3(delivery),
		tenantID,
		controlprotocol.ExecutorProtocolV4,
		claimGeneration,
	)
	if terminal == nil {
		return decision, nil, err
	}
	report, reportErr := executorReportV4FromRecord(*terminal)
	if reportErr != nil {
		return decision, nil, errors.Join(err, reportErr)
	}
	return decision, &report, err
}

func (s *DeliveryStore) acceptDelivery(
	delivery controlprotocol.ExecutorDeliveryV3,
	tenantID string,
	protocolVersion int,
	claimGeneration uint64,
) (deliveryDecision, *deliveryRecord, error) {
	if !boundedDeliveryText(tenantID, 128) {
		return 0, nil, errors.New("verified delivery tenant ID is invalid")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	next := cloneDeliveryRecords(s.records)
	record, exists := next[delivery.DeliveryID]
	if exists {
		if record.ProtocolVersion != protocolVersion {
			return 0, nil, errors.New("delivery ID was reused across executor protocol versions")
		}
		if record.CommandID != delivery.CommandID || record.CommandDigest != delivery.CommandDigest {
			return 0, nil, errors.New("delivery ID was reused for another command")
		}
		if record.TenantID != "" && record.TenantID != tenantID {
			return 0, nil, errors.New("delivery ID was reused across verified tenants")
		}
		if delivery.DeliveryGeneration < record.DeliveryGeneration {
			return deliveryStale, nil, nil
		}
		if record.ClaimGeneration != 0 && claimGeneration != 0 &&
			record.ClaimGeneration != claimGeneration {
			return 0, nil, errors.New("delivery ID was reused across signed claim generations")
		}
		changed := false
		if record.TenantID == "" {
			record.TenantID = tenantID
			changed = true
		}
		if record.Phase != deliveryPhaseTerminal &&
			record.ClaimGeneration == 0 && claimGeneration != 0 {
			record.ClaimGeneration = claimGeneration
			changed = true
		}
		if delivery.DeliveryGeneration > record.DeliveryGeneration {
			record.DeliveryGeneration = delivery.DeliveryGeneration
			record.SettledGeneration = 0
			if record.Terminal != nil {
				report := *record.Terminal
				report.DeliveryGeneration = delivery.DeliveryGeneration
				record.Terminal = &report
			}
			changed = true
		}
		if changed {
			next[delivery.DeliveryID] = record
			if err := s.persistLocked(next); err != nil {
				return 0, nil, err
			}
		}
		switch record.Phase {
		case deliveryPhaseAccepted:
			return deliveryExecute, nil, nil
		case deliveryPhaseExecuting:
			report := outcomeUnknownReport(record)
			record.Phase, record.Terminal = deliveryPhaseTerminal, &report
			next = cloneDeliveryRecords(s.records)
			next[delivery.DeliveryID] = record
			if err := s.persistLocked(next); err != nil {
				return 0, nil, err
			}
			retained := cloneDeliveryRecord(record)
			return deliveryReport, &retained, nil
		case deliveryPhaseTerminal:
			retained := cloneDeliveryRecord(record)
			return deliveryReport, &retained, nil
		default:
			return 0, nil, errors.New("delivery record has invalid phase")
		}
	}
	compactAcknowledgedDeliveries(next, tenantID)
	if deliveryRecordsForTenant(next, tenantID) >= maxDeliveryRecordsPerTenant {
		return 0, nil, fmt.Errorf("executor delivery state tenant %q reached its %d-record safety limit", tenantID, maxDeliveryRecordsPerTenant)
	}
	if len(next) >= maxDeliveryRecords {
		return 0, nil, fmt.Errorf("executor delivery state reached its %d-record limit", maxDeliveryRecords)
	}
	record = deliveryRecord{
		ProtocolVersion: protocolVersion,
		DeliveryID:      delivery.DeliveryID, DeliveryGeneration: delivery.DeliveryGeneration,
		TenantID: tenantID, CommandID: delivery.CommandID, CommandDigest: delivery.CommandDigest,
		ClaimGeneration: claimGeneration, Phase: deliveryPhaseAccepted,
	}
	next[delivery.DeliveryID] = record
	compactTenantReservedBytes(next, tenantID)
	if reservedDeliveryBytesForTenant(next, tenantID) > maxDeliveryReservedBytesPerTenant {
		return 0, nil, fmt.Errorf("executor delivery state tenant %q reached its %d-byte terminal reserve", tenantID, maxDeliveryReservedBytesPerTenant)
	}
	compactGlobalReservedBytes(next, s.nodeID)
	if err := s.persistLocked(next); err != nil {
		return 0, nil, err
	}
	return deliveryExecute, nil, nil
}

// Reject durably retires a structurally routed delivery without entering the
// local Executor handler. An already-terminal outcome always wins over a later
// verification failure so policy rotation or expiry cannot erase evidence.
func (s *DeliveryStore) Reject(delivery controlprotocol.ExecutorDeliveryV3, rejected controlprotocol.ExecutorReportV3) (*controlprotocol.ExecutorReportV3, error) {
	if err := delivery.Validate(); err != nil {
		return nil, err
	}
	if err := rejected.Validate(); err != nil || rejected.Status != controlprotocol.ExecutorStatusRejected {
		return nil, errors.New("invalid rejected delivery report")
	}
	terminal, err := s.rejectDelivery(
		delivery,
		controlprotocol.ExecutorProtocolV3,
		rejected,
		nil,
		nil,
	)
	if terminal == nil {
		return nil, err
	}
	return cloneExecutorReport(terminal.Terminal), err
}

func (s *DeliveryStore) RejectV4(
	delivery controlprotocol.ExecutorDeliveryV4,
	rejected controlprotocol.ExecutorReportV4,
) (*controlprotocol.ExecutorReportV4, error) {
	if err := delivery.Validate(); err != nil {
		return nil, err
	}
	if err := rejected.Validate(); err != nil || rejected.Status != controlprotocol.ExecutorStatusRejected ||
		rejected.Result.Admission != nil || rejected.Result.ActivationCanary != nil {
		return nil, errors.New("invalid rejected delivery report")
	}
	common, admission, activationCanary := executorReportV4Record(rejected)
	terminal, err := s.rejectDelivery(
		executorDeliveryV3(delivery),
		controlprotocol.ExecutorProtocolV4,
		common,
		admission,
		activationCanary,
	)
	if terminal == nil {
		return nil, err
	}
	report, reportErr := executorReportV4FromRecord(*terminal)
	if reportErr != nil {
		return nil, errors.Join(err, reportErr)
	}
	return &report, err
}

func (s *DeliveryStore) rejectDelivery(
	delivery controlprotocol.ExecutorDeliveryV3,
	protocolVersion int,
	rejected controlprotocol.ExecutorReportV3,
	admissionProjection *controlprotocol.ExecutorAdmissionProjectionV1,
	activationCanary *controlprotocol.ExecutorActivationCanaryResultV1,
) (*deliveryRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := cloneDeliveryRecords(s.records)
	record, exists := next[delivery.DeliveryID]
	if exists {
		if record.ProtocolVersion != protocolVersion {
			return nil, errors.New("delivery ID was reused across executor protocol versions")
		}
		if record.CommandID != delivery.CommandID || record.CommandDigest != delivery.CommandDigest {
			return nil, errors.New("delivery ID was reused for another command")
		}
		if delivery.DeliveryGeneration < record.DeliveryGeneration {
			return nil, nil
		}
		if delivery.DeliveryGeneration > record.DeliveryGeneration {
			record.DeliveryGeneration = delivery.DeliveryGeneration
			record.SettledGeneration = 0
		}
		if record.Phase == deliveryPhaseTerminal && record.Terminal != nil {
			report := *record.Terminal
			report.DeliveryGeneration = record.DeliveryGeneration
			record.Terminal = &report
			next[delivery.DeliveryID] = record
			if err := s.persistLocked(next); err != nil {
				return nil, err
			}
			retained := cloneDeliveryRecord(record)
			return &retained, nil
		}
		if record.Phase == deliveryPhaseExecuting {
			rejected = outcomeUnknownReport(record)
			admissionProjection = nil
			activationCanary = nil
		}
	} else {
		compactAcknowledgedDeliveries(next, "")
		if len(next) >= maxDeliveryRecords {
			return nil, fmt.Errorf("executor delivery state reached its %d-record limit", maxDeliveryRecords)
		}
	}
	rejected.DeliveryGeneration = delivery.DeliveryGeneration
	record = deliveryRecord{
		ProtocolVersion: protocolVersion,
		DeliveryID:      delivery.DeliveryID, DeliveryGeneration: delivery.DeliveryGeneration,
		TenantID: record.TenantID, CommandID: delivery.CommandID, CommandDigest: delivery.CommandDigest,
		ClaimGeneration: rejected.ClaimGeneration,
		Phase:           deliveryPhaseTerminal, Terminal: &rejected,
		Admission:        cloneAdmissionProjection(admissionProjection),
		ActivationCanary: cloneActivationCanaryResult(activationCanary),
	}
	next[delivery.DeliveryID] = record
	compactGlobalReservedBytes(next, s.nodeID)
	if err := s.persistLocked(next); err != nil {
		return nil, err
	}
	retained := cloneDeliveryRecord(record)
	return &retained, nil
}

func (s *DeliveryStore) MarkExecuting(deliveryID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[deliveryID]
	if !ok || record.Phase != deliveryPhaseAccepted {
		return errors.New("delivery is not durably accepted")
	}
	next := cloneDeliveryRecords(s.records)
	record.Phase = deliveryPhaseExecuting
	next[deliveryID] = record
	return s.persistLocked(next)
}

func (s *DeliveryStore) MarkTerminal(report controlprotocol.ExecutorReportV3) error {
	if err := report.Validate(); err != nil {
		return err
	}
	return s.markTerminal(
		report.DeliveryID,
		report.DeliveryGeneration,
		report.CommandID,
		report.CommandDigest,
		controlprotocol.ExecutorProtocolV3,
		report,
		nil,
		nil,
	)
}

func (s *DeliveryStore) MarkTerminalV4(report controlprotocol.ExecutorReportV4) error {
	if err := report.Validate(); err != nil {
		return err
	}
	common, admission, activationCanary := executorReportV4Record(report)
	return s.markTerminal(
		report.DeliveryID,
		report.DeliveryGeneration,
		report.CommandID,
		report.CommandDigest,
		controlprotocol.ExecutorProtocolV4,
		common,
		admission,
		activationCanary,
	)
}

func (s *DeliveryStore) markTerminal(
	deliveryID string,
	deliveryGeneration uint64,
	commandID, commandDigest string,
	protocolVersion int,
	report controlprotocol.ExecutorReportV3,
	admissionProjection *controlprotocol.ExecutorAdmissionProjectionV1,
	activationCanary *controlprotocol.ExecutorActivationCanaryResultV1,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[deliveryID]
	if !ok || record.ProtocolVersion != protocolVersion ||
		record.Phase != deliveryPhaseExecuting || record.DeliveryGeneration != deliveryGeneration ||
		record.CommandID != commandID || record.CommandDigest != commandDigest ||
		record.ClaimGeneration != 0 && record.ClaimGeneration != report.ClaimGeneration {
		return errors.New("terminal report does not match an executing delivery")
	}
	next := cloneDeliveryRecords(s.records)
	record.Phase = deliveryPhaseTerminal
	record.Terminal = cloneExecutorReport(&report)
	record.Admission = cloneAdmissionProjection(admissionProjection)
	record.ActivationCanary = cloneActivationCanaryResult(activationCanary)
	if record.ClaimGeneration == 0 {
		record.ClaimGeneration = report.ClaimGeneration
	}
	next[deliveryID] = record
	return s.persistLocked(next)
}

func (s *DeliveryStore) Settle(deliveryID string, generation uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[deliveryID]
	if !ok || record.Phase != deliveryPhaseTerminal || generation != record.DeliveryGeneration {
		return errors.New("acknowledgement does not match a terminal delivery")
	}
	if record.SettledGeneration == generation {
		return nil
	}
	next := cloneDeliveryRecords(s.records)
	record.SettledGeneration = generation
	next[deliveryID] = record
	return s.persistLocked(next)
}

func (s *DeliveryStore) persistLocked(next map[string]deliveryRecord) error {
	next = canonicalDeliveryRecords(next)
	if err := ensureDeliveryTerminalCapacity(s.nodeID, next); err != nil {
		return err
	}
	raw, err := encodeDeliveryState(s.nodeID, next)
	if err != nil {
		return err
	}
	if err := replaceDeliveryState(s.path, raw); err != nil {
		return err
	}
	s.formatVersion = deliveryStateWriteVersion
	s.records = next
	return nil
}

func canonicalDeliveryRecords(records map[string]deliveryRecord) map[string]deliveryRecord {
	canonical := cloneDeliveryRecords(records)
	for id, record := range canonical {
		if record.ProtocolVersion == 0 {
			record.ProtocolVersion = controlprotocol.ExecutorProtocolV3
			canonical[id] = record
		}
	}
	return canonical
}

// compactAcknowledgedDeliveries makes room only by removing acknowledged done
// and rejected generations. Done means the independent signed-command fence is
// durable; rejected means the handler was never entered. Failed records from
// older builds and outcome_unknown records remain fail-closed because either
// may describe an effect whose fence did not advance. Accepted, executing, and
// unacknowledged terminal records are never candidates.
func compactAcknowledgedDeliveries(records map[string]deliveryRecord, tenantID string) {
	if tenantID != "" {
		count := deliveryRecordsForTenant(records, tenantID)
		if count >= maxDeliveryRecordsPerTenant {
			removeAcknowledgedDeliveries(records, tenantID, count-tenantDeliveryCompactionTarget)
		}
	}
	if len(records) >= maxDeliveryRecords {
		removeAcknowledgedDeliveries(records, "", len(records)-deliveryCompactionTarget)
	}
}

func removeAcknowledgedDeliveries(records map[string]deliveryRecord, tenantID string, remove int) {
	if remove <= 0 {
		return
	}
	candidates := make([]string, 0, remove)
	for id, record := range records {
		if tenantID != "" && record.TenantID != tenantID {
			continue
		}
		if record.Phase != deliveryPhaseTerminal || record.Terminal == nil ||
			record.SettledGeneration != record.DeliveryGeneration {
			continue
		}
		if record.Terminal.Status == controlprotocol.ExecutorStatusDone ||
			record.Terminal.Status == controlprotocol.ExecutorStatusRejected {
			candidates = append(candidates, id)
		}
	}
	sort.Strings(candidates)
	if remove > len(candidates) {
		remove = len(candidates)
	}
	for _, id := range candidates[:remove] {
		delete(records, id)
	}
}

func deliveryRecordsForTenant(records map[string]deliveryRecord, tenantID string) int {
	count := 0
	for _, record := range records {
		if record.TenantID == tenantID {
			count++
		}
	}
	return count
}

func compactTenantReservedBytes(records map[string]deliveryRecord, tenantID string) {
	if reservedDeliveryBytesForTenant(records, tenantID) <= maxDeliveryReservedBytesPerTenant {
		return
	}
	candidates := make([]string, 0)
	for id, record := range records {
		if record.TenantID == tenantID && record.Phase == deliveryPhaseTerminal && record.Terminal != nil &&
			record.SettledGeneration == record.DeliveryGeneration &&
			(record.Terminal.Status == controlprotocol.ExecutorStatusDone ||
				record.Terminal.Status == controlprotocol.ExecutorStatusRejected) {
			candidates = append(candidates, id)
		}
	}
	sort.Strings(candidates)
	for _, id := range candidates {
		delete(records, id)
		if reservedDeliveryBytesForTenant(records, tenantID) <= maxDeliveryReservedBytesPerTenant {
			return
		}
	}
}

func compactGlobalReservedBytes(records map[string]deliveryRecord, nodeID string) {
	size, err := reservedDeliveryStateSize(nodeID, records)
	if err != nil || size <= maxDeliveryStateBytes {
		return
	}
	candidates := make([]string, 0)
	for id, record := range records {
		if record.Phase == deliveryPhaseTerminal && record.Terminal != nil &&
			record.SettledGeneration == record.DeliveryGeneration &&
			(record.Terminal.Status == controlprotocol.ExecutorStatusDone ||
				record.Terminal.Status == controlprotocol.ExecutorStatusRejected) {
			candidates = append(candidates, id)
		}
	}
	sort.Strings(candidates)
	removeBytes := size - deliveryCompactionTargetBytes
	for _, id := range candidates {
		raw, err := json.Marshal(reservedDeliveryRecord(records[id]))
		if err != nil {
			return
		}
		delete(records, id)
		removeBytes -= len(raw) + 1
		if removeBytes <= 0 {
			return
		}
	}
}

func reservedDeliveryBytesForTenant(records map[string]deliveryRecord, tenantID string) int {
	total := 0
	for _, record := range records {
		if record.TenantID != tenantID {
			continue
		}
		extra := deliveryTerminalReserveExtra(record)
		raw, err := json.Marshal(reservedDeliveryRecord(record))
		if err != nil {
			return math.MaxInt
		}
		total += len(raw) + 1 + extra // include the enclosing array comma
	}
	return total
}

func reservedDeliveryStateSize(nodeID string, records map[string]deliveryRecord) (int, error) {
	reserved := make(map[string]deliveryRecord, len(records))
	extra := 0
	for id, record := range records {
		reserved[id] = reservedDeliveryRecord(record)
		extra += deliveryTerminalReserveExtra(record)
	}
	raw, err := marshalDeliveryState(nodeID, reserved)
	if err != nil {
		return 0, err
	}
	return len(raw) + extra, nil
}

// ensureDeliveryTerminalCapacity proves that every accepted or executing
// delivery can grow into the largest valid terminal report and later persist
// its acknowledgement. The proof is made before the handler is invoked and is
// preserved by every state mutation.
func ensureDeliveryTerminalCapacity(nodeID string, records map[string]deliveryRecord) error {
	reserved := make(map[string]deliveryRecord, len(records))
	tenantBytes := make(map[string]int)
	extra := 0
	for id, record := range records {
		terminalExtra := deliveryTerminalReserveExtra(record)
		candidate := reservedDeliveryRecord(record)
		reserved[id] = candidate
		extra += terminalExtra
		if candidate.TenantID == "" {
			continue
		}
		raw, err := json.Marshal(candidate)
		if err != nil {
			return fmt.Errorf("encode reserved terminal delivery: %w", err)
		}
		tenantBytes[candidate.TenantID] += len(raw) + 1 + terminalExtra
	}
	for tenantID, size := range tenantBytes {
		if size > maxDeliveryReservedBytesPerTenant {
			return fmt.Errorf("tenant %q needs %d reserved terminal bytes, limit is %d", tenantID, size, maxDeliveryReservedBytesPerTenant)
		}
	}
	raw, err := marshalDeliveryState(nodeID, reserved)
	if err != nil {
		return fmt.Errorf("reserve worst-case terminal delivery state: %w", err)
	}
	if len(raw)+extra > maxDeliveryStateBytes {
		return fmt.Errorf("reserve worst-case terminal delivery state: executor delivery state would exceed %d bytes", maxDeliveryStateBytes)
	}
	return nil
}

func reservedDeliveryRecord(record deliveryRecord) deliveryRecord {
	if record.Phase == deliveryPhaseAccepted || record.Phase == deliveryPhaseExecuting {
		report := reservedExecutorReport(record)
		record.Phase = deliveryPhaseTerminal
		record.Terminal = &report
		record.Admission = nil
		record.ActivationCanary = nil
	}
	if record.Phase == deliveryPhaseTerminal && record.SettledGeneration != record.DeliveryGeneration {
		record.SettledGeneration = record.DeliveryGeneration
	}
	return record
}

func reservedExecutorReport(record deliveryRecord) controlprotocol.ExecutorReportV3 {
	if record.ProtocolVersion == controlprotocol.ExecutorProtocolV4 {
		return outcomeUnknownReport(record)
	}
	return controlprotocol.ExecutorReportV3{
		ProtocolVersion: controlprotocol.ExecutorProtocolV3,
		DeliveryID:      record.DeliveryID, DeliveryGeneration: record.DeliveryGeneration,
		CommandID: record.CommandID, CommandDigest: record.CommandDigest,
		Status:         controlprotocol.ExecutorStatusOutcomeUnknown,
		ReportedStatus: strings.Repeat("<", 64), ClaimGeneration: math.MaxUint64,
		ErrorCode: strings.Repeat("\x00", 128),
		Result: controlprotocol.ExecutorReportResultV3{
			RuntimeRef: strings.Repeat("\x00", 1024), Error: strings.Repeat("\x00", 4096),
			Replayed: true, Absent: true,
		},
	}
}

// deliveryTerminalReserveExtra adds the complete protocol-4 wire-report cap
// on top of a small valid terminal placeholder. This deliberately
// over-reserves the placeholder's common fields, but proves capacity without
// repeatedly searching the JSON-size boundary for every retained record.
func deliveryTerminalReserveExtra(record deliveryRecord) int {
	if record.ProtocolVersion == controlprotocol.ExecutorProtocolV4 &&
		(record.Phase == deliveryPhaseAccepted || record.Phase == deliveryPhaseExecuting) {
		return controlprotocol.MaxExecutorReportBytes
	}
	return 0
}

func executorDeliveryV3(delivery controlprotocol.ExecutorDeliveryV4) controlprotocol.ExecutorDeliveryV3 {
	return controlprotocol.ExecutorDeliveryV3{
		DeliveryID: delivery.DeliveryID, DeliveryGeneration: delivery.DeliveryGeneration,
		CommandID: delivery.CommandID, CommandDigest: delivery.CommandDigest,
		CommandDSSEBase64: delivery.CommandDSSEBase64,
	}
}

func executorReportV4Record(
	report controlprotocol.ExecutorReportV4,
) (
	controlprotocol.ExecutorReportV3,
	*controlprotocol.ExecutorAdmissionProjectionV1,
	*controlprotocol.ExecutorActivationCanaryResultV1,
) {
	common := controlprotocol.ExecutorReportV3{
		ProtocolVersion: controlprotocol.ExecutorProtocolV3,
		DeliveryID:      report.DeliveryID, DeliveryGeneration: report.DeliveryGeneration,
		CommandID: report.CommandID, CommandDigest: report.CommandDigest,
		Status: report.Status, ReportedStatus: report.ReportedStatus,
		ClaimGeneration: report.ClaimGeneration, ErrorCode: report.ErrorCode,
		Result: controlprotocol.ExecutorReportResultV3{
			RuntimeRef: report.Result.RuntimeRef, Error: report.Result.Error,
			Replayed: report.Result.Replayed, Absent: report.Result.Absent,
		},
	}
	return common,
		cloneAdmissionProjection(report.Result.Admission),
		cloneActivationCanaryResult(report.Result.ActivationCanary)
}

func executorReportV4FromRecord(record deliveryRecord) (controlprotocol.ExecutorReportV4, error) {
	if record.ProtocolVersion != controlprotocol.ExecutorProtocolV4 || record.Terminal == nil {
		return controlprotocol.ExecutorReportV4{}, errors.New("delivery record does not contain a protocol-4 terminal report")
	}
	common := record.Terminal
	if common.ProtocolVersion != controlprotocol.ExecutorProtocolV3 {
		return controlprotocol.ExecutorReportV4{}, errors.New("protocol-4 terminal storage marker is invalid")
	}
	if record.ClaimGeneration != common.ClaimGeneration {
		return controlprotocol.ExecutorReportV4{}, errors.New("protocol-4 terminal report changed its signed claim generation")
	}
	report := controlprotocol.ExecutorReportV4{
		ProtocolVersion: controlprotocol.ExecutorProtocolV4,
		DeliveryID:      common.DeliveryID, DeliveryGeneration: common.DeliveryGeneration,
		CommandID: common.CommandID, CommandDigest: common.CommandDigest,
		Status: common.Status, ReportedStatus: common.ReportedStatus,
		ClaimGeneration: common.ClaimGeneration, ErrorCode: common.ErrorCode,
		Result: controlprotocol.ExecutorReportResultV4{
			RuntimeRef: common.Result.RuntimeRef, Error: common.Result.Error,
			Replayed: common.Result.Replayed, Absent: common.Result.Absent,
			Admission:        cloneAdmissionProjection(record.Admission),
			ActivationCanary: cloneActivationCanaryResult(record.ActivationCanary),
		},
	}
	if err := report.Validate(); err != nil {
		return controlprotocol.ExecutorReportV4{}, fmt.Errorf("validate retained executor report v4: %w", err)
	}
	return report, nil
}

func encodeDeliveryState(nodeID string, records map[string]deliveryRecord) ([]byte, error) {
	raw, err := marshalDeliveryState(nodeID, records)
	if err != nil {
		return nil, err
	}
	if len(raw) > maxDeliveryStateBytes {
		return nil, fmt.Errorf("executor delivery state would exceed %d bytes", maxDeliveryStateBytes)
	}
	return raw, nil
}

func marshalDeliveryState(nodeID string, records map[string]deliveryRecord) ([]byte, error) {
	if !boundedDeliveryText(nodeID, 128) || len(records) > maxDeliveryRecords {
		return nil, errors.New("invalid executor delivery state identity or capacity")
	}
	ordered := make([]deliveryRecord, 0, len(records))
	for _, record := range records {
		if record.ProtocolVersion == 0 {
			// Direct in-package fixtures created before the format bump remain
			// protocol 3; persisted version-3 records always write this field.
			record.ProtocolVersion = controlprotocol.ExecutorProtocolV3
		}
		if err := validateDeliveryRecord(record); err != nil {
			return nil, err
		}
		ordered = append(ordered, cloneDeliveryRecord(record))
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].DeliveryID < ordered[j].DeliveryID })
	var encoded bytes.Buffer
	if err := json.NewEncoder(&encoded).Encode(deliveryStateFile{
		Version: deliveryStateWriteVersion, NodeID: nodeID, Records: ordered,
	}); err != nil {
		return nil, err
	}
	return encoded.Bytes(), nil
}

func validateDeliveryRecord(record deliveryRecord) error {
	if record.ProtocolVersion != controlprotocol.ExecutorProtocolV3 &&
		record.ProtocolVersion != controlprotocol.ExecutorProtocolV4 ||
		!boundedDeliveryText(record.DeliveryID, 256) || record.DeliveryGeneration == 0 ||
		!boundedDeliveryText(record.CommandID, 256) || !controlprotocol.ValidSHA256Digest(record.CommandDigest) ||
		record.SettledGeneration > record.DeliveryGeneration ||
		(record.TenantID != "" && !boundedDeliveryText(record.TenantID, 128)) {
		return errors.New("invalid delivery identity or generation")
	}
	switch record.Phase {
	case deliveryPhaseAccepted, deliveryPhaseExecuting:
		if record.Terminal != nil || record.Admission != nil || record.ActivationCanary != nil ||
			record.SettledGeneration != 0 {
			return errors.New("non-terminal delivery contains terminal state")
		}
		if record.ProtocolVersion == controlprotocol.ExecutorProtocolV4 && record.ClaimGeneration == 0 {
			return errors.New("protocol-4 non-terminal delivery is missing its verified claim generation")
		}
	case deliveryPhaseTerminal:
		if record.Terminal == nil || record.Terminal.DeliveryID != record.DeliveryID ||
			record.Terminal.DeliveryGeneration != record.DeliveryGeneration ||
			record.Terminal.CommandID != record.CommandID || record.Terminal.CommandDigest != record.CommandDigest {
			return errors.New("terminal delivery report does not match its record")
		}
		switch record.ProtocolVersion {
		case controlprotocol.ExecutorProtocolV3:
			if record.Admission != nil || record.ActivationCanary != nil {
				return errors.New("protocol-3 terminal delivery contains a protocol-4 projection")
			}
			if err := record.Terminal.Validate(); err != nil {
				return err
			}
		case controlprotocol.ExecutorProtocolV4:
			if _, err := executorReportV4FromRecord(record); err != nil {
				return err
			}
		}
		if record.TenantID == "" && record.Terminal.Status != controlprotocol.ExecutorStatusRejected {
			return errors.New("only a pre-verification rejected delivery may omit tenant identity")
		}
	default:
		return errors.New("invalid delivery phase")
	}
	if record.TenantID == "" && record.Phase != deliveryPhaseTerminal {
		return errors.New("non-terminal delivery is missing verified tenant identity")
	}
	return nil
}

func outcomeUnknownReport(record deliveryRecord) controlprotocol.ExecutorReportV3 {
	return controlprotocol.ExecutorReportV3{
		ProtocolVersion: controlprotocol.ExecutorProtocolV3,
		DeliveryID:      record.DeliveryID, DeliveryGeneration: record.DeliveryGeneration,
		CommandID: record.CommandID, CommandDigest: record.CommandDigest,
		Status: controlprotocol.ExecutorStatusOutcomeUnknown, ReportedStatus: "failed",
		ClaimGeneration: record.ClaimGeneration,
		ErrorCode:       "outcome_unknown",
		Result: controlprotocol.ExecutorReportResultV3{
			Error: "execution may have changed the node; reconcile before issuing another command",
		},
	}
}

func cloneDeliveryRecords(source map[string]deliveryRecord) map[string]deliveryRecord {
	clone := make(map[string]deliveryRecord, len(source))
	for id, record := range source {
		clone[id] = cloneDeliveryRecord(record)
	}
	return clone
}

func cloneDeliveryRecord(record deliveryRecord) deliveryRecord {
	record.Terminal = cloneExecutorReport(record.Terminal)
	record.Admission = cloneAdmissionProjection(record.Admission)
	record.ActivationCanary = cloneActivationCanaryResult(record.ActivationCanary)
	return record
}

func cloneExecutorReport(report *controlprotocol.ExecutorReportV3) *controlprotocol.ExecutorReportV3 {
	if report == nil {
		return nil
	}
	clone := *report
	return &clone
}

func cloneAdmissionProjection(
	projection *controlprotocol.ExecutorAdmissionProjectionV1,
) *controlprotocol.ExecutorAdmissionProjectionV1 {
	if projection == nil {
		return nil
	}
	clone := *projection
	clone.TaskAuthorities = append(
		[]controlprotocol.ExecutorTaskAuthorityV1(nil),
		projection.TaskAuthorities...,
	)
	clone.EgressRouteIDs = append([]string(nil), projection.EgressRouteIDs...)
	clone.ConnectorIDs = append([]string(nil), projection.ConnectorIDs...)
	return &clone
}

func cloneActivationCanaryResult(
	result *controlprotocol.ExecutorActivationCanaryResultV1,
) *controlprotocol.ExecutorActivationCanaryResultV1 {
	if result == nil {
		return nil
	}
	clone := *result
	return &clone
}

func readDeliveryState(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("stat executor delivery state %q: %w", path, err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() <= 0 || info.Size() > maxDeliveryStateBytes {
		return nil, fmt.Errorf("executor delivery state %q must be a non-empty owner-only regular file no larger than %d bytes", path, maxDeliveryStateBytes)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open executor delivery state %q: %w", path, err)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) || !opened.Mode().IsRegular() || opened.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("executor delivery state %q changed while opening or is unsafe", path)
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxDeliveryStateBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read executor delivery state %q: %w", path, err)
	}
	if len(raw) == 0 || len(raw) > maxDeliveryStateBytes {
		return nil, fmt.Errorf("executor delivery state %q is empty or exceeds its limit", path)
	}
	return raw, nil
}

func replaceDeliveryState(path string, raw []byte) error {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".steward-executor-deliveries-*")
	if err != nil {
		return fmt.Errorf("create temporary executor delivery state: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(raw); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("replace executor delivery state %q: %w", path, err)
	}
	return syncDirectory(directory)
}

func boundedDeliveryText(value string, limit int) bool {
	return strings.TrimSpace(value) != "" && len(value) <= limit && !strings.ContainsAny(value, "\r\n\x00")
}
