package executoruplink

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/hardrails/steward/internal/dsse"
)

const (
	stateVersion       = 2
	legacyStateVersion = 1
	maxStateBytes      = 1 << 20
)

var ErrStateMigrationRequired = errors.New("executor uplink state migration required")

type position struct {
	ClaimGeneration  uint64 `json:"claim_generation"`
	Generation       uint64 `json:"generation"`
	Sequence         uint64 `json:"sequence"`
	ReportedStatus   string `json:"reported_status"`
	Absent           bool   `json:"absent,omitempty"`
	LegacyClaimFence bool   `json:"legacy_claim_fence,omitempty"`
}

type stateKey struct {
	TenantID   string
	InstanceID string
}

type stateRecord struct {
	TenantID         string `json:"tenant_id"`
	InstanceID       string `json:"instance_id"`
	ClaimGeneration  uint64 `json:"claim_generation"`
	Generation       uint64 `json:"generation"`
	Sequence         uint64 `json:"sequence"`
	ReportedStatus   string `json:"reported_status"`
	Absent           bool   `json:"absent,omitempty"`
	LegacyClaimFence bool   `json:"legacy_claim_fence,omitempty"`
}

type stateFile struct {
	Version   int           `json:"version"`
	Positions []stateRecord `json:"positions"`
}

type legacyPosition struct {
	Generation     uint64 `json:"generation"`
	Sequence       uint64 `json:"sequence"`
	ReportedStatus string `json:"reported_status"`
	Absent         bool   `json:"absent,omitempty"`
}

// StateStore durably fences stale lifecycle commands across Executor restarts.
// Version 2 keys every position by tenant plus instance so one node-scoped
// credential can safely carry multiple tenants whose instance IDs overlap.
type StateStore struct {
	mu        sync.Mutex
	path      string
	positions map[stateKey]position
}

// StateFormatSummary reports the durable uplink state version after the owning
// package has validated the complete file without changing it.
type StateFormatSummary struct {
	Present       bool
	FormatVersion int
}

func LoadStateStore(path string) (*StateStore, error) {
	if path == "" {
		return nil, errors.New("uplink state file is required")
	}
	raw, err := readStateFile(path)
	if err != nil {
		return nil, err
	}
	var header struct {
		Version int `json:"version"`
	}
	if err := json.Unmarshal(raw, &header); err != nil {
		return nil, fmt.Errorf("decode uplink state %q: %w", path, err)
	}
	if header.Version == legacyStateVersion {
		return nil, fmt.Errorf("%w: %q uses version 1; run the explicit tenant-bound migration before startup", ErrStateMigrationRequired, path)
	}
	if header.Version != stateVersion {
		return nil, fmt.Errorf("uplink state %q has unsupported format version %d", path, header.Version)
	}
	positions, err := decodeCurrentState(raw, path)
	if err != nil {
		return nil, err
	}
	return &StateStore{path: path, positions: positions}, nil
}

func decodeCurrentState(raw []byte, path string) (map[stateKey]position, error) {
	var state stateFile
	if err := dsse.DecodeStrictInto(raw, maxStateBytes, &state); err != nil {
		return nil, fmt.Errorf("decode uplink state %q: %w", path, err)
	}
	if state.Positions == nil {
		return nil, fmt.Errorf("uplink state %q is missing its positions array", path)
	}
	positions := make(map[stateKey]position, len(state.Positions))
	for _, record := range state.Positions {
		key := stateKey{TenantID: record.TenantID, InstanceID: record.InstanceID}
		value := position{
			ClaimGeneration: record.ClaimGeneration, Generation: record.Generation,
			Sequence: record.Sequence, ReportedStatus: record.ReportedStatus, Absent: record.Absent,
			LegacyClaimFence: record.LegacyClaimFence,
		}
		if err := validateStateEntry(key, value); err != nil {
			return nil, fmt.Errorf("uplink state %q contains an invalid position: %w", path, err)
		}
		if _, exists := positions[key]; exists {
			return nil, fmt.Errorf("uplink state %q contains a duplicate tenant/instance position", path)
		}
		positions[key] = value
	}
	return positions, nil
}

// InspectStateFormat validates either supported on-disk uplink state format
// through a read-only descriptor. It accepts the legacy format for upgrade
// planning even though normal startup requires its explicit tenant migration.
func InspectStateFormat(path string) (StateFormatSummary, error) {
	raw, err := readStateFile(path)
	if err != nil {
		return StateFormatSummary{}, err
	}
	var envelope struct {
		Version   int             `json:"version"`
		Positions json.RawMessage `json:"positions"`
	}
	if err := dsse.DecodeStrictInto(raw, maxStateBytes, &envelope); err != nil {
		return StateFormatSummary{}, fmt.Errorf("decode uplink state %q: %w", path, err)
	}
	if len(envelope.Positions) == 0 {
		return StateFormatSummary{}, fmt.Errorf("uplink state %q is missing its positions", path)
	}
	switch envelope.Version {
	case legacyStateVersion:
		if _, err := decodeLegacyPositions(envelope.Positions, path, "format-inspection"); err != nil {
			return StateFormatSummary{}, err
		}
	case stateVersion:
		if _, err := decodeCurrentState(raw, path); err != nil {
			return StateFormatSummary{}, err
		}
	default:
		return StateFormatSummary{}, fmt.Errorf("uplink state %q has unsupported format version %d", path, envelope.Version)
	}
	return StateFormatSummary{Present: true, FormatVersion: envelope.Version}, nil
}

func readStateFile(path string) ([]byte, error) {
	pathInfo, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("uplink state %q is missing; initialize a newly enrolled node once before starting the executor", path)
	}
	if err != nil {
		return nil, fmt.Errorf("stat uplink state %q: %w", path, err)
	}
	if !pathInfo.Mode().IsRegular() || pathInfo.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("uplink state %q must be a regular file with mode 0600 or stricter", path)
	}
	if pathInfo.Size() > maxStateBytes {
		return nil, fmt.Errorf("uplink state %q exceeds %d bytes", path, maxStateBytes)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open uplink state %q: %w", path, err)
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat opened uplink state %q: %w", path, err)
	}
	if !openedInfo.Mode().IsRegular() || openedInfo.Mode().Perm()&0o077 != 0 || !os.SameFile(pathInfo, openedInfo) {
		return nil, fmt.Errorf("uplink state %q changed while opening or is not an owner-only regular file", path)
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxStateBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read uplink state %q: %w", path, err)
	}
	if len(raw) == 0 || len(raw) > maxStateBytes {
		return nil, fmt.Errorf("uplink state %q is empty or exceeds %d bytes", path, maxStateBytes)
	}
	return raw, nil
}

// InitializeStateStore creates the empty version-2 fence for a newly enrolled
// Executor. It is deliberately exclusive and never overwrites an existing file.
func InitializeStateStore(path string) error {
	if path == "" {
		return errors.New("uplink state file is required")
	}
	raw, err := encodeState(map[stateKey]position{})
	if err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("initialize uplink state %q: %w", path, err)
	}
	ok := false
	defer func() {
		_ = file.Close()
		if !ok {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(raw); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := syncDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	ok = true
	return nil
}

// MigrateStateStoreV1ToV2 explicitly assigns every legacy instance fence to
// tenantID, preserves the original bytes in path+".v1.bak", then atomically
// installs version 2. It never guesses a tenant, auto-runs during load, overwrites
// a backup, accepts a downgrade, or removes the backup after success.
func MigrateStateStoreV1ToV2(path, tenantID string) (string, error) {
	if !boundedIdentity(tenantID, 128) {
		return "", errors.New("migration tenant ID must be non-empty and bounded")
	}
	raw, err := readStateFile(path)
	if err != nil {
		return "", err
	}
	var envelope struct {
		Version   int             `json:"version"`
		Positions json.RawMessage `json:"positions"`
	}
	if err := dsse.DecodeStrictInto(raw, maxStateBytes, &envelope); err != nil {
		return "", fmt.Errorf("strictly decode legacy uplink state %q: %w", path, err)
	}
	if envelope.Version != legacyStateVersion || len(envelope.Positions) == 0 {
		return "", fmt.Errorf("legacy uplink state %q is not version 1; refusing migration or downgrade", path)
	}
	positions, err := decodeLegacyPositions(envelope.Positions, path, tenantID)
	if err != nil {
		return "", err
	}
	next, err := encodeState(positions)
	if err != nil {
		return "", err
	}
	backup := path + ".v1.bak"
	if err := writeExclusiveSynced(backup, raw); err != nil {
		return "", fmt.Errorf("create migration backup %q: %w", backup, err)
	}
	if err := replaceStateFile(path, next); err != nil {
		return backup, fmt.Errorf("install migrated uplink state (original remains at %q): %w", backup, err)
	}
	return backup, nil
}

func decodeLegacyPositions(raw json.RawMessage, path, tenantID string) (map[stateKey]position, error) {
	var positionsByInstance map[string]legacyPosition
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&positionsByInstance); err != nil {
		return nil, fmt.Errorf("decode legacy uplink state %q: %w", path, err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("legacy uplink state %q must contain exactly one JSON object", path)
	}
	if positionsByInstance == nil {
		return nil, fmt.Errorf("legacy uplink state %q has null positions", path)
	}
	positions := make(map[stateKey]position, len(positionsByInstance))
	for instanceID, legacy := range positionsByInstance {
		key := stateKey{TenantID: tenantID, InstanceID: instanceID}
		value := position{
			// Version 1 did not persist claim_generation. Preserve its sequence
			// high-water mark across every claim until the first newer command is
			// accepted, rather than guessing a value that could permit replay.
			LegacyClaimFence: true,
			Generation:       legacy.Generation, Sequence: legacy.Sequence,
			ReportedStatus: legacy.ReportedStatus, Absent: legacy.Absent,
		}
		if err := validateStateEntry(key, value); err != nil {
			return nil, fmt.Errorf("legacy uplink state %q contains an invalid position: %w", path, err)
		}
		positions[key] = value
	}
	return positions, nil
}

func (s *StateStore) position(tenantID, instanceID string) (position, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	value, ok := s.positions[stateKey{TenantID: tenantID, InstanceID: instanceID}]
	return value, ok
}

func (s *StateStore) advance(tenantID, instanceID string, value position) error {
	key := stateKey{TenantID: tenantID, InstanceID: instanceID}
	if err := validateStateEntry(key, value); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.positions[key]
	if ok && statePrecedes(value, current) {
		return errors.New("refusing to move uplink state backwards")
	}
	next := make(map[stateKey]position, len(s.positions)+1)
	for existingKey, existing := range s.positions {
		next[existingKey] = existing
	}
	next[key] = value
	raw, err := encodeState(next)
	if err != nil {
		return err
	}
	if err := replaceStateFile(s.path, raw); err != nil {
		return err
	}
	s.positions = next
	return nil
}

func statePrecedes(candidate, current position) bool {
	if current.LegacyClaimFence {
		return candidate.Generation < current.Generation ||
			(candidate.Generation == current.Generation && candidate.Sequence < current.Sequence)
	}
	return candidate.ClaimGeneration < current.ClaimGeneration ||
		candidate.Generation < current.Generation ||
		(candidate.ClaimGeneration == current.ClaimGeneration &&
			candidate.Generation == current.Generation && candidate.Sequence < current.Sequence)
}

func validateStateEntry(key stateKey, value position) error {
	if !boundedIdentity(key.TenantID, 128) || !boundedIdentity(key.InstanceID, 256) ||
		(value.ClaimGeneration == 0) != value.LegacyClaimFence || value.Generation == 0 || value.Sequence == 0 ||
		!boundedIdentity(value.ReportedStatus, 64) {
		return errors.New("tenant, instance, fencing coordinates, and reported status are required")
	}
	return nil
}

func boundedIdentity(value string, limit int) bool {
	return strings.TrimSpace(value) != "" && len(value) <= limit && !strings.ContainsRune(value, '\x00')
}

func encodeState(positions map[stateKey]position) ([]byte, error) {
	records := make([]stateRecord, 0, len(positions))
	for key, value := range positions {
		records = append(records, stateRecord{
			TenantID: key.TenantID, InstanceID: key.InstanceID,
			ClaimGeneration: value.ClaimGeneration, Generation: value.Generation,
			Sequence: value.Sequence, ReportedStatus: value.ReportedStatus, Absent: value.Absent,
			LegacyClaimFence: value.LegacyClaimFence,
		})
	}
	sort.Slice(records, func(i, j int) bool {
		if records[i].TenantID == records[j].TenantID {
			return records[i].InstanceID < records[j].InstanceID
		}
		return records[i].TenantID < records[j].TenantID
	})
	var encoded bytes.Buffer
	if err := json.NewEncoder(&encoded).Encode(stateFile{Version: stateVersion, Positions: records}); err != nil {
		return nil, err
	}
	if encoded.Len() > maxStateBytes {
		return nil, fmt.Errorf("uplink state would exceed %d bytes", maxStateBytes)
	}
	return encoded.Bytes(), nil
}

func replaceStateFile(path string, raw []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".steward-executor-state-*")
	if err != nil {
		return fmt.Errorf("create temporary uplink state: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("replace uplink state %q: %w", path, err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return err
	}
	return syncDirectory(dir)
}

func writeExclusiveSynced(path string, raw []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		_ = file.Close()
		if !ok {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(raw); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := syncDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	ok = true
	return nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open uplink state directory %q: %w", path, err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync uplink state directory %q: %w", path, err)
	}
	return nil
}
