package admission

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const (
	legacyFenceVersion      = 1
	routeFenceVersion       = 2
	maintenanceFenceVersion = 3
	leaseFenceVersion       = 4
	fenceVersion            = leaseFenceVersion
	maxFenceBytes           = 4 << 20
)

// FenceRecord is the durable high-water mark for one tenant-scoped instance.
// CapsuleDigest and RoutePolicyDigest make an equal-generation retry
// idempotent only for the same admitted artifact and gateway semantics.
type FenceRecord struct {
	TenantID          string
	InstanceID        string
	Generation        uint64
	CapsuleDigest     string
	PolicyDigest      string
	LineageID         string
	WorkloadDigest    string
	ImageConfigDigest string
	RoutePolicyDigest string
	LeaseExpiresAt    string
	Present           bool
}

// FenceStore persists policy and generation rollback protection as one
// owner-only, atomically replaced snapshot. It is small by design: the
// executor's host capacity bounds the number of live instance records.
type FenceStore struct {
	mu            sync.Mutex
	path          string
	formatVersion int
	policyEpoch   uint64
	maintenance   MaintenanceState
	byInstance    map[string]FenceRecord
}

// MaintenanceState is the durable node-local admission cordon. It blocks new
// workload admission and starts while leaving status, stop, destroy, evidence,
// and recovery operations available.
type MaintenanceState struct {
	Enabled   bool   `json:"enabled"`
	EnteredAt string `json:"entered_at,omitempty"`
	Reason    string `json:"reason,omitempty"`
}

// OpenFenceStore loads an existing strict snapshot. Initialization is separate.
func OpenFenceStore(path string) (*FenceStore, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("fence store path is required")
	}
	store := &FenceStore{path: path, byInstance: make(map[string]FenceRecord)}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("admission fence store is missing; initialize it explicitly")
	}
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() > maxFenceBytes {
		return nil, errors.New("fence store must be a bounded regular file with mode 0600 or stricter")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if err := store.decode(raw); err != nil {
		return nil, fmt.Errorf("decode fence store: %w", err)
	}
	return store, nil
}

// InitializeFenceStore creates the empty high-water store exactly once. Normal
// startup never treats a missing store as an empty first run because that would
// erase replay protection.
func InitializeFenceStore(path string) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("fence store path is required")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	store := &FenceStore{path: path, byInstance: make(map[string]FenceRecord)}
	raw, err := store.encode()
	if err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(raw); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	err = d.Sync()
	closeErr := d.Close()
	if err != nil {
		return err
	}
	return closeErr
}

// Fences returns the currently persisted rollback coordinates.
func (s *FenceStore) Fences(tenantID, instanceID string) PersistedFences {
	s.mu.Lock()
	defer s.mu.Unlock()
	record := s.byInstance[fenceKey(tenantID, instanceID)]
	return PersistedFences{Generation: record.Generation, PolicyEpoch: s.policyEpoch}
}

// Matches reports whether a previously committed signed admission is exactly
// the requested tenant/instance generation, capsule, and policy epoch. It keeps
// the secure endpoint from adopting a lookalike container created through the
// legacy workload API.
func (s *FenceStore) Matches(record FenceRecord, policyEpoch uint64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.byInstance[fenceKey(record.TenantID, record.InstanceID)]
	return ok && s.policyEpoch == policyEpoch && current == record
}

// Record returns a copy of one committed signed admission record.
func (s *FenceStore) Record(tenantID, instanceID string) (FenceRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.byInstance[fenceKey(tenantID, instanceID)]
	return record, ok
}

// RenewLease atomically extends the local authority window for one exact live
// generation. Equal expiry is idempotent; shortening or reviving an expired
// lease is rejected so delayed commands cannot move the fence backward.
func (s *FenceStore) RenewLease(
	tenantID, instanceID string,
	generation uint64,
	expiresAt string,
	now time.Time,
) error {
	if !bounded(tenantID, 128) || !bounded(instanceID, 256) || generation == 0 || now.IsZero() {
		return errors.New("invalid workload lease identity")
	}
	expires, err := time.Parse(time.RFC3339Nano, expiresAt)
	if err != nil || expires.IsZero() || expiresAt != expires.UTC().Format(time.RFC3339Nano) ||
		!expires.After(now) || expires.After(now.Add(MaxWorkloadLeaseDuration+CommandClockSkew)) {
		return errors.New("invalid workload lease expiry")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := fenceKey(tenantID, instanceID)
	record, ok := s.byInstance[key]
	if !ok || !record.Present || record.Generation != generation {
		return errors.New("workload lease does not match a present admission generation")
	}
	if record.LeaseExpiresAt != "" {
		current, parseErr := time.Parse(time.RFC3339Nano, record.LeaseExpiresAt)
		if parseErr != nil {
			return errors.New("stored workload lease is invalid")
		}
		if expires.Before(current) {
			return errors.New("workload lease expiry rollback")
		}
		if expires.Equal(current) {
			return nil
		}
	}
	previous := record
	record.LeaseExpiresAt = expiresAt
	s.byInstance[key] = record
	if err := s.persistLocked(); err != nil {
		s.byInstance[key] = previous
		return err
	}
	return nil
}

// Records returns a stable copy for opaque runtime-reference lookup.
func (s *FenceStore) Records() []FenceRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	records := make([]FenceRecord, 0, len(s.byInstance))
	for _, record := range s.byInstance {
		records = append(records, record)
	}
	return records
}

// FormatVersion returns the version read from the durable snapshot. The value
// changes to the current writer version after a successful persisted mutation.
// It is intended for read-only upgrade compatibility checks.
func (s *FenceStore) FormatVersion() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.formatVersion
}

func (s *FenceStore) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.byInstance)
}

// Maintenance returns a copy of the durable node-local cordon state.
func (s *FenceStore) Maintenance() MaintenanceState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.maintenance
}

// SetMaintenance atomically enters or exits the node-local admission cordon.
// Re-entering with the same reason is idempotent. A different reason is a
// conflict so an operator cannot accidentally rewrite why an active cordon was
// established.
func (s *FenceStore) SetMaintenance(enabled bool, reason string, now time.Time) error {
	if enabled {
		if !ValidMaintenanceReason(reason) || now.IsZero() {
			return errors.New("maintenance requires a bounded reason and observation time")
		}
		now = now.UTC()
	} else if reason != "" {
		return errors.New("maintenance exit does not accept a reason")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if enabled && s.maintenance.Enabled {
		if s.maintenance.Reason != reason {
			return errors.New("maintenance is already enabled with a different reason")
		}
		return nil
	}
	if !enabled && !s.maintenance.Enabled {
		return nil
	}
	previous := s.maintenance
	if enabled {
		s.maintenance = MaintenanceState{
			Enabled: true, EnteredAt: now.Format(time.RFC3339Nano), Reason: reason,
		}
	} else {
		s.maintenance = MaintenanceState{}
	}
	if err := s.persistLocked(); err != nil {
		s.maintenance = previous
		return err
	}
	return nil
}

// Commit advances the policy and instance high-water marks. Equal generation
// is accepted only when it names the exact same capsule.
func (s *FenceStore) Commit(record FenceRecord, policyEpoch uint64) error {
	if !bounded(record.TenantID, 128) || !bounded(record.InstanceID, 256) ||
		record.Generation == 0 || !digest(record.CapsuleDigest) || !digest(record.PolicyDigest) ||
		!bounded(record.LineageID, 256) || !digest(record.WorkloadDigest) ||
		!digest(record.ImageConfigDigest) || record.RoutePolicyDigest != "" && !digest(record.RoutePolicyDigest) || policyEpoch == 0 {
		return errors.New("invalid fence record")
	}
	if record.LeaseExpiresAt != "" {
		leaseExpiry, err := time.Parse(time.RFC3339Nano, record.LeaseExpiresAt)
		if err != nil || leaseExpiry.IsZero() || record.LeaseExpiresAt != leaseExpiry.UTC().Format(time.RFC3339Nano) {
			return errors.New("invalid fence workload lease")
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if policyEpoch < s.policyEpoch {
		return errors.New("policy epoch rollback")
	}
	key := fenceKey(record.TenantID, record.InstanceID)
	current := s.byInstance[key]
	if record.Generation < current.Generation {
		return errors.New("instance generation rollback")
	}
	if record.Generation == current.Generation && current.Generation != 0 &&
		(current.CapsuleDigest != record.CapsuleDigest || current.PolicyDigest != record.PolicyDigest ||
			current.LineageID != record.LineageID || current.WorkloadDigest != record.WorkloadDigest ||
			current.ImageConfigDigest != record.ImageConfigDigest || current.RoutePolicyDigest != record.RoutePolicyDigest) {
		return errors.New("equal generation identifies a different signed lineage")
	}
	if record.Generation == current.Generation {
		// An idempotent admit retry must not erase a lease accepted after the
		// original admission. Only RenewLease may change this authority window.
		record.LeaseExpiresAt = current.LeaseExpiresAt
	}
	oldEpoch, oldRecord := s.policyEpoch, current
	s.policyEpoch = policyEpoch
	s.byInstance[key] = record
	if err := s.persistLocked(); err != nil {
		s.policyEpoch = oldEpoch
		if oldRecord.Generation == 0 {
			delete(s.byInstance, key)
		} else {
			s.byInstance[key] = oldRecord
		}
		return err
	}
	return nil
}

func (s *FenceStore) persistLocked() error {
	raw, err := s.encode()
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".steward-fences-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
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
	if err := os.Rename(tmpName, s.path); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	err = d.Sync()
	closeErr := d.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	s.formatVersion = fenceVersion
	return nil
}

func (s *FenceStore) encode() ([]byte, error) {
	if len(s.byInstance) > 65535 {
		return nil, errors.New("too many fence records")
	}
	records := make([]FenceRecord, 0, len(s.byInstance))
	for _, record := range s.byInstance {
		records = append(records, record)
	}
	sort.Slice(records, func(i, j int) bool {
		if records[i].TenantID == records[j].TenantID {
			return records[i].InstanceID < records[j].InstanceID
		}
		return records[i].TenantID < records[j].TenantID
	})
	raw := []byte{'S', 'T', 'F', 'N', fenceVersion}
	raw = binary.BigEndian.AppendUint64(raw, s.policyEpoch)
	raw = binary.BigEndian.AppendUint32(raw, uint32(len(records)))
	for _, record := range records {
		raw = appendFenceText(raw, record.TenantID)
		raw = appendFenceText(raw, record.InstanceID)
		raw = binary.BigEndian.AppendUint64(raw, record.Generation)
		raw = appendFenceText(raw, record.CapsuleDigest)
		raw = appendFenceText(raw, record.PolicyDigest)
		raw = appendFenceText(raw, record.LineageID)
		raw = appendFenceText(raw, record.WorkloadDigest)
		raw = appendFenceText(raw, record.ImageConfigDigest)
		raw = appendFenceText(raw, record.RoutePolicyDigest)
		raw = appendFenceText(raw, record.LeaseExpiresAt)
		if record.Present {
			raw = append(raw, 1)
		} else {
			raw = append(raw, 0)
		}
	}
	if s.maintenance.Enabled {
		raw = append(raw, 1)
		raw = appendFenceText(raw, s.maintenance.EnteredAt)
		raw = appendFenceText(raw, s.maintenance.Reason)
	} else {
		raw = append(raw, 0)
	}
	if len(raw) > maxFenceBytes {
		return nil, errors.New("fence store exceeds size limit")
	}
	return raw, nil
}

func (s *FenceStore) decode(raw []byte) error {
	if len(raw) < 17 || string(raw[:4]) != "STFN" ||
		(raw[4] != legacyFenceVersion && raw[4] != routeFenceVersion &&
			raw[4] != maintenanceFenceVersion && raw[4] != leaseFenceVersion) {
		return errors.New("invalid fence store header")
	}
	version := raw[4]
	s.policyEpoch = binary.BigEndian.Uint64(raw[5:13])
	count := binary.BigEndian.Uint32(raw[13:17])
	raw = raw[17:]
	for range count {
		tenant, rest, ok := takeFenceText(raw, 128)
		if !ok {
			return errors.New("invalid fence tenant")
		}
		instance, rest, ok := takeFenceText(rest, 256)
		if !ok || len(rest) < 8 {
			return errors.New("invalid fence instance")
		}
		generation := binary.BigEndian.Uint64(rest[:8])
		capsule, rest, ok := takeFenceText(rest[8:], 128)
		if !ok || generation == 0 || !digest(capsule) {
			return errors.New("invalid fence coordinates")
		}
		policy, rest, ok := takeFenceText(rest, 128)
		if !ok || !digest(policy) {
			return errors.New("invalid fence policy")
		}
		lineage, rest, ok := takeFenceText(rest, 256)
		if !ok {
			return errors.New("invalid fence lineage")
		}
		workloadDigest, rest, ok := takeFenceText(rest, 128)
		if !ok || !digest(workloadDigest) {
			return errors.New("invalid fence workload digest")
		}
		imageConfigDigest, rest, ok := takeFenceText(rest, 128)
		if !ok || !digest(imageConfigDigest) {
			return errors.New("invalid fence image config digest")
		}
		routePolicyDigest := ""
		if version >= routeFenceVersion {
			routePolicyDigest, rest, ok = takeOptionalFenceDigest(rest)
			if !ok {
				return errors.New("invalid fence route policy digest")
			}
		}
		leaseExpiresAt := ""
		if version >= leaseFenceVersion {
			leaseExpiresAt, rest, ok = takeOptionalFenceTimestamp(rest)
			if !ok {
				return errors.New("invalid workload lease expiry")
			}
		}
		if len(rest) < 1 || rest[0] > 1 {
			return errors.New("invalid fence presence")
		}
		present := rest[0] == 1
		rest = rest[1:]
		key := fenceKey(tenant, instance)
		if _, exists := s.byInstance[key]; exists {
			return errors.New("duplicate fence record")
		}
		s.byInstance[key] = FenceRecord{
			TenantID: tenant, InstanceID: instance, Generation: generation,
			CapsuleDigest: capsule, PolicyDigest: policy, LineageID: lineage,
			WorkloadDigest: workloadDigest, ImageConfigDigest: imageConfigDigest,
			RoutePolicyDigest: routePolicyDigest, LeaseExpiresAt: leaseExpiresAt, Present: present,
		}
		raw = rest
	}
	if version >= maintenanceFenceVersion {
		if len(raw) < 1 || raw[0] > 1 {
			return errors.New("invalid fence maintenance state")
		}
		enabled := raw[0] == 1
		raw = raw[1:]
		if enabled {
			enteredAt, rest, ok := takeFenceText(raw, len(time.RFC3339Nano)+10)
			if !ok {
				return errors.New("invalid fence maintenance time")
			}
			observed, err := time.Parse(time.RFC3339Nano, enteredAt)
			if err != nil || observed.IsZero() || enteredAt != observed.UTC().Format(time.RFC3339Nano) {
				return errors.New("invalid fence maintenance time")
			}
			reason, rest, ok := takeFenceText(rest, 256)
			if !ok || !ValidMaintenanceReason(reason) {
				return errors.New("invalid fence maintenance reason")
			}
			s.maintenance = MaintenanceState{Enabled: true, EnteredAt: enteredAt, Reason: reason}
			raw = rest
		}
	}
	if len(raw) != 0 {
		return errors.New("trailing fence store bytes")
	}
	s.formatVersion = int(version)
	return nil
}

func fenceKey(tenantID, instanceID string) string { return tenantID + "\x00" + instanceID }

// ValidMaintenanceReason reports whether value is safe for both the executor
// API and the durable fence representation.
func ValidMaintenanceReason(value string) bool {
	if len(value) == 0 || len(value) > 256 || strings.TrimSpace(value) != value || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func appendFenceText(raw []byte, value string) []byte {
	raw = binary.BigEndian.AppendUint16(raw, uint16(len(value)))
	return append(raw, value...)
}

func takeFenceText(raw []byte, limit int) (string, []byte, bool) {
	if len(raw) < 2 {
		return "", nil, false
	}
	length := int(binary.BigEndian.Uint16(raw[:2]))
	if length == 0 || length > limit || len(raw) < 2+length {
		return "", nil, false
	}
	value := string(raw[2 : 2+length])
	if strings.ContainsRune(value, '\x00') {
		return "", nil, false
	}
	return value, raw[2+length:], true
}

func takeOptionalFenceDigest(raw []byte) (string, []byte, bool) {
	if len(raw) < 2 {
		return "", nil, false
	}
	length := int(binary.BigEndian.Uint16(raw[:2]))
	if length == 0 {
		return "", raw[2:], true
	}
	if length > 128 || len(raw) < 2+length {
		return "", nil, false
	}
	value := string(raw[2 : 2+length])
	if !digest(value) {
		return "", nil, false
	}
	return value, raw[2+length:], true
}

func takeOptionalFenceTimestamp(raw []byte) (string, []byte, bool) {
	if len(raw) < 2 {
		return "", nil, false
	}
	length := int(binary.BigEndian.Uint16(raw[:2]))
	if length == 0 {
		return "", raw[2:], true
	}
	if length > len(time.RFC3339Nano)+10 || len(raw) < 2+length {
		return "", nil, false
	}
	value := string(raw[2 : 2+length])
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.IsZero() || value != parsed.UTC().Format(time.RFC3339Nano) {
		return "", nil, false
	}
	return value, raw[2+length:], true
}
