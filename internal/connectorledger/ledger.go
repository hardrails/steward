// Package connectorledger maintains the signed, hash-linked record of mediated
// connector calls. It is deliberately separate from the Executor receipt format:
// adding a high-volume network vocabulary must not make an existing admission
// evidence chain unreadable by an older Steward binary.
package connectorledger

import (
	"bufio"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/hardrails/steward/internal/dsse"
)

const (
	PayloadTypeV1 = "application/vnd.steward.connector-receipt.v1+json"
	PayloadTypeV2 = "application/vnd.steward.connector-receipt.v2+json"
	SchemaV1      = "steward.connector-receipt.v1"
	SchemaV2      = "steward.connector-receipt.v2"
	// PayloadType remains the original format identifier for source compatibility
	// with callers that construct legacy, non-permit receipt fixtures.
	PayloadType              = PayloadTypeV1
	MaxLineBytes             = 128 << 10
	MaxLogBytes              = 64 << 20
	MaxTenantBudgets         = 128
	DefaultMaxTenants        = 16
	DefaultMaxBytesPerTenant = 4 << 20
	terminalReserveBytes     = MaxLineBytes + 1
	minimumTenantBytes       = 2 * terminalReserveBytes
)

var (
	chainDomain = []byte("steward-connector-ledger-v1\x00")

	// ErrTenantQuotaExceeded means a tenant has consumed its durable receipt
	// slice. Other admitted tenants retain their independent slices.
	ErrTenantQuotaExceeded = errors.New("connector ledger tenant byte quota exceeded")
	// ErrTenantUnbudgeted means an explicitly partitioned ledger has no durable
	// receipt allocation for the exact tenant identity in an event.
	ErrTenantUnbudgeted = errors.New("connector ledger tenant is not budgeted")
	// ErrTenantIdentityCapacity means the ledger has no unclaimed historical
	// tenant slot. Tenant identities are retained for the life of the ledger.
	ErrTenantIdentityCapacity = errors.New("connector ledger tenant identity capacity exceeded")
)

// Limits partitions the bounded receipt ledger between tenant identities.
// TenantBudgets, when non-nil, is an exact non-borrowing allocation and cannot
// be combined with the uniform compatibility fields used by DefaultLimits.
// Every byte allowance includes durable record bytes and space reserved for
// terminal records of incomplete calls.
type Limits struct {
	MaxTenants        int
	MaxBytesPerTenant int64
	TenantBudgets     map[string]int64
}

// DefaultLimits returns the hardened single-host partition used by Open and
// OpenWithVisit.
func DefaultLimits() Limits {
	return Limits{MaxTenants: DefaultMaxTenants, MaxBytesPerTenant: DefaultMaxBytesPerTenant}
}

// Validate rejects limits that cannot reserve a worst-case authorization and
// its matching terminal record, or whose product can exceed the bounded log.
func (limits Limits) Validate() error {
	if limits.TenantBudgets != nil {
		if limits.MaxTenants != 0 || limits.MaxBytesPerTenant != 0 {
			return errors.New("connector ledger explicit and uniform tenant limits cannot be combined")
		}
		if len(limits.TenantBudgets) > MaxTenantBudgets {
			return fmt.Errorf("connector ledger permits at most %d tenant budgets", MaxTenantBudgets)
		}
		var total int64
		for tenantID, bytes := range limits.TenantBudgets {
			if !publicIdentity(tenantID, 128) {
				return errors.New("connector ledger tenant budget has an invalid tenant identity")
			}
			if bytes < minimumTenantBytes {
				return fmt.Errorf("connector ledger tenant byte quota must be at least %d", minimumTenantBytes)
			}
			if total > MaxLogBytes-bytes {
				return errors.New("connector ledger tenant quotas exceed total capacity")
			}
			total += bytes
		}
		return nil
	}
	if limits.MaxTenants <= 0 {
		return errors.New("connector ledger max tenants must be positive")
	}
	if limits.MaxBytesPerTenant < minimumTenantBytes {
		return fmt.Errorf("connector ledger tenant byte quota must be at least %d", minimumTenantBytes)
	}
	// Divide before comparing so an operator-supplied product cannot overflow.
	if int64(limits.MaxTenants) > MaxLogBytes/limits.MaxBytesPerTenant {
		return errors.New("connector ledger tenant quotas exceed total capacity")
	}
	return nil
}

func (limits Limits) clone() Limits {
	if limits.TenantBudgets == nil {
		return limits
	}
	cloned := make(map[string]int64, len(limits.TenantBudgets))
	for tenantID, bytes := range limits.TenantBudgets {
		cloned[tenantID] = bytes
	}
	limits.TenantBudgets = cloned
	return limits
}

func (limits Limits) tenantQuota(tenantID string) (int64, error) {
	if limits.TenantBudgets != nil {
		quota, ok := limits.TenantBudgets[tenantID]
		if !ok {
			return 0, ErrTenantUnbudgeted
		}
		return quota, nil
	}
	return limits.MaxBytesPerTenant, nil
}

type Phase string

const (
	Authorize Phase = "authorize"
	Deny      Phase = "deny"
	Terminal  Phase = "terminal"
)

type Outcome string

const (
	Allowed   Outcome = "allowed"
	Denied    Outcome = "denied"
	Responded Outcome = "responded"
	Failed    Outcome = "failed"
)

// Event is the bounded, non-secret portion supplied by Gateway. It records
// enforcement identity and transfer metadata, never headers, credentials,
// origins, paths, queries, or bodies.
type Event struct {
	Phase             Phase   `json:"phase"`
	Outcome           Outcome `json:"outcome"`
	TenantID          string  `json:"tenant_id"`
	RuntimeRef        string  `json:"runtime_ref"`
	CapsuleDigest     string  `json:"capsule_digest"`
	PolicyDigest      string  `json:"policy_digest"`
	RoutePolicyDigest string  `json:"route_policy_digest"`
	Generation        uint64  `json:"generation"`
	GrantID           string  `json:"grant_id"`
	ConnectorID       string  `json:"connector_id"`
	OperationID       string  `json:"operation_id"`
	TaskDigest        string  `json:"task_digest"`
	AuthorityKeyID    string  `json:"authority_key_id,omitempty"`
	PermitDigest      string  `json:"permit_digest,omitempty"`
	RequestDigest     string  `json:"request_digest,omitempty"`
	HTTPStatus        int     `json:"http_status,omitempty"`
	RequestBytes      int64   `json:"request_bytes"`
	ResponseBytes     int64   `json:"response_bytes"`
	ErrorCode         string  `json:"error_code,omitempty"`
}

// Receipt contains one signed chain coordinate and one connector event.
type Receipt struct {
	SchemaVersion string `json:"schema_version"`
	NodeID        string `json:"node_id"`
	Epoch         uint64 `json:"epoch"`
	Sequence      uint64 `json:"sequence"`
	PreviousHash  string `json:"previous_hash"`
	ObservedAt    string `json:"observed_at"`
	Event         Event  `json:"event"`
}

// Head is safe to retain outside the node to detect removal of a complete
// signed suffix during a later verification.
type Head struct {
	NodeID    string `json:"node_id"`
	Epoch     uint64 `json:"epoch"`
	Sequence  uint64 `json:"sequence"`
	ChainHash string `json:"chain_hash"`
	KeyID     string `json:"key_id"`
}

// VerifiedReceipt retains the exact DSSE line whose hash advances the chain.
type VerifiedReceipt struct {
	Receipt Receipt
	Raw     []byte
	Hash    string
}

// Log serializes append and fsync. A failed write or sync poisons the open
// handle: callers must reopen and verify the file before attempting more work.
type Log struct {
	mu       sync.Mutex
	path     string
	file     *os.File
	private  ed25519.PrivateKey
	public   ed25519.PublicKey
	nodeID   string
	epoch    uint64
	keyID    string
	next     uint64
	last     string
	failed   bool
	reserved int64
	pending  map[string]Event
	spent    map[string]struct{}
	limits   Limits
	// tenantBytes includes durable line bytes and pending terminal reserves.
	// Map membership is also the permanent historical tenant identity set.
	tenantBytes map[string]int64
}

func Open(path string, private ed25519.PrivateKey, nodeID string, epoch uint64) (*Log, error) {
	return OpenWithLimits(path, private, nodeID, epoch, DefaultLimits(), nil)
}

// OpenWithVisit verifies the complete existing chain and visits each record
// before returning an append handle. Gateway uses the verified authorization
// records to reconstruct spent task claims after restart or state rollback.
func OpenWithVisit(path string, private ed25519.PrivateKey, nodeID string, epoch uint64, visit func(VerifiedReceipt) error) (*Log, error) {
	return OpenWithLimits(path, private, nodeID, epoch, DefaultLimits(), visit)
}

// OpenWithLimits verifies the complete existing chain, reconstructs tenant
// usage, and visits each record before returning an append handle.
func OpenWithLimits(path string, private ed25519.PrivateKey, nodeID string, epoch uint64, limits Limits, visit func(VerifiedReceipt) error) (*Log, error) {
	if !validPath(path) || len(private) != ed25519.PrivateKeySize || !validText(nodeID, 256) || epoch == 0 {
		return nil, errors.New("connector ledger requires a clean path, Ed25519 key, bounded node id, and positive epoch")
	}
	if err := limits.Validate(); err != nil {
		return nil, err
	}
	limits = limits.clone()
	created := false
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		created = true
	} else if err != nil {
		return nil, fmt.Errorf("stat connector ledger: %w", err)
	} else if !validFileInfo(info) {
		return nil, errors.New("connector ledger must be a bounded owner-only regular file")
	}
	flags := os.O_RDWR | os.O_APPEND
	if created {
		flags |= os.O_CREATE | os.O_EXCL
	}
	file, err := os.OpenFile(path, flags, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open connector ledger: %w", err)
	}
	closeWith := func(openErr error) (*Log, error) {
		_ = file.Close()
		return nil, openErr
	}
	// Path locks are not sufficient here: the same inode can be reached through
	// a hard link with a different pathname. Keep an exclusive descriptor lock
	// for the lifetime of the append handle so only one verified chain head can
	// ever authorize writes to this ledger.
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return closeWith(errors.New("connector ledger is already open by another writer"))
		}
		return closeWith(fmt.Errorf("lock connector ledger: %w", err))
	}
	if created {
		if err := file.Chmod(0o600); err != nil {
			return closeWith(err)
		}
		if err := syncDirectory(filepath.Dir(path)); err != nil {
			return closeWith(err)
		}
	} else {
		opened, err := file.Stat()
		if err != nil || !os.SameFile(info, opened) || !validFileInfo(opened) || opened.Size() != info.Size() {
			return closeWith(errors.New("connector ledger changed while opening"))
		}
	}
	public := private.Public().(ed25519.PublicKey)
	pending := make(map[string]Event)
	spent := make(map[string]struct{})
	tenantBytes := make(map[string]int64)
	head, err := verifyFile(file, public, nodeID, epoch, func(record VerifiedReceipt) error {
		if err := updateHistory(pending, spent, record.Receipt.Event); err != nil {
			return err
		}
		if err := addTenantUsage(tenantBytes, record.Receipt.Event.TenantID, int64(len(record.Raw)+1), limits); err != nil {
			return err
		}
		if visit != nil {
			return visit(record)
		}
		return nil
	})
	if err != nil {
		return closeWith(fmt.Errorf("verify connector ledger: %w", err))
	}
	reserved := int64(len(pending)) * terminalReserveBytes
	for _, event := range pending {
		if err := addTenantUsage(tenantBytes, event.TenantID, terminalReserveBytes, limits); err != nil {
			return closeWith(fmt.Errorf("reserve connector terminal record: %w", err))
		}
	}
	if info, statErr := file.Stat(); statErr != nil {
		return closeWith(statErr)
	} else if info.Size()+reserved > MaxLogBytes {
		return closeWith(errors.New("connector ledger cannot reserve terminal records for incomplete calls"))
	}
	return &Log{
		path: path, file: file, private: append(ed25519.PrivateKey(nil), private...),
		public: append(ed25519.PublicKey(nil), public...), nodeID: nodeID, epoch: epoch,
		keyID: KeyID(public), next: head.Sequence + 1, last: head.ChainHash,
		reserved: reserved, pending: pending, spent: spent, limits: limits, tenantBytes: tenantBytes,
	}, nil
}

// Append records a denial that has no matching external effect. Authorized
// calls use Begin and Finish so space for the terminal receipt is reserved
// before the upstream request can start.
func (l *Log) Append(event Event) (Head, error) {
	if err := validateEvent(event); err != nil {
		return Head{}, err
	}
	if event.Phase != Deny {
		return Head{}, errors.New("connector authorization and terminal events require Begin and Finish")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.appendLocked(event, 0)
}

// Begin durably records an authorization and reserves worst-case space for its
// terminal receipt. No external effect should start until Begin succeeds.
func (l *Log) Begin(event Event) (Head, error) {
	if err := validateEvent(event); err != nil {
		return Head{}, err
	}
	if event.Phase != Authorize {
		return Head{}, errors.New("connector Begin requires an authorization event")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	key := event.TaskDigest
	if _, exists := l.spent[key]; exists {
		return Head{}, errors.New("connector authorization task is already spent")
	}
	head, err := l.appendLocked(event, terminalReserveBytes)
	if err != nil {
		return Head{}, err
	}
	l.pending[key] = event
	l.spent[key] = struct{}{}
	return head, nil
}

// Finish durably closes one authorized call and releases its reserved space.
func (l *Log) Finish(event Event) (Head, error) {
	if err := validateEvent(event); err != nil {
		return Head{}, err
	}
	if event.Phase != Terminal {
		return Head{}, errors.New("connector Finish requires a terminal event")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	authorized, exists := l.pending[event.TaskDigest]
	if !exists || !sameCall(authorized, event) {
		return Head{}, errors.New("connector terminal event has no matching authorization")
	}
	head, err := l.appendLocked(event, -terminalReserveBytes)
	if err != nil {
		return Head{}, err
	}
	delete(l.pending, event.TaskDigest)
	return head, nil
}

// Pending returns verified authorization events without a terminal record.
// Gateway closes these as outcome_unknown after an unclean restart.
func (l *Log) Pending() []Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	result := make([]Event, 0, len(l.pending))
	for _, event := range l.pending {
		result = append(result, event)
	}
	return result
}

func (l *Log) appendLocked(event Event, reservationDelta int64) (Head, error) {
	if l.file == nil {
		return Head{}, errors.New("connector ledger is closed")
	}
	if l.failed {
		return Head{}, errors.New("connector ledger requires reopen after an ambiguous write")
	}
	payloadType, schemaVersion := PayloadTypeV1, SchemaV1
	if event.PermitDigest != "" {
		payloadType, schemaVersion = PayloadTypeV2, SchemaV2
	}
	receipt := Receipt{
		SchemaVersion: schemaVersion, NodeID: l.nodeID, Epoch: l.epoch, Sequence: l.next,
		PreviousHash: l.last, ObservedAt: time.Now().UTC().Format(time.RFC3339Nano), Event: event,
	}
	payload, err := json.Marshal(receipt)
	if err != nil {
		return Head{}, err
	}
	envelope, err := dsse.Sign(payloadType, payload, l.keyID, l.private)
	if err != nil {
		return Head{}, err
	}
	raw, err := dsse.Marshal(envelope)
	if err != nil {
		return Head{}, err
	}
	if len(raw) == 0 || len(raw) > MaxLineBytes {
		return Head{}, errors.New("connector receipt exceeds line limit")
	}
	info, err := l.file.Stat()
	if err != nil {
		return Head{}, err
	}
	reserved := l.reserved + reservationDelta
	if reserved < 0 || info.Size()+int64(len(raw)+1)+reserved > MaxLogBytes {
		return Head{}, errors.New("connector ledger capacity exceeded")
	}
	quota, err := l.limits.tenantQuota(event.TenantID)
	if err != nil {
		return Head{}, err
	}
	tenantUsage := l.tenantBytes[event.TenantID] + int64(len(raw)+1) + reservationDelta
	if tenantUsage < 0 || tenantUsage > quota {
		return Head{}, ErrTenantQuotaExceeded
	}
	if _, exists := l.tenantBytes[event.TenantID]; !exists && l.limits.TenantBudgets == nil && len(l.tenantBytes) >= l.limits.MaxTenants {
		return Head{}, ErrTenantIdentityCapacity
	}
	line := append(append([]byte(nil), raw...), '\n')
	if _, err := l.file.Write(line); err != nil {
		l.failed = true
		return Head{}, err
	}
	if err := l.file.Sync(); err != nil {
		l.failed = true
		return Head{}, err
	}
	l.last = hashLine(raw)
	l.next++
	l.reserved = reserved
	l.tenantBytes[event.TenantID] = tenantUsage
	return l.headLocked(), nil
}

func addTenantUsage(usage map[string]int64, tenantID string, delta int64, limits Limits) error {
	current, exists := usage[tenantID]
	if !exists && limits.TenantBudgets == nil && len(usage) >= limits.MaxTenants {
		return ErrTenantIdentityCapacity
	}
	quota, err := limits.tenantQuota(tenantID)
	if err != nil {
		return err
	}
	if delta < 0 || current > quota-delta {
		return ErrTenantQuotaExceeded
	}
	usage[tenantID] = current + delta
	return nil
}

func (l *Log) Head() Head {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.headLocked()
}

// Failed reports whether an append had an ambiguous write or sync failure.
// Callers may roll back an in-memory reservation only while this remains false.
func (l *Log) Failed() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.failed
}

func (l *Log) headLocked() Head {
	sequence := uint64(0)
	if l.next > 0 {
		sequence = l.next - 1
	}
	return Head{NodeID: l.nodeID, Epoch: l.epoch, Sequence: sequence, ChainHash: l.last, KeyID: l.keyID}
}

func (l *Log) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil {
		return nil
	}
	err := l.file.Close()
	l.file = nil
	return err
}

func VerifyRecords(path string, public ed25519.PublicKey, nodeID string, epoch uint64, visit func(VerifiedReceipt) error) (Head, error) {
	if !validPath(path) || len(public) != ed25519.PublicKeySize || !validText(nodeID, 256) || epoch == 0 {
		return Head{}, errors.New("connector ledger verification arguments are invalid")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return Head{}, err
	}
	if !validFileInfo(info) {
		return Head{}, errors.New("connector ledger must be a bounded owner-only regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return Head{}, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) || !validFileInfo(opened) {
		return Head{}, errors.New("connector ledger changed while opening")
	}
	pending := make(map[string]Event)
	spent := make(map[string]struct{})
	return verifyFile(file, public, nodeID, epoch, func(record VerifiedReceipt) error {
		if err := updateHistory(pending, spent, record.Receipt.Event); err != nil {
			return err
		}
		if visit != nil {
			return visit(record)
		}
		return nil
	})
}

// Validate inspects an existing ledger without creating it. A missing ledger is
// a valid prospective path: Open creates the file during normal startup. When
// the file exists, Validate verifies its permissions, signatures, chain, node
// identity, and epoch using the public half of the configured private key.
func Validate(path string, private ed25519.PrivateKey, nodeID string, epoch uint64) (Head, error) {
	return ValidateWithLimits(path, private, nodeID, epoch, DefaultLimits())
}

// ValidateWithLimits verifies that an existing ledger fits both its signed
// format and the proposed tenant partitions without creating or changing it.
func ValidateWithLimits(path string, private ed25519.PrivateKey, nodeID string, epoch uint64, limits Limits) (Head, error) {
	if !validPath(path) || len(private) != ed25519.PrivateKeySize || !validText(nodeID, 256) || epoch == 0 {
		return Head{}, errors.New("connector ledger requires a clean path, Ed25519 key, bounded node id, and positive epoch")
	}
	if err := limits.Validate(); err != nil {
		return Head{}, err
	}
	public := private.Public().(ed25519.PublicKey)
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return Head{NodeID: nodeID, Epoch: epoch, ChainHash: zeroHash(), KeyID: KeyID(public)}, nil
	} else if err != nil {
		return Head{}, fmt.Errorf("stat connector ledger: %w", err)
	}
	pending := make(map[string]Event)
	spent := make(map[string]struct{})
	tenantBytes := make(map[string]int64)
	head, err := VerifyRecords(path, public, nodeID, epoch, func(record VerifiedReceipt) error {
		if err := updateHistory(pending, spent, record.Receipt.Event); err != nil {
			return err
		}
		return addTenantUsage(tenantBytes, record.Receipt.Event.TenantID, int64(len(record.Raw)+1), limits)
	})
	if err != nil {
		return Head{}, err
	}
	for _, event := range pending {
		if err := addTenantUsage(tenantBytes, event.TenantID, terminalReserveBytes, limits); err != nil {
			return Head{}, fmt.Errorf("reserve connector terminal record: %w", err)
		}
	}
	return head, nil
}

func verifyFile(file *os.File, public ed25519.PublicKey, nodeID string, epoch uint64, visit func(VerifiedReceipt) error) (Head, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return Head{}, err
	}
	info, err := file.Stat()
	if err != nil {
		return Head{}, err
	}
	if info.Size() > 0 {
		var terminal [1]byte
		if _, err := file.ReadAt(terminal[:], info.Size()-1); err != nil || terminal[0] != '\n' {
			return Head{}, errors.New("connector ledger has an incomplete final record")
		}
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return Head{}, err
	}
	head := Head{NodeID: nodeID, Epoch: epoch, ChainHash: zeroHash(), KeyID: KeyID(public)}
	previous := zeroHash()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), MaxLineBytes+1)
	lineNumber := 0
	trusted := map[string]ed25519.PublicKey{head.KeyID: public}
	for scanner.Scan() {
		lineNumber++
		raw := append([]byte(nil), scanner.Bytes()...)
		if len(raw) == 0 || len(raw) > MaxLineBytes {
			return Head{}, fmt.Errorf("connector ledger line %d is empty or oversized", lineNumber)
		}
		envelope, err := dsse.Parse(raw)
		if err != nil || envelope.PayloadType != PayloadTypeV1 && envelope.PayloadType != PayloadTypeV2 {
			return Head{}, fmt.Errorf("verify connector ledger line %d: unsupported receipt envelope", lineNumber)
		}
		payload, keyID, err := dsse.Verify(raw, envelope.PayloadType, trusted)
		if err != nil || keyID != head.KeyID {
			return Head{}, fmt.Errorf("verify connector ledger line %d: %w", lineNumber, err)
		}
		var receipt Receipt
		if err := dsse.DecodeStrictInto(payload, MaxLineBytes, &receipt); err != nil {
			return Head{}, fmt.Errorf("decode connector ledger line %d: %w", lineNumber, err)
		}
		if err := validateReceipt(receipt, envelope.PayloadType, nodeID, epoch, uint64(lineNumber), previous); err != nil {
			return Head{}, fmt.Errorf("validate connector ledger line %d: %w", lineNumber, err)
		}
		current := hashLine(raw)
		if visit != nil {
			if err := visit(VerifiedReceipt{Receipt: receipt, Raw: raw, Hash: current}); err != nil {
				return Head{}, err
			}
		}
		previous, head.Sequence, head.ChainHash = current, receipt.Sequence, current
	}
	if err := scanner.Err(); err != nil {
		return Head{}, fmt.Errorf("read connector ledger: %w", err)
	}
	if _, err := file.Seek(0, io.SeekEnd); err != nil {
		return Head{}, err
	}
	return head, nil
}

func validateReceipt(receipt Receipt, payloadType, nodeID string, epoch, sequence uint64, previous string) error {
	expectedSchema := SchemaV1
	if payloadType == PayloadTypeV2 {
		expectedSchema = SchemaV2
	}
	if receipt.SchemaVersion != expectedSchema || receipt.NodeID != nodeID || receipt.Epoch != epoch ||
		receipt.Sequence != sequence || receipt.PreviousHash != previous {
		return errors.New("connector receipt chain coordinates do not match")
	}
	observed, err := time.Parse(time.RFC3339Nano, receipt.ObservedAt)
	if err != nil || observed.IsZero() || receipt.ObservedAt != observed.UTC().Format(time.RFC3339Nano) {
		return errors.New("connector receipt has an invalid observation time")
	}
	if payloadType == PayloadTypeV1 && receipt.Event.PermitDigest != "" ||
		payloadType == PayloadTypeV2 && receipt.Event.PermitDigest == "" {
		return errors.New("connector receipt schema does not match its permit fields")
	}
	return validateEvent(receipt.Event)
}

func updateHistory(pending map[string]Event, spent map[string]struct{}, event Event) error {
	switch event.Phase {
	case Authorize:
		if _, exists := spent[event.TaskDigest]; exists {
			return errors.New("connector ledger contains a duplicate spent authorization")
		}
		spent[event.TaskDigest] = struct{}{}
		pending[event.TaskDigest] = event
	case Terminal:
		authorized, exists := pending[event.TaskDigest]
		if !exists || !sameCall(authorized, event) {
			return errors.New("connector ledger terminal has no matching authorization")
		}
		delete(pending, event.TaskDigest)
	}
	return nil
}

func sameCall(left, right Event) bool {
	return left.TenantID == right.TenantID && left.RuntimeRef == right.RuntimeRef &&
		left.CapsuleDigest == right.CapsuleDigest && left.PolicyDigest == right.PolicyDigest &&
		left.RoutePolicyDigest == right.RoutePolicyDigest && left.Generation == right.Generation &&
		left.GrantID == right.GrantID && left.ConnectorID == right.ConnectorID &&
		left.OperationID == right.OperationID && left.TaskDigest == right.TaskDigest &&
		left.AuthorityKeyID == right.AuthorityKeyID &&
		left.PermitDigest == right.PermitDigest && left.RequestDigest == right.RequestDigest &&
		left.RequestBytes == right.RequestBytes
}

func validateEvent(event Event) error {
	if !publicIdentity(event.TenantID, 128) || !runtimeRef(event.RuntimeRef) ||
		!digest(event.CapsuleDigest) || !digest(event.PolicyDigest) || !digest(event.RoutePolicyDigest) || event.Generation == 0 ||
		!grantID(event.GrantID) || !identifier(event.ConnectorID) || !identifier(event.OperationID) ||
		!digest(event.TaskDigest) || event.RequestBytes < 0 || event.RequestBytes > 1<<30 ||
		event.ResponseBytes < 0 || event.ResponseBytes > 1<<30 || event.HTTPStatus < 0 || event.HTTPStatus > 599 ||
		(event.ErrorCode != "" && !identifier(event.ErrorCode)) {
		return errors.New("invalid bounded connector event")
	}
	if (event.PermitDigest == "") != (event.RequestDigest == "") ||
		(event.PermitDigest == "") != (event.AuthorityKeyID == "") ||
		event.PermitDigest != "" && (!digest(event.PermitDigest) || !digest(event.RequestDigest)) {
		return errors.New("connector permit and request digests must be valid and present together")
	}
	if event.AuthorityKeyID != "" && !identifier(event.AuthorityKeyID) {
		return errors.New("connector action authority key ID is invalid")
	}
	switch event.Phase {
	case Authorize:
		if event.Outcome != Allowed || event.HTTPStatus != 0 || event.ResponseBytes != 0 || event.ErrorCode != "" {
			return errors.New("invalid connector authorization event")
		}
	case Deny:
		if event.Outcome != Denied || event.HTTPStatus != 0 || event.ResponseBytes != 0 || event.ErrorCode == "" {
			return errors.New("invalid connector denial event")
		}
	case Terminal:
		if event.Outcome != Responded && event.Outcome != Failed {
			return errors.New("invalid connector terminal outcome")
		}
		if event.Outcome == Responded && (event.HTTPStatus < 100 || event.HTTPStatus > 599 || event.ErrorCode != "") {
			return errors.New("responded connector outcome requires an HTTP status and no transport error")
		}
		if event.Outcome == Failed && event.ErrorCode == "" {
			return errors.New("failed connector outcome requires an error code")
		}
	default:
		return errors.New("invalid connector phase")
	}
	return nil
}

func KeyID(public ed25519.PublicKey) string {
	digest := sha256.Sum256(public)
	return "sha256:" + hex.EncodeToString(digest[:])
}

// TaskDigest creates the non-reversible correlation value stored in receipts.
// Callers should still use unpredictable task IDs because hashes of weak IDs can
// be guessed offline.
func TaskDigest(taskID string) (string, error) {
	if !identifier(taskID) {
		return "", errors.New("task id must use 1-128 letters, digits, dot, underscore, or hyphen")
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte("steward-connector-task-v1\x00"))
	_, _ = hash.Write([]byte(taskID))
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

func hashLine(raw []byte) string {
	hash := sha256.New()
	_, _ = hash.Write(chainDomain)
	_, _ = hash.Write(raw)
	return "sha256:" + hex.EncodeToString(hash.Sum(nil))
}

func zeroHash() string { return "sha256:" + strings.Repeat("0", 64) }

func validPath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && path != string(filepath.Separator) && !strings.ContainsRune(path, '\x00')
}

func validFileInfo(info os.FileInfo) bool {
	return info != nil && info.Mode().IsRegular() && info.Mode().Perm()&0o077 == 0 && info.Size() >= 0 && info.Size() <= MaxLogBytes
}

func validText(value string, limit int) bool {
	return value != "" && len(value) <= limit && utf8.ValidString(value) && strings.TrimSpace(value) == value && !strings.ContainsRune(value, '\x00')
}

// publicIdentity matches the existing signed-admission and Gateway grant text
// contract. Leading or trailing whitespace is unusual but already valid public
// identity data, so a connector receipt must preserve it rather than failing
// only when the tenant first performs work.
func publicIdentity(value string, limit int) bool {
	return strings.TrimSpace(value) != "" && len(value) <= limit && utf8.ValidString(value) && !strings.ContainsRune(value, '\x00')
}

func identifier(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for index, character := range value {
		if character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' ||
			character >= '0' && character <= '9' || index > 0 && (character == '.' || character == '_' || character == '-') {
			continue
		}
		return false
	}
	return true
}

func digest(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+64 {
		return false
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil && hex.EncodeToString(decoded) == strings.TrimPrefix(value, "sha256:")
}

func runtimeRef(value string) bool {
	return strings.HasPrefix(value, "executor-") && len(value) == len("executor-")+64 && lowerHex(value[len("executor-"):])
}

func grantID(value string) bool {
	return strings.HasPrefix(value, "grant-") && len(value) == len("grant-")+64 && lowerHex(value[len("grant-"):])
}

func lowerHex(value string) bool {
	for _, character := range value {
		if character < '0' || character > '9' && character < 'a' || character > 'f' {
			return false
		}
	}
	return value != ""
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
