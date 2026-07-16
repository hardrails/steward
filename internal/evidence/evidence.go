// Package evidence maintains a locally verifiable, append-only receipt chain.
// It uses exact binary payloads and framed envelopes so verification never relies
// on JSON canonicalization or permissive duplicate-field handling.
package evidence

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/hardrails/steward/internal/dsse"
)

const (
	PayloadType      = "application/vnd.steward.receipt.v1+binary"
	ExportFormat     = "application/vnd.steward.evidence-export.v1+ndjson"
	MaxEnvelopeBytes = 64 << 10
	MaxDeltaRecords  = 128
	MaxDeltaBytes    = 700 << 10
	maxLogBytes      = 64 << 20
	maxExportBytes   = 256 << 20
	maxExportLine    = 128 << 10
	receiptVersion   = 1
	envelopeVersion  = 1
)

var chainDomain = []byte("steward-evidence-chain-v1\x00")

// EventType is deliberately a closed receipt vocabulary. New decisions require
// an explicit format version/change rather than arbitrary event strings.
type EventType byte

const (
	AdmissionAllow      EventType = 1
	AdmissionDeny       EventType = 2
	JournalPrepare      EventType = 3
	JournalCommit       EventType = 4
	JournalCompensate   EventType = 5
	GatewayRegistration EventType = 6
	InferenceAuthorize  EventType = 7
	InferenceTerminal   EventType = 8
	ServiceMapping      EventType = 9
	LifecycleStart      EventType = 10
	LifecycleStop       EventType = 11
	LifecycleDestroy    EventType = 12
	StatePurge          EventType = 13
	PolicyReload        EventType = 14
	Drift               EventType = 15
	Revocation          EventType = 16
)

// Outcome is a closed result vocabulary. Details belong in bounded,
// non-sensitive ErrorCode and MetadataHash fields.
type Outcome byte

const (
	Allowed     Outcome = 1
	Denied      Outcome = 2
	Committed   Outcome = 3
	Failed      Outcome = 4
	Compensated Outcome = 5
)

// Event contains the caller-supplied, non-secret portion of a receipt. The log
// supplies node identity, epoch, sequence and previous chain hash itself.
type Event struct {
	Type          EventType
	TenantID      string
	RuntimeRef    string
	CapsuleDigest string
	PolicyDigest  string
	Generation    uint64
	GrantID       string
	Outcome       Outcome
	ErrorCode     string
	MetadataHash  string
}

// Receipt is the exact signed statement after its chain coordinates were set.
// PreviousHash is the prior chain hash, not merely the prior payload hash.
type Receipt struct {
	Version      byte
	NodeID       string
	Epoch        uint64
	Sequence     uint64
	PreviousHash [sha256.Size]byte
	Event
}

// VerifiedReceipt pairs one authenticated receipt with the chain hash after
// that receipt. Frame is an independent copy of the exact length-prefixed,
// signed envelope consumed by verification; it can be moved without
// reserializing the signed payload. Retaining the final pair outside the node
// lets a later verifier detect removal of a complete signed suffix.
type VerifiedReceipt struct {
	Receipt   Receipt
	ChainHash [sha256.Size]byte
	Frame     []byte
}

// Head is the compact, non-secret result of verifying a complete chain.
type Head struct {
	NodeID    string
	Epoch     uint64
	Sequence  uint64
	ChainHash [sha256.Size]byte
	KeyID     string
}

// Coordinate identifies an exact durable position in a receipt chain. The
// genesis coordinate is sequence zero with a zero chain hash.
type Coordinate struct {
	Sequence  uint64
	ChainHash [sha256.Size]byte
}

// Delta carries an exact bounded prefix after a requested coordinate. Frames
// retain the native four-byte length prefix and signed envelope bytes. Head is
// the coordinate derived after the last returned frame, or the supplied
// coordinate when no newer receipt exists.
type Delta struct {
	Frames [][]byte
	Head   Head
}

// FormatSummary reports the receipt version physically observed in an
// existing evidence log. Empty logs contain no receipt header, so
// FormatVersion is zero. This is a structural, read-only compatibility check;
// callers that need authenticity must also verify the chain with its public
// key through OpenForValidation or VerifyRecords.
type FormatSummary struct {
	Present       bool
	FormatVersion int
	Records       uint64
}

// Envelope is a DSSE-like envelope carrying exact binary statement bytes. The
// signature is over PreAuthEncoding(PayloadType, Payload), not a reserialized
// Receipt struct.
type Envelope struct {
	Version     byte
	PayloadType string
	Payload     []byte
	KeyID       string
	Signature   []byte
}

// Log owns a private signing key for one node receipt chain. Callers should
// append authorization receipts before an externally visible side effect.
type Log struct {
	mu       sync.Mutex
	path     string
	file     *os.File
	private  ed25519.PrivateKey
	public   ed25519.PublicKey
	readOnly bool
	nodeID   string
	epoch    uint64
	keyID    string
	next     uint64
	lastHash [sha256.Size]byte
}

// Open verifies the entire existing chain with the supplied private key's
// public half before accepting appends. A changed key, partial frame or
// reordering is a fail-closed error. Like every self-contained hash chain, it
// cannot prove that an attacker did not remove a complete signed suffix unless
// the verifier also retains an expected head/sequence externally.
func Open(path string, private ed25519.PrivateKey, nodeID string, epoch uint64) (*Log, error) {
	if path == "" || !validText(nodeID, 256) || epoch == 0 {
		return nil, errors.New("evidence requires path, bounded node id, and positive epoch")
	}
	if len(private) != ed25519.PrivateKeySize {
		return nil, errors.New("evidence private key has invalid length")
	}
	created := false
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		created = true
	} else if err != nil {
		return nil, fmt.Errorf("stat evidence %q: %w", path, err)
	} else if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("evidence %q must be a regular file with mode 0600 or stricter", path)
	} else if info.Size() > maxLogBytes {
		return nil, fmt.Errorf("evidence %q exceeds %d bytes", path, maxLogBytes)
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open evidence %q: %w", path, err)
	}
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return nil, err
	}
	if created {
		if err := syncDirectory(filepath.Dir(path)); err != nil {
			_ = f.Close()
			return nil, err
		}
	}
	public := private.Public().(ed25519.PublicKey)
	next, last, err := verifyFile(f, public, nodeID, epoch)
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("verify evidence %q: %w", path, err)
	}
	return &Log{path: path, file: f, private: private, public: append(ed25519.PublicKey(nil), public...), nodeID: nodeID, epoch: epoch,
		keyID: KeyID(public), next: next, lastHash: last}, nil
}

// OpenForValidation verifies an existing evidence chain through a read-only
// descriptor. It never creates a missing log, changes its mode, or opens it for
// append. The returned Log supports inspection methods used by secure-admission
// startup validation; Append fails explicitly.
func OpenForValidation(path string, public ed25519.PublicKey, nodeID string, epoch uint64) (*Log, error) {
	if path == "" || len(public) != ed25519.PublicKeySize || !validText(nodeID, 256) || epoch == 0 {
		return nil, errors.New("evidence validation requires path, public key, bounded node id, and positive epoch")
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("evidence %q is missing; initialize durable admission state before validation", path)
	}
	if err != nil {
		return nil, fmt.Errorf("stat evidence %q: %w", path, err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("evidence %q must be a regular file with mode 0600 or stricter", path)
	}
	if info.Size() > maxLogBytes {
		return nil, fmt.Errorf("evidence %q exceeds %d bytes", path, maxLogBytes)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open evidence %q for validation: %w", path, err)
	}
	openedInfo, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("stat opened evidence %q: %w", path, err)
	}
	if !os.SameFile(info, openedInfo) || !openedInfo.Mode().IsRegular() || openedInfo.Mode().Perm()&0o077 != 0 || openedInfo.Size() > maxLogBytes {
		_ = f.Close()
		return nil, fmt.Errorf("evidence %q changed while it was opened for validation", path)
	}
	next, last, err := verifyFile(f, public, nodeID, epoch)
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("verify evidence %q: %w", path, err)
	}
	return &Log{path: path, file: f, public: append(ed25519.PublicKey(nil), public...), readOnly: true,
		nodeID: nodeID, epoch: epoch, keyID: KeyID(public), next: next, lastHash: last}, nil
}

// InspectFormat validates every frame and receipt structurally through a
// read-only descriptor and reports the observed receipt version. It never
// creates a missing log or changes file metadata.
func InspectFormat(path string) (FormatSummary, error) {
	if path == "" {
		return FormatSummary{}, errors.New("evidence path is required")
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return FormatSummary{}, fmt.Errorf("evidence %q is missing", path)
	}
	if err != nil {
		return FormatSummary{}, fmt.Errorf("stat evidence %q: %w", path, err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() > maxLogBytes {
		return FormatSummary{}, fmt.Errorf("evidence %q must be a bounded regular file with mode 0600 or stricter", path)
	}
	file, err := os.Open(path)
	if err != nil {
		return FormatSummary{}, fmt.Errorf("open evidence %q for format inspection: %w", path, err)
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return FormatSummary{}, fmt.Errorf("stat opened evidence %q: %w", path, err)
	}
	if !os.SameFile(info, openedInfo) || !openedInfo.Mode().IsRegular() || openedInfo.Mode().Perm()&0o077 != 0 || openedInfo.Size() > maxLogBytes {
		return FormatSummary{}, fmt.Errorf("evidence %q changed while it was opened for format inspection", path)
	}
	summary := FormatSummary{Present: true}
	for {
		raw, err := readFrame(file)
		if errors.Is(err, io.EOF) {
			return summary, nil
		}
		if err != nil {
			return FormatSummary{}, fmt.Errorf("inspect evidence %q: %w", path, err)
		}
		envelope, err := unmarshalEnvelope(raw)
		if err != nil {
			return FormatSummary{}, fmt.Errorf("inspect evidence %q: %w", path, err)
		}
		receipt, err := unmarshalReceipt(envelope.Payload)
		if err != nil {
			return FormatSummary{}, fmt.Errorf("inspect evidence %q: %w", path, err)
		}
		if summary.FormatVersion != 0 && summary.FormatVersion != int(receipt.Version) {
			return FormatSummary{}, fmt.Errorf("evidence %q contains mixed receipt format versions", path)
		}
		summary.FormatVersion = int(receipt.Version)
		summary.Records++
	}
}

// Verify checks a receipt file without its private key and returns the final
// chain receipt. An empty valid file returns nil.
func Verify(path string, public ed25519.PublicKey, nodeID string, epoch uint64) (*Receipt, error) {
	if len(public) != ed25519.PublicKeySize || !validText(nodeID, 256) || epoch == 0 {
		return nil, errors.New("evidence verification arguments are invalid")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if err := validateInputFile(f, maxLogBytes, "evidence log"); err != nil {
		return nil, err
	}
	_, _, last, err := verifyFileWithLast(f, public, nodeID, epoch)
	return last, err
}

// VerifyRecords authenticates the complete chain before returning its head and
// invokes visit for each verified record in sequence. Callers that publish
// partial output should run this once with a nil visitor first, then a second
// time with their visitor, so a corrupt suffix cannot make partial output look
// like a complete export.
func VerifyRecords(path string, public ed25519.PublicKey, nodeID string, epoch uint64, visit func(VerifiedReceipt) error) (Head, error) {
	if len(public) != ed25519.PublicKeySize || !validText(nodeID, 256) || epoch == 0 {
		return Head{}, errors.New("evidence verification arguments are invalid")
	}
	f, err := os.Open(path)
	if err != nil {
		return Head{}, err
	}
	defer f.Close()
	if err := validateInputFile(f, maxLogBytes, "evidence log"); err != nil {
		return Head{}, err
	}
	next, hash, _, err := verifyFileWithVisitor(f, public, nodeID, epoch, visit)
	if err != nil {
		return Head{}, err
	}
	return Head{NodeID: nodeID, Epoch: epoch, Sequence: next - 1, ChainHash: hash, KeyID: KeyID(public)}, nil
}

// VerifyDelta authenticates a bounded sequence of exact native frames starting
// immediately after a trusted, externally retained prior coordinate. It does
// not authenticate that prior coordinate itself. It applies the same key, node,
// epoch, receipt-schema and chain-coordinate checks as full-file verification,
// then requires every receipt tenant to be accepted by tenantMember.
func VerifyDelta(frames [][]byte, public ed25519.PublicKey, nodeID string, epoch uint64, prior Coordinate, tenantMember func(string) bool) (Head, error) {
	if len(public) != ed25519.PublicKeySize || !validText(nodeID, 256) || epoch == 0 || tenantMember == nil {
		return Head{}, errors.New("evidence delta verification arguments are invalid")
	}
	if err := validateCoordinate(prior); err != nil {
		return Head{}, err
	}
	if len(frames) > MaxDeltaRecords {
		return Head{}, fmt.Errorf("evidence delta exceeds %d records", MaxDeltaRecords)
	}
	total := 0
	for _, frame := range frames {
		if len(frame) < 5 || len(frame) > MaxEnvelopeBytes+4 {
			return Head{}, errors.New("evidence delta contains an invalid frame size")
		}
		if total > MaxDeltaBytes-len(frame) {
			return Head{}, fmt.Errorf("evidence delta exceeds %d decoded bytes", MaxDeltaBytes)
		}
		total += len(frame)
	}
	if uint64(len(frames)) > ^uint64(0)-prior.Sequence {
		return Head{}, errors.New("evidence delta sequence would overflow")
	}

	head := Head{NodeID: nodeID, Epoch: epoch, Sequence: prior.Sequence, ChainHash: prior.ChainHash, KeyID: KeyID(public)}
	expected := prior.Sequence + 1
	previous := prior.ChainHash
	for index, frame := range frames {
		receipt, current, err := verifyCanonicalFrame(frame, public, nodeID, epoch, expected, previous)
		if err != nil {
			return Head{}, fmt.Errorf("verify evidence delta record %d: %w", index+1, err)
		}
		if !tenantMember(receipt.TenantID) {
			return Head{}, fmt.Errorf("evidence delta record %d has unauthorized tenant", index+1)
		}
		head.Sequence = receipt.Sequence
		head.ChainHash = current
		previous = current
		expected++
	}
	return head, nil
}

// VerifyAnyRecords auto-detects and verifies either the native length-framed
// evidence log or Steward's portable NDJSON export. Portable receipt fields are
// checked projections of the embedded signed frames; the frames, not the JSON
// projections, remain the cryptographic source of truth.
func VerifyAnyRecords(path string, public ed25519.PublicKey, nodeID string, epoch uint64, visit func(VerifiedReceipt) error) (Head, error) {
	if len(public) != ed25519.PublicKeySize || !validText(nodeID, 256) || epoch == 0 {
		return Head{}, errors.New("evidence verification arguments are invalid")
	}
	f, err := os.Open(path)
	if err != nil {
		return Head{}, err
	}
	defer f.Close()
	if err := validateInputFile(f, maxExportBytes, "evidence input"); err != nil {
		return Head{}, err
	}
	portable, err := isPortableExport(f)
	if err != nil {
		return Head{}, err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return Head{}, err
	}
	if !portable {
		info, err := f.Stat()
		if err != nil {
			return Head{}, err
		}
		if info.Size() > maxLogBytes {
			return Head{}, fmt.Errorf("evidence log exceeds %d bytes", maxLogBytes)
		}
		next, hash, _, err := verifyFileWithVisitor(f, public, nodeID, epoch, visit)
		if err != nil {
			return Head{}, err
		}
		return Head{NodeID: nodeID, Epoch: epoch, Sequence: next - 1, ChainHash: hash, KeyID: KeyID(public)}, nil
	}
	return verifyExportWithVisitor(f, public, nodeID, epoch, visit)
}

// EventName and OutcomeName expose the closed receipt vocabulary without
// turning unknown numeric values into apparently valid audit labels.
func EventName(value EventType) string {
	switch value {
	case AdmissionAllow:
		return "admission_allow"
	case AdmissionDeny:
		return "admission_deny"
	case JournalPrepare:
		return "journal_prepare"
	case JournalCommit:
		return "journal_commit"
	case JournalCompensate:
		return "journal_compensate"
	case GatewayRegistration:
		return "gateway_registration"
	case InferenceAuthorize:
		return "inference_authorize"
	case InferenceTerminal:
		return "inference_terminal"
	case ServiceMapping:
		return "service_mapping"
	case LifecycleStart:
		return "lifecycle_start"
	case LifecycleStop:
		return "lifecycle_stop"
	case LifecycleDestroy:
		return "lifecycle_destroy"
	case StatePurge:
		return "state_purge"
	case PolicyReload:
		return "policy_reload"
	case Drift:
		return "drift"
	case Revocation:
		return "revocation"
	default:
		return ""
	}
}

func OutcomeName(value Outcome) string {
	switch value {
	case Allowed:
		return "allowed"
	case Denied:
		return "denied"
	case Committed:
		return "committed"
	case Failed:
		return "failed"
	case Compensated:
		return "compensated"
	default:
		return ""
	}
}

// Append serializes and signs one receipt, writes its length-framed envelope,
// and fsyncs before reporting success.
func (l *Log) Append(event Event) (Receipt, error) {
	if err := validateEvent(event); err != nil {
		return Receipt{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil {
		return Receipt{}, errors.New("evidence log is closed")
	}
	if l.readOnly {
		return Receipt{}, errors.New("evidence log is open for validation only")
	}
	receipt := Receipt{Version: receiptVersion, NodeID: l.nodeID, Epoch: l.epoch,
		Sequence: l.next, PreviousHash: l.lastHash, Event: event}
	payload, err := marshalReceipt(receipt)
	if err != nil {
		return Receipt{}, err
	}
	pae := PreAuthEncoding(PayloadType, payload)
	envelope := Envelope{Version: envelopeVersion, PayloadType: PayloadType, Payload: payload,
		KeyID: l.keyID, Signature: ed25519.Sign(l.private, pae)}
	raw, err := marshalEnvelope(envelope)
	if err != nil {
		return Receipt{}, err
	}
	if len(raw) > MaxEnvelopeBytes {
		return Receipt{}, errors.New("evidence envelope exceeds size limit")
	}
	info, err := l.file.Stat()
	if err != nil {
		return Receipt{}, err
	}
	if info.Size()+int64(4+len(raw)) > maxLogBytes {
		return Receipt{}, errors.New("evidence log would exceed size limit")
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(raw)))
	if err := writeAll(l.file, header[:]); err != nil {
		return Receipt{}, err
	}
	if err := writeAll(l.file, raw); err != nil {
		return Receipt{}, err
	}
	if err := l.file.Sync(); err != nil {
		return Receipt{}, err
	}
	l.lastHash = chainHash(receipt.PreviousHash, pae)
	l.next++
	return receipt, nil
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

// PublicKey returns a copy suitable for offline verification.
func (l *Log) PublicKey() ed25519.PublicKey {
	return append(ed25519.PublicKey(nil), l.public...)
}

// NextSequence exposes only the non-secret durable chain position so startup
// can detect a missing whole log when admission fences already exist.
func (l *Log) NextSequence() uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.next
}

// CurrentHead returns the exact compact head already authenticated when the
// log was opened and updated after each fsynced append. Unlike ExportDelta, it
// describes the whole local chain rather than the end of one bounded batch.
// An evidence publisher uses this snapshot to prove rollback when a retained
// controller checkpoint is no longer present in the local log.
func (l *Log) CurrentHead() (Head, error) {
	if l == nil {
		return Head{}, errors.New("evidence log is unavailable")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil {
		return Head{}, errors.New("evidence log is closed")
	}
	if l.next == 0 {
		return Head{}, errors.New("evidence log has an invalid in-memory coordinate")
	}
	return Head{
		NodeID: l.nodeID, Epoch: l.epoch, Sequence: l.next - 1,
		ChainHash: l.lastHash, KeyID: l.keyID,
	}, nil
}

// ExportDelta returns the next bounded group of exact signed frames after an
// externally retained chain coordinate. The coordinate must match this log
// exactly; a caller cannot skip a missing or changed receipt.
func (l *Log) ExportDelta(after Coordinate) (Delta, error) {
	if err := validateCoordinate(after); err != nil {
		return Delta{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil {
		return Delta{}, errors.New("evidence log is closed")
	}
	if _, err := l.file.Seek(0, io.SeekStart); err != nil {
		return Delta{}, err
	}

	result := Delta{Head: Head{
		NodeID: l.nodeID, Epoch: l.epoch, Sequence: after.Sequence,
		ChainHash: after.ChainHash, KeyID: l.keyID,
	}}
	found := after.Sequence == 0
	var previous [sha256.Size]byte
	var expected uint64 = 1
	var scanned int64
	total := 0
	for {
		raw, err := readFrame(l.file)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return Delta{}, err
		}
		scanned += int64(4 + len(raw))
		if scanned > maxLogBytes {
			return Delta{}, fmt.Errorf("evidence log exceeds %d bytes", maxLogBytes)
		}
		receipt, current, err := verifyEnvelope(raw, l.public, l.nodeID, l.epoch, expected, previous)
		if err != nil {
			return Delta{}, err
		}
		previous = current
		expected++

		if receipt.Sequence <= after.Sequence {
			if receipt.Sequence == after.Sequence {
				if current != after.ChainHash {
					return Delta{}, errors.New("evidence delta coordinate does not match the log")
				}
				found = true
			}
			continue
		}
		if !found {
			return Delta{}, errors.New("evidence delta coordinate is not present in the log")
		}
		frame := frameBytes(raw)
		if len(result.Frames) == MaxDeltaRecords || total > MaxDeltaBytes-len(frame) {
			break
		}
		result.Frames = append(result.Frames, frame)
		total += len(frame)
		result.Head.Sequence = receipt.Sequence
		result.Head.ChainHash = current
	}
	if !found {
		return Delta{}, errors.New("evidence delta coordinate is not present in the log")
	}
	return result, nil
}

// KeyID is a stable non-secret identifier for a receipt public key.
func KeyID(public ed25519.PublicKey) string {
	sum := sha256.Sum256(public)
	return hex.EncodeToString(sum[:16])
}

// PreAuthEncoding is the exact DSSE-style signing input. Decimal lengths make
// the concatenation injective and PayloadType provides a protocol boundary.
func PreAuthEncoding(payloadType string, payload []byte) []byte {
	return []byte(fmt.Sprintf("DSSEv1 %d %s %d %s", len(payloadType), payloadType, len(payload), payload))
}

func verifyFile(f *os.File, public ed25519.PublicKey, nodeID string, epoch uint64) (uint64, [sha256.Size]byte, error) {
	next, last, _, err := verifyFileWithLast(f, public, nodeID, epoch)
	return next, last, err
}

func verifyFileWithLast(f *os.File, public ed25519.PublicKey, nodeID string, epoch uint64) (uint64, [sha256.Size]byte, *Receipt, error) {
	return verifyFileWithVisitor(f, public, nodeID, epoch, nil)
}

func verifyFileWithVisitor(f *os.File, public ed25519.PublicKey, nodeID string, epoch uint64, visit func(VerifiedReceipt) error) (uint64, [sha256.Size]byte, *Receipt, error) {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return 0, [sha256.Size]byte{}, nil, err
	}
	var previous [sha256.Size]byte
	var expected uint64 = 1
	var last *Receipt
	var total int64
	for {
		raw, err := readFrame(f)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return 0, [sha256.Size]byte{}, nil, err
		}
		total += int64(4 + len(raw))
		if total > maxLogBytes {
			return 0, [sha256.Size]byte{}, nil, fmt.Errorf("evidence log exceeds %d bytes", maxLogBytes)
		}
		receipt, current, err := verifyEnvelope(raw, public, nodeID, epoch, expected, previous)
		if err != nil {
			return 0, [sha256.Size]byte{}, nil, err
		}
		previous = current
		if visit != nil {
			if err := visit(VerifiedReceipt{Receipt: receipt, ChainHash: previous, Frame: frameBytes(raw)}); err != nil {
				return 0, [sha256.Size]byte{}, nil, err
			}
		}
		copyReceipt := receipt
		last = &copyReceipt
		expected++
	}
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		return 0, [sha256.Size]byte{}, nil, err
	}
	return expected, previous, last, nil
}

func verifyEnvelope(raw []byte, public ed25519.PublicKey, nodeID string, epoch, expected uint64, previous [sha256.Size]byte) (Receipt, [sha256.Size]byte, error) {
	envelope, err := unmarshalEnvelope(raw)
	if err != nil {
		return Receipt{}, [sha256.Size]byte{}, err
	}
	pae := PreAuthEncoding(envelope.PayloadType, envelope.Payload)
	if envelope.Version != envelopeVersion || envelope.PayloadType != PayloadType || envelope.KeyID != KeyID(public) ||
		len(envelope.Signature) != ed25519.SignatureSize || !ed25519.Verify(public, pae, envelope.Signature) {
		return Receipt{}, [sha256.Size]byte{}, errors.New("invalid evidence envelope signature or identity")
	}
	receipt, err := unmarshalReceipt(envelope.Payload)
	if err != nil {
		return Receipt{}, [sha256.Size]byte{}, err
	}
	if receipt.NodeID != nodeID || receipt.Epoch != epoch || receipt.Sequence != expected || receipt.PreviousHash != previous {
		return Receipt{}, [sha256.Size]byte{}, errors.New("evidence chain coordinate mismatch")
	}
	return receipt, chainHash(receipt.PreviousHash, pae), nil
}

func frameBytes(envelope []byte) []byte {
	frame := make([]byte, 4+len(envelope))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(envelope)))
	copy(frame[4:], envelope)
	return frame
}

func verifyFrame(frame []byte, public ed25519.PublicKey, nodeID string, epoch, expected uint64, previous [sha256.Size]byte) (Receipt, [sha256.Size]byte, error) {
	if len(frame) < 5 {
		return Receipt{}, [sha256.Size]byte{}, errors.New("portable evidence contains a short signed frame")
	}
	size := binary.BigEndian.Uint32(frame[:4])
	if size == 0 || size > MaxEnvelopeBytes || uint64(size) != uint64(len(frame)-4) {
		return Receipt{}, [sha256.Size]byte{}, errors.New("portable evidence contains an invalid signed frame")
	}
	return verifyEnvelope(frame[4:], public, nodeID, epoch, expected, previous)
}

func verifyCanonicalFrame(frame []byte, public ed25519.PublicKey, nodeID string, epoch, expected uint64, previous [sha256.Size]byte) (Receipt, [sha256.Size]byte, error) {
	if len(frame) < 5 {
		return Receipt{}, [sha256.Size]byte{}, errors.New("evidence delta contains a short signed frame")
	}
	size := binary.BigEndian.Uint32(frame[:4])
	if size == 0 || size > MaxEnvelopeBytes || uint64(size) != uint64(len(frame)-4) {
		return Receipt{}, [sha256.Size]byte{}, errors.New("evidence delta contains an invalid signed frame")
	}
	envelope, err := unmarshalEnvelope(frame[4:])
	if err != nil {
		return Receipt{}, [sha256.Size]byte{}, err
	}
	canonicalEnvelope, err := marshalEnvelope(envelope)
	if err != nil || !bytes.Equal(canonicalEnvelope, frame[4:]) {
		return Receipt{}, [sha256.Size]byte{}, errors.New("evidence delta contains a non-canonical envelope")
	}
	receipt, err := unmarshalReceipt(envelope.Payload)
	if err != nil {
		return Receipt{}, [sha256.Size]byte{}, err
	}
	canonicalReceipt, err := marshalReceipt(receipt)
	if err != nil || !bytes.Equal(canonicalReceipt, envelope.Payload) {
		return Receipt{}, [sha256.Size]byte{}, errors.New("evidence delta contains a non-canonical receipt")
	}
	return verifyEnvelope(frame[4:], public, nodeID, epoch, expected, previous)
}

func validateCoordinate(value Coordinate) error {
	if value.Sequence == 0 && value.ChainHash != [sha256.Size]byte{} {
		return errors.New("evidence genesis coordinate must have a zero chain hash")
	}
	return nil
}

type portableLine struct {
	Kind          *string       `json:"kind"`
	Format        *string       `json:"format"`
	SignedFrame   *string       `json:"signed_frame"`
	NodeID        *string       `json:"node_id"`
	Epoch         *uint64       `json:"epoch"`
	Sequence      *uint64       `json:"sequence"`
	PreviousHash  *string       `json:"previous_hash"`
	ChainHash     *string       `json:"chain_hash"`
	Event         *string       `json:"event"`
	TenantID      *string       `json:"tenant_id"`
	RuntimeRef    *string       `json:"runtime_ref"`
	CapsuleDigest *string       `json:"capsule_digest"`
	PolicyDigest  *string       `json:"policy_digest"`
	Generation    *uint64       `json:"generation"`
	GrantID       *string       `json:"grant_id"`
	Outcome       *string       `json:"outcome"`
	ErrorCode     *string       `json:"error_code"`
	MetadataHash  *string       `json:"metadata_hash"`
	Head          *portableHead `json:"head"`
}

type portableHead struct {
	NodeID    *string `json:"node_id"`
	Epoch     *uint64 `json:"epoch"`
	Sequence  *uint64 `json:"sequence"`
	ChainHash *string `json:"chain_hash"`
	KeyID     *string `json:"key_id"`
}

func verifyExportWithVisitor(f *os.File, public ed25519.PublicKey, nodeID string, epoch uint64, visit func(VerifiedReceipt) error) (Head, error) {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return Head{}, err
	}
	reader := bufio.NewReaderSize(f, maxExportLine+1)
	var previous [sha256.Size]byte
	var expected uint64 = 1
	var total int64
	lineNumber := 0
	seenHead := false
	for {
		raw, err := reader.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) {
			return Head{}, fmt.Errorf("portable evidence line %d exceeds %d bytes", lineNumber+1, maxExportLine)
		}
		if errors.Is(err, io.EOF) {
			if len(raw) != 0 {
				return Head{}, errors.New("portable evidence is truncated or lacks its final newline")
			}
			break
		}
		if err != nil {
			return Head{}, fmt.Errorf("read portable evidence: %w", err)
		}
		lineNumber++
		total += int64(len(raw))
		if total > maxExportBytes {
			return Head{}, fmt.Errorf("portable evidence exceeds %d bytes", maxExportBytes)
		}
		if len(raw) <= 1 || len(raw) > maxExportLine {
			return Head{}, fmt.Errorf("portable evidence line %d is empty or exceeds its limit", lineNumber)
		}
		if seenHead {
			return Head{}, errors.New("portable evidence contains content after its final head")
		}
		var line portableLine
		if err := dsse.DecodeStrictInto(raw[:len(raw)-1], maxExportLine, &line); err != nil {
			return Head{}, fmt.Errorf("decode portable evidence line %d: %w", lineNumber, err)
		}
		if line.Kind == nil || line.Format == nil || *line.Format != ExportFormat {
			return Head{}, fmt.Errorf("portable evidence line %d has an invalid kind or format", lineNumber)
		}
		switch *line.Kind {
		case "receipt":
			if err := validatePortableReceiptShape(line); err != nil {
				return Head{}, fmt.Errorf("portable evidence line %d: %w", lineNumber, err)
			}
			frame, err := base64.StdEncoding.DecodeString(*line.SignedFrame)
			if err != nil || base64.StdEncoding.EncodeToString(frame) != *line.SignedFrame {
				return Head{}, fmt.Errorf("portable evidence line %d has a non-canonical signed frame", lineNumber)
			}
			receipt, current, err := verifyFrame(frame, public, nodeID, epoch, expected, previous)
			if err != nil {
				return Head{}, fmt.Errorf("verify portable evidence line %d: %w", lineNumber, err)
			}
			if !portableReceiptMatches(line, receipt, current) {
				return Head{}, fmt.Errorf("portable evidence line %d does not match its signed frame", lineNumber)
			}
			if visit != nil {
				if err := visit(VerifiedReceipt{Receipt: receipt, ChainHash: current, Frame: append([]byte(nil), frame...)}); err != nil {
					return Head{}, err
				}
			}
			previous = current
			expected++
		case "head":
			if err := validatePortableHeadShape(line); err != nil {
				return Head{}, fmt.Errorf("portable evidence line %d: %w", lineNumber, err)
			}
			derived := Head{NodeID: nodeID, Epoch: epoch, Sequence: expected - 1, ChainHash: previous, KeyID: KeyID(public)}
			if !portableHeadMatches(*line.Head, derived) {
				return Head{}, errors.New("portable evidence final head does not match its signed receipt chain")
			}
			seenHead = true
		default:
			return Head{}, fmt.Errorf("portable evidence line %d has unknown kind %q", lineNumber, *line.Kind)
		}
	}
	if !seenHead {
		return Head{}, errors.New("portable evidence is missing its final head")
	}
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		return Head{}, err
	}
	return Head{NodeID: nodeID, Epoch: epoch, Sequence: expected - 1, ChainHash: previous, KeyID: KeyID(public)}, nil
}

func validatePortableReceiptShape(line portableLine) error {
	if line.Head != nil || line.SignedFrame == nil || line.NodeID == nil || line.Epoch == nil || line.Sequence == nil ||
		line.PreviousHash == nil || line.ChainHash == nil || line.Event == nil || line.TenantID == nil ||
		line.RuntimeRef == nil || line.CapsuleDigest == nil || line.PolicyDigest == nil || line.Generation == nil ||
		line.GrantID == nil || line.Outcome == nil {
		return errors.New("receipt does not have the required portable evidence fields")
	}
	return nil
}

func validatePortableHeadShape(line portableLine) error {
	if line.Head == nil || line.SignedFrame != nil || line.NodeID != nil || line.Epoch != nil || line.Sequence != nil ||
		line.PreviousHash != nil || line.ChainHash != nil || line.Event != nil || line.TenantID != nil ||
		line.RuntimeRef != nil || line.CapsuleDigest != nil || line.PolicyDigest != nil || line.Generation != nil ||
		line.GrantID != nil || line.Outcome != nil || line.ErrorCode != nil || line.MetadataHash != nil {
		return errors.New("head contains missing or receipt-only fields")
	}
	if line.Head.NodeID == nil || line.Head.Epoch == nil || line.Head.Sequence == nil || line.Head.ChainHash == nil || line.Head.KeyID == nil {
		return errors.New("head does not have all required fields")
	}
	return nil
}

func portableReceiptMatches(line portableLine, receipt Receipt, current [sha256.Size]byte) bool {
	return *line.NodeID == receipt.NodeID && *line.Epoch == receipt.Epoch && *line.Sequence == receipt.Sequence &&
		*line.PreviousHash == formattedHash(receipt.PreviousHash) && *line.ChainHash == formattedHash(current) &&
		*line.Event == EventName(receipt.Type) && *line.TenantID == receipt.TenantID && *line.RuntimeRef == receipt.RuntimeRef &&
		*line.CapsuleDigest == receipt.CapsuleDigest && *line.PolicyDigest == receipt.PolicyDigest &&
		*line.Generation == receipt.Generation && *line.GrantID == receipt.GrantID && *line.Outcome == OutcomeName(receipt.Outcome) &&
		optionalProjectionMatches(line.ErrorCode, receipt.ErrorCode) && optionalProjectionMatches(line.MetadataHash, receipt.MetadataHash)
}

func optionalProjectionMatches(got *string, want string) bool {
	if want == "" {
		return got == nil
	}
	return got != nil && *got == want
}

func portableHeadMatches(got portableHead, want Head) bool {
	return *got.NodeID == want.NodeID && *got.Epoch == want.Epoch && *got.Sequence == want.Sequence &&
		*got.ChainHash == formattedHash(want.ChainHash) && *got.KeyID == want.KeyID
}

func formattedHash(hash [sha256.Size]byte) string {
	return "sha256:" + hex.EncodeToString(hash[:])
}

func validateInputFile(f *os.File, maxBytes int64, label string) error {
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s must be a regular file", label)
	}
	if info.Size() > maxBytes {
		return fmt.Errorf("%s exceeds %d bytes", label, maxBytes)
	}
	return nil
}

func isPortableExport(f *os.File) (bool, error) {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return false, err
	}
	var buffer [4096]byte
	for {
		n, err := f.Read(buffer[:])
		for _, value := range buffer[:n] {
			switch value {
			case ' ', '\t', '\r', '\n':
				continue
			default:
				return value == '{', nil
			}
		}
		if errors.Is(err, io.EOF) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
	}
}

func readFrame(reader io.Reader) ([]byte, error) {
	var header [4]byte
	_, err := io.ReadFull(reader, header[:])
	if errors.Is(err, io.EOF) {
		return nil, io.EOF
	}
	if err != nil {
		return nil, fmt.Errorf("read evidence frame header: %w", err)
	}
	size := binary.BigEndian.Uint32(header[:])
	if size == 0 || size > MaxEnvelopeBytes {
		return nil, errors.New("invalid evidence frame size")
	}
	raw := make([]byte, size)
	if _, err := io.ReadFull(reader, raw); err != nil {
		return nil, fmt.Errorf("read evidence frame: %w", err)
	}
	return raw, nil
}

func chainHash(previous [sha256.Size]byte, pae []byte) [sha256.Size]byte {
	hash := sha256.New()
	_, _ = hash.Write(chainDomain)
	_, _ = hash.Write(previous[:])
	_, _ = hash.Write(pae)
	var out [sha256.Size]byte
	copy(out[:], hash.Sum(nil))
	return out
}

// receipt encoding: version|node|epoch|sequence|previous|event fields. All
// strings are uint16 length-prefixed; no maps, optional fields, or JSON parser
// are involved in the signed interpretation.
func marshalReceipt(value Receipt) ([]byte, error) {
	if value.Version != receiptVersion || !validText(value.NodeID, 256) || value.Epoch == 0 || value.Sequence == 0 || value.Generation == 0 {
		return nil, errors.New("invalid receipt coordinates")
	}
	if err := validateEvent(value.Event); err != nil {
		return nil, err
	}
	buf := make([]byte, 0, 256)
	buf = append(buf, value.Version)
	buf = appendText(buf, value.NodeID)
	buf = appendUint64(buf, value.Epoch)
	buf = appendUint64(buf, value.Sequence)
	buf = append(buf, value.PreviousHash[:]...)
	buf = append(buf, byte(value.Type))
	buf = appendText(buf, value.TenantID)
	buf = appendText(buf, value.RuntimeRef)
	buf = appendText(buf, value.CapsuleDigest)
	buf = appendText(buf, value.PolicyDigest)
	buf = appendUint64(buf, value.Generation)
	buf = appendText(buf, value.GrantID)
	buf = append(buf, byte(value.Outcome))
	buf = appendText(buf, value.ErrorCode)
	buf = appendText(buf, value.MetadataHash)
	return buf, nil
}

func unmarshalReceipt(raw []byte) (Receipt, error) {
	if len(raw) < 1+2+8+8+sha256.Size+1+2+2+2+2+8+2+1+2+2 || raw[0] != receiptVersion {
		return Receipt{}, errors.New("invalid receipt version or length")
	}
	value := Receipt{Version: raw[0]}
	var ok bool
	value.NodeID, raw, ok = takeText(raw[1:])
	if !ok || len(raw) < 16+sha256.Size+1 {
		return Receipt{}, errors.New("invalid receipt node id")
	}
	value.Epoch = binary.BigEndian.Uint64(raw[:8])
	value.Sequence = binary.BigEndian.Uint64(raw[8:16])
	copy(value.PreviousHash[:], raw[16:16+sha256.Size])
	value.Type = EventType(raw[16+sha256.Size])
	raw = raw[17+sha256.Size:]
	fields := []*string{&value.TenantID, &value.RuntimeRef, &value.CapsuleDigest, &value.PolicyDigest}
	for _, field := range fields {
		*field, raw, ok = takeText(raw)
		if !ok {
			return Receipt{}, errors.New("invalid receipt text field")
		}
	}
	if len(raw) < 8 {
		return Receipt{}, errors.New("invalid receipt generation")
	}
	value.Generation = binary.BigEndian.Uint64(raw[:8])
	value.GrantID, raw, ok = takeText(raw[8:])
	if !ok || len(raw) < 1 {
		return Receipt{}, errors.New("invalid receipt grant id")
	}
	value.Outcome = Outcome(raw[0])
	value.ErrorCode, raw, ok = takeOptionalText(raw[1:])
	if !ok {
		return Receipt{}, errors.New("invalid receipt error code")
	}
	value.MetadataHash, raw, ok = takeOptionalText(raw)
	if !ok || len(raw) != 0 {
		return Receipt{}, errors.New("invalid receipt metadata hash")
	}
	if _, err := marshalReceipt(value); err != nil {
		return Receipt{}, err
	}
	return value, nil
}

// envelope encoding: version|payload type|payload|key id|signature.
func marshalEnvelope(value Envelope) ([]byte, error) {
	if value.Version != envelopeVersion || value.PayloadType != PayloadType || !validText(value.KeyID, 128) ||
		len(value.Payload) == 0 || len(value.Payload) > MaxEnvelopeBytes || len(value.Signature) != ed25519.SignatureSize {
		return nil, errors.New("invalid evidence envelope")
	}
	buf := make([]byte, 0, len(value.Payload)+len(value.Signature)+128)
	buf = append(buf, value.Version)
	buf = appendText(buf, value.PayloadType)
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(value.Payload)))
	buf = append(buf, length[:]...)
	buf = append(buf, value.Payload...)
	buf = appendText(buf, value.KeyID)
	buf = append(buf, value.Signature...)
	return buf, nil
}

func unmarshalEnvelope(raw []byte) (Envelope, error) {
	if len(raw) < 1+2+4+2+ed25519.SignatureSize || raw[0] != envelopeVersion {
		return Envelope{}, errors.New("invalid evidence envelope version or length")
	}
	value := Envelope{Version: raw[0]}
	var ok bool
	value.PayloadType, raw, ok = takeText(raw[1:])
	if !ok || len(raw) < 4 {
		return Envelope{}, errors.New("invalid evidence payload type")
	}
	length := int(binary.BigEndian.Uint32(raw[:4]))
	raw = raw[4:]
	if length == 0 || length > MaxEnvelopeBytes || len(raw) < length+2+ed25519.SignatureSize {
		return Envelope{}, errors.New("invalid evidence payload length")
	}
	value.Payload = append([]byte(nil), raw[:length]...)
	value.KeyID, raw, ok = takeText(raw[length:])
	if !ok || len(raw) != ed25519.SignatureSize {
		return Envelope{}, errors.New("invalid evidence key id or signature")
	}
	value.Signature = append([]byte(nil), raw...)
	if _, err := marshalEnvelope(value); err != nil {
		return Envelope{}, err
	}
	return value, nil
}

func validateEvent(value Event) error {
	if !validEvent(value.Type) || !validOutcome(value.Outcome) || value.Generation == 0 ||
		!validText(value.TenantID, 128) || !validText(value.RuntimeRef, 512) ||
		!validText(value.CapsuleDigest, 128) || !validText(value.PolicyDigest, 128) ||
		!validText(value.GrantID, 256) || !validOptionalText(value.ErrorCode, 128) || !validOptionalText(value.MetadataHash, 128) {
		return errors.New("invalid bounded evidence event")
	}
	return nil
}

func validEvent(value EventType) bool { return value >= AdmissionAllow && value <= Revocation }
func validOutcome(value Outcome) bool { return value >= Allowed && value <= Compensated }

func appendUint64(dst []byte, value uint64) []byte {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	return append(dst, encoded[:]...)
}

func appendText(dst []byte, value string) []byte {
	var length [2]byte
	binary.BigEndian.PutUint16(length[:], uint16(len(value)))
	dst = append(dst, length[:]...)
	return append(dst, value...)
}

func takeText(raw []byte) (string, []byte, bool) {
	if len(raw) < 2 {
		return "", nil, false
	}
	length := int(binary.BigEndian.Uint16(raw[:2]))
	if length == 0 || len(raw) < 2+length {
		return "", nil, false
	}
	value := string(raw[2 : 2+length])
	return value, raw[2+length:], validText(value, 512)
}

func takeOptionalText(raw []byte) (string, []byte, bool) {
	if len(raw) < 2 {
		return "", nil, false
	}
	length := int(binary.BigEndian.Uint16(raw[:2]))
	if len(raw) < 2+length {
		return "", nil, false
	}
	value := string(raw[2 : 2+length])
	return value, raw[2+length:], validOptionalText(value, 512)
}

func validText(value string, limit int) bool {
	return value != "" && validOptionalText(value, limit)
}

func validOptionalText(value string, limit int) bool {
	return len(value) <= limit && utf8.ValidString(value) && !strings.ContainsRune(value, '\x00')
}

func writeAll(f *os.File, raw []byte) error {
	for len(raw) > 0 {
		n, err := f.Write(raw)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		raw = raw[n:]
	}
	return nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
