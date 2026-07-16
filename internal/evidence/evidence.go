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
	"syscall"
	"unicode/utf8"

	"github.com/hardrails/steward/internal/dsse"
)

const (
	PayloadType      = "application/vnd.steward.receipt.v1+binary"
	ExportFormat     = "application/vnd.steward.evidence-export.v1+ndjson"
	MaxEnvelopeBytes = 64 << 10
	MaxDeltaRecords  = 128
	MaxDeltaBytes    = 700 << 10
	MaxLogBytes      = 64 << 20
	maxExportBytes   = 256 << 20
	maxExportLine    = 128 << 10
	receiptVersionV1 = 1
	receiptVersionV2 = 2
	envelopeVersion  = 1
	checkpointStride = MaxDeltaRecords
	// A valid frame is at least five bytes. This cap is therefore looser than
	// the number of sparse checkpoints that can fit in a bounded valid log.
	maxCheckpointCount = MaxLogBytes/(5*checkpointStride) + 2
)

var chainDomain = []byte("steward-evidence-chain-v1\x00")

// ErrDeltaCoordinate means an externally retained coordinate is valid in
// shape but is not the same coordinate in this local log. Callers may use a
// separately authenticated local head to report rollback or a fork. Other
// export errors, especially I/O failures, must not be treated as divergence.
var ErrDeltaCoordinate = errors.New("evidence delta coordinate does not match the local log")

// ErrActivationMarkerConflict means an idempotent begin/checkpoint request
// disagrees with the activation identity already retained in the signed log.
var ErrActivationMarkerConflict = errors.New("activation marker conflicts with retained evidence")

// EventType is deliberately a closed receipt vocabulary. New decisions require
// an explicit format version/change rather than arbitrary event strings.
type EventType byte

const (
	AdmissionAllow       EventType = 1
	AdmissionDeny        EventType = 2
	JournalPrepare       EventType = 3
	JournalCommit        EventType = 4
	JournalCompensate    EventType = 5
	GatewayRegistration  EventType = 6
	InferenceAuthorize   EventType = 7
	InferenceTerminal    EventType = 8
	ServiceMapping       EventType = 9
	LifecycleStart       EventType = 10
	LifecycleStop        EventType = 11
	LifecycleDestroy     EventType = 12
	StatePurge           EventType = 13
	PolicyReload         EventType = 14
	Drift                EventType = 15
	Revocation           EventType = 16
	ActivationBegin      EventType = 17
	ActivationCheckpoint EventType = 18
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
// coordinate when no newer receipt exists. More reports whether the verified
// local head still has receipts after Head.
type Delta struct {
	Frames [][]byte
	Head   Head
	More   bool
}

// FormatSummary reports the highest semantic receipt version observed in an
// existing evidence log. A log may contain both version 1 ordinary receipts
// and version 2 activation markers in one signed chain. Empty logs contain no
// receipt header, so FormatVersion is zero. This is a structural, read-only
// compatibility check; callers that need authenticity must also verify the
// chain with its public key through OpenForValidation or VerifyRecords.
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
	mu                    sync.Mutex
	path                  string
	file                  *os.File
	private               ed25519.PrivateKey
	public                ed25519.PublicKey
	readOnly              bool
	nodeID                string
	epoch                 uint64
	keyID                 string
	next                  uint64
	lastHash              [sha256.Size]byte
	logBytes              int64
	modTimeNano           int64
	checkpoints           []logCheckpoint
	activationBegins      map[activationMarkerKey]activationMarker
	activationCheckpoints map[activationMarkerKey]activationMarker
}

type activationMarkerKey struct {
	TenantID   string
	RuntimeRef string
	Generation uint64
}

type activationMarker struct {
	ActivationID  string
	CapsuleDigest string
	PolicyDigest  string
	Digest        string
	Receipt       Receipt
}

// logCheckpoint is created only from a fully verified receipt or a successful
// fsynced append. Offset is the byte immediately after Sequence, so an export
// can verify forward from ChainHash without replaying the complete prefix.
type logCheckpoint struct {
	Sequence  uint64
	ChainHash [sha256.Size]byte
	Offset    int64
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
	f, created, err := openEvidenceForAppend(path)
	if err != nil {
		return nil, err
	}
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return nil, err
	}
	openedInfo, err := validateEvidencePathFile(path, f)
	if err != nil {
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
	next, last, checkpoints, logBytes, err := verifyFileWithIndex(f, public, nodeID, epoch)
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("verify evidence %q: %w", path, err)
	}
	begins, activationCheckpoints, err := verifyActivationMarkers(
		f, public, nodeID, epoch,
	)
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("verify activation markers in evidence %q: %w", path, err)
	}
	verifiedInfo, err := validateEvidencePathFile(path, f)
	if err != nil || verifiedInfo.Size() != logBytes ||
		verifiedInfo.Size() != openedInfo.Size() || !verifiedInfo.ModTime().Equal(openedInfo.ModTime()) {
		_ = f.Close()
		return nil, fmt.Errorf("evidence %q changed while its verified index was built", path)
	}
	return &Log{path: path, file: f, private: private, public: append(ed25519.PublicKey(nil), public...), nodeID: nodeID, epoch: epoch,
		keyID: KeyID(public), next: next, lastHash: last, logBytes: logBytes,
		modTimeNano: verifiedInfo.ModTime().UnixNano(), checkpoints: checkpoints,
		activationBegins: begins, activationCheckpoints: activationCheckpoints}, nil
}

func openEvidenceForAppend(path string) (*os.File, bool, error) {
	return openEvidenceForAppendAfterMissing(path, nil)
}

func openEvidenceForAppendAfterMissing(path string, afterMissing func()) (*os.File, bool, error) {
	const maxAttempts = 3
	for attempt := 0; attempt < maxAttempts; attempt++ {
		before, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			if afterMissing != nil {
				afterMissing()
				afterMissing = nil
			}
			file, openErr := openEvidenceDescriptor(path,
				syscall.O_RDWR|syscall.O_APPEND|syscall.O_CREAT|syscall.O_EXCL, 0o600)
			if errors.Is(openErr, syscall.EEXIST) {
				continue
			}
			if openErr != nil {
				return nil, false, fmt.Errorf("create evidence %q exclusively: %w", path, openErr)
			}
			if lockErr := lockEvidenceWriter(file); lockErr != nil {
				_ = file.Close()
				return nil, false, lockErr
			}
			if _, validateErr := validateEvidencePathFile(path, file); validateErr != nil {
				_ = file.Close()
				return nil, false, validateErr
			}
			return file, true, nil
		}
		if err != nil {
			return nil, false, fmt.Errorf("stat evidence %q: %w", path, err)
		}
		if !before.Mode().IsRegular() || before.Mode().Perm()&0o077 != 0 {
			return nil, false, fmt.Errorf("evidence %q must be a regular file with mode 0600 or stricter", path)
		}
		if before.Size() > MaxLogBytes {
			return nil, false, fmt.Errorf("evidence %q exceeds %d bytes", path, MaxLogBytes)
		}
		file, openErr := openEvidenceDescriptor(path, syscall.O_RDWR|syscall.O_APPEND, 0)
		if errors.Is(openErr, syscall.ENOENT) {
			continue
		}
		if openErr != nil {
			return nil, false, fmt.Errorf("open evidence %q: %w", path, openErr)
		}
		if lockErr := lockEvidenceWriter(file); lockErr != nil {
			_ = file.Close()
			return nil, false, lockErr
		}
		opened, validateErr := validateEvidencePathFile(path, file)
		if validateErr != nil || !os.SameFile(before, opened) {
			_ = file.Close()
			if validateErr != nil {
				return nil, false, validateErr
			}
			return nil, false, fmt.Errorf("evidence %q changed while it was opened", path)
		}
		return file, false, nil
	}
	return nil, false, fmt.Errorf("evidence %q changed repeatedly while it was opened", path)
}

func openEvidenceDescriptor(path string, flags int, mode uint32) (*os.File, error) {
	fd, err := syscall.Open(path, flags|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, mode)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, errors.New("open evidence returned an invalid descriptor")
	}
	return file, nil
}

func lockEvidenceWriter(file *os.File) error {
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return errors.New("evidence log is already open by another writer")
		}
		return fmt.Errorf("lock evidence log: %w", err)
	}
	return nil
}

func validateEvidencePathFile(path string, file *os.File) (os.FileInfo, error) {
	opened, err := file.Stat()
	if err != nil {
		return nil, err
	}
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("stat evidence path %q: %w", path, err)
	}
	if !opened.Mode().IsRegular() || !pathInfo.Mode().IsRegular() ||
		opened.Mode().Perm()&0o077 != 0 || pathInfo.Mode().Perm()&0o077 != 0 ||
		opened.Size() > MaxLogBytes || pathInfo.Size() > MaxLogBytes {
		return nil, fmt.Errorf("evidence %q must remain a bounded regular file with mode 0600 or stricter", path)
	}
	if !os.SameFile(pathInfo, opened) {
		return nil, fmt.Errorf("evidence path %q no longer names the opened log", path)
	}
	if pathInfo.Mode() != opened.Mode() || pathInfo.Size() != opened.Size() ||
		!pathInfo.ModTime().Equal(opened.ModTime()) {
		return nil, fmt.Errorf("evidence path %q changed while its descriptor was inspected", path)
	}
	return opened, nil
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
	if info.Size() > MaxLogBytes {
		return nil, fmt.Errorf("evidence %q exceeds %d bytes", path, MaxLogBytes)
	}
	f, err := openEvidenceDescriptor(path, syscall.O_RDONLY, 0)
	if err != nil {
		return nil, fmt.Errorf("open evidence %q for validation: %w", path, err)
	}
	openedInfo, err := validateEvidencePathFile(path, f)
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("stat opened evidence %q: %w", path, err)
	}
	if !os.SameFile(info, openedInfo) {
		_ = f.Close()
		return nil, fmt.Errorf("evidence %q changed while it was opened for validation", path)
	}
	next, last, checkpoints, logBytes, err := verifyFileWithIndex(f, public, nodeID, epoch)
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("verify evidence %q: %w", path, err)
	}
	verifiedInfo, err := validateEvidencePathFile(path, f)
	if err != nil || verifiedInfo.Size() != logBytes ||
		verifiedInfo.Size() != openedInfo.Size() || !verifiedInfo.ModTime().Equal(openedInfo.ModTime()) {
		_ = f.Close()
		return nil, fmt.Errorf("evidence %q changed while its verified index was built", path)
	}
	return &Log{path: path, file: f, public: append(ed25519.PublicKey(nil), public...), readOnly: true,
		nodeID: nodeID, epoch: epoch, keyID: KeyID(public), next: next, lastHash: last,
		logBytes: logBytes, modTimeNano: verifiedInfo.ModTime().UnixNano(), checkpoints: checkpoints}, nil
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
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() > MaxLogBytes {
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
	if !os.SameFile(info, openedInfo) || !openedInfo.Mode().IsRegular() || openedInfo.Mode().Perm()&0o077 != 0 || openedInfo.Size() > MaxLogBytes {
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
		if int(receipt.Version) > summary.FormatVersion {
			summary.FormatVersion = int(receipt.Version)
		}
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
	if err := validateInputFile(f, MaxLogBytes, "evidence log"); err != nil {
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
	if err := validateInputFile(f, MaxLogBytes, "evidence log"); err != nil {
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
	return VerifyDeltaRecords(frames, public, nodeID, epoch, prior, tenantMember, nil)
}

// VerifyDeltaRecords applies the same bounded delta verification as
// VerifyDelta and visits each authenticated receipt only after its tenant and
// chain coordinates have been accepted. Frame is an independent copy of the
// exact signed frame supplied by the caller.
func VerifyDeltaRecords(
	frames [][]byte,
	public ed25519.PublicKey,
	nodeID string,
	epoch uint64,
	prior Coordinate,
	tenantMember func(string) bool,
	visit func(VerifiedReceipt) error,
) (Head, error) {
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
		if visit != nil {
			if err := visit(VerifiedReceipt{
				Receipt: receipt, ChainHash: current,
				Frame: append([]byte(nil), frame...),
			}); err != nil {
				return Head{}, err
			}
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
		if info.Size() > MaxLogBytes {
			return Head{}, fmt.Errorf("evidence log exceeds %d bytes", MaxLogBytes)
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
	case ActivationBegin:
		return "activation_begin"
	case ActivationCheckpoint:
		return "activation_checkpoint"
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
	if event.Type == ActivationBegin ||
		event.Type == ActivationCheckpoint {
		return Receipt{}, errors.New("activation markers require their idempotent append methods")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.appendLocked(event)
}

// AppendActivationBegin records at most one activation identity for a fresh
// tenant/runtime/generation tuple. Exact retries return the original receipt;
// a different identity or digest fails closed without growing the global log.
func (l *Log) AppendActivationBegin(event Event) (Receipt, error) {
	return l.appendActivationMarker(event, ActivationBegin)
}

// AppendActivationCheckpoint records at most one terminal checkpoint for the
// activation established by AppendActivationBegin. Exact retries are
// idempotent; unknown activations and conflicting digests are rejected.
func (l *Log) AppendActivationCheckpoint(event Event) (Receipt, error) {
	return l.appendActivationMarker(event, ActivationCheckpoint)
}

func (l *Log) appendActivationMarker(
	event Event,
	expected EventType,
) (Receipt, error) {
	if err := validateEvent(event); err != nil {
		return Receipt{}, err
	}
	if event.Type != expected {
		return Receipt{}, errors.New("activation marker uses the wrong event type")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil {
		return Receipt{}, errors.New("evidence log is closed")
	}
	if l.readOnly {
		return Receipt{}, errors.New("evidence log is open for validation only")
	}
	if err := l.validateFileStateLocked(); err != nil {
		return Receipt{}, l.failClosedLocked(err)
	}
	if _, err := l.verifyTailLocked(); err != nil {
		return Receipt{}, l.failClosedLocked(err)
	}
	key := activationMarkerKey{
		TenantID: event.TenantID, RuntimeRef: event.RuntimeRef,
		Generation: event.Generation,
	}
	candidate := activationMarker{
		ActivationID:  event.GrantID,
		CapsuleDigest: event.CapsuleDigest,
		PolicyDigest:  event.PolicyDigest,
		Digest:        event.MetadataHash,
	}
	if expected == ActivationBegin {
		if event.Outcome != Allowed || event.ErrorCode != "" ||
			event.MetadataHash == "" {
			return Receipt{}, errors.New("activation begin has invalid closed semantics")
		}
		if existing, ok := l.activationBegins[key]; ok {
			if existing.ActivationID == candidate.ActivationID &&
				existing.CapsuleDigest == candidate.CapsuleDigest &&
				existing.PolicyDigest == candidate.PolicyDigest &&
				existing.Digest == candidate.Digest {
				return existing.Receipt, nil
			}
			return Receipt{}, fmt.Errorf("%w: activation begin disagrees with the retained fresh admission identity", ErrActivationMarkerConflict)
		}
	} else {
		begin, ok := l.activationBegins[key]
		if !ok || begin.ActivationID != candidate.ActivationID ||
			begin.CapsuleDigest != candidate.CapsuleDigest ||
			begin.PolicyDigest != candidate.PolicyDigest {
			return Receipt{}, fmt.Errorf("%w: activation checkpoint has no matching fresh admission identity", ErrActivationMarkerConflict)
		}
		if event.Outcome != Committed || event.ErrorCode != "" ||
			event.MetadataHash == "" {
			return Receipt{}, errors.New("activation checkpoint has invalid closed semantics")
		}
		if existing, ok := l.activationCheckpoints[key]; ok {
			if existing.ActivationID == candidate.ActivationID &&
				existing.CapsuleDigest == candidate.CapsuleDigest &&
				existing.PolicyDigest == candidate.PolicyDigest &&
				existing.Digest == candidate.Digest {
				return existing.Receipt, nil
			}
			return Receipt{}, fmt.Errorf("%w: activation checkpoint disagrees with the retained activation identity", ErrActivationMarkerConflict)
		}
	}
	receipt, err := l.appendLocked(event)
	if err != nil {
		return Receipt{}, err
	}
	candidate.Receipt = receipt
	if expected == ActivationBegin {
		l.activationBegins[key] = candidate
	} else {
		l.activationCheckpoints[key] = candidate
	}
	return receipt, nil
}

func (l *Log) appendLocked(event Event) (Receipt, error) {
	if l.file == nil {
		return Receipt{}, errors.New("evidence log is closed")
	}
	if l.readOnly {
		return Receipt{}, errors.New("evidence log is open for validation only")
	}
	if err := l.validateFileStateLocked(); err != nil {
		return Receipt{}, l.failClosedLocked(err)
	}
	if _, err := l.verifyTailLocked(); err != nil {
		return Receipt{}, l.failClosedLocked(err)
	}
	receipt := Receipt{Version: receiptVersionForEvent(event.Type), NodeID: l.nodeID, Epoch: l.epoch,
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
	frameSize := int64(4 + len(raw))
	if l.logBytes > MaxLogBytes-frameSize {
		return Receipt{}, errors.New("evidence log would exceed size limit")
	}
	if receipt.Sequence%checkpointStride == 0 && len(l.checkpoints) >= maxCheckpointCount {
		return Receipt{}, errors.New("evidence checkpoint index would exceed its bound")
	}
	expectedBytes := l.logBytes + frameSize
	current := chainHash(receipt.PreviousHash, pae)
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(raw)))
	if err := writeAll(l.file, header[:]); err != nil {
		return Receipt{}, l.failClosedLocked(err)
	}
	if err := writeAll(l.file, raw); err != nil {
		return Receipt{}, l.failClosedLocked(err)
	}
	if err := l.file.Sync(); err != nil {
		return Receipt{}, l.failClosedLocked(err)
	}
	info, err := validateEvidencePathFile(l.path, l.file)
	if err != nil {
		return Receipt{}, l.failClosedLocked(err)
	}
	if info.Size() != expectedBytes {
		return Receipt{}, l.failClosedLocked(errors.New("evidence log changed during append"))
	}
	l.lastHash = current
	l.next++
	l.logBytes = expectedBytes
	l.modTimeNano = info.ModTime().UnixNano()
	if receipt.Sequence%checkpointStride == 0 {
		l.checkpoints = append(l.checkpoints, logCheckpoint{
			Sequence: receipt.Sequence, ChainHash: current, Offset: expectedBytes,
		})
	}
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

// CurrentHead returns the exact compact head authenticated by the full scan at
// open, each fsynced append, and a bounded replay of the final sparse segment.
// Older segments are fully reverified on reopen; a live handle relies on its
// exclusive writer lock and path/metadata continuity within the documented
// node trust boundary. Unlike ExportDelta, the head describes the whole local
// chain rather than the end of one bounded batch. An evidence publisher uses
// this snapshot to prove rollback when a retained controller checkpoint is no
// longer present in the local log.
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
	if err := l.validateFileStateLocked(); err != nil {
		return Head{}, l.failClosedLocked(err)
	}
	if _, err := l.verifyTailLocked(); err != nil {
		return Head{}, l.failClosedLocked(err)
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
	result, _, err := l.exportDelta(after)
	return result, err
}

// exportDelta also returns how many frames were authenticated from the nearest
// sparse checkpoint. Tests use this count to hold the bounded-scan invariant;
// callers use ExportDelta.
func (l *Log) exportDelta(after Coordinate) (Delta, int, error) {
	if err := validateCoordinate(after); err != nil {
		return Delta{}, 0, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil {
		return Delta{}, 0, errors.New("evidence log is closed")
	}
	if err := l.validateFileStateLocked(); err != nil {
		return Delta{}, 0, l.failClosedLocked(err)
	}

	result := Delta{Head: Head{
		NodeID: l.nodeID, Epoch: l.epoch, Sequence: after.Sequence,
		ChainHash: after.ChainHash, KeyID: l.keyID,
	}}
	localSequence := l.next - 1
	if after.Sequence > localSequence {
		return Delta{}, 0, ErrDeltaCoordinate
	}
	if after.Sequence == localSequence {
		if after.ChainHash != l.lastHash {
			return Delta{}, 0, ErrDeltaCoordinate
		}
		scannedRecords, err := l.verifyTailLocked()
		if err != nil {
			return Delta{}, scannedRecords, l.failClosedLocked(err)
		}
		result.Head.ChainHash = l.lastHash
		return result, scannedRecords, nil
	}

	checkpointIndex := after.Sequence / checkpointStride
	if checkpointIndex >= uint64(len(l.checkpoints)) {
		return Delta{}, 0, l.failClosedLocked(errors.New("evidence checkpoint index is inconsistent with the verified log"))
	}
	checkpoint := l.checkpoints[int(checkpointIndex)]
	if checkpoint.Sequence != checkpointIndex*checkpointStride || checkpoint.Sequence > after.Sequence ||
		checkpoint.Offset < 0 || checkpoint.Offset > l.logBytes {
		return Delta{}, 0, l.failClosedLocked(errors.New("evidence checkpoint index contains an invalid entry"))
	}
	if checkpoint.Sequence == after.Sequence && checkpoint.ChainHash != after.ChainHash {
		return Delta{}, 0, ErrDeltaCoordinate
	}
	if _, err := l.file.Seek(checkpoint.Offset, io.SeekStart); err != nil {
		return Delta{}, 0, l.failClosedLocked(err)
	}

	found := checkpoint.Sequence == after.Sequence
	previous := checkpoint.ChainHash
	expected := checkpoint.Sequence + 1
	scannedRecords := 0
	scannedBytes := checkpoint.Offset
	total := 0
	for expected <= localSequence {
		if found && len(result.Frames) == MaxDeltaRecords {
			break
		}
		raw, err := readFrame(l.file)
		if err != nil {
			if errors.Is(err, io.EOF) {
				err = errors.New("evidence log ended before its verified head")
			}
			return Delta{}, scannedRecords, l.failClosedLocked(err)
		}
		scannedRecords++
		scannedBytes += int64(4 + len(raw))
		if scannedBytes > l.logBytes || scannedBytes > MaxLogBytes {
			err := fmt.Errorf("evidence log exceeds its verified %d-byte boundary", l.logBytes)
			return Delta{}, scannedRecords, l.failClosedLocked(err)
		}
		receipt, current, err := verifyEnvelope(raw, l.public, l.nodeID, l.epoch, expected, previous)
		if err != nil {
			return Delta{}, scannedRecords, l.failClosedLocked(err)
		}
		previous = current
		expected++

		if receipt.Sequence <= after.Sequence {
			if receipt.Sequence == after.Sequence {
				if current != after.ChainHash {
					return Delta{}, scannedRecords, ErrDeltaCoordinate
				}
				found = true
			}
			continue
		}
		if !found {
			return Delta{}, scannedRecords, ErrDeltaCoordinate
		}
		frame := frameBytes(raw)
		if total > MaxDeltaBytes-len(frame) {
			break
		}
		result.Frames = append(result.Frames, frame)
		total += len(frame)
		result.Head.Sequence = receipt.Sequence
		result.Head.ChainHash = current
	}
	if !found {
		return Delta{}, scannedRecords, l.failClosedLocked(errors.New("evidence checkpoint replay did not reach the requested coordinate"))
	}
	result.More = result.Head.Sequence < localSequence
	return result, scannedRecords, nil
}

func (l *Log) verifyTailLocked() (int, error) {
	localSequence := l.next - 1
	if localSequence == 0 {
		if l.logBytes != 0 || len(l.checkpoints) != 1 {
			return 0, errors.New("empty evidence log has inconsistent verified state")
		}
		return 0, nil
	}
	checkpointIndex := (localSequence - 1) / checkpointStride
	if checkpointIndex >= uint64(len(l.checkpoints)) {
		return 0, errors.New("evidence tail checkpoint is missing")
	}
	checkpoint := l.checkpoints[int(checkpointIndex)]
	if checkpoint.Sequence != checkpointIndex*checkpointStride ||
		checkpoint.Offset < 0 || checkpoint.Offset > l.logBytes {
		return 0, errors.New("evidence tail checkpoint is invalid")
	}
	if _, err := l.file.Seek(checkpoint.Offset, io.SeekStart); err != nil {
		return 0, err
	}
	previous := checkpoint.ChainHash
	expected := checkpoint.Sequence + 1
	offset := checkpoint.Offset
	scannedRecords := 0
	for expected <= localSequence {
		raw, err := readFrame(l.file)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return scannedRecords, errors.New("evidence tail ended before its verified head")
			}
			return scannedRecords, err
		}
		scannedRecords++
		offset += int64(4 + len(raw))
		if offset > l.logBytes || offset > MaxLogBytes {
			return scannedRecords, errors.New("evidence tail exceeds its verified byte boundary")
		}
		_, current, err := verifyEnvelope(raw, l.public, l.nodeID, l.epoch, expected, previous)
		if err != nil {
			return scannedRecords, err
		}
		previous = current
		expected++
	}
	if offset != l.logBytes || previous != l.lastHash {
		return scannedRecords, errors.New("evidence tail does not match its verified head")
	}
	return scannedRecords, nil
}

func (l *Log) validateFileStateLocked() error {
	info, err := validateEvidencePathFile(l.path, l.file)
	if err != nil {
		return err
	}
	if info.Size() != l.logBytes || info.ModTime().UnixNano() != l.modTimeNano {
		return errors.New("evidence log changed outside its append lock")
	}
	return nil
}

func (l *Log) failClosedLocked(cause error) error {
	if l.file == nil {
		return cause
	}
	closeErr := l.file.Close()
	l.file = nil
	return errors.Join(cause, closeErr)
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

func verifyFileWithIndex(
	f *os.File,
	public ed25519.PublicKey,
	nodeID string,
	epoch uint64,
) (uint64, [sha256.Size]byte, []logCheckpoint, int64, error) {
	next, last, _, checkpoints, total, err := verifyFileState(f, public, nodeID, epoch, nil, true)
	return next, last, checkpoints, total, err
}

func verifyFileWithLast(f *os.File, public ed25519.PublicKey, nodeID string, epoch uint64) (uint64, [sha256.Size]byte, *Receipt, error) {
	return verifyFileWithVisitor(f, public, nodeID, epoch, nil)
}

func verifyFileWithVisitor(f *os.File, public ed25519.PublicKey, nodeID string, epoch uint64, visit func(VerifiedReceipt) error) (uint64, [sha256.Size]byte, *Receipt, error) {
	next, previous, last, _, _, err := verifyFileState(f, public, nodeID, epoch, visit, false)
	return next, previous, last, err
}

func verifyActivationMarkers(
	f *os.File,
	public ed25519.PublicKey,
	nodeID string,
	epoch uint64,
) (
	map[activationMarkerKey]activationMarker,
	map[activationMarkerKey]activationMarker,
	error,
) {
	begins := make(map[activationMarkerKey]activationMarker)
	checkpoints := make(map[activationMarkerKey]activationMarker)
	_, _, _, err := verifyFileWithVisitor(
		f, public, nodeID, epoch,
		func(record VerifiedReceipt) error {
			return applyActivationMarker(
				begins, checkpoints, record.Receipt,
			)
		},
	)
	if err != nil {
		return nil, nil, err
	}
	return begins, checkpoints, nil
}

func applyActivationMarker(
	begins map[activationMarkerKey]activationMarker,
	checkpoints map[activationMarkerKey]activationMarker,
	receipt Receipt,
) error {
	if receipt.Type != ActivationBegin &&
		receipt.Type != ActivationCheckpoint {
		return nil
	}
	key := activationMarkerKey{
		TenantID: receipt.TenantID, RuntimeRef: receipt.RuntimeRef,
		Generation: receipt.Generation,
	}
	marker := activationMarker{
		ActivationID:  receipt.GrantID,
		CapsuleDigest: receipt.CapsuleDigest,
		PolicyDigest:  receipt.PolicyDigest,
		Digest:        receipt.MetadataHash,
		Receipt:       receipt,
	}
	if receipt.Type == ActivationBegin {
		if receipt.Outcome != Allowed || receipt.ErrorCode != "" ||
			receipt.MetadataHash == "" {
			return errors.New("activation begin receipt has invalid closed semantics")
		}
		if existing, ok := begins[key]; ok {
			if existing.ActivationID == marker.ActivationID &&
				existing.CapsuleDigest == marker.CapsuleDigest &&
				existing.PolicyDigest == marker.PolicyDigest &&
				existing.Digest == marker.Digest {
				return errors.New("evidence contains duplicate activation begin markers")
			}
			return errors.New("evidence contains conflicting activation begin markers")
		}
		begins[key] = marker
		return nil
	}
	begin, ok := begins[key]
	if !ok || begin.ActivationID != marker.ActivationID ||
		begin.CapsuleDigest != marker.CapsuleDigest ||
		begin.PolicyDigest != marker.PolicyDigest {
		return errors.New("activation checkpoint has no matching activation begin")
	}
	if receipt.Outcome != Committed || receipt.ErrorCode != "" ||
		receipt.MetadataHash == "" {
		return errors.New("activation checkpoint receipt has invalid closed semantics")
	}
	if existing, ok := checkpoints[key]; ok {
		if existing.ActivationID == marker.ActivationID &&
			existing.CapsuleDigest == marker.CapsuleDigest &&
			existing.PolicyDigest == marker.PolicyDigest &&
			existing.Digest == marker.Digest {
			return errors.New("evidence contains duplicate activation checkpoints")
		}
		return errors.New("evidence contains conflicting activation checkpoints")
	}
	checkpoints[key] = marker
	return nil
}

func verifyFileState(
	f *os.File,
	public ed25519.PublicKey,
	nodeID string,
	epoch uint64,
	visit func(VerifiedReceipt) error,
	buildIndex bool,
) (uint64, [sha256.Size]byte, *Receipt, []logCheckpoint, int64, error) {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return 0, [sha256.Size]byte{}, nil, nil, 0, err
	}
	var previous [sha256.Size]byte
	var expected uint64 = 1
	var last *Receipt
	var total int64
	var checkpoints []logCheckpoint
	if buildIndex {
		checkpoints = append(checkpoints, logCheckpoint{})
	}
	for {
		raw, err := readFrame(f)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return 0, [sha256.Size]byte{}, nil, nil, 0, err
		}
		total += int64(4 + len(raw))
		if total > MaxLogBytes {
			return 0, [sha256.Size]byte{}, nil, nil, 0, fmt.Errorf("evidence log exceeds %d bytes", MaxLogBytes)
		}
		receipt, current, err := verifyEnvelope(raw, public, nodeID, epoch, expected, previous)
		if err != nil {
			return 0, [sha256.Size]byte{}, nil, nil, 0, err
		}
		previous = current
		if buildIndex && receipt.Sequence%checkpointStride == 0 {
			if len(checkpoints) >= maxCheckpointCount {
				return 0, [sha256.Size]byte{}, nil, nil, 0, errors.New("evidence checkpoint index exceeds its bound")
			}
			checkpoints = append(checkpoints, logCheckpoint{
				Sequence: receipt.Sequence, ChainHash: current, Offset: total,
			})
		}
		if visit != nil {
			if err := visit(VerifiedReceipt{Receipt: receipt, ChainHash: previous, Frame: frameBytes(raw)}); err != nil {
				return 0, [sha256.Size]byte{}, nil, nil, 0, err
			}
		}
		copyReceipt := receipt
		last = &copyReceipt
		expected++
	}
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		return 0, [sha256.Size]byte{}, nil, nil, 0, err
	}
	return expected, previous, last, checkpoints, total, nil
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
	if !validReceiptVersionForEvent(value.Version, value.Type) {
		return nil, errors.New("receipt format version does not match its closed event vocabulary")
	}
	if !validText(value.NodeID, 256) || value.Epoch == 0 ||
		value.Sequence == 0 || value.Generation == 0 {
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
	if len(raw) < 1+2+8+8+sha256.Size+1+2+2+2+2+8+2+1+2+2 ||
		(raw[0] != receiptVersionV1 && raw[0] != receiptVersionV2) {
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

func validEvent(value EventType) bool {
	return value >= AdmissionAllow && value <= ActivationCheckpoint
}
func validOutcome(value Outcome) bool { return value >= Allowed && value <= Compensated }

// Format 2 keeps the binary layout but extends the closed vocabulary with
// activation markers. Keeping ordinary events at format 1 avoids pretending
// that their signed meaning changed, while the higher marker version makes an
// older reader visibly ineligible for rollback.
func receiptVersionForEvent(value EventType) byte {
	if value == ActivationBegin || value == ActivationCheckpoint {
		return receiptVersionV2
	}
	return receiptVersionV1
}

func validReceiptVersionForEvent(version byte, event EventType) bool {
	return version == receiptVersionForEvent(event)
}

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
