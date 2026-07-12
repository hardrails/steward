// Package evidence maintains a locally verifiable, append-only receipt chain.
// It uses exact binary payloads and framed envelopes so verification never relies
// on JSON canonicalization or permissive duplicate-field handling.
package evidence

import (
	"crypto/ed25519"
	"crypto/sha256"
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
)

const (
	PayloadType      = "application/vnd.steward.receipt.v1+binary"
	MaxEnvelopeBytes = 64 << 10
	maxLogBytes      = 64 << 20
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
	return &Log{path: path, file: f, private: private, nodeID: nodeID, epoch: epoch,
		keyID: KeyID(public), next: next, lastHash: last}, nil
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
	_, _, last, err := verifyFileWithLast(f, public, nodeID, epoch)
	return last, err
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
	key := l.private.Public().(ed25519.PublicKey)
	return append(ed25519.PublicKey(nil), key...)
}

// NextSequence exposes only the non-secret durable chain position so startup
// can detect a missing whole log when admission fences already exist.
func (l *Log) NextSequence() uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.next
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
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return 0, [sha256.Size]byte{}, nil, err
	}
	var previous [sha256.Size]byte
	var expected uint64 = 1
	var last *Receipt
	for {
		raw, err := readFrame(f)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return 0, [sha256.Size]byte{}, nil, err
		}
		envelope, err := unmarshalEnvelope(raw)
		if err != nil {
			return 0, [sha256.Size]byte{}, nil, err
		}
		if envelope.Version != envelopeVersion || envelope.PayloadType != PayloadType || envelope.KeyID != KeyID(public) ||
			len(envelope.Signature) != ed25519.SignatureSize || !ed25519.Verify(public, PreAuthEncoding(envelope.PayloadType, envelope.Payload), envelope.Signature) {
			return 0, [sha256.Size]byte{}, nil, errors.New("invalid evidence envelope signature or identity")
		}
		receipt, err := unmarshalReceipt(envelope.Payload)
		if err != nil {
			return 0, [sha256.Size]byte{}, nil, err
		}
		if receipt.NodeID != nodeID || receipt.Epoch != epoch || receipt.Sequence != expected || receipt.PreviousHash != previous {
			return 0, [sha256.Size]byte{}, nil, errors.New("evidence chain coordinate mismatch")
		}
		previous = chainHash(receipt.PreviousHash, PreAuthEncoding(envelope.PayloadType, envelope.Payload))
		copyReceipt := receipt
		last = &copyReceipt
		expected++
	}
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		return 0, [sha256.Size]byte{}, nil, err
	}
	return expected, previous, last, nil
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
