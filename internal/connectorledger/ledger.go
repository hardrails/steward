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
	"time"
	"unicode/utf8"

	"github.com/hardrails/steward/internal/dsse"
)

const (
	PayloadType  = "application/vnd.steward.connector-receipt.v1+json"
	SchemaV1     = "steward.connector-receipt.v1"
	MaxLineBytes = 128 << 10
	MaxLogBytes  = 64 << 20
)

var chainDomain = []byte("steward-connector-ledger-v1\x00")

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
	Committed Outcome = "committed"
	Failed    Outcome = "failed"
)

// Event is the bounded, non-secret portion supplied by Gateway. It records
// enforcement identity and transfer metadata, never headers, credentials,
// origins, paths, queries, or bodies.
type Event struct {
	Phase         Phase   `json:"phase"`
	Outcome       Outcome `json:"outcome"`
	TenantID      string  `json:"tenant_id"`
	RuntimeRef    string  `json:"runtime_ref"`
	CapsuleDigest string  `json:"capsule_digest"`
	PolicyDigest  string  `json:"policy_digest"`
	Generation    uint64  `json:"generation"`
	GrantID       string  `json:"grant_id"`
	ConnectorID   string  `json:"connector_id"`
	OperationID   string  `json:"operation_id"`
	TaskDigest    string  `json:"task_digest"`
	HTTPStatus    int     `json:"http_status,omitempty"`
	RequestBytes  int64   `json:"request_bytes"`
	ResponseBytes int64   `json:"response_bytes"`
	ErrorCode     string  `json:"error_code,omitempty"`
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
	mu      sync.Mutex
	path    string
	file    *os.File
	private ed25519.PrivateKey
	public  ed25519.PublicKey
	nodeID  string
	epoch   uint64
	keyID   string
	next    uint64
	last    string
	failed  bool
}

func Open(path string, private ed25519.PrivateKey, nodeID string, epoch uint64) (*Log, error) {
	if !validPath(path) || len(private) != ed25519.PrivateKeySize || !validText(nodeID, 256) || epoch == 0 {
		return nil, errors.New("connector ledger requires a clean path, Ed25519 key, bounded node id, and positive epoch")
	}
	created := false
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		created = true
	} else if err != nil {
		return nil, fmt.Errorf("stat connector ledger: %w", err)
	} else if !validFileInfo(info) {
		return nil, errors.New("connector ledger must be a bounded owner-only regular file")
	}
	file, err := os.OpenFile(path, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open connector ledger: %w", err)
	}
	closeWith := func(openErr error) (*Log, error) {
		_ = file.Close()
		return nil, openErr
	}
	if err := file.Chmod(0o600); err != nil {
		return closeWith(err)
	}
	if created {
		if err := syncDirectory(filepath.Dir(path)); err != nil {
			return closeWith(err)
		}
	}
	public := private.Public().(ed25519.PublicKey)
	head, err := verifyFile(file, public, nodeID, epoch, nil)
	if err != nil {
		return closeWith(fmt.Errorf("verify connector ledger: %w", err))
	}
	return &Log{
		path: path, file: file, private: append(ed25519.PrivateKey(nil), private...),
		public: append(ed25519.PublicKey(nil), public...), nodeID: nodeID, epoch: epoch,
		keyID: KeyID(public), next: head.Sequence + 1, last: head.ChainHash,
	}, nil
}

func (l *Log) Append(event Event) (Head, error) {
	if err := validateEvent(event); err != nil {
		return Head{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil {
		return Head{}, errors.New("connector ledger is closed")
	}
	if l.failed {
		return Head{}, errors.New("connector ledger requires reopen after an ambiguous write")
	}
	receipt := Receipt{
		SchemaVersion: SchemaV1, NodeID: l.nodeID, Epoch: l.epoch, Sequence: l.next,
		PreviousHash: l.last, ObservedAt: time.Now().UTC().Format(time.RFC3339Nano), Event: event,
	}
	payload, err := json.Marshal(receipt)
	if err != nil {
		return Head{}, err
	}
	envelope, err := dsse.Sign(PayloadType, payload, l.keyID, l.private)
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
	if info.Size()+int64(len(raw)+1) > MaxLogBytes {
		return Head{}, errors.New("connector ledger capacity exceeded")
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
	return l.headLocked(), nil
}

func (l *Log) Head() Head {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.headLocked()
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
	return verifyFile(file, public, nodeID, epoch, visit)
}

// Validate inspects an existing ledger without creating it. A missing ledger is
// a valid prospective path: Open creates the file during normal startup. When
// the file exists, Validate verifies its permissions, signatures, chain, node
// identity, and epoch using the public half of the configured private key.
func Validate(path string, private ed25519.PrivateKey, nodeID string, epoch uint64) (Head, error) {
	if !validPath(path) || len(private) != ed25519.PrivateKeySize || !validText(nodeID, 256) || epoch == 0 {
		return Head{}, errors.New("connector ledger requires a clean path, Ed25519 key, bounded node id, and positive epoch")
	}
	public := private.Public().(ed25519.PublicKey)
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return Head{NodeID: nodeID, Epoch: epoch, ChainHash: zeroHash(), KeyID: KeyID(public)}, nil
	} else if err != nil {
		return Head{}, fmt.Errorf("stat connector ledger: %w", err)
	}
	return VerifyRecords(path, public, nodeID, epoch, nil)
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
		payload, keyID, err := dsse.Verify(raw, PayloadType, trusted)
		if err != nil || keyID != head.KeyID {
			return Head{}, fmt.Errorf("verify connector ledger line %d: %w", lineNumber, err)
		}
		var receipt Receipt
		if err := dsse.DecodeStrictInto(payload, MaxLineBytes, &receipt); err != nil {
			return Head{}, fmt.Errorf("decode connector ledger line %d: %w", lineNumber, err)
		}
		if err := validateReceipt(receipt, nodeID, epoch, uint64(lineNumber), previous); err != nil {
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

func validateReceipt(receipt Receipt, nodeID string, epoch, sequence uint64, previous string) error {
	if receipt.SchemaVersion != SchemaV1 || receipt.NodeID != nodeID || receipt.Epoch != epoch ||
		receipt.Sequence != sequence || receipt.PreviousHash != previous {
		return errors.New("connector receipt chain coordinates do not match")
	}
	observed, err := time.Parse(time.RFC3339Nano, receipt.ObservedAt)
	if err != nil || observed.IsZero() || receipt.ObservedAt != observed.UTC().Format(time.RFC3339Nano) {
		return errors.New("connector receipt has an invalid observation time")
	}
	return validateEvent(receipt.Event)
}

func validateEvent(event Event) error {
	if !validText(event.TenantID, 128) || !runtimeRef(event.RuntimeRef) ||
		!digest(event.CapsuleDigest) || !digest(event.PolicyDigest) || event.Generation == 0 ||
		!grantID(event.GrantID) || !identifier(event.ConnectorID) || !identifier(event.OperationID) ||
		!digest(event.TaskDigest) || event.RequestBytes < 0 || event.RequestBytes > 1<<30 ||
		event.ResponseBytes < 0 || event.ResponseBytes > 1<<30 || event.HTTPStatus < 0 || event.HTTPStatus > 599 ||
		(event.ErrorCode != "" && !identifier(event.ErrorCode)) {
		return errors.New("invalid bounded connector event")
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
		if event.Outcome != Committed && event.Outcome != Failed {
			return errors.New("invalid connector terminal outcome")
		}
		if event.Outcome == Committed && (event.HTTPStatus < 100 || event.HTTPStatus > 599 || event.ErrorCode != "") {
			return errors.New("committed connector outcome requires an HTTP status and no error")
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
