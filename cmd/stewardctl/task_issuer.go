package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"syscall"
	"time"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/securefile"
	"github.com/hardrails/steward/internal/taskpermit"
)

type taskIssuerConfig struct {
	Admission, Intent, Trust, Key, KeyID, Store string
	Operations                                  []string
	Validity                                    time.Duration
	Capacity                                    int
}

type taskIssuerRequest struct {
	TaskID        string `json:"task_id"`
	OperationID   string `json:"operation_id"`
	RequestBase64 string `json:"request_base64"`
}

// The station owns the key. Callers can select only a task ID, an approved
// operation and exact request bytes, never a runtime, key or trust document.
type taskIssuer struct {
	mu         sync.Mutex
	config     taskIssuerConfig
	root       *os.Root
	lock       *os.File
	snapshots  string
	public     ed25519.PublicKey
	admitted   permitAdmission
	intent     admission.InstanceIntent
	operations map[string]serviceTrustOperation
	count      int
}

var (
	errTaskIssuerConflict = errors.New("task issuance conflicts with retained authority")
	errTaskIssuerCapacity = errors.New("task signing station reached its retained capacity")
	errTaskIssuerBusy     = errors.New("task signing station is busy")
)

func openTaskIssuer(config taskIssuerConfig) (_ *taskIssuer, returnErr error) {
	if !filepath.IsAbs(config.Store) || config.Capacity < 1 || config.Capacity > 4096 ||
		config.Validity < 10*time.Second || config.Validity > taskpermit.MaxValidity ||
		config.Validity%time.Second != 0 || !validOptionalControlIdentifier(config.KeyID, 128) ||
		config.KeyID == "" || len(config.Operations) == 0 || len(config.Operations) > 8 {
		return nil, errors.New("task issuer requires a private store, key identity, one to eight operations, finite capacity and a whole-second validity from 10s to 15m")
	}
	config.Operations = slices.Clone(config.Operations)
	slices.Sort(config.Operations)
	for index, operation := range config.Operations {
		if operation == "" || !validOptionalControlIdentifier(operation, 128) ||
			index > 0 && operation == config.Operations[index-1] {
			return nil, errors.New("task issuer operations must be distinct canonical identities")
		}
	}
	info, err := os.Lstat(config.Store)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 ||
		info.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
		return nil, errors.New("task issuer store must be an existing owner-controlled 0700 directory")
	}
	root, err := os.OpenRoot(config.Store)
	if err != nil {
		return nil, err
	}
	issuer := &taskIssuer{config: config, root: root}
	defer func() {
		if returnErr != nil {
			_ = issuer.Close()
		}
	}()
	openedRoot, err := root.Stat(".")
	if err != nil || !os.SameFile(info, openedRoot) {
		return nil, errors.New("task issuer store changed while opening")
	}
	issuer.lock, err = root.OpenFile("LOCK", os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	lockInfo, err := issuer.lock.Stat()
	if err != nil || !lockInfo.Mode().IsRegular() || lockInfo.Mode().Perm() != 0o600 ||
		lockInfo.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
		return nil, errors.New("task issuer store lock is not an owner-only regular file")
	}
	if err = syscall.Flock(int(issuer.lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return nil, errors.New("task issuer store is already open by another signer")
	}
	issuer.snapshots, err = os.MkdirTemp("", "steward-task-issuer-")
	if err != nil {
		return nil, err
	}
	inputs := map[string][]byte{}
	for name, source := range map[string]string{
		"admission": config.Admission, "intent": config.Intent, "trust": config.Trust, "key": config.Key,
	} {
		if !filepath.IsAbs(source) {
			return nil, errors.New("task issuer authority paths must be absolute")
		}
		permissions := securefile.TrustFile
		if name == "key" {
			permissions = securefile.OwnerOnly
		}
		raw, readErr := securefile.Read(source, int64(maxArtifactBytes), permissions)
		if readErr != nil {
			return nil, fmt.Errorf("read task issuer %s: %w", name, readErr)
		}
		if err = writeNewFile(filepath.Join(issuer.snapshots, name), raw, 0o600); err != nil {
			return nil, err
		}
		if name != "key" {
			inputs[name] = slices.Clone(raw)
		}
		clear(raw)
	}
	private, err := readPrivateKey(filepath.Join(issuer.snapshots, "key"))
	if err != nil {
		return nil, err
	}
	issuer.public = slices.Clone(private.Public().(ed25519.PublicKey))
	clear(private)
	if err = dsse.DecodeStrictInto(inputs["admission"], maxArtifactBytes, &issuer.admitted); err != nil {
		return nil, err
	}
	if err = dsse.DecodeStrictInto(inputs["intent"], maxArtifactBytes, &issuer.intent); err != nil {
		return nil, err
	}
	if err = validateTaskIssuanceAuthority(issuer.admitted, issuer.intent, config.KeyID, issuer.public); err != nil {
		return nil, err
	}
	issuer.operations = make(map[string]serviceTrustOperation)
	for _, id := range config.Operations {
		operation, loadErr := readServiceTrust(filepath.Join(issuer.snapshots, "trust"), issuer.intent, id)
		if loadErr != nil {
			return nil, loadErr
		}
		if config.Validity > time.Duration(operation.MaxPermitSeconds)*time.Second {
			return nil, errors.New("task issuer validity exceeds an allowed operation's permit limit")
		}
		issuer.operations[id] = operation
	}
	// Only public authority contributes to the binding. The key never enters
	// durable records or a response, and configuration cannot change on restart.
	binding, err := json.Marshal(struct {
		Inputs     map[string][]byte `json:"inputs"`
		Public     []byte            `json:"public"`
		KeyID      string            `json:"key_id"`
		Operations []string          `json:"operations"`
		Validity   int64             `json:"validity_seconds"`
		Capacity   int               `json:"capacity"`
	}{inputs, issuer.public, config.KeyID, config.Operations, int64(config.Validity / time.Second), config.Capacity})
	if err != nil {
		return nil, err
	}
	fingerprint := sha256.Sum256(binding)
	if err = issuer.bindStore([]byte(hex.EncodeToString(fingerprint[:]))); err != nil {
		return nil, err
	}
	return issuer, nil
}

func (issuer *taskIssuer) Close() error {
	// Shutdown may time out while a handler is still syncing retained authority.
	// Do not close its root or remove its key snapshot underneath that handler.
	issuer.mu.Lock()
	defer issuer.mu.Unlock()
	var result error
	if issuer.snapshots != "" {
		result = errors.Join(result, os.RemoveAll(issuer.snapshots))
		issuer.snapshots = ""
	}
	if issuer.lock != nil {
		result = errors.Join(result, issuer.lock.Close())
		issuer.lock = nil
	}
	if issuer.root != nil {
		result = errors.Join(result, issuer.root.Close())
		issuer.root = nil
	}
	return result
}

func (issuer *taskIssuer) bindStore(binding []byte) error {
	directory, err := issuer.root.Open(".")
	if err != nil {
		return err
	}
	entries, readErr := directory.ReadDir(issuer.config.Capacity + 3)
	closeErr := directory.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) || closeErr != nil {
		return errors.Join(readErr, closeErr)
	}
	for _, entry := range entries {
		if entry.Name() == "LOCK" || entry.Name() == "BINDING" {
			continue
		}
		name := entry.Name()
		if !entry.Type().IsRegular() || len(name) != 69 || filepath.Ext(name) != ".json" {
			return errors.New("task issuer store contains an unknown artifact")
		}
		if _, err := hex.DecodeString(name[:64]); err != nil {
			return errors.New("task issuer store contains an invalid task identity")
		}
		issuer.count++
	}
	if issuer.count > issuer.config.Capacity {
		return errTaskIssuerCapacity
	}
	prior, err := securefile.ReadRootMode(issuer.root, "BINDING", 64, 0o600)
	if errors.Is(err, os.ErrNotExist) && issuer.count == 0 {
		return issuer.write("BINDING", binding)
	}
	if err != nil || !bytes.Equal(prior, binding) {
		return errors.New("task issuer store does not match this authority configuration")
	}
	return nil
}

func (issuer *taskIssuer) issue(request taskIssuerRequest) ([]byte, error) {
	if !issuer.mu.TryLock() {
		return nil, errTaskIssuerBusy
	}
	defer issuer.mu.Unlock()
	if issuer.root == nil {
		return nil, errTaskIssuerBusy
	}
	if request.TaskID == "" || !validOptionalControlIdentifier(request.TaskID, 128) ||
		!slices.Contains(issuer.config.Operations, request.OperationID) {
		return nil, errors.New("task identity or operation is not permitted by this signing station")
	}
	body, err := base64.StdEncoding.Strict().DecodeString(request.RequestBase64)
	if err != nil || len(body) == 0 || int64(len(body)) > taskpermit.MaxRequestBytes ||
		base64.StdEncoding.EncodeToString(body) != request.RequestBase64 {
		return nil, errors.New("task request is not bounded canonical base64")
	}
	nameDigest := sha256.Sum256([]byte(request.TaskID))
	name := hex.EncodeToString(nameDigest[:]) + ".json"
	retained, err := securefile.ReadRootMode(issuer.root, name, maxTaskBundleBytes, 0o600)
	if err == nil {
		if err = issuer.match(retained, request, body); err != nil {
			return nil, errors.Join(errTaskIssuerConflict, err)
		}
		// A previous file fsync may have failed after writing valid bytes.
		// Re-establish file and directory durability before returning a replay.
		file, openErr := issuer.root.OpenFile(name, os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if openErr != nil {
			return nil, openErr
		}
		if err = errors.Join(file.Sync(), file.Close(), issuer.sync()); err != nil {
			return nil, err
		}
		return retained, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, errors.Join(errTaskIssuerConflict, err)
	}
	// A dangling symlink can read as missing. It is still retained state,
	// never permission to sign a replacement for this identity.
	if _, statErr := issuer.root.Lstat(name); !errors.Is(statErr, os.ErrNotExist) {
		return nil, errors.Join(errTaskIssuerConflict, statErr)
	}
	if issuer.count >= issuer.config.Capacity {
		return nil, errTaskIssuerCapacity
	}
	directory, err := os.MkdirTemp(issuer.snapshots, "request-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(directory)
	requestPath, bundlePath := filepath.Join(directory, "request"), filepath.Join(directory, "bundle")
	if err = writeNewFile(requestPath, body, 0o600); err != nil {
		return nil, err
	}
	// Reuse the existing native issuer. No subprocess, shell or second signing
	// implementation, and no dispatch or runtime activation occurs here.
	err = issueTask([]string{
		"-admission", filepath.Join(issuer.snapshots, "admission"),
		"-intent", filepath.Join(issuer.snapshots, "intent"),
		"-trust", filepath.Join(issuer.snapshots, "trust"),
		"-key", filepath.Join(issuer.snapshots, "key"), "-key-id", issuer.config.KeyID,
		"-request", requestPath, "-operation-id", request.OperationID, "-task-id", request.TaskID,
		"-valid-for", issuer.config.Validity.String(), "-out", bundlePath,
	}, io.Discard)
	if err != nil {
		return nil, err
	}
	bundle, err := securefile.Read(bundlePath, maxTaskBundleBytes, securefile.OwnerOnly)
	if err != nil {
		return nil, err
	}
	if err = issuer.match(bundle, request, body); err != nil {
		return nil, err
	}
	issuer.count++ // Failed persistence consumes capacity until a verified restart.
	if err = issuer.write(name, bundle); err != nil {
		return nil, err
	}
	return bundle, nil
}

func (issuer *taskIssuer) match(bundle []byte, request taskIssuerRequest, body []byte) error {
	verified, err := decodeTaskBundle(bundle, map[string]ed25519.PublicKey{issuer.config.KeyID: issuer.public}, timeNow().UTC(), issuer.config.Validity)
	if err != nil {
		return err
	}
	if verified.Verified.Statement.TaskID != request.TaskID || verified.Bundle.Operation.ID != request.OperationID ||
		!bytes.Equal(verified.Request, body) {
		return errTaskIssuerConflict
	}
	statement, admitted, intent := verified.Verified.Statement, issuer.admitted, issuer.intent
	if statement.TenantID != intent.TenantID || statement.NodeID != intent.NodeID ||
		statement.InstanceID != intent.InstanceID || statement.Generation != intent.Generation ||
		statement.Generation != admitted.Generation || statement.CapsuleDigest != intent.CapsuleDigest ||
		statement.CapsuleDigest != admitted.CapsuleDigest || statement.PolicyDigest != admitted.PolicyDigest ||
		statement.RoutePolicyDigest != admitted.RoutePolicyDigest || statement.RuntimeRef != admitted.RuntimeRef ||
		statement.GrantID != admitted.GrantID || statement.ServiceID != intent.ServiceID ||
		statement.ServiceID != admitted.ServiceID || verified.Bundle.ServicePath != admitted.ServicePath ||
		verified.Bundle.Operation != issuer.operations[request.OperationID] {
		return errTaskIssuerConflict
	}
	return nil
}

func (issuer *taskIssuer) write(name string, raw []byte) error {
	file, err := issuer.root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, writeErr := io.Copy(file, bytes.NewReader(raw))
	syncErr := file.Sync()
	closeErr := file.Close()
	if err = errors.Join(writeErr, syncErr, closeErr); err != nil {
		// An ambiguous file is retained. A retry must not replace its authority.
		return err
	}
	return issuer.sync()
}

func (issuer *taskIssuer) sync() error {
	directory, err := issuer.root.Open(".")
	if err != nil {
		return err
	}
	return errors.Join(directory.Sync(), directory.Close())
}
