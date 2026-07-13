// Package storagehandle defines the opaque reference exchanged for trusted,
// preprovisioned state and secret storage. It deliberately does not provision
// storage. A trusted host component owns the fixed backend root and resolves a
// reference only after checking its complete tenant and lineage scope.
package storagehandle

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

const (
	// Version is the only supported opaque-reference schema.
	Version = 1

	maxReferenceBytes  = 4 << 10
	maxIdentifierBytes = 64
)

var (
	ErrInvalid       = errors.New("invalid storage handle")
	ErrCapacity      = errors.New("storage handle capacity exceeded")
	ErrNotFound      = errors.New("storage handle not found")
	ErrConflict      = errors.New("storage handle binding conflict")
	ErrRevoked       = errors.New("storage handle revoked")
	ErrScopeMismatch = errors.New("storage handle scope mismatch")
)

// Kind distinguishes state from secret material without exposing a backend path.
type Kind string

const (
	KindState  Kind = "state"
	KindSecret Kind = "secret"
)

// Status is the host-owned lifecycle state of a preprovisioned handle.
type Status string

const (
	StatusReady   Status = "ready"
	StatusRevoked Status = "revoked"
)

// Reference is the complete untrusted wire representation. Callers cannot choose
// a path, mount option, device, UID, GID, or backend name.
type Reference struct {
	Version    int    `json:"version"`
	HandleID   string `json:"handle_id"`
	Generation uint64 `json:"generation"`
	Kind       Kind   `json:"kind"`
}

// Scope is trusted context from signed authority, never from Reference.
type Scope struct {
	TenantID  string
	LineageID string
	Kind      Kind
}

// Record is a trusted registry entry created out of band. BackendID is a strict
// identifier below Registry's fixed root, not a path supplied by a tenant.
type Record struct {
	Reference
	TenantID  string `json:"-"`
	LineageID string `json:"-"`
	BackendID string `json:"-"`
	Status    Status `json:"-"`
}

// Registry is a bounded, mutex-protected view of host-preprovisioned handles.
// Durable storage and provisioning remain the responsibility of the trusted host
// harness in this feasibility phase.
type Registry struct {
	mu         sync.Mutex
	root       *os.Root
	maxRecords int
	byID       map[string]Record
	leases     map[string]map[*Lease]struct{}
	closed     bool
}

// Lease pins one verified backend directory descriptor. It deliberately exposes
// no reusable host path. Revocation closes the descriptor and prevents new use;
// a caller must still stop any workload that already received a mounted backend.
type Lease struct {
	mu        sync.RWMutex
	root      *os.Root
	reference Reference
	registry  *Registry
	closed    bool
}

// NewRegistry accepts one fixed absolute root selected by the host operator.
func NewRegistry(root string, maxRecords int) (*Registry, error) {
	if root == "" || !filepath.IsAbs(root) || filepath.Clean(root) != root || root == string(filepath.Separator) {
		return nil, fmt.Errorf("%w: backend root must be a clean absolute non-root path", ErrInvalid)
	}
	if maxRecords < 1 {
		return nil, fmt.Errorf("%w: max records must be positive", ErrInvalid)
	}
	rootDescriptor, err := os.OpenRoot(root)
	if err != nil {
		return nil, fmt.Errorf("%w: open backend root: %v", ErrInvalid, err)
	}
	info, err := rootDescriptor.Lstat(".")
	if err != nil || !info.IsDir() {
		_ = rootDescriptor.Close()
		return nil, fmt.Errorf("%w: backend root must be a directory", ErrInvalid)
	}
	return &Registry{
		root: rootDescriptor, maxRecords: maxRecords, byID: make(map[string]Record),
		leases: make(map[string]map[*Lease]struct{}),
	}, nil
}

// Add is exact-idempotent. It rejects rebinding an existing opaque ID.
func (r *Registry) Add(record Record) (bool, error) {
	if err := validateRecord(record); err != nil {
		return false, err
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return false, ErrRevoked
	}
	if existing, ok := r.byID[record.HandleID]; ok {
		if existing == record {
			return false, nil
		}
		return false, ErrConflict
	}
	if len(r.byID) >= r.maxRecords {
		return false, ErrCapacity
	}
	r.byID[record.HandleID] = record
	return true, nil
}

// Resolve checks the opaque generation and complete trusted scope before opening
// the exact backend below the descriptor-pinned registry root.
func (r *Registry) Resolve(reference Reference, scope Scope) (*Lease, error) {
	if err := validateReference(reference); err != nil {
		return nil, err
	}
	if err := validateScope(scope); err != nil {
		return nil, err
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil, ErrRevoked
	}
	record, ok := r.byID[reference.HandleID]
	if !ok || record.Generation != reference.Generation || record.Kind != reference.Kind {
		return nil, ErrNotFound
	}
	if record.TenantID != scope.TenantID || record.LineageID != scope.LineageID || record.Kind != scope.Kind {
		return nil, ErrScopeMismatch
	}
	if record.Status != StatusReady {
		return nil, ErrRevoked
	}

	kindName := string(record.Kind)
	kindInfo, err := r.root.Lstat(kindName)
	if err != nil || !kindInfo.IsDir() || kindInfo.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%w: invalid kind backend", ErrInvalid)
	}
	kindRoot, err := r.root.OpenRoot(kindName)
	if err != nil {
		return nil, fmt.Errorf("%w: open kind backend: %v", ErrInvalid, err)
	}
	defer kindRoot.Close()
	backendInfo, err := kindRoot.Lstat(record.BackendID)
	if err != nil || !backendInfo.IsDir() || backendInfo.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%w: invalid handle backend", ErrInvalid)
	}
	backendRoot, err := kindRoot.OpenRoot(record.BackendID)
	if err != nil {
		return nil, fmt.Errorf("%w: open handle backend: %v", ErrInvalid, err)
	}
	lease := &Lease{root: backendRoot, reference: record.Reference, registry: r}
	if r.leases[record.HandleID] == nil {
		r.leases[record.HandleID] = make(map[*Lease]struct{})
	}
	r.leases[record.HandleID][lease] = struct{}{}
	return lease, nil
}

// Revoke is exact-idempotent and never makes a revoked handle ready again.
func (r *Registry) Revoke(reference Reference, scope Scope) (bool, error) {
	if err := validateReference(reference); err != nil {
		return false, err
	}
	if err := validateScope(scope); err != nil {
		return false, err
	}

	r.mu.Lock()
	record, ok := r.byID[reference.HandleID]
	if !ok || record.Generation != reference.Generation || record.Kind != reference.Kind {
		r.mu.Unlock()
		return false, ErrNotFound
	}
	if record.TenantID != scope.TenantID || record.LineageID != scope.LineageID || record.Kind != scope.Kind {
		r.mu.Unlock()
		return false, ErrScopeMismatch
	}
	if record.Status == StatusRevoked {
		r.mu.Unlock()
		return false, nil
	}
	record.Status = StatusRevoked
	r.byID[reference.HandleID] = record
	active := r.leases[reference.HandleID]
	delete(r.leases, reference.HandleID)
	r.mu.Unlock()
	for lease := range active {
		lease.closeDescriptor()
	}
	return true, nil
}

// Reference returns the public identity bound to the lease.
func (l *Lease) Reference() Reference {
	return l.reference
}

// Valid reports whether the registry has left the descriptor usable. It does not
// claim that a workload which already received a mount has been stopped.
func (l *Lease) Valid() bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return !l.closed && l.root != nil
}

// Close releases this caller's descriptor-bound lease.
func (l *Lease) Close() error {
	l.closeDescriptor()
	if l.registry != nil {
		l.registry.removeLease(l)
	}
	return nil
}

func (l *Lease) closeDescriptor() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return
	}
	l.closed = true
	if l.root != nil {
		_ = l.root.Close()
		l.root = nil
	}
}

func (r *Registry) removeLease(lease *Lease) {
	r.mu.Lock()
	defer r.mu.Unlock()
	byHandle := r.leases[lease.reference.HandleID]
	delete(byHandle, lease)
	if len(byHandle) == 0 {
		delete(r.leases, lease.reference.HandleID)
	}
}

// Close revokes every outstanding lease and releases the pinned root descriptor.
func (r *Registry) Close() error {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil
	}
	r.closed = true
	var active []*Lease
	for _, byHandle := range r.leases {
		for lease := range byHandle {
			active = append(active, lease)
		}
	}
	r.leases = make(map[string]map[*Lease]struct{})
	root := r.root
	r.root = nil
	r.mu.Unlock()
	for _, lease := range active {
		lease.closeDescriptor()
	}
	if root != nil {
		return root.Close()
	}
	return nil
}

// ParseReference reads one bounded strict JSON object. Duplicate and unknown fields
// are rejected before decoding so permissive JSON behavior cannot rebind a handle.
func ParseReference(reader io.Reader) (Reference, error) {
	data, err := io.ReadAll(io.LimitReader(reader, maxReferenceBytes+1))
	if err != nil {
		return Reference{}, fmt.Errorf("%w: read reference: %v", ErrInvalid, err)
	}
	if len(data) > maxReferenceBytes {
		return Reference{}, fmt.Errorf("%w: reference exceeds %d bytes", ErrInvalid, maxReferenceBytes)
	}
	if err := rejectDuplicateObjectFields(data); err != nil {
		return Reference{}, err
	}

	var reference Reference
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&reference); err != nil {
		return Reference{}, fmt.Errorf("%w: decode reference: %v", ErrInvalid, err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return Reference{}, err
	}
	if err := validateReference(reference); err != nil {
		return Reference{}, err
	}
	return reference, nil
}

// MarshalReference returns stable field-ordered JSON used by fixtures and digests.
func MarshalReference(reference Reference) ([]byte, error) {
	if err := validateReference(reference); err != nil {
		return nil, err
	}
	return json.Marshal(reference)
}

func rejectDuplicateObjectFields(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("%w: decode object: %v", ErrInvalid, err)
	}
	opening, ok := token.(json.Delim)
	if !ok || opening != '{' {
		return fmt.Errorf("%w: reference must be an object", ErrInvalid)
	}
	seen := make(map[string]struct{}, 4)
	for decoder.More() {
		token, err = decoder.Token()
		if err != nil {
			return fmt.Errorf("%w: decode field: %v", ErrInvalid, err)
		}
		field, ok := token.(string)
		if !ok {
			return fmt.Errorf("%w: object key must be a string", ErrInvalid)
		}
		if _, duplicate := seen[field]; duplicate {
			return fmt.Errorf("%w: duplicate field %q", ErrInvalid, field)
		}
		seen[field] = struct{}{}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return fmt.Errorf("%w: decode field %q: %v", ErrInvalid, field, err)
		}
	}
	if token, err = decoder.Token(); err != nil || token != json.Delim('}') {
		return fmt.Errorf("%w: incomplete object", ErrInvalid)
	}
	return requireJSONEOF(decoder)
}

func requireJSONEOF(decoder *json.Decoder) error {
	var extra json.RawMessage
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("%w: multiple JSON values", ErrInvalid)
		}
		return fmt.Errorf("%w: trailing JSON: %v", ErrInvalid, err)
	}
	return nil
}

func validateRecord(record Record) error {
	if err := validateReference(record.Reference); err != nil {
		return err
	}
	if !validIdentifier(record.TenantID) || !validIdentifier(record.LineageID) || !validIdentifier(record.BackendID) {
		return fmt.Errorf("%w: invalid record identifier", ErrInvalid)
	}
	if record.Status != StatusReady && record.Status != StatusRevoked {
		return fmt.Errorf("%w: unsupported status %q", ErrInvalid, record.Status)
	}
	return nil
}

func validateReference(reference Reference) error {
	if reference.Version != Version {
		return fmt.Errorf("%w: unsupported version %d", ErrInvalid, reference.Version)
	}
	if !validIdentifier(reference.HandleID) {
		return fmt.Errorf("%w: invalid handle ID", ErrInvalid)
	}
	if reference.Generation == 0 {
		return fmt.Errorf("%w: generation must be positive", ErrInvalid)
	}
	if reference.Kind != KindState && reference.Kind != KindSecret {
		return fmt.Errorf("%w: unsupported kind %q", ErrInvalid, reference.Kind)
	}
	return nil
}

func validateScope(scope Scope) error {
	if !validIdentifier(scope.TenantID) || !validIdentifier(scope.LineageID) {
		return fmt.Errorf("%w: invalid scope identifier", ErrInvalid)
	}
	if scope.Kind != KindState && scope.Kind != KindSecret {
		return fmt.Errorf("%w: unsupported scope kind %q", ErrInvalid, scope.Kind)
	}
	return nil
}

func validIdentifier(value string) bool {
	if len(value) == 0 || len(value) > maxIdentifierBytes {
		return false
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' {
			continue
		}
		if index > 0 && (character == '_' || character == '-') {
			continue
		}
		return false
	}
	return true
}
