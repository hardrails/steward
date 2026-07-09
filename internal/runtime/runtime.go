// Package runtime is Steward's tracker for agent-instance lifecycle. State is
// held in memory by default; a tracker built with LoadTracker also persists
// every mutation to a state file so tracked instances survive a restart.
package runtime

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
)

// Status mirrors the state names used by the control plane's own state machine;
// the two sides are kept in sync by convention, so do not rename these values.
type Status string

const (
	StatusPending    Status = "PENDING"
	StatusRunning    Status = "RUNNING"
	StatusStopped    Status = "STOPPED"
	StatusHibernated Status = "HIBERNATED"
	StatusDestroyed  Status = "DESTROYED"
	// StatusFailed is part of the shared status vocabulary but is never emitted
	// by Steward itself: it is reserved for the caller (the control plane), which
	// writes FAILED on its own row when it cannot reach this Steward. It stays in
	// the enum so both sides share one vocabulary; do not remove it.
	StatusFailed Status = "FAILED"
)

// DefaultMaxInstances bounds how many instances a tracker will hold when the
// constructor is given a non-positive limit. It is a circuit breaker against an
// unbounded-Provision DoS, not a scheduler.
const DefaultMaxInstances = 1024

// ErrNotFound is returned when an operation names a runtime_ref the tracker does
// not know. The HTTP layer turns this into a 404.
var ErrNotFound = errors.New("unknown runtime_ref")

// ErrCapacityExceeded is returned by Provision when the tracker already holds
// its maximum number of instances. The HTTP layer turns this into a 503.
var ErrCapacityExceeded = errors.New("instance capacity exceeded")

// Instance is a tracked agent instance. Spec is opaque config, round-tripped
// verbatim; the tracker never parses or validates its contents.
type Instance struct {
	InstanceID string          `json:"instance_id"`
	RuntimeRef string          `json:"runtime_ref"`
	Status     Status          `json:"status"`
	Spec       json.RawMessage `json:"spec,omitempty"`
}

func (i *Instance) clone() *Instance {
	c := *i
	if i.Spec != nil {
		c.Spec = append(json.RawMessage(nil), i.Spec...)
	}
	return &c
}

// Tracker tracks instances behind a single mutex. By default it holds state in
// memory only and a restart loses everything; when constructed with a state file
// (see LoadTracker) it additionally persists every mutation so state survives a
// restart. stateFile is empty for the in-memory case and never mutated after
// construction, so it needs no lock.
type Tracker struct {
	mu           sync.Mutex
	byRef        map[string]*Instance
	byID         map[string]string
	maxInstances int
	stateFile    string
}

// NewTracker returns an in-memory tracker that holds at most maxInstances
// instances and never persists; a restart loses all tracked state. A
// non-positive maxInstances is replaced with DefaultMaxInstances. Use
// LoadTracker for durable state.
func NewTracker(maxInstances int) *Tracker {
	return newTracker(maxInstances, "")
}

// newTracker is the shared constructor for NewTracker and LoadTracker. An empty
// stateFile disables persistence.
func newTracker(maxInstances int, stateFile string) *Tracker {
	if maxInstances <= 0 {
		maxInstances = DefaultMaxInstances
	}
	return &Tracker{
		byRef:        make(map[string]*Instance),
		byID:         make(map[string]string),
		maxInstances: maxInstances,
		stateFile:    stateFile,
	}
}

// Provision is idempotent on instanceID: a repeated call for an already-tracked
// instance returns the existing instance with created=false, so a client
// retrying an ambiguous timed-out call cannot double-provision. It returns
// ErrCapacityExceeded when a *new* instance would push the tracker past its
// configured maximum; re-provisioning an already-tracked instance never fails on
// capacity because it does not grow the map.
func (t *Tracker) Provision(instanceID string, spec json.RawMessage) (inst *Instance, created bool, err error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if ref, ok := t.byID[instanceID]; ok {
		// Defensive: byID and byRef are only ever mutated together under this
		// mutex, so a present id implies a present ref. Guard anyway so a future
		// edit that breaks the invariant re-provisions cleanly instead of
		// panicking on a nil clone.
		if existing, ok := t.byRef[ref]; ok {
			return existing.clone(), false, nil
		}
		delete(t.byID, instanceID)
	}

	if len(t.byRef) >= t.maxInstances {
		return nil, false, ErrCapacityExceeded
	}

	stored := &Instance{
		InstanceID: instanceID,
		RuntimeRef: newRuntimeRef(),
		Status:     StatusPending,
		Spec:       append(json.RawMessage(nil), spec...),
	}
	t.byRef[stored.RuntimeRef] = stored
	t.byID[instanceID] = stored.RuntimeRef
	if err := t.persistLocked(); err != nil {
		// Persistence failed: undo the in-memory insert so memory never claims a
		// durability the state file does not have. The caller sees the error and
		// can retry; a retry re-provisions cleanly.
		delete(t.byRef, stored.RuntimeRef)
		delete(t.byID, instanceID)
		return nil, false, err
	}
	return stored.clone(), true, nil
}

// Len returns the number of currently tracked instances. It is safe for
// concurrent use.
func (t *Tracker) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.byRef)
}

// MaxInstances returns the configured capacity cap: the maximum number of
// instances the tracker holds before Provision returns ErrCapacityExceeded. It
// is fixed at construction and never mutated afterward, so it needs no lock.
func (t *Tracker) MaxInstances() int {
	return t.maxInstances
}

// Durable reports whether this tracker persists its state to a file. It exposes
// only whether persistence is enabled, never the file path, so a caller can
// advertise durability (for example in GET /v1/capabilities) without leaking a
// local filesystem path. stateFile is fixed at construction and never mutated
// afterward, so it needs no lock.
func (t *Tracker) Durable() bool {
	return t.stateFile != ""
}

func (t *Tracker) Start(runtimeRef string) (*Instance, error) {
	return t.transition(runtimeRef, StatusRunning)
}

func (t *Tracker) Stop(runtimeRef string) (*Instance, error) {
	return t.transition(runtimeRef, StatusStopped)
}

func (t *Tracker) Hibernate(runtimeRef string) (*Instance, error) {
	return t.transition(runtimeRef, StatusHibernated)
}

// Destroy removes the instance and releases its instance_id for reuse. A later
// Provision with the same instance_id creates a new, unrelated instance with a
// fresh runtime_ref rather than erroring or resurrecting the destroyed one; the
// idempotency guarantee therefore covers only an instance's live span, not a
// span that straddles a Destroy. This release-on-destroy is intentional: the
// caller treats a destroyed instance_id as free to reuse.
func (t *Tracker) Destroy(runtimeRef string) (*Instance, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	inst, ok := t.byRef[runtimeRef]
	if !ok {
		return nil, ErrNotFound
	}
	prevStatus := inst.Status
	inst.Status = StatusDestroyed
	delete(t.byRef, runtimeRef)
	delete(t.byID, inst.InstanceID)
	if err := t.persistLocked(); err != nil {
		// Roll back the removal so memory matches the last durable state.
		inst.Status = prevStatus
		t.byRef[runtimeRef] = inst
		t.byID[inst.InstanceID] = runtimeRef
		return nil, err
	}
	return inst.clone(), nil
}

func (t *Tracker) Status(runtimeRef string) (*Instance, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	inst, ok := t.byRef[runtimeRef]
	if !ok {
		return nil, ErrNotFound
	}
	return inst.clone(), nil
}

func (t *Tracker) transition(runtimeRef string, status Status) (*Instance, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	inst, ok := t.byRef[runtimeRef]
	if !ok {
		return nil, ErrNotFound
	}
	prev := inst.Status
	inst.Status = status
	if err := t.persistLocked(); err != nil {
		inst.Status = prev // roll back to the last durable status
		return nil, err
	}
	return inst.clone(), nil
}

func newRuntimeRef() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err) // a crypto/rand failure is unrecoverable
	}
	return "rt_" + hex.EncodeToString(b[:])
}
