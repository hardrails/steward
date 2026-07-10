// Package runtime is Steward's tracker for agent-instance lifecycle. State is
// held in memory by default; a tracker built with LoadTracker also persists
// every mutation to a state file so tracked instances survive a restart.
package runtime

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"
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
// verbatim; the tracker never parses or validates its contents. Generation is
// the fencing token of the lineage this instance belongs to: a fresh Provision
// sets it, a re-provision only ever raises it (never lowers), and the uplink
// dispatcher fences a stale command whose carried generation is older than the
// one tracked here. Its zero value ("no lineage baseline / no fencing") is a
// safe default, so it is omitempty and needs no state-file format-version bump
// (see docs/instance-generation-fencing.md). CreatedAt is set once, when a
// *new* instance is created by Provision, and never changes again — including
// across a re-provision of the same still-live instance_id, which returns the
// existing instance (and its original CreatedAt) unchanged.
//
// CreatedAt has no `omitempty`: encoding/json's omitempty never omits a struct
// field regardless of value (unlike Generation's int64, a zero time.Time is
// not treated as "empty"), so it is deliberately not tagged with an omitempty
// that would silently be a no-op. This is still additive and needs no
// state-file format-version bump: a snapshot loaded from a file written before
// this field existed simply has no created_at key, decodes to Go's zero
// time.Time, and that zero value never matches a real (non-zero)
// ListFilter.CreatedSince — the same safe-default reasoning Generation's
// zero value uses, just without the byte-identical-on-rewrite property
// omitempty gives Generation.
type Instance struct {
	InstanceID string          `json:"instance_id"`
	RuntimeRef string          `json:"runtime_ref"`
	Status     Status          `json:"status"`
	Generation int64           `json:"generation,omitempty"`
	CreatedAt  time.Time       `json:"created_at"`
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
//
// generation is the fencing token of the lineage this provision belongs to: a
// new instance adopts it as its baseline; an already-tracked instance's
// generation is raised to max(existing, generation) — it is never lowered,
// regardless of caller — and the adoption happens atomically with the rest of
// this call, under the same lock, so no lifecycle command can observe a
// not-yet-adopted generation on a freshly (re-)provisioned instance. Passing 0
// is the coherent "no fencing" value: it never lowers an existing generation and
// a brand-new instance simply starts unfenced (today's REST-handler behavior;
// see docs/instance-generation-fencing.md).
func (t *Tracker) Provision(instanceID string, generation int64, spec json.RawMessage) (inst *Instance, created bool, err error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if ref, ok := t.byID[instanceID]; ok {
		// Defensive: byID and byRef are only ever mutated together under this
		// mutex, so a present id implies a present ref. Guard anyway so a future
		// edit that breaks the invariant re-provisions cleanly instead of
		// panicking on a nil clone.
		if existing, ok := t.byRef[ref]; ok {
			if generation > existing.Generation {
				prevGeneration := existing.Generation
				existing.Generation = generation
				if err := t.persistLocked(); err != nil {
					existing.Generation = prevGeneration // roll back to the last durable generation
					return nil, false, err
				}
			}
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
		Generation: generation,
		CreatedAt:  time.Now().UTC(),
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

// List returns every currently tracked instance, deep-cloned and sorted by
// runtime_ref. It reuses the same snapshotLocked clone-and-sort discipline the
// state file uses, so a listed instance never aliases live tracker state and the
// order is deterministic (stable output, reproducible tests). The result is a
// fresh, non-nil slice — empty when nothing is tracked — so it serializes as an
// empty JSON array rather than null. It is safe for concurrent use.
func (t *Tracker) List() []Instance {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.snapshotLocked().Instances
}

// ListFilter narrows the instances ListFiltered returns. Every non-zero field
// composes with the others via AND; a zero-value ListFilter matches every
// instance, the same result as List().
type ListFilter struct {
	// Status, when non-empty, keeps only instances whose status is exactly this
	// value (an exact match against the wire enum, e.g. "RUNNING" — no
	// case-folding). A destroyed instance is never tracked in the first place
	// (Destroy removes it), so Status: StatusDestroyed always matches nothing.
	Status Status
	// InstanceIDPrefix, when non-empty, keeps only instances whose instance_id
	// has this as a plain string prefix.
	InstanceIDPrefix string
	// CreatedSince, when non-zero, keeps only instances created at or after
	// this instant (inclusive).
	CreatedSince time.Time
}

// ListFiltered is List narrowed by filter: every currently tracked instance
// that matches every non-zero field of filter, deep-cloned and sorted by
// runtime_ref exactly as List() orders them. The result is a fresh, non-nil
// slice — empty when nothing matches — so it serializes as an empty JSON array
// rather than null. It is safe for concurrent use.
func (t *Tracker) ListFiltered(filter ListFilter) []Instance {
	t.mu.Lock()
	defer t.mu.Unlock()
	all := t.snapshotLocked().Instances

	out := make([]Instance, 0, len(all))
	for _, inst := range all {
		if filter.Status != "" && inst.Status != filter.Status {
			continue
		}
		if filter.InstanceIDPrefix != "" && !strings.HasPrefix(inst.InstanceID, filter.InstanceIDPrefix) {
			continue
		}
		if !filter.CreatedSince.IsZero() && inst.CreatedAt.Before(filter.CreatedSince) {
			continue
		}
		out = append(out, inst)
	}
	return out
}

// RefForInstance returns the runtime_ref currently tracked for instanceID, or
// ("", false) when no live instance has that instance_id. It is a locked read of
// the existing byID index and runs no lifecycle logic: it exists so a caller that
// addresses instances by instance_id (the outbound uplink client) can resolve the
// tracker's own runtime_ref and then drive the same transition methods the REST
// handlers already call. A resolve-then-act across two locked calls is safe — if
// the instance is destroyed between this read and the follow-up mutator, that
// mutator returns ErrNotFound, which is the intended "gone" outcome, not a race.
func (t *Tracker) RefForInstance(instanceID string) (runtimeRef string, ok bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	ref, ok := t.byID[instanceID]
	return ref, ok
}

// GenerationForInstance returns the generation currently tracked for
// instanceID, or (0, false) when no live instance has that instance_id. It is a
// locked read of the existing byID/byRef indexes and runs no lifecycle logic:
// it exists so the uplink dispatcher can fence a stale command before dispatch,
// the sibling of RefForInstance for the fence-check path (see
// docs/instance-generation-fencing.md).
func (t *Tracker) GenerationForInstance(instanceID string) (generation int64, ok bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	ref, ok := t.byID[instanceID]
	if !ok {
		return 0, false
	}
	inst, ok := t.byRef[ref]
	if !ok {
		// Defensive: same invariant guard as Provision — byID/byRef are only ever
		// mutated together under this mutex.
		return 0, false
	}
	return inst.Generation, true
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
