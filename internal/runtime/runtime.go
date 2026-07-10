// Package runtime is Steward's tracker for agent-instance lifecycle. State is
// held in memory by default; a tracker built with LoadTracker also persists
// every mutation to a state file so tracked instances survive a restart.
package runtime

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
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

// DefaultStopGracePeriod is how long Stop/Destroy wait after SIGTERM before
// escalating to SIGKILL, when process execution is enabled and no explicit grace
// period is configured. It matches the CLI flag's default.
const DefaultStopGracePeriod = 10 * time.Second

// ErrNotFound is returned when an operation names a runtime_ref the tracker does
// not know. The HTTP layer turns this into a 404.
var ErrNotFound = errors.New("unknown runtime_ref")

// ErrCapacityExceeded is returned by Provision when the tracker already holds
// its maximum number of instances. The HTTP layer turns this into a 503.
var ErrCapacityExceeded = errors.New("instance capacity exceeded")

// ErrInvalidStateTransition is returned by a lifecycle transition (Start,
// Stop, or Hibernate) when the requested target status is not reachable from
// the instance's current status — for example, stopping or hibernating an
// instance that is still PENDING (never started). The HTTP layer turns this
// into a 409, and the outbound uplink reports the command failed rather than
// silently mutating the instance into a nonsensical state. Every wrapping of
// it names the current and requested status so the error tells an operator
// exactly which transition was refused (see transitionAllowed and transition).
var ErrInvalidStateTransition = errors.New("invalid state transition")

// ErrProcessExecDisabled is returned by Provision when a spec carries a "command"
// field (an intent to run a real process) but process execution is disabled at the
// Steward level (-enable-process-exec is off, the default). It is fail-loud on
// purpose: a caller's real intent is rejected, never silently stored and ignored.
// The HTTP layer turns this into a 400 (codeProcessExecDisabled).
var ErrProcessExecDisabled = errors.New("process execution is disabled but the spec has a command")

// ErrInvalidProcessSpec is returned when a spec expresses process-execution intent
// (a "command" field) but is malformed — command not a non-empty string, or
// args/env/working_dir of the wrong JSON type. The HTTP layer turns this into a 400
// (codeInvalidSpec). It is detected at Provision (fail early), and defensively again
// at Start.
var ErrInvalidProcessSpec = errors.New("invalid process spec")

// ErrProcessStart is returned by Start when a valid, allowed start could not spawn
// the configured process (executable not found, permission denied, missing
// working_dir, or a failed resume). The instance is left in its prior status — it is
// NOT falsely reported RUNNING. The HTTP layer turns this into a 400
// (codeProcessStartFailed): the root cause is the caller-supplied command or its
// environment, not a Steward fault, so it is a client-fixable 4xx rather than a 5xx.
var ErrProcessStart = errors.New("process failed to start")

// transitionAllowed reports whether an instance in status `from` may move to
// status `to` via a Start (→RUNNING), Stop (→STOPPED), or Hibernate
// (→HIBERNATED) operation. Destroy is not routed through here — a live
// instance can always be destroyed — and Provision has its own idempotency
// path, so this governs only the three transition verbs.
//
// The table encodes one rule beyond the always-allowed self-transition: a
// PENDING instance has never run, so it can only be started (or destroyed);
// stopping or hibernating a never-started instance is rejected rather than
// recording a nonsensical STOPPED/HIBERNATED. Once an instance has run at
// least once (RUNNING, STOPPED, or HIBERNATED) any of start/stop/hibernate is
// allowed, matching the loose lifecycle the control plane drives — Steward
// mirrors that state machine (see the Status doc comment), it does not impose
// a stricter one. A status not covered below (FAILED, which Steward never
// emits itself, or any future addition) permits no transition: fail-closed,
// the house default.
//
// A self-transition (from == to) is always allowed and is the load-bearing
// idempotency guarantee, not an oversight: an at-least-once-redelivered start
// whose report was lost — the server redelivers it and the instance is already
// RUNNING — must report done, not a spurious failure; a retried batch's
// start/stop must "converge on the same terminal status either way"
// (ARCHITECTURE.md). Rejecting a self-transition would break both, and the
// double-invoke covenant they rest on.
func transitionAllowed(from, to Status) bool {
	if from == to {
		return true // idempotent no-op: redelivery- and retry-safe.
	}
	switch to {
	case StatusRunning: // start: from any non-terminal status, including a never-started PENDING.
		switch from {
		case StatusPending, StatusStopped, StatusHibernated:
			return true
		}
	case StatusStopped: // stop: only an instance that has run — never a PENDING one.
		switch from {
		case StatusRunning, StatusHibernated:
			return true
		}
	case StatusHibernated: // hibernate: only an instance that has run — never a PENDING one.
		switch from {
		case StatusRunning, StatusStopped:
			return true
		}
	}
	return false
}

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
// The four process-supervision fields (PID, LastExitCode, LastExitReason) are
// additive and populated only when process execution is enabled and the instance
// carries a command spec; for every other instance they stay zero and are omitted
// from the wire and the state file. Like CreatedAt and Generation before them, they
// need no state-file format-version bump: a snapshot written before they existed
// simply lacks the keys and decodes to their zero values (see the CreatedAt doc
// comment and docs). PID is the OS pid of the currently supervised process (0 when
// none), persisted so a best-effort liveness check can run after a restart.
// LastExitCode/LastExitReason record the most recent process exit so an operator can
// tell a crash ("crashed") from a requested stop ("stopped"/"killed") or lost
// supervision ("supervision_lost") — a distinction the Status field cannot carry,
// since Steward never emits FAILED and every non-running end state is STOPPED.
// LastExitCode is a *int so a clean exit (0) is distinguishable from "never exited"
// (nil/absent).
type Instance struct {
	InstanceID     string          `json:"instance_id"`
	RuntimeRef     string          `json:"runtime_ref"`
	Status         Status          `json:"status"`
	Generation     int64           `json:"generation,omitempty"`
	CreatedAt      time.Time       `json:"created_at"`
	Spec           json.RawMessage `json:"spec,omitempty"`
	PID            int             `json:"pid,omitempty"`
	LastExitCode   *int            `json:"last_exit_code,omitempty"`
	LastExitReason string          `json:"last_exit_reason,omitempty"`
}

func (i *Instance) clone() *Instance {
	c := *i
	if i.Spec != nil {
		c.Spec = append(json.RawMessage(nil), i.Spec...)
	}
	if i.LastExitCode != nil {
		v := *i.LastExitCode
		c.LastExitCode = &v
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

	// Process supervision — all opt-in and zero-valued unless WithExec turns it on
	// (see exec.go). When execEnabled is false (the default), every lifecycle
	// transition stays the pure status mutation it has always been, procs stays
	// empty, and none of the process logic runs. logger is never nil: it defaults to
	// a discard handler so exec.go can log unconditionally.
	execEnabled     bool
	stopGracePeriod time.Duration
	logger          *slog.Logger
	procs           map[string]*supervisedProcess // live processes by runtime_ref; guarded by mu
}

// Option configures a Tracker at construction. Options are the backward-compatible
// seam for opt-in features (process supervision today): a tracker built with no
// options is the pure status tracker Steward has always been, so every existing
// NewTracker/LoadTracker call site is unaffected.
type Option func(*Tracker)

// ExecConfig turns on real OS-process supervision for instances whose spec carries a
// "command" field. Enabled is the master switch (-enable-process-exec);
// StopGracePeriod is how long Stop/Destroy wait after SIGTERM before escalating to
// SIGKILL (non-positive keeps DefaultStopGracePeriod); Logger receives the process
// lifecycle events (nil keeps the discard default). See exec.go and ARCHITECTURE.md.
type ExecConfig struct {
	Enabled         bool
	StopGracePeriod time.Duration
	Logger          *slog.Logger
}

// WithExec applies an ExecConfig to a tracker under construction.
func WithExec(cfg ExecConfig) Option {
	return func(t *Tracker) {
		t.execEnabled = cfg.Enabled
		if cfg.StopGracePeriod > 0 {
			t.stopGracePeriod = cfg.StopGracePeriod
		}
		if cfg.Logger != nil {
			t.logger = cfg.Logger
		}
	}
}

// NewTracker returns an in-memory tracker that holds at most maxInstances instances
// and never persists; a restart loses all tracked state. A non-positive
// maxInstances is replaced with DefaultMaxInstances. Use LoadTracker for durable
// state. Optional Options (WithExec) enable opt-in features.
func NewTracker(maxInstances int, opts ...Option) *Tracker {
	return newTracker(maxInstances, "", opts...)
}

// newTracker is the shared constructor for NewTracker and LoadTracker. An empty
// stateFile disables persistence.
func newTracker(maxInstances int, stateFile string, opts ...Option) *Tracker {
	if maxInstances <= 0 {
		maxInstances = DefaultMaxInstances
	}
	t := &Tracker{
		byRef:           make(map[string]*Instance),
		byID:            make(map[string]string),
		maxInstances:    maxInstances,
		stateFile:       stateFile,
		stopGracePeriod: DefaultStopGracePeriod,
		logger:          slog.New(slog.DiscardHandler),
		procs:           make(map[string]*supervisedProcess),
	}
	for _, opt := range opts {
		opt(t)
	}
	return t
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
	// Process-exec opt-in gate. A spec carrying a "command" field expresses intent to
	// run a real process. If process execution is disabled, that intent is REJECTED
	// loudly (never silently stored and later ignored). If it is enabled, the process
	// spec is validated now so a malformed command fails at provision, not only at
	// the first start. A spec with no command field is the historical opaque blob and
	// is unaffected either way, so an existing caller provisioning arbitrary config is
	// exactly as before. This runs before the idempotency lookup on purpose: a
	// command-bearing spec must be rejected under a disabled Steward regardless of
	// whether the instance_id happens to already exist.
	_, hasCommand, specErr := parseProcessSpec(spec)
	if hasCommand && !t.execEnabled {
		return nil, false, ErrProcessExecDisabled
	}
	if hasCommand && specErr != nil {
		return nil, false, fmt.Errorf("%w: %v", ErrInvalidProcessSpec, specErr)
	}

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
// takes the lock because SetMaxInstances can update the cap live (a SIGHUP config
// reload), so a lock-free read would race that write — the race detector would
// flag it, and GET /v1/capabilities reads this on every request concurrently with
// a reload.
func (t *Tracker) MaxInstances() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.maxInstances
}

// SetMaxInstances updates the tracker's live capacity cap. It does not evict or
// otherwise touch any already-tracked instance, even when lowering the cap below
// the current instance count: Provision's existing capacity check
// (len(t.byRef) >= t.maxInstances) already blocks *new* provisions once the count
// reaches the new, lower ceiling, and every existing instance is left exactly as
// it was. This is the same "circuit breaker on growth, not on reload" posture
// load() already applies to a state file that holds more instances than its cap
// (see persist.go): a lowered cap stops the tracker growing further and lets the
// count drain back under the ceiling through ordinary Destroy attrition, rather
// than force-stopping live instances — which would turn an operator's capacity
// re-tune into an outage.
//
// Validating maxInstances is the caller's responsibility, matching every other
// operator-facing config boundary in this codebase (see cmd/steward/main.go's
// -max-instances check in prepareRuntime, and reloadMaxInstances for the SIGHUP
// path): this method does NOT silently substitute DefaultMaxInstances the way the
// newTracker constructor's non-positive convenience does, because a caller here
// already holds a validated value and a silent substitution would mask a
// misconfiguration instead of surfacing it.
func (t *Tracker) SetMaxInstances(maxInstances int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.maxInstances = maxInstances
}

// Durable reports whether this tracker persists its state to a file. It exposes
// only whether persistence is enabled, never the file path, so a caller can
// advertise durability (for example in GET /v1/capabilities) without leaking a
// local filesystem path. stateFile is fixed at construction and never mutated
// afterward, so it needs no lock.
func (t *Tracker) Durable() bool {
	return t.stateFile != ""
}

// Start, Stop, and Hibernate route to the pure in-memory transition when process
// execution is disabled (the default) — byte-for-byte the behavior Steward has
// always had — and to the process-aware path (see exec.go) when it is enabled. The
// process-aware path still falls back to a pure transition for an instance whose
// spec carries no command, so an opaque instance under an exec-enabled Steward is
// unaffected too.

func (t *Tracker) Start(runtimeRef string) (*Instance, error) {
	if !t.execEnabled {
		return t.transition(runtimeRef, StatusRunning)
	}
	return t.startExec(runtimeRef)
}

func (t *Tracker) Stop(runtimeRef string) (*Instance, error) {
	if !t.execEnabled {
		return t.transition(runtimeRef, StatusStopped)
	}
	return t.stopExec(runtimeRef)
}

func (t *Tracker) Hibernate(runtimeRef string) (*Instance, error) {
	if !t.execEnabled {
		return t.transition(runtimeRef, StatusHibernated)
	}
	return t.hibernateExec(runtimeRef)
}

// Destroy removes the instance and releases its instance_id for reuse. A later
// Provision with the same instance_id creates a new, unrelated instance with a
// fresh runtime_ref rather than erroring or resurrecting the destroyed one; the
// idempotency guarantee therefore covers only an instance's live span, not a
// span that straddles a Destroy. This release-on-destroy is intentional: the
// caller treats a destroyed instance_id as free to reuse.
func (t *Tracker) Destroy(runtimeRef string) (*Instance, error) {
	t.mu.Lock()

	inst, ok := t.byRef[runtimeRef]
	if !ok {
		t.mu.Unlock()
		return nil, ErrNotFound
	}
	// A tracked real process (only ever present when process execution is enabled) is
	// terminated regardless of the instance's current status. Latch the coming exit
	// as intentional first, so its monitor does not race a crash transition, then
	// remove tracking and persist under the lock, and finally terminate the process
	// AFTER releasing the lock — terminate can block up to the grace period and must
	// not freeze the tracker. When exec is disabled, sp is always nil and this is the
	// pure removal Destroy has always been.
	sp := t.procs[runtimeRef]
	if sp != nil {
		sp.markIntentional()
	}
	prevStatus := inst.Status
	inst.Status = StatusDestroyed
	delete(t.byRef, runtimeRef)
	delete(t.byID, inst.InstanceID)
	delete(t.procs, runtimeRef)
	if err := t.persistLocked(); err != nil {
		// Roll back the removal so memory matches the last durable state.
		inst.Status = prevStatus
		t.byRef[runtimeRef] = inst
		t.byID[inst.InstanceID] = runtimeRef
		if sp != nil {
			t.procs[runtimeRef] = sp
		}
		t.mu.Unlock()
		return nil, err
	}
	out := inst.clone()
	t.mu.Unlock()

	if sp != nil {
		exitCode, reason := sp.terminate(t.stopGracePeriod)
		t.logger.Info("destroyed instance and terminated its supervised process",
			"runtime_ref", runtimeRef, "instance_id", out.InstanceID, "exit_code", exitCode, "reason", reason)
	}
	return out, nil
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

// StatusCounts returns the number of currently tracked instances in each
// status, keyed by Status. Unlike List, it does not clone or sort individual
// instances — it is a locked read of byRef that only tallies the Status field
// — so it is cheap enough for a frequently-scraped /metrics endpoint even
// though it still touches every tracked instance once. Only statuses with at
// least one live instance appear as keys; the caller treats an absent key as
// zero. A destroyed instance is never tracked (Destroy removes it from
// byRef), so StatusDestroyed never appears here.
func (t *Tracker) StatusCounts() map[Status]int {
	t.mu.Lock()
	defer t.mu.Unlock()
	counts := make(map[Status]int)
	for _, inst := range t.byRef {
		counts[inst.Status]++
	}
	return counts
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
	if !transitionAllowed(inst.Status, status) {
		// Name the current and requested status so the 409 (REST) and the uplink
		// failure log say exactly which transition was refused — the 3am test.
		return nil, fmt.Errorf("%w: %s cannot become %s", ErrInvalidStateTransition, inst.Status, status)
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
