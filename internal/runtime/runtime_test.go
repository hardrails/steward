package runtime

import (
	"encoding/json"
	"errors"
	"sync"
	"testing"
)

func TestProvisionCreatesInstance(t *testing.T) {
	tr := NewTracker(0)
	spec := json.RawMessage(`{"model":"opus","memory_mb":512}`)

	inst, created, err := tr.Provision("agent-1", 0, spec)
	if err != nil {
		t.Fatalf("provision: unexpected err %v", err)
	}

	if !created {
		t.Fatal("first provision must report created=true")
	}
	if inst.InstanceID != "agent-1" {
		t.Fatalf("instance_id = %q, want agent-1", inst.InstanceID)
	}
	if inst.RuntimeRef == "" {
		t.Fatal("runtime_ref must be non-empty")
	}
	if inst.Status != StatusPending {
		t.Fatalf("status = %q, want PENDING", inst.Status)
	}
	if string(inst.Spec) != string(spec) {
		t.Fatalf("spec = %s, want verbatim round-trip %s", inst.Spec, spec)
	}
}

func TestProvisionIdempotentOnInstanceID(t *testing.T) {
	tr := NewTracker(0)

	first, created1, err1 := tr.Provision("agent-1", 0, json.RawMessage(`{"a":1}`))
	second, created2, err2 := tr.Provision("agent-1", 0, json.RawMessage(`{"b":2}`))
	if err1 != nil || err2 != nil {
		t.Fatalf("provision: unexpected errs %v, %v", err1, err2)
	}

	if !created1 {
		t.Fatal("first provision must report created=true")
	}
	if created2 {
		t.Fatal("repeated provision must report created=false")
	}
	if first.RuntimeRef != second.RuntimeRef {
		t.Fatalf("runtime_ref changed on repeat: %q != %q", first.RuntimeRef, second.RuntimeRef)
	}
	if len(tr.byRef) != 1 {
		t.Fatalf("tracker holds %d instances, want 1", len(tr.byRef))
	}
	// The second spec is ignored; the existing instance is returned unchanged.
	if string(second.Spec) != `{"a":1}` {
		t.Fatalf("spec = %s, want the original {\"a\":1}", second.Spec)
	}
}

func TestLifecycleTransitions(t *testing.T) {
	tr := NewTracker(0)
	inst, _, _ := tr.Provision("agent-1", 0, nil)
	ref := inst.RuntimeRef

	started, err := tr.Start(ref)
	if err != nil || started.Status != StatusRunning {
		t.Fatalf("start: status=%q err=%v, want RUNNING nil", started.Status, err)
	}

	stopped, err := tr.Stop(ref)
	if err != nil || stopped.Status != StatusStopped {
		t.Fatalf("stop: status=%q err=%v, want STOPPED nil", stopped.Status, err)
	}

	hibernated, err := tr.Hibernate(ref)
	if err != nil || hibernated.Status != StatusHibernated {
		t.Fatalf("hibernate: status=%q err=%v, want HIBERNATED nil", hibernated.Status, err)
	}

	destroyed, err := tr.Destroy(ref)
	if err != nil || destroyed.Status != StatusDestroyed {
		t.Fatalf("destroy: status=%q err=%v, want DESTROYED nil", destroyed.Status, err)
	}

	if _, err := tr.Status(ref); !errors.Is(err, ErrNotFound) {
		t.Fatalf("status after destroy: err=%v, want ErrNotFound", err)
	}
}

func TestUnknownRuntimeRefIsNotFound(t *testing.T) {
	tr := NewTracker(0)
	const unknown = "rt_does_not_exist"

	ops := map[string]func(string) (*Instance, error){
		"status":    tr.Status,
		"start":     tr.Start,
		"stop":      tr.Stop,
		"hibernate": tr.Hibernate,
		"destroy":   tr.Destroy,
	}
	for name, op := range ops {
		if _, err := op(unknown); !errors.Is(err, ErrNotFound) {
			t.Fatalf("%s(unknown): err=%v, want ErrNotFound", name, err)
		}
	}
}

func TestConcurrentProvisionCreatesOnlyOne(t *testing.T) {
	tr := NewTracker(0)
	const goroutines = 64

	var wg sync.WaitGroup
	refs := make([]string, goroutines)
	createdFlags := make([]bool, goroutines)

	start := make(chan struct{})
	for i := range goroutines {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-start
			inst, created, err := tr.Provision("agent-1", 0, json.RawMessage(`{}`))
			if err != nil {
				t.Errorf("provision: unexpected err %v", err)
				return
			}
			refs[idx] = inst.RuntimeRef
			createdFlags[idx] = created
		}(i)
	}
	close(start)
	wg.Wait()

	createdCount := 0
	for _, c := range createdFlags {
		if c {
			createdCount++
		}
	}
	if createdCount != 1 {
		t.Fatalf("created=true reported %d times, want exactly 1", createdCount)
	}
	for i, ref := range refs {
		if ref != refs[0] {
			t.Fatalf("goroutine %d saw runtime_ref %q, want %q", i, ref, refs[0])
		}
	}
	if len(tr.byRef) != 1 {
		t.Fatalf("tracker holds %d instances, want 1", len(tr.byRef))
	}
}

func TestSpecIsDefensivelyCopied(t *testing.T) {
	tr := NewTracker(0)
	spec := json.RawMessage(`{"k":"v"}`)
	inst, _, _ := tr.Provision("agent-1", 0, spec)

	// Mutating the caller's slice must not corrupt tracked state.
	spec[2] = 'X'
	got, err := tr.Status(inst.RuntimeRef)
	if err != nil {
		t.Fatalf("status: unexpected err %v", err)
	}
	if string(got.Spec) != `{"k":"v"}` {
		t.Fatalf("spec = %s, want tracker copy unaffected by caller mutation", got.Spec)
	}
}

func TestProvisionCapacityExceeded(t *testing.T) {
	tr := NewTracker(2)

	if _, _, err := tr.Provision("a", 0, nil); err != nil {
		t.Fatalf("provision a: %v", err)
	}
	if _, _, err := tr.Provision("b", 0, nil); err != nil {
		t.Fatalf("provision b: %v", err)
	}
	if _, _, err := tr.Provision("c", 0, nil); !errors.Is(err, ErrCapacityExceeded) {
		t.Fatalf("provision c: err=%v, want ErrCapacityExceeded", err)
	}

	// Re-provisioning an already-tracked instance must still succeed at capacity;
	// it does not grow the map.
	if _, created, err := tr.Provision("a", 0, nil); err != nil || created {
		t.Fatalf("reprovision a at capacity: created=%v err=%v, want false nil", created, err)
	}
}

func TestMaxInstancesReportsConfiguredCap(t *testing.T) {
	if got := NewTracker(7).MaxInstances(); got != 7 {
		t.Fatalf("MaxInstances() = %d, want the configured 7", got)
	}
	// A non-positive cap falls back to the default, and the accessor reports it.
	if got := NewTracker(0).MaxInstances(); got != DefaultMaxInstances {
		t.Fatalf("MaxInstances() = %d, want DefaultMaxInstances (%d)", got, DefaultMaxInstances)
	}
}

// TestSetMaxInstancesUpdatesLiveCap pins the SIGHUP hot-reload's runtime half:
// SetMaxInstances changes the cap Provision enforces and MaxInstances reports,
// and — critically — lowering it below the live instance count evicts nothing: the
// already-tracked instances stay, and only new provisions are blocked until the
// count drains back under the new ceiling. This is the "circuit breaker on growth,
// not on reload" behavior the SIGHUP path relies on.
func TestSetMaxInstancesUpdatesLiveCap(t *testing.T) {
	tr := NewTracker(2)

	if _, _, err := tr.Provision("a", 0, nil); err != nil {
		t.Fatalf("provision a: %v", err)
	}
	if _, _, err := tr.Provision("b", 0, nil); err != nil {
		t.Fatalf("provision b: %v", err)
	}
	// At capacity: a new provision is refused today.
	if _, _, err := tr.Provision("c", 0, nil); !errors.Is(err, ErrCapacityExceeded) {
		t.Fatalf("provision c at cap 2: err=%v, want ErrCapacityExceeded", err)
	}

	// Raise the cap: the accessor reports it and the previously-blocked provision
	// now succeeds.
	tr.SetMaxInstances(3)
	if got := tr.MaxInstances(); got != 3 {
		t.Fatalf("MaxInstances() = %d after raise, want 3", got)
	}
	if _, created, err := tr.Provision("c", 0, nil); err != nil || !created {
		t.Fatalf("provision c after raising cap: created=%v err=%v, want true nil", created, err)
	}

	// Lower the cap below the live count (3 tracked, new cap 2). Nothing is
	// evicted: every instance is still present and a new provision is refused.
	tr.SetMaxInstances(2)
	if got := tr.MaxInstances(); got != 2 {
		t.Fatalf("MaxInstances() = %d after lower, want 2", got)
	}
	if got := tr.Len(); got != 3 {
		t.Fatalf("Len() = %d after lowering the cap, want 3 (no eviction)", got)
	}
	for _, id := range []string{"a", "b", "c"} {
		if _, ok := tr.RefForInstance(id); !ok {
			t.Errorf("instance %q was evicted by lowering the cap; it must survive", id)
		}
	}
	if _, _, err := tr.Provision("d", 0, nil); !errors.Is(err, ErrCapacityExceeded) {
		t.Fatalf("provision d over the lowered cap: err=%v, want ErrCapacityExceeded", err)
	}

	// Attrition drains the count back under the ceiling: with cap 2, a new
	// provision needs the count below 2, so destroying two of the three tracked
	// instances (count → 1) lets a new one fit again — the ceiling was never an
	// eviction, just a growth block until the count came down naturally.
	for _, id := range []string{"a", "b"} {
		ref, _ := tr.RefForInstance(id)
		if _, err := tr.Destroy(ref); err != nil {
			t.Fatalf("destroy %q: %v", id, err)
		}
	}
	if _, created, err := tr.Provision("d", 0, nil); err != nil || !created {
		t.Fatalf("provision d after attrition: created=%v err=%v, want true nil", created, err)
	}
}

func TestDurableReflectsPersistenceMode(t *testing.T) {
	if NewTracker(0).Durable() {
		t.Fatal("Durable() = true for an in-memory tracker, want false")
	}
	tr, _ := stateBoundTracker(t, 0)
	if !tr.Durable() {
		t.Fatal("Durable() = false for a state-file-backed tracker, want true")
	}
}

func TestRefForInstanceResolvesTrackedInstance(t *testing.T) {
	tr := NewTracker(0)
	inst, _, err := tr.Provision("agent-1", 0, nil)
	if err != nil {
		t.Fatalf("provision: %v", err)
	}

	ref, ok := tr.RefForInstance("agent-1")
	if !ok {
		t.Fatal("RefForInstance(agent-1): ok=false, want true for a tracked instance")
	}
	if ref != inst.RuntimeRef {
		t.Fatalf("RefForInstance(agent-1) = %q, want the tracked runtime_ref %q", ref, inst.RuntimeRef)
	}
}

func TestRefForInstanceUnknownIDReportsNotOk(t *testing.T) {
	tr := NewTracker(0)

	if ref, ok := tr.RefForInstance("never-provisioned"); ok || ref != "" {
		t.Fatalf("RefForInstance(unknown) = (%q, %v), want (\"\", false)", ref, ok)
	}

	// After a destroy the instance_id is released, so RefForInstance stops
	// resolving it — the resolve-then-act "gone" outcome the uplink relies on.
	inst, _, err := tr.Provision("agent-1", 0, nil)
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	if _, err := tr.Destroy(inst.RuntimeRef); err != nil {
		t.Fatalf("destroy: %v", err)
	}
	if ref, ok := tr.RefForInstance("agent-1"); ok || ref != "" {
		t.Fatalf("RefForInstance after destroy = (%q, %v), want (\"\", false)", ref, ok)
	}
}

func TestDestroyReleasesInstanceIDForReuse(t *testing.T) {
	tr := NewTracker(0)

	first, _, err := tr.Provision("agent-1", 0, nil)
	if err != nil {
		t.Fatalf("first provision: %v", err)
	}
	if _, err := tr.Destroy(first.RuntimeRef); err != nil {
		t.Fatalf("destroy: %v", err)
	}

	// A provision after destroy creates a new, unrelated instance with a fresh
	// runtime_ref rather than resurrecting the old one.
	second, created, err := tr.Provision("agent-1", 0, nil)
	if err != nil {
		t.Fatalf("second provision: %v", err)
	}
	if !created {
		t.Fatal("provision after destroy must report created=true (new instance)")
	}
	if second.RuntimeRef == first.RuntimeRef {
		t.Fatal("provision after destroy must assign a fresh runtime_ref")
	}
}

// TestProvisionGenerationSetForNewInstance pins task 2's first acceptance check:
// provisioning a new id sets its generation to the value the caller carried.
func TestProvisionGenerationSetForNewInstance(t *testing.T) {
	tr := NewTracker(0)
	inst, _, err := tr.Provision("agent-1", 3, nil)
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	if inst.Generation != 3 {
		t.Fatalf("generation = %d, want 3", inst.Generation)
	}
}

// TestProvisionGenerationNeverLowered pins task 2's core rule: a re-provision
// with a lower generation than the tracked one leaves it unchanged, and a
// re-provision with a higher generation raises it — max(existing, generation),
// never lowered, regardless of caller.
func TestProvisionGenerationNeverLowered(t *testing.T) {
	tr := NewTracker(0)
	inst, _, err := tr.Provision("agent-1", 5, nil)
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	if inst.Generation != 5 {
		t.Fatalf("initial generation = %d, want 5", inst.Generation)
	}

	// A lower generation on re-provision must not lower the tracked one.
	lower, created, err := tr.Provision("agent-1", 2, nil)
	if err != nil {
		t.Fatalf("reprovision with lower generation: %v", err)
	}
	if created {
		t.Fatal("reprovision must report created=false")
	}
	if lower.Generation != 5 {
		t.Fatalf("generation after a lower reprovision = %d, want unchanged 5", lower.Generation)
	}

	// A higher generation on re-provision must raise the tracked one.
	higher, _, err := tr.Provision("agent-1", 9, nil)
	if err != nil {
		t.Fatalf("reprovision with higher generation: %v", err)
	}
	if higher.Generation != 9 {
		t.Fatalf("generation after a higher reprovision = %d, want raised to 9", higher.Generation)
	}
}

// TestProvisionGenerationZeroLeavesExistingUntouched pins the REST-handler
// compatibility case: passing generation 0 (the direct-REST path's "no fencing"
// value) to Provision for an already-tracked instance must not lower or zero an
// existing non-zero generation.
func TestProvisionGenerationZeroLeavesExistingUntouched(t *testing.T) {
	tr := NewTracker(0)
	if _, _, err := tr.Provision("agent-1", 4, nil); err != nil {
		t.Fatalf("provision: %v", err)
	}
	again, created, err := tr.Provision("agent-1", 0, nil)
	if err != nil {
		t.Fatalf("reprovision with generation 0: %v", err)
	}
	if created {
		t.Fatal("reprovision must report created=false")
	}
	if again.Generation != 4 {
		t.Fatalf("generation after a generation-0 reprovision = %d, want unchanged 4", again.Generation)
	}
}

// TestGenerationForInstanceResolvesTrackedInstance mirrors
// TestRefForInstanceResolvesTrackedInstance for the generation accessor.
func TestGenerationForInstanceResolvesTrackedInstance(t *testing.T) {
	tr := NewTracker(0)
	if _, _, err := tr.Provision("agent-1", 7, nil); err != nil {
		t.Fatalf("provision: %v", err)
	}

	gen, ok := tr.GenerationForInstance("agent-1")
	if !ok {
		t.Fatal("GenerationForInstance(agent-1): ok=false, want true for a tracked instance")
	}
	if gen != 7 {
		t.Fatalf("GenerationForInstance(agent-1) = %d, want 7", gen)
	}
}

// TestGenerationForInstanceUnknownIDReportsNotOk mirrors
// TestRefForInstanceUnknownIDReportsNotOk for the generation accessor: an
// unknown id, and an id whose instance has since been destroyed, both report
// (0, false).
func TestGenerationForInstanceUnknownIDReportsNotOk(t *testing.T) {
	tr := NewTracker(0)

	if gen, ok := tr.GenerationForInstance("never-provisioned"); ok || gen != 0 {
		t.Fatalf("GenerationForInstance(unknown) = (%d, %v), want (0, false)", gen, ok)
	}

	inst, _, err := tr.Provision("agent-1", 2, nil)
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	if _, err := tr.Destroy(inst.RuntimeRef); err != nil {
		t.Fatalf("destroy: %v", err)
	}
	if gen, ok := tr.GenerationForInstance("agent-1"); ok || gen != 0 {
		t.Fatalf("GenerationForInstance after destroy = (%d, %v), want (0, false)", gen, ok)
	}
}

// TestListEmptyReturnsNonNilSlice pins that an empty tracker lists a non-nil,
// zero-length slice, so the HTTP layer serializes it as [] rather than null.
func TestListEmptyReturnsNonNilSlice(t *testing.T) {
	tr := NewTracker(0)
	got := tr.List()
	if got == nil {
		t.Fatal("List() on empty tracker = nil, want a non-nil empty slice")
	}
	if len(got) != 0 {
		t.Fatalf("List() on empty tracker has %d instances, want 0", len(got))
	}
}

// TestListReturnsAllSortedByRuntimeRef pins the core List() contract: every
// tracked instance appears exactly once, and the slice is sorted ascending by
// runtime_ref (the same deterministic order snapshotLocked writes to disk).
func TestListReturnsAllSortedByRuntimeRef(t *testing.T) {
	tr := NewTracker(0)

	want := make(map[string]bool)
	for _, id := range []string{"agent-1", "agent-2", "agent-3", "agent-4"} {
		inst, _, err := tr.Provision(id, 0, json.RawMessage(`{"id":"`+id+`"}`))
		if err != nil {
			t.Fatalf("provision %q: %v", id, err)
		}
		want[inst.RuntimeRef] = true
	}

	list := tr.List()
	if len(list) != len(want) {
		t.Fatalf("List() returned %d instances, want %d", len(list), len(want))
	}
	for i := 1; i < len(list); i++ {
		if list[i-1].RuntimeRef >= list[i].RuntimeRef {
			t.Fatalf("List() not sorted by runtime_ref: %q >= %q at index %d",
				list[i-1].RuntimeRef, list[i].RuntimeRef, i)
		}
	}
	for _, inst := range list {
		if !want[inst.RuntimeRef] {
			t.Fatalf("List() returned unexpected runtime_ref %q", inst.RuntimeRef)
		}
		delete(want, inst.RuntimeRef)
	}
	if len(want) != 0 {
		t.Fatalf("List() omitted %d provisioned instances: %v", len(want), want)
	}
}

// TestListReturnsIndependentCopies pins that the listed instances are deep
// clones: mutating a returned element (its status or its spec bytes) must not
// corrupt live tracker state. This is the careless-caller guard — a consumer
// that scribbles on the list cannot poison the tracker.
func TestListReturnsIndependentCopies(t *testing.T) {
	tr := NewTracker(0)
	inst, _, err := tr.Provision("agent-1", 0, json.RawMessage(`{"k":"v"}`))
	if err != nil {
		t.Fatalf("provision: %v", err)
	}

	list := tr.List()
	if len(list) != 1 {
		t.Fatalf("List() returned %d instances, want 1", len(list))
	}
	list[0].Status = StatusDestroyed
	list[0].Spec[2] = 'X'

	got, err := tr.Status(inst.RuntimeRef)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if got.Status != StatusPending {
		t.Fatalf("tracked status = %q after mutating a List() copy, want unchanged PENDING", got.Status)
	}
	if string(got.Spec) != `{"k":"v"}` {
		t.Fatalf("tracked spec = %s after mutating a List() copy, want unchanged", got.Spec)
	}
}
