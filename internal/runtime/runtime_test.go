package runtime

import (
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"
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
// TestProvisionSetsCreatedAt pins that a freshly created instance gets a
// non-zero CreatedAt close to "now", and that CreatedAt survives clone()
// unchanged.
func TestProvisionSetsCreatedAt(t *testing.T) {
	tr := NewTracker(0)
	before := time.Now().Add(-time.Second)
	inst, _, err := tr.Provision("agent-1", 0, nil)
	after := time.Now().Add(time.Second)
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	if inst.CreatedAt.IsZero() {
		t.Fatal("CreatedAt is zero, want a real timestamp")
	}
	if inst.CreatedAt.Before(before) || inst.CreatedAt.After(after) {
		t.Fatalf("CreatedAt = %v, want between %v and %v", inst.CreatedAt, before, after)
	}
}

// TestReprovisionPreservesOriginalCreatedAt pins that re-provisioning an
// already-tracked instance_id (the idempotent path) returns the ORIGINAL
// CreatedAt, not a fresh one — CreatedAt marks when the tracked instance was
// first created, not when it was last provisioned.
func TestReprovisionPreservesOriginalCreatedAt(t *testing.T) {
	tr := NewTracker(0)
	first, _, err := tr.Provision("agent-1", 0, nil)
	if err != nil {
		t.Fatalf("first provision: %v", err)
	}

	second, created, err := tr.Provision("agent-1", 0, nil)
	if err != nil {
		t.Fatalf("reprovision: %v", err)
	}
	if created {
		t.Fatal("reprovision must report created=false")
	}
	if !second.CreatedAt.Equal(first.CreatedAt) {
		t.Fatalf("CreatedAt changed on reprovision: %v != %v", second.CreatedAt, first.CreatedAt)
	}
}

// TestDestroyThenReprovisionGetsFreshCreatedAt pins the complementary case: a
// genuinely new instance (a different runtime_ref, minted after Destroy
// released the instance_id) gets its own fresh CreatedAt rather than
// inheriting the destroyed instance's.
func TestDestroyThenReprovisionGetsFreshCreatedAt(t *testing.T) {
	tr := NewTracker(0)
	first, _, err := tr.Provision("agent-1", 0, nil)
	if err != nil {
		t.Fatalf("first provision: %v", err)
	}
	if _, err := tr.Destroy(first.RuntimeRef); err != nil {
		t.Fatalf("destroy: %v", err)
	}

	time.Sleep(time.Millisecond)
	second, created, err := tr.Provision("agent-1", 0, nil)
	if err != nil {
		t.Fatalf("second provision: %v", err)
	}
	if !created {
		t.Fatal("provision after destroy must report created=true")
	}
	if !second.CreatedAt.After(first.CreatedAt) {
		t.Fatalf("second CreatedAt %v must be after first CreatedAt %v", second.CreatedAt, first.CreatedAt)
	}
}

// TestListFilteredZeroValueMatchesList pins that ListFiltered with a
// zero-value ListFilter returns exactly what List() returns.
func TestListFilteredZeroValueMatchesList(t *testing.T) {
	tr := NewTracker(0)
	for _, id := range []string{"a", "b", "c"} {
		if _, _, err := tr.Provision(id, 0, nil); err != nil {
			t.Fatalf("provision %q: %v", id, err)
		}
	}

	want := tr.List()
	got := tr.ListFiltered(ListFilter{})
	if len(got) != len(want) {
		t.Fatalf("ListFiltered(zero value) returned %d instances, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].RuntimeRef != want[i].RuntimeRef {
			t.Fatalf("order mismatch at %d: ListFiltered %q, List %q", i, got[i].RuntimeRef, want[i].RuntimeRef)
		}
	}
}

// TestListFilteredByStatus pins the status filter alone: only instances in
// exactly that status are returned.
func TestListFilteredByStatus(t *testing.T) {
	tr := NewTracker(0)
	running, _, err := tr.Provision("running-1", 0, nil)
	if err != nil {
		t.Fatalf("provision running-1: %v", err)
	}
	if _, err := tr.Start(running.RuntimeRef); err != nil {
		t.Fatalf("start running-1: %v", err)
	}
	if _, _, err := tr.Provision("pending-1", 0, nil); err != nil {
		t.Fatalf("provision pending-1: %v", err)
	}

	got := tr.ListFiltered(ListFilter{Status: StatusRunning})
	if len(got) != 1 || got[0].InstanceID != "running-1" {
		t.Fatalf("ListFiltered(status=RUNNING) = %+v, want exactly running-1", got)
	}
}

// TestListFilteredByInstanceIDPrefix pins the instance_id_prefix filter alone:
// a plain string-prefix match.
func TestListFilteredByInstanceIDPrefix(t *testing.T) {
	tr := NewTracker(0)
	for _, id := range []string{"web-1", "web-2", "worker-1"} {
		if _, _, err := tr.Provision(id, 0, nil); err != nil {
			t.Fatalf("provision %q: %v", id, err)
		}
	}

	got := tr.ListFiltered(ListFilter{InstanceIDPrefix: "web-"})
	if len(got) != 2 {
		t.Fatalf("ListFiltered(prefix=web-) returned %d instances, want 2: %+v", len(got), got)
	}
	for _, inst := range got {
		if inst.InstanceID != "web-1" && inst.InstanceID != "web-2" {
			t.Fatalf("ListFiltered(prefix=web-) returned unexpected instance_id %q", inst.InstanceID)
		}
	}
}

// TestListFilteredByCreatedSince pins the created_since filter alone:
// inclusive of instances created exactly at the boundary, exclusive of
// instances created before it.
func TestListFilteredByCreatedSince(t *testing.T) {
	tr := NewTracker(0)
	if _, _, err := tr.Provision("old-1", 0, nil); err != nil {
		t.Fatalf("provision old-1: %v", err)
	}
	time.Sleep(2 * time.Millisecond)
	boundary := time.Now()
	time.Sleep(2 * time.Millisecond)
	newer, _, err := tr.Provision("new-1", 0, nil)
	if err != nil {
		t.Fatalf("provision new-1: %v", err)
	}

	got := tr.ListFiltered(ListFilter{CreatedSince: boundary})
	if len(got) != 1 || got[0].InstanceID != "new-1" {
		t.Fatalf("ListFiltered(created_since=boundary) = %+v, want exactly new-1", got)
	}

	// Inclusive at the exact instant an instance was created.
	gotInclusive := tr.ListFiltered(ListFilter{CreatedSince: newer.CreatedAt})
	if len(gotInclusive) != 1 || gotInclusive[0].InstanceID != "new-1" {
		t.Fatalf("ListFiltered(created_since=new-1's own CreatedAt) = %+v, want exactly new-1 (inclusive)", gotInclusive)
	}
}

// TestListFilteredCombinedFiltersAND pins that multiple non-zero filter fields
// compose via AND, not OR.
func TestListFilteredCombinedFiltersAND(t *testing.T) {
	tr := NewTracker(0)
	webRunning, _, err := tr.Provision("web-1", 0, nil)
	if err != nil {
		t.Fatalf("provision web-1: %v", err)
	}
	if _, err := tr.Start(webRunning.RuntimeRef); err != nil {
		t.Fatalf("start web-1: %v", err)
	}
	if _, _, err := tr.Provision("web-2", 0, nil); err != nil { // PENDING, wrong status
		t.Fatalf("provision web-2: %v", err)
	}
	workerRunning, _, err := tr.Provision("worker-1", 0, nil) // wrong prefix
	if err != nil {
		t.Fatalf("provision worker-1: %v", err)
	}
	if _, err := tr.Start(workerRunning.RuntimeRef); err != nil {
		t.Fatalf("start worker-1: %v", err)
	}

	got := tr.ListFiltered(ListFilter{Status: StatusRunning, InstanceIDPrefix: "web-"})
	if len(got) != 1 || got[0].InstanceID != "web-1" {
		t.Fatalf("ListFiltered(status=RUNNING, prefix=web-) = %+v, want exactly web-1", got)
	}
}

// TestListFilteredEmptyResult pins that a filter matching nothing returns a
// non-nil, zero-length slice (never nil), the same "empty JSON array, not
// null" contract List() already guarantees.
func TestListFilteredEmptyResult(t *testing.T) {
	tr := NewTracker(0)
	if _, _, err := tr.Provision("agent-1", 0, nil); err != nil {
		t.Fatalf("provision: %v", err)
	}

	got := tr.ListFiltered(ListFilter{InstanceIDPrefix: "does-not-exist-"})
	if got == nil {
		t.Fatal("ListFiltered with no matches = nil, want a non-nil empty slice")
	}
	if len(got) != 0 {
		t.Fatalf("ListFiltered with no matches returned %d instances, want 0", len(got))
	}
}

// TestListFilteredExcludesDestroyed pins that a status filter can never match
// a destroyed instance: Destroy removes it from the tracker entirely, so it
// is absent from every ListFiltered call regardless of filter.
func TestListFilteredExcludesDestroyed(t *testing.T) {
	tr := NewTracker(0)
	inst, _, err := tr.Provision("agent-1", 0, nil)
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	if _, err := tr.Destroy(inst.RuntimeRef); err != nil {
		t.Fatalf("destroy: %v", err)
	}

	got := tr.ListFiltered(ListFilter{Status: StatusDestroyed})
	if len(got) != 0 {
		t.Fatalf("ListFiltered(status=DESTROYED) = %+v, want empty (destroyed instances are not tracked)", got)
	}
}

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

// TestStatusCountsEmptyReturnsEmptyMap pins the "cheap to compute" contract's
// base case: an empty tracker returns an empty (non-nil) map, not one carrying
// a zero entry per known status.
func TestStatusCountsEmptyReturnsEmptyMap(t *testing.T) {
	tr := NewTracker(0)
	counts := tr.StatusCounts()
	if counts == nil {
		t.Fatal("StatusCounts() on an empty tracker = nil, want a non-nil empty map")
	}
	if len(counts) != 0 {
		t.Fatalf("StatusCounts() on an empty tracker = %v, want empty", counts)
	}
}

// TestStatusCountsTalliesByStatus pins the core StatusCounts contract: every
// tracked instance is tallied under its own status, and a Destroy removes its
// instance from every tally (StatusDestroyed never appears — Destroy deletes
// from byRef, so there is nothing left to count as destroyed).
func TestStatusCountsTalliesByStatus(t *testing.T) {
	tr := NewTracker(0)

	pending, _, err := tr.Provision("agent-1", 0, nil)
	if err != nil {
		t.Fatalf("provision agent-1: %v", err)
	}
	running, _, err := tr.Provision("agent-2", 0, nil)
	if err != nil {
		t.Fatalf("provision agent-2: %v", err)
	}
	if _, err := tr.Start(running.RuntimeRef); err != nil {
		t.Fatalf("start agent-2: %v", err)
	}
	toDestroy, _, err := tr.Provision("agent-3", 0, nil)
	if err != nil {
		t.Fatalf("provision agent-3: %v", err)
	}
	if _, err := tr.Destroy(toDestroy.RuntimeRef); err != nil {
		t.Fatalf("destroy agent-3: %v", err)
	}

	counts := tr.StatusCounts()
	if counts[StatusPending] != 1 {
		t.Errorf("StatusCounts()[PENDING] = %d, want 1 (%s)", counts[StatusPending], pending.RuntimeRef)
	}
	if counts[StatusRunning] != 1 {
		t.Errorf("StatusCounts()[RUNNING] = %d, want 1", counts[StatusRunning])
	}
	if n, ok := counts[StatusDestroyed]; ok {
		t.Errorf("StatusCounts()[DESTROYED] = %d present, want the key entirely absent (a destroyed instance is not tracked)", n)
	}
	if total := counts[StatusPending] + counts[StatusRunning]; total != 2 {
		t.Errorf("total tallied instances = %d, want 2 (the destroyed one must not appear anywhere)", total)
	}
}
