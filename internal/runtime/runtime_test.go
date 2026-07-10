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

	inst, created, err := tr.Provision("agent-1", spec)
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

	first, created1, err1 := tr.Provision("agent-1", json.RawMessage(`{"a":1}`))
	second, created2, err2 := tr.Provision("agent-1", json.RawMessage(`{"b":2}`))
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
	inst, _, _ := tr.Provision("agent-1", nil)
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
			inst, created, err := tr.Provision("agent-1", json.RawMessage(`{}`))
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
	inst, _, _ := tr.Provision("agent-1", spec)

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

	if _, _, err := tr.Provision("a", nil); err != nil {
		t.Fatalf("provision a: %v", err)
	}
	if _, _, err := tr.Provision("b", nil); err != nil {
		t.Fatalf("provision b: %v", err)
	}
	if _, _, err := tr.Provision("c", nil); !errors.Is(err, ErrCapacityExceeded) {
		t.Fatalf("provision c: err=%v, want ErrCapacityExceeded", err)
	}

	// Re-provisioning an already-tracked instance must still succeed at capacity;
	// it does not grow the map.
	if _, created, err := tr.Provision("a", nil); err != nil || created {
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
	inst, _, err := tr.Provision("agent-1", nil)
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
	inst, _, err := tr.Provision("agent-1", nil)
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

	first, _, err := tr.Provision("agent-1", nil)
	if err != nil {
		t.Fatalf("first provision: %v", err)
	}
	if _, err := tr.Destroy(first.RuntimeRef); err != nil {
		t.Fatalf("destroy: %v", err)
	}

	// A provision after destroy creates a new, unrelated instance with a fresh
	// runtime_ref rather than resurrecting the old one.
	second, created, err := tr.Provision("agent-1", nil)
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
