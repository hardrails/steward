package uplink

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/runtime"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// newDispatcher builds a dispatcher over a real in-memory tracker bound to node-7.
func newDispatcher(t *testing.T) (*dispatcher, *runtime.Tracker) {
	t.Helper()
	tr := runtime.NewTracker(0)
	return &dispatcher{tracker: tr, nodeID: "node-7", logger: discardLogger()}, tr
}

// newInstrumentedDispatcher is newDispatcher plus a live *Metrics, for tests
// that assert on command-outcome counters. auditPath, when non-empty, also
// wires a real *AuditLogger writing to that file; the caller is responsible
// for closing it (t.Cleanup is not used here so a test can read the file's
// contents before closing, avoiding any Close-vs-read ordering question).
func newInstrumentedDispatcher(t *testing.T, auditPath string) (*dispatcher, *runtime.Tracker, *Metrics) {
	t.Helper()
	tr := runtime.NewTracker(0)
	d := &dispatcher{tracker: tr, nodeID: "node-7", logger: discardLogger(), metrics: &Metrics{}}
	if auditPath != "" {
		al, err := NewAuditLogger(auditPath)
		if err != nil {
			t.Fatalf("NewAuditLogger: %v", err)
		}
		t.Cleanup(func() { _ = al.Close() })
		d.audit = al
	}
	return d, tr, d.metrics
}

// ref builds the runtime_ref the control plane would mint for node-7's instanceID.
func ref(nodeID, instanceID string) string {
	return runtimeRefPrefix + itoa(len(nodeID)) + ":" + nodeID + ":" + instanceID
}

func itoa(n int) string {
	// small, dependency-free int->string for test ref building
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func cmd(id, nodeID, instanceID, kind string, payload string, gen int64) command {
	c := command{
		CommandID:       id,
		NodeID:          nodeID,
		RuntimeRef:      ref(nodeID, instanceID),
		Kind:            kind,
		ClaimGeneration: gen,
	}
	if payload != "" {
		c.Payload = json.RawMessage(payload)
	}
	return c
}

// cmdGen is like cmd but also sets InstanceGeneration, for the fence-guard
// tests: instanceGen is the command's carried instance_generation, distinct
// from claimGen (the report-path fencing token cmd already covers).
func cmdGen(id, nodeID, instanceID, kind, payload string, claimGen, instanceGen int64) command {
	c := cmd(id, nodeID, instanceID, kind, payload, claimGen)
	c.InstanceGeneration = instanceGen
	return c
}

func TestDispatchProvisionThenLifecycleReportedStatuses(t *testing.T) {
	d, tr := newDispatcher(t)

	// provision -> provisioning (PENDING), and the tracker actually holds it.
	rep, _, _ := d.execute(cmd("c1", "node-7", "agent-1", kindProvision, `{"model":"opus"}`, 1))
	if rep.Status != statusDone || rep.ReportedStatus != "provisioning" {
		t.Fatalf("provision: status=%q reported=%q, want done/provisioning", rep.Status, rep.ReportedStatus)
	}
	if rep.CommandID != "c1" || rep.ClaimGeneration != 1 {
		t.Fatalf("provision: echoed command_id=%q gen=%d, want c1/1", rep.CommandID, rep.ClaimGeneration)
	}
	if tr.Len() != 1 {
		t.Fatalf("tracker holds %d after provision, want 1", tr.Len())
	}

	cases := []struct {
		kind string
		want string
	}{
		{kindStart, "running"},
		{kindStop, "stopped"},
		{kindHibernate, "hibernated"},
	}
	for _, c := range cases {
		rep, _, _ := d.execute(cmd("c-"+c.kind, "node-7", "agent-1", c.kind, "", 2))
		if rep.Status != statusDone || rep.ReportedStatus != c.want {
			t.Fatalf("%s: status=%q reported=%q, want done/%s", c.kind, rep.Status, rep.ReportedStatus, c.want)
		}
	}

	// destroy -> done/stopped, and the instance is gone.
	rep, _, _ = d.execute(cmd("c-destroy", "node-7", "agent-1", kindDestroy, "", 3))
	if rep.Status != statusDone || rep.ReportedStatus != "stopped" {
		t.Fatalf("destroy: status=%q reported=%q, want done/stopped", rep.Status, rep.ReportedStatus)
	}
	if tr.Len() != 0 {
		t.Fatalf("tracker holds %d after destroy, want 0", tr.Len())
	}
}

func TestDispatchRedeliveredDestroyReportsDone(t *testing.T) {
	d, _ := newDispatcher(t)

	// The instance was never provisioned on this node (a redelivered destroy after a
	// lost report, whose instance is already gone): destroy's goal is already met.
	rep, _, _ := d.execute(cmd("c1", "node-7", "ghost", kindDestroy, "", 5))
	if rep.Status != statusDone || rep.ReportedStatus != "stopped" {
		t.Fatalf("redelivered destroy: status=%q reported=%q, want done/stopped", rep.Status, rep.ReportedStatus)
	}
	if rep.ClaimGeneration != 5 {
		t.Fatalf("redelivered destroy echoed gen=%d, want 5", rep.ClaimGeneration)
	}

	// A second identical delivery is still done — idempotent.
	rep, _, _ = d.execute(cmd("c1", "node-7", "ghost", kindDestroy, "", 6))
	if rep.Status != statusDone || rep.ReportedStatus != "stopped" {
		t.Fatalf("second redelivered destroy: status=%q reported=%q, want done/stopped", rep.Status, rep.ReportedStatus)
	}
}

func TestDispatchStartOnUnknownInstanceReportsFailed(t *testing.T) {
	d, _ := newDispatcher(t)

	// start is the one kind eligible for the deferred retry: retry=true on the
	// first pass, terminal (failed) only after the batch runner's retry pass.
	rep, retry, _ := d.execute(cmd("c1", "node-7", "never-provisioned", kindStart, "", 1))
	if rep.Status != statusFailed || rep.ReportedStatus != "failed" {
		t.Fatalf("start on unknown instance: status=%q reported=%q, want failed/failed", rep.Status, rep.ReportedStatus)
	}
	if !retry {
		t.Fatal("start on unknown instance: retry=false, want true (an unknown instance is one bounded retry away from failed)")
	}
	if !resultContains(t, rep.Result, "unknown instance") {
		t.Fatalf("start on unknown instance: result %s does not name the cause", rep.Result)
	}
}

// TestDispatchStopHibernateOnUnknownInstanceReportsFailedImmediately pins the
// second, narrower hosted review finding: unlike start, stop and hibernate never
// defer/retry on an unknown instance — they report failed on the very first pass.
// Deferring them would risk acting on an instance a sibling provision elsewhere in
// the same batch creates later, which is a new ordering inversion, not a fix.
func TestDispatchStopHibernateOnUnknownInstanceReportsFailedImmediately(t *testing.T) {
	d, _ := newDispatcher(t)

	for _, kind := range []string{kindStop, kindHibernate} {
		rep, retry, _ := d.execute(cmd("c1", "node-7", "never-provisioned", kind, "", 1))
		if rep.Status != statusFailed || rep.ReportedStatus != "failed" {
			t.Fatalf("%s on unknown instance: status=%q reported=%q, want failed/failed", kind, rep.Status, rep.ReportedStatus)
		}
		if retry {
			t.Fatalf("%s on unknown instance: retry=true, want false (only start defers/retries)", kind)
		}
		if !resultContains(t, rep.Result, "unknown instance") {
			t.Fatalf("%s on unknown instance: result %s does not name the cause", kind, rep.Result)
		}
	}
}

func TestDispatchForeignNodeIDRejected(t *testing.T) {
	d, tr := newDispatcher(t)

	// A command whose runtime_ref names a different node is rejected without touching
	// the tracker, even for provision.
	rep, _, _ := d.execute(cmd("c1", "node-99", "agent-1", kindProvision, `{"model":"opus"}`, 1))
	if rep.Status != statusFailed || rep.ReportedStatus != "failed" {
		t.Fatalf("foreign node: status=%q reported=%q, want failed/failed", rep.Status, rep.ReportedStatus)
	}
	if tr.Len() != 0 {
		t.Fatalf("tracker holds %d after a foreign-node command, want 0", tr.Len())
	}
	if rep.CommandID != "c1" || rep.ClaimGeneration != 1 {
		t.Fatalf("foreign node: echoed command_id=%q gen=%d, want c1/1", rep.CommandID, rep.ClaimGeneration)
	}
}

// spyTracker records whether Provision was called; every other method delegates to
// an embedded real tracker so it stays a faithful stand-in.
type spyTracker struct {
	*runtime.Tracker
	provisionCalls int
}

func (s *spyTracker) Provision(instanceID string, generation int64, spec json.RawMessage) (*runtime.Instance, bool, error) {
	s.provisionCalls++
	return s.Tracker.Provision(instanceID, generation, spec)
}

// fenceSpyTracker records a call count for every mutator method (not just
// Provision), embedding a real tracker so every other read stays faithful. It
// exists to prove a fenced command never reaches ANY tracker mutator, not just
// that it produces no report.
type fenceSpyTracker struct {
	*runtime.Tracker
	provisionCalls int
	startCalls     int
	stopCalls      int
	hibernateCalls int
	destroyCalls   int
}

func (s *fenceSpyTracker) Provision(instanceID string, generation int64, spec json.RawMessage) (*runtime.Instance, bool, error) {
	s.provisionCalls++
	return s.Tracker.Provision(instanceID, generation, spec)
}

func (s *fenceSpyTracker) Start(runtimeRef string) (*runtime.Instance, error) {
	s.startCalls++
	return s.Tracker.Start(runtimeRef)
}

func (s *fenceSpyTracker) Stop(runtimeRef string) (*runtime.Instance, error) {
	s.stopCalls++
	return s.Tracker.Stop(runtimeRef)
}

func (s *fenceSpyTracker) Hibernate(runtimeRef string) (*runtime.Instance, error) {
	s.hibernateCalls++
	return s.Tracker.Hibernate(runtimeRef)
}

func (s *fenceSpyTracker) Destroy(runtimeRef string) (*runtime.Instance, error) {
	s.destroyCalls++
	return s.Tracker.Destroy(runtimeRef)
}

func (s *fenceSpyTracker) totalMutatorCalls() int {
	return s.provisionCalls + s.startCalls + s.stopCalls + s.hibernateCalls + s.destroyCalls
}

// TestDispatchFenceDropsStaleCommandForEveryKind pins task 4's central acceptance
// check: a command whose instance_generation is strictly OLDER than the
// generation this node tracks for its instance_id is dropped for every command
// kind — no report is sent (rep is the zero value), fenced=true, retry=false,
// the tracker mutator is never called (proved via the spy, not just "no
// report"), and the drop is logged at INFO, never ERROR.
func TestDispatchFenceDropsStaleCommandForEveryKind(t *testing.T) {
	cases := []struct {
		kind    string
		payload string
	}{
		{kindStart, ""},
		{kindStop, ""},
		{kindHibernate, ""},
		{kindDestroy, ""},
		{kindProvision, `{"model":"opus"}`},
	}
	for _, c := range cases {
		t.Run(c.kind, func(t *testing.T) {
			tr := runtime.NewTracker(0)
			// Seed a tracked baseline of generation 5 directly on the raw tracker (not
			// through the spy), so the spy's call counts below reflect only the
			// command under test.
			if _, _, err := tr.Provision("agent-1", 5, nil); err != nil {
				t.Fatalf("seed provision: %v", err)
			}
			var logBuf strings.Builder
			logger := slog.New(slog.NewTextHandler(&logBuf, nil))
			spy := &fenceSpyTracker{Tracker: tr}
			d := &dispatcher{tracker: spy, nodeID: "node-7", logger: logger}

			// instance_generation 3 is strictly older than the tracked 5: stale.
			cmd := cmdGen("c1", "node-7", "agent-1", c.kind, c.payload, 1, 3)
			rep, retry, fenced := d.execute(cmd)

			if !fenced {
				t.Fatalf("%s: fenced=false, want true (instance_generation 3 < tracked 5)", c.kind)
			}
			if retry {
				t.Fatalf("%s: retry=true, want false for a fenced command", c.kind)
			}
			if rep.CommandID != "" || rep.Status != "" || rep.ReportedStatus != "" || rep.ClaimGeneration != 0 || rep.Result != nil {
				t.Fatalf("%s: rep=%+v, want the zero report (no report sent for a fenced command)", c.kind, rep)
			}
			if n := spy.totalMutatorCalls(); n != 0 {
				t.Fatalf("%s: tracker mutator called %d times, want 0 (the fence must run before any dispatch)", c.kind, n)
			}
			logs := logBuf.String()
			if !strings.Contains(logs, "level=INFO") || !strings.Contains(logs, "fenced") {
				t.Fatalf("%s: fence drop not logged at INFO naming \"fenced\":\n%s", c.kind, logs)
			}
			if strings.Contains(logs, "level=ERROR") {
				t.Fatalf("%s: a fenced command must not log at ERROR:\n%s", c.kind, logs)
			}
		})
	}
}

// TestDispatchFenceAllowsCommandAtOrAboveTrackedGeneration pins the "strictly
// older only" rule: a command whose instance_generation equals or exceeds the
// tracked generation is never fenced and proceeds to dispatch normally.
func TestDispatchFenceAllowsCommandAtOrAboveTrackedGeneration(t *testing.T) {
	for _, gen := range []int64{5, 9} {
		t.Run(fmt.Sprintf("instance_generation=%d", gen), func(t *testing.T) {
			tr := runtime.NewTracker(0)
			if _, _, err := tr.Provision("agent-1", 5, nil); err != nil {
				t.Fatalf("seed provision: %v", err)
			}
			d := &dispatcher{tracker: tr, nodeID: "node-7", logger: discardLogger()}

			// The representative non-fenced command is a start (agent-1 is PENDING,
			// so PENDING→RUNNING is a valid transition); fencing is kind-agnostic, so
			// this exercises the same not-fenced-proceeds path a stop would while
			// avoiding the now-rejected stop-on-PENDING.
			cmd := cmdGen("c1", "node-7", "agent-1", kindStart, "", 1, gen)
			rep, _, fenced := d.execute(cmd)
			if fenced {
				t.Fatalf("instance_generation=%d: fenced=true, want false (not older than tracked 5)", gen)
			}
			if rep.Status != statusDone {
				t.Fatalf("instance_generation=%d: status=%q, want done (the command must proceed)", gen, rep.Status)
			}
		})
	}
}

// TestDispatchFenceIgnoresZeroInstanceGeneration pins the old-control-plane
// compatibility rule: instance_generation 0 is the "unset" sentinel and is never
// fenced, even when the tracker already holds a higher tracked generation.
func TestDispatchFenceIgnoresZeroInstanceGeneration(t *testing.T) {
	tr := runtime.NewTracker(0)
	if _, _, err := tr.Provision("agent-1", 5, nil); err != nil {
		t.Fatalf("seed provision: %v", err)
	}
	d := &dispatcher{tracker: tr, nodeID: "node-7", logger: discardLogger()}

	// start (agent-1 is PENDING) is the representative non-fenced command; fencing
	// is kind-agnostic, so this avoids the now-rejected stop-on-PENDING.
	cmd := cmdGen("c1", "node-7", "agent-1", kindStart, "", 1, 0)
	rep, _, fenced := d.execute(cmd)
	if fenced {
		t.Fatal("instance_generation=0 must never be fenced (old-control-plane compatibility)")
	}
	if rep.Status != statusDone {
		t.Fatalf("status=%q, want done", rep.Status)
	}
}

// TestDispatchFenceNeverSeenInstanceNotFenced pins the first-seen bootstrap: an
// instance_id the tracker has never seen has no baseline to compare against, so
// the fence does not trigger regardless of the carried instance_generation.
func TestDispatchFenceNeverSeenInstanceNotFenced(t *testing.T) {
	d, _ := newDispatcher(t)

	cmd := cmdGen("c1", "node-7", "never-provisioned", kindDestroy, "", 1, 99)
	rep, _, fenced := d.execute(cmd)
	if fenced {
		t.Fatal("a never-seen instance_id must not be fenced (first-seen bootstrap)")
	}
	// destroy on a never-seen instance is the existing idempotent "already gone"
	// outcome, unaffected by the fence.
	if rep.Status != statusDone || rep.ReportedStatus != "stopped" {
		t.Fatalf("status=%q reported=%q, want done/stopped (idempotent destroy)", rep.Status, rep.ReportedStatus)
	}
}

// TestDispatchProvisionAdoptsGeneration pins the provision-adoption rule: a
// provision command's instance_generation becomes the new tracked baseline, so a
// subsequent command carrying an older generation is fenced.
func TestDispatchProvisionAdoptsGeneration(t *testing.T) {
	d, tr := newDispatcher(t)

	first := cmdGen("c1", "node-7", "agent-1", kindProvision, `{"model":"opus"}`, 1, 7)
	rep, _, fenced := d.execute(first)
	if fenced {
		t.Fatal("a first provision must never be fenced")
	}
	if rep.Status != statusDone {
		t.Fatalf("provision status=%q, want done", rep.Status)
	}
	gen, ok := tr.GenerationForInstance("agent-1")
	if !ok || gen != 7 {
		t.Fatalf("GenerationForInstance = (%d,%v), want (7,true) after provision adopts the carried generation", gen, ok)
	}

	// A later command carrying a generation older than the adopted 7 is now fenced.
	stale := cmdGen("c2", "node-7", "agent-1", kindStop, "", 2, 3)
	_, _, staleFenced := d.execute(stale)
	if !staleFenced {
		t.Fatal("a command older than the adopted generation must be fenced")
	}
}

// TestDispatchProvisionClampsNegativeGenerationToZero pins the write-path
// symmetry with persist.go's load-time reject of a negative Instance.Generation:
// an out-of-contract negative instance_generation on a provision command must
// never be persisted as-is (it would round-trip through the state file and brick
// the node as "corrupt" on the next restart). It is treated as the unset
// sentinel (0) instead — never fenced, and the tracked generation lands at 0.
func TestDispatchProvisionClampsNegativeGenerationToZero(t *testing.T) {
	d, tr := newDispatcher(t)

	cmd := cmdGen("c1", "node-7", "agent-1", kindProvision, `{"model":"opus"}`, 1, -5)
	rep, _, fenced := d.execute(cmd)
	if fenced {
		t.Fatal("a first provision must never be fenced, even with an out-of-contract negative generation")
	}
	if rep.Status != statusDone {
		t.Fatalf("provision status=%q, want done", rep.Status)
	}

	gen, ok := tr.GenerationForInstance("agent-1")
	if !ok || gen != 0 {
		t.Fatalf("GenerationForInstance = (%d,%v), want (0,true) — a negative wire generation must clamp to 0, not persist negative", gen, ok)
	}
}

// TestDispatchNegativeGenerationDoesNotFenceAlreadyTrackedInstance pins a hosted
// review finding: the clamp must run BEFORE the fence check, not only inside
// provision(). An already-tracked instance (generation 5) receiving ANY command
// with a negative instance_generation must not be fenced — a negative value has
// to be normalized to the unset sentinel (0) first, or it would otherwise compare
// as "older than every positive tracked generation" and get silently dropped,
// including a legitimate re-provision that should succeed (raising/holding the
// tracked generation via Provision's max(existing, 0) = existing rule).
func TestDispatchNegativeGenerationDoesNotFenceAlreadyTrackedInstance(t *testing.T) {
	d, tr := newDispatcher(t)

	seed := cmdGen("c1", "node-7", "agent-1", kindProvision, `{"model":"opus"}`, 1, 5)
	if _, _, fenced := d.execute(seed); fenced {
		t.Fatal("seed provision must not be fenced")
	}

	reprovision := cmdGen("c2", "node-7", "agent-1", kindProvision, `{"model":"opus-2"}`, 2, -1)
	rep, _, fenced := d.execute(reprovision)
	if fenced {
		t.Fatal("a negative instance_generation on an already-tracked instance must not be fenced — it must clamp to 0 before the fence check runs")
	}
	if rep.Status != statusDone {
		t.Fatalf("re-provision status=%q, want done", rep.Status)
	}

	gen, ok := tr.GenerationForInstance("agent-1")
	if !ok || gen != 5 {
		t.Fatalf("GenerationForInstance = (%d,%v), want (5,true) — max(existing=5, clamped=0) must hold the tracked generation at 5", gen, ok)
	}
}

func TestDispatchNonObjectPayloadRejectedBeforeProvision(t *testing.T) {
	for _, payload := range []string{`[1,2,3]`, `42`, `"a string"`, `true`} {
		spy := &spyTracker{Tracker: runtime.NewTracker(0)}
		d := &dispatcher{tracker: spy, nodeID: "node-7", logger: discardLogger()}

		rep, _, _ := d.execute(cmd("c1", "node-7", "agent-1", kindProvision, payload, 1))
		if rep.Status != statusFailed || rep.ReportedStatus != "failed" {
			t.Fatalf("payload %s: status=%q reported=%q, want failed/failed", payload, rep.Status, rep.ReportedStatus)
		}
		if spy.provisionCalls != 0 {
			t.Fatalf("payload %s: Provision called %d times, want 0 (rejected before the tracker)", payload, spy.provisionCalls)
		}
		if !resultContains(t, rep.Result, "JSON object") {
			t.Fatalf("payload %s: result %s does not name the shape problem", payload, rep.Result)
		}
	}
}

func TestDispatchNullAndAbsentPayloadProvisionSucceeds(t *testing.T) {
	// null and absent payloads are "no spec," exactly as the inbound REST handler
	// treats an explicit null / absent spec — they must provision, not be rejected.
	for _, payload := range []string{`null`, ``} {
		d, tr := newDispatcher(t)
		rep, _, _ := d.execute(cmd("c1", "node-7", "agent-1", kindProvision, payload, 1))
		if rep.Status != statusDone || rep.ReportedStatus != "provisioning" {
			t.Fatalf("payload %q: status=%q reported=%q, want done/provisioning", payload, rep.Status, rep.ReportedStatus)
		}
		if tr.Len() != 1 {
			t.Fatalf("payload %q: tracker holds %d, want 1", payload, tr.Len())
		}
	}
}

func TestDispatchUnknownKindReportsFailed(t *testing.T) {
	d, _ := newDispatcher(t)
	rep, _, _ := d.execute(cmd("c1", "node-7", "agent-1", "teleport", "", 1))
	if rep.Status != statusFailed || rep.ReportedStatus != "failed" {
		t.Fatalf("unknown kind: status=%q reported=%q, want failed/failed", rep.Status, rep.ReportedStatus)
	}
}

func TestDispatchUnparseableRefReportsFailed(t *testing.T) {
	d := &dispatcher{tracker: runtime.NewTracker(0), nodeID: "node-7", logger: discardLogger()}
	c := command{CommandID: "c1", RuntimeRef: "not-an-uplink-ref", Kind: kindStart, ClaimGeneration: 1}
	rep, _, _ := d.execute(c)
	if rep.Status != statusFailed || rep.ReportedStatus != "failed" {
		t.Fatalf("unparseable ref: status=%q reported=%q, want failed/failed", rep.Status, rep.ReportedStatus)
	}
}

func TestDispatchProvisionAtCapacityReportsFailed(t *testing.T) {
	tr := runtime.NewTracker(1)
	if _, _, err := tr.Provision("first", 0, nil); err != nil {
		t.Fatalf("seed provision: %v", err)
	}
	d := &dispatcher{tracker: tr, nodeID: "node-7", logger: discardLogger()}

	rep, _, _ := d.execute(cmd("c1", "node-7", "second", kindProvision, `{}`, 1))
	if rep.Status != statusFailed || rep.ReportedStatus != "failed" {
		t.Fatalf("provision at capacity: status=%q reported=%q, want failed/failed", rep.Status, rep.ReportedStatus)
	}
}

// TestDispatchRetrySignal pins the contract Poller.executeBatch depends on: only a
// start whose instance is not yet known signals retry=true; every other outcome (a
// resolved lifecycle transition, a stop/hibernate miss, a provision, a destroy) is
// terminal (retry=false), so the batch runner never defers work it should report now.
func TestDispatchRetrySignal(t *testing.T) {
	d, tr := newDispatcher(t)

	// start on an unknown instance: retryable (a sibling provision may create it).
	if _, retry, _ := d.execute(cmd("c1", "node-7", "agent-1", kindStart, "", 1)); !retry {
		t.Fatal("start on an unknown instance must signal retry=true")
	}

	// Once provisioned, the same start resolves and is terminal.
	if _, _, err := tr.Provision("agent-1", 0, nil); err != nil {
		t.Fatalf("provision: %v", err)
	}
	if _, retry, _ := d.execute(cmd("c2", "node-7", "agent-1", kindStart, "", 2)); retry {
		t.Fatal("start on a known instance must signal retry=false")
	}

	// stop/hibernate on an unknown instance are terminal immediately — only start
	// gets the deferred retry.
	if _, retry, _ := d.execute(cmd("c5", "node-7", "never-provisioned", kindStop, "", 5)); retry {
		t.Fatal("stop on an unknown instance must signal retry=false")
	}
	if _, retry, _ := d.execute(cmd("c6", "node-7", "never-provisioned", kindHibernate, "", 6)); retry {
		t.Fatal("hibernate on an unknown instance must signal retry=false")
	}

	// provision and destroy never depend on a sibling command, so never retry.
	if _, retry, _ := d.execute(cmd("c3", "node-7", "agent-2", kindProvision, `{}`, 3)); retry {
		t.Fatal("provision must never signal retry")
	}
	if _, retry, _ := d.execute(cmd("c4", "node-7", "ghost", kindDestroy, "", 4)); retry {
		t.Fatal("destroy must never signal retry")
	}
}

// TestDispatchCommandCountersOnlyCountTerminalOutcomes pins the metrics-
// counting contract execute's doc comment describes: the success/failure
// counters increment exactly once per REPORTED (non-fenced, non-retry)
// outcome, never for a fenced drop and never twice for a start whose first
// pass only defers (retry=true, no report sent) before its retry pass
// produces the real, counted outcome.
func TestDispatchCommandCountersOnlyCountTerminalOutcomes(t *testing.T) {
	d, tr, metrics := newInstrumentedDispatcher(t, "")

	// A straightforward success.
	if rep, _, _ := d.execute(cmd("c1", "node-7", "agent-1", kindProvision, `{"model":"opus"}`, 1)); rep.Status != statusDone {
		t.Fatalf("provision: status=%q, want done", rep.Status)
	}
	// A straightforward failure (unknown kind).
	if rep, _, _ := d.execute(cmd("c2", "node-7", "agent-1", "teleport", "", 2)); rep.Status != statusFailed {
		t.Fatalf("unknown kind: status=%q, want failed", rep.Status)
	}
	snap := metrics.snapshot(time.Second, DefaultCommandQueueDepth)
	if snap.CommandsSucceeded != 1 || snap.CommandsFailed != 1 {
		t.Fatalf("after 1 success + 1 failure: snapshot = %+v, want succeeded=1 failed=1", snap)
	}

	// A fenced command: must not move either counter.
	if _, _, err := tr.Provision("agent-2", 5, nil); err != nil {
		t.Fatalf("seed agent-2 at generation 5: %v", err)
	}
	stale := cmdGen("c3", "node-7", "agent-2", kindStop, "", 3, 2)
	if _, _, fenced := d.execute(stale); !fenced {
		t.Fatal("expected the stale command to be fenced")
	}
	snap = metrics.snapshot(time.Second, DefaultCommandQueueDepth)
	if snap.CommandsSucceeded != 1 || snap.CommandsFailed != 1 {
		t.Fatalf("after a fenced command: snapshot = %+v, want unchanged (succeeded=1 failed=1)", snap)
	}

	// A start on an unknown instance: retry=true on the first pass must NOT
	// count (its report is discarded, never sent); only the retry pass's real
	// outcome, once the instance exists, counts.
	deferredRep, retry, _ := d.execute(cmd("c4", "node-7", "agent-3", kindStart, "", 4))
	if !retry || deferredRep.Status != statusFailed {
		t.Fatalf("deferred start: retry=%v status=%q, want retry=true status=failed", retry, deferredRep.Status)
	}
	snap = metrics.snapshot(time.Second, DefaultCommandQueueDepth)
	if snap.CommandsSucceeded != 1 || snap.CommandsFailed != 1 {
		t.Fatalf("after a deferred (not yet retried) start: snapshot = %+v, want still succeeded=1 failed=1 (the deferral must not count)", snap)
	}
	if _, _, err := tr.Provision("agent-3", 0, nil); err != nil {
		t.Fatalf("provision agent-3 so the retry resolves: %v", err)
	}
	retryRep, retryAgain, _ := d.execute(cmd("c4", "node-7", "agent-3", kindStart, "", 4))
	if retryAgain || retryRep.Status != statusDone {
		t.Fatalf("retried start: retry=%v status=%q, want retry=false status=done", retryAgain, retryRep.Status)
	}
	snap = metrics.snapshot(time.Second, DefaultCommandQueueDepth)
	if snap.CommandsSucceeded != 2 || snap.CommandsFailed != 1 {
		t.Fatalf("after the retry's real outcome: snapshot = %+v, want succeeded=2 failed=1 (counted exactly once, on the retry pass)", snap)
	}
}

// TestDispatchAuditLogRecordsExactlyOneLinePerTerminalOutcome is the audit-log
// analog of the counters test above: it drives the same deferred-start-then-
// retry shape through a dispatcher wired to a real *AuditLogger and asserts
// the file holds exactly one well-formed JSON line per REPORTED command —
// none for the fenced drop, none for the discarded first-pass deferral, and
// the failure line carries error detail.
func TestDispatchAuditLogRecordsExactlyOneLinePerTerminalOutcome(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	d, tr, _ := newInstrumentedDispatcher(t, auditPath)

	if _, _, err := tr.Provision("agent-2", 5, nil); err != nil {
		t.Fatalf("seed agent-2 at generation 5: %v", err)
	}

	d.execute(cmd("c1", "node-7", "agent-1", kindProvision, `{"model":"opus"}`, 1)) // success
	d.execute(cmd("c2", "node-7", "agent-1", "teleport", "", 2))                    // failure
	d.execute(cmdGen("c3", "node-7", "agent-2", kindStop, "", 3, 2))                // fenced: no record
	d.execute(cmd("c4", "node-7", "agent-3", kindStart, "", 4))                     // deferred: no record yet
	if _, _, err := tr.Provision("agent-3", 0, nil); err != nil {
		t.Fatalf("provision agent-3: %v", err)
	}
	d.execute(cmd("c4", "node-7", "agent-3", kindStart, "", 4)) // retried: now records

	records := readAuditRecords(t, auditPath)
	if len(records) != 3 {
		t.Fatalf("got %d audit records, want 3 (c1 success, c2 failure, c4's retried outcome — never c3 fenced or c4's discarded deferral):\n%+v", len(records), records)
	}

	byID := map[string]auditRecord{}
	for _, r := range records {
		byID[r.CommandID] = r
	}
	if r, ok := byID["c1"]; !ok || r.Status != "success" || r.InstanceID != "agent-1" || r.Kind != kindProvision || r.Error != "" {
		t.Fatalf("c1 record = %+v (found=%v), want success/agent-1/provision with no error", r, ok)
	}
	if r, ok := byID["c2"]; !ok || r.Status != "failure" || r.Kind != "teleport" || r.Error == "" {
		t.Fatalf("c2 record = %+v (found=%v), want failure/teleport with a non-empty error detail", r, ok)
	}
	if r, ok := byID["c4"]; !ok || r.Status != "success" || r.InstanceID != "agent-3" || r.Kind != kindStart {
		t.Fatalf("c4 record = %+v (found=%v), want success/agent-3/start (the retried, real outcome)", r, ok)
	}
	if _, ok := byID["c3"]; ok {
		t.Fatal("c3 (fenced) must not appear in the audit log")
	}
}

// TestDispatchAuditWriteFailureLogsWarnAndDoesNotDisruptTheReport pins the
// documented degradation: a failed audit-log write (here, forced by closing
// the logger's own file out from under it, simulating a disk/permissions
// failure mid-run) must not affect the report execute already produced or the
// command-counter metrics — both are logged as WARN and otherwise ignored,
// never surfaced as a command failure the caller didn't actually have.
func TestDispatchAuditWriteFailureLogsWarnAndDoesNotDisruptTheReport(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	al, err := NewAuditLogger(auditPath)
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}
	// Close the underlying file directly (not via al.Close, which a real
	// shutdown would call once and stop using afterward): this simulates an
	// I/O failure on an AuditLogger the dispatcher is still actively using,
	// the shape a full disk or a revoked permission would take.
	if err := al.file.Close(); err != nil {
		t.Fatalf("close underlying file: %v", err)
	}

	var logBuf strings.Builder
	tr := runtime.NewTracker(0)
	d := &dispatcher{
		tracker: tr,
		nodeID:  "node-7",
		logger:  slog.New(slog.NewTextHandler(&logBuf, nil)),
		metrics: &Metrics{},
		audit:   al,
	}

	rep, _, _ := d.execute(cmd("c1", "node-7", "agent-1", kindProvision, `{"model":"opus"}`, 1))
	if rep.Status != statusDone {
		t.Fatalf("report status = %q, want done — a broken audit log must not turn a successful command into a failure", rep.Status)
	}
	if snap := d.metrics.snapshot(time.Second, DefaultCommandQueueDepth); snap.CommandsSucceeded != 1 {
		t.Fatalf("CommandsSucceeded = %d, want 1 — a broken audit log must not stop metrics from counting", snap.CommandsSucceeded)
	}
	logs := logBuf.String()
	if !strings.Contains(logs, "audit log write failed") || !strings.Contains(logs, "c1") {
		t.Fatalf("expected a WARN naming the audit write failure and command_id c1, got:\n%s", logs)
	}
}

// readAuditRecords reads path as JSON-lines and decodes each into an
// auditRecord, failing the test on any malformed line.
func readAuditRecords(t *testing.T, path string) []auditRecord {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	var records []auditRecord
	for _, line := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
		if line == "" {
			continue
		}
		var r auditRecord
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("audit log line %q is not valid JSON: %v", line, err)
		}
		records = append(records, r)
	}
	return records
}

func TestParseRuntimeRef(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		nodeID, instanceID, err := parseRuntimeRef("uplink:6:node-7:agent-1")
		if err != nil {
			t.Fatalf("unexpected err %v", err)
		}
		if nodeID != "node-7" || instanceID != "agent-1" {
			t.Fatalf("got (%q,%q), want (node-7,agent-1)", nodeID, instanceID)
		}
	})
	t.Run("colon in instance_id preserved", func(t *testing.T) {
		nodeID, instanceID, err := parseRuntimeRef("uplink:6:node-7:agent:1:2")
		if err != nil {
			t.Fatalf("unexpected err %v", err)
		}
		if nodeID != "node-7" || instanceID != "agent:1:2" {
			t.Fatalf("got (%q,%q), want (node-7,agent:1:2)", nodeID, instanceID)
		}
	})
	t.Run("colon in node_id disambiguated by length", func(t *testing.T) {
		// node_id "no:e-7" is length 6, so the length prefix, not a naive split,
		// fixes the boundary.
		nodeID, instanceID, err := parseRuntimeRef("uplink:6:no:e-7:agent-1")
		if err != nil {
			t.Fatalf("unexpected err %v", err)
		}
		if nodeID != "no:e-7" || instanceID != "agent-1" {
			t.Fatalf("got (%q,%q), want (no:e-7,agent-1)", nodeID, instanceID)
		}
	})
	t.Run("round-trips the ref helper", func(t *testing.T) {
		nodeID, instanceID, err := parseRuntimeRef(ref("node-7", "agent-1"))
		if err != nil || nodeID != "node-7" || instanceID != "agent-1" {
			t.Fatalf("round-trip got (%q,%q,%v)", nodeID, instanceID, err)
		}
	})

	bad := []string{
		"",
		"node-7:agent-1",           // no prefix
		"uplink:",                  // empty body
		"uplink:6:node-7",          // no separator after node_id
		"uplink:x:node-7:agent-1",  // non-numeric length
		"uplink:99:node-7:agent-1", // length overruns
		"uplink:0::agent-1",        // empty node_id
		"uplink:6:node-7:",         // empty instance_id
		"uplink:+6:node-7:agent-1", // signed length rejected
	}
	for _, badRef := range bad {
		if _, _, err := parseRuntimeRef(badRef); err == nil {
			t.Errorf("parseRuntimeRef(%q): got nil err, want a parse error", badRef)
		}
	}
}

func resultContains(t *testing.T, result json.RawMessage, substr string) bool {
	t.Helper()
	var r struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(result, &r); err != nil {
		t.Fatalf("result %s is not the {error} shape: %v", result, err)
	}
	return strings.Contains(r.Error, substr)
}
