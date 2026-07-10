package uplink

import (
	"encoding/json"
	"io"
	"log/slog"
	"strings"
	"testing"

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

func TestDispatchProvisionThenLifecycleReportedStatuses(t *testing.T) {
	d, tr := newDispatcher(t)

	// provision -> provisioning (PENDING), and the tracker actually holds it.
	rep, _ := d.execute(cmd("c1", "node-7", "agent-1", kindProvision, `{"model":"opus"}`, 1))
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
		rep, _ := d.execute(cmd("c-"+c.kind, "node-7", "agent-1", c.kind, "", 2))
		if rep.Status != statusDone || rep.ReportedStatus != c.want {
			t.Fatalf("%s: status=%q reported=%q, want done/%s", c.kind, rep.Status, rep.ReportedStatus, c.want)
		}
	}

	// destroy -> done/stopped, and the instance is gone.
	rep, _ = d.execute(cmd("c-destroy", "node-7", "agent-1", kindDestroy, "", 3))
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
	rep, _ := d.execute(cmd("c1", "node-7", "ghost", kindDestroy, "", 5))
	if rep.Status != statusDone || rep.ReportedStatus != "stopped" {
		t.Fatalf("redelivered destroy: status=%q reported=%q, want done/stopped", rep.Status, rep.ReportedStatus)
	}
	if rep.ClaimGeneration != 5 {
		t.Fatalf("redelivered destroy echoed gen=%d, want 5", rep.ClaimGeneration)
	}

	// A second identical delivery is still done — idempotent.
	rep, _ = d.execute(cmd("c1", "node-7", "ghost", kindDestroy, "", 6))
	if rep.Status != statusDone || rep.ReportedStatus != "stopped" {
		t.Fatalf("second redelivered destroy: status=%q reported=%q, want done/stopped", rep.Status, rep.ReportedStatus)
	}
}

func TestDispatchStartOnUnknownInstanceReportsFailed(t *testing.T) {
	d, _ := newDispatcher(t)

	// start is the one kind eligible for the deferred retry: retry=true on the
	// first pass, terminal (failed) only after the batch runner's retry pass.
	rep, retry := d.execute(cmd("c1", "node-7", "never-provisioned", kindStart, "", 1))
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
		rep, retry := d.execute(cmd("c1", "node-7", "never-provisioned", kind, "", 1))
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
	rep, _ := d.execute(cmd("c1", "node-99", "agent-1", kindProvision, `{"model":"opus"}`, 1))
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

func (s *spyTracker) Provision(instanceID string, spec json.RawMessage) (*runtime.Instance, bool, error) {
	s.provisionCalls++
	return s.Tracker.Provision(instanceID, spec)
}

func TestDispatchNonObjectPayloadRejectedBeforeProvision(t *testing.T) {
	for _, payload := range []string{`[1,2,3]`, `42`, `"a string"`, `true`} {
		spy := &spyTracker{Tracker: runtime.NewTracker(0)}
		d := &dispatcher{tracker: spy, nodeID: "node-7", logger: discardLogger()}

		rep, _ := d.execute(cmd("c1", "node-7", "agent-1", kindProvision, payload, 1))
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
		rep, _ := d.execute(cmd("c1", "node-7", "agent-1", kindProvision, payload, 1))
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
	rep, _ := d.execute(cmd("c1", "node-7", "agent-1", "teleport", "", 1))
	if rep.Status != statusFailed || rep.ReportedStatus != "failed" {
		t.Fatalf("unknown kind: status=%q reported=%q, want failed/failed", rep.Status, rep.ReportedStatus)
	}
}

func TestDispatchUnparseableRefReportsFailed(t *testing.T) {
	d := &dispatcher{tracker: runtime.NewTracker(0), nodeID: "node-7", logger: discardLogger()}
	c := command{CommandID: "c1", RuntimeRef: "not-an-uplink-ref", Kind: kindStart, ClaimGeneration: 1}
	rep, _ := d.execute(c)
	if rep.Status != statusFailed || rep.ReportedStatus != "failed" {
		t.Fatalf("unparseable ref: status=%q reported=%q, want failed/failed", rep.Status, rep.ReportedStatus)
	}
}

func TestDispatchProvisionAtCapacityReportsFailed(t *testing.T) {
	tr := runtime.NewTracker(1)
	if _, _, err := tr.Provision("first", nil); err != nil {
		t.Fatalf("seed provision: %v", err)
	}
	d := &dispatcher{tracker: tr, nodeID: "node-7", logger: discardLogger()}

	rep, _ := d.execute(cmd("c1", "node-7", "second", kindProvision, `{}`, 1))
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
	if _, retry := d.execute(cmd("c1", "node-7", "agent-1", kindStart, "", 1)); !retry {
		t.Fatal("start on an unknown instance must signal retry=true")
	}

	// Once provisioned, the same start resolves and is terminal.
	if _, _, err := tr.Provision("agent-1", nil); err != nil {
		t.Fatalf("provision: %v", err)
	}
	if _, retry := d.execute(cmd("c2", "node-7", "agent-1", kindStart, "", 2)); retry {
		t.Fatal("start on a known instance must signal retry=false")
	}

	// stop/hibernate on an unknown instance are terminal immediately — only start
	// gets the deferred retry.
	if _, retry := d.execute(cmd("c5", "node-7", "never-provisioned", kindStop, "", 5)); retry {
		t.Fatal("stop on an unknown instance must signal retry=false")
	}
	if _, retry := d.execute(cmd("c6", "node-7", "never-provisioned", kindHibernate, "", 6)); retry {
		t.Fatal("hibernate on an unknown instance must signal retry=false")
	}

	// provision and destroy never depend on a sibling command, so never retry.
	if _, retry := d.execute(cmd("c3", "node-7", "agent-2", kindProvision, `{}`, 3)); retry {
		t.Fatal("provision must never signal retry")
	}
	if _, retry := d.execute(cmd("c4", "node-7", "ghost", kindDestroy, "", 4)); retry {
		t.Fatal("destroy must never signal retry")
	}
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
