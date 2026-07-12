package uplink

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	"github.com/hardrails/steward/internal/runtime"
)

// runtimeRefPrefix is the fixed prefix of the control-plane-minted, self-describing
// runtime_ref: uplink:<len(node_id)>:<node_id>:<instance_id>. It is a length-
// prefixed (netstring) node_id so the boundary between node_id and instance_id is
// fixed regardless of content, and instance_id — the terminal segment — may itself
// contain colons. This is the injective inverse of the public control-plane
// runtime-reference format; the client only ever parses it (it never mints one),
// so only the parse direction lives here.
const runtimeRefPrefix = "uplink:"

// CommandKind values are the wire strings for the five queued lifecycle intents,
// 1:1 with the tracker's mutator methods.
const (
	kindProvision = "provision"
	kindStart     = "start"
	kindStop      = "stop"
	kindHibernate = "hibernate"
	kindDestroy   = "destroy"
)

// CommandStatus values are the two terminal outcomes the node reports for a
// command.
const (
	statusDone   = "done"
	statusFailed = "failed"
)

// command is one queued lifecycle command as it arrives in a poll response.
// InstanceGeneration is inbound-only: the node reads it to decide whether to
// act (see the fence guard in execute) and never echoes it back on a report —
// claim_generation remains the sole fencing token on the report path. Zero is
// the "unset" sentinel: an absent field decodes to 0 naturally, so an old
// control plane that never sends it, and a new one that sends 0, are both
// treated as "no fencing for this command" (see
// docs/instance-generation-fencing.md).
type command struct {
	CommandID          string          `json:"command_id"`
	NodeID             string          `json:"node_id"`
	RuntimeRef         string          `json:"runtime_ref"`
	Kind               string          `json:"kind"`
	Payload            json.RawMessage `json:"payload"`
	ClaimGeneration    int64           `json:"claim_generation"`
	InstanceGeneration int64           `json:"instance_generation"`
}

// pollResponse is the body of a successful POST /uplink/poll. An empty poll is
// {"commands": []} with 200, never 204.
type pollResponse struct {
	Commands []command `json:"commands"`
}

// report is the body POSTed to /uplink/report after executing one command. It
// echoes command_id and claim_generation from the command verbatim: claim_generation
// is the fencing token the server uses to discard a stale report from a superseded
// (lease-reclaimed) execution, so it is built by copying, never regenerated.
type report struct {
	CommandID       string          `json:"command_id"`
	Status          string          `json:"status"`
	ReportedStatus  string          `json:"reported_status"`
	ClaimGeneration int64           `json:"claim_generation"`
	Result          json.RawMessage `json:"result"`
}

// reportResponse is the body of a POST /uplink/report. applied:false is the
// server's "already handled / fenced / stale / duplicate" no-op signal, returned
// with 200 — never a 4xx — so the client must not treat it as an error to retry.
type reportResponse struct {
	Applied bool `json:"applied"`
}

// Tracker is the subset of *runtime.Tracker the dispatcher drives. It is an
// interface so a test can inject a spy (for example to prove a rejected payload,
// or a fenced command, never reaches Provision); *runtime.Tracker satisfies it
// directly.
type Tracker interface {
	Provision(instanceID string, generation int64, spec json.RawMessage) (*runtime.Instance, bool, error)
	Start(runtimeRef string) (*runtime.Instance, error)
	Stop(runtimeRef string) (*runtime.Instance, error)
	Hibernate(runtimeRef string) (*runtime.Instance, error)
	Destroy(runtimeRef string) (*runtime.Instance, error)
	RefForInstance(instanceID string) (string, bool)
	GenerationForInstance(instanceID string) (int64, bool)
}

// reportedStatus translates Steward's own UPPERCASE Status vocabulary (which must
// not be renamed — the direct-REST contract depends on it) into the wire's
// lowercase reported_status wire vocabulary. DESTROYED maps to "stopped" because
// the wire vocabulary has no "destroyed" member and
// "stopped" is the closest "no longer running" match (confirmed against the
// control-plane side, not a placeholder). It returns ok=false for a status outside
// the known set, which the tracker never produces.
func reportedStatus(s runtime.Status) (string, bool) {
	switch s {
	case runtime.StatusPending:
		return "provisioning", true
	case runtime.StatusRunning:
		return "running", true
	case runtime.StatusStopped:
		return "stopped", true
	case runtime.StatusHibernated:
		return "hibernated", true
	case runtime.StatusFailed:
		return "failed", true
	case runtime.StatusDestroyed:
		return "stopped", true
	default:
		return "", false
	}
}

// dispatcher executes one command against the tracker and produces the report to
// send. It holds no state beyond its tracker, this node's node_id, a logger, its
// always-present metrics counters, and an optional audit logger, and it performs
// no I/O of its own beyond an optional audit-log append — the poll loop owns the
// HTTP round-trips.
type dispatcher struct {
	tracker Tracker
	nodeID  string
	logger  *slog.Logger
	// metrics is never nil (see NewPoller): command counters are always
	// collected, cheaply, so /metrics only has to decide whether to render them.
	metrics *Metrics
	// audit is nil when -audit-log-file is unset (auditing disabled); every call
	// through it is nil-safe (see AuditLogger.Record).
	audit *AuditLogger
}

// execute runs one command against the tracker and returns the report to POST,
// a retry signal, and a fenced signal.
//
// fenced is true only when the command's instance_generation is strictly older
// than the generation this node currently tracks for its instance_id (see the
// fence guard below) — a stale, superseded-lineage command from at-least-once
// redelivery. A fenced command never reaches a tracker mutator, produces no
// report (rep is the zero value and must not be sent), and is not deferred:
// this is the third outcome distinct from the (report, retry) pair, and
// Poller.executeBatch must check it before consulting retry.
//
// retry is true only when the command is a start that failed solely because its
// instance is not (yet) known to this node: a sibling provision elsewhere in the
// SAME poll batch may still create it, so the batch runner defers exactly one
// retry before treating that outcome as terminal (see Poller.executeBatch).
// stop/hibernate never retry, even on the same "unknown instance" miss: unlike
// start, there is no legitimate case where a sibling provision in the same batch
// should make a stop/hibernate succeed after the fact — deferring one would risk
// stopping/hibernating an instance a sibling provision just created for an
// unrelated reason, which is a NEW ordering inversion (a hosted review finding),
// not a fix. Every other outcome — success, a rejected/foreign/unknown/fenced
// command, a provision or destroy result, a stop/hibernate miss, or a lifecycle
// failure once the ref resolved — returns retry=false. Every non-fenced outcome
// returns a report echoing the command's command_id and claim_generation, even
// on rejection, so the server can retire the command.
//
// A non-fenced, non-retry outcome is also, by definition, the outcome actually
// reported to the server (see Poller.executeBatch) — so it is the one place both
// the command-counter metrics and the optional audit log record a command as
// executed. A deferred start's first pass (retry=true) built a report via fail()
// internally but never sends it and is not deferred; recording here too would
// double-count it once for the discarded deferral and once for its real,
// retried-pass outcome. The instanceID local is seeded with the raw runtime_ref
// before parseRuntimeRef runs so the one failure mode with no parsed instance_id
// (an unparseable ref) still logs/records something diagnostic instead of an
// empty string.
func (d *dispatcher) execute(cmd command) (rep report, retry, fenced bool) {
	rep = report{CommandID: cmd.CommandID, ClaimGeneration: cmd.ClaimGeneration}
	instanceID := cmd.RuntimeRef
	defer func() {
		if !fenced && !retry {
			d.recordOutcome(cmd.CommandID, instanceID, cmd.Kind, rep)
		}
	}()

	nodeID, parsedInstanceID, err := parseRuntimeRef(cmd.RuntimeRef)
	if err != nil {
		d.logger.Error("uplink command has an unparseable runtime_ref; reporting failed",
			"command_id", cmd.CommandID, "runtime_ref", cmd.RuntimeRef, "err", err)
		return d.fail(rep, "runtime_ref is unparseable"), false, false
	}
	instanceID = parsedInstanceID
	// The explicit node_id and the node encoded in runtime_ref must both name
	// this node and each other. The server should only queue commands for this
	// node, so any mismatch is a version-skew, corruption, or routing tripwire.
	// Reject it before a tracker lookup or mutation.
	if cmd.NodeID != d.nodeID || nodeID != d.nodeID || cmd.NodeID != nodeID {
		d.logger.Error("uplink command addressed to a foreign node_id; rejecting",
			"command_id", cmd.CommandID, "command_node_id", cmd.NodeID,
			"runtime_ref_node_id", nodeID, "this_node_id", d.nodeID)
		return d.fail(rep, "command node_id and runtime_ref must address this node"), false, false
	}

	// A negative instance_generation is out-of-contract for a trusted control
	// plane (real generations are minted >= 1); normalize it to the unset
	// sentinel (0) HERE, before the fence check, not inside provision(). The
	// fence guard below runs before the per-kind dispatch and must see the same
	// clamped value provision() eventually adopts — otherwise a re-provision
	// for an already-tracked instance (known=true) carrying a negative
	// generation is itself fenced (any negative < any tracked generation) and
	// silently dropped before the clamp ever gets a chance to run, defeating
	// the whole point of normalizing it.
	generation := cmd.InstanceGeneration
	if generation < 0 {
		d.logger.Warn("uplink command carried a negative instance_generation; treating as unset (0)",
			"command_id", cmd.CommandID, "instance_id", instanceID, "instance_generation", generation)
		generation = 0
	}

	// The fence guard: one chokepoint before the per-kind dispatch, so no command
	// kind can reach a tracker mutator around it. known=false (never-seen
	// instance_id) and generation==0 (old control plane / unset / clamped) both
	// mean "do not fence" — see docs/instance-generation-fencing.md. Only a
	// strictly older carried generation than the tracked one is stale.
	if trackedGen, known := d.tracker.GenerationForInstance(instanceID); known && generation != 0 && generation < trackedGen {
		d.logger.Info("uplink command is fenced (its instance_generation is superseded); dropping without a report",
			"command_id", cmd.CommandID, "kind", cmd.Kind, "instance_id", instanceID,
			"command_generation", generation, "tracked_generation", trackedGen)
		return report{}, false, true
	}

	switch cmd.Kind {
	case kindProvision:
		return d.provision(rep, instanceID, generation, cmd.Payload), false, false
	case kindStart:
		r, retry := d.transition(rep, instanceID, cmd.Kind, d.tracker.Start)
		return r, retry, false
	case kindStop:
		r, retry := d.transition(rep, instanceID, cmd.Kind, d.tracker.Stop)
		return r, retry, false
	case kindHibernate:
		r, retry := d.transition(rep, instanceID, cmd.Kind, d.tracker.Hibernate)
		return r, retry, false
	case kindDestroy:
		return d.destroy(rep, instanceID), false, false
	default:
		d.logger.Error("uplink command has an unknown kind; reporting failed",
			"command_id", cmd.CommandID, "kind", cmd.Kind)
		return d.fail(rep, "unknown command kind"), false, false
	}
}

// provision applies the same object-shape validation the inbound REST handler
// applies to spec (an explicit null or absent payload is "no spec"; any other
// present value must be a JSON object) so the uplink path enforces the exact same
// instance-spec contract, then calls the tracker. A non-object payload is reported
// failed and never reaches Tracker.Provision. generation is passed straight
// through to Tracker.Provision, which atomically adopts it as the instance's new
// lineage baseline (new instance: set; existing instance: raised to
// max(existing, generation), never lowered).
func (d *dispatcher) provision(rep report, instanceID string, generation int64, payload json.RawMessage) report {
	// generation is already clamped non-negative by execute() before the fence
	// check — see the comment there for why the clamp cannot live here alone
	// (a negative value must not reach the fence guard unclamped, or a
	// re-provision for an already-tracked instance is itself fenced before
	// this function ever runs).

	spec := payload
	if bytes.Equal(bytes.TrimSpace(spec), []byte("null")) {
		spec = nil
	}
	if len(spec) > 0 && !runtime.IsJSONObject(spec) {
		d.logger.Error("uplink provision payload is not a JSON object; reporting failed without calling the tracker",
			"command_id", rep.CommandID, "instance_id", instanceID)
		return d.fail(rep, "provision payload must be a JSON object")
	}

	inst, _, err := d.tracker.Provision(instanceID, generation, spec)
	if err != nil {
		d.logger.Error("uplink provision failed",
			"command_id", rep.CommandID, "instance_id", instanceID, "err", err)
		return d.fail(rep, "provision failed")
	}
	return d.succeed(rep, inst.Status)
}

// transition resolves instanceID to the tracker's runtime_ref and drives one of
// start/stop/hibernate. It returns retry=true only for kindStart on the "unknown
// instance" miss — instanceID is not in the tracker's index — because a sibling
// provision elsewhere in the SAME poll batch may still create it; the batch runner
// defers exactly one retry before this becomes a terminal failure. stop/hibernate
// never retry on that same miss: there is no legitimate case where a sibling
// provision should make a stop/hibernate succeed after the fact, and deferring one
// would risk stopping/hibernating an instance a sibling provision in the same batch
// just created — a NEW ordering inversion, not the one this mechanism exists to
// close (a hosted review finding narrowed this from all three lifecycle kinds to
// start only). Once the ref resolves, ErrNotFound from the mutator itself (a destroy
// racing between resolve and act) is a genuine, non-retryable failure: the instance
// existed at resolve time and is now deliberately gone, so a retry cannot help.
// start's miss is logged at DEBUG, not ERROR: on the first pass it is an expected,
// self-correcting condition (the provision has not run yet), and the batch runner
// logs the real ERROR if the instance is still unknown after the retry pass.
// stop/hibernate's miss is terminal immediately, so it is logged at ERROR here,
// exactly like any other first-pass failure.
func (d *dispatcher) transition(rep report, instanceID, kind string, op func(string) (*runtime.Instance, error)) (report, bool) {
	ref, ok := d.tracker.RefForInstance(instanceID)
	if !ok {
		if kind != kindStart {
			d.logger.Error("uplink lifecycle command names an instance not known to this node; reporting failed",
				"command_id", rep.CommandID, "kind", kind, "instance_id", instanceID)
			return d.fail(rep, kind+" names an unknown instance"), false
		}
		d.logger.Debug("uplink start command names an instance not yet known to this node; deferring one retry",
			"command_id", rep.CommandID, "kind", kind, "instance_id", instanceID)
		return d.fail(rep, kind+" names an unknown instance"), true
	}
	inst, err := op(ref)
	if err != nil {
		d.logger.Error("uplink lifecycle transition failed",
			"command_id", rep.CommandID, "kind", kind, "instance_id", instanceID, "err", err)
		return d.fail(rep, kind+" failed"), false
	}
	return d.succeed(rep, inst.Status), false
}

// destroy drives a destroy idempotently: the command's desired end state is "this
// instance is gone," so an already-absent instance (RefForInstance misses, or the
// mutator races another destroy to ErrNotFound) means the goal is already met and
// is reported done, not failed. This is the one place ErrNotFound is not a failure;
// treating it as one would falsely fail a redelivered destroy after a lost report.
func (d *dispatcher) destroy(rep report, instanceID string) report {
	ref, ok := d.tracker.RefForInstance(instanceID)
	if !ok {
		d.logger.Info("uplink destroy names an already-absent instance; reporting done (idempotent)",
			"command_id", rep.CommandID, "instance_id", instanceID)
		return d.succeed(rep, runtime.StatusDestroyed)
	}
	inst, err := d.tracker.Destroy(ref)
	if err != nil {
		if errors.Is(err, runtime.ErrNotFound) {
			d.logger.Info("uplink destroy raced another destroy; reporting done (idempotent)",
				"command_id", rep.CommandID, "instance_id", instanceID)
			return d.succeed(rep, runtime.StatusDestroyed)
		}
		d.logger.Error("uplink destroy failed",
			"command_id", rep.CommandID, "instance_id", instanceID, "err", err)
		return d.fail(rep, "destroy failed")
	}
	return d.succeed(rep, inst.Status)
}

// succeed fills rep as a done report carrying the wire reported_status for status.
// A status the tracker should never emit degrades to a failed report rather than a
// silently-empty reported_status.
func (d *dispatcher) succeed(rep report, status runtime.Status) report {
	reported, ok := reportedStatus(status)
	if !ok {
		d.logger.Error("uplink cannot map a tracker status to a wire status; reporting failed",
			"command_id", rep.CommandID, "status", status)
		return d.fail(rep, "unmappable tracker status")
	}
	rep.Status = statusDone
	rep.ReportedStatus = reported
	rep.Result = emptyResult
	return rep
}

// fail fills rep as a failed report. reported_status is the wire "failed" state and
// result carries an opaque, human-readable reason for the control plane's logs.
func (d *dispatcher) fail(rep report, reason string) report {
	rep.Status = statusFailed
	rep.ReportedStatus = "failed"
	rep.Result = errorResult(reason)
	return rep
}

// recordOutcome updates the command-counter metrics and, when enabled, appends
// one audit-log record for cmd's terminal (reported) outcome. It is called by
// execute's defer exactly once per non-fenced, non-retry outcome — see that
// doc comment for why fenced/retry outcomes must not reach here.
//
// A failed audit-log write is logged at WARN and otherwise ignored: the audit
// log is a best-effort operational trail, not a source of truth the tracker or
// the control plane depend on, so a full disk or a permissions change must not
// stop command execution or the report that already succeeded.
func (d *dispatcher) recordOutcome(commandID, instanceID, kind string, rep report) {
	succeeded := rep.Status == statusDone
	d.metrics.recordCommandOutcome(succeeded)

	if d.audit == nil {
		return
	}
	status := "success"
	errDetail := ""
	if !succeeded {
		status = "failure"
		errDetail = auditErrorDetail(rep.Result)
	}
	if err := d.audit.Record(commandID, instanceID, kind, status, errDetail); err != nil {
		d.logger.Warn("audit log write failed", "command_id", commandID, "err", err)
	}
}

// auditErrorDetail extracts the human-readable reason from a failed report's
// Result (see errorResult) for the audit log's error field. A Result that
// does not decode to {"error": "..."} (structurally impossible today, since
// every failure path builds Result via errorResult, but defensive against a
// future caller of fail() that doesn't) yields an empty string rather than an
// error: the audit log still gets a record for the failure, just without
// detail.
func auditErrorDetail(result json.RawMessage) string {
	var r struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(result, &r); err != nil {
		return ""
	}
	return r.Error
}

// emptyResult is the opaque success result: an empty JSON object, never null, so
// the wire result field is always a JSON object.
var emptyResult = json.RawMessage(`{}`)

// errorResult builds an opaque failure result naming the reason.
func errorResult(reason string) json.RawMessage {
	b, err := json.Marshal(struct {
		Error string `json:"error"`
	}{Error: reason})
	if err != nil {
		// A struct with a single string field cannot fail to marshal; fall back to
		// a valid empty object rather than emitting invalid JSON.
		return emptyResult
	}
	return b
}

// parseRuntimeRef is the injective inverse of the control plane's
// format_runtime_ref: it parses uplink:<len(node_id)>:<node_id>:<instance_id> and
// returns (node_id, instance_id). The length prefix is a code-point count (matching
// the control plane's netstring codec), so the node_id boundary is fixed no matter
// what the ids contain and instance_id — the terminal segment — may hold colons. A
// wrong prefix, a non-decimal or overrunning length, or an empty component is an
// error; the caller reports the command failed rather than trusting a naive split.
func parseRuntimeRef(ref string) (nodeID, instanceID string, err error) {
	if !strings.HasPrefix(ref, runtimeRefPrefix) {
		return "", "", fmt.Errorf("runtime_ref %q does not begin with %q", ref, runtimeRefPrefix)
	}
	body := []rune(strings.TrimPrefix(ref, runtimeRefPrefix))

	sep := indexRune(body, ':')
	if sep < 0 {
		return "", "", fmt.Errorf("runtime_ref %q is missing the node_id length separator", ref)
	}
	length, err := netstringLength(string(body[:sep]))
	if err != nil {
		return "", "", fmt.Errorf("runtime_ref %q has a bad node_id length: %w", ref, err)
	}
	contentStart := sep + 1
	contentEnd := contentStart + length
	if contentEnd > len(body) {
		return "", "", fmt.Errorf("runtime_ref %q node_id length overruns the ref", ref)
	}
	nodeID = string(body[contentStart:contentEnd])
	if contentEnd >= len(body) || body[contentEnd] != ':' {
		return "", "", fmt.Errorf("runtime_ref %q is missing the separator after node_id", ref)
	}
	instanceID = string(body[contentEnd+1:])
	if nodeID == "" || instanceID == "" {
		return "", "", fmt.Errorf("runtime_ref %q has an empty node_id or instance_id", ref)
	}
	return nodeID, instanceID, nil
}

// netstringLength parses a netstring length field: a non-empty run of ASCII digits.
// It rejects a leading sign or non-ASCII digit that strconv.Atoi would otherwise
// accept, matching the control plane's decimal-only codec.
func netstringLength(s string) (int, error) {
	if s == "" {
		return 0, errors.New("empty node_id length")
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("non-numeric node_id length %q", s)
		}
	}
	return strconv.Atoi(s)
}

// indexRune returns the index of the first occurrence of target in rs, or -1.
func indexRune(rs []rune, target rune) int {
	for i, r := range rs {
		if r == target {
			return i
		}
	}
	return -1
}
