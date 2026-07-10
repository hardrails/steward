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
// contain colons. This is the injective inverse of the control plane's
// hardrails_runtime.node_uplink.core.format_runtime_ref; the client only ever
// parses it (it never mints one), so only the parse direction lives here.
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
type command struct {
	CommandID       string          `json:"command_id"`
	NodeID          string          `json:"node_id"`
	RuntimeRef      string          `json:"runtime_ref"`
	Kind            string          `json:"kind"`
	Payload         json.RawMessage `json:"payload"`
	ClaimGeneration int64           `json:"claim_generation"`
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
// interface so a test can inject a spy (for example to prove a rejected payload
// never reaches Provision); *runtime.Tracker satisfies it directly.
type Tracker interface {
	Provision(instanceID string, spec json.RawMessage) (*runtime.Instance, bool, error)
	Start(runtimeRef string) (*runtime.Instance, error)
	Stop(runtimeRef string) (*runtime.Instance, error)
	Hibernate(runtimeRef string) (*runtime.Instance, error)
	Destroy(runtimeRef string) (*runtime.Instance, error)
	RefForInstance(instanceID string) (string, bool)
}

// reportedStatus translates Steward's own UPPERCASE Status vocabulary (which must
// not be renamed — the direct-REST contract depends on it) into the wire's
// lowercase reported_status (a hardrails_runtime AgentInstanceStatus). DESTROYED
// maps to "stopped" because AgentInstanceStatus has no "destroyed" member and
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
// send. It holds no state beyond its tracker, this node's node_id, and a logger,
// and it performs no I/O — the poll loop owns the HTTP round-trips.
type dispatcher struct {
	tracker Tracker
	nodeID  string
	logger  *slog.Logger
}

// execute runs one command against the tracker and returns the report to POST plus
// a retry signal. retry is true only when the command is a start/stop/hibernate
// that failed solely because its instance is not (yet) known to this node: a
// sibling provision elsewhere in the SAME poll batch may still create it, so the
// batch runner defers exactly one retry before treating that outcome as terminal
// (see Poller.executeBatch). Every other outcome — success, a rejected/foreign/
// unknown command, a provision or destroy result, or a lifecycle failure once the
// ref resolved — returns retry=false. It always returns a report echoing the
// command's command_id and claim_generation, even on rejection, so the server can
// retire the command.
func (d *dispatcher) execute(cmd command) (report, bool) {
	rep := report{CommandID: cmd.CommandID, ClaimGeneration: cmd.ClaimGeneration}

	nodeID, instanceID, err := parseRuntimeRef(cmd.RuntimeRef)
	if err != nil {
		d.logger.Error("uplink command has an unparseable runtime_ref; reporting failed",
			"command_id", cmd.CommandID, "runtime_ref", cmd.RuntimeRef, "err", err)
		return d.fail(rep, "runtime_ref is unparseable"), false
	}
	// The client-side analog of the server adapter's _verify_issued check: the
	// server should only ever queue commands for this node, so a foreign node_id is
	// a version-skew/bug tripwire, not an expected path. Reject without touching the
	// tracker.
	if nodeID != d.nodeID {
		d.logger.Error("uplink command addressed to a foreign node_id; rejecting",
			"command_id", cmd.CommandID, "command_node_id", nodeID, "this_node_id", d.nodeID)
		return d.fail(rep, "runtime_ref is addressed to a different node"), false
	}

	switch cmd.Kind {
	case kindProvision:
		return d.provision(rep, instanceID, cmd.Payload), false
	case kindStart:
		return d.transition(rep, instanceID, cmd.Kind, d.tracker.Start)
	case kindStop:
		return d.transition(rep, instanceID, cmd.Kind, d.tracker.Stop)
	case kindHibernate:
		return d.transition(rep, instanceID, cmd.Kind, d.tracker.Hibernate)
	case kindDestroy:
		return d.destroy(rep, instanceID), false
	default:
		d.logger.Error("uplink command has an unknown kind; reporting failed",
			"command_id", cmd.CommandID, "kind", cmd.Kind)
		return d.fail(rep, "unknown command kind"), false
	}
}

// provision applies the same object-shape validation the inbound REST handler
// applies to spec (an explicit null or absent payload is "no spec"; any other
// present value must be a JSON object) so the uplink path enforces the exact same
// instance-spec contract, then calls the tracker. A non-object payload is reported
// failed and never reaches Tracker.Provision.
func (d *dispatcher) provision(rep report, instanceID string, payload json.RawMessage) report {
	spec := payload
	if bytes.Equal(bytes.TrimSpace(spec), []byte("null")) {
		spec = nil
	}
	if len(spec) > 0 && !runtime.IsJSONObject(spec) {
		d.logger.Error("uplink provision payload is not a JSON object; reporting failed without calling the tracker",
			"command_id", rep.CommandID, "instance_id", instanceID)
		return d.fail(rep, "provision payload must be a JSON object")
	}

	inst, _, err := d.tracker.Provision(instanceID, spec)
	if err != nil {
		d.logger.Error("uplink provision failed",
			"command_id", rep.CommandID, "instance_id", instanceID, "err", err)
		return d.fail(rep, "provision failed")
	}
	return d.succeed(rep, inst.Status)
}

// transition resolves instanceID to the tracker's runtime_ref and drives one of
// start/stop/hibernate. It returns retry=true only for the "unknown instance"
// miss — instanceID is not in the tracker's index — because a sibling provision
// elsewhere in the SAME poll batch may still create it; the batch runner defers
// exactly one retry before this becomes a terminal failure. Once the ref resolves,
// ErrNotFound from the mutator itself (a destroy racing between resolve and act) is
// a genuine, non-retryable failure: the instance existed at resolve time and is now
// deliberately gone, so a retry cannot help. The miss is logged at DEBUG, not
// ERROR: on the first pass it is an expected, self-correcting condition (the
// provision has not run yet), and the batch runner logs the real ERROR if the
// instance is still unknown after the retry pass.
func (d *dispatcher) transition(rep report, instanceID, kind string, op func(string) (*runtime.Instance, error)) (report, bool) {
	ref, ok := d.tracker.RefForInstance(instanceID)
	if !ok {
		d.logger.Debug("uplink lifecycle command names an instance not yet known to this node; deferring one retry",
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
