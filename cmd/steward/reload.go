package main

import (
	"log/slog"

	"github.com/hardrails/steward/internal/runtime"
)

// reloadMaxInstances hot-reloads the max_instances cap from the -config file in
// response to SIGHUP. It is the live sibling of the startup fold in main() and
// obeys the exact same precedence and validation rules, so an operator can retune
// a node's capacity ceiling without a restart while nothing about the reload
// diverges from what a real boot would accept.
//
// Scope is deliberately narrow: only max_instances is reloaded. Every other
// setting — the listen address, the uplink URL and credential, the state file —
// is a much larger, riskier live-reconfiguration surface (rebinding a port,
// re-dialing a control plane, swapping a durable-state file underneath in-flight
// mutations) and is out of scope for this mechanism. max_instances is a pure
// in-memory field (it is not part of the persisted state snapshot; see
// persist.go), so reloading it touches no listener, no socket, and no file.
//
// Every branch below logs a line whose message starts with "sighup reload:" so a
// test can assert on it and an operator can grep one prefix for the whole reload
// story. On any rejection the live cap is left exactly as it was — a SIGHUP can
// never crash the process or apply a partial change.
//
// fileMayApply carries the startup precedence decision (see main()): if a
// -max-instances flag or STEWARD_MAX_INSTANCES env var pinned the cap at startup,
// the config file may not fill it then and must not override it on a live reload
// either. That is a considered choice — the reload obeys the same flag > env >
// file precedence as startup rather than inventing a different rule for the live
// path — so a mismatch is logged as an explicit rejection, never silently applied
// or silently ignored.
func reloadMaxInstances(configFile string, fileMayApply bool, tracker *runtime.Tracker, logger *slog.Logger) {
	// No -config file at startup: there is nothing to re-read, so SIGHUP is a
	// documented no-op. This is a real log line, not silence, so an operator who
	// sent SIGHUP expecting a reload sees why nothing happened.
	if configFile == "" {
		logger.Info("sighup reload: no -config file was set at startup, so there is nothing to reload (documented no-op)")
		return
	}

	// Re-read and re-parse the file through the same fail-closed loader startup
	// uses: it rejects a read error, malformed JSON, an unknown key, or trailing
	// data. A bad file must never crash the process or apply a partial change, so
	// on any error the live cap stays exactly as it was.
	fc, err := loadConfigFile(configFile)
	if err != nil {
		logger.Error("sighup reload: re-reading the -config file failed; keeping the live max_instances cap unchanged",
			"err", err)
		return
	}

	// The file omits max_instances: nothing to reload for this key.
	if fc.MaxInstances == nil {
		logger.Info("sighup reload: the -config file has no max_instances key; nothing to reload",
			"config", configFile)
		return
	}

	// A -max-instances flag or STEWARD_MAX_INSTANCES env var set at startup
	// permanently takes precedence over the file for this key (flag > env > file).
	// Applying the file's value on a live reload would silently invert that
	// precedence, so reject it loudly instead — naming both the file's value and
	// the live cap that stays in force.
	if !fileMayApply {
		logger.Warn("sighup reload: max_instances not applied; a -max-instances flag or STEWARD_MAX_INSTANCES env var set at startup takes precedence over the config file (flag > env > file) on the live reload path too",
			"config", configFile,
			"file_max_instances", *fc.MaxInstances,
			"live_max_instances", tracker.MaxInstances())
		return
	}

	// A non-positive value is a configuration mistake, not a request for
	// "unlimited" — the same fail-closed rule prepareRuntime's startup check
	// applies, with the same actionable hint. Reject it and keep the last-valid
	// cap; do not call SetMaxInstances with it.
	if *fc.MaxInstances <= 0 {
		logger.Error("sighup reload: invalid max_instances in the -config file; keeping the live cap unchanged",
			"value", *fc.MaxInstances,
			"hint", "-max-instances (or STEWARD_MAX_INSTANCES, or max_instances in the config file) must be a positive integer; omit it to use the default 1024")
		return
	}

	// No change from the live cap: report it (an operator greps this to confirm
	// their SIGHUP was seen) and skip the write.
	old := tracker.MaxInstances()
	if *fc.MaxInstances == old {
		logger.Info("sighup reload: max_instances is unchanged; nothing to reload",
			"max_instances", old)
		return
	}

	// The success path an operator greps for: name the old and new cap clearly.
	// SetMaxInstances does not evict any already-tracked instance, even when the
	// new cap is below the current count — Provision's own capacity check blocks
	// new provisions until ordinary attrition drops the count back under the
	// ceiling (see runtime.Tracker.SetMaxInstances and the "circuit breaker on
	// growth, not on reload" precedent in persist.go).
	//
	// old was read via a separate, prior MaxInstances() lock acquisition, so the
	// logged "old" is accurate only because reloadMaxInstances is the sole caller
	// of SetMaxInstances today. A second call site (e.g. an API-driven cap
	// update) would need its own lock or a combined swap-and-return method to
	// keep this read-then-write pair race-free.
	tracker.SetMaxInstances(*fc.MaxInstances)
	logger.Info("sighup reload: max_instances updated",
		"old_max_instances", old,
		"new_max_instances", *fc.MaxInstances)
}
