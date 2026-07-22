// Command steward runs the on-node lifecycle supervisor HTTP server.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/hardrails/steward/internal/runtime"
	"github.com/hardrails/steward/internal/server"
	"github.com/hardrails/steward/internal/uplink"
)

func main() {
	// A bootstrap logger at the default level records the few startup errors that
	// must be reported before -log-level is known: the env-default validations
	// below run before flag.Parse. They are Error-level lines, emitted regardless
	// of the eventual level; the logger is rebuilt at the configured level in
	// prepareRuntime, before any request is served or poll is sent.
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	// The uplink poll interval's default comes from STEWARD_UPLINK_POLL_INTERVAL when
	// set. A SET-but-unparseable value (a "30sec" typo for "30s") is a fail-closed
	// startup error naming the value, the env var, and the expected format — the same
	// discipline the credential loader and the -uplink-url check apply — never a
	// silent fall back to the 10s default at a cadence the operator did not ask for.
	// An unset value uses the default silently. (The -uplink-poll-interval CLI flag
	// already fails closed on an invalid value: Go's flag package parses a duration
	// flag with time.ParseDuration and exits non-zero on a parse error.)
	pollIntervalDefault, err := envDuration("STEWARD_UPLINK_POLL_INTERVAL", 10*time.Second)
	if err != nil {
		logger.Error("configure uplink poll interval", "err", err)
		os.Exit(1)
	}

	// STEWARD_DISABLE_INBOUND_LISTENER controls network exposure, not a soft
	// operational limit like -max-instances or -uplink-poll-interval — a set-but-
	// unparseable value ("yes", "on", a typo) must not silently fall back to false
	// (listener enabled), or an operator who explicitly tried to close the inbound
	// surface would get it silently left open instead. Fail closed here, the same
	// discipline envDuration applies to the poll interval above, rather than the
	// soft envOrInt fallback other, non-security-relevant flags use.
	disableInboundDefault, err := envBool("STEWARD_DISABLE_INBOUND_LISTENER", false)
	if err != nil {
		logger.Error("configure inbound listener", "err", err)
		os.Exit(1)
	}

	// STEWARD_ENABLE_METRICS gates the optional /metrics endpoint. It is not a
	// security-critical "does this open a network surface at all" switch the way
	// -disable-inbound-listener is (that flag decides whether ANY listener binds;
	// this one only decides whether one more GET route exists on an already-bound
	// listener), but the same "a typo must not silently pick the wrong side"
	// reasoning still applies, so it gets the same fail-closed envBool treatment
	// rather than the soft envOrInt-style fallback.
	enableMetricsDefault, err := envBool("STEWARD_ENABLE_METRICS", false)
	if err != nil {
		logger.Error("configure metrics endpoint", "err", err)
		os.Exit(1)
	}

	// STEWARD_UPLINK_TLS_SKIP_VERIFY disables verification of the control plane's
	// TLS certificate — a security-critical switch, so a set-but-unparseable value
	// gets the same fail-closed envBool treatment -disable-inbound-listener does
	// rather than a soft fallback: a typo must never silently pick the insecure
	// side. It defaults false (verify), and prepareRuntime logs a loud warning when
	// it is true.
	uplinkTLSSkipVerifyDefault, err := envBool("STEWARD_UPLINK_TLS_SKIP_VERIFY", false)
	if err != nil {
		logger.Error("configure uplink TLS", "err", err)
		os.Exit(1)
	}

	// STEWARD_ENABLE_PROCESS_EXEC turns Steward from a lifecycle-status tracker into a
	// real process supervisor: with it on, provisioning a spec that carries a
	// "command" field and starting it spawns and supervises an actual OS process. It
	// is a security-critical switch (it enables real command execution), so a
	// set-but-unparseable value gets the same fail-closed envBool treatment
	// -disable-inbound-listener does — a typo must never silently pick the executing
	// side. It defaults false (pure status tracking, exactly as before).
	enableProcessExecDefault, err := envBool("STEWARD_ENABLE_PROCESS_EXEC", false)
	if err != nil {
		logger.Error("configure process execution", "err", err)
		os.Exit(1)
	}
	allowNonLoopbackProcessExecDefault, err := envBool("STEWARD_ALLOW_NONLOOPBACK_PROCESS_EXEC", false)
	if err != nil {
		logger.Error("configure non-loopback process execution acknowledgement", "err", err)
		os.Exit(1)
	}
	allowRootProcessExecDefault, err := envBool("STEWARD_ALLOW_ROOT_PROCESS_EXEC", false)
	if err != nil {
		logger.Error("configure root process execution acknowledgement", "err", err)
		os.Exit(1)
	}

	// STEWARD_PROCESS_STOP_GRACE_PERIOD is how long a stop waits after SIGTERM before
	// escalating to SIGKILL. Like the poll interval it gets the fail-closed
	// envDuration treatment: a set-but-unparseable value is a startup error, never a
	// silent fall back to the default. Only used when process execution is enabled.
	processStopGraceDefault, err := envDuration("STEWARD_PROCESS_STOP_GRACE_PERIOD", runtime.DefaultStopGracePeriod)
	if err != nil {
		logger.Error("configure process stop grace period", "err", err)
		os.Exit(1)
	}

	// STEWARD_UPLINK_COMMAND_QUEUE_DEPTH is the backpressure bound this feature adds;
	// a SET-but-unparseable value ("25O") must not silently fall back to the 256
	// default and run at a cap the operator never chose, so it gets the same
	// fail-closed treatment envDuration/envBool give (not the soft envOrInt the
	// pre-existing -max-instances flag uses). A non-positive value is caught later,
	// fail-closed, in prepareRuntime.
	queueDepthDefault, err := envInt("STEWARD_UPLINK_COMMAND_QUEUE_DEPTH", 256)
	if err != nil {
		logger.Error("configure uplink command queue depth", "err", err)
		os.Exit(1)
	}

	addr := flag.String("addr", envOr("STEWARD_ADDR", "127.0.0.1:8080"), "host:port to listen on")
	maxInstances := flag.Int("max-instances", envOrInt("STEWARD_MAX_INSTANCES", 1024),
		"maximum number of tracked instances before Provision returns 503")
	rateLimitPerSecond := flag.Int("max-requests-per-second", envOrInt("STEWARD_MAX_REQUESTS_PER_SECOND", 20),
		"max inbound requests per second per source IP before returning 429 (burst is 2x this); 0 or negative disables the per-source rate limiter")
	stateFile := flag.String("state-file", envOr("STEWARD_STATE_FILE", ""),
		"optional path to a JSON file for durable instance state; empty means in-memory only (state is lost on restart)")
	uplinkURL := flag.String("uplink-url", envOr("STEWARD_UPLINK_URL", ""),
		"control-plane base URL for the outbound uplink; empty disables it (inbound REST only)")
	uplinkCredentialFile := flag.String("uplink-credential-file", envOr("STEWARD_UPLINK_CREDENTIAL_FILE", ""),
		"path to the node's uplink credential JSON; required when -uplink-url is set")
	uplinkTLSCAFile := flag.String("uplink-tls-ca-file", envOr("STEWARD_UPLINK_TLS_CA_FILE", ""),
		"path to a PEM CA bundle used to verify the control plane's TLS certificate; empty verifies against the host's system root CAs")
	uplinkTLSClientCert := flag.String("uplink-tls-client-cert", envOr("STEWARD_UPLINK_TLS_CLIENT_CERT", ""),
		"path to a PEM client certificate presented for mutual TLS (mTLS); requires -uplink-tls-client-key")
	uplinkTLSClientKey := flag.String("uplink-tls-client-key", envOr("STEWARD_UPLINK_TLS_CLIENT_KEY", ""),
		"path to the PEM private key for -uplink-tls-client-cert; requires -uplink-tls-client-cert")
	uplinkTLSSkipVerify := flag.Bool("uplink-tls-skip-verify", uplinkTLSSkipVerifyDefault,
		"INSECURE: skip verification of the control plane's TLS certificate. Defeats TLS authentication and exposes the uplink to a man-in-the-middle; off by default and logged loudly when on. For temporary diagnostics only.")
	uplinkPollInterval := flag.Duration("uplink-poll-interval", pollIntervalDefault,
		"base cadence for uplink polling; jitter is applied on top; clamped to a 5-minute ceiling (the failed-poll backoff cap)")
	uplinkCommandQueueDepth := flag.Int("uplink-command-queue-depth", queueDepthDefault,
		"maximum number of received-but-not-yet-executed uplink commands held at once (queued plus in-flight); a poll cycle's excess beyond this is rejected and left for the control plane to redeliver, rather than committing the node to unbounded work. Must be a positive integer; only consumed when -uplink-url is set.")
	disableInbound := flag.Bool("disable-inbound-listener", disableInboundDefault,
		"do not bind an inbound HTTP listener; requires -uplink-url. All fleet operations then flow through the outbound uplink poll loop only.")
	enableMetrics := flag.Bool("enable-metrics", enableMetricsDefault,
		"expose GET /metrics (Prometheus text exposition format) on the inbound listener: current instance count by status, uplink poll latency and backoff state, and uplink command success/failure counters; off by default. Has no effect when -disable-inbound-listener is set (there is no listener to serve it from).")
	auditLogFile := flag.String("audit-log-file", envOr("STEWARD_AUDIT_LOG_FILE", ""),
		"optional path to a JSON-lines file recording one record per executed uplink command (timestamp, command_id, instance_id, kind, status, and error detail on failure); empty disables command auditing")
	enableProcessExec := flag.Bool("enable-process-exec", enableProcessExecDefault,
		"enable real OS-process supervision: when on, an instance whose spec has a \"command\" field spawns and supervises an actual process on start (SIGTERM/SIGKILL on stop, SIGSTOP/SIGCONT on hibernate/resume). Off by default (pure status tracking). Provisioning a command-bearing spec is REJECTED with 400 while this is off. Spawned commands run with STEWARD'S OWN user and privileges (no privilege drop, no sandbox) — if Steward runs as root, they run as root, so run Steward as an unprivileged, dedicated user. No sandboxing or resource limits — see ARCHITECTURE.md.")
	allowNonLoopbackProcessExec := flag.Bool("allow-nonloopback-process-exec", allowNonLoopbackProcessExecDefault,
		"DANGEROUS acknowledgement: permit process execution while the inbound listener is reachable beyond loopback. Off by default; prefer -disable-inbound-listener with the authenticated outbound uplink, or bind -addr to loopback.")
	allowRootProcessExec := flag.Bool("allow-root-process-exec", allowRootProcessExecDefault,
		"DANGEROUS acknowledgement: permit process execution while Steward runs as root. Off by default; prefer an unprivileged dedicated service account.")
	processStopGracePeriod := flag.Duration("process-stop-grace-period", processStopGraceDefault,
		"how long a stop waits after SIGTERM before escalating to SIGKILL, when process execution is enabled; must be positive")
	logLevel := flag.String("log-level", envOr("STEWARD_LOG_LEVEL", "info"),
		"log verbosity: one of debug, info, warn, error (case-insensitive)")
	configFile := flag.String("config", envOr("STEWARD_CONFIG", ""),
		"optional path to a JSON config file supplying any of the settings above; a flag or env var overrides it (precedence: flag > env > config file)")
	checkConfig := flag.Bool("check-config", false,
		"validate the resolved configuration (flags, env, and any -config file) with the same fail-closed checks a real startup runs, then exit 0 (valid) or non-zero (naming the problem), without binding a port or starting the uplink loop")
	showVersion := flag.Bool("version", false,
		"print version information and exit")
	showSchema := flag.Bool("schema", false,
		"print the JSON Schema (draft 2020-12) for the -config file to stdout and exit 0, without binding a port or starting the uplink loop; it describes the config file's shape and constraints (generated from the config struct, so it never drifts from what a real boot accepts)")
	flag.Parse()

	// -version prints the build/version string and exits 0, before loading the
	// config file, binding any port, loading state, or starting the uplink loop. It
	// resolves the same value GET /v1/capabilities advertises (server.ResolveVersion):
	// the Go toolchain's stamped VCS revision or tagged module version, falling back
	// to the compiled-in constant under `go run`.
	if *showVersion {
		fmt.Println("steward " + server.ResolveVersion())
		os.Exit(0)
	}

	// -schema prints the JSON Schema for the -config file and exits 0, in the same
	// early action-flag block as -version and before loadConfigFile: it describes
	// the config file's *shape*, not any particular file's resolved values, so it
	// needs no -config, no port, and no uplink loop. The schema is generated by
	// reflecting over the fileConfig struct (see configschema.go), so a field added
	// there appears here automatically and the schema cannot silently drift from
	// what a real boot accepts. It goes to stdout like -version; a generation error
	// (only reachable if a future fileConfig field has a Go type with no JSON Schema
	// mapping) fails loudly on stderr rather than emitting a silently-incomplete
	// schema.
	if *showSchema {
		schema, err := configSchemaJSON()
		if err != nil {
			fmt.Fprintln(os.Stderr, "generate config schema:", err)
			os.Exit(1)
		}
		fmt.Println(string(schema))
		os.Exit(0)
	}

	// Load the JSON config file (if any) and fold it in as the lowest-precedence
	// layer, below env and flags. It is read after -version (which needs no config)
	// but before every validation, so -check-config validates a -config file too and
	// a malformed file fails closed identically for a real boot and a dry run.
	fc, err := loadConfigFile(*configFile)
	if err != nil {
		logger.Error("load config file", "err", err)
		os.Exit(1)
	}
	// Fold the config file in as the lowest-precedence layer, below env and flags.
	// flag.Parse has already applied the flag layer (an explicitly-passed flag) and
	// the env layer (folded into each flag's default via envOr/envOrInt/envDuration/
	// envBool). A config-file value may therefore fill a setting only when BOTH its
	// flag was not passed and its env var is unset — fileMayFill encodes exactly that,
	// so the file can never override an operator's flag or env choice. An empty (or
	// unset) env var counts as "env absent" so the file may fill it, matching
	// envOr/envOrInt/envDuration/envBool, which all treat an empty value as unset.
	setFlags := map[string]bool{}
	flag.Visit(func(f *flag.Flag) { setFlags[f.Name] = true })
	fileMayFill := func(flagName, envKey string) bool {
		return !setFlags[flagName] && os.Getenv(envKey) == ""
	}
	// Capture the max-instances precedence decision once, here, while fileMayFill
	// is in scope: setFlags and the environment are fixed after startup, so this
	// bool is stable for the process's whole life. The SIGHUP reload goroutine
	// (wired after prepareRuntime) closes over it so a live config re-read honors
	// the same flag > env > file precedence the startup fold below applies — a cap
	// pinned by -max-instances or STEWARD_MAX_INSTANCES at startup is never
	// overridden by a later file re-read either, rather than the live path
	// inventing a different rule from the startup one.
	fileMayReloadMaxInstances := fileMayFill("max-instances", "STEWARD_MAX_INSTANCES")
	if fc.Addr != nil && fileMayFill("addr", "STEWARD_ADDR") {
		*addr = *fc.Addr
	}
	if fc.MaxInstances != nil && fileMayFill("max-instances", "STEWARD_MAX_INSTANCES") {
		*maxInstances = *fc.MaxInstances
	}
	if fc.StateFile != nil && fileMayFill("state-file", "STEWARD_STATE_FILE") {
		*stateFile = *fc.StateFile
	}
	if fc.UplinkURL != nil && fileMayFill("uplink-url", "STEWARD_UPLINK_URL") {
		*uplinkURL = *fc.UplinkURL
	}
	if fc.UplinkCredentialFile != nil && fileMayFill("uplink-credential-file", "STEWARD_UPLINK_CREDENTIAL_FILE") {
		*uplinkCredentialFile = *fc.UplinkCredentialFile
	}
	if fc.UplinkTLSCAFile != nil && fileMayFill("uplink-tls-ca-file", "STEWARD_UPLINK_TLS_CA_FILE") {
		*uplinkTLSCAFile = *fc.UplinkTLSCAFile
	}
	if fc.UplinkTLSClientCert != nil && fileMayFill("uplink-tls-client-cert", "STEWARD_UPLINK_TLS_CLIENT_CERT") {
		*uplinkTLSClientCert = *fc.UplinkTLSClientCert
	}
	if fc.UplinkTLSClientKey != nil && fileMayFill("uplink-tls-client-key", "STEWARD_UPLINK_TLS_CLIENT_KEY") {
		*uplinkTLSClientKey = *fc.UplinkTLSClientKey
	}
	if fc.UplinkTLSSkipVerify != nil && fileMayFill("uplink-tls-skip-verify", "STEWARD_UPLINK_TLS_SKIP_VERIFY") {
		*uplinkTLSSkipVerify = *fc.UplinkTLSSkipVerify
	}
	if fc.UplinkCommandQueueDepth != nil && fileMayFill("uplink-command-queue-depth", "STEWARD_UPLINK_COMMAND_QUEUE_DEPTH") {
		*uplinkCommandQueueDepth = *fc.UplinkCommandQueueDepth
	}
	if fc.DisableInboundListener != nil && fileMayFill("disable-inbound-listener", "STEWARD_DISABLE_INBOUND_LISTENER") {
		*disableInbound = *fc.DisableInboundListener
	}
	if fc.LogLevel != nil && fileMayFill("log-level", "STEWARD_LOG_LEVEL") {
		*logLevel = *fc.LogLevel
	}
	if fc.EnableProcessExec != nil && fileMayFill("enable-process-exec", "STEWARD_ENABLE_PROCESS_EXEC") {
		*enableProcessExec = *fc.EnableProcessExec
	}
	if fc.AllowNonLoopbackProcessExec != nil && fileMayFill("allow-nonloopback-process-exec", "STEWARD_ALLOW_NONLOOPBACK_PROCESS_EXEC") {
		*allowNonLoopbackProcessExec = *fc.AllowNonLoopbackProcessExec
	}
	if fc.AllowRootProcessExec != nil && fileMayFill("allow-root-process-exec", "STEWARD_ALLOW_ROOT_PROCESS_EXEC") {
		*allowRootProcessExec = *fc.AllowRootProcessExec
	}
	// process_stop_grace_period is carried as a Go duration string (like
	// uplink_poll_interval), parsed here the same way; a malformed value is a
	// fail-closed startup error naming the file and the bad value.
	if fc.ProcessStopGracePeriod != nil && fileMayFill("process-stop-grace-period", "STEWARD_PROCESS_STOP_GRACE_PERIOD") {
		d, perr := time.ParseDuration(*fc.ProcessStopGracePeriod)
		if perr != nil {
			logger.Error("configure process stop grace period",
				"err", fmt.Errorf("config file %q has an invalid process_stop_grace_period %q: not a valid duration (want e.g. \"10s\", \"30s\")", *configFile, *fc.ProcessStopGracePeriod))
			os.Exit(1)
		}
		*processStopGracePeriod = d
	}
	// The poll interval is the one non-string setting: the file carries it as a Go
	// duration string (e.g. "30s"), parsed here the same way envDuration and the
	// -uplink-poll-interval flag parse theirs. A malformed value is a fail-closed
	// startup error naming the file and the bad value, never a silent default.
	if fc.UplinkPollInterval != nil && fileMayFill("uplink-poll-interval", "STEWARD_UPLINK_POLL_INTERVAL") {
		d, perr := time.ParseDuration(*fc.UplinkPollInterval)
		if perr != nil {
			logger.Error("configure uplink poll interval",
				"err", fmt.Errorf("config file %q has an invalid uplink_poll_interval %q: not a valid duration (want e.g. \"10s\", \"1m30s\")", *configFile, *fc.UplinkPollInterval))
			os.Exit(1)
		}
		*uplinkPollInterval = d
	}

	cfg := resolvedConfig{
		addr:                        *addr,
		maxInstances:                *maxInstances,
		stateFile:                   *stateFile,
		uplinkURL:                   *uplinkURL,
		uplinkCredentialFile:        *uplinkCredentialFile,
		uplinkTLSCAFile:             *uplinkTLSCAFile,
		uplinkTLSClientCert:         *uplinkTLSClientCert,
		uplinkTLSClientKey:          *uplinkTLSClientKey,
		uplinkTLSSkipVerify:         *uplinkTLSSkipVerify,
		uplinkPollInterval:          *uplinkPollInterval,
		uplinkCommandQueueDepth:     *uplinkCommandQueueDepth,
		disableInbound:              *disableInbound,
		enableMetrics:               *enableMetrics,
		auditLogFile:                *auditLogFile,
		logLevel:                    *logLevel,
		enableProcessExec:           *enableProcessExec,
		allowNonLoopbackProcessExec: *allowNonLoopbackProcessExec,
		allowRootProcessExec:        *allowRootProcessExec,
		processStopGracePeriod:      *processStopGracePeriod,
	}

	// -check-config is a dry run: it exercises the exact same validation-and-build
	// sequence a real startup runs (prepareRuntime), then exits 0 (valid) or
	// non-zero with the same actionable error — without binding a port, serving, or
	// starting the uplink poll loop. It is the "will this configuration work?"
	// question an operator asks before rolling a config out, the -config file
	// included.
	if *checkConfig {
		_, _, _, dryRunAuditLogger, err := prepareRuntime(cfg, logger, true)
		// prepareRuntime opens the audit log file (when -audit-log-file is set)
		// even in a dry run, so -check-config exercises the same fail-closed
		// openability check a real boot would; close it again immediately since a
		// dry run keeps nothing running afterward. Nil-safe either way (auditing
		// disabled, or prepareRuntime failed before ever opening it).
		_ = dryRunAuditLogger.Close()
		if err != nil {
			os.Exit(1)
		}
		fmt.Println("configuration valid")
		os.Exit(0)
	}

	logger, tracker, poller, auditLogger, err := prepareRuntime(cfg, logger, false)
	if err != nil {
		os.Exit(1)
	}
	// auditLogger is the caller's to close regardless of whether poller is nil
	// (see prepareRuntime's doc comment): -audit-log-file is accepted even with
	// the uplink disabled, in which case the file is opened but never reachable
	// through poller. Closing it directly here -- rather than through a
	// poller-scoped close that would never run in that combination -- is what
	// keeps the file handle from leaking for the process's entire lifetime.
	// Nil-safe, so this defer is unconditional.
	defer func() { _ = auditLogger.Close() }()

	// Register the signal handler as the FIRST thing after a successful
	// prepareRuntime, before any further startup logging or server construction:
	// any work between prepareRuntime succeeding and this call is a window where
	// SIGTERM/SIGINT would hit the OS default disposition (immediate termination)
	// instead of triggering a graceful shutdown -- the earlier this runs, the
	// smaller that window.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	runtimeFailure := make(chan struct{}, 1)
	reportRuntimeFailure := func() {
		select {
		case runtimeFailure <- struct{}{}:
		default:
		}
		stop()
	}

	// SIGHUP triggers a live re-read of the -config file to hot-reload the
	// max_instances cap (only). It is wired here, at the same "as early as
	// possible" point as the shutdown handler above and for the same reason: any
	// window between prepareRuntime succeeding and this registration is one where a
	// SIGHUP would hit the OS default disposition (process termination) instead of
	// a reload — the earlier this runs, the smaller that window.
	//
	// SIGHUP must NOT be one of NotifyContext's signals above: that call cancels
	// ctx — i.e. begins graceful shutdown — on any signal it lists, and a reload
	// must never shut the process down. So it gets its own channel and a small
	// goroutine. The channel is buffered (size 1) so a SIGHUP arriving while a
	// previous reload is still running is not dropped by the runtime's internal
	// signal-forwarding goroutine blocking on an unbuffered send. The goroutine
	// exits on ctx.Done() so it does not leak past shutdown.
	hupCh := make(chan os.Signal, 1)
	signal.Notify(hupCh, syscall.SIGHUP)
	defer signal.Stop(hupCh)
	go func() {
		for {
			select {
			case <-hupCh:
				reloadMaxInstances(*configFile, fileMayReloadMaxInstances, tracker, logger)
			case <-ctx.Done():
				return
			}
		}
	}()

	// When the inbound listener is disabled, srv stays nil: no http.Server is built
	// and no ListenAndServe goroutine is started. All fleet operations then flow
	// through the uplink poll loop only (see the fail-closed guard in prepareRuntime,
	// which already refused this combination without -uplink-url).
	var srv *http.Server
	if !cfg.disableInbound {
		// The per-source rate limiter is a DoS defense for this unauthenticated-by-design
		// listener, in the same class as the body-size and instance-count caps. Log its
		// state at startup so an operator sees whether inbound requests are throttled; a
		// disabled limiter is a WARN because it leaves the flood surface open (a
		// deliberate choice only when a fronting gateway already rate-limits).
		if *rateLimitPerSecond > 0 {
			logger.Info("inbound rate limiting enabled", "max_requests_per_second_per_source", *rateLimitPerSecond)
		} else {
			logger.Warn("inbound rate limiting disabled",
				"hint", "per-source request throttling is off; set -max-requests-per-second (or STEWARD_MAX_REQUESTS_PER_SECOND) to a positive value to re-enable it")
		}
		if cfg.enableMetrics {
			logger.Info("metrics endpoint enabled", "path", "/metrics")
		}

		// uplinkMetricsSource is declared as the server.UplinkMetrics interface
		// (not *uplink.Poller) and left at its zero value when poller is nil, so
		// it stays a genuinely nil interface -- assigning a nil *uplink.Poller to
		// an interface variable directly would instead produce a non-nil
		// interface holding a nil pointer (the classic Go typed-nil trap), which
		// handleMetrics's `s.uplinkMetrics != nil` check would then wrongly treat
		// as "uplink metrics available."
		var uplinkMetricsSource server.UplinkMetrics
		if poller != nil {
			uplinkMetricsSource = poller
		}
		srv = &http.Server{
			Addr:              cfg.addr,
			Handler:           server.NewWithTracker(logger, tracker, *rateLimitPerSecond, cfg.enableMetrics, uplinkMetricsSource).Handler(),
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       15 * time.Second,
			WriteTimeout:      15 * time.Second,
			IdleTimeout:       60 * time.Second,
		}
	}

	// Start the uplink poll loop bound to the same signal context, so a shutdown
	// cancels both its inter-poll wait and any in-flight request. Its done channel
	// is awaited in the graceful-shutdown block below.
	var uplinkDone <-chan struct{}
	if poller != nil {
		done := make(chan struct{})
		go func() {
			defer close(done)
			poller.Run(ctx)
			// Poller.Run returns for real work only when ctx is cancelled (a
			// shutdown already in progress -- ctx.Err() is non-nil): main always
			// sets uplink.Config.CredentialPath (above), so a fatal 401/403 now
			// pauses and watches the credential file for a fix instead of giving
			// up -- see waitForCredentialChange -- rather than stopping the loop
			// outright. This branch is a defensive fallback for the one case Run
			// can still return with ctx.Err() == nil: CredentialPath unset (not
			// reachable from main today, but Poller is also a library type other
			// callers can construct without it). With no inbound listener to fall
			// back to, that would otherwise leave main blocked on <-ctx.Done()
			// forever: no uplink loop running, no REST API serving, a zombie
			// process an operator's monitoring would see as "up" while it does
			// nothing. Mirrors the server goroutine's own error->stop() pattern
			// above -- a fatal exit on the ONLY control path triggers the same
			// graceful shutdown, rather than hanging silently.
			if srv == nil && ctx.Err() == nil {
				logger.Error("uplink poll loop exited and no inbound listener is configured; shutting down")
				reportRuntimeFailure()
			}
		}()
		uplinkDone = done
	}

	if srv != nil {
		go func() {
			logger.Info("steward listening", "addr", cfg.addr, "version", server.ResolveVersion())
			if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.Error("server error", "err", err)
				reportRuntimeFailure()
			}
		}()
	} else {
		logger.Info("inbound listener disabled; serving via uplink only", "version", server.ResolveVersion())
	}

	<-ctx.Done()
	logger.Info("shutting down")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if srv != nil {
		if err := srv.Shutdown(shutdownCtx); err != nil {
			logger.Error("shutdown error", "err", err)
			os.Exit(1)
		}
	}

	// Wait for the uplink loop to finish, bounded by the same shutdown deadline. ctx
	// is already cancelled, so Run returns promptly; the bound guards against a
	// wedged in-flight request outliving the deadline.
	if uplinkDone != nil {
		select {
		case <-uplinkDone:
		case <-shutdownCtx.Done():
			logger.Warn("uplink poll loop did not stop within the shutdown deadline")
		}
	}
	select {
	case <-runtimeFailure:
		// os.Exit bypasses deferred cleanup. Close the optional audit file after
		// every worker has stopped so systemd receives a failure status without
		// leaking buffered host state.
		_ = auditLogger.Close()
		os.Exit(1)
	default:
	}
}

// resolvedConfig is the fully-layered startup configuration: every setting after
// precedence (flag > env > -config file > built-in default) has been applied. It is
// the single input both the real startup path and the -check-config dry run
// validate and build from, so the two can never diverge on what a valid config is.
type resolvedConfig struct {
	addr                        string
	maxInstances                int
	stateFile                   string
	uplinkURL                   string
	uplinkCredentialFile        string
	uplinkTLSCAFile             string
	uplinkTLSClientCert         string
	uplinkTLSClientKey          string
	uplinkTLSSkipVerify         bool
	uplinkPollInterval          time.Duration
	uplinkCommandQueueDepth     int
	disableInbound              bool
	enableMetrics               bool
	auditLogFile                string
	logLevel                    string
	enableProcessExec           bool
	allowNonLoopbackProcessExec bool
	allowRootProcessExec        bool
	processStopGracePeriod      time.Duration
}

// effectiveUID and inspectExtendedACL are seams for startup-policy tests.
// Production always uses the OS implementations; tests replace them briefly to
// prove fail-closed behavior without depending on the account or filesystem
// running the suite.
var (
	effectiveUID       = os.Geteuid
	inspectExtendedACL = extendedACLPresent
)

// listenerIsLoopback reports whether addr names a literal loopback-only listener.
// It deliberately does not resolve arbitrary hostnames: startup admission must not
// turn DNS state into a security decision. Only literal IPv4/IPv6 loopback
// addresses are accepted; even "localhost" requires the explicit non-loopback
// acknowledgement because its host mapping is outside Steward's control.
func listenerIsLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// validateDurableStateFile rejects an existing state path that is not a regular,
// owner-only file. Snapshots include complete workload definitions and may include
// command environment values. Newly created snapshots are 0600; an operator-
// supplied file must meet the same rule even when process execution is disabled.
// A missing path is valid first-run state and will be created securely.
func validateDurableStateFile(path string) error {
	if path == "" {
		return nil
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect state file %q permissions: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("state file %q must be a regular file, not a symlink or special file", path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("state file %q permissions are %04o; durable state requires 0600 or stricter (run chmod 600 %q)", path, info.Mode().Perm(), path)
	}
	hasACL, err := inspectExtendedACL(path)
	if err != nil {
		return fmt.Errorf("inspect state file %q extended ACL: %w", path, err)
	}
	if hasACL {
		return fmt.Errorf("state file %q has an extended access ACL; durable state requires owner-only access (remove the ACL and run chmod 600 %q)", path, path)
	}
	return nil
}

// prepareRuntime runs every fail-closed startup check against cfg and builds the
// live objects the server runs from — the restored tracker, the poller when the
// uplink is enabled, and the audit logger when -audit-log-file is set. It is the
// ONE validation-and-construction sequence shared by the real startup path and the
// -check-config dry run, so a dry run can never accept a config a real boot would
// reject (or the reverse). It rebuilds the logger at the configured level (returned
// for the caller to keep using) and, on any invalid setting, logs the same
// actionable error a real boot would and returns it. It binds no port and starts no
// goroutine: the caller wires the HTTP server and starts the poll loop from the
// returned objects.
//
// The returned *uplink.AuditLogger is ALWAYS the caller's to close (via its Close
// method, nil-safe if auditing was never enabled) once it is done with it,
// regardless of whether poller is nil: when -audit-log-file is set without
// -uplink-url, the file is still opened (so -check-config exercises the exact
// fail-closed openability check a real boot would) but never wired into a Poller,
// so the caller cannot reach it through poller alone. Returning it as its own value
// — rather than relying on the (possibly-nil) poller to hold the only reference —
// is what lets main close it unconditionally instead of leaking the file handle for
// the process's entire lifetime whenever the uplink is disabled.
//
// When checkOnly is true the success/progress logs ("durable state enabled",
// "uplink enabled") are suppressed: a dry run validates a configuration, it does not
// enable anything, so reporting those would be misleading. The fail-closed error
// logs and the poll-interval-clamp warning — which report on the config itself — are
// emitted either way.
func prepareRuntime(cfg resolvedConfig, logger *slog.Logger, checkOnly bool) (*slog.Logger, *runtime.Tracker, *uplink.Poller, *uplink.AuditLogger, error) {
	// Rebuild the logger at the configured level now that the config is resolved. A
	// garbage -log-level (or STEWARD_LOG_LEVEL, or log_level in the config file) is a
	// fail-closed startup error naming the bad value and the accepted set, logged via
	// the bootstrap logger since the configured one is not yet valid.
	level, err := parseLogLevel(cfg.logLevel)
	if err != nil {
		logger.Error("configure log level", "err", err)
		return logger, nil, nil, nil, err
	}
	logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))

	// -max-instances is a DoS circuit-breaker (an unauthenticated loop of distinct
	// instance_ids is the same OOM shape as an unbounded request body); a
	// non-positive value is a configuration mistake, not a request for "unlimited".
	// The tracker constructor's <=0 → DefaultMaxInstances convenience is for
	// programmatic callers (server.New, tests); at this operator-facing CLI boundary
	// the default already comes from the flag's own 1024, so a non-positive value
	// here can only be a typo. Fail closed and name it — the same discipline the
	// -uplink-url and -disable-inbound-listener checks apply — rather than silently
	// running at 1024 the operator never asked for.
	if cfg.maxInstances <= 0 {
		logger.Error("invalid -max-instances",
			"value", cfg.maxInstances,
			"hint", "-max-instances (or STEWARD_MAX_INSTANCES) must be a positive integer; omit it to use the default 1024")
		return logger, nil, nil, nil, fmt.Errorf("invalid -max-instances %d", cfg.maxInstances)
	}

	// -uplink-command-queue-depth bounds the uplink's received-but-not-yet-executed
	// backlog (queued plus in-flight); a non-positive value is a configuration
	// mistake, not a request for "unbounded", the same fail-closed posture as
	// -max-instances. It is validated unconditionally (not gated on -uplink-url)
	// precisely so the -config schema's exclusiveMinimum:0 constraint stays faithful
	// to the real validator — no stricter, no looser — even though the value is only
	// consumed when the uplink is enabled. A positive default (256) means a config
	// that never sets it always passes.
	if cfg.uplinkCommandQueueDepth <= 0 {
		logger.Error("invalid -uplink-command-queue-depth",
			"value", cfg.uplinkCommandQueueDepth,
			"hint", "-uplink-command-queue-depth (or STEWARD_UPLINK_COMMAND_QUEUE_DEPTH) must be a positive integer; omit it to use the default 256")
		return logger, nil, nil, nil, fmt.Errorf("invalid -uplink-command-queue-depth %d", cfg.uplinkCommandQueueDepth)
	}

	// A node with neither the inbound listener nor the outbound uplink enabled would
	// be unreachable in both directions — a dark, useless process. Fail closed here,
	// before any other startup work, naming both the flag and the fix, the same
	// discipline the uplink credential and poll-interval checks below apply.
	if cfg.disableInbound && cfg.uplinkURL == "" {
		logger.Error("inbound listener disabled but no uplink configured",
			"hint", "a node with neither an inbound listener nor an outbound uplink is unreachable; set -uplink-url (or STEWARD_UPLINK_URL) to poll a control plane, or drop -disable-inbound-listener to serve the inbound REST API")
		return logger, nil, nil, nil, errors.New("inbound listener disabled but no uplink configured")
	}

	// -addr is only exercised by ListenAndServe on the real startup path, which a
	// dry run deliberately never reaches — so without this check, -check-config
	// would bless an unservable addr (a missing-port typo, an out-of-range port) as
	// "configuration valid". Validate syntax without binding: guarded by
	// !disableInbound, since addr is unused on an uplink-only node and a garbage
	// value there must not fail a config that never binds it.
	if !cfg.disableInbound {
		_, port, err := net.SplitHostPort(cfg.addr)
		if err != nil {
			logger.Error("invalid -addr", "value", cfg.addr, "err", err,
				"hint", "-addr (or STEWARD_ADDR) must be host:port, e.g. \"127.0.0.1:8080\" or \":8080\"")
			return logger, nil, nil, nil, fmt.Errorf("invalid -addr %q: %w", cfg.addr, err)
		}
		if n, convErr := strconv.Atoi(port); convErr == nil && (n < 0 || n > 65535) {
			logger.Error("invalid -addr port", "value", cfg.addr, "port", n,
				"hint", "-addr's port must be 0-65535")
			return logger, nil, nil, nil, fmt.Errorf("invalid -addr %q: port %d out of range", cfg.addr, n)
		}
	}

	// Process execution is a security-critical opt-in: with it on, Steward spawns and
	// supervises real OS processes for command-bearing specs. The stop grace period
	// (SIGTERM→SIGKILL window) must be positive; a non-positive value is a
	// configuration mistake, so fail closed and name it, the same discipline
	// -max-instances applies. Only validated when execution is actually enabled — an
	// unused grace value on a tracker in status-only mode must not fail startup.
	if cfg.enableProcessExec && cfg.processStopGracePeriod <= 0 {
		logger.Error("invalid -process-stop-grace-period",
			"value", cfg.processStopGracePeriod.String(),
			"hint", "-process-stop-grace-period (or STEWARD_PROCESS_STOP_GRACE_PERIOD) must be a positive duration, e.g. \"10s\"; omit it to use the default 10s")
		return logger, nil, nil, nil, fmt.Errorf("invalid -process-stop-grace-period %s", cfg.processStopGracePeriod)
	}

	// A directly reachable command-execution endpoint is too dangerous as an
	// accidental default. Loopback and uplink-only nodes are admitted; any broader
	// inbound bind requires an explicit, loudly logged acknowledgement. Steward does
	// not implement authentication itself, so the preferred sovereign topology is an
	// authenticated outbound uplink with no inbound listener.
	if cfg.enableProcessExec && !cfg.disableInbound && !listenerIsLoopback(cfg.addr) {
		if !cfg.allowNonLoopbackProcessExec {
			logger.Error("process execution with a non-loopback inbound listener is blocked",
				"addr", cfg.addr,
				"hint", "use -disable-inbound-listener with the authenticated outbound uplink, bind -addr to loopback, or explicitly acknowledge the risk with -allow-nonloopback-process-exec")
			return logger, nil, nil, nil, fmt.Errorf("process execution blocked on non-loopback listener %q", cfg.addr)
		}
		logger.Warn("DANGEROUS: process execution is exposed through a non-loopback inbound listener",
			"addr", cfg.addr,
			"acknowledgement", "allow-nonloopback-process-exec")
	}

	// Steward executes commands with its own identity and intentionally contains no
	// privilege-dropping machinery. Root therefore turns every accepted command into
	// root code execution; require a separate acknowledgement rather than allowing a
	// service-manager or container default to create that posture silently.
	if cfg.enableProcessExec && effectiveUID() == 0 {
		if !cfg.allowRootProcessExec {
			logger.Error("process execution while running as root is blocked",
				"hint", "run Steward as an unprivileged dedicated user, or explicitly acknowledge the risk with -allow-root-process-exec")
			return logger, nil, nil, nil, errors.New("process execution blocked while running as root")
		}
		logger.Warn("DANGEROUS: process execution is running with root privileges",
			"acknowledgement", "allow-root-process-exec")
	}

	if err := validateDurableStateFile(cfg.stateFile); err != nil {
		logger.Error("unsafe durable state file", "err", err)
		return logger, nil, nil, nil, err
	}

	// LoadTracker restores any existing state (validating the file) before the server
	// accepts requests. An empty -state-file disables persistence (the in-memory
	// default); a corrupt or unreadable file fails closed here with a message naming
	// the path and fix, rather than starting with silently-empty state. In a dry run
	// this validates the file is loadable without keeping the tracker for real use.
	// WithExec threads the process-supervision settings in; when execution is disabled
	// it is inert and the tracker is the pure status map it has always been. On a real
	// (non-dry-run) boot with a state file and execution enabled, this is also where
	// LoadTracker reconciles any previously-supervised process against reality (a
	// liveness probe on its stored pid), so the exec config must be in place first.
	tracker, err := runtime.LoadTracker(cfg.maxInstances, cfg.stateFile, runtime.WithExec(runtime.ExecConfig{
		Enabled:         cfg.enableProcessExec,
		StopGracePeriod: cfg.processStopGracePeriod,
		Logger:          logger,
	}))
	if err != nil {
		logger.Error("load state", "err", err)
		return logger, nil, nil, nil, err
	}
	if cfg.stateFile != "" && !checkOnly {
		logger.Info("durable state enabled", "path", cfg.stateFile, "restored_instances", tracker.Len())
	}
	if cfg.enableProcessExec && !checkOnly {
		logger.Warn("process execution is ENABLED: instances with a \"command\" spec will spawn and supervise real OS processes; there is no sandboxing or resource limiting (see ARCHITECTURE.md)",
			"stop_grace_period", cfg.processStopGracePeriod.String())
	}

	// -audit-log-file is opened here, before the uplink is built, regardless of
	// whether the uplink is enabled — so -check-config exercises the same
	// fail-closed open-for-append check a real boot would (see
	// uplink.NewAuditLogger). It only ever RECEIVES records from the uplink
	// dispatcher (see docs/uplink-client.md's command audit log section), so a
	// configured audit log with no uplink is accepted but inert; that
	// combination gets a WARN, not a fail-closed error, because it is merely
	// pointless, not unsafe (unlike -disable-inbound-listener without
	// -uplink-url, which leaves the node unreachable).
	var auditLogger *uplink.AuditLogger
	if cfg.auditLogFile != "" {
		auditLogger, err = uplink.NewAuditLogger(cfg.auditLogFile)
		if err != nil {
			logger.Error("open audit log file", "err", err)
			return logger, nil, nil, nil, err
		}
		if cfg.uplinkURL == "" {
			logger.Warn("audit log file configured but the uplink is disabled; no commands will ever be executed to log",
				"hint", "set -uplink-url (or STEWARD_UPLINK_URL) to enable the uplink and start recording executed commands, or drop -audit-log-file if this is intentional")
		} else if !checkOnly {
			logger.Info("command audit logging enabled", "path", cfg.auditLogFile)
		}
	}

	// The uplink is enabled iff -uplink-url is set (mirroring how -state-file's
	// presence enables durable state). When enabled, load the node credential
	// fail-closed and build the poller — a missing or corrupt credential, or a URL
	// that is not an absolute http(s) URL, is a startup error naming the path/value,
	// never a silently-disabled uplink. The poll goroutine is started by the caller,
	// not here; in a dry run NewPoller validates the URL and credential without
	// dialing. CredentialPath is threaded through unconditionally so a fatal 401/403
	// hot-reloads instead of stopping the loop — see uplink.Poller.Run and
	// docs/uplink-client.md's credential hot-reload section.
	var poller *uplink.Poller
	if cfg.uplinkURL != "" {
		if cfg.uplinkCredentialFile == "" {
			logger.Error("uplink enabled but no credential file",
				"hint", "set -uplink-credential-file (or STEWARD_UPLINK_CREDENTIAL_FILE) when -uplink-url is set")
			return logger, nil, nil, auditLogger, errors.New("uplink enabled but no credential file")
		}
		cred, err := uplink.LoadCredential(cfg.uplinkCredentialFile)
		if err != nil {
			logger.Error("load uplink credential", "err", err)
			return logger, nil, nil, auditLogger, err
		}
		// -uplink-tls-skip-verify defeats TLS authentication entirely, so warn
		// loudly whenever it is set -- in a dry run too, since it is a fact about
		// the config an operator must see before a rollout, exactly like the
		// poll-interval-clamp warning below.
		if cfg.uplinkTLSSkipVerify {
			logger.Warn("uplink TLS certificate verification is DISABLED (-uplink-tls-skip-verify); the control plane's certificate is not checked and the outbound channel is exposed to a man-in-the-middle — use only for temporary diagnostics, never in production")
		}
		// Build the outbound HTTP client with the operator-configured TLS settings
		// (custom CA, client cert for mTLS, or skip-verify). NewHTTPClient fails
		// closed on an unreadable CA/cert/key, a CA with no usable certificate, or a
		// client cert without its key, so a TLS misconfiguration is a startup error
		// here (and under -check-config, which runs prepareRuntime), never a silent
		// fall back to system defaults.
		httpClient, err := uplink.NewHTTPClient(uplink.TLSConfig{
			CAFile:         cfg.uplinkTLSCAFile,
			ClientCertFile: cfg.uplinkTLSClientCert,
			ClientKeyFile:  cfg.uplinkTLSClientKey,
			SkipVerify:     cfg.uplinkTLSSkipVerify,
		})
		if err != nil {
			logger.Error("configure uplink TLS", "err", err)
			return logger, nil, nil, auditLogger, err
		}
		poller, err = uplink.NewPoller(tracker, uplink.Config{
			BaseURL:           cfg.uplinkURL,
			Credential:        cred.Credential,
			NodeID:            cred.NodeID,
			PollInterval:      cfg.uplinkPollInterval,
			CommandQueueDepth: cfg.uplinkCommandQueueDepth,
			HTTPClient:        httpClient,
			Logger:            logger,
			CredentialPath:    cfg.uplinkCredentialFile,
			AuditLogger:       auditLogger,
		})
		if err != nil {
			logger.Error("configure uplink", "err", err)
			return logger, nil, nil, auditLogger, err
		}
		if !checkOnly {
			logger.Info("uplink enabled",
				"url", cfg.uplinkURL, "node_id", cred.NodeID, "tenant_id", cred.TenantID,
				"poll_interval", cfg.uplinkPollInterval.String(),
				"command_queue_depth", cfg.uplinkCommandQueueDepth)
		}
		// -uplink-poll-interval has no documented ceiling, but the steady-state poll
		// cadence is clamped to the same 5-minute cap used for failed-poll backoff
		// (see backoffDuration): a base at or above the cap polls at the cap, not at
		// the configured value. Warn once naming both, so this is visible rather than
		// a silent surprise — in a dry run too, since it is a fact about the config.
		if cfg.uplinkPollInterval > uplink.MaxBackoff {
			logger.Warn("uplink poll interval exceeds the backoff cap; effective interval is clamped",
				"configured_interval", cfg.uplinkPollInterval.String(), "effective_interval", uplink.MaxBackoff.String())
		}
	}

	return logger, tracker, poller, auditLogger, nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envOrInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}

// envInt reads an integer from the environment, failing closed on a SET-but-invalid
// value instead of silently falling back — the same posture envDuration and envBool
// take, and the reason it is a type-named helper (fail-closed) rather than an
// "Or"-named one (soft, like envOrInt). An unset key returns fallback with no error.
// A set value that strconv.Atoi rejects (a non-integer typo like "25O") returns an
// error naming the key, the bad value, and the fix, so main can make it a startup
// error rather than run at a value the operator never chose.
//
// It is used for -uplink-command-queue-depth specifically: a typo in its env var must
// not silently disable the backpressure bound this feature exists to enforce. The
// pre-existing -max-instances / -max-requests-per-second flags keep the soft envOrInt
// for backward compatibility; giving them the same fail-closed treatment is a separate,
// deliberate change, not smuggled in here.
func envInt(key string, fallback int) (int, error) {
	v := os.Getenv(key)
	if v == "" {
		return fallback, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("invalid %s %q: not a valid integer; fix the value or unset it to use the default", key, v)
	}
	return n, nil
}

// envBool mirrors envDuration's shape and posture, not envOrInt's: this reads a
// SECURITY-relevant boolean (whether the inbound listener binds at all), where a
// set-but-unparseable value ("yes", "on", a typo) must not silently fall back to
// the default. A soft fallback would be wrong in EITHER direction here — an
// operator who typo'd true-meaning-"disable" would silently get the listener
// left open; a hypothetical future flag defaulting true could as easily leave
// something silently closed. Fail closed and name the value, same as
// envDuration does for the poll interval. An unset key returns fallback with no
// error (the expected default path).
func envBool(key string, fallback bool) (bool, error) {
	v := os.Getenv(key)
	if v == "" {
		return fallback, nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false, fmt.Errorf("invalid %s %q: not a valid boolean (want e.g. \"true\", \"false\", \"1\", \"0\"); fix the value or unset it to use the default", key, v)
	}
	return b, nil
}

// envDuration reads a Go duration from the environment, failing closed on a
// SET-but-invalid value instead of silently falling back. An unset key returns
// fallback with no error (the expected default path); a set value that
// time.ParseDuration rejects returns an error naming the key, the bad value, and
// the expected format, so main can make it a startup error rather than run at a
// cadence the operator never asked for.
func envDuration(key string, fallback time.Duration) (time.Duration, error) {
	v := os.Getenv(key)
	if v == "" {
		return fallback, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("invalid %s %q: not a valid duration (want e.g. \"10s\", \"1m30s\"); fix the value or unset it to use the default", key, v)
	}
	return d, nil
}

// parseLogLevel maps a case-insensitive level name to a slog.Level, failing
// closed on any other value. The flag/env default ("info") always parses, so
// only an explicit garbage -log-level or STEWARD_LOG_LEVEL reaches the error
// path — where it names the bad value and the accepted set rather than silently
// picking a verbosity the operator never chose.
func parseLogLevel(s string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("invalid log level %q: want one of debug, info, warn, error (via -log-level or STEWARD_LOG_LEVEL)", s)
	}
}

// fileConfig is the -config JSON file's shape: durable node settings supplied as
// the lowest-precedence layer (flag > env > file). Operational rate limiting,
// metrics enablement, and audit-log output remain flag/environment-only. Every
// field is a pointer so an absent key is distinguishable from a present zero value —
// an absent key leaves the env/flag/default value untouched, while a present key
// (even one set to "" or false) overrides the built-in default. Keys are snake_case,
// matching this repo's other JSON files (state, credential) and the STEWARD_* env
// var suffixes. uplink_poll_interval is a Go duration string (e.g. "30s"), parsed
// the same way the flag and env var parse theirs.
type fileConfig struct {
	Addr                        *string `json:"addr"`
	MaxInstances                *int    `json:"max_instances"`
	StateFile                   *string `json:"state_file"`
	UplinkURL                   *string `json:"uplink_url"`
	UplinkCredentialFile        *string `json:"uplink_credential_file"`
	UplinkTLSCAFile             *string `json:"uplink_tls_ca_file"`
	UplinkTLSClientCert         *string `json:"uplink_tls_client_cert"`
	UplinkTLSClientKey          *string `json:"uplink_tls_client_key"`
	UplinkTLSSkipVerify         *bool   `json:"uplink_tls_skip_verify"`
	UplinkPollInterval          *string `json:"uplink_poll_interval"`
	UplinkCommandQueueDepth     *int    `json:"uplink_command_queue_depth"`
	DisableInboundListener      *bool   `json:"disable_inbound_listener"`
	LogLevel                    *string `json:"log_level"`
	EnableProcessExec           *bool   `json:"enable_process_exec"`
	AllowNonLoopbackProcessExec *bool   `json:"allow_nonloopback_process_exec"`
	AllowRootProcessExec        *bool   `json:"allow_root_process_exec"`
	ProcessStopGracePeriod      *string `json:"process_stop_grace_period"`
}

// loadConfigFile reads and parses the JSON config file at path, fail-closed. It
// mirrors the state-file and credential-file loaders: a read error, malformed JSON,
// an unknown key, or trailing data is a startup error naming the file and the
// problem, never a silently-ignored or half-applied config — an operator's typo'd
// key ("max_instance" for "max_instances") is exactly the "will this config work?"
// foot-gun -check-config exists to catch, so an unknown key is rejected rather than
// silently dropped. An empty path means no config file (the default) and returns a
// zero fileConfig. Value *validity* (a bad log level, a non-positive max-instances, a
// malformed uplink URL) is deliberately NOT checked here — it is caught by the same
// startup sequence that validates flags and env, so a file value and a flag value
// fail identically.
func loadConfigFile(path string) (fileConfig, error) {
	if path == "" {
		return fileConfig{}, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fileConfig{}, fmt.Errorf("read config file %q: %w (fix its path or permissions, or drop -config to use flags and env only)", path, err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var fc fileConfig
	if err := dec.Decode(&fc); err != nil {
		return fileConfig{}, fmt.Errorf("config file %q is not valid Steward config JSON: %w (fix the file, or drop -config to use flags and env only)", path, err)
	}
	if dec.More() {
		return fileConfig{}, fmt.Errorf("config file %q has trailing data after the JSON object; it must contain exactly one JSON object (fix the file, or drop -config to use flags and env only)", path)
	}
	return fc, nil
}
