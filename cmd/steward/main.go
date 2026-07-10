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
	uplinkPollInterval := flag.Duration("uplink-poll-interval", pollIntervalDefault,
		"base cadence for uplink polling; jitter is applied on top; clamped to a 5-minute ceiling (the failed-poll backoff cap)")
	disableInbound := flag.Bool("disable-inbound-listener", disableInboundDefault,
		"do not bind an inbound HTTP listener; requires -uplink-url. All fleet operations then flow through the outbound uplink poll loop only.")
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
	if fc.DisableInboundListener != nil && fileMayFill("disable-inbound-listener", "STEWARD_DISABLE_INBOUND_LISTENER") {
		*disableInbound = *fc.DisableInboundListener
	}
	if fc.LogLevel != nil && fileMayFill("log-level", "STEWARD_LOG_LEVEL") {
		*logLevel = *fc.LogLevel
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
		addr:                 *addr,
		maxInstances:         *maxInstances,
		stateFile:            *stateFile,
		uplinkURL:            *uplinkURL,
		uplinkCredentialFile: *uplinkCredentialFile,
		uplinkPollInterval:   *uplinkPollInterval,
		disableInbound:       *disableInbound,
		logLevel:             *logLevel,
	}

	// -check-config is a dry run: it exercises the exact same validation-and-build
	// sequence a real startup runs (prepareRuntime), then exits 0 (valid) or
	// non-zero with the same actionable error — without binding a port, serving, or
	// starting the uplink poll loop. It is the "will this configuration work?"
	// question an operator asks before rolling a config out, the -config file
	// included.
	if *checkConfig {
		if _, _, _, err := prepareRuntime(cfg, logger, true); err != nil {
			os.Exit(1)
		}
		fmt.Println("configuration valid")
		os.Exit(0)
	}

	logger, tracker, poller, err := prepareRuntime(cfg, logger, false)
	if err != nil {
		os.Exit(1)
	}

	// Register the signal handler as the FIRST thing after a successful
	// prepareRuntime, before any further startup logging or server construction:
	// any work between prepareRuntime succeeding and this call is a window where
	// SIGTERM/SIGINT would hit the OS default disposition (immediate termination)
	// instead of triggering a graceful shutdown -- the earlier this runs, the
	// smaller that window.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

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
		srv = &http.Server{
			Addr:              cfg.addr,
			Handler:           server.NewWithTracker(logger, tracker, *rateLimitPerSecond).Handler(),
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
				stop()
			}
		}()
		uplinkDone = done
	}

	if srv != nil {
		go func() {
			logger.Info("steward listening", "addr", cfg.addr, "version", server.Version)
			if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.Error("server error", "err", err)
				stop()
			}
		}()
	} else {
		logger.Info("inbound listener disabled; serving via uplink only", "version", server.Version)
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
}

// resolvedConfig is the fully-layered startup configuration: every setting after
// precedence (flag > env > -config file > built-in default) has been applied. It is
// the single input both the real startup path and the -check-config dry run
// validate and build from, so the two can never diverge on what a valid config is.
type resolvedConfig struct {
	addr                 string
	maxInstances         int
	stateFile            string
	uplinkURL            string
	uplinkCredentialFile string
	uplinkPollInterval   time.Duration
	disableInbound       bool
	logLevel             string
}

// prepareRuntime runs every fail-closed startup check against cfg and builds the
// live objects the server runs from — the restored tracker and, when the uplink is
// enabled, the poller. It is the ONE validation-and-construction sequence shared by
// the real startup path and the -check-config dry run, so a dry run can never accept
// a config a real boot would reject (or the reverse). It rebuilds the logger at the
// configured level (returned for the caller to keep using) and, on any invalid
// setting, logs the same actionable error a real boot would and returns it. It binds
// no port and starts no goroutine: the caller wires the HTTP server and starts the
// poll loop from the returned objects.
//
// When checkOnly is true the success/progress logs ("durable state enabled",
// "uplink enabled") are suppressed: a dry run validates a configuration, it does not
// enable anything, so reporting those would be misleading. The fail-closed error
// logs and the poll-interval-clamp warning — which report on the config itself — are
// emitted either way.
func prepareRuntime(cfg resolvedConfig, logger *slog.Logger, checkOnly bool) (*slog.Logger, *runtime.Tracker, *uplink.Poller, error) {
	// Rebuild the logger at the configured level now that the config is resolved. A
	// garbage -log-level (or STEWARD_LOG_LEVEL, or log_level in the config file) is a
	// fail-closed startup error naming the bad value and the accepted set, logged via
	// the bootstrap logger since the configured one is not yet valid.
	level, err := parseLogLevel(cfg.logLevel)
	if err != nil {
		logger.Error("configure log level", "err", err)
		return logger, nil, nil, err
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
		return logger, nil, nil, fmt.Errorf("invalid -max-instances %d", cfg.maxInstances)
	}

	// A node with neither the inbound listener nor the outbound uplink enabled would
	// be unreachable in both directions — a dark, useless process. Fail closed here,
	// before any other startup work, naming both the flag and the fix, the same
	// discipline the uplink credential and poll-interval checks below apply.
	if cfg.disableInbound && cfg.uplinkURL == "" {
		logger.Error("inbound listener disabled but no uplink configured",
			"hint", "a node with neither an inbound listener nor an outbound uplink is unreachable; set -uplink-url (or STEWARD_UPLINK_URL) to poll a control plane, or drop -disable-inbound-listener to serve the inbound REST API")
		return logger, nil, nil, errors.New("inbound listener disabled but no uplink configured")
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
			return logger, nil, nil, fmt.Errorf("invalid -addr %q: %w", cfg.addr, err)
		}
		if n, convErr := strconv.Atoi(port); convErr == nil && (n < 0 || n > 65535) {
			logger.Error("invalid -addr port", "value", cfg.addr, "port", n,
				"hint", "-addr's port must be 0-65535")
			return logger, nil, nil, fmt.Errorf("invalid -addr %q: port %d out of range", cfg.addr, n)
		}
	}

	// LoadTracker restores any existing state (validating the file) before the server
	// accepts requests. An empty -state-file disables persistence (the in-memory
	// default); a corrupt or unreadable file fails closed here with a message naming
	// the path and fix, rather than starting with silently-empty state. In a dry run
	// this validates the file is loadable without keeping the tracker for real use.
	tracker, err := runtime.LoadTracker(cfg.maxInstances, cfg.stateFile)
	if err != nil {
		logger.Error("load state", "err", err)
		return logger, nil, nil, err
	}
	if cfg.stateFile != "" && !checkOnly {
		logger.Info("durable state enabled", "path", cfg.stateFile, "restored_instances", tracker.Len())
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
			return logger, nil, nil, errors.New("uplink enabled but no credential file")
		}
		cred, err := uplink.LoadCredential(cfg.uplinkCredentialFile)
		if err != nil {
			logger.Error("load uplink credential", "err", err)
			return logger, nil, nil, err
		}
		poller, err = uplink.NewPoller(tracker, uplink.Config{
			BaseURL:        cfg.uplinkURL,
			Credential:     cred.Credential,
			NodeID:         cred.NodeID,
			PollInterval:   cfg.uplinkPollInterval,
			Logger:         logger,
			CredentialPath: cfg.uplinkCredentialFile,
		})
		if err != nil {
			logger.Error("configure uplink", "err", err)
			return logger, nil, nil, err
		}
		if !checkOnly {
			logger.Info("uplink enabled",
				"url", cfg.uplinkURL, "node_id", cred.NodeID, "tenant_id", cred.TenantID,
				"poll_interval", cfg.uplinkPollInterval.String())
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

	return logger, tracker, poller, nil
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

// fileConfig is the -config JSON file's shape: the same settings the flags and env
// vars carry, supplied as the lowest-precedence layer (flag > env > file). Every
// field is a pointer so an absent key is distinguishable from a present zero value —
// an absent key leaves the env/flag/default value untouched, while a present key
// (even one set to "" or false) overrides the built-in default. Keys are snake_case,
// matching this repo's other JSON files (state, credential) and the STEWARD_* env
// var suffixes. uplink_poll_interval is a Go duration string (e.g. "30s"), parsed
// the same way the flag and env var parse theirs.
type fileConfig struct {
	Addr                   *string `json:"addr"`
	MaxInstances           *int    `json:"max_instances"`
	StateFile              *string `json:"state_file"`
	UplinkURL              *string `json:"uplink_url"`
	UplinkCredentialFile   *string `json:"uplink_credential_file"`
	UplinkPollInterval     *string `json:"uplink_poll_interval"`
	DisableInboundListener *bool   `json:"disable_inbound_listener"`
	LogLevel               *string `json:"log_level"`
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
