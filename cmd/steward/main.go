// Command steward runs the on-node lifecycle supervisor HTTP server.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/hardrails/steward/internal/runtime"
	"github.com/hardrails/steward/internal/server"
	"github.com/hardrails/steward/internal/uplink"
)

func main() {
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
	flag.Parse()

	// A node with neither the inbound listener nor the outbound uplink enabled would
	// be unreachable in both directions — a dark, useless process. Fail closed here,
	// before any other startup work, naming both the flag and the fix, the same
	// discipline the uplink credential and poll-interval checks below apply.
	if *disableInbound && *uplinkURL == "" {
		logger.Error("inbound listener disabled but no uplink configured",
			"hint", "a node with neither an inbound listener nor an outbound uplink is unreachable; set -uplink-url (or STEWARD_UPLINK_URL) to poll a control plane, or drop -disable-inbound-listener to serve the inbound REST API")
		os.Exit(1)
	}

	// LoadTracker restores any existing state before the server accepts requests.
	// An empty -state-file disables persistence (the in-memory default); a corrupt
	// or unreadable file fails closed here with a message naming the path and fix,
	// rather than starting with silently-empty state.
	tracker, err := runtime.LoadTracker(*maxInstances, *stateFile)
	if err != nil {
		logger.Error("load state", "err", err)
		os.Exit(1)
	}
	if *stateFile != "" {
		logger.Info("durable state enabled", "path", *stateFile, "restored_instances", tracker.Len())
	}

	// The uplink is enabled iff -uplink-url is set (mirroring how -state-file's
	// presence enables durable state). When enabled, load the node credential
	// fail-closed before serving — a missing or corrupt credential is a startup
	// error naming the path, never a silently-disabled uplink, the same discipline
	// LoadTracker applies to a corrupt state file — and build the poller. The poll
	// goroutine is started below, bound to the shutdown context.
	var poller *uplink.Poller
	if *uplinkURL != "" {
		if *uplinkCredentialFile == "" {
			logger.Error("uplink enabled but no credential file",
				"hint", "set -uplink-credential-file (or STEWARD_UPLINK_CREDENTIAL_FILE) when -uplink-url is set")
			os.Exit(1)
		}
		cred, err := uplink.LoadCredential(*uplinkCredentialFile)
		if err != nil {
			logger.Error("load uplink credential", "err", err)
			os.Exit(1)
		}
		poller, err = uplink.NewPoller(tracker, uplink.Config{
			BaseURL:      *uplinkURL,
			Credential:   cred.Credential,
			NodeID:       cred.NodeID,
			PollInterval: *uplinkPollInterval,
			Logger:       logger,
		})
		if err != nil {
			logger.Error("configure uplink", "err", err)
			os.Exit(1)
		}
		logger.Info("uplink enabled",
			"url", *uplinkURL, "node_id", cred.NodeID, "tenant_id", cred.TenantID,
			"poll_interval", uplinkPollInterval.String())
		// -uplink-poll-interval has no documented ceiling, but the steady-state poll
		// cadence is clamped to the same 5-minute cap used for failed-poll backoff
		// (see backoffDuration): a base at or above the cap polls at the cap, not at
		// the configured value. Warn once at startup naming both, so this is visible
		// rather than a silent surprise.
		if *uplinkPollInterval > uplink.MaxBackoff {
			logger.Warn("uplink poll interval exceeds the backoff cap; effective interval is clamped",
				"configured_interval", uplinkPollInterval.String(), "effective_interval", uplink.MaxBackoff.String())
		}
	}

	// When the inbound listener is disabled, srv stays nil: no http.Server is built
	// and no ListenAndServe goroutine is started. All fleet operations then flow
	// through the uplink poll loop only (see the fail-closed guard above, which
	// already refused this combination without -uplink-url).
	var srv *http.Server
	if !*disableInbound {
		srv = &http.Server{
			Addr:              *addr,
			Handler:           server.NewWithTracker(logger, tracker).Handler(),
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       15 * time.Second,
			WriteTimeout:      15 * time.Second,
			IdleTimeout:       60 * time.Second,
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Start the uplink poll loop bound to the same signal context, so a shutdown
	// cancels both its inter-poll wait and any in-flight request. Its done channel
	// is awaited in the graceful-shutdown block below.
	var uplinkDone <-chan struct{}
	if poller != nil {
		done := make(chan struct{})
		go func() {
			defer close(done)
			poller.Run(ctx)
			// Poller.Run returns two ways: ctx was cancelled (a shutdown already in
			// progress -- ctx.Err() is non-nil), or it gave up on its own (a fatal
			// credential rejection -- classFatal -- ctx.Err() is still nil). The
			// latter, with no inbound listener to fall back to, would otherwise leave
			// main blocked on <-ctx.Done() forever: no uplink loop running, no REST
			// API serving, a zombie process an operator's monitoring would see as
			// "up" while it does nothing. Mirrors the server goroutine's own
			// error->stop() pattern above -- a fatal exit on the ONLY control path
			// triggers the same graceful shutdown, rather than hanging silently.
			if srv == nil && ctx.Err() == nil {
				logger.Error("uplink poll loop exited and no inbound listener is configured; shutting down")
				stop()
			}
		}()
		uplinkDone = done
	}

	if srv != nil {
		go func() {
			logger.Info("steward listening", "addr", *addr, "version", server.Version)
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
