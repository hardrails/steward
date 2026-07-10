// Command steward runs the on-node lifecycle supervisor HTTP server.
package main

import (
	"context"
	"errors"
	"flag"
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
	addr := flag.String("addr", envOr("STEWARD_ADDR", "127.0.0.1:8080"), "host:port to listen on")
	maxInstances := flag.Int("max-instances", envOrInt("STEWARD_MAX_INSTANCES", 1024),
		"maximum number of tracked instances before Provision returns 503")
	stateFile := flag.String("state-file", envOr("STEWARD_STATE_FILE", ""),
		"optional path to a JSON file for durable instance state; empty means in-memory only (state is lost on restart)")
	uplinkURL := flag.String("uplink-url", envOr("STEWARD_UPLINK_URL", ""),
		"control-plane base URL for the outbound uplink; empty disables it (inbound REST only)")
	uplinkCredentialFile := flag.String("uplink-credential-file", envOr("STEWARD_UPLINK_CREDENTIAL_FILE", ""),
		"path to the node's uplink credential JSON; required when -uplink-url is set")
	uplinkPollInterval := flag.Duration("uplink-poll-interval", envOrDuration("STEWARD_UPLINK_POLL_INTERVAL", 10*time.Second),
		"base cadence for uplink polling; jitter is applied on top")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

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
	}

	srv := &http.Server{
		Addr:              *addr,
		Handler:           server.NewWithTracker(logger, tracker).Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
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
		}()
		uplinkDone = done
	}

	go func() {
		logger.Info("steward listening", "addr", *addr, "version", server.Version)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server error", "err", err)
			stop()
		}
	}()

	<-ctx.Done()
	logger.Info("shutting down")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("shutdown error", "err", err)
		os.Exit(1)
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

func envOrDuration(key string, fallback time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return fallback
}
