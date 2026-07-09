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
)

func main() {
	addr := flag.String("addr", envOr("STEWARD_ADDR", "127.0.0.1:8080"), "host:port to listen on")
	maxInstances := flag.Int("max-instances", envOrInt("STEWARD_MAX_INSTANCES", 1024),
		"maximum number of tracked instances before Provision returns 503")
	stateFile := flag.String("state-file", envOr("STEWARD_STATE_FILE", ""),
		"optional path to a JSON file for durable instance state; empty means in-memory only (state is lost on restart)")
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

	go func() {
		logger.Info("steward listening", "addr", *addr)
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
