// steward-executor is a separate, host-local Docker/gVisor execution service.
// It is control-plane and agent-vendor independent.
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
	"strings"
	"syscall"
	"time"

	"github.com/hardrails/steward/internal/buildinfo"
	"github.com/hardrails/steward/internal/executor"
	"github.com/hardrails/steward/internal/executoruplink"
	stewarduplink "github.com/hardrails/steward/internal/uplink"
)

func main() {
	version := flag.Bool("version", false, "print the Steward Executor version and exit")
	addr := flag.String("addr", "127.0.0.1:8090", "host:port to listen on")
	dockerSocket := flag.String("docker-socket", "/var/run/docker.sock", "Docker Engine Unix socket")
	tokenFile := flag.String("token-file", "", "path to executor bearer token (required)")
	disableInbound := flag.Bool("disable-inbound-listener", false, "run outbound-only without binding the host-local HTTP API")
	uplinkURL := flag.String("uplink-url", "", "optional control-plane base URL for outbound executor commands")
	uplinkCredentialFile := flag.String("uplink-credential-file", "", "path to versioned executor uplink credential")
	uplinkStateFile := flag.String("uplink-state-file", "", "path to durable executor command-fencing state")
	uplinkPollInterval := flag.Duration("uplink-poll-interval", 10*time.Second, "base interval between executor uplink polls")
	uplinkAllowInsecureHTTP := flag.Bool("uplink-allow-insecure-http", false, "explicitly allow plaintext HTTP to a non-loopback uplink")
	uplinkTLSCAFile := flag.String("uplink-tls-ca-file", "", "optional PEM CA bundle for the executor uplink")
	uplinkTLSClientCert := flag.String("uplink-tls-client-cert", "", "optional mTLS client certificate for the executor uplink")
	uplinkTLSClientKey := flag.String("uplink-tls-client-key", "", "optional mTLS client key for the executor uplink")
	uplinkTLSSkipVerify := flag.Bool("uplink-tls-skip-verify", false, "INSECURE: disable executor uplink server certificate verification")
	defaults := executor.DefaultHostPolicy()
	maxMemoryBytes := flag.Int64("max-memory-bytes", defaults.MaxMemoryBytes, "maximum memory bytes for one workload")
	maxCPUMillis := flag.Int64("max-cpu-millis", defaults.MaxCPUMillis, "maximum CPU millicores for one workload")
	maxPIDs := flag.Int64("max-pids", defaults.MaxPIDs, "maximum processes for one workload")
	maxWorkloads := flag.Int("max-workloads", defaults.MaxWorkloads, "maximum executor-managed workloads on this host")
	maxWorkloadsPerTenant := flag.Int("max-workloads-per-tenant", defaults.MaxWorkloadsPerTenant, "maximum executor-managed workloads for one tenant")
	flag.Parse()
	if *version {
		fmt.Println("steward-executor " + buildinfo.Resolve())
		return
	}
	if *tokenFile == "" {
		slog.Error("-token-file is required")
		os.Exit(2)
	}
	token, err := readToken(*tokenFile)
	if err != nil {
		slog.Error("read executor token", "err", err)
		os.Exit(2)
	}
	docker := executor.NewDockerHTTP(*dockerSocket)
	available, err := docker.RuntimeAvailable(context.Background(), "runsc")
	if err != nil {
		slog.Error("check Docker runsc runtime", "err", err)
		os.Exit(2)
	}
	if !available {
		slog.Error("Docker runtime runsc is required; install and configure gVisor before starting")
		os.Exit(2)
	}
	policy := executor.HostPolicy{
		MaxMemoryBytes:        *maxMemoryBytes,
		MaxCPUMillis:          *maxCPUMillis,
		MaxPIDs:               *maxPIDs,
		MaxWorkloads:          *maxWorkloads,
		MaxWorkloadsPerTenant: *maxWorkloadsPerTenant,
	}
	server, err := executor.NewServerWithPolicy(docker, token, policy, slog.Default())
	if err != nil {
		slog.Error("configure executor", "err", err)
		os.Exit(2)
	}
	handler := server.Handler()
	var poller *executoruplink.Poller
	if *uplinkURL != "" {
		if *uplinkCredentialFile == "" || *uplinkStateFile == "" {
			slog.Error("-uplink-credential-file and -uplink-state-file are required with -uplink-url")
			os.Exit(2)
		}
		state, err := executoruplink.LoadStateStore(*uplinkStateFile)
		if err != nil {
			slog.Error("load executor uplink state", "err", err)
			os.Exit(2)
		}
		httpClient, err := stewarduplink.NewHTTPClient(stewarduplink.TLSConfig{
			CAFile: *uplinkTLSCAFile, ClientCertFile: *uplinkTLSClientCert,
			ClientKeyFile: *uplinkTLSClientKey, SkipVerify: *uplinkTLSSkipVerify,
		})
		if err != nil {
			slog.Error("configure executor uplink TLS", "err", err)
			os.Exit(2)
		}
		if *uplinkTLSSkipVerify {
			slog.Warn("executor uplink TLS verification is disabled")
		}
		poller, err = executoruplink.NewPoller(executoruplink.Config{
			BaseURL: *uplinkURL, CredentialPath: *uplinkCredentialFile,
			PollInterval: *uplinkPollInterval, AllowInsecureHTTP: *uplinkAllowInsecureHTTP,
			HTTPClient: httpClient, Handler: handler, LocalToken: token, State: state,
			Logger: slog.Default(),
		})
		if err != nil {
			slog.Error("configure executor uplink", "err", err)
			os.Exit(2)
		}
	} else if *uplinkCredentialFile != "" || *uplinkStateFile != "" || *uplinkAllowInsecureHTTP ||
		*uplinkTLSCAFile != "" || *uplinkTLSClientCert != "" || *uplinkTLSClientKey != "" || *uplinkTLSSkipVerify {
		slog.Error("executor uplink options require -uplink-url")
		os.Exit(2)
	}
	if *disableInbound && poller == nil {
		slog.Error("-disable-inbound-listener requires -uplink-url; otherwise the executor has no control channel")
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if poller != nil {
		go poller.Run(ctx)
	}
	if *disableInbound {
		<-ctx.Done()
		return
	}
	httpServer := &http.Server{
		Addr: *addr, Handler: handler,
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() { errCh <- httpServer.ListenAndServe() }()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			slog.Error("shutdown executor", "err", err)
		}
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			slog.Error("serve executor", "err", err)
			os.Exit(1)
		}
	}
}

func readToken(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("executor token must be a regular file")
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return "", errors.New("executor token must have mode 0600 or stricter")
	}
	if info.Size() > 4096 {
		return "", errors.New("executor token must not exceed 4096 bytes")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	token := strings.TrimSpace(string(raw))
	if token == "" {
		return "", errors.New("executor token must not be empty")
	}
	return token, nil
}
