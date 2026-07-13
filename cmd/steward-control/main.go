package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/hardrails/steward/internal/buildinfo"
	"github.com/hardrails/steward/internal/controlauth"
	"github.com/hardrails/steward/internal/controlplane"
	"github.com/hardrails/steward/internal/controlstore"
	"github.com/hardrails/steward/internal/securefile"
)

const (
	defaultStateDirectory = "/var/lib/steward-control"
	defaultListenAddress  = "127.0.0.1:8443"
)

type options struct {
	address, stateDirectory, authKeyFile string
	tlsCertFile, tlsKeyFile              string
	initialize, checkConfig, version     bool
	leaseDuration, terminalRetention     time.Duration
	maxPoll                              int
	limits                               controlstore.Limits
}

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "steward-control:", err)
		os.Exit(1)
	}
}

func run(arguments []string, stdout, stderr io.Writer) error {
	parsed, err := parseOptions(arguments, stderr)
	if err != nil {
		return err
	}
	if parsed.version {
		_, err := fmt.Fprintln(stdout, "steward-control", buildinfo.Resolve())
		return err
	}
	logger := slog.New(slog.NewJSONHandler(stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if parsed.initialize {
		if parsed.checkConfig {
			return errors.New("-initialize and -check-config are mutually exclusive")
		}
		return initialize(parsed, stdout)
	}
	manager, err := controlauth.LoadKey(parsed.authKeyFile)
	if err != nil {
		return err
	}
	store, err := controlstore.Open(parsed.stateDirectory, parsed.limits)
	if err != nil {
		return err
	}
	defer store.Close()
	tlsConfig, err := transportConfig(parsed)
	if err != nil {
		return err
	}
	if _, err := store.Status(); err != nil {
		return err
	}
	if parsed.checkConfig {
		_, err := fmt.Fprintln(stdout, "steward-control configuration is valid")
		return err
	}
	handler, err := controlplane.New(controlplane.Config{
		Store: store, Auth: manager, LeaseDuration: parsed.leaseDuration,
		MaxPoll: parsed.maxPoll, Logger: logger,
	})
	if err != nil {
		return err
	}
	return serve(parsed.address, handler, tlsConfig, logger)
}

func parseOptions(arguments []string, stderr io.Writer) (options, error) {
	limits := controlstore.DefaultLimits()
	parsed := options{limits: limits}
	flags := flag.NewFlagSet("steward-control", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&parsed.address, "addr", defaultListenAddress, "control HTTP(S) listen address")
	flags.StringVar(&parsed.stateDirectory, "state-dir", defaultStateDirectory, "owner-only durable control state directory")
	flags.StringVar(&parsed.authKeyFile, "auth-key-file", "", "owner-only control authentication key (default: <state-dir>/auth.key)")
	flags.StringVar(&parsed.tlsCertFile, "tls-cert-file", "", "TLS server certificate PEM for a non-loopback listener")
	flags.StringVar(&parsed.tlsKeyFile, "tls-key-file", "", "owner-only TLS server private key PEM")
	flags.BoolVar(&parsed.initialize, "initialize", false, "initialize state and print a one-time site-admin token")
	flags.BoolVar(&parsed.checkConfig, "check-config", false, "validate configuration and durable state without serving")
	flags.BoolVar(&parsed.version, "version", false, "print version and exit")
	flags.DurationVar(&parsed.leaseDuration, "delivery-lease", 2*time.Minute, "Executor delivery lease")
	flags.IntVar(&parsed.maxPoll, "max-poll-deliveries", 32, "maximum deliveries considered per node poll")
	flags.IntVar(&parsed.limits.MaxTenants, "max-tenants", limits.MaxTenants, "maximum retained tenants")
	flags.IntVar(&parsed.limits.MaxNodes, "max-nodes", limits.MaxNodes, "maximum retained nodes")
	flags.IntVar(&parsed.limits.MaxCredentials, "max-credentials", limits.MaxCredentials, "maximum retained operator and node credentials")
	flags.IntVar(&parsed.limits.MaxEnrollments, "max-enrollments", limits.MaxEnrollments, "maximum retained enrollment capabilities")
	flags.IntVar(&parsed.limits.MaxCommands, "max-commands", limits.MaxCommands, "maximum retained commands")
	flags.IntVar(&parsed.limits.MaxCommandsPerTenant, "max-commands-per-tenant", limits.MaxCommandsPerTenant, "maximum retained commands per tenant")
	flags.IntVar(&parsed.limits.MaxCommandsPerNode, "max-commands-per-node", limits.MaxCommandsPerNode, "maximum retained commands per node")
	flags.DurationVar(&parsed.terminalRetention, "terminal-retention", limits.TerminalRetention, "minimum retention for completed command status")
	if err := flags.Parse(arguments); err != nil {
		return options{}, err
	}
	if flags.NArg() != 0 {
		return options{}, errors.New("unexpected positional arguments")
	}
	if parsed.version {
		return parsed, nil
	}
	if !filepath.IsAbs(parsed.stateDirectory) || filepath.Clean(parsed.stateDirectory) != parsed.stateDirectory ||
		parsed.stateDirectory == string(filepath.Separator) {
		return options{}, errors.New("-state-dir must be a clean absolute non-root path")
	}
	if parsed.authKeyFile == "" {
		parsed.authKeyFile = filepath.Join(parsed.stateDirectory, "auth.key")
	}
	if !filepath.IsAbs(parsed.authKeyFile) || filepath.Clean(parsed.authKeyFile) != parsed.authKeyFile {
		return options{}, errors.New("-auth-key-file must be a clean absolute path")
	}
	for _, path := range []string{parsed.tlsCertFile, parsed.tlsKeyFile} {
		if path != "" && (!filepath.IsAbs(path) || filepath.Clean(path) != path) {
			return options{}, errors.New("control TLS files must use clean absolute paths")
		}
	}
	parsed.limits.TerminalRetention = parsed.terminalRetention
	if err := parsed.limits.Validate(); err != nil {
		return options{}, err
	}
	if parsed.leaseDuration <= 0 || parsed.leaseDuration > 15*time.Minute || parsed.maxPoll <= 0 || parsed.maxPoll > 128 {
		return options{}, errors.New("delivery lease and poll batch are outside their safe limits")
	}
	if _, _, err := net.SplitHostPort(parsed.address); err != nil {
		return options{}, fmt.Errorf("-addr must contain a valid host and port: %w", err)
	}
	return parsed, nil
}

func initialize(parsed options, stdout io.Writer) error {
	store, err := controlstore.Initialize(parsed.stateDirectory, parsed.limits)
	if errors.Is(err, controlstore.ErrAlreadyInitialized) {
		store, err = controlstore.Open(parsed.stateDirectory, parsed.limits)
	}
	if err != nil {
		return err
	}
	defer store.Close()
	status, err := store.Status()
	if err != nil {
		return err
	}
	if status.Tenants != 0 || status.Nodes != 0 || status.Credentials != 0 || status.Enrollments != 0 || status.Commands != 0 {
		return errors.New("refusing to initialize a non-empty control store")
	}
	var manager *controlauth.Manager
	manager, err = controlauth.LoadKey(parsed.authKeyFile)
	if errors.Is(err, os.ErrNotExist) || os.IsNotExist(err) {
		manager, err = controlauth.InitializeKey(parsed.authKeyFile)
	}
	if err != nil {
		return err
	}
	raw, credential, err := store.BootstrapSiteAdmin(manager, time.Now().UTC())
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintln(stdout, raw); err != nil {
		if identity, authErr := store.AuthenticateOperator(manager, raw); authErr == nil {
			_, _ = store.RevokeCredential(identity, credential.ID, time.Now().UTC())
		}
		return fmt.Errorf("write site-admin token: %w", err)
	}
	return nil
}

func transportConfig(parsed options) (*tls.Config, error) {
	host, _, _ := net.SplitHostPort(parsed.address)
	requiresTLS := !literalLoopback(host)
	if (parsed.tlsCertFile == "") != (parsed.tlsKeyFile == "") {
		return nil, errors.New("-tls-cert-file and -tls-key-file must be set together")
	}
	if parsed.tlsCertFile == "" {
		if requiresTLS {
			return nil, errors.New("a non-loopback control listener requires a TLS certificate and owner-only key")
		}
		return nil, nil
	}
	certificatePEM, err := securefile.Read(parsed.tlsCertFile, 1<<20, securefile.TrustFile)
	if err != nil {
		return nil, fmt.Errorf("read control TLS certificate: %w", err)
	}
	keyPEM, err := securefile.Read(parsed.tlsKeyFile, 1<<20, securefile.OwnerOnly)
	if err != nil {
		return nil, fmt.Errorf("read control TLS key: %w", err)
	}
	certificate, err := tls.X509KeyPair(certificatePEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("load control TLS certificate and key: %w", err)
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate}}, nil
}

func literalLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func serve(address string, handler http.Handler, tlsConfig *tls.Config, logger *slog.Logger) error {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	server := &http.Server{
		Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32 << 10,
		TLSConfig: tlsConfig,
	}
	serveErrors := make(chan error, 1)
	go func() {
		logger.Info("Steward Control listening", "address", listener.Addr().String(), "tls", tlsConfig != nil)
		if tlsConfig != nil {
			serveErrors <- server.ServeTLS(listener, "", "")
			return
		}
		serveErrors <- server.Serve(listener)
	}()
	shutdownContext, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	select {
	case err := <-serveErrors:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-shutdownContext.Done():
	}
	context, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := server.Shutdown(context); err != nil {
		return err
	}
	err = <-serveErrors
	if !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
