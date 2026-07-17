package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
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
	"syscall"
	"time"

	"github.com/hardrails/steward/internal/buildinfo"
	"github.com/hardrails/steward/internal/controlauth"
	"github.com/hardrails/steward/internal/controlplane"
	"github.com/hardrails/steward/internal/controlstore"
	"github.com/hardrails/steward/internal/controlwitness"
	"github.com/hardrails/steward/internal/securefile"
)

const (
	defaultStateDirectory = "/var/lib/steward-control"
	defaultListenAddress  = "127.0.0.1:8443"
)

type options struct {
	address, stateDirectory, authKeyFile string
	adminTokenFile                       string
	witnessPrivateKeyFile                string
	witnessPublicKeyFile                 string
	tlsCertFile, tlsKeyFile              string
	initialize, initializeWitnessKey     bool
	enableMetrics                        bool
	checkConfig, version                 bool
	leaseDuration, terminalRetention     time.Duration
	maxPoll                              int
	limits                               controlstore.Limits
	operationsThresholds                 controlstore.OperationsThresholds
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
		return initialize(parsed, stdout)
	}
	if parsed.initializeWitnessKey {
		return initializeWitnessKey(parsed, stdout)
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
	witnessPrivateKey, _, err := controlwitness.LoadPair(parsed.witnessPrivateKeyFile, parsed.witnessPublicKeyFile)
	if err != nil {
		return err
	}
	if err := validateWitnessTLSKeySeparation(tlsConfig, witnessPrivateKey); err != nil {
		return err
	}
	if parsed.checkConfig {
		_, err := fmt.Fprintln(stdout, "steward-control configuration is valid")
		return err
	}
	handler, err := controlplane.New(controlplane.Config{
		Store: store, Auth: manager, WitnessPrivateKey: witnessPrivateKey, LeaseDuration: parsed.leaseDuration,
		MaxPoll: parsed.maxPoll, Logger: logger, EnableMetrics: parsed.enableMetrics,
		OperationsThresholds: parsed.operationsThresholds,
	})
	if err != nil {
		return err
	}
	return serve(parsed.address, handler, tlsConfig, logger)
}

func parseOptions(arguments []string, stderr io.Writer) (options, error) {
	limits := controlstore.DefaultLimits()
	thresholds := controlstore.DefaultOperationsThresholds()
	parsed := options{limits: limits, operationsThresholds: thresholds}
	flags := flag.NewFlagSet("steward-control", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&parsed.address, "addr", defaultListenAddress, "control HTTP(S) listen address")
	flags.StringVar(&parsed.stateDirectory, "state-dir", defaultStateDirectory, "owner-only durable control state directory")
	flags.StringVar(&parsed.authKeyFile, "auth-key-file", "", "owner-only control authentication key (default: <state-dir>/auth.key)")
	flags.StringVar(&parsed.adminTokenFile, "admin-token-file", "", "new owner-only bootstrap token file (default: <state-dir>/site-admin.token)")
	flags.StringVar(&parsed.witnessPrivateKeyFile, "witness-private-key-file", "", "owner-only Ed25519 evidence-witness private key (default: <state-dir>/witness.private.pem)")
	flags.StringVar(&parsed.witnessPublicKeyFile, "witness-public-key-file", "", "published Ed25519 evidence-witness public key (default: <state-dir>/witness.public.pem)")
	flags.StringVar(&parsed.tlsCertFile, "tls-cert-file", "", "TLS server certificate PEM for a non-loopback listener")
	flags.StringVar(&parsed.tlsKeyFile, "tls-key-file", "", "owner-only TLS server private key PEM")
	flags.BoolVar(&parsed.initialize, "initialize", false, "initialize state and print a one-time site-admin token")
	flags.BoolVar(&parsed.initializeWitnessKey, "initialize-witness-key", false, "create or validate the dedicated evidence-witness key pair and exit")
	flags.BoolVar(&parsed.enableMetrics, "enable-metrics", false, "expose authenticated Prometheus metrics")
	flags.BoolVar(&parsed.checkConfig, "check-config", false, "validate configuration and durable state without serving")
	flags.BoolVar(&parsed.version, "version", false, "print version and exit")
	flags.DurationVar(&parsed.leaseDuration, "delivery-lease", 2*time.Minute, "Executor delivery lease")
	flags.IntVar(&parsed.maxPoll, "max-poll-deliveries", 32, "maximum deliveries considered per node poll")
	flags.IntVar(&parsed.limits.MaxTenants, "max-tenants", limits.MaxTenants, "maximum retained tenants")
	flags.IntVar(&parsed.limits.MaxNodes, "max-nodes", limits.MaxNodes, "maximum retained nodes")
	flags.IntVar(&parsed.limits.MaxNodesPerTenant, "max-nodes-per-tenant", limits.MaxNodesPerTenant, "maximum retained nodes bound to one tenant")
	flags.IntVar(&parsed.limits.MaxCredentials, "max-credentials", limits.MaxCredentials, "maximum retained operator and node credentials")
	flags.IntVar(&parsed.limits.MaxCredentialsPerTenant, "max-credentials-per-tenant", limits.MaxCredentialsPerTenant, "maximum retained credentials bound to one tenant")
	flags.IntVar(&parsed.limits.MaxEnrollments, "max-enrollments", limits.MaxEnrollments, "maximum retained enrollment capabilities")
	flags.IntVar(&parsed.limits.MaxEnrollmentsPerTenant, "max-enrollments-per-tenant", limits.MaxEnrollmentsPerTenant, "maximum retained enrollments bound to one tenant")
	flags.IntVar(&parsed.limits.MaxCommands, "max-commands", limits.MaxCommands, "maximum retained commands")
	flags.IntVar(&parsed.limits.MaxCommandsPerTenant, "max-commands-per-tenant", limits.MaxCommandsPerTenant, "maximum retained commands per tenant")
	flags.IntVar(&parsed.limits.MaxCommandsPerNode, "max-commands-per-node", limits.MaxCommandsPerNode, "maximum retained commands per node")
	flags.DurationVar(&parsed.terminalRetention, "terminal-retention", limits.TerminalRetention, "minimum retention for completed command status")
	flags.DurationVar(
		&parsed.operationsThresholds.NodeStaleAfter,
		"node-stale-after",
		thresholds.NodeStaleAfter,
		"elapsed time before an active node requires attention",
	)
	flags.DurationVar(
		&parsed.operationsThresholds.EvidenceStaleAfter,
		"evidence-stale-after",
		thresholds.EvidenceStaleAfter,
		"elapsed time before an Executor evidence report requires attention",
	)
	flags.DurationVar(
		&parsed.operationsThresholds.CommandOverdueAfter,
		"command-overdue-after",
		thresholds.CommandOverdueAfter,
		"elapsed time before a pending command requires attention",
	)
	flags.IntVar(
		&parsed.operationsThresholds.CapacityWarningPercent,
		"capacity-warning-percent",
		thresholds.CapacityWarningPercent,
		"capacity percentage at which retained state requires attention",
	)
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
	if parsed.adminTokenFile == "" {
		parsed.adminTokenFile = filepath.Join(parsed.stateDirectory, "site-admin.token")
	}
	if parsed.witnessPrivateKeyFile == "" {
		parsed.witnessPrivateKeyFile = filepath.Join(parsed.stateDirectory, "witness.private.pem")
	}
	if parsed.witnessPublicKeyFile == "" {
		parsed.witnessPublicKeyFile = filepath.Join(parsed.stateDirectory, "witness.public.pem")
	}
	if !filepath.IsAbs(parsed.authKeyFile) || filepath.Clean(parsed.authKeyFile) != parsed.authKeyFile {
		return options{}, errors.New("-auth-key-file must be a clean absolute path")
	}
	if !filepath.IsAbs(parsed.adminTokenFile) || filepath.Clean(parsed.adminTokenFile) != parsed.adminTokenFile ||
		parsed.adminTokenFile == parsed.authKeyFile {
		return options{}, errors.New("-admin-token-file must be a distinct clean absolute path")
	}
	if !filepath.IsAbs(parsed.witnessPrivateKeyFile) ||
		filepath.Clean(parsed.witnessPrivateKeyFile) != parsed.witnessPrivateKeyFile {
		return options{}, errors.New("-witness-private-key-file must be a clean absolute path")
	}
	if !filepath.IsAbs(parsed.witnessPublicKeyFile) ||
		filepath.Clean(parsed.witnessPublicKeyFile) != parsed.witnessPublicKeyFile {
		return options{}, errors.New("-witness-public-key-file must be a clean absolute path")
	}
	distinctPaths := []string{
		parsed.authKeyFile,
		parsed.adminTokenFile,
		parsed.witnessPrivateKeyFile,
		parsed.witnessPublicKeyFile,
	}
	for index, path := range distinctPaths {
		for other := index + 1; other < len(distinctPaths); other++ {
			if path == distinctPaths[other] {
				return options{}, errors.New("control authentication, bootstrap, and witness files must use distinct paths")
			}
		}
	}
	for _, path := range []string{parsed.tlsCertFile, parsed.tlsKeyFile} {
		if path != "" && (!filepath.IsAbs(path) || filepath.Clean(path) != path) {
			return options{}, errors.New("control TLS files must use clean absolute paths")
		}
		for _, sensitivePath := range distinctPaths {
			if path != "" && path == sensitivePath {
				return options{}, errors.New("control TLS, authentication, bootstrap, and witness files must use distinct paths")
			}
		}
	}
	modeCount := 0
	for _, active := range []bool{parsed.initialize, parsed.initializeWitnessKey, parsed.checkConfig} {
		if active {
			modeCount++
		}
	}
	if modeCount > 1 {
		return options{}, errors.New("-initialize, -initialize-witness-key, and -check-config are mutually exclusive")
	}
	parsed.limits.TerminalRetention = parsed.terminalRetention
	if err := parsed.limits.Validate(); err != nil {
		return options{}, err
	}
	if err := parsed.operationsThresholds.Validate(); err != nil {
		return options{}, err
	}
	if parsed.leaseDuration <= 0 || parsed.leaseDuration > controlstore.MaxDeliveryLease || parsed.maxPoll <= 0 || parsed.maxPoll > 128 {
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
	if status.Tenants != 0 || status.Nodes != 0 || status.Credentials > 1 || status.Enrollments != 0 || status.Commands != 0 {
		return errors.New("refusing to initialize control state that is not empty or a lone bootstrap credential")
	}
	var manager *controlauth.Manager
	manager, err = controlauth.LoadKey(parsed.authKeyFile)
	if errors.Is(err, os.ErrNotExist) || os.IsNotExist(err) {
		manager, err = controlauth.InitializeKey(parsed.authKeyFile)
	}
	if err != nil {
		return err
	}
	if _, _, err := ensureWitnessKeyPair(parsed.witnessPrivateKeyFile, parsed.witnessPublicKeyFile); err != nil {
		return err
	}
	output, err := reserveSecretOutput(parsed.adminTokenFile)
	if err != nil {
		return err
	}
	defer output.abort()
	raw, _, _, err := store.BootstrapSiteAdmin(manager, time.Now().UTC())
	if err != nil {
		return err
	}
	if err := output.commit([]byte(raw + "\n")); err != nil {
		return fmt.Errorf("write site-admin token: %w", err)
	}
	_, err = fmt.Fprintln(stdout, parsed.adminTokenFile)
	return err
}

func initializeWitnessKey(parsed options, stdout io.Writer) error {
	if _, err := controlauth.LoadKey(parsed.authKeyFile); err != nil {
		return err
	}
	store, err := controlstore.Open(parsed.stateDirectory, parsed.limits)
	if err != nil {
		return err
	}
	defer store.Close()
	if _, err := store.Status(); err != nil {
		return err
	}
	if _, _, err := ensureWitnessKeyPair(parsed.witnessPrivateKeyFile, parsed.witnessPublicKeyFile); err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, parsed.witnessPublicKeyFile)
	return err
}

func ensureWitnessKeyPair(privatePath, publicPath string) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	privateInfo, privateErr := os.Lstat(privatePath)
	publicInfo, publicErr := os.Lstat(publicPath)
	privateMissing := errors.Is(privateErr, os.ErrNotExist)
	publicMissing := errors.Is(publicErr, os.ErrNotExist)
	if privateErr != nil && !privateMissing {
		return nil, nil, fmt.Errorf("inspect controller witness private key: %w", privateErr)
	}
	if publicErr != nil && !publicMissing {
		return nil, nil, fmt.Errorf("inspect controller witness public key: %w", publicErr)
	}
	if privateMissing != publicMissing {
		return nil, nil, errors.New("controller witness key pair is partial; refusing to create, rotate, or overwrite either file")
	}
	if privateMissing {
		private, public, err := controlwitness.Initialize(privatePath, publicPath)
		return private, public, err
	}
	if privateInfo == nil || publicInfo == nil {
		return nil, nil, errors.New("controller witness key pair could not be classified")
	}
	private, public, err := controlwitness.LoadPair(privatePath, publicPath)
	return private, public, err
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
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}}, nil
}

func validateWitnessTLSKeySeparation(tlsConfig *tls.Config, witnessPrivate ed25519.PrivateKey) error {
	if tlsConfig == nil {
		return nil
	}
	if len(witnessPrivate) != ed25519.PrivateKeySize || len(tlsConfig.Certificates) != 1 ||
		len(tlsConfig.Certificates[0].Certificate) == 0 {
		return errors.New("control TLS and evidence-witness key configuration is invalid")
	}
	certificate := tlsConfig.Certificates[0].Leaf
	if certificate == nil {
		var err error
		certificate, err = x509.ParseCertificate(tlsConfig.Certificates[0].Certificate[0])
		if err != nil {
			return fmt.Errorf("parse control TLS leaf certificate: %w", err)
		}
	}
	witnessPublic := witnessPrivate.Public().(ed25519.PublicKey)
	if witnessPublic.Equal(certificate.PublicKey) {
		return errors.New("control TLS and evidence-witness identities must use different keys")
	}
	return nil
}

func literalLoopback(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

type secretOutput struct {
	path      string
	file      *os.File
	committed bool
}

func reserveSecretOutput(path string) (*secretOutput, error) {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("reserve owner-only secret output: %w", err)
	}
	output := &secretOutput{path: path, file: file}
	if err := file.Sync(); err != nil {
		output.abort()
		return nil, fmt.Errorf("sync secret reservation: %w", err)
	}
	if err := syncParent(path); err != nil {
		output.abort()
		return nil, err
	}
	return output, nil
}

func (output *secretOutput) commit(contents []byte) error {
	if output == nil || output.file == nil || output.committed || len(contents) == 0 || len(contents) > 4096 {
		return errors.New("secret output reservation cannot be committed")
	}
	for written := 0; written < len(contents); {
		count, err := output.file.Write(contents[written:])
		if err != nil {
			return err
		}
		if count <= 0 {
			return io.ErrShortWrite
		}
		written += count
	}
	if err := output.file.Sync(); err != nil {
		return err
	}
	if err := output.file.Close(); err != nil {
		return err
	}
	output.file = nil
	if err := syncParent(output.path); err != nil {
		return err
	}
	output.committed = true
	return nil
}

func (output *secretOutput) abort() {
	if output == nil || output.committed {
		return
	}
	if output.file != nil {
		_ = output.file.Close()
		output.file = nil
	}
	_ = os.Remove(output.path)
	_ = syncParent(output.path)
}

func syncParent(path string) error {
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("open secret output directory: %w", err)
	}
	return errors.Join(directory.Sync(), directory.Close())
}

func serve(address string, handler http.Handler, tlsConfig *tls.Config, logger *slog.Logger) error {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	handler, err = controlplane.NewHostGate(listener.Addr().String(), tlsConfig, handler)
	if err != nil {
		_ = listener.Close()
		return err
	}
	server := &http.Server{
		Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32 << 10,
		TLSConfig: tlsConfig, ErrorLog: slog.NewLogLogger(logger.Handler(), slog.LevelError),
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
