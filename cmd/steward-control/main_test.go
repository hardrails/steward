package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/controlauth"
	"github.com/hardrails/steward/internal/controlstore"
	"github.com/hardrails/steward/internal/controlwitness"
)

func TestRunInitializesRecoverableControllerWithOwnerOnlyTokenHandoff(t *testing.T) {
	stateDirectory := filepath.Join(t.TempDir(), "control")
	arguments := []string{"-initialize", "-state-dir", stateDirectory, "-addr", "127.0.0.1:0"}
	var output bytes.Buffer
	if err := run(arguments, &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	tokenPath := filepath.Join(stateDirectory, "site-admin.token")
	if strings.TrimSpace(output.String()) != tokenPath {
		t.Fatalf("initialize output=%q want token path %q", output.String(), tokenPath)
	}
	raw, err := os.ReadFile(tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	token := strings.TrimSpace(string(raw))
	if !strings.HasPrefix(token, "steward_cp_v1_") || strings.ContainsAny(token, " \t\r\n") {
		t.Fatalf("bootstrap token has unexpected shape: %q", token)
	}
	tokenInfo, err := os.Stat(tokenPath)
	if err != nil || tokenInfo.Mode().Perm() != 0o600 {
		t.Fatalf("admin token info=%v error=%v", tokenInfo, err)
	}
	keyInfo, err := os.Stat(filepath.Join(stateDirectory, "auth.key"))
	if err != nil || keyInfo.Mode().Perm() != 0o600 {
		t.Fatalf("auth key info=%v error=%v", keyInfo, err)
	}
	witnessPrivatePath := filepath.Join(stateDirectory, "witness.private.pem")
	witnessPublicPath := filepath.Join(stateDirectory, "witness.public.pem")
	witnessPrivate, witnessPublic, err := controlwitness.LoadPair(witnessPrivatePath, witnessPublicPath)
	if err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(witnessPrivatePath); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("witness private key info=%v error=%v", info, err)
	}
	if info, err := os.Stat(witnessPublicPath); err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("witness public key info=%v error=%v", info, err)
	}
	store, err := controlstore.Open(stateDirectory, controlstore.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	status, err := store.Status()
	store.Close()
	if err != nil || status.Credentials != 1 {
		t.Fatalf("status=%+v error=%v", status, err)
	}
	// If local publication was lost after the durable bootstrap, a new
	// exclusive output path reproduces the same token instead of stranding the
	// store with no usable administrator.
	if err := os.Remove(tokenPath); err != nil {
		t.Fatal(err)
	}
	recoveredPath := filepath.Join(filepath.Dir(stateDirectory), "recovered-admin.token")
	recoveryArguments := append(append([]string(nil), arguments...), "-admin-token-file", recoveredPath)
	output.Reset()
	if err := run(recoveryArguments, &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	recovered, err := os.ReadFile(recoveredPath)
	if err != nil || string(recovered) != string(raw) {
		t.Fatalf("recovered token changed: %q error=%v", recovered, err)
	}
	if err := run(recoveryArguments, &bytes.Buffer{}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "reserve") {
		t.Fatalf("existing token output was overwritten: %v", err)
	}
	reloadedPrivate, reloadedPublic, err := controlwitness.LoadPair(witnessPrivatePath, witnessPublicPath)
	if err != nil || !bytes.Equal(reloadedPrivate, witnessPrivate) || !bytes.Equal(reloadedPublic, witnessPublic) {
		t.Fatalf("bootstrap recovery changed witness identity: %v", err)
	}
	var checked bytes.Buffer
	if err := run([]string{"-check-config", "-state-dir", stateDirectory, "-addr", "127.0.0.1:0"}, &checked, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(checked.String()) != "steward-control configuration is valid" {
		t.Fatalf("check output=%q", checked.String())
	}
}

func TestTransportConfigRequiresTLSOutsideLiteralLoopback(t *testing.T) {
	base := options{address: "127.0.0.1:8443"}
	if config, err := transportConfig(base); err != nil || config != nil {
		t.Fatalf("loopback transport=%#v error=%v", config, err)
	}
	for _, address := range []string{"0.0.0.0:8443", ":8443", "localhost:8443", "control.internal:8443"} {
		base.address = address
		if config, err := transportConfig(base); err == nil || config != nil {
			t.Fatalf("remote address %q accepted without TLS", address)
		}
	}
	base.address = "127.0.0.1:8443"
	base.tlsCertFile = "/tmp/cert.pem"
	if _, err := transportConfig(base); err == nil {
		t.Fatal("partial TLS configuration accepted")
	}
}

func TestParseOptionsRejectsUnsafePathsAndCapacity(t *testing.T) {
	for _, arguments := range [][]string{
		{"-unknown"},
		{"positional"},
		{"-state-dir", "relative"},
		{"-state-dir", "/"},
		{"-state-dir", "/tmp/control", "-auth-key-file", "relative"},
		{"-state-dir", "/tmp/control", "-admin-token-file", "relative"},
		{"-state-dir", "/tmp/control", "-auth-key-file", "/tmp/same", "-admin-token-file", "/tmp/same"},
		{"-state-dir", "/tmp/control", "-witness-private-key-file", "relative"},
		{"-state-dir", "/tmp/control", "-witness-public-key-file", "relative"},
		{"-state-dir", "/tmp/control", "-auth-key-file", "/tmp/same", "-witness-private-key-file", "/tmp/same"},
		{"-state-dir", "/tmp/control", "-witness-private-key-file", "/tmp/same", "-witness-public-key-file", "/tmp/same"},
		{"-state-dir", "/tmp/control", "-tls-cert-file", "relative", "-tls-key-file", "/tmp/key"},
		{"-state-dir", "/tmp/control", "-tls-cert-file", "/tmp/control/witness.public.pem", "-tls-key-file", "/tmp/key"},
		{"-state-dir", "/tmp/control", "-initialize", "-initialize-witness-key"},
		{"-state-dir", "/tmp/control", "-initialize-witness-key", "-check-config"},
		{"-state-dir", "/tmp/control", "-delivery-lease", "0s"},
		{"-state-dir", "/tmp/control", "-delivery-lease", (controlstore.MaxDeliveryLease + time.Second).String()},
		{"-state-dir", "/tmp/control", "-max-poll-deliveries", "0"},
		{"-state-dir", "/tmp/control", "-max-poll-deliveries", "129"},
		{"-state-dir", "/tmp/control", "-max-tenants", "0"},
		{"-state-dir", "/tmp/control", "-node-stale-after", "0s"},
		{"-state-dir", "/tmp/control", "-evidence-stale-after", (controlstore.MaxOperationsThreshold + time.Second).String()},
		{"-state-dir", "/tmp/control", "-command-overdue-after", "-1s"},
		{"-state-dir", "/tmp/control", "-capacity-warning-percent", "0"},
		{"-state-dir", "/tmp/control", "-capacity-warning-percent", "101"},
		{"-state-dir", "/tmp/control", "-addr", "missing-port"},
	} {
		if _, err := parseOptions(arguments, &bytes.Buffer{}); err == nil {
			t.Fatalf("unsafe options accepted: %v", arguments)
		}
	}
	if _, err := parseOptions([]string{"-state-dir", "/tmp/control", "-max-nodes", "100", "-max-nodes-per-tenant", "50"}, &bytes.Buffer{}); err != nil {
		t.Fatalf("paired low node limits rejected: %v", err)
	}
	parsed, err := parseOptions([]string{
		"-state-dir", "/tmp/control",
		"-enable-metrics",
		"-node-stale-after", "3m",
		"-evidence-stale-after", "7m",
		"-command-overdue-after", "11m",
		"-capacity-warning-percent", "75",
	}, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("valid operations options rejected: %v", err)
	}
	if !parsed.enableMetrics ||
		parsed.operationsThresholds != (controlstore.OperationsThresholds{
			NodeStaleAfter: 3 * time.Minute, EvidenceStaleAfter: 7 * time.Minute,
			CommandOverdueAfter: 11 * time.Minute, CapacityWarningPercent: 75,
		}) {
		t.Fatalf("operations options = %+v metrics=%v", parsed.operationsThresholds, parsed.enableMetrics)
	}
}

func TestRunRejectsAmbiguousModeAndMissingDurableInputs(t *testing.T) {
	stateDirectory := filepath.Join(t.TempDir(), "control")
	if err := run([]string{"-initialize", "-check-config", "-state-dir", stateDirectory}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("initialize and check-config were accepted together")
	}
	if err := run([]string{"-state-dir", stateDirectory}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("missing authentication key was accepted")
	}
}

func TestInitializeWitnessKeyMigratesLegacyStateIdempotently(t *testing.T) {
	stateDirectory := initializeLegacyControllerForWitnessTest(t)
	arguments := []string{"-initialize-witness-key", "-state-dir", stateDirectory, "-addr", "127.0.0.1:0"}
	var output bytes.Buffer
	if err := run(arguments, &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	privatePath := filepath.Join(stateDirectory, "witness.private.pem")
	publicPath := filepath.Join(stateDirectory, "witness.public.pem")
	if strings.TrimSpace(output.String()) != publicPath {
		t.Fatalf("witness initialization output=%q want public path %q", output.String(), publicPath)
	}
	privateBefore, publicBefore, err := controlwitness.LoadPair(privatePath, publicPath)
	if err != nil {
		t.Fatal(err)
	}
	output.Reset()
	if err := run(arguments, &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	privateAfter, publicAfter, err := controlwitness.LoadPair(privatePath, publicPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(privateAfter, privateBefore) || !bytes.Equal(publicAfter, publicBefore) {
		t.Fatal("idempotent witness migration rotated the controller identity")
	}
	if err := run([]string{"-check-config", "-state-dir", stateDirectory, "-addr", "127.0.0.1:0"}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatalf("migrated controller configuration is invalid: %v", err)
	}
}

func TestWitnessLifecycleRejectsPartialMismatchUnsafePermissionsAndSymlink(t *testing.T) {
	t.Run("partial", func(t *testing.T) {
		stateDirectory := initializeLegacyControllerForWitnessTest(t)
		privatePath := filepath.Join(stateDirectory, "witness.private.pem")
		if err := os.WriteFile(privatePath, []byte("caller-owned-partial"), 0o600); err != nil {
			t.Fatal(err)
		}
		err := run([]string{"-initialize-witness-key", "-state-dir", stateDirectory}, &bytes.Buffer{}, &bytes.Buffer{})
		if err == nil || !strings.Contains(err.Error(), "partial") {
			t.Fatalf("partial witness pair error = %v", err)
		}
		raw, readErr := os.ReadFile(privatePath)
		if readErr != nil || string(raw) != "caller-owned-partial" {
			t.Fatalf("partial private key was changed: %q, %v", raw, readErr)
		}
		if _, statErr := os.Lstat(filepath.Join(stateDirectory, "witness.public.pem")); !os.IsNotExist(statErr) {
			t.Fatalf("partial migration created a public key: %v", statErr)
		}
	})

	t.Run("mismatch", func(t *testing.T) {
		stateDirectory := initializeLegacyControllerForWitnessTest(t)
		initializeWitnessForTest(t, stateDirectory)
		otherDirectory := filepath.Join(t.TempDir(), "other")
		if err := os.Mkdir(otherDirectory, 0o700); err != nil {
			t.Fatal(err)
		}
		otherPrivate := filepath.Join(otherDirectory, "witness.private.pem")
		otherPublic := filepath.Join(otherDirectory, "witness.public.pem")
		if _, _, err := controlwitness.Initialize(otherPrivate, otherPublic); err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(otherPublic)
		if err != nil {
			t.Fatal(err)
		}
		publicPath := filepath.Join(stateDirectory, "witness.public.pem")
		if err := os.WriteFile(publicPath, raw, 0o644); err != nil {
			t.Fatal(err)
		}
		err = run([]string{"-initialize-witness-key", "-state-dir", stateDirectory}, &bytes.Buffer{}, &bytes.Buffer{})
		if err == nil || !strings.Contains(err.Error(), "does not match") {
			t.Fatalf("mismatched witness pair error = %v", err)
		}
	})

	t.Run("unsafe-private-permissions", func(t *testing.T) {
		stateDirectory := initializeLegacyControllerForWitnessTest(t)
		initializeWitnessForTest(t, stateDirectory)
		if err := os.Chmod(filepath.Join(stateDirectory, "witness.private.pem"), 0o640); err != nil {
			t.Fatal(err)
		}
		if err := run([]string{"-check-config", "-state-dir", stateDirectory}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
			t.Fatal("group-readable witness private key was accepted")
		}
	})

	t.Run("public-symlink", func(t *testing.T) {
		stateDirectory := initializeLegacyControllerForWitnessTest(t)
		initializeWitnessForTest(t, stateDirectory)
		publicPath := filepath.Join(stateDirectory, "witness.public.pem")
		raw, err := os.ReadFile(publicPath)
		if err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(t.TempDir(), "public.pem")
		if err := os.WriteFile(target, raw, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(publicPath); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, publicPath); err != nil {
			t.Fatal(err)
		}
		if err := run([]string{"-check-config", "-state-dir", stateDirectory}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
			t.Fatal("witness public-key symlink was accepted")
		}
	})
}

func TestRunReportsVersionWithoutState(t *testing.T) {
	var output bytes.Buffer
	if err := run([]string{"-version"}, &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(output.String(), "steward-control ") {
		t.Fatalf("version output=%q", output.String())
	}
}

func TestTransportConfigLoadsOnlyMatchedOwnerOnlyTLSMaterial(t *testing.T) {
	certFile, keyFile := writeControlCertificate(t)
	parsed := options{address: "0.0.0.0:8443", tlsCertFile: certFile, tlsKeyFile: keyFile}
	config, err := transportConfig(parsed)
	if err != nil || config == nil || config.MinVersion != tls.VersionTLS13 || len(config.Certificates) != 1 {
		t.Fatalf("valid TLS transport = (%#v, %v)", config, err)
	}

	missing := filepath.Join(t.TempDir(), "missing.pem")
	parsed.tlsCertFile = missing
	if _, err := transportConfig(parsed); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("missing certificate error = %v", err)
	}
	parsed.tlsCertFile, parsed.tlsKeyFile = certFile, missing
	if _, err := transportConfig(parsed); err == nil || !strings.Contains(err.Error(), "key") {
		t.Fatalf("missing key error = %v", err)
	}

	invalidCert := filepath.Join(t.TempDir(), "cert.pem")
	invalidKey := filepath.Join(filepath.Dir(invalidCert), "key.pem")
	if err := os.WriteFile(invalidCert, []byte("invalid certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(invalidKey, []byte("invalid key"), 0o600); err != nil {
		t.Fatal(err)
	}
	parsed.tlsCertFile, parsed.tlsKeyFile = invalidCert, invalidKey
	if _, err := transportConfig(parsed); err == nil || !strings.Contains(err.Error(), "load control TLS") {
		t.Fatalf("mismatched TLS material error = %v", err)
	}
}

func TestCheckConfigRejectsTLSWithoutAnExactHostSAN(t *testing.T) {
	stateDirectory := filepath.Join(t.TempDir(), "control")
	if err := run([]string{
		"-initialize", "-state-dir", stateDirectory, "-addr", "127.0.0.1:0",
	}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	for name, dnsNames := range map[string][]string{
		"missing":  nil,
		"wildcard": {"*.customer.example"},
	} {
		t.Run(name, func(t *testing.T) {
			certFile, keyFile := writeControlCertificateWithDNSNames(t, dnsNames)
			err := run([]string{
				"-check-config", "-addr", "0.0.0.0:8443", "-state-dir", stateDirectory,
				"-tls-cert-file", certFile, "-tls-key-file", keyFile,
			}, &bytes.Buffer{}, &bytes.Buffer{})
			if err == nil || !strings.Contains(err.Error(), "Host policy") {
				t.Fatalf("unsafe TLS Host policy error = %v", err)
			}
		})
	}
}

func TestCheckConfigRejectsTLSKeyReusedAsWitnessIdentity(t *testing.T) {
	for _, mode := range []string{"copied", "hard-linked"} {
		t.Run(mode, func(t *testing.T) {
			stateDirectory := filepath.Join(t.TempDir(), "control")
			if err := run([]string{
				"-initialize", "-state-dir", stateDirectory, "-addr", "127.0.0.1:0",
			}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
				t.Fatal(err)
			}
			witnessPrivatePath := filepath.Join(stateDirectory, "witness.private.pem")
			witnessPrivate, _, err := controlwitness.LoadPair(
				witnessPrivatePath, filepath.Join(stateDirectory, "witness.public.pem"),
			)
			if err != nil {
				t.Fatal(err)
			}
			tlsDirectory := t.TempDir()
			certFile, keyFile := writeControlCertificateWithKey(t, tlsDirectory, witnessPrivate)
			if mode == "hard-linked" {
				if err := os.Remove(keyFile); err != nil {
					t.Fatal(err)
				}
				if err := os.Link(witnessPrivatePath, keyFile); err != nil {
					t.Fatal(err)
				}
			}
			err = run([]string{
				"-check-config", "-addr", "0.0.0.0:8443", "-state-dir", stateDirectory,
				"-tls-cert-file", certFile, "-tls-key-file", keyFile,
			}, &bytes.Buffer{}, &bytes.Buffer{})
			if err == nil || !strings.Contains(err.Error(), "must use different keys") {
				t.Fatalf("reused %s TLS/witness identity error=%v", mode, err)
			}
		})
	}
}

func TestSecretOutputReservationCommitsOrRemovesExactlyOnce(t *testing.T) {
	var absent *secretOutput
	if err := absent.commit([]byte("secret")); err == nil {
		t.Fatal("nil secret reservation committed")
	}
	absent.abort()

	directory := t.TempDir()
	abortedPath := filepath.Join(directory, "aborted.token")
	aborted, err := reserveSecretOutput(abortedPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := aborted.commit(nil); err == nil {
		t.Fatal("empty secret committed")
	}
	if err := aborted.commit(bytes.Repeat([]byte("x"), 4097)); err == nil {
		t.Fatal("oversized secret committed")
	}
	aborted.abort()
	if _, err := os.Stat(abortedPath); !os.IsNotExist(err) {
		t.Fatalf("aborted secret still exists: %v", err)
	}

	committedPath := filepath.Join(directory, "committed.token")
	committed, err := reserveSecretOutput(committedPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := committed.commit([]byte("secret\n")); err != nil {
		t.Fatal(err)
	}
	if err := committed.commit([]byte("replacement\n")); err == nil {
		t.Fatal("committed secret was replaced")
	}
	committed.abort()
	if raw, err := os.ReadFile(committedPath); err != nil || string(raw) != "secret\n" {
		t.Fatalf("committed secret = %q, %v", raw, err)
	}
	if err := syncParent(filepath.Join(directory, "missing", "token")); err == nil {
		t.Fatal("sync of a missing parent succeeded")
	}
}

func TestInitializeRefusesToAdoptNonemptyControlState(t *testing.T) {
	stateDirectory := filepath.Join(t.TempDir(), "control")
	arguments := []string{"-initialize", "-state-dir", stateDirectory, "-addr", "127.0.0.1:0"}
	if err := run(arguments, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	tokenRaw, err := os.ReadFile(filepath.Join(stateDirectory, "site-admin.token"))
	if err != nil {
		t.Fatal(err)
	}
	manager, err := controlauth.LoadKey(filepath.Join(stateDirectory, "auth.key"))
	if err != nil {
		t.Fatal(err)
	}
	store, err := controlstore.Open(stateDirectory, controlstore.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	admin, err := store.AuthenticateOperator(manager, strings.TrimSpace(string(tokenRaw)))
	if err != nil {
		t.Fatal(err)
	}
	if _, created, err := store.CreateTenant(admin, "tenant-a", time.Now().UTC()); err != nil || !created {
		t.Fatalf("create retained tenant = (%v, %v)", created, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(stateDirectory, "site-admin.token")); err != nil {
		t.Fatal(err)
	}
	arguments = append(arguments, "-admin-token-file", filepath.Join(stateDirectory, "replacement.token"))
	if err := run(arguments, &bytes.Buffer{}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "not empty") {
		t.Fatalf("nonempty state adoption error = %v", err)
	}
}

// TestControlAcceptanceWithInstrumentedBinary closes the coverage measurement
// gap for the real controller process. Normal unit and pre-commit runs skip it;
// scripts/coverage.sh supplies a private counter directory and unions the
// resulting main/control-plane/store counters with the unit profile.
func TestControlAcceptanceWithInstrumentedBinary(t *testing.T) {
	coverDirectory := os.Getenv("STEWARD_CONTROL_TEST_COVERDIR")
	if coverDirectory == "" {
		t.Skip("controller integration coverage is enabled by scripts/coverage.sh")
	}
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	binDirectory := t.TempDir()
	controlBinary := filepath.Join(binDirectory, "steward-control")
	ctlBinary := filepath.Join(binDirectory, "stewardctl")
	for _, build := range []struct {
		output string
		args   []string
	}{
		{output: controlBinary, args: []string{"build", "-cover", "-coverpkg=./...", "-o", controlBinary, "./cmd/steward-control"}},
		{output: ctlBinary, args: []string{"build", "-o", ctlBinary, "./cmd/stewardctl"}},
	} {
		command := exec.Command("go", build.args...)
		command.Dir = root
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("build %s: %v\n%s", filepath.Base(build.output), err, output)
		}
	}
	for _, invocation := range []struct {
		arguments  []string
		shouldFail bool
	}{
		{arguments: []string{"-version"}},
		{arguments: []string{"-unknown"}, shouldFail: true},
	} {
		command := exec.Command(controlBinary, invocation.arguments...)
		command.Env = append(os.Environ(), "GOCOVERDIR="+coverDirectory)
		output, err := command.CombinedOutput()
		if invocation.shouldFail != (err != nil) {
			t.Fatalf("instrumented controller %v: error=%v output=%s", invocation.arguments, err, output)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, "/bin/bash", filepath.Join(root, "scripts", "control-acceptance.sh"))
	command.Dir = root
	environment := make([]string, 0, len(os.Environ())+3)
	for _, value := range os.Environ() {
		if strings.HasPrefix(value, "GOCOVERDIR=") ||
			strings.HasPrefix(value, "STEWARD_CONTROL_BIN=") ||
			strings.HasPrefix(value, "STEWARDCTL_BIN=") {
			continue
		}
		environment = append(environment, value)
	}
	command.Env = append(environment,
		"GOCOVERDIR="+coverDirectory,
		"STEWARD_CONTROL_BIN="+controlBinary,
		"STEWARDCTL_BIN="+ctlBinary,
	)
	output, err := command.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("controller acceptance exceeded its deadline: %v\n%s", ctx.Err(), output)
	}
	if err != nil {
		t.Fatalf("controller acceptance: %v\n%s", err, output)
	}
}

func writeControlCertificate(t *testing.T) (string, string) {
	t.Helper()
	return writeControlCertificateWithDNSNames(t, []string{"control.test"})
}

func writeControlCertificateWithDNSNames(t *testing.T, dnsNames []string) (string, string) {
	t.Helper()
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return writeControlCertificateWithKeyAndDNSNames(t, t.TempDir(), private, dnsNames)
}

func writeControlCertificateWithKey(t *testing.T, directory string, private crypto.Signer) (string, string) {
	t.Helper()
	return writeControlCertificateWithKeyAndDNSNames(t, directory, private, []string{"control.test"})
}

func writeControlCertificateWithKeyAndDNSNames(
	t *testing.T,
	directory string,
	private crypto.Signer,
	dnsNames []string,
) (string, string) {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "steward-control-test"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames: append([]string(nil), dnsNames...),
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, private.Public(), private)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	certFile := filepath.Join(directory, "server.crt")
	keyFile := filepath.Join(directory, "server.key")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}

func initializeLegacyControllerForWitnessTest(t *testing.T) string {
	t.Helper()
	stateDirectory := filepath.Join(t.TempDir(), "control")
	store, err := controlstore.Initialize(stateDirectory, controlstore.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	manager, err := controlauth.InitializeKey(filepath.Join(stateDirectory, "auth.key"))
	if err != nil {
		t.Fatal(err)
	}
	raw, _, _, err := store.BootstrapSiteAdmin(manager, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	admin, err := store.AuthenticateOperator(manager, raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, created, err := store.CreateTenant(admin, "legacy-tenant", time.Now().UTC()); err != nil || !created {
		t.Fatalf("populate legacy controller state = (%v, %v)", created, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	return stateDirectory
}

func initializeWitnessForTest(t *testing.T, stateDirectory string) {
	t.Helper()
	if err := run([]string{"-initialize-witness-key", "-state-dir", stateDirectory}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
}
