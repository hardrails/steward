package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/evidence"
	"github.com/hardrails/steward/internal/executoruplink"
	"github.com/hardrails/steward/internal/journal"
	"github.com/hardrails/steward/internal/nodeclient"
)

func TestReadTokenTrimsFileWhitespace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "executor-token")
	if err := os.WriteFile(path, []byte("development-only-executor-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	token, err := nodeclient.ReadToken(path)
	if err != nil {
		t.Fatal(err)
	}
	if token != "development-only-executor-token" {
		t.Fatalf("token = %q", token)
	}
}

func TestReadTokenRejectsOverPermissiveFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "executor-token")
	if err := os.WriteFile(path, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := nodeclient.ReadToken(path); err == nil {
		t.Fatal("world-readable executor token was accepted")
	}
}

func TestSecureArtifactAndKeyReadersRejectUnsafeOrMalformedInputs(t *testing.T) {
	dir := t.TempDir()
	regular := filepath.Join(dir, "artifact")
	if err := os.WriteFile(regular, []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := readSecureArtifact(regular, false, 16); err != nil || string(got) != "payload" {
		t.Fatalf("readSecureArtifact = %q, %v", got, err)
	}
	if _, err := readSecureArtifact(regular, false, 3); err == nil {
		t.Fatal("readSecureArtifact accepted oversized artifact")
	}
	if err := os.Chmod(regular, 0o622); err != nil {
		t.Fatal(err)
	}
	if _, err := readSecureArtifact(regular, false, 16); err == nil {
		t.Fatal("readSecureArtifact accepted group-writable trust artifact")
	}
	if _, err := readSecureArtifact(regular, true, 16); err == nil {
		t.Fatal("readSecureArtifact accepted group-writable secret")
	}
	if err := os.Chmod(regular, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "artifact-link")
	if err := os.Symlink(regular, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readSecureArtifact(link, false, 16); err == nil {
		t.Fatal("readSecureArtifact followed symlink")
	}
	if _, err := readSecureArtifact(dir, false, 16); err == nil {
		t.Fatal("readSecureArtifact accepted directory")
	}

	badPublic := filepath.Join(dir, "bad-public")
	if err := os.WriteFile(badPublic, []byte("not base64"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readEd25519PublicKey(badPublic); err == nil {
		t.Fatal("readEd25519PublicKey accepted malformed key")
	}
	badPrivate := filepath.Join(dir, "bad-private")
	if err := os.WriteFile(badPrivate, []byte("not pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readEd25519PrivateKey(badPrivate); err == nil {
		t.Fatal("readEd25519PrivateKey accepted malformed key")
	}
}

func TestEd25519KeyReadersAcceptOnlyExpectedFormats(t *testing.T) {
	dir := t.TempDir()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicPath := filepath.Join(dir, "public")
	if err := os.WriteFile(publicPath, []byte(base64.StdEncoding.EncodeToString(public)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got, err := readEd25519PublicKey(publicPath); err != nil || !got.Equal(public) {
		t.Fatalf("read public key: %v", err)
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	privatePath := filepath.Join(dir, "private")
	if err := os.WriteFile(privatePath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded}), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := readEd25519PrivateKey(privatePath); err != nil || !got.Equal(private) {
		t.Fatalf("read private key: %v", err)
	}
	if err := os.Chmod(privatePath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readEd25519PrivateKey(privatePath); err == nil {
		t.Fatal("readEd25519PrivateKey accepted group/world readable key")
	}
}

func TestReadTokenRejectsEmptyOversizedAndDirectory(t *testing.T) {
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty-token")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := nodeclient.ReadToken(empty); err == nil {
		t.Fatal("readToken accepted empty token")
	}
	large := filepath.Join(dir, "large-token")
	if err := os.WriteFile(large, []byte(strings.Repeat("x", 4097)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := nodeclient.ReadToken(large); err == nil {
		t.Fatal("readToken accepted oversized token")
	}
	if _, err := nodeclient.ReadToken(dir); err == nil {
		t.Fatal("readToken accepted directory")
	}
}

func TestExecutorMainServesHealthAndShutsDown(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs the real executor binary")
	}
	bin := buildExecutor(t)
	socket := fakeDockerSocket(t, true)
	token := executorTokenFile(t)
	addr := freeAddress(t)
	cmd := exec.Command(bin, "-docker-socket", socket, "-token-file", token, "-addr", addr)
	cmd.Env = executorEnv()
	var output strings.Builder
	cmd.Stdout, cmd.Stderr = &output, &output
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		}
	})
	url := "http://" + addr + "/v1/healthz"
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if response, err := http.Get(url); err == nil {
			response.Body.Close()
			if response.StatusCode == http.StatusOK {
				break
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	response, err := http.Get(url)
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("executor health failed: response=%v err=%v output=%s", response, err, output.String())
	}
	response.Body.Close()
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if err := waitCommand(cmd, 5*time.Second); err != nil {
		t.Fatalf("executor shutdown: %v output=%s", err, output.String())
	}
}

func TestExecutorMainRunsOutboundOnlyUplink(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs the real executor binary")
	}
	bin := buildExecutor(t)
	socket := fakeDockerSocket(t, true)
	token := executorTokenFile(t)
	var polls atomic.Int32
	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/executor-uplink/poll" || r.Header.Get("Authorization") != "Bearer opaque" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		polls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"commands":[]}`))
	}))
	defer control.Close()
	dir := t.TempDir()
	credential := filepath.Join(dir, "credential.json")
	if err := os.WriteFile(credential, []byte(`{"version":1,"tenant_id":"tenant-a","node_id":"executor-1","credential":"opaque"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(dir, "state.json")
	if err := executoruplink.InitializeStateStore(statePath); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin,
		"-docker-socket", socket, "-token-file", token,
		"-disable-inbound-listener", "-uplink-url", control.URL,
		"-uplink-credential-file", credential,
		"-uplink-state-file", statePath,
		"-uplink-poll-interval", "10ms",
	)
	cmd.Env = executorEnv()
	var output strings.Builder
	cmd.Stdout, cmd.Stderr = &output, &output
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		}
	})
	deadline := time.Now().Add(5 * time.Second)
	for polls.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if polls.Load() == 0 {
		t.Fatalf("executor never polled: %s", output.String())
	}
	_ = cmd.Process.Signal(syscall.SIGTERM)
	if err := waitCommand(cmd, 5*time.Second); err != nil {
		t.Fatalf("outbound-only shutdown: %v output=%s", err, output.String())
	}
}

func TestExecutorMainFailsClosedOnMissingRunscAndPartialUplink(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the real executor binary")
	}
	bin := buildExecutor(t)
	token := executorTokenFile(t)
	missingRunsc := exec.Command(bin, "-docker-socket", fakeDockerSocket(t, false), "-token-file", token)
	missingRunsc.Env = executorEnv()
	if output, err := missingRunsc.CombinedOutput(); err == nil || !strings.Contains(string(output), "runsc") {
		t.Fatalf("missing runsc did not fail closed: err=%v output=%s", err, output)
	}
	partial := exec.Command(bin,
		"-docker-socket", fakeDockerSocket(t, true), "-token-file", token,
		"-uplink-url", "http://127.0.0.1:1",
	)
	partial.Env = executorEnv()
	if output, err := partial.CombinedOutput(); err == nil || !strings.Contains(string(output), "uplink-credential-file") {
		t.Fatalf("partial uplink did not fail closed: err=%v output=%s", err, output)
	}
	unquotaedWithoutAdmission := exec.Command(bin,
		"-docker-socket", fakeDockerSocket(t, true), "-token-file", token,
		"-allow-unquotaed-state-on-dedicated-host",
	)
	unquotaedWithoutAdmission.Env = executorEnv()
	if output, err := unquotaedWithoutAdmission.CombinedOutput(); err == nil || !strings.Contains(string(output), "signed admission requires") {
		t.Fatalf("unquotaed state without signed admission did not fail closed: err=%v output=%s", err, output)
	}
}

func TestExecutorMainVersionNeedsNoDockerOrCredential(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the real executor binary")
	}
	bin := buildExecutor(t)
	command := exec.Command(bin, "-version")
	command.Env = executorEnv()
	output, err := command.CombinedOutput()
	if err != nil || !strings.HasPrefix(string(output), "steward-executor ") {
		t.Fatalf("version: err=%v output=%s", err, output)
	}
}

func TestExecutorMainInitializesAdmissionFenceExactlyOnce(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the real executor binary")
	}
	bin := buildExecutor(t)
	path := filepath.Join(t.TempDir(), "admission-fences.bin")
	command := exec.Command(bin, "-initialize-admission-fence", "-admission-fence-file", path)
	command.Env = executorEnv()
	if output, err := command.CombinedOutput(); err != nil || !strings.Contains(string(output), "initialized admission fence") {
		t.Fatalf("initialize: err=%v output=%s", err, output)
	}
	command = exec.Command(bin, "-initialize-admission-fence", "-admission-fence-file", path)
	command.Env = executorEnv()
	if output, err := command.CombinedOutput(); err == nil {
		t.Fatalf("reinitialize unexpectedly succeeded: %s", output)
	}
}

func TestExecutorMainCheckConfigValidatesWithoutServing(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the real executor binary")
	}
	bin := buildExecutor(t)
	addr := freeAddress(t)
	command := exec.Command(bin,
		"-check-config",
		"-docker-socket", fakeDockerSocket(t, true),
		"-token-file", executorTokenFile(t),
		"-addr", addr,
	)
	command.Env = executorEnv()
	output, err := command.CombinedOutput()
	if err != nil || string(output) != "executor configuration valid\n" {
		t.Fatalf("check config: err=%v output=%s", err, output)
	}
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("check-config bound the listener: %v", err)
	}
	listener.Close()
}

func TestExecutorMainCheckConfigValidatesEveryUplinkFile(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the real executor binary")
	}
	bin := buildExecutor(t)
	dir := t.TempDir()
	credential := filepath.Join(dir, "credential.json")
	if err := os.WriteFile(credential, []byte(`{"version":1,"tenant_id":"t","node_id":"n","credential":"opaque"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(dir, "state.json")
	if err := executoruplink.InitializeStateStore(state); err != nil {
		t.Fatal(err)
	}
	base := []string{
		"-check-config",
		"-docker-socket", fakeDockerSocket(t, true),
		"-token-file", executorTokenFile(t),
		"-disable-inbound-listener",
		"-uplink-url", "http://127.0.0.1:1",
		"-uplink-credential-file", credential,
		"-uplink-state-file", state,
	}
	run := func(args ...string) (string, error) {
		t.Helper()
		command := exec.Command(bin, args...)
		command.Env = executorEnv()
		output, err := command.CombinedOutput()
		return string(output), err
	}
	if output, err := run(base...); err != nil || output != "executor configuration valid\n" {
		t.Fatalf("valid uplink files: err=%v output=%s", err, output)
	}

	missingCredential := append([]string(nil), base...)
	missingCredential[9] = filepath.Join(dir, "missing-credential.json")
	if output, err := run(missingCredential...); err == nil || !strings.Contains(output, "credential") {
		t.Fatalf("missing credential passed: err=%v output=%s", err, output)
	}

	missingState := append([]string(nil), base...)
	missingState[11] = filepath.Join(dir, "missing-state.json")
	if output, err := run(missingState...); err == nil || !strings.Contains(output, "state") {
		t.Fatalf("missing state passed: err=%v output=%s", err, output)
	}

	badCA := filepath.Join(dir, "bad-ca.pem")
	if err := os.WriteFile(badCA, []byte("not a PEM CA"), 0o600); err != nil {
		t.Fatal(err)
	}
	badTLS := append(append([]string(nil), base...), "-uplink-tls-ca-file", badCA)
	badTLS[7] = "https://control.invalid"
	if output, err := run(badTLS...); err == nil || !strings.Contains(output, "CA") {
		t.Fatalf("malformed CA passed: err=%v output=%s", err, output)
	}
}

func TestExecutorMainInitializesFenceOnceWithoutDocker(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the real executor binary")
	}
	bin := buildExecutor(t)
	path := filepath.Join(t.TempDir(), "state.json")
	command := exec.Command(bin, "-initialize-uplink-state", "-uplink-state-file", path)
	command.Env = executorEnv()
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("initialize: %v output=%s", err, output)
	}
	if _, err := executoruplink.LoadStateStore(path); err != nil {
		t.Fatal(err)
	}
	command = exec.Command(bin, "-initialize-uplink-state", "-uplink-state-file", path)
	command.Env = executorEnv()
	if output, err := command.CombinedOutput(); err == nil {
		t.Fatalf("second initialization overwrote fence: %s", output)
	}

	legacyPath := filepath.Join(t.TempDir(), "legacy-state.json")
	legacy := []byte(`{"version":1,"positions":{"agent-1":{"generation":2,"sequence":7,"reported_status":"running"}}}`)
	if err := os.WriteFile(legacyPath, legacy, 0o600); err != nil {
		t.Fatal(err)
	}
	command = exec.Command(bin, "-migrate-uplink-state-v1-tenant", "tenant-a", "-uplink-state-file", legacyPath)
	command.Env = executorEnv()
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("migrate: %v output=%s", err, output)
	}
	if _, err := executoruplink.LoadStateStore(legacyPath); err != nil {
		t.Fatal(err)
	}
	backup, err := os.ReadFile(legacyPath + ".v1.bak")
	if err != nil || string(backup) != string(legacy) {
		t.Fatalf("migration backup=%q err=%v", backup, err)
	}
	command = exec.Command(bin, "-migrate-uplink-state-v1-tenant", "tenant-a", "-uplink-state-file", legacyPath)
	command.Env = executorEnv()
	if output, err := command.CombinedOutput(); err == nil {
		t.Fatalf("second migration or downgrade was accepted: %s", output)
	}
}

func buildExecutor(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "steward-executor")
	args := []string{"build", "-o", bin, "."}
	if os.Getenv("STEWARD_EXECUTOR_TEST_COVERDIR") != "" {
		args = []string{"build", "-cover", "-o", bin, "."}
	}
	command := exec.Command("go", args...)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build executor: %v\n%s", err, output)
	}
	return bin
}

func TestExecutorMainCheckConfigValidatesSecureAdmission(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the real executor binary")
	}
	bin := buildExecutor(t)
	dir := t.TempDir()
	sitePublic, sitePrivate, _ := ed25519.GenerateKey(rand.Reader)
	publisherPublic, _, _ := ed25519.GenerateKey(rand.Reader)
	_, receiptPrivate, _ := ed25519.GenerateKey(rand.Reader)
	policy := admission.SitePolicy{
		SchemaVersion: admission.SchemaV1, PolicyID: "site-a", PolicyEpoch: 1,
		Publishers: []admission.PublisherRule{{
			KeyID: "publisher-a", PublicKey: base64.StdEncoding.EncodeToString(publisherPublic),
			AllowedProfiles:     []admission.ProfileRef{{ID: "generic-v1", Version: "v1"}},
			AllowedRepositories: []string{"registry.local/agent"},
			ResourceCeiling:     admission.ResourceLimits{MemoryBytes: 1 << 20, CPUMillis: 100, PIDs: 32},
		}},
		Tenants: []admission.TenantRule{{
			TenantID: "tenant-a", PublisherKeyIDs: []string{"publisher-a"},
			ResourceCeiling: admission.ResourceLimits{MemoryBytes: 1 << 20, CPUMillis: 100, PIDs: 32},
		}},
	}
	payload, _ := json.Marshal(policy)
	envelope, err := dsse.Sign(admission.PolicyPayloadType, payload, "site-root", sitePrivate)
	if err != nil {
		t.Fatal(err)
	}
	policyRaw, _ := dsse.Marshal(envelope)
	policyPath := filepath.Join(dir, "policy.dsse.json")
	rootPath := filepath.Join(dir, "site-root.public")
	receiptPath := filepath.Join(dir, "receipt.private.pem")
	if err := os.WriteFile(policyPath, policyRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rootPath, []byte(base64.StdEncoding.EncodeToString(sitePublic)), 0o600); err != nil {
		t.Fatal(err)
	}
	privateDER, _ := x509.MarshalPKCS8PrivateKey(receiptPrivate)
	if err := os.WriteFile(receiptPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	fencePath := filepath.Join(dir, "fences.bin")
	if err := admission.InitializeFenceStore(fencePath); err != nil {
		t.Fatal(err)
	}
	journalPath := filepath.Join(dir, "journal.bin")
	operationJournal, err := journal.Open(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := operationJournal.Close(); err != nil {
		t.Fatal(err)
	}
	evidencePath := filepath.Join(dir, "evidence.bin")
	receiptLog, err := evidence.Open(evidencePath, receiptPrivate, "node-a", 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := receiptLog.Close(); err != nil {
		t.Fatal(err)
	}
	args := []string{
		"-check-config", "-docker-socket", fakeDockerSocket(t, true), "-token-file", executorTokenFile(t),
		"-admission-policy-file", policyPath,
		"-admission-site-root-public-key-file", rootPath,
		"-admission-site-root-key-id", "site-root", "-admission-node-id", "node-a",
		"-admission-fence-file", fencePath,
		"-admission-journal-file", journalPath,
		"-admission-evidence-file", evidencePath,
		"-admission-evidence-key-file", receiptPath,
	}
	before := snapshotExecutorTree(t, dir)
	command := exec.Command(bin, args...)
	command.Env = executorEnv()
	output, err := command.CombinedOutput()
	if err != nil || string(output) != "executor configuration valid\n" {
		t.Fatalf("secure check config: err=%v output=%s", err, output)
	}
	after := snapshotExecutorTree(t, dir)
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("secure check-config changed durable files\nbefore=%#v\nafter=%#v", before, after)
	}
	pendingJournalPath := filepath.Join(dir, "pending-journal.bin")
	pendingJournal, err := journal.Open(pendingJournalPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pendingJournal.Prepare("pending", "target", 1); err != nil {
		t.Fatal(err)
	}
	if err := pendingJournal.Close(); err != nil {
		t.Fatal(err)
	}
	pendingArgs := append([]string(nil), args...)
	for index := range pendingArgs {
		if pendingArgs[index] == "-admission-journal-file" {
			pendingArgs[index+1] = pendingJournalPath
			break
		}
	}
	pendingCheck := exec.Command(bin, pendingArgs...)
	pendingCheck.Env = executorEnv()
	if output, err := pendingCheck.CombinedOutput(); err == nil || !strings.Contains(string(output), "operation journal has pending work") {
		t.Fatalf("pending journal check did not fail: err=%v output=%s", err, output)
	}
	addr := freeAddress(t)
	degradedArgs := append([]string(nil), pendingArgs[1:]...)
	degradedArgs = append(degradedArgs, "-addr", addr)
	degraded := exec.Command(bin, degradedArgs...)
	degraded.Env = executorEnv()
	var degradedOutput strings.Builder
	degraded.Stdout, degraded.Stderr = &degradedOutput, &degradedOutput
	if err := degraded.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if degraded.ProcessState == nil {
			_ = degraded.Process.Kill()
			_, _ = degraded.Process.Wait()
		}
	})
	readinessURL := "http://" + addr + "/v1/readiness"
	deadline := time.Now().Add(5 * time.Second)
	var readinessStatus int
	for time.Now().Before(deadline) {
		request, _ := http.NewRequest(http.MethodGet, readinessURL, nil)
		request.Header.Set("Authorization", "Bearer local-secret")
		if response, err := http.DefaultClient.Do(request); err == nil {
			readinessStatus = response.StatusCode
			response.Body.Close()
			if readinessStatus == http.StatusServiceUnavailable {
				break
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	if readinessStatus != http.StatusServiceUnavailable {
		t.Fatalf("degraded startup readiness=%d output=%s", readinessStatus, degradedOutput.String())
	}
	if err := degraded.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if err := waitCommand(degraded, 5*time.Second); err != nil {
		t.Fatalf("degraded executor shutdown: %v output=%s", err, degradedOutput.String())
	}
	if !strings.Contains(degradedOutput.String(), "starting in degraded containment mode") {
		t.Fatalf("degraded startup was not logged: %s", degradedOutput.String())
	}
	for _, missing := range []struct {
		flag string
		path string
		want string
	}{
		{flag: "-admission-journal-file", path: filepath.Join(dir, "missing-journal.bin"), want: "journal"},
		{flag: "-admission-evidence-file", path: filepath.Join(dir, "missing-evidence.bin"), want: "evidence"},
	} {
		missingArgs := append([]string(nil), args...)
		for index := range missingArgs {
			if missingArgs[index] == missing.flag {
				missingArgs[index+1] = missing.path
				break
			}
		}
		check := exec.Command(bin, missingArgs...)
		check.Env = executorEnv()
		if output, err := check.CombinedOutput(); err == nil || !strings.Contains(string(output), missing.want) || !strings.Contains(string(output), "missing") {
			t.Fatalf("missing %s: err=%v output=%s", missing.want, err, output)
		}
		if _, err := os.Lstat(missing.path); !os.IsNotExist(err) {
			t.Fatalf("check-config created %s: %v", missing.path, err)
		}
	}
	partial := exec.Command(bin,
		"-check-config", "-docker-socket", fakeDockerSocket(t, true), "-token-file", executorTokenFile(t),
		"-admission-policy-file", policyPath,
	)
	partial.Env = executorEnv()
	if output, err := partial.CombinedOutput(); err == nil || !strings.Contains(string(output), "signed admission requires") {
		t.Fatalf("partial admission did not fail: err=%v output=%s", err, output)
	}
}

type executorTreeEntry struct {
	Mode    os.FileMode
	ModTime time.Time
	Bytes   string
}

func snapshotExecutorTree(t *testing.T, root string) map[string]executorTreeEntry {
	t.Helper()
	result := make(map[string]executorTreeEntry)
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		entry := executorTreeEntry{Mode: info.Mode(), ModTime: info.ModTime()}
		if info.Mode().IsRegular() {
			raw, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			entry.Bytes = string(raw)
		}
		result[relative] = entry
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func executorEnv() []string {
	dir := os.Getenv("STEWARD_EXECUTOR_TEST_COVERDIR")
	if dir == "" {
		return nil
	}
	env := make([]string, 0, len(os.Environ())+1)
	for _, value := range os.Environ() {
		if !strings.HasPrefix(value, "GOCOVERDIR=") {
			env = append(env, value)
		}
	}
	return append(env, "GOCOVERDIR="+dir)
}

func executorTokenFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("local-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func fakeDockerSocket(t *testing.T, runsc bool) string {
	t.Helper()
	file, err := os.CreateTemp("/tmp", "steward-executor-docker-")
	if err != nil {
		t.Fatal(err)
	}
	path := file.Name()
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1.41/info" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if runsc {
			_, _ = w.Write([]byte(`{"Runtimes":{"runsc":{}}}`))
		} else {
			_, _ = w.Write([]byte(`{"Runtimes":{"runc":{}}}`))
		}
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close(); _ = os.Remove(path) })
	return path
}

func freeAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	return address
}

func waitCommand(command *exec.Cmd, timeout time.Duration) error {
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	select {
	case err := <-done:
		return err
	case <-time.After(timeout):
		_ = command.Process.Kill()
		return <-done
	}
}
