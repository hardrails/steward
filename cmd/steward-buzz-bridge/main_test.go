package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	testAuthor  = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testAgent   = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	testEvent   = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	testReply   = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	testChannel = "123e4567-e89b-12d3-a456-426614174000"
)

func TestConfigRejectsBroadOrUnsafeAuthority(t *testing.T) {
	cfg := validTestConfig(t.TempDir())
	if err := cfg.validate(); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*config){
		"identity is invalid":      func(value *config) { value.SchemaVersion = "wrong" },
		"authors are missing":      func(value *config) { value.AllowedAuthors = nil },
		"author is not canonical":  func(value *config) { value.AllowedAuthors = []string{strings.ToUpper(testAuthor)} },
		"agent author is allowed":  func(value *config) { value.AllowedAuthors = []string{testAgent} },
		"relay has userinfo":       func(value *config) { value.RelayURL = "https://user@buzz.example" },
		"relay has path":           func(value *config) { value.RelayURL = "https://buzz.example/api" },
		"remote gateway":           func(value *config) { value.GatewayURL = "https://node.example" },
		"gateway port is invalid":  func(value *config) { value.GatewayURL = "http://127.0.0.1:99999" },
		"listener port is invalid": func(value *config) { value.HTTPListen = "127.0.0.1:nope" },
		"relative secret":          func(value *config) { value.TaskKeyFile = "task.pem" },
		"relative optional secret": func(value *config) { value.BuzzAuthTagFile = "buzz.auth" },
		"relative Control CA":      func(value *config) { value.ControlCAFile = "control-ca.pem" },
		"poll interval is invalid": func(value *config) { value.PollIntervalSeconds = 301 },
		"record cap is invalid":    func(value *config) { value.MaxRecords = 10001 },
		"duplicate channel":        func(value *config) { value.Channels = []string{testChannel, testChannel} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			candidate := cfg
			candidate.AllowedAuthors = append([]string(nil), cfg.AllowedAuthors...)
			candidate.Channels = append([]string(nil), cfg.Channels...)
			mutate(&candidate)
			if err := candidate.validate(); err == nil {
				t.Fatal("unsafe configuration was accepted")
			}
		})
	}
}

func TestMalformedVerifiedEventsAreIgnoredWithoutPoisoningTheChannel(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	b := &bridge{cfg: validTestConfig(t.TempDir()), now: func() time.Time { return now }}
	malformed := validEvent(now)
	malformed.Tags = [][]string{{"h"}}
	if b.eligible(testChannel, malformed) {
		t.Fatal("malformed event was eligible")
	}
	oversized := validEvent(now)
	oversized.Content = strings.Repeat("x", maxMessageBytes+1)
	if b.eligible(testChannel, oversized) {
		t.Fatal("oversized event was eligible")
	}
}

func TestNewBridgeValidatesEveryProtectedInput(t *testing.T) {
	directory := t.TempDir()
	cfg := validTestConfig(directory)
	for _, path := range []string{
		cfg.BuzzPrivateKeyFile, cfg.ControlTokenFile, cfg.GatewayTokenFile,
		cfg.ServiceTrustFile, cfg.TaskKeyFile,
	} {
		if err := os.WriteFile(path, []byte("protected\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(cfg.BuzzBinary, []byte("#!/bin/sh\nprintf '{\"public_key\":\""+testAgent+"\"}\\n'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.StewardctlBinary, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(directory, "bridge.json")
	if err := os.WriteFile(configPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	readyBridge, err := newBridge(configPath, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newBridge(filepath.Join(directory, "missing-config.json"), slog.Default()); err == nil ||
		!strings.Contains(err.Error(), "read configuration") {
		t.Fatalf("missing configuration error=%v", err)
	}
	malformedPath := filepath.Join(directory, "malformed.json")
	if err := os.WriteFile(malformedPath, []byte("{} {}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := newBridge(malformedPath, slog.Default()); err == nil || !strings.Contains(err.Error(), "strict JSON") {
		t.Fatalf("malformed configuration error=%v", err)
	}
	invalid := cfg
	invalid.SchemaVersion = "wrong"
	invalidRaw, err := json.Marshal(invalid)
	if err != nil {
		t.Fatal(err)
	}
	invalidPath := filepath.Join(directory, "invalid.json")
	if err := os.WriteFile(invalidPath, invalidRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := newBridge(invalidPath, slog.Default()); err == nil || !strings.Contains(err.Error(), "identity") {
		t.Fatalf("invalid configuration error=%v", err)
	}
	stateFile := filepath.Join(directory, "state-file")
	if err := os.WriteFile(stateFile, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	invalid = cfg
	invalid.StateDirectory = stateFile
	invalidRaw, err = json.Marshal(invalid)
	if err != nil {
		t.Fatal(err)
	}
	stateConfigPath := filepath.Join(directory, "state-invalid.json")
	if err := os.WriteFile(stateConfigPath, invalidRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := newBridge(stateConfigPath, slog.Default()); err == nil || !strings.Contains(err.Error(), "state directory") {
		t.Fatalf("invalid state directory error=%v", err)
	}
	invalid = cfg
	invalid.BuzzPrivateKeyFile = filepath.Join(directory, "missing-private-key")
	invalidRaw, err = json.Marshal(invalid)
	if err != nil {
		t.Fatal(err)
	}
	keyConfigPath := filepath.Join(directory, "key-invalid.json")
	if err := os.WriteFile(keyConfigPath, invalidRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := newBridge(keyConfigPath, slog.Default()); err == nil || !strings.Contains(err.Error(), "private key") {
		t.Fatalf("missing private key error=%v", err)
	}
	var stdout, stderr bytes.Buffer
	if code := runMain([]string{"-version"}, &stdout, &stderr); code != 0 || !strings.HasPrefix(stdout.String(), "steward-buzz-bridge ") {
		t.Fatalf("version code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := runMain([]string{"-config", configPath, "-check-config"}, &stdout, &stderr); code != 0 ||
		!strings.Contains(stdout.String(), `"valid":true`) {
		t.Fatalf("check code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if err := readyBridge.ingest(testChannel, validEvent(time.Now())); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := runMain([]string{"-config", configPath, "-list-records"}, &stdout, &stderr); code != 0 ||
		!strings.Contains(stdout.String(), `"event_id":"`+testEvent+`"`) || strings.Contains(stdout.String(), "hello") {
		t.Fatalf("list code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := runMain([]string{"-config", configPath, "-retry-record", testEvent}, &stdout, &stderr); code != 0 ||
		!strings.Contains(stdout.String(), `"queued":true`) {
		t.Fatalf("retry code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	recordPath := filepath.Join(cfg.StateDirectory, "records", testEvent+".json")
	completed, err := readRecord(recordPath)
	if err != nil {
		t.Fatal(err)
	}
	completed.Phase = "replied"
	completed.ReplyDigest = sha256Digest([]byte("answer"))
	completed.ReplyEventID = testReply
	if err := writeRecord(recordPath, completed); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := runMain([]string{"-config", configPath, "-retry-record", testEvent}, &stdout, &stderr); code != 1 ||
		!strings.Contains(stderr.String(), "cannot be retried") {
		t.Fatalf("completed retry code=%d stderr=%q", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := runMain([]string{"-config", configPath, "-retry-record", "INVALID"}, &stdout, &stderr); code != 1 ||
		!strings.Contains(stderr.String(), "64 lowercase hexadecimal") {
		t.Fatalf("invalid retry code=%d stderr=%q", code, stderr.String())
	}
	locked, acquired, err := acquireEventLock(strings.TrimSuffix(recordPath, ".json") + ".lock")
	if err != nil || !acquired {
		t.Fatalf("record lock acquired=%v error=%v", acquired, err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := runMain([]string{"-config", configPath, "-retry-record", testEvent}, &stdout, &stderr); code != 1 ||
		!strings.Contains(stderr.String(), "currently being processed") {
		t.Fatalf("locked retry code=%d stderr=%q", code, stderr.String())
	}
	if err := releaseEventLock(locked); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(recordPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := runMain([]string{"-config", configPath, "-list-records"}, &stdout, &stderr); code != 1 ||
		!strings.Contains(stderr.String(), "record is invalid") {
		t.Fatalf("corrupt list code=%d stderr=%q", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := runMain([]string{"-config", configPath, "-once", "-list-records"}, &stdout, &stderr); code != 2 ||
		!strings.Contains(stderr.String(), "choose only one") {
		t.Fatalf("conflicting mode code=%d stderr=%q", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := runMain([]string{"-config", configPath, "-retry-record", strings.Repeat("e", 64)}, &stdout, &stderr); code != 1 ||
		!strings.Contains(stderr.String(), "no such file") {
		t.Fatalf("missing retry code=%d stderr=%q", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := runMain(nil, &stdout, &stderr); code != 2 || !strings.Contains(stderr.String(), "-config is required") {
		t.Fatalf("missing config code=%d stderr=%q", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := runMain([]string{"-unknown"}, &stdout, &stderr); code != 2 || !strings.Contains(stderr.String(), "flag provided") {
		t.Fatalf("unknown flag code=%d stderr=%q", code, stderr.String())
	}
	if err := os.Chmod(cfg.GatewayTokenFile, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := newBridge(configPath, slog.Default()); err == nil || !strings.Contains(err.Error(), "gateway.token") {
		t.Fatalf("unsafe Gateway token error=%v", err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := runMain([]string{"-config", configPath, "-check-config"}, &stdout, &stderr); code != 1 ||
		!strings.Contains(stderr.String(), "gateway.token") {
		t.Fatalf("unsafe config code=%d stderr=%q", code, stderr.String())
	}
	if err := os.Chmod(cfg.GatewayTokenFile, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.BuzzAuthTagFile = filepath.Join(directory, "missing-buzz-auth-tag")
	raw, err = json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := newBridge(configPath, slog.Default()); err == nil || !strings.Contains(err.Error(), "owner attestation") {
		t.Fatalf("missing optional Buzz owner attestation error=%v", err)
	}
	cfg.BuzzAuthTagFile = ""
	cfg.ControlCAFile = filepath.Join(directory, "missing-control-ca")
	raw, err = json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := newBridge(configPath, slog.Default()); err == nil || !strings.Contains(err.Error(), "Control CA") {
		t.Fatalf("missing Control CA error=%v", err)
	}
	cfg.ControlCAFile = ""
	cfg.BuzzBinary = filepath.Join(directory, "missing-buzz")
	raw, err = json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := newBridge(configPath, slog.Default()); err == nil || !strings.Contains(err.Error(), "required executable") {
		t.Fatalf("missing executable error=%v", err)
	}
}

func TestTaskRecoveryUsesTheRetainedBundle(t *testing.T) {
	directory := t.TempDir()
	cfg := validTestConfig(directory)
	stewardctl := writeExecutable(t, directory, "recover-stewardctl", `#!/bin/sh
result=
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-result-out" ]; then shift; result=$1; fi
  shift
done
if [ -n "$result" ]; then
  printf '{"run_id":"run_00000000000000000000000000000000","status":"completed","output":"recovered answer"}\n' >"$result"
  chmod 600 "$result"
fi
printf '{}\n'
`)
	cfg.StewardctlBinary = stewardctl
	if err := prepareStateDirectory(cfg.StateDirectory); err != nil {
		t.Fatal(err)
	}
	runDirectory := filepath.Join(cfg.StateDirectory, "runs", "retained")
	if err := os.Mkdir(runDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(runDirectory, "task.bundle.json"), []byte("retained\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rec := record{TaskID: "task-retained", RunDirectory: runDirectory}
	b := &bridge{cfg: cfg, logger: slog.Default(), now: time.Now}
	reply, err := b.runOrRecoverTask(context.Background(), validEvent(time.Now()), &rec,
		filepath.Join(cfg.StateDirectory, "records", testEvent+".json"))
	if err != nil || reply != "recovered answer" {
		t.Fatalf("recovered reply=%q error=%v", reply, err)
	}
	for attempt := 1; attempt <= 100; attempt++ {
		path := filepath.Join(cfg.StateDirectory, "runs", fmt.Sprintf("task-full-recovery-%d", attempt))
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := b.nextRunDirectory("task-full"); err == nil || !strings.Contains(err.Error(), "exhausted") {
		t.Fatalf("exhausted recovery error=%v", err)
	}
}

func TestPollReportsAChannelFailureWithoutClaimingSuccess(t *testing.T) {
	directory := t.TempDir()
	cfg := validTestConfig(directory)
	cfg.BuzzBinary = writeExecutable(t, directory, "failed-buzz", "#!/bin/sh\nexit 7\n")
	if err := prepareStateDirectory(cfg.StateDirectory); err != nil {
		t.Fatal(err)
	}
	b := &bridge{cfg: cfg, logger: slog.Default(), buzzKey: "nsec-fixture", now: time.Now}
	err := b.poll(context.Background())
	if err == nil || !strings.Contains(err.Error(), "failed items") || b.lastPoll != "" {
		t.Fatalf("poll error=%v last_poll=%q", err, b.lastPoll)
	}
}

func TestStatusSurfaceIsLoopbackSafeAndContentFree(t *testing.T) {
	b := &bridge{cfg: validTestConfig(t.TempDir()), lastError: "initial_poll_pending"}
	handler := b.statusServer().Handler

	health := httptest.NewRecorder()
	handler.ServeHTTP(health, httptest.NewRequest(http.MethodGet, "/health", nil))
	if health.Code != http.StatusServiceUnavailable || health.Header().Get("Cache-Control") != "no-store" ||
		!strings.Contains(health.Body.String(), `"ready":false`) {
		t.Fatalf("initial health code=%d headers=%v body=%s", health.Code, health.Header(), health.Body.String())
	}
	b.setError("")
	health = httptest.NewRecorder()
	handler.ServeHTTP(health, httptest.NewRequest(http.MethodGet, "/health", nil))
	if health.Code != http.StatusOK || !strings.Contains(health.Body.String(), `"ready":true`) {
		t.Fatalf("ready health code=%d body=%s", health.Code, health.Body.String())
	}

	status := httptest.NewRecorder()
	handler.ServeHTTP(status, httptest.NewRequest(http.MethodGet, "/status", nil))
	if status.Code != http.StatusOK || !strings.Contains(status.Body.String(), statusSchema) ||
		strings.Contains(status.Body.String(), "protected") {
		t.Fatalf("status code=%d body=%s", status.Code, status.Body.String())
	}
	denied := httptest.NewRecorder()
	handler.ServeHTTP(denied, httptest.NewRequest(http.MethodPost, "/status?unexpected=1", nil))
	if denied.Code != http.StatusMethodNotAllowed || !strings.Contains(denied.Body.String(), `"error":"method_not_allowed"`) {
		t.Fatalf("denied code=%d body=%s", denied.Code, denied.Body.String())
	}
}

func TestCommandAndResultBoundariesFailClosed(t *testing.T) {
	output, err := runCommand(context.Background(), "/bin/sh", []string{"-c", "printf useful"}, nil,
		[]string{"PATH=/usr/bin:/bin"}, 32)
	if err != nil || string(output) != "useful" {
		t.Fatalf("command output=%q error=%v", output, err)
	}
	if _, err := runCommand(context.Background(), "/bin/sh", []string{"-c", "exit 7"}, nil,
		[]string{"PATH=/usr/bin:/bin"}, 32); err == nil || !strings.Contains(err.Error(), "exit 7") {
		t.Fatalf("exit error=%v", err)
	}
	_, classified := runCommand(context.Background(), "/bin/sh", []string{"-c", "printf 'sensitive detail' >&2; exit 2"}, nil,
		[]string{"PATH=/usr/bin:/bin"}, 32)
	if classified == nil || publicFailureCode(classified) != "command_failed" || strings.Contains(publicFailureCode(classified), "sensitive") {
		t.Fatalf("public failure code=%q error=%v", publicFailureCode(classified), classified)
	}
	if _, err := runCommand(context.Background(), "/bin/sh", []string{"-c", "printf 123456789"}, nil,
		[]string{"PATH=/usr/bin:/bin"}, 4); err == nil || !strings.Contains(err.Error(), "byte limit") {
		t.Fatalf("limit error=%v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := runCommand(cancelled, "/bin/sh", []string{"-c", "sleep 1"}, nil,
		[]string{"PATH=/usr/bin:/bin"}, 32); err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("timeout error=%v", err)
	}

	directory := t.TempDir()
	result := filepath.Join(directory, "result.json")
	if err := os.WriteFile(result, []byte(`{"status":"completed","output":"answer"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if reply, err := readTaskReply(result); err != nil || reply != "answer" {
		t.Fatalf("reply=%q error=%v", reply, err)
	}
	if err := os.WriteFile(result, []byte(`{"status":"failed","output":"answer"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readTaskReply(result); err == nil || !strings.Contains(err.Error(), "completed") {
		t.Fatalf("failed result error=%v", err)
	}
	if _, err := readTaskReply(filepath.Join(directory, "missing-result.json")); err == nil {
		t.Fatal("missing task result was accepted")
	}
	if boundedError(fmt.Errorf("%s", strings.Repeat("x", 600))) != strings.Repeat("x", 512) {
		t.Fatal("bounded error did not enforce its byte cap")
	}
	if boundedError(nil) != "" || !fileExists(result) || fileExists(filepath.Join(directory, "missing")) {
		t.Fatal("nil error or file-existence boundary is incorrect")
	}
	buffer := &boundedBuffer{maximum: 4}
	if written, _ := buffer.Write([]byte("abcdef")); written != 6 || !buffer.exceeded || !bytes.Equal(buffer.content, []byte("abcd")) {
		t.Fatalf("bounded buffer written=%d exceeded=%v content=%q", written, buffer.exceeded, buffer.content)
	}
}

func TestFilesystemAndReplyFailureBranches(t *testing.T) {
	directory := t.TempDir()
	permissive := filepath.Join(directory, "permissive")
	if err := os.Mkdir(permissive, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := prepareStateDirectory(permissive); err == nil || !strings.Contains(err.Error(), "owner-only") {
		t.Fatalf("permissive state error=%v", err)
	}
	target := filepath.Join(directory, "target")
	if err := os.WriteFile(target, []byte("value"), 0o600); err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(directory, "linked")
	if err := os.Symlink(target, linked); err != nil {
		t.Fatal(err)
	}
	if _, err := readSecureFile(linked, 32, true); err == nil {
		t.Fatal("symlinked secret was accepted")
	}
	if _, err := runCommand(context.Background(), filepath.Join(directory, "missing"), nil, nil,
		[]string{"PATH=/usr/bin:/bin"}, 32); err == nil || !strings.Contains(err.Error(), "could not start") {
		t.Fatalf("missing command error=%v", err)
	}
	recorder := httptest.NewRecorder()
	writeStatusJSON(recorder, http.StatusOK, make(chan int))
	if recorder.Code != http.StatusInternalServerError || !strings.Contains(recorder.Body.String(), "response encoding failed") {
		t.Fatalf("encoding response code=%d body=%s", recorder.Code, recorder.Body.String())
	}

	cfg := validTestConfig(directory)
	cfg.BuzzBinary = writeExecutable(t, directory, "invalid-thread-buzz", "#!/bin/sh\nprintf 'not-json\\n'\n")
	b := &bridge{cfg: cfg, logger: slog.Default(), buzzKey: "nsec-fixture", now: time.Now}
	if _, _, err := b.findExistingReply(context.Background(), testChannel, testEvent, "answer"); err == nil ||
		!strings.Contains(err.Error(), "invalid verified thread") {
		t.Fatalf("invalid thread error=%v", err)
	}
	if err := prepareStateDirectory(cfg.StateDirectory); err != nil {
		t.Fatal(err)
	}
	recordPath := filepath.Join(cfg.StateDirectory, "records", testEvent+".json")
	if err := os.WriteFile(recordPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.loadOrCreateRecord(recordPath, testChannel, validEvent(time.Now())); err == nil ||
		!strings.Contains(err.Error(), "does not match") {
		t.Fatalf("corrupt record error=%v", err)
	}
	if err := writeRecord(filepath.Join(directory, "missing", "record.json"), record{}); err == nil {
		t.Fatal("record write into a missing directory succeeded")
	}
	if err := syncDirectory(filepath.Join(directory, "missing")); err == nil {
		t.Fatal("missing directory sync succeeded")
	}
}

func TestEventLockExcludesOverlappingProcessorsAndRecovers(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "event.lock")
	if lock, acquired, err := acquireEventLock(filepath.Join(directory, "missing", "event.lock")); err == nil || acquired || lock != nil {
		t.Fatalf("missing-parent lock=%v acquired=%v error=%v", lock, acquired, err)
	}
	first, acquired, err := acquireEventLock(path)
	if err != nil || !acquired {
		t.Fatalf("first lock acquired=%v error=%v", acquired, err)
	}
	second, acquired, err := acquireEventLock(path)
	if err != nil || acquired || second != nil {
		t.Fatalf("overlapping lock=%v acquired=%v error=%v", second, acquired, err)
	}
	if err := releaseEventLock(first); err != nil {
		t.Fatal(err)
	}
	third, acquired, err := acquireEventLock(path)
	if err != nil || !acquired {
		t.Fatalf("recovered lock acquired=%v error=%v", acquired, err)
	}
	if err := releaseEventLock(third); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if lock, acquired, err := acquireEventLock(path); err == nil || acquired || lock != nil {
		t.Fatalf("unsafe lock=%v acquired=%v error=%v", lock, acquired, err)
	}
	if err := releaseEventLock(nil); err != nil {
		t.Fatal(err)
	}

	cfg := validTestConfig(directory)
	if err := prepareStateDirectory(cfg.StateDirectory); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	event := validEvent(now)
	eventLock, acquired, err := acquireEventLock(filepath.Join(cfg.StateDirectory, "records", event.ID+".lock"))
	if err != nil || !acquired {
		t.Fatalf("process lock acquired=%v error=%v", acquired, err)
	}
	b := &bridge{cfg: cfg, logger: slog.Default(), now: func() time.Time { return now }}
	if err := b.process(context.Background(), testChannel, event); err != nil {
		t.Fatalf("busy event was not deferred: %v", err)
	}
	if err := releaseEventLock(eventLock); err != nil {
		t.Fatal(err)
	}
}

func TestAdditionalFilesystemAndStateFailureBoundaries(t *testing.T) {
	if identifier("") || identifier(strings.Repeat("a", 129)) || identifier("Uppercase") || !identifier("valid-id_1.2") {
		t.Fatal("identifier boundary is incorrect")
	}
	directory := t.TempDir()
	if err := prepareStateDirectory(filepath.Join(directory, "missing-parent", "state")); err == nil ||
		!strings.Contains(err.Error(), "create state directory") {
		t.Fatalf("missing parent error=%v", err)
	}
	badChildren := filepath.Join(directory, "bad-children")
	if err := os.Mkdir(badChildren, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(badChildren, "records"), []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := prepareStateDirectory(badChildren); err == nil || !strings.Contains(err.Error(), "child directories") {
		t.Fatalf("invalid child error=%v", err)
	}

	cfg := validTestConfig(directory)
	now := time.Now().UTC()
	b := &bridge{cfg: cfg, logger: slog.Default(), now: func() time.Time { return now }}
	if err := b.process(context.Background(), testChannel, validEvent(now)); err == nil ||
		!strings.Contains(err.Error(), "acquire inbox capacity lock") {
		t.Fatalf("missing lock directory error=%v", err)
	}
	if _, _, err := b.loadOrCreateRecord(filepath.Join(directory, "missing-record-parent", testEvent+".json"),
		testChannel, validEvent(now)); err == nil {
		t.Fatal("record creation with a missing parent succeeded")
	}
	result := filepath.Join(directory, "empty-result.json")
	if err := os.WriteFile(result, []byte(`{"status":"completed","output":"  "}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readTaskReply(result); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("empty reply error=%v", err)
	}
	lock, acquired, err := acquireEventLock(filepath.Join(directory, "closed.lock"))
	if err != nil || !acquired {
		t.Fatalf("closed lock acquired=%v error=%v", acquired, err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	if err := releaseEventLock(lock); err == nil {
		t.Fatal("releasing a closed lock succeeded")
	}
}

func TestEligibilityRequiresExactCryptographicMentionShape(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	b := &bridge{cfg: validTestConfig(t.TempDir()), now: func() time.Time { return now }}
	event := validEvent(now)
	if !b.eligible(testChannel, event) {
		t.Fatal("valid event was not eligible")
	}
	cases := map[string]func(*buzzEvent){
		"text only mention":  func(value *buzzEvent) { value.Tags = [][]string{{"h", testChannel}} },
		"duplicate mention":  func(value *buzzEvent) { value.Tags = append(value.Tags, []string{"p", testAgent}) },
		"wrong channel":      func(value *buzzEvent) { value.Tags[0][1] = "223e4567-e89b-12d3-a456-426614174000" },
		"wrong author":       func(value *buzzEvent) { value.PublicKey = strings.Repeat("e", 64) },
		"future timestamp":   func(value *buzzEvent) { value.CreatedAt = now.Unix() + 301 },
		"self-authored loop": func(value *buzzEvent) { value.PublicKey = testAgent },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			candidate := event
			candidate.Tags = cloneTags(event.Tags)
			mutate(&candidate)
			if b.eligible(testChannel, candidate) {
				t.Fatal("ineligible event was accepted")
			}
		})
	}
}

func TestPollRunsOneTaskAndRecoversWithoutDuplicateReply(t *testing.T) {
	directory := t.TempDir()
	now := time.Unix(1_900_000_000, 0)
	eventJSON := fmt.Sprintf(
		`[{"id":"%s","pubkey":"%s","kind":9,"content":"research this","created_at":%d,"tags":[["h","%s"],["p","%s"]]}]`,
		testEvent, testAuthor, now.Unix(), testChannel, testAgent,
	)
	replyCapture := filepath.Join(directory, "reply.txt")
	buzz := writeExecutable(t, directory, "buzz", `#!/bin/sh
[ "$STEWARD_BUZZ_PRINT_PUBLIC_KEY" = 1 ] && { printf '{"public_key":"`+testAgent+`"}\n'; exit 0; }
case " $* " in
  *" messages get "*) printf '%s\n' "$STEWARD_TEST_EVENT" ;;
  *" messages thread "*)
    if [ -f "$STEWARD_TEST_REPLY" ]; then
      content=$(cat "$STEWARD_TEST_REPLY")
      printf '[{"id":"%s","pubkey":"%s","kind":9,"content":"%s","created_at":1900000001,"tags":[["h","%s"],["e","%s","","reply"]]}]\n' \
        '`+testReply+`' '`+testAgent+`' "$content" '`+testChannel+`' '`+testEvent+`'
    else
      printf '[]\n'
    fi ;;
  *" messages send "*) cat >"$STEWARD_TEST_REPLY"; printf '{"event_id":"%s"}\n' '`+testReply+`' ;;
  *) exit 2 ;;
esac
`)
	stewardctl := writeExecutable(t, directory, "stewardctl", `#!/bin/sh
run=
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-run-dir" ]; then shift; run=$1; fi
  shift
done
[ -n "$run" ] || exit 2
mkdir -m 700 "$run"
printf '{"run_id":"run_00000000000000000000000000000000","status":"completed","output":"useful answer"}\n' >"$run/result.json"
chmod 600 "$run/result.json"
printf '{}\n'
`)
	t.Setenv("STEWARD_TEST_EVENT", eventJSON)
	t.Setenv("STEWARD_TEST_REPLY", replyCapture)
	cfg := validTestConfig(directory)
	cfg.BuzzBinary = buzz
	cfg.StewardctlBinary = stewardctl
	if err := prepareStateDirectory(cfg.StateDirectory); err != nil {
		t.Fatal(err)
	}
	taskSum := sha256.Sum256([]byte("steward-buzz-task-v1\x00" + cfg.TenantID + "\x00" + cfg.IntegrationID + "\x00" + testEvent))
	initialRun := filepath.Join(cfg.StateDirectory, "runs", "task-"+fmt.Sprintf("%x", taskSum[:16]))
	if err := os.Mkdir(initialRun, 0o700); err != nil {
		t.Fatal(err)
	}
	b := &bridge{cfg: cfg, logger: slog.Default(), buzzKey: "nsec-fixture", now: func() time.Time { return now }}
	// The production child receives a minimal environment. Add fixture-only
	// values by wrapping binaries because arbitrary parent env is intentionally absent.
	b.BuzzBinaryEnvironmentForTest(t, eventJSON, replyCapture)
	cfg.BuzzBinary = b.cfg.BuzzBinary
	if err := b.poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := b.drainReady(context.Background()); err != nil {
		t.Fatal(err)
	}
	if content, err := os.ReadFile(replyCapture); err != nil || string(content) != "useful answer" {
		t.Fatalf("reply=%q error=%v", content, err)
	}
	recordPath := filepath.Join(cfg.StateDirectory, "records", testEvent+".json")
	raw, err := os.ReadFile(recordPath)
	if err != nil || !strings.Contains(string(raw), `"phase": "replied"`) {
		t.Fatalf("record=%s error=%v", raw, err)
	}
	if !strings.Contains(string(raw), `"run_directory": "`+initialRun+`-recovery-1"`) {
		t.Fatalf("record did not retain the recovered run directory: %s", raw)
	}
	found, replyID, err := b.findExistingReply(context.Background(), testChannel, testEvent, "useful answer")
	if err != nil || !found || replyID != testReply {
		t.Fatalf("existing reply found=%v id=%q error=%v", found, replyID, err)
	}
	if err := b.poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if content, _ := os.ReadFile(replyCapture); string(content) != "useful answer" {
		t.Fatalf("second poll changed reply: %q", content)
	}
	cfg.MaxRecords = 1
	b.cfg.MaxRecords = 1
	secondEvent := validEvent(now)
	secondEvent.ID = strings.Repeat("e", 64)
	if _, _, err := b.loadOrCreateRecord(filepath.Join(cfg.StateDirectory, "records", secondEvent.ID+".json"),
		testChannel, secondEvent); err == nil || !strings.Contains(err.Error(), "max_records") {
		t.Fatalf("record capacity error=%v", err)
	}
	for _, path := range []string{
		cfg.BuzzPrivateKeyFile, cfg.ControlTokenFile, cfg.GatewayTokenFile,
		cfg.ServiceTrustFile, cfg.TaskKeyFile,
	} {
		if err := os.WriteFile(path, []byte("protected\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cfg.BuzzAuthTagFile = filepath.Join(directory, "buzz.auth-tag")
	cfg.ControlCAFile = filepath.Join(directory, "control-ca.pem")
	for _, path := range []string{cfg.BuzzAuthTagFile, cfg.ControlCAFile} {
		if err := os.WriteFile(path, []byte("optional\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	emptyWrapper := "#!/bin/sh\nexport STEWARD_TEST_EVENT='[]'\nexport STEWARD_TEST_REPLY='" + replyCapture + "'\nexec '" + buzz + "' \"$@\"\n"
	if err := os.WriteFile(cfg.BuzzBinary, []byte(emptyWrapper), 0o700); err != nil {
		t.Fatal(err)
	}
	cfg.HTTPListen = "127.0.0.1:19083"
	configRaw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(directory, "bridge.json")
	if err := os.WriteFile(configPath, configRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := runMain([]string{"-config", configPath, "-once"}, &stdout, &stderr); code != 0 {
		t.Fatalf("once code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestBridgeBindsConfiguredIdentityToPrivateKey(t *testing.T) {
	directory := t.TempDir()
	cfg := validTestConfig(directory)
	for _, path := range []string{cfg.BuzzPrivateKeyFile, cfg.ControlTokenFile, cfg.GatewayTokenFile, cfg.ServiceTrustFile, cfg.TaskKeyFile} {
		if err := os.WriteFile(path, []byte("protected\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	wrong := strings.Repeat("e", 64)
	if err := os.WriteFile(cfg.BuzzBinary, []byte("#!/bin/sh\nprintf '{\"public_key\":\""+wrong+"\"}\\n'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.StewardctlBinary, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "bridge.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := newBridge(path, slog.Default()); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("identity mismatch error=%v", err)
	}
}

func TestCompositePaginationDrainsMoreThanOneRelayPage(t *testing.T) {
	directory := t.TempDir()
	now := time.Unix(1_900_000_000, 0)
	writePage := func(name string, first int) string {
		t.Helper()
		events := make([]buzzEvent, maxEventsPerPage)
		for index := range events {
			events[index] = buzzEvent{ID: fmt.Sprintf("%064x", first+index), PublicKey: testAuthor, Kind: 9,
				Content: "queued", CreatedAt: now.Unix(), Tags: [][]string{{"h", testChannel}, {"p", testAgent}}}
		}
		raw, err := json.Marshal(events)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	older := writePage("older.json", 1)
	newer := writePage("newer.json", maxEventsPerPage+1)
	oldestNewerID := fmt.Sprintf("%064x", maxEventsPerPage+1)
	oldestOlderID := fmt.Sprintf("%064x", 1)
	script := `#!/bin/sh
before_id=
while [ "$#" -gt 0 ]; do
  if [ "$1" = --before-id ]; then shift; before_id=$1; fi
  shift
done
case "$before_id" in
  "") cat '` + newer + `' ;;
  '` + oldestNewerID + `') cat '` + older + `' ;;
  '` + oldestOlderID + `') printf '[]\n' ;;
  *) exit 2 ;;
esac
`
	cfg := validTestConfig(directory)
	cfg.BuzzBinary = writeExecutable(t, directory, "buzz-paginated", script)
	if err := prepareStateDirectory(cfg.StateDirectory); err != nil {
		t.Fatal(err)
	}
	b := &bridge{cfg: cfg, logger: slog.Default(), buzzKey: "nsec-fixture", now: func() time.Time { return now }}
	if err := b.poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	queued, _, err := b.recordCounts()
	if err != nil || queued != 2*maxEventsPerPage {
		t.Fatalf("queued=%d error=%v", queued, err)
	}
	if !fileExists(filepath.Join(cfg.StateDirectory, "cursors", testChannel+".json")) {
		t.Fatal("cursor did not advance after every relay page was durably accepted")
	}
}

func TestAmbiguousPublishReconcilesWithoutDuplicateSend(t *testing.T) {
	directory := t.TempDir()
	now := time.Unix(1_900_000_000, 0)
	allow := filepath.Join(directory, "allow-thread")
	sends := filepath.Join(directory, "send-count")
	buzz := writeExecutable(t, directory, "buzz-ambiguous", `#!/bin/sh
case " $* " in
  *" messages thread "*)
    if [ -f '`+allow+`' ]; then
      printf '[{"id":"`+testReply+`","pubkey":"`+testAgent+`","kind":9,"content":"answer","created_at":1900000001,"tags":[["h","`+testChannel+`"],["e","`+testEvent+`","","reply"]]}]\n'
    else printf '[]\n'; fi ;;
  *" messages send "*)
    count=0; [ ! -f '`+sends+`' ] || count=$(cat '`+sends+`'); count=$((count + 1)); printf '%s' "$count" >'`+sends+`'
    cat >/dev/null; printf '{"event_id":"`+testReply+`"}\n' ;;
  *) exit 2 ;;
esac
`)
	cfg := validTestConfig(directory)
	cfg.BuzzBinary = buzz
	if err := prepareStateDirectory(cfg.StateDirectory); err != nil {
		t.Fatal(err)
	}
	b := &bridge{cfg: cfg, logger: slog.Default(), buzzKey: "nsec-fixture", now: func() time.Time { return now }}
	if err := b.ingest(testChannel, validEvent(now)); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(cfg.StateDirectory, "records", testEvent+".json")
	rec, err := readRecord(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(rec.RunDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rec.RunDirectory, "result.json"), []byte(`{"status":"completed","output":"answer"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	rec.Phase = "publishing"
	rec.ReplyDigest = sha256Digest([]byte("answer"))
	if err := writeRecord(path, rec); err != nil {
		t.Fatal(err)
	}
	if worked, err := b.processNext(context.Background()); !worked || err == nil || !strings.Contains(err.Error(), "publish_outcome_unknown") {
		t.Fatalf("first publish worked=%v error=%v", worked, err)
	}
	rec, err = readRecord(path)
	if err != nil || rec.Phase != "publish_outcome_unknown" || rec.ErrorCode != "publish_outcome_unknown" {
		t.Fatalf("ambiguous record=%+v error=%v", rec, err)
	}
	var listed bytes.Buffer
	if err := b.writeRecordList(&listed); err != nil || !strings.Contains(listed.String(), testEvent) ||
		strings.Contains(listed.String(), "answer") {
		t.Fatalf("record list=%q error=%v", listed.String(), err)
	}
	if err := os.WriteFile(allow, []byte("ready"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := b.retryDurableRecord(testEvent); err != nil {
		t.Fatal(err)
	}
	if worked, err := b.processNext(context.Background()); !worked || err != nil {
		t.Fatalf("reconcile worked=%v error=%v", worked, err)
	}
	count, err := os.ReadFile(sends)
	if err != nil || string(count) != "1" {
		t.Fatalf("send count=%q error=%v", count, err)
	}
	rec, err = readRecord(path)
	if err != nil || rec.Phase != "replied" || rec.ReplyEventID != testReply {
		t.Fatalf("reconciled record=%+v error=%v", rec, err)
	}
}

func TestIndependentWorkersDoNotHeadOfLineBlock(t *testing.T) {
	directory := t.TempDir()
	now := time.Unix(1_900_000_000, 0)
	started := filepath.Join(directory, "started")
	if err := os.Mkdir(started, 0o700); err != nil {
		t.Fatal(err)
	}
	stewardctl := writeExecutable(t, directory, "stewardctl-concurrent", `#!/bin/sh
run=
while [ "$#" -gt 0 ]; do
  if [ "$1" = -run-dir ]; then shift; run=$1; fi
  shift
done
[ -n "$run" ] || exit 2
mkdir -m 700 "$run"
touch '`+started+`'/"$(basename "$run")"
for unused in 1 2 3 4 5 6 7 8 9 10; do
  [ "$(find '`+started+`' -type f | wc -l | tr -d ' ')" -ge 2 ] && break
  sleep 0.1
done
[ "$(find '`+started+`' -type f | wc -l | tr -d ' ')" -ge 2 ] || exit 7
printf '{"status":"completed","output":"answer"}\n' >"$run/result.json"
chmod 600 "$run/result.json"
printf '{}\n'
`)
	buzz := writeExecutable(t, directory, "buzz-concurrent", `#!/bin/sh
event=
while [ "$#" -gt 0 ]; do
  if [ "$1" = --event ]; then shift; event=$1; fi
  shift
done
[ -n "$event" ] || exit 2
printf '[{"id":"`+testReply+`","pubkey":"`+testAgent+`","kind":9,"content":"answer","created_at":1900000001,"tags":[["h","`+testChannel+`"],["e","%s","","reply"]]}]\n' "$event"
`)
	cfg := validTestConfig(directory)
	cfg.StewardctlBinary, cfg.BuzzBinary = stewardctl, buzz
	if err := prepareStateDirectory(cfg.StateDirectory); err != nil {
		t.Fatal(err)
	}
	b := &bridge{cfg: cfg, logger: slog.Default(), buzzKey: "nsec-fixture", now: func() time.Time { return now }}
	first := validEvent(now)
	second := validEvent(now)
	second.ID = strings.Repeat("e", 64)
	for _, event := range []buzzEvent{first, second} {
		if err := b.ingest(testChannel, event); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	errorsChannel := make(chan error, 2)
	for worker := 0; worker < 2; worker++ {
		go func() {
			worked, err := b.processNext(ctx)
			if !worked && err == nil {
				err = errors.New("worker found no durable work")
			}
			errorsChannel <- err
		}()
	}
	for worker := 0; worker < 2; worker++ {
		if err := <-errorsChannel; err != nil {
			t.Fatal(err)
		}
	}
	queued, failed, err := b.recordCounts()
	if err != nil || queued != 0 || failed != 0 {
		t.Fatalf("queued=%d failed=%d error=%v", queued, failed, err)
	}
}

func TestCommandFailureTaxonomyAndRedaction(t *testing.T) {
	tests := []struct {
		name      string
		binary    string
		exitCode  int
		wantCode  string
		retryable bool
	}{
		{name: "invalid Buzz request", binary: "buzz", exitCode: 1, wantCode: "buzz_request_invalid"},
		{name: "relay unavailable", binary: "steward-buzz", exitCode: 2, wantCode: "buzz_relay_unavailable", retryable: true},
		{name: "authentication rejected", binary: "buzz-cli", exitCode: 3, wantCode: "buzz_authentication_failed"},
		{name: "external Buzz failure", binary: "buzz", exitCode: 4, wantCode: "buzz_external_failure", retryable: true},
		{name: "Buzz conflict", binary: "buzz", exitCode: 5, wantCode: "buzz_conflict", retryable: true},
		{name: "unknown Buzz failure", binary: "buzz", exitCode: 9, wantCode: "buzz_command_failed", retryable: true},
		{name: "Steward task failure", binary: "stewardctl", exitCode: 7, wantCode: "steward_task_command_failed", retryable: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := classifyCommandFailure(test.binary, test.exitCode, "token=secret")
			var failure *commandFailure
			if !errors.As(err, &failure) || failure.code != test.wantCode || failure.retryable != test.retryable {
				t.Fatalf("failure=%+v error=%v", failure, err)
			}
			redacted := redactCommandSecrets(err, "secret")
			if strings.Contains(redacted.Error(), "secret") || !strings.Contains(redacted.Error(), "[redacted]") {
				t.Fatalf("redacted error=%q", redacted)
			}
		})
	}

	detail := safeCommandDetail([]byte("line one\nline\ttwo\x00" + strings.Repeat("x", 600)))
	if strings.ContainsAny(detail, "\n\t\x00") || len(detail) != 512 {
		t.Fatalf("unsafe bounded command detail length=%d value=%q", len(detail), detail)
	}
	ordinary := errors.New("ordinary failure")
	if redactCommandSecrets(ordinary, "ordinary") != ordinary {
		t.Fatal("redaction replaced a non-command error")
	}
	cause := errors.New("underlying failure")
	wrapped := &bridgeFailure{code: "bridge_failed", retryable: true, cause: cause}
	if !errors.Is(wrapped, cause) || publicFailureCode(wrapped) != "bridge_failed" {
		t.Fatalf("bridge failure did not preserve its cause: %v", wrapped)
	}
	withoutDetail := (&commandFailure{binary: "buzz", exitCode: 2, code: "relay_unavailable"}).Error()
	if strings.HasSuffix(withoutDetail, ": ") {
		t.Fatalf("empty command detail was rendered: %q", withoutDetail)
	}
}

func TestRecordFailureBackoffAndDeadLetterPolicy(t *testing.T) {
	now := time.Unix(1_900_000_000, 0).UTC()
	b := &bridge{now: func() time.Time { return now }}
	if recordReady(record{NextAttemptAt: now.Add(time.Second).Format(time.RFC3339Nano)}, now) ||
		recordReady(record{NextAttemptAt: "invalid"}, now) {
		t.Fatal("future or malformed retry time was ready")
	}

	retryable := record{Phase: "pending"}
	b.recordFailure(&retryable, &bridgeFailure{code: "relay_unavailable", retryable: true, cause: errors.New("offline")})
	if retryable.Attempts != 1 || retryable.ErrorCode != "relay_unavailable" || !retryable.Retryable ||
		retryable.NextAttemptAt != now.Add(5*time.Second).Format(time.RFC3339Nano) || retryable.Phase != "pending" {
		t.Fatalf("first retry=%+v", retryable)
	}
	retryable.Attempts = 8
	b.recordFailure(&retryable, &commandFailure{code: "buzz_relay_unavailable", retryable: true})
	if retryable.Attempts != 9 || retryable.NextAttemptAt != now.Add(5*time.Minute).Format(time.RFC3339Nano) {
		t.Fatalf("capped retry=%+v", retryable)
	}
	b.recordFailure(&retryable, errors.New("last attempt"))
	if retryable.Phase != "dead_letter" || retryable.ResumePhase != "pending" || retryable.NextAttemptAt != "" {
		t.Fatalf("exhausted retry=%+v", retryable)
	}

	permanent := record{Phase: "dispatched"}
	b.recordFailure(&permanent, &bridgeFailure{code: "invalid_reply", retryable: false, cause: errors.New("bad result")})
	if permanent.Phase != "dead_letter" || permanent.ResumePhase != "dispatched" || permanent.ErrorCode != "invalid_reply" {
		t.Fatalf("permanent failure=%+v", permanent)
	}
	clearRecordFailure(&permanent)
	if permanent.LastError != "" || permanent.ErrorCode != "" || permanent.Retryable || permanent.NextAttemptAt != "" {
		t.Fatalf("cleared failure=%+v", permanent)
	}
}

func TestReadRecordRejectsIncompleteDurableTransitions(t *testing.T) {
	directory := t.TempDir()
	cfg := validTestConfig(directory)
	if err := prepareStateDirectory(cfg.StateDirectory); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_900_000_000, 0).UTC()
	b := &bridge{cfg: cfg, logger: slog.Default(), now: func() time.Time { return now }}
	if err := b.ingest(testChannel, validEvent(now)); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(cfg.StateDirectory, "records", testEvent+".json")
	base, err := readRecord(path)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		want string
		edit func(*record)
	}{
		{name: "unknown phase", want: "invalid phase", edit: func(rec *record) { rec.Phase = "unknown" }},
		{name: "unknown resume phase", want: "invalid resume phase", edit: func(rec *record) { rec.ResumePhase = "replied" }},
		{name: "malformed retry time", want: "invalid retry time", edit: func(rec *record) { rec.NextAttemptAt = "tomorrow" }},
		{name: "publishing without reply digest", want: "incomplete phase transition", edit: func(rec *record) { rec.Phase = "publishing" }},
		{name: "dead letter without resume phase", want: "incomplete phase transition", edit: func(rec *record) { rec.Phase = "dead_letter" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := base
			test.edit(&candidate)
			raw, err := json.Marshal(candidate)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := readRecord(path); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("record error=%v", err)
			}
		})
	}
}

func (b *bridge) BuzzBinaryEnvironmentForTest(t *testing.T, event, reply string) {
	t.Helper()
	original := b.cfg.BuzzBinary
	wrapper := filepath.Join(filepath.Dir(original), "buzz-wrapper")
	script := fmt.Sprintf("#!/bin/sh\nexport STEWARD_TEST_EVENT='%s'\nexport STEWARD_TEST_REPLY='%s'\nexec '%s' \"$@\"\n",
		strings.ReplaceAll(event, "'", "'\\''"), reply, original)
	if err := os.WriteFile(wrapper, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	b.cfg.BuzzBinary = wrapper
}

func validTestConfig(directory string) config {
	return config{
		SchemaVersion: configSchema, IntegrationID: "buzz-a", TenantID: "tenant-a", Deployment: "researcher",
		RelayURL: "https://buzz.example", AgentPublicKey: testAgent, AllowedAuthors: []string{testAuthor},
		Channels: []string{testChannel}, BuzzPrivateKeyFile: filepath.Join(directory, "buzz.key"),
		StateDirectory: filepath.Join(directory, "state"), BuzzBinary: filepath.Join(directory, "buzz"),
		StewardctlBinary: filepath.Join(directory, "stewardctl"), ControlURL: "https://control.example",
		ControlTokenFile: filepath.Join(directory, "control.token"), GatewayURL: "http://127.0.0.1:18091",
		GatewayTokenFile: filepath.Join(directory, "gateway.token"), ServiceTrustFile: filepath.Join(directory, "trust.json"),
		TaskKeyFile: filepath.Join(directory, "task.pem"), TaskKeyID: "buzz-task", HTTPListen: "127.0.0.1:19082",
	}
}

func validEvent(now time.Time) buzzEvent {
	return buzzEvent{ID: testEvent, PublicKey: testAuthor, Kind: 9, Content: "hello", CreatedAt: now.Unix(),
		Tags: [][]string{{"h", testChannel}, {"p", testAgent}}}
}

func cloneTags(tags [][]string) [][]string {
	result := make([][]string, len(tags))
	for index := range tags {
		result[index] = append([]string(nil), tags[index]...)
	}
	return result
}

func writeExecutable(t *testing.T, directory, name, content string) string {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, []byte(content), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}
