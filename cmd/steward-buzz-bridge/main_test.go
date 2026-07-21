package main

import (
	"context"
	"fmt"
	"log/slog"
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
		"author is not canonical": func(value *config) { value.AllowedAuthors = []string{strings.ToUpper(testAuthor)} },
		"agent author is allowed": func(value *config) { value.AllowedAuthors = []string{testAgent} },
		"relay has userinfo":      func(value *config) { value.RelayURL = "https://user@buzz.example" },
		"remote gateway":          func(value *config) { value.GatewayURL = "https://node.example" },
		"relative secret":         func(value *config) { value.TaskKeyFile = "task.pem" },
		"duplicate channel":       func(value *config) { value.Channels = []string{testChannel, testChannel} },
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

func TestEligibilityRequiresExactCryptographicMentionShape(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	b := &bridge{cfg: validTestConfig(t.TempDir()), now: func() time.Time { return now }}
	event := validEvent(now)
	if eligible, err := b.eligible(testChannel, event); err != nil || !eligible {
		t.Fatalf("valid event eligible=%v error=%v", eligible, err)
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
			if eligible, _ := b.eligible(testChannel, candidate); eligible {
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
	b := &bridge{cfg: cfg, logger: slog.Default(), buzzKey: "nsec-fixture", now: func() time.Time { return now }}
	// The production child receives a minimal environment. Add fixture-only
	// values by wrapping binaries because arbitrary parent env is intentionally absent.
	b.BuzzBinaryEnvironmentForTest(t, eventJSON, replyCapture)
	if err := b.poll(context.Background()); err != nil {
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
	if err := b.poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if content, _ := os.ReadFile(replyCapture); string(content) != "useful answer" {
		t.Fatalf("second poll changed reply: %q", content)
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
