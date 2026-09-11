package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/hardrails/steward/internal/gateway"
)

func TestInferenceReconfigurationPreservesAccountingUnlessExplicitlyDisabled(t *testing.T) {
	directory, err := os.MkdirTemp("/tmp", "sgia-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	token := filepath.Join(directory, "service.token")
	if err := os.WriteFile(token, []byte("test-service-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	privateKey, publicKey := filepath.Join(directory, "private.pem"), filepath.Join(directory, "public.key")
	if err := run([]string{"keygen", "-private-out", privateKey, "-public-out", publicKey}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	group := os.Getgid()
	if group == 0 {
		group = 1
	}
	config := gateway.Config{
		Version: 1, ControlSocket: filepath.Join(directory, "control.sock"), ServiceAddress: "127.0.0.1:8091",
		ServiceTokenFile: token, StateFile: filepath.Join(directory, "state.json"), GrantRoot: filepath.Join(directory, "grants"),
		ExecutorGID: group, RelayGID: group, ConnectorReceiptFile: filepath.Join(directory, "receipts.ndjson"),
		ConnectorReceiptKeyFile: privateKey, ConnectorReceiptNodeID: "node/gateway", ConnectorReceiptEpoch: 1,
		ConnectorReceiptTenantBudgets: []gateway.ConnectorReceiptTenantBudget{{TenantID: "tenant", Bytes: 4 << 20}},
	}
	path := filepath.Join(directory, "gateway.json")
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		flags  []string
		want   bool
		scope  bool
		reject bool
	}{
		{[]string{"-require-attempt-receipts", "-require-task-scope"}, true, true, false},
		{nil, true, true, false},
		{[]string{"-disallow-attempt-receipts"}, true, true, true},
		{[]string{"-require-task-scope=false"}, true, true, true},
		{[]string{"-disallow-task-scope=false"}, true, true, true},
		{[]string{"-require-task-scope", "-disallow-task-scope"}, true, true, true},
		{[]string{"-require-task-scope=false", "-disallow-task-scope"}, true, true, true},
		{[]string{"-require-task-scope", "-disallow-task-scope=false"}, true, true, true},
		{[]string{"-disallow-task-scope"}, true, false, false},
		{nil, true, false, false},
		{[]string{"-require-attempt-receipts=false"}, true, false, true},
		{[]string{"-disallow-attempt-receipts=false"}, true, false, true},
		{[]string{"-require-attempt-receipts", "-disallow-attempt-receipts"}, true, false, true},
		{[]string{"-require-attempt-receipts=false", "-disallow-attempt-receipts"}, true, false, true},
		{[]string{"-require-attempt-receipts", "-disallow-attempt-receipts=false"}, true, false, true},
		{[]string{"-disallow-attempt-receipts"}, false, false, false},
		{nil, false, false, false},
		{[]string{"-require-attempt-receipts=false"}, false, false, true},
		{[]string{"-require-attempt-receipts"}, true, false, false},
		{nil, true, false, false},
		{[]string{"-disallow-attempt-receipts"}, false, false, false},
	} {
		before, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		arguments := append([]string{"gateway", "inference", "set", "-config", path, "-provider", "vllm"}, test.flags...)
		err = run(arguments, &bytes.Buffer{}, &bytes.Buffer{})
		if (err != nil) != test.reject {
			t.Fatalf("flags=%v rejected=%v err=%v", test.flags, test.reject, err)
		}
		if test.reject {
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatalf("rejected flags %v changed configuration", test.flags)
			}
		}
		loaded, _, _, _, err := gateway.LoadConfig(path)
		if err != nil || len(loaded.Routes) != 1 || loaded.Routes[0].RequireAttemptReceipts != test.want || loaded.Routes[0].RequireTaskScope != test.scope {
			t.Fatalf("flags=%v routes=%+v err=%v", test.flags, loaded.Routes, err)
		}
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"gateway", "inference", "set", "-config", path, "-provider", "vllm", "-require-task-scope"}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("task scope without attempt accounting was accepted")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("invalid task scope replaced the original configuration")
	}
	for _, test := range []struct {
		flags   []string
		maximum int
		reject  bool
	}{
		{[]string{"-max-calls-per-grant", "2"}, 0, true},
		{[]string{"-require-attempt-receipts", "-max-calls-per-grant", "2"}, 2, false},
		{nil, 2, false},
		{[]string{"-max-calls-per-grant", "0"}, 2, true},
		{[]string{"-max-calls-per-grant", "-1"}, 2, true},
		{[]string{"-max-calls-per-grant", "1000001"}, 2, true},
		{[]string{"-disallow-attempt-receipts"}, 2, true},
		{[]string{"-disallow-call-limit=false"}, 2, true},
		{[]string{"-disallow-call-limit", "-max-calls-per-grant", "3"}, 2, true},
		{[]string{"-disallow-call-limit=false", "-max-calls-per-grant", "3"}, 2, true},
		{[]string{"-max-calls-per-grant", "3"}, 3, false},
		{nil, 3, false},
		{[]string{"-disallow-call-limit"}, 0, false},
		{nil, 0, false},
	} {
		before, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		arguments := append([]string{"gateway", "inference", "set", "-config", path, "-provider", "vllm"}, test.flags...)
		err = run(arguments, &bytes.Buffer{}, &bytes.Buffer{})
		if (err != nil) != test.reject {
			t.Fatalf("flags=%v rejected=%v err=%v", test.flags, test.reject, err)
		}
		if test.reject {
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatalf("rejected flags %v changed configuration", test.flags)
			}
		}
		loaded, _, _, _, err := gateway.LoadConfig(path)
		if err != nil || len(loaded.Routes) != 1 || loaded.Routes[0].MaxCallsPerGrant != test.maximum {
			t.Fatalf("flags=%v routes=%+v err=%v", test.flags, loaded.Routes, err)
		}
	}
	config.ConnectorReceiptTenantBudgets = nil
	for _, test := range []struct {
		flags   []string
		profile string
		reject  bool
	}{
		{[]string{"-request-profile", "openai-text-chat.v1", "-upstream-model", "pinned-model", "-max-tokens-cap", "64", "-max-calls-per-grant", "3"}, "openai-text-chat.v1", false},
		{nil, "openai-text-chat.v1", false},
		{[]string{"-disallow-call-limit"}, "openai-text-chat.v1", true},
		{[]string{"-max-tokens-cap", "0"}, "openai-text-chat.v1", true},
		{[]string{"-request-profile", ""}, "openai-text-chat.v1", true},
		{[]string{"-request-profile", "unknown"}, "openai-text-chat.v1", true},
		{[]string{"-disallow-request-profile=false"}, "openai-text-chat.v1", true},
		{[]string{"-request-profile", "openai-text-chat.v1", "-disallow-request-profile"}, "openai-text-chat.v1", true},
		{[]string{"-disallow-request-profile"}, "", false},
	} {
		before, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		arguments := append([]string{"gateway", "inference", "set", "-config", path, "-provider", "vllm"}, test.flags...)
		err = run(arguments, &bytes.Buffer{}, &bytes.Buffer{})
		if (err != nil) != test.reject {
			t.Fatalf("flags=%v err=%v", test.flags, err)
		}
		loaded, _, _, _, err := gateway.LoadConfig(path)
		if err != nil || loaded.Routes[0].RequestProfile != test.profile {
			t.Fatalf("flags=%v err=%v", test.flags, err)
		}
		if test.reject {
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("invalid profile changed configuration")
			}
		}
		if test.profile != "" && (loaded.Routes[0].MaxTokensCap != 64 || loaded.Routes[0].UpstreamModel != "pinned-model") {
			t.Fatal("rerun lost bound model or token ceiling")
		}
	}
	raw, err = json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"gateway", "inference", "set", "-config", path, "-provider", "vllm", "-require-attempt-receipts"}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("accounting enabled without a tenant receipt budget")
	}
	unchanged, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(raw, unchanged) {
		t.Fatal("failed accounting configuration changed the original file")
	}
}
