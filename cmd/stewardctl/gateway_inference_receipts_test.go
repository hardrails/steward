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
		reject bool
	}{
		{[]string{"-require-attempt-receipts"}, true, false},
		{nil, true, false},
		{[]string{"-require-attempt-receipts=false"}, true, true},
		{[]string{"-disallow-attempt-receipts=false"}, true, true},
		{[]string{"-require-attempt-receipts", "-disallow-attempt-receipts"}, true, true},
		{[]string{"-require-attempt-receipts=false", "-disallow-attempt-receipts"}, true, true},
		{[]string{"-require-attempt-receipts", "-disallow-attempt-receipts=false"}, true, true},
		{[]string{"-disallow-attempt-receipts"}, false, false},
		{nil, false, false},
		{[]string{"-require-attempt-receipts=false"}, false, true},
		{[]string{"-require-attempt-receipts"}, true, false},
		{nil, true, false},
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
		if err != nil || len(loaded.Routes) != 1 || loaded.Routes[0].RequireAttemptReceipts != test.want {
			t.Fatalf("flags=%v routes=%+v err=%v", test.flags, loaded.Routes, err)
		}
	}
	config.ConnectorReceiptTenantBudgets = nil
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
