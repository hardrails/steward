package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/connectorledger"
	"github.com/hardrails/steward/internal/gateway"
)

func TestSecondGatewayCannotReplaceSocketOrOpenMutableState(t *testing.T) {
	directory, err := os.MkdirTemp("/tmp", "sglock-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	privatePath := filepath.Join(directory, "connector-receipts.private.pem")
	receiptPath := filepath.Join(directory, "connector-receipts.ndjson")
	private := writeGatewayTestPrivateKey(t, privatePath)
	receipts, err := connectorledger.Open(receiptPath, private, "node-test/gateway", 1)
	if err != nil {
		t.Fatal(err)
	}
	taskDigest, err := connectorledger.TaskDigest("gateway-lock-fixture")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := receipts.Append(connectorledger.Event{
		Phase: connectorledger.Deny, Outcome: connectorledger.Denied, TenantID: "tenant-a",
		RuntimeRef: "executor-" + strings.Repeat("a", 64), CapsuleDigest: gatewayLockDigest('b'),
		PolicyDigest: gatewayLockDigest('c'), RoutePolicyDigest: gatewayLockDigest('d'), Generation: 1,
		GrantID: "grant-" + strings.Repeat("e", 64), ConnectorID: "ticketing",
		OperationID: "create-ticket", TaskDigest: taskDigest, ErrorCode: "policy_denied",
	}); err != nil {
		t.Fatal(err)
	}
	if err := receipts.Close(); err != nil {
		t.Fatal(err)
	}

	tokenPath := filepath.Join(directory, "token")
	if err := os.WriteFile(tokenPath, []byte("service-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	config := gateway.Config{
		Version: 1, ControlSocket: filepath.Join(directory, "control.sock"), ServiceAddress: unusedLoopbackAddress(t),
		ServiceTokenFile: tokenPath, StateFile: filepath.Join(directory, "state.json"), GrantRoot: filepath.Join(directory, "grants"),
		ExecutorGID: os.Getgid(), RelayGID: os.Getgid(), EgressAuditFile: filepath.Join(directory, "egress.jsonl"),
		ConnectorReceiptFile: receiptPath, ConnectorReceiptKeyFile: privatePath,
		ConnectorReceiptNodeID: "node-test/gateway", ConnectorReceiptEpoch: 1,
	}
	if config.ExecutorGID == 0 {
		config.ExecutorGID, config.RelayGID = 1, 1
	}
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(directory, "gateway.json")
	if err := os.WriteFile(configPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var firstOut, firstErr synchronizedBuffer
	firstDone := make(chan int, 1)
	go func() { firstDone <- run(ctx, []string{"-config", configPath}, &firstOut, &firstErr) }()
	waitForGatewaySocket(t, config.ControlSocket, firstErr.String)

	socketBefore, err := os.Lstat(config.ControlSocket)
	if err != nil {
		t.Fatal(err)
	}
	ledgerBefore := readGatewayLockFile(t, receiptPath)
	stateBefore := readGatewayLockFile(t, config.StateFile)
	auditBefore := readGatewayLockFile(t, config.EgressAuditFile)

	var secondOut, secondErr bytes.Buffer
	if code := run(context.Background(), []string{"-config", configPath}, &secondOut, &secondErr); code != 2 ||
		!strings.Contains(secondErr.String(), "already running") {
		cancel()
		t.Fatalf("second gateway code=%d stdout=%q stderr=%q", code, secondOut.String(), secondErr.String())
	}
	alternate := config
	alternate.ControlSocket = filepath.Join(directory, "alternate-control.sock")
	alternate.ServiceAddress = unusedLoopbackAddress(t)
	alternateRaw, err := json.Marshal(alternate)
	if err != nil {
		t.Fatal(err)
	}
	alternatePath := filepath.Join(directory, "alternate-gateway.json")
	if err := os.WriteFile(alternatePath, alternateRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	secondOut.Reset()
	secondErr.Reset()
	if code := run(context.Background(), []string{"-config", alternatePath}, &secondOut, &secondErr); code != 2 ||
		!strings.Contains(secondErr.String(), "already running") {
		cancel()
		t.Fatalf("alternate gateway code=%d stdout=%q stderr=%q", code, secondOut.String(), secondErr.String())
	}
	if _, err := os.Lstat(alternate.ControlSocket); !errors.Is(err, os.ErrNotExist) {
		cancel()
		t.Fatalf("alternate Gateway touched its control socket before shared-resource exclusion: %v", err)
	}
	socketAfter, err := os.Lstat(config.ControlSocket)
	if err != nil {
		cancel()
		t.Fatalf("first control socket disappeared: %v", err)
	}
	if !os.SameFile(socketBefore, socketAfter) {
		cancel()
		t.Fatal("second Gateway replaced the first Gateway control socket")
	}
	if got := readGatewayLockFile(t, receiptPath); !bytes.Equal(got, ledgerBefore) {
		cancel()
		t.Fatal("second Gateway changed the connector receipt ledger")
	}
	if got := readGatewayLockFile(t, config.StateFile); !bytes.Equal(got, stateBefore) {
		cancel()
		t.Fatal("second Gateway changed retained Gateway state")
	}
	if got := readGatewayLockFile(t, config.EgressAuditFile); !bytes.Equal(got, auditBefore) {
		cancel()
		t.Fatal("second Gateway changed the egress audit log")
	}
	assertGatewayHealthy(t, config.ControlSocket)

	cancel()
	select {
	case code := <-firstDone:
		if code != 0 {
			t.Fatalf("first Gateway code=%d stderr=%s", code, firstErr.String())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("first Gateway did not stop")
	}
	nextLock, err := acquireGatewayLifetimeLock(config)
	if err != nil {
		t.Fatalf("Gateway lock remained held after process lifetime: %v", err)
	}
	if err := nextLock.Close(); err != nil {
		t.Fatal(err)
	}
}

func writeGatewayTestPrivateKey(t *testing.T, path string) ed25519.PrivateKey {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return private
}

func gatewayLockDigest(fill byte) string {
	return "sha256:" + strings.Repeat(string(fill), 64)
}

func waitForGatewaySocket(t *testing.T, path string, stderr func() string) {
	t.Helper()
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSocket != 0 {
			return
		}
	}
	t.Fatalf("Gateway control socket did not become ready: %s", stderr())
}

func readGatewayLockFile(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func assertGatewayHealthy(t *testing.T, socket string) {
	t.Helper()
	transport := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: time.Second}
	response, err := client.Get("http://gateway/v1/healthz")
	if err != nil {
		t.Fatalf("first Gateway is no longer reachable: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("first Gateway health status=%d", response.StatusCode)
	}
}
