package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/connectorledger"
	"github.com/hardrails/steward/internal/evidence"
	"github.com/hardrails/steward/internal/executoruplink"
	"github.com/hardrails/steward/internal/gateway"
	"github.com/hardrails/steward/internal/journal"
)

type upgradeFixture struct {
	directory        string
	fence            string
	journal          string
	evidence         string
	uplink           string
	supervisor       string
	gatewayConfig    string
	gatewayState     string
	gatewayGrantRoot string
	receiptLog       string
	receiptKey       string
	manifest         string
}

func newUpgradeFixture(t *testing.T) upgradeFixture {
	t.Helper()
	directory, err := os.MkdirTemp("/tmp", "steward-upgrade-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	fixture := upgradeFixture{
		directory: directory, fence: filepath.Join(directory, "fences.bin"), journal: filepath.Join(directory, "journal.bin"),
		evidence: filepath.Join(directory, "evidence.bin"), uplink: filepath.Join(directory, "uplink.json"),
		supervisor: filepath.Join(directory, "supervisor.json"), gatewayConfig: filepath.Join(directory, "gateway.json"),
		gatewayState: filepath.Join(directory, "gateway-state.json"), gatewayGrantRoot: filepath.Join(directory, "grants"),
		receiptLog: filepath.Join(directory, "connector-receipts.ndjson"), receiptKey: filepath.Join(directory, "connector-receipts.pem"),
		manifest: filepath.Join(directory, "release.json"),
	}
	if err := admission.InitializeFenceStore(fixture.fence); err != nil {
		t.Fatal(err)
	}
	operations, err := journal.Open(fixture.journal)
	if err != nil {
		t.Fatal(err)
	}
	if err := operations.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixture.evidence, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := executoruplink.InitializeStateStore(fixture.uplink); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixture.supervisor, []byte("{\"version\":1,\"instances\":[]}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	token := filepath.Join(directory, "gateway-token")
	if err := os.WriteFile(token, []byte("upgrade-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, receiptPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	receiptDER, err := x509.MarshalPKCS8PrivateKey(receiptPrivate)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixture.receiptKey, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: receiptDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	receipts, err := connectorledger.Open(fixture.receiptLog, receiptPrivate, "node-a/gateway", 1)
	if err != nil {
		t.Fatal(err)
	}
	taskDigest, err := connectorledger.TaskDigest("upgrade-format-task")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := receipts.Append(connectorledger.Event{
		Phase: connectorledger.Deny, Outcome: connectorledger.Denied, TenantID: "tenant-a",
		RuntimeRef: "executor-" + strings.Repeat("a", 64), CapsuleDigest: digest('b'), PolicyDigest: digest('c'),
		RoutePolicyDigest: digest('d'), Generation: 1, GrantID: "grant-" + strings.Repeat("e", 64),
		ConnectorID: "ticketing", OperationID: "create-ticket", TaskDigest: taskDigest, ErrorCode: "policy_denied",
	}); err != nil {
		t.Fatal(err)
	}
	if err := receipts.Close(); err != nil {
		t.Fatal(err)
	}
	executorGID := os.Getgid()
	if executorGID == 0 {
		executorGID = 1
	}
	config := gateway.Config{
		Version: 1, ControlSocket: filepath.Join(directory, "gateway.sock"), ServiceAddress: "127.0.0.1:8091",
		ServiceTokenFile: token, StateFile: fixture.gatewayState, GrantRoot: fixture.gatewayGrantRoot,
		ExecutorGID: executorGID, RelayGID: executorGID,
		ConnectorReceiptFile: fixture.receiptLog, ConnectorReceiptKeyFile: fixture.receiptKey,
		ConnectorReceiptNodeID: "node-a/gateway", ConnectorReceiptEpoch: 1,
	}
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixture.gatewayConfig, raw, 0o640); err != nil {
		t.Fatal(err)
	}
	writeUpgradeManifest(t, fixture.manifest, map[string]releaseFormatRange{
		"admission_fence":       {ReadMin: 1, ReadMax: 2, Write: 2},
		"connector_receipt_log": {ReadMin: 1, ReadMax: 1, Write: 1},
		"evidence_log":          {ReadMin: 1, ReadMax: 1, Write: 1},
		"gateway_state":         {ReadMin: 1, ReadMax: 3, Write: 3},
		"operation_journal":     {ReadMin: 1, ReadMax: 1, Write: 1},
		"supervisor_state":      {ReadMin: 1, ReadMax: 1, Write: 1},
		"uplink_state":          {ReadMin: 1, ReadMax: 2, Write: 2},
	})
	return fixture
}

func (fixture upgradeFixture) arguments(action, mode string) []string {
	return []string{
		"upgrade", action, "-signed-admission", mode,
		"-fence-file", fixture.fence, "-journal-file", fixture.journal, "-evidence-file", fixture.evidence,
		"-uplink-state-file", fixture.uplink, "-supervisor-state-file", fixture.supervisor,
		"-gateway-config", fixture.gatewayConfig, "-release-manifest", fixture.manifest,
	}
}

func writeUpgradeManifest(t *testing.T, path string, formats map[string]releaseFormatRange) {
	t.Helper()
	raw, err := json.Marshal(releaseManifest{
		Schema: "steward.release.v2", Version: "v9.9.9", OS: "linux", Architecture: "amd64",
		StateFormats: releaseStateFormats{
			AdmissionFence: formats["admission_fence"], ConnectorReceiptLog: formats["connector_receipt_log"],
			EvidenceLog: formats["evidence_log"], GatewayState: formats["gateway_state"],
			OperationJournal: formats["operation_journal"], SupervisorState: formats["supervisor_state"],
			UplinkState: formats["uplink_state"],
		},
		Files: json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestUpgradeCheckDrainedSnapshotIsReadOnly(t *testing.T) {
	fixture := newUpgradeFixture(t)
	paths := []string{
		fixture.fence, fixture.journal, fixture.evidence, fixture.uplink, fixture.supervisor,
		fixture.gatewayConfig, fixture.receiptLog, fixture.receiptKey, fixture.manifest,
	}
	before := make(map[string][]byte, len(paths))
	for _, path := range paths {
		before[path], _ = os.ReadFile(path)
	}
	var output bytes.Buffer
	if err := run(fixture.arguments("check-drained", "configured"), &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	want := "{\"signed_admission\":\"configured\",\"active_fences\":0,\"pending_operations\":0,\"retained_gateway_grants\":0,\"formats\":{\"admission_fence\":2,\"connector_receipt_log\":1,\"evidence_log\":null,\"gateway_state\":null,\"operation_journal\":null,\"supervisor_state\":1,\"uplink_state\":2},\"target_compatible\":true,\"drained\":true}\n"
	if output.String() != want {
		t.Fatalf("check-drained snapshot\n got: %s want: %s", output.String(), want)
	}
	if _, err := os.Lstat(fixture.gatewayState); !os.IsNotExist(err) {
		t.Fatalf("read-only check created Gateway state: %v", err)
	}
	if _, err := os.Lstat(fixture.gatewayGrantRoot); !os.IsNotExist(err) {
		t.Fatalf("read-only check created Gateway grant root: %v", err)
	}
	for _, path := range paths {
		after, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(before[path], after) {
			t.Fatalf("read-only check changed %s: err=%v", path, err)
		}
	}

	output.Reset()
	if err := run(fixture.arguments("inspect-formats", "configured"), &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	want = "{\"signed_admission\":\"configured\",\"formats\":{\"admission_fence\":2,\"connector_receipt_log\":1,\"evidence_log\":null,\"gateway_state\":null,\"operation_journal\":null,\"supervisor_state\":1,\"uplink_state\":2},\"target_compatible\":true}\n"
	if output.String() != want {
		t.Fatalf("inspect-formats snapshot\n got: %s want: %s", output.String(), want)
	}
}

func TestUpgradeCheckDrainedReportsAllLegacyFormats(t *testing.T) {
	fixture := newUpgradeFixture(t)
	legacyFence := []byte{'S', 'T', 'F', 'N', 1}
	legacyFence = binary.BigEndian.AppendUint64(legacyFence, 0)
	legacyFence = binary.BigEndian.AppendUint32(legacyFence, 0)
	if err := os.WriteFile(fixture.fence, legacyFence, 0o600); err != nil {
		t.Fatal(err)
	}
	operations, err := journal.Open(fixture.journal)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := operations.Prepare("terminal", "legacy-format", 1); err != nil {
		t.Fatal(err)
	}
	if err := operations.Commit("terminal"); err != nil {
		t.Fatal(err)
	}
	if err := operations.Close(); err != nil {
		t.Fatal(err)
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	log, err := evidence.Open(fixture.evidence, private, "node-a", 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(evidence.Event{
		Type: evidence.AdmissionAllow, TenantID: "tenant-a", RuntimeRef: "runtime-a",
		CapsuleDigest: digest('a'), PolicyDigest: digest('b'), Generation: 1,
		GrantID: "grant-a", Outcome: evidence.Allowed,
	}); err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixture.gatewayState, []byte(`{"version":1,"grants":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixture.uplink, []byte(`{"version":1,"positions":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := run(fixture.arguments("check-drained", "configured"), &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{
		`"admission_fence":1`, `"connector_receipt_log":1`, `"evidence_log":1`, `"gateway_state":1`,
		`"operation_journal":1`, `"supervisor_state":1`, `"uplink_state":1`,
	} {
		if !strings.Contains(output.String(), fragment) {
			t.Fatalf("legacy format snapshot missing %s: %s", fragment, output.String())
		}
	}
}

func TestUpgradeCheckDrainedBlocksLiveSemanticStateAndAllowsTombstones(t *testing.T) {
	fixture := newUpgradeFixture(t)
	store, err := admission.OpenFenceStore(fixture.fence)
	if err != nil {
		t.Fatal(err)
	}
	record := admission.FenceRecord{
		TenantID: "tenant-a", InstanceID: "instance-a", Generation: 1, CapsuleDigest: digest('a'),
		PolicyDigest: digest('b'), LineageID: "lineage-a", WorkloadDigest: digest('c'),
		ImageConfigDigest: digest('d'), Present: true,
	}
	if err := store.Commit(record, 1); err != nil {
		t.Fatal(err)
	}
	operations, err := journal.Open(fixture.journal)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := operations.Prepare("pending", "docker-create", 1); err != nil {
		t.Fatal(err)
	}
	if err := operations.Close(); err != nil {
		t.Fatal(err)
	}
	grantID := gateway.GrantID("tenant-a", "instance-a", 1)
	gatewayState := map[string]any{"version": 2, "grants": []map[string]any{{
		"grant_id": grantID, "tenant_id": "tenant-a", "instance_id": "instance-a", "generation": 1,
		"service": true, "active": false,
	}}}
	raw, _ := json.Marshal(gatewayState)
	if err := os.WriteFile(fixture.gatewayState, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	err = run(fixture.arguments("check-drained", "configured"), &output, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "destroy active signed workloads") ||
		!strings.Contains(err.Error(), "journal reconciliation") || !strings.Contains(err.Error(), "retained Gateway grants") {
		t.Fatalf("blocking action = %v", err)
	}
	if !strings.Contains(output.String(), `"active_fences":1`) || !strings.Contains(output.String(), `"pending_operations":1`) ||
		!strings.Contains(output.String(), `"retained_gateway_grants":1`) || !strings.Contains(output.String(), `"drained":false`) {
		t.Fatalf("blocking report = %s", output.String())
	}

	// A durable tombstone preserves anti-replay history but does not represent a
	// live workload and therefore is not itself a drain blocker.
	tombstoneFixture := newUpgradeFixture(t)
	tombstones, err := admission.OpenFenceStore(tombstoneFixture.fence)
	if err != nil {
		t.Fatal(err)
	}
	if err := tombstones.Commit(record, 1); err != nil {
		t.Fatal(err)
	}
	record.Generation = 2
	record.Present = false
	if err := tombstones.Commit(record, 2); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	if err := run(tombstoneFixture.arguments("check-drained", "configured"), &output, &bytes.Buffer{}); err != nil {
		t.Fatalf("tombstone blocked drain: %v", err)
	}
	if !strings.Contains(output.String(), `"active_fences":0`) || !strings.Contains(output.String(), `"drained":true`) {
		t.Fatalf("tombstone report = %s", output.String())
	}
}

func TestUpgradeCheckDrainedMissingAndAmbiguousStateFailsClosed(t *testing.T) {
	fixture := newUpgradeFixture(t)
	var output bytes.Buffer
	for _, arguments := range [][]string{
		{"upgrade"}, {"upgrade", "unknown"}, {"upgrade", "check-drained"},
		{"upgrade", "check-drained", "-signed-admission", "maybe"},
		append(fixture.arguments("check-drained", "configured"), "unexpected"),
	} {
		if err := run(arguments, &output, &bytes.Buffer{}); err == nil {
			t.Fatalf("ambiguous upgrade command accepted: %v", arguments)
		}
	}
	if err := os.Remove(fixture.fence); err != nil {
		t.Fatal(err)
	}
	if err := run(fixture.arguments("check-drained", "configured"), &output, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "restore and reconcile") {
		t.Fatalf("missing configured fence error = %v", err)
	}
	if _, err := os.Lstat(fixture.fence); !os.IsNotExist(err) {
		t.Fatalf("missing fence was created: %v", err)
	}
	for _, path := range []string{fixture.journal, fixture.evidence} {
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
	output.Reset()
	if err := run(fixture.arguments("check-drained", "unconfigured"), &output, &bytes.Buffer{}); err != nil {
		t.Fatalf("explicit unconfigured mode rejected absent admission state: %v", err)
	}
	if !strings.Contains(output.String(), `"admission_fence":null`) || !strings.Contains(output.String(), `"operation_journal":null`) {
		t.Fatalf("unconfigured report = %s", output.String())
	}
	if err := os.WriteFile(fixture.fence, []byte("malformed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run(fixture.arguments("check-drained", "unconfigured"), &output, &bytes.Buffer{}); err == nil {
		t.Fatal("unconfigured mode ignored existing malformed state")
	}
	if err := os.Remove(fixture.fence); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(fixture.gatewayConfig); err != nil {
		t.Fatal(err)
	}
	if err := run(fixture.arguments("check-drained", "unconfigured"), &output, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "Gateway configuration") {
		t.Fatalf("missing Gateway config error = %v", err)
	}
}

func TestUpgradeManifestCompatibilityBlocksUnreadableObservedVersion(t *testing.T) {
	fixture := newUpgradeFixture(t)
	writeUpgradeManifest(t, fixture.manifest, map[string]releaseFormatRange{
		"admission_fence":       {ReadMin: 1, ReadMax: 1, Write: 1},
		"connector_receipt_log": {ReadMin: 1, ReadMax: 1, Write: 1},
		"evidence_log":          {ReadMin: 1, ReadMax: 1, Write: 1},
		"gateway_state":         {ReadMin: 1, ReadMax: 3, Write: 3},
		"operation_journal":     {ReadMin: 1, ReadMax: 1, Write: 1},
		"supervisor_state":      {ReadMin: 1, ReadMax: 1, Write: 1},
		"uplink_state":          {ReadMin: 1, ReadMax: 2, Write: 2},
	})
	var output bytes.Buffer
	err := run(fixture.arguments("check-drained", "configured"), &output, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "admission_fence version 2") || !strings.Contains(err.Error(), "choose a compatible release") {
		t.Fatalf("compatibility error = %v", err)
	}
	if !strings.Contains(output.String(), `"target_compatible":false`) {
		t.Fatalf("compatibility report = %s", output.String())
	}

	writeUpgradeManifest(t, fixture.manifest, map[string]releaseFormatRange{
		"admission_fence":       {ReadMin: 1, ReadMax: 2, Write: 1},
		"connector_receipt_log": {ReadMin: 1, ReadMax: 1, Write: 1},
		"evidence_log":          {ReadMin: 1, ReadMax: 1, Write: 1},
		"gateway_state":         {ReadMin: 1, ReadMax: 3, Write: 3},
		"operation_journal":     {ReadMin: 1, ReadMax: 1, Write: 1},
		"supervisor_state":      {ReadMin: 1, ReadMax: 1, Write: 1},
		"uplink_state":          {ReadMin: 1, ReadMax: 2, Write: 2},
	})
	output.Reset()
	err = run(fixture.arguments("check-drained", "configured"), &output, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "would be rewritten by lower writer version 1") || !strings.Contains(err.Error(), "explicit state migration") {
		t.Fatalf("downward-writer compatibility error = %v", err)
	}
	if !strings.Contains(output.String(), `"target_compatible":false`) {
		t.Fatalf("downward-writer report = %s", output.String())
	}

	if err := os.WriteFile(fixture.manifest, []byte(`{"schema":"steward.release.v2","schema":"duplicate"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	if err := run(fixture.arguments("inspect-formats", "configured"), &output, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "decode target release manifest") {
		t.Fatalf("ambiguous manifest error = %v", err)
	}
}

func TestUpgradeManifestRequiresReceiptFormatAndPreservesGatewayV3(t *testing.T) {
	fixture := newUpgradeFixture(t)
	raw, err := os.ReadFile(fixture.manifest)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	formats, ok := document["state_formats"].(map[string]any)
	if !ok {
		t.Fatal("test manifest state_formats is not an object")
	}
	delete(formats, "connector_receipt_log")
	raw, err = json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixture.manifest, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	err = run(fixture.arguments("inspect-formats", "configured"), &output, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "invalid connector_receipt_log reader/writer range") {
		t.Fatalf("missing connector receipt format error = %v", err)
	}

	if err := os.WriteFile(fixture.gatewayState, []byte(`{"version":3,"grants":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	writeUpgradeManifest(t, fixture.manifest, map[string]releaseFormatRange{
		"admission_fence":       {ReadMin: 1, ReadMax: 2, Write: 2},
		"connector_receipt_log": {ReadMin: 1, ReadMax: 1, Write: 1},
		"evidence_log":          {ReadMin: 1, ReadMax: 1, Write: 1},
		"gateway_state":         {ReadMin: 1, ReadMax: 3, Write: 3},
		"operation_journal":     {ReadMin: 1, ReadMax: 1, Write: 1},
		"supervisor_state":      {ReadMin: 1, ReadMax: 1, Write: 1},
		"uplink_state":          {ReadMin: 1, ReadMax: 2, Write: 2},
	})
	output.Reset()
	if err := run(fixture.arguments("inspect-formats", "configured"), &output, &bytes.Buffer{}); err != nil {
		t.Fatalf("v3-compatible target rejected: %v", err)
	}
	if !strings.Contains(output.String(), `"gateway_state":3`) || !strings.Contains(output.String(), `"target_compatible":true`) {
		t.Fatalf("v3-compatible report = %s", output.String())
	}

	writeUpgradeManifest(t, fixture.manifest, map[string]releaseFormatRange{
		"admission_fence":       {ReadMin: 1, ReadMax: 2, Write: 2},
		"connector_receipt_log": {ReadMin: 1, ReadMax: 1, Write: 1},
		"evidence_log":          {ReadMin: 1, ReadMax: 1, Write: 1},
		"gateway_state":         {ReadMin: 1, ReadMax: 3, Write: 2},
		"operation_journal":     {ReadMin: 1, ReadMax: 1, Write: 1},
		"supervisor_state":      {ReadMin: 1, ReadMax: 1, Write: 1},
		"uplink_state":          {ReadMin: 1, ReadMax: 2, Write: 2},
	})
	output.Reset()
	err = run(fixture.arguments("inspect-formats", "configured"), &output, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "gateway_state version 3 would be rewritten by lower writer version 2") {
		t.Fatalf("v3 writer downgrade error = %v", err)
	}
	if !strings.Contains(output.String(), `"target_compatible":false`) {
		t.Fatalf("v3 writer downgrade report = %s", output.String())
	}
}
