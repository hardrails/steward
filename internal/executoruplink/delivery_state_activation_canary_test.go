package executoruplink

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/dsse"
)

func TestDeliveryStorePersistsAndDeepClonesActivationCanaryProjection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "deliveries.json")
	store := newDeliveryStore(t, path)
	delivery := deliveryFixtureV4("activation-canary-v4", 1)
	if decision, terminal, err := store.AcceptV4(delivery, "tenant-a", 7, "activation-canary"); err != nil ||
		decision != deliveryExecute || terminal != nil {
		t.Fatalf("accept activation canary: decision=%v terminal=%+v err=%v", decision, terminal, err)
	}
	if err := store.MarkExecuting(delivery.DeliveryID); err != nil {
		t.Fatal(err)
	}
	projection := deliveryCanaryResultFixture()
	report := controlprotocol.ExecutorReportV4{
		ProtocolVersion: controlprotocol.ExecutorProtocolV4,
		DeliveryID:      delivery.DeliveryID, DeliveryGeneration: delivery.DeliveryGeneration,
		CommandID: delivery.CommandID, CommandDigest: delivery.CommandDigest,
		Status: controlprotocol.ExecutorStatusDone, ReportedStatus: "running",
		ClaimGeneration: 7,
		Result: controlprotocol.ExecutorReportResultV4{
			RuntimeRef:       "executor-" + strings.Repeat("a", 64),
			ActivationCanary: &projection,
		},
	}
	if err := store.MarkTerminalV4(report); err != nil {
		t.Fatal(err)
	}

	reloaded, err := LoadDeliveryStore(path, "node-1")
	if err != nil {
		t.Fatal(err)
	}
	reports, more, err := reloaded.UnacknowledgedReportsV4(1)
	if err != nil || more || len(reports) != 1 ||
		!reflect.DeepEqual(reports[0].Result.ActivationCanary, &projection) {
		t.Fatalf("recovered activation canary reports=%+v more=%v err=%v", reports, more, err)
	}
	reports[0].Result.ActivationCanary.ActivationID = "mutated"
	reports, _, err = reloaded.UnacknowledgedReportsV4(1)
	if err != nil || len(reports) != 1 ||
		!reflect.DeepEqual(reports[0].Result.ActivationCanary, &projection) {
		t.Fatalf("returned canary aliases delivery state: reports=%+v err=%v", reports, err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"activation_canary":{"schema_version":"steward.activation-canary-result.v1"`) {
		t.Fatalf("durable delivery state omitted typed canary projection: %s", raw)
	}
}

func deliveryCanaryResultFixture() controlprotocol.ExecutorActivationCanaryResultV1 {
	terminal := []byte(`{"ok":true}`)
	receipts := []byte("authorize\nterminal\nexport\n")
	return controlprotocol.ExecutorActivationCanaryResultV1{
		SchemaVersion:        controlprotocol.ExecutorActivationCanaryResultSchemaV1,
		ActivationID:         "activation-1",
		AdmissionDigest:      "sha256:" + strings.Repeat("1", 64),
		TaskDigest:           "sha256:" + strings.Repeat("2", 64),
		PermitDigest:         "sha256:" + strings.Repeat("3", 64),
		RunID:                "run_" + strings.Repeat("4", 32),
		TerminalResultDigest: dsse.Digest(terminal), TerminalResultBytes: int64(len(terminal)),
		TerminalResultBase64:       base64.StdEncoding.EncodeToString(terminal),
		GatewayEvidenceBase64:      base64.StdEncoding.EncodeToString(receipts),
		ActivationCheckpointDigest: "sha256:" + strings.Repeat("5", 64),
		Qualified:                  true,
	}
}
