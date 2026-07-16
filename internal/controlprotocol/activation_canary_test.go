package controlprotocol

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/hardrails/steward/internal/dsse"
)

func TestExecutorActivationCanaryResultV1ValidatesBoundedCanonicalProjection(t *testing.T) {
	valid := executorCanaryResultFixture()
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid activation canary result: %v", err)
	}

	tests := map[string]func(*ExecutorActivationCanaryResultV1){
		"schema":          func(value *ExecutorActivationCanaryResultV1) { value.SchemaVersion = "v2" },
		"activation":      func(value *ExecutorActivationCanaryResultV1) { value.ActivationID = "bad/id" },
		"run":             func(value *ExecutorActivationCanaryResultV1) { value.RunID = "run_ABC" },
		"terminal digest": func(value *ExecutorActivationCanaryResultV1) { value.TerminalResultDigest = digestFixture("9") },
		"terminal length": func(value *ExecutorActivationCanaryResultV1) { value.TerminalResultBytes++ },
		"terminal base64": func(value *ExecutorActivationCanaryResultV1) { value.TerminalResultBase64 += "\n" },
		"receipt base64":  func(value *ExecutorActivationCanaryResultV1) { value.GatewayEvidenceBase64 += "\n" },
		"receipt lines": func(value *ExecutorActivationCanaryResultV1) {
			value.GatewayEvidenceBase64 = base64.StdEncoding.EncodeToString([]byte("one\ntwo\n"))
		},
		"receipt carriage return": func(value *ExecutorActivationCanaryResultV1) {
			value.GatewayEvidenceBase64 = base64.StdEncoding.EncodeToString([]byte("one\r\ntwo\nthree\n"))
		},
		"unqualified": func(value *ExecutorActivationCanaryResultV1) { value.Qualified = false },
		"object limit": func(value *ExecutorActivationCanaryResultV1) {
			terminal := []byte(strings.Repeat("t", maxExecutorActivationCanaryTerminalBytes))
			value.TerminalResultBase64 = base64.StdEncoding.EncodeToString(terminal)
			value.TerminalResultBytes = int64(len(terminal))
			value.TerminalResultDigest = dsse.Digest(terminal)
			line := strings.Repeat("r", maxExecutorActivationCanaryEvidenceBytes/3-1) + "\n"
			receipts := []byte(line + line + line)
			value.GatewayEvidenceBase64 = base64.StdEncoding.EncodeToString(receipts)
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			mutate(&candidate)
			if err := candidate.Validate(); err == nil {
				t.Fatal("invalid activation canary result was accepted")
			}
		})
	}
}

func TestExecutorReportV4ActivationCanaryRequiresSuccessfulRunningRuntime(t *testing.T) {
	projection := executorCanaryResultFixture()
	valid := ExecutorReportV4{
		ProtocolVersion: ExecutorProtocolV4,
		DeliveryID:      "delivery-1", DeliveryGeneration: 1,
		CommandID: "command-1", CommandDigest: digestFixture("a"),
		Status: ExecutorStatusDone, ReportedStatus: "running", ClaimGeneration: 7,
		Result: ExecutorReportResultV4{
			RuntimeRef: "executor-" + strings.Repeat("b", 64), ActivationCanary: &projection,
		},
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid activation canary report: %v", err)
	}
	tests := map[string]func(*ExecutorReportV4){
		"terminal status": func(value *ExecutorReportV4) { value.Status = ExecutorStatusFailed },
		"runtime status":  func(value *ExecutorReportV4) { value.ReportedStatus = "passed" },
		"runtime missing": func(value *ExecutorReportV4) { value.Result.RuntimeRef = "" },
		"error code":      func(value *ExecutorReportV4) { value.ErrorCode = "failed" },
		"error":           func(value *ExecutorReportV4) { value.Result.Error = "failed" },
		"replayed":        func(value *ExecutorReportV4) { value.Result.Replayed = true },
		"absent":          func(value *ExecutorReportV4) { value.Result.Absent = true },
		"admission": func(value *ExecutorReportV4) {
			projection := ExecutorAdmissionProjectionV1{
				SchemaVersion: ExecutorAdmissionProjectionSchemaV1,
				RuntimeRef:    value.Result.RuntimeRef, Status: "running",
				CapsuleDigest: digestFixture("b"), PolicyDigest: digestFixture("c"),
				Generation: 1, EvidenceKeyID: strings.Repeat("d", 32),
			}
			value.Result.Admission = &projection
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			projectionCopy := projection
			candidate.Result.ActivationCanary = &projectionCopy
			mutate(&candidate)
			if err := candidate.Validate(); err == nil {
				t.Fatal("invalid activation canary report was accepted")
			}
		})
	}
}

func executorCanaryResultFixture() ExecutorActivationCanaryResultV1 {
	terminal := []byte(`{"schema_version":"steward.hermes-workspace-audit-result.v1"}`)
	receipts := []byte("authorize\nterminal\nexport\n")
	return ExecutorActivationCanaryResultV1{
		SchemaVersion:   ExecutorActivationCanaryResultSchemaV1,
		ActivationID:    "activation-1",
		AdmissionDigest: digestFixture("1"), TaskDigest: digestFixture("2"),
		PermitDigest: digestFixture("3"), RunID: "run_" + strings.Repeat("4", 32),
		TerminalResultDigest: dsse.Digest(terminal), TerminalResultBytes: int64(len(terminal)),
		TerminalResultBase64:       base64.StdEncoding.EncodeToString(terminal),
		GatewayEvidenceBase64:      base64.StdEncoding.EncodeToString(receipts),
		ActivationCheckpointDigest: digestFixture("5"), Qualified: true,
	}
}

func digestFixture(character string) string { return "sha256:" + strings.Repeat(character, 64) }
