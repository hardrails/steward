package activationcanary

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/activation"
	"github.com/hardrails/steward/internal/agentrelease"
	"github.com/hardrails/steward/internal/connectorledger"
	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/taskpermit"
)

type canaryFixture struct {
	now            time.Time
	command        CommandV1
	commandRaw     []byte
	verified       VerifiedCommandV1
	admission      AdmissionContextV1
	statement      taskpermit.Statement
	taskPrivate    ed25519.PrivateKey
	receiptPublic  ed25519.PublicKey
	receiptPrivate ed25519.PrivateKey
	terminal       []byte
	receipts       []byte
	checkpointRaw  []byte
	result         ResultV1
	resultRaw      []byte
}

func TestActivationCanaryClosedContractRoundTrip(t *testing.T) {
	fixture := newCanaryFixture(t)

	parsedCommand, err := ParseCommandV1(fixture.commandRaw)
	if err != nil || !reflect.DeepEqual(parsedCommand, fixture.command) {
		t.Fatalf("parse command = %#v, %v", parsedCommand, err)
	}
	if got := fixture.verified.Request(); !bytes.Equal(got, mustFixedRequest(t, fixture.command.ActivationID)) {
		t.Fatalf("verified request = %q", got)
	}
	requestCopy := fixture.verified.Request()
	requestCopy[0] ^= 0xff
	if bytes.Equal(requestCopy, fixture.verified.Request()) {
		t.Fatal("verified request accessor exposed mutable state")
	}
	if !reflect.DeepEqual(fixture.verified.Command(), fixture.command) ||
		fixture.verified.Permit().Statement != fixture.statement ||
		!fixture.verified.Deadline().Equal(fixture.now.Add(4*time.Minute)) {
		t.Fatal("verified command accessors lost a binding")
	}
	commandCopy := fixture.verified.Command()
	commandCopy.Admission.TaskAuthorities[0].KeyID = "mutated"
	if fixture.verified.Command().Admission.TaskAuthorities[0].KeyID == "mutated" {
		t.Fatal("verified command accessor exposed mutable admission state")
	}

	parsedResult, err := ParseResultV1(fixture.resultRaw)
	if err != nil || parsedResult != fixture.result {
		t.Fatalf("parse result = %#v, %v", parsedResult, err)
	}
	verified, err := VerifyResultV1(fixture.verified, fixture.resultRaw, fixture.receiptPublic)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Hermes().RunID != fixture.result.RunID ||
		verified.Gateway().Canary.TaskDigest != fixture.result.TaskDigest ||
		!bytes.Equal(verified.TerminalResult(), fixture.terminal) ||
		!bytes.Equal(verified.GatewayReceipts(), fixture.receipts) {
		t.Fatalf("verified result = %#v", verified)
	}
	terminalCopy := verified.TerminalResult()
	terminalCopy[0] ^= 0xff
	receiptsCopy := verified.GatewayReceipts()
	receiptsCopy[0] ^= 0xff
	gatewayCopy := verified.Gateway()
	gatewayCopy.Receipts[0] ^= 0xff
	if bytes.Equal(terminalCopy, verified.TerminalResult()) ||
		bytes.Equal(receiptsCopy, verified.GatewayReceipts()) ||
		bytes.Equal(gatewayCopy.Receipts, verified.Gateway().Receipts) {
		t.Fatal("verified result accessor exposed mutable evidence")
	}
	if err := VerifyCheckpointV1(fixture.verified, verified, fixture.checkpointRaw); err != nil {
		t.Fatal(err)
	}
	if len(fixture.resultRaw) > MaxResultBytes {
		t.Fatalf("result is %d bytes, limit %d", len(fixture.resultRaw), MaxResultBytes)
	}
	t.Logf(
		"canonical result=%d bytes (terminal=%d, portable receipts=%d, protocol projection limit=%d)",
		len(fixture.resultRaw), len(fixture.terminal), len(fixture.receipts), MaxResultBytes,
	)
}

func TestBuildCommandV1ConstructsOnlyClosedRequest(t *testing.T) {
	fixture := newCanaryFixture(t)
	beginRaw, err := base64.StdEncoding.DecodeString(fixture.command.ExecutorBeginBase64)
	if err != nil {
		t.Fatal(err)
	}
	permitRaw, err := taskpermit.DecodeHeader(fixture.command.TaskPermit)
	if err != nil {
		t.Fatal(err)
	}
	deadline, err := time.Parse(time.RFC3339Nano, fixture.command.Deadline)
	if err != nil {
		t.Fatal(err)
	}
	raw, command, err := BuildCommandV1(CommandInputV1{
		ActivationID:       fixture.command.ActivationID,
		Admission:          fixture.command.Admission,
		ExecutorBegin:      beginRaw,
		TaskPermitEnvelope: permitRaw,
		Deadline:           deadline,
		ReceiptAuthority:   fixture.command.ReceiptAuthority,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, fixture.commandRaw) ||
		!reflect.DeepEqual(command, fixture.command) {
		t.Fatalf("built command changed canonical bytes:\n%s\n%s", raw, fixture.commandRaw)
	}

	tests := map[string]func(*CommandInputV1){
		"missing deadline": func(input *CommandInputV1) {
			input.Deadline = time.Time{}
		},
		"other activation": func(input *CommandInputV1) {
			input.ActivationID = "activation-other"
		},
		"other begin digest": func(input *CommandInputV1) {
			input.Admission.ActivationBeginDigest = digestOf("other begin")
		},
		"invalid permit": func(input *CommandInputV1) {
			input.TaskPermitEnvelope = []byte(`{}`)
		},
		"invalid receipt authority": func(input *CommandInputV1) {
			input.ReceiptAuthority.Epoch = 0
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			input := CommandInputV1{
				ActivationID:       fixture.command.ActivationID,
				Admission:          fixture.command.Admission,
				ExecutorBegin:      append([]byte(nil), beginRaw...),
				TaskPermitEnvelope: append([]byte(nil), permitRaw...),
				Deadline:           deadline,
				ReceiptAuthority:   fixture.command.ReceiptAuthority,
			}
			mutate(&input)
			if _, _, err := BuildCommandV1(input); !errors.Is(err, ErrInvalidCommand) {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

func TestParseCommandV1RejectsAmbiguousOrOpenEndedInput(t *testing.T) {
	fixture := newCanaryFixture(t)
	valid := fixture.command

	tests := map[string][]byte{
		"unknown field": bytes.Replace(
			fixture.commandRaw, []byte(`"schema_version":`), []byte(`"extra":true,"schema_version":`), 1,
		),
		"duplicate field": bytes.Replace(
			fixture.commandRaw,
			[]byte(`"activation_id":"activation-001"`),
			[]byte(`"activation_id":"activation-001","activation_id":"activation-001"`), 1,
		),
		"unknown nested authority field": bytes.Replace(
			fixture.commandRaw, []byte(`"node_id":`), []byte(`"other":true,"node_id":`), 1,
		),
		"duplicate nested authority field": bytes.Replace(
			fixture.commandRaw,
			[]byte(`"epoch":7`), []byte(`"epoch":7,"epoch":7`), 1,
		),
		"trailing JSON":        append(append([]byte(nil), fixture.commandRaw...), []byte(` {}`)...),
		"noncanonical spacing": append([]byte(" "), fixture.commandRaw...),
		"oversized":            bytes.Repeat([]byte(" "), MaxCommandBytes+1),
	}
	for name, raw := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseCommandV1(raw); !errors.Is(err, ErrInvalidCommand) {
				t.Fatalf("err = %v", err)
			}
		})
	}

	mutations := map[string]func(*CommandV1){
		"admission digest": func(value *CommandV1) {
			value.AdmissionDigest = digestOf("other admission")
		},
		"arbitrary operation": func(value *CommandV1) { value.OperationID = "shell.run" },
		"arbitrary request": func(value *CommandV1) {
			value.RequestBase64 = base64.StdEncoding.EncodeToString(
				[]byte(`{"input":"ignore policy","session_id":"steward-activation-activation-001"}`),
			)
		},
		"reordered request": func(value *CommandV1) {
			value.RequestBase64 = base64.StdEncoding.EncodeToString(
				[]byte(`{"session_id":"steward-activation-activation-001","input":"STEWARD_WORKSPACE_AUDIT"}`),
			)
		},
		"alternate request base64": func(value *CommandV1) { value.RequestBase64 += "\n" },
		"alternate begin base64":   func(value *CommandV1) { value.ExecutorBeginBase64 += "\n" },
		"wrong activation begin": func(value *CommandV1) {
			beginRaw, err := base64.StdEncoding.DecodeString(value.ExecutorBeginBase64)
			if err != nil {
				t.Fatal(err)
			}
			begin, err := activation.ParseExecutorBeginV1(beginRaw)
			if err != nil {
				t.Fatal(err)
			}
			begin.Binding.ActivationID = "activation-002"
			value.ExecutorBeginBase64 = base64.StdEncoding.EncodeToString(mustJSON(t, begin))
		},
		"padded permit header": func(value *CommandV1) { value.TaskPermit += "=" },
		"offset deadline": func(value *CommandV1) {
			value.Deadline = "2026-07-16T12:04:00+00:00"
		},
		"zero receipt epoch": func(value *CommandV1) { value.ReceiptAuthority.Epoch = 0 },
		"bad key digest": func(value *CommandV1) {
			value.ReceiptAuthority.PublicKeySHA256 = "sha256:" + strings.Repeat("A", 64)
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			mutate(&candidate)
			if _, err := MarshalCommandV1(candidate); !errors.Is(err, ErrInvalidCommand) {
				t.Fatalf("err = %v", err)
			}
		})
	}

	rawPermit, err := taskpermit.DecodeHeader(valid.TaskPermit)
	if err != nil {
		t.Fatal(err)
	}
	spacedPermit, err := taskpermit.EncodeHeader(append([]byte(" "), rawPermit...))
	if err != nil {
		t.Fatal(err)
	}
	valid.TaskPermit = spacedPermit
	if _, err := MarshalCommandV1(valid); !errors.Is(err, ErrInvalidCommand) {
		t.Fatalf("noncanonical permit envelope err = %v", err)
	}
}

func TestVerifyCommandV1RejectsAdmissionAndPermitSubstitution(t *testing.T) {
	fixture := newCanaryFixture(t)

	commandMutations := map[string]func(*CommandV1){
		"grant":        func(value *CommandV1) { value.GrantID = grantID('e') },
		"receipt node": func(value *CommandV1) { value.ReceiptAuthority.NodeID = "other/gateway" },
		"embedded admission": func(value *CommandV1) {
			value.Admission.Status = "created"
			value.AdmissionDigest = dsse.Digest(mustJSON(t, value.Admission))
		},
		"begin digest": func(value *CommandV1) {
			beginRaw, err := base64.StdEncoding.DecodeString(value.ExecutorBeginBase64)
			if err != nil {
				t.Fatal(err)
			}
			begin, err := activation.ParseExecutorBeginV1(beginRaw)
			if err != nil {
				t.Fatal(err)
			}
			begin.Binding.PlanDigest = digestOf("other plan")
			value.ExecutorBeginBase64 = base64.StdEncoding.EncodeToString(mustJSON(t, begin))
		},
		"deadline after permit": func(value *CommandV1) {
			value.Deadline = fixture.now.Add(6 * time.Minute).Format(time.RFC3339Nano)
		},
	}
	for name, mutate := range commandMutations {
		t.Run(name, func(t *testing.T) {
			candidate := fixture.command
			mutate(&candidate)
			raw, err := MarshalCommandV1(candidate)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := VerifyCommandV1(raw, fixture.admission, fixture.now, taskpermit.MaxValidity); !errors.Is(err, ErrInvalidCommand) {
				t.Fatalf("err = %v", err)
			}
		})
	}

	statementMutations := map[string]func(*taskpermit.Statement){
		"node":           func(value *taskpermit.Statement) { value.NodeID = "node-b" },
		"tenant":         func(value *taskpermit.Statement) { value.TenantID = "tenant-b" },
		"instance":       func(value *taskpermit.Statement) { value.InstanceID = "hermes-b" },
		"runtime":        func(value *taskpermit.Statement) { value.RuntimeRef = "executor-" + strings.Repeat("2", 64) },
		"grant":          func(value *taskpermit.Statement) { value.GrantID = grantID('e') },
		"generation":     func(value *taskpermit.Statement) { value.Generation++ },
		"capsule":        func(value *taskpermit.Statement) { value.CapsuleDigest = digestOf("other capsule") },
		"policy":         func(value *taskpermit.Statement) { value.PolicyDigest = digestOf("other policy") },
		"route policy":   func(value *taskpermit.Statement) { value.RoutePolicyDigest = digestOf("other route") },
		"service":        func(value *taskpermit.Statement) { value.ServiceID = "other-api" },
		"operation":      func(value *taskpermit.Statement) { value.OperationID = "other.run" },
		"request digest": func(value *taskpermit.Statement) { value.RequestDigest = digestOf("other request") },
		"request bytes":  func(value *taskpermit.Statement) { value.RequestBytes++ },
		"content type":   func(value *taskpermit.Statement) { value.ContentType = "application/problem+json" },
	}
	for name, mutate := range statementMutations {
		t.Run(name, func(t *testing.T) {
			statement := fixture.statement
			mutate(&statement)
			candidate := fixture.command
			candidate.TaskPermit = signTaskHeader(t, statement, "tenant-task", fixture.taskPrivate)
			raw, err := MarshalCommandV1(candidate)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := VerifyCommandV1(raw, fixture.admission, fixture.now, taskpermit.MaxValidity); !errors.Is(err, ErrInvalidCommand) {
				t.Fatalf("err = %v", err)
			}
		})
	}

	_, foreignPrivate := generateKey(t)
	foreign := fixture.command
	foreign.TaskPermit = signTaskHeader(t, fixture.statement, "foreign-task", foreignPrivate)
	foreignRaw, err := MarshalCommandV1(foreign)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyCommandV1(foreignRaw, fixture.admission, fixture.now, taskpermit.MaxValidity); !errors.Is(err, ErrInvalidCommand) {
		t.Fatalf("foreign signer err = %v", err)
	}

	duplicatePayload := mustJSON(t, fixture.statement)
	duplicatePayload = bytes.Replace(
		duplicatePayload, []byte(`"node_id":"node-a"`),
		[]byte(`"node_id":"node-a","node_id":"node-a"`), 1,
	)
	duplicate := fixture.command
	duplicate.TaskPermit = signTaskPayloadHeader(t, duplicatePayload, "tenant-task", fixture.taskPrivate)
	duplicateRaw, err := MarshalCommandV1(duplicate)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyCommandV1(duplicateRaw, fixture.admission, fixture.now, taskpermit.MaxValidity); !errors.Is(err, ErrInvalidCommand) {
		t.Fatalf("duplicate signed field err = %v", err)
	}

	badAdmission := fixture.admission
	badAdmission.Projection.Status = "exited"
	if _, err := VerifyCommandV1(fixture.commandRaw, badAdmission, fixture.now, taskpermit.MaxValidity); !errors.Is(err, ErrInvalidCommand) {
		t.Fatalf("exited admission err = %v", err)
	}
}

func TestVerifyHistoricalCommandV1UsesSignedIntervalNotAuditorClock(t *testing.T) {
	fixture := newCanaryFixture(t)
	afterExpiry := fixture.now.Add(24 * time.Hour)
	if _, err := VerifyCommandV1(
		fixture.commandRaw,
		fixture.admission,
		afterExpiry,
		taskpermit.MaxValidity,
	); !errors.Is(err, ErrInvalidCommand) {
		t.Fatalf("live verification after expiry err = %v", err)
	}
	historical, err := VerifyHistoricalCommandV1(
		fixture.commandRaw,
		fixture.admission,
		taskpermit.MaxValidity,
	)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := VerifyResultV1(
		historical,
		fixture.resultRaw,
		fixture.receiptPublic,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyCheckpointV1(
		historical,
		verified,
		fixture.checkpointRaw,
	); err != nil {
		t.Fatal(err)
	}
}

func TestBuildCheckpointV1RequiresEvidenceForTheExactCommand(t *testing.T) {
	fixture := newCanaryFixture(t)
	evidence, err := VerifyEvidenceV1(
		fixture.verified,
		fixture.result.RunID,
		fixture.terminal,
		fixture.receipts,
		fixture.receiptPublic,
	)
	if err != nil {
		t.Fatal(err)
	}
	checkpointRaw, err := BuildCheckpointV1(fixture.verified, evidence)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(checkpointRaw, fixture.checkpointRaw) {
		t.Fatal("checkpoint helper did not reproduce the verified checkpoint")
	}

	evidence.commandKey = digestOf("another command")
	if _, err := BuildCheckpointV1(fixture.verified, evidence); !errors.Is(err, ErrInvalidResult) {
		t.Fatalf("command substitution err = %v", err)
	}
	if _, err := BuildCheckpointV1(VerifiedCommandV1{}, VerifiedEvidenceV1{}); !errors.Is(err, ErrInvalidResult) {
		t.Fatalf("unverified values err = %v", err)
	}
}

func TestParseResultV1RejectsAmbiguousOrOversizedProjection(t *testing.T) {
	fixture := newCanaryFixture(t)

	malformed := map[string][]byte{
		"unknown field": bytes.Replace(
			fixture.resultRaw, []byte(`"schema_version":`), []byte(`"other":true,"schema_version":`), 1,
		),
		"duplicate field": bytes.Replace(
			fixture.resultRaw, []byte(`"qualified":true`), []byte(`"qualified":true,"qualified":true`), 1,
		),
		"trailing JSON":        append(append([]byte(nil), fixture.resultRaw...), []byte(` {}`)...),
		"noncanonical spacing": append([]byte(" "), fixture.resultRaw...),
		"oversized":            bytes.Repeat([]byte(" "), MaxResultBytes+1),
	}
	for name, raw := range malformed {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseResultV1(raw); !errors.Is(err, ErrInvalidResult) {
				t.Fatalf("err = %v", err)
			}
		})
	}

	mutations := map[string]func(*ResultV1){
		"not qualified":             func(value *ResultV1) { value.Qualified = false },
		"bad task digest":           func(value *ResultV1) { value.TaskDigest = "sha256:" + strings.Repeat("A", 64) },
		"wrong result digest":       func(value *ResultV1) { value.TerminalResultDigest = digestOf("other") },
		"wrong result bytes":        func(value *ResultV1) { value.TerminalResultBytes++ },
		"alternate result base64":   func(value *ResultV1) { value.TerminalResultBase64 += "\n" },
		"alternate evidence base64": func(value *ResultV1) { value.GatewayEvidenceBase64 += "\n" },
		"evidence missing newline": func(value *ResultV1) {
			raw, _ := base64.StdEncoding.DecodeString(value.GatewayEvidenceBase64)
			value.GatewayEvidenceBase64 = base64.StdEncoding.EncodeToString(raw[:len(raw)-1])
		},
		"malformed checkpoint digest": func(value *ResultV1) { value.ActivationCheckpointDigest = "checkpoint" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			candidate := fixture.result
			mutate(&candidate)
			if _, err := MarshalResultV1(candidate); !errors.Is(err, ErrInvalidResult) {
				t.Fatalf("err = %v", err)
			}
		})
	}

	tooLargeTerminal := fixture.result
	terminal := bytes.Repeat([]byte{'x'}, MaxTerminalResultBytes+1)
	tooLargeTerminal.TerminalResultBase64 = base64.StdEncoding.EncodeToString(terminal)
	tooLargeTerminal.TerminalResultBytes = int64(len(terminal))
	tooLargeTerminal.TerminalResultDigest = dsse.Digest(terminal)
	if _, err := MarshalResultV1(tooLargeTerminal); !errors.Is(err, ErrInvalidResult) {
		t.Fatalf("oversized terminal err = %v", err)
	}

	tooLargeEvidence := fixture.result
	evidence := bytes.Repeat([]byte("x\n"), MaxGatewayEvidenceBytes/2+1)
	tooLargeEvidence.GatewayEvidenceBase64 = base64.StdEncoding.EncodeToString(evidence)
	if _, err := MarshalResultV1(tooLargeEvidence); !errors.Is(err, ErrInvalidResult) {
		t.Fatalf("oversized evidence err = %v", err)
	}
}

func TestVerifyResultV1RejectsCorrelationAuthorityAndSemanticFailures(t *testing.T) {
	fixture := newCanaryFixture(t)

	mutations := map[string]func(*ResultV1){
		"activation": func(value *ResultV1) { value.ActivationID = "activation-002" },
		"admission":  func(value *ResultV1) { value.AdmissionDigest = digestOf("other admission") },
		"task":       func(value *ResultV1) { value.TaskDigest = digestOf("other task") },
		"permit":     func(value *ResultV1) { value.PermitDigest = digestOf("other permit") },
		"run":        func(value *ResultV1) { value.RunID = "run_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			candidate := fixture.result
			mutate(&candidate)
			raw, err := MarshalResultV1(candidate)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := VerifyResultV1(fixture.verified, raw, fixture.receiptPublic); !errors.Is(err, ErrInvalidResult) {
				t.Fatalf("err = %v", err)
			}
		})
	}

	foreignPublic, _ := generateKey(t)
	if _, err := VerifyResultV1(fixture.verified, fixture.resultRaw, foreignPublic); !errors.Is(err, ErrInvalidResult) {
		t.Fatalf("foreign Gateway key err = %v", err)
	}

	reordered := fixture.result
	lines := bytes.Split(bytes.TrimSuffix(fixture.receipts, []byte{'\n'}), []byte{'\n'})
	lines[1], lines[2] = lines[2], lines[1]
	reordered.GatewayEvidenceBase64 = base64.StdEncoding.EncodeToString(
		append(bytes.Join(lines, []byte{'\n'}), '\n'),
	)
	reorderedRaw, err := MarshalResultV1(reordered)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyResultV1(fixture.verified, reorderedRaw, fixture.receiptPublic); !errors.Is(err, ErrInvalidResult) {
		t.Fatalf("reordered phases err = %v", err)
	}

	failedReceipts := makeGatewayReceipts(t, fixture, func(event *connectorledger.Event) {
		event.TaskStatus = connectorledger.TaskStatusAgentReportedFailed
	})
	wrongPhase := fixture.result
	wrongPhase.GatewayEvidenceBase64 = base64.StdEncoding.EncodeToString(failedReceipts)
	wrongPhaseRaw, err := MarshalResultV1(wrongPhase)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyResultV1(fixture.verified, wrongPhaseRaw, fixture.receiptPublic); !errors.Is(err, ErrInvalidResult) {
		t.Fatalf("failed terminal phase err = %v", err)
	}

	arbitraryTerminal := fixture.result
	badTerminal := bytes.Replace(fixture.terminal, []byte(`"status":"completed"`), []byte(`"status":"failed"`), 1)
	arbitraryTerminal.TerminalResultBase64 = base64.StdEncoding.EncodeToString(badTerminal)
	arbitraryTerminal.TerminalResultBytes = int64(len(badTerminal))
	arbitraryTerminal.TerminalResultDigest = dsse.Digest(badTerminal)
	arbitraryRaw, err := MarshalResultV1(arbitraryTerminal)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyResultV1(fixture.verified, arbitraryRaw, fixture.receiptPublic); !errors.Is(err, ErrInvalidResult) {
		t.Fatalf("arbitrary terminal err = %v", err)
	}

	wrongAuthority := fixture.command
	wrongAuthority.ReceiptAuthority.Epoch++
	wrongCommandRaw, err := MarshalCommandV1(wrongAuthority)
	if err != nil {
		t.Fatal(err)
	}
	wrongVerified, err := VerifyCommandV1(wrongCommandRaw, fixture.admission, fixture.now, taskpermit.MaxValidity)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyResultV1(wrongVerified, fixture.resultRaw, fixture.receiptPublic); !errors.Is(err, ErrInvalidResult) {
		t.Fatalf("wrong receipt epoch err = %v", err)
	}

	verifiedResult, err := VerifyResultV1(fixture.verified, fixture.resultRaw, fixture.receiptPublic)
	if err != nil {
		t.Fatal(err)
	}
	terminalAt, err := time.Parse(time.RFC3339Nano, verifiedResult.Gateway().TerminalAt)
	if err != nil {
		t.Fatal(err)
	}
	expired := fixture.verified
	expired.deadline = terminalAt.Add(-time.Nanosecond)
	if _, err := VerifyResultV1(expired, fixture.resultRaw, fixture.receiptPublic); !errors.Is(err, ErrInvalidResult) {
		t.Fatalf("terminal after absolute deadline err = %v", err)
	}
}

func TestBuildResultV1RejectsOverflowBeforeClaimingCheckpoint(t *testing.T) {
	fixture := newCanaryFixture(t)
	oversizedTerminal := bytes.Repeat([]byte{'x'}, MaxTerminalResultBytes+1)
	raw, _, err := BuildResultV1(
		fixture.verified, fixture.result.RunID, oversizedTerminal,
		fixture.receipts, fixture.checkpointRaw, fixture.receiptPublic,
	)
	if !errors.Is(err, ErrInvalidResult) || raw != nil {
		t.Fatalf("oversized terminal raw=%d err=%v", len(raw), err)
	}

	oversizedReceipts := bytes.Repeat([]byte("x\n"), MaxGatewayEvidenceBytes/2+1)
	raw, _, err = BuildResultV1(
		fixture.verified, fixture.result.RunID, fixture.terminal,
		oversizedReceipts, fixture.checkpointRaw, fixture.receiptPublic,
	)
	if !errors.Is(err, ErrInvalidResult) || raw != nil {
		t.Fatalf("oversized receipts raw=%d err=%v", len(raw), err)
	}
}

func TestVerifyCheckpointV1RejectsAnyCanaryOrAdmissionMismatch(t *testing.T) {
	fixture := newCanaryFixture(t)
	verified, err := VerifyResultV1(fixture.verified, fixture.resultRaw, fixture.receiptPublic)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyCheckpointV1(
		fixture.verified, VerifiedResultV1{}, fixture.checkpointRaw,
	); !errors.Is(err, ErrInvalidResult) {
		t.Fatalf("unverified result err = %v", err)
	}
	laterCommand := fixture.command
	laterCommand.Deadline = fixture.now.Add(4*time.Minute + 30*time.Second).Format(time.RFC3339Nano)
	laterRaw, err := MarshalCommandV1(laterCommand)
	if err != nil {
		t.Fatal(err)
	}
	laterVerifiedCommand, err := VerifyCommandV1(
		laterRaw, fixture.admission, fixture.now, taskpermit.MaxValidity,
	)
	if err != nil {
		t.Fatal(err)
	}
	laterVerifiedResult, err := VerifyResultV1(
		laterVerifiedCommand, fixture.resultRaw, fixture.receiptPublic,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyCheckpointV1(
		fixture.verified, laterVerifiedResult, fixture.checkpointRaw,
	); !errors.Is(err, ErrInvalidResult) {
		t.Fatalf("cross-command verified result err = %v", err)
	}
	checkpoint, err := activation.ParseExecutorCheckpointV1(fixture.checkpointRaw)
	if err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(*activation.ExecutorCheckpointV1){
		"activation": func(value *activation.ExecutorCheckpointV1) {
			value.Binding.ActivationID = "activation-002"
		},
		"node": func(value *activation.ExecutorCheckpointV1) {
			value.Binding.NodeID = "node-b"
		},
		"tenant": func(value *activation.ExecutorCheckpointV1) {
			value.Binding.TenantID = "tenant-b"
		},
		"instance": func(value *activation.ExecutorCheckpointV1) {
			value.Binding.InstanceID = "hermes-b"
		},
		"generation": func(value *activation.ExecutorCheckpointV1) {
			value.Binding.Generation++
		},
		"plan": func(value *activation.ExecutorCheckpointV1) {
			value.Binding.PlanDigest = digestOf("other plan")
		},
		"release": func(value *activation.ExecutorCheckpointV1) {
			value.Binding.ReleaseDigest = digestOf("other release")
		},
		"policy": func(value *activation.ExecutorCheckpointV1) {
			value.Binding.PolicyDigest = digestOf("other policy")
		},
		"intent": func(value *activation.ExecutorCheckpointV1) {
			value.Binding.IntentDigest = digestOf("other intent")
		},
		"archive digest": func(value *activation.ExecutorCheckpointV1) {
			value.Binding.Archive.Digest = digestOf("other archive")
		},
		"archive bytes": func(value *activation.ExecutorCheckpointV1) {
			value.Binding.Archive.Bytes++
		},
		"runtime": func(value *activation.ExecutorCheckpointV1) {
			value.RuntimeRef = "executor-" + strings.Repeat("2", 64)
		},
		"capsule": func(value *activation.ExecutorCheckpointV1) {
			value.CapsuleDigest = digestOf("other capsule")
		},
		"route": func(value *activation.ExecutorCheckpointV1) {
			value.RoutePolicyDigest = digestOf("other route")
		},
		"grant": func(value *activation.ExecutorCheckpointV1) {
			value.GrantID = grantID('e')
		},
		"receipts": func(value *activation.ExecutorCheckpointV1) {
			value.GatewayReceiptsDigest = digestOf("other receipts")
		},
		"terminal coordinate": func(value *activation.ExecutorCheckpointV1) {
			value.GatewayEvidence.Sequence++
		},
		"canary": func(value *activation.ExecutorCheckpointV1) {
			value.Canary.ResultDigest = digestOf("other result")
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			candidate := checkpoint
			mutate(&candidate)
			raw := mustJSON(t, candidate)
			if err := VerifyCheckpointV1(fixture.verified, verified, raw); !errors.Is(err, ErrInvalidResult) {
				t.Fatalf("err = %v", err)
			}
		})
	}

	unknown := bytes.Replace(
		fixture.checkpointRaw, []byte(`"schema_version":`),
		[]byte(`"unknown":true,"schema_version":`), 1,
	)
	if err := VerifyCheckpointV1(fixture.verified, verified, unknown); !errors.Is(err, ErrInvalidResult) {
		t.Fatalf("unknown checkpoint field err = %v", err)
	}
}

func newCanaryFixture(t *testing.T) canaryFixture {
	return newCanaryFixtureForKind(t, agentrelease.CanaryKindHermesWorkspaceAuditV1)
}

func newCanaryFixtureForKind(t *testing.T, kind string) canaryFixture {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	activationID := "activation-001"
	contract, ok := agentrelease.CanaryContractForKind(kind)
	if !ok {
		t.Fatal("unknown canary contract")
	}
	request, err := agentrelease.BuildCanaryRequest(contract.Request, activationID)
	if err != nil {
		t.Fatal(err)
	}
	taskPublic, taskPrivate := generateKey(t)
	receiptPublic, receiptPrivate := generateKey(t)
	instanceID := "hermes-a"
	statement := taskpermit.Statement{
		SchemaVersion: taskpermit.SchemaV1,
		NodeID:        "node-a", TenantID: "tenant-a", InstanceID: instanceID,
		RuntimeRef: "executor-" + strings.Repeat("1", 64),
		GrantID:    grantID('d'), Generation: 7,
		CapsuleDigest: digestOf("capsule"), PolicyDigest: digestOf("policy"),
		RoutePolicyDigest: digestOf("route"),
		ServiceID:         contract.ServiceID, OperationID: contract.OperationID,
		OperationPolicyDigest: digestOf("operation"), TaskID: "activation-task",
		RequestDigest: taskpermit.RequestDigest(request), RequestBytes: int64(len(request)),
		ContentType: "application/json",
		NotBefore:   now.Add(-time.Minute).Format(time.RFC3339),
		ExpiresAt:   now.Add(5 * time.Minute).Format(time.RFC3339),
	}
	binding := activation.BindingV1{
		ActivationID: activationID,
		PlanDigest:   digestOf("plan"), ReleaseDigest: digestOf("release"),
		PolicyDigest: statement.PolicyDigest, IntentDigest: digestOf("intent"),
		Archive:  activation.ArchiveV1{Digest: digestOf("archive"), Bytes: 1024},
		TenantID: statement.TenantID, NodeID: statement.NodeID,
		InstanceID: statement.InstanceID, Generation: statement.Generation,
	}
	beginRaw, err := activation.MarshalExecutorBeginV1(
		binding,
		statement.RuntimeRef,
		"steward-state-"+strings.Repeat("b", 64),
		statement.CapsuleDigest,
	)
	if err != nil {
		t.Fatal(err)
	}
	projection := controlprotocol.ExecutorAdmissionProjectionV1{
		SchemaVersion: controlprotocol.ExecutorAdmissionProjectionSchemaV1,
		RuntimeRef:    statement.RuntimeRef, Status: "running",
		CapsuleDigest: statement.CapsuleDigest, PolicyDigest: statement.PolicyDigest,
		Generation: statement.Generation, EvidenceKeyID: strings.Repeat("a", 32),
		GrantID: statement.GrantID, ServicePath: "/v1/services/" + statement.GrantID + "/",
		ServiceID: statement.ServiceID,
		TaskAuthorities: []controlprotocol.ExecutorTaskAuthorityV1{{
			KeyID: "tenant-task", PublicKey: base64.StdEncoding.EncodeToString(taskPublic),
		}},
		RoutePolicyDigest: statement.RoutePolicyDigest,
		ActivationID:      activationID, ActivationBeginDigest: dsse.Digest(beginRaw),
	}
	if err := projection.Validate(); err != nil {
		t.Fatal(err)
	}
	projectionRaw := mustJSON(t, projection)
	command := CommandV1{
		SchemaVersion: CommandSchemaV1, ActivationID: activationID,
		AdmissionDigest:     dsse.Digest(projectionRaw),
		Admission:           projection,
		GrantID:             statement.GrantID,
		ExecutorBeginBase64: base64.StdEncoding.EncodeToString(beginRaw),
		OperationID:         statement.OperationID,
		TaskPermit:          signTaskHeader(t, statement, "tenant-task", taskPrivate),
		RequestBase64:       base64.StdEncoding.EncodeToString(request),
		Deadline:            now.Add(4 * time.Minute).Format(time.RFC3339Nano),
		ReceiptAuthority: ReceiptAuthorityV1{
			NodeID: "node-a/gateway", Epoch: 7,
			PublicKeySHA256: controlprotocol.ExecutorEvidencePublicKeySHA256(receiptPublic),
		},
	}
	commandRaw, err := MarshalCommandV1(command)
	if err != nil {
		t.Fatal(err)
	}
	admission := AdmissionContextV1{
		NodeID: statement.NodeID, TenantID: statement.TenantID,
		InstanceID: statement.InstanceID, Projection: projection,
	}
	verified, err := VerifyCommandV1(commandRaw, admission, now, taskpermit.MaxValidity)
	if err != nil {
		t.Fatal(err)
	}
	terminal := validHermesTerminal(t, activationID)
	fixture := canaryFixture{
		now: now, command: command, commandRaw: commandRaw, verified: verified,
		admission: admission, statement: statement, taskPrivate: taskPrivate,
		receiptPublic: receiptPublic, receiptPrivate: receiptPrivate, terminal: terminal,
	}
	fixture.receipts = makeGatewayReceipts(t, fixture, nil)
	evidence, err := VerifyEvidenceV1(
		verified, "run_0123456789abcdef0123456789abcdef",
		terminal, fixture.receipts, receiptPublic,
	)
	if err != nil {
		t.Fatal(err)
	}
	fixture.checkpointRaw, err = BuildCheckpointV1(verified, evidence)
	if err != nil {
		t.Fatal(err)
	}
	resultRaw, _, err := BuildResultV1(
		verified, "run_0123456789abcdef0123456789abcdef", terminal,
		fixture.receipts, fixture.checkpointRaw, receiptPublic,
	)
	if err != nil {
		t.Fatal(err)
	}
	fixture.resultRaw = resultRaw
	fixture.result, err = ParseResultV1(resultRaw)
	if err != nil {
		t.Fatal(err)
	}
	return fixture
}

func makeGatewayReceipts(
	t *testing.T,
	fixture canaryFixture,
	mutateTerminal func(*connectorledger.Event),
) []byte {
	t.Helper()
	path := filepath.Join(t.TempDir(), "gateway.ndjson")
	log, err := connectorledger.Open(
		path, fixture.receiptPrivate,
		fixture.command.ReceiptAuthority.NodeID, fixture.command.ReceiptAuthority.Epoch,
	)
	if err != nil {
		t.Fatal(err)
	}
	statement := fixture.statement
	taskDigest := taskpermit.TaskDigest(statement.TenantID, statement.InstanceID, statement.TaskID)
	authorize := connectorledger.Event{
		Phase: connectorledger.Authorize, Outcome: connectorledger.Allowed,
		Kind: connectorledger.ServiceTask, TenantID: statement.TenantID,
		RuntimeRef: statement.RuntimeRef, CapsuleDigest: statement.CapsuleDigest,
		PolicyDigest: statement.PolicyDigest, RoutePolicyDigest: statement.RoutePolicyDigest,
		Generation: statement.Generation, GrantID: statement.GrantID,
		ServiceID: statement.ServiceID, OperationID: statement.OperationID,
		OperationPolicyDigest: statement.OperationPolicyDigest, TaskDigest: taskDigest,
		AuthorityKeyID: fixture.verified.Permit().KeyID,
		PermitDigest:   fixture.verified.Permit().EnvelopeDigest,
		RequestDigest:  statement.RequestDigest, RequestBytes: statement.RequestBytes,
		TaskProtocol: connectorledger.TaskProtocolLifecycleV1,
	}
	if _, err := log.Begin(authorize); err != nil {
		t.Fatal(err)
	}
	dispatch := authorize
	dispatch.Phase, dispatch.Outcome = connectorledger.Dispatch, connectorledger.Responded
	dispatch.HTTPStatus, dispatch.ResponseBytes = 202, 96
	dispatch.RunID = "run_0123456789abcdef0123456789abcdef"
	if _, err := log.Dispatch(dispatch); err != nil {
		t.Fatal(err)
	}
	terminal := dispatch
	terminal.Phase, terminal.Outcome = connectorledger.Terminal, connectorledger.Responded
	terminal.HTTPStatus = 200
	terminal.ResponseBytes = int64(len(fixture.terminal))
	terminal.TaskStatus = connectorledger.TaskStatusAgentReportedCompleted
	terminal.ResultDigest = dsse.Digest(fixture.terminal)
	if mutateTerminal != nil {
		mutateTerminal(&terminal)
	}
	if _, err := log.Finish(terminal); err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	var selected []connectorledger.VerifiedReceipt
	if _, err := connectorledger.VerifyRecords(
		path, fixture.receiptPublic, fixture.command.ReceiptAuthority.NodeID,
		fixture.command.ReceiptAuthority.Epoch,
		func(record connectorledger.VerifiedReceipt) error {
			if record.Receipt.Event.TaskDigest == taskDigest {
				selected = append(selected, record)
			}
			return nil
		},
	); err != nil {
		t.Fatal(err)
	}
	receipts, err := connectorledger.MarshalPortableTaskEvidence(selected)
	if err != nil {
		t.Fatal(err)
	}
	return receipts
}

func validHermesTerminal(t *testing.T, activationID string) []byte {
	t.Helper()
	workspace := struct {
		Entries        []any  `json:"entries"`
		FileCount      int    `json:"file_count"`
		ManifestDigest string `json:"manifest_digest"`
		Root           string `json:"root"`
		SchemaVersion  string `json:"schema_version"`
		TotalBytes     int64  `json:"total_bytes"`
	}{
		Entries: []any{}, ManifestDigest: agentrelease.HermesWorkspaceAuditEmptyManifestDigest,
		Root: activation.HermesWorkspaceRoot, SchemaVersion: activation.HermesWorkspaceSchemaV1,
	}
	workspaceRaw := mustJSON(t, workspace)
	terminal := struct {
		Object    string `json:"object"`
		RunID     string `json:"run_id"`
		Status    string `json:"status"`
		UpdatedAt int64  `json:"updated_at"`
		CreatedAt int64  `json:"created_at"`
		SessionID string `json:"session_id"`
		Model     string `json:"model"`
		Output    string `json:"output"`
		Usage     struct {
			InputTokens  int64 `json:"input_tokens"`
			OutputTokens int64 `json:"output_tokens"`
			TotalTokens  int64 `json:"total_tokens"`
		} `json:"usage"`
		LastEvent string `json:"last_event"`
	}{
		Object: activation.HermesRunObject,
		RunID:  "run_0123456789abcdef0123456789abcdef",
		Status: activation.HermesCompletedStatus, UpdatedAt: 2, CreatedAt: 1,
		SessionID: agentrelease.HermesSessionIDPrefix + "-" + activationID,
		Model:     "steward-fixture-model", Output: string(workspaceRaw),
		LastEvent: activation.HermesCompletedEvent,
	}
	terminal.Usage.InputTokens = 2
	terminal.Usage.OutputTokens = 1
	terminal.Usage.TotalTokens = 3
	return mustJSON(t, terminal)
}

func mustFixedRequest(t *testing.T, activationID string) []byte {
	t.Helper()
	raw, err := agentrelease.BuildCanaryRequest(agentrelease.RequestRecipe{
		Input: agentrelease.HermesWorkspaceAuditInput, SessionIDPrefix: agentrelease.HermesSessionIDPrefix,
	}, activationID)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func signTaskHeader(t *testing.T, statement taskpermit.Statement, keyID string, private ed25519.PrivateKey) string {
	t.Helper()
	return signTaskPayloadHeader(t, mustJSON(t, statement), keyID, private)
}

func signTaskPayloadHeader(t *testing.T, payload []byte, keyID string, private ed25519.PrivateKey) string {
	t.Helper()
	envelope, err := dsse.Sign(taskpermit.PayloadType, payload, keyID, private)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := dsse.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	header, err := taskpermit.EncodeHeader(raw)
	if err != nil {
		t.Fatal(err)
	}
	return header
}

func generateKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return public, private
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func grantID(fill byte) string { return "grant-" + strings.Repeat(string(fill), 64) }

func digestOf(value string) string { return dsse.Digest([]byte(value)) }
