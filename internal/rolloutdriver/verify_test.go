package rolloutdriver

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/activation"
	"github.com/hardrails/steward/internal/activationcanary"
	"github.com/hardrails/steward/internal/agentrelease"
	"github.com/hardrails/steward/internal/connectorledger"
	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/taskpermit"
)

func TestVerifyCanaryV1QualifiesSignedRemoteEvidenceAndDerivesCheckpoint(t *testing.T) {
	fixture := newVerifiedRolloutCanaryFixture(t)
	input := fixture.input()
	verified, err := VerifyCanaryV1(input)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(verified.CommandRaw(), fixture.commandRaw) ||
		!bytes.Equal(verified.ResultRaw(), fixture.resultRaw) ||
		!bytes.Equal(verified.CheckpointRaw(), fixture.checkpointRaw) {
		t.Fatal("verified exact artifact bytes changed")
	}
	if verified.Command().ActivationID != fixture.prepared.Target().ActivationID ||
		verified.Result().RunID != rolloutCanaryRunID ||
		verified.Checkpoint().Binding != fixture.prepared.Binding() ||
		verified.Checkpoint().GatewayEvidence.PublicKeySHA256 !=
			fixture.prepared.Target().GatewayReceiptPublicKeySHA256 {
		t.Fatalf("unexpected verified values: command=%#v result=%#v checkpoint=%#v",
			verified.Command(), verified.Result(), verified.Checkpoint())
	}

	commandRaw := verified.CommandRaw()
	commandRaw[0] ^= 0xff
	resultRaw := verified.ResultRaw()
	resultRaw[0] ^= 0xff
	checkpointRaw := verified.CheckpointRaw()
	checkpointRaw[0] ^= 0xff
	command := verified.Command()
	command.Admission.TaskAuthorities[0].KeyID = "mutated"
	input.CommandRaw[0] ^= 0xff
	input.ResultRaw[0] ^= 0xff
	input.Admission.TaskAuthorities[0].KeyID = "mutated"
	input.ReceiptPublicKey[0] ^= 0xff
	if !bytes.Equal(verified.CommandRaw(), fixture.commandRaw) ||
		!bytes.Equal(verified.ResultRaw(), fixture.resultRaw) ||
		!bytes.Equal(verified.CheckpointRaw(), fixture.checkpointRaw) ||
		verified.Command().Admission.TaskAuthorities[0].KeyID != fixture.driver.taskKeyID {
		t.Fatal("verified artifact accessor leaked mutable storage")
	}
}

func TestVerifyCanaryV1QualifiesOpenClawRemoteEvidence(t *testing.T) {
	fixture := newVerifiedRolloutCanaryFixtureForKind(
		t, agentrelease.CanaryKindOpenClawWorkspaceAuditV1,
	)
	verified, err := VerifyCanaryV1(fixture.input())
	if err != nil {
		t.Fatal(err)
	}
	terminal, err := base64.StdEncoding.DecodeString(verified.Result().TerminalResultBase64)
	if err != nil {
		t.Fatal(err)
	}
	canary, err := activation.VerifyCanaryResultV1(
		agentrelease.CanaryKindOpenClawWorkspaceAuditV1,
		terminal,
		fixture.prepared.Target().ActivationID,
	)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Result().RunID != rolloutCanaryRunID ||
		canary.ManifestDigest != agentrelease.OpenClawWorkspaceAuditManifestDigest ||
		verified.Command().Admission.ServiceID != agentrelease.OpenClawServiceID {
		t.Fatalf("unexpected verified OpenClaw rollout evidence: %#v", verified.Result())
	}
}

func TestVerifyCanaryV1RejectsRolloutAndEvidenceSubstitution(t *testing.T) {
	fixture := newVerifiedRolloutCanaryFixture(t)
	base := fixture.input()
	foreignPublic, _ := testKey(99)

	tests := map[string]func(*VerifyCanaryInputV1){
		"admission projection": func(input *VerifyCanaryInputV1) {
			input.Admission.EvidenceKeyID = strings.Repeat("b", 32)
		},
		"noncanonical command": func(input *VerifyCanaryInputV1) {
			input.CommandRaw = append(append([]byte(nil), input.CommandRaw...), ' ')
		},
		"noncanonical result": func(input *VerifyCanaryInputV1) {
			input.ResultRaw = append(append([]byte(nil), input.ResultRaw...), ' ')
		},
		"target canary task identity": func(input *VerifyCanaryInputV1) {
			input.Prepared.target.CanaryCommandID = "another-canary"
		},
		"operation policy": func(input *VerifyCanaryInputV1) {
			input.Prepared.target.OperationPolicyDigest = testDigest("another-operation-policy")
		},
		"receipt epoch": func(input *VerifyCanaryInputV1) {
			input.Prepared.target.GatewayReceiptEpoch++
		},
		"receipt key target pin": func(input *VerifyCanaryInputV1) {
			input.Prepared.target.GatewayReceiptPublicKeySHA256 = testDigest("another-receipt-key")
		},
		"independent receipt key": func(input *VerifyCanaryInputV1) {
			input.ReceiptPublicKey = foreignPublic
		},
		"exact prepared begin bytes": func(input *VerifyCanaryInputV1) {
			input.Prepared.executorBeginRaw = append(
				append([]byte(nil), input.Prepared.executorBeginRaw...), ' ',
			)
		},
		"rollout deadline": func(input *VerifyCanaryInputV1) {
			input.Prepared.plan.Deadline = fixture.driver.now.Add(3 * time.Minute).Format(time.RFC3339Nano)
		},
		"activation canary timeout": func(input *VerifyCanaryInputV1) {
			input.Prepared.activationPlan.Timeouts.CanarySeconds = 60
		},
		"command receipt authority": func(input *VerifyCanaryInputV1) {
			command, err := activationcanary.ParseCommandV1(input.CommandRaw)
			if err != nil {
				t.Fatal(err)
			}
			command.ReceiptAuthority.Epoch++
			input.CommandRaw, err = activationcanary.MarshalCommandV1(command)
			if err != nil {
				t.Fatal(err)
			}
		},
		"checkpoint digest": func(input *VerifyCanaryInputV1) {
			result, err := activationcanary.ParseResultV1(input.ResultRaw)
			if err != nil {
				t.Fatal(err)
			}
			result.ActivationCheckpointDigest = testDigest("another-checkpoint")
			input.ResultRaw, err = activationcanary.MarshalResultV1(result)
			if err != nil {
				t.Fatal(err)
			}
		},
		"Gateway receipt signature": func(input *VerifyCanaryInputV1) {
			result, err := activationcanary.ParseResultV1(input.ResultRaw)
			if err != nil {
				t.Fatal(err)
			}
			receipts, err := base64.StdEncoding.DecodeString(result.GatewayEvidenceBase64)
			if err != nil {
				t.Fatal(err)
			}
			receipts[32] ^= 1
			result.GatewayEvidenceBase64 = base64.StdEncoding.EncodeToString(receipts)
			input.ResultRaw, err = activationcanary.MarshalResultV1(result)
			if err != nil {
				t.Fatal(err)
			}
		},
		"Hermes terminal substitution": func(input *VerifyCanaryInputV1) {
			result, err := activationcanary.ParseResultV1(input.ResultRaw)
			if err != nil {
				t.Fatal(err)
			}
			terminal, err := base64.StdEncoding.DecodeString(result.TerminalResultBase64)
			if err != nil {
				t.Fatal(err)
			}
			terminal = bytes.Replace(
				terminal,
				[]byte(`"model":"steward-fixture-model"`),
				[]byte(`"model":"substituted-model"`),
				1,
			)
			result.TerminalResultBase64 = base64.StdEncoding.EncodeToString(terminal)
			result.TerminalResultBytes = int64(len(terminal))
			result.TerminalResultDigest = dsse.Digest(terminal)
			input.ResultRaw, err = activationcanary.MarshalResultV1(result)
			if err != nil {
				t.Fatal(err)
			}
		},
	}

	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			input := cloneVerifyCanaryInput(base)
			mutate(&input)
			if _, err := VerifyCanaryV1(input); !errors.Is(err, ErrInvalid) {
				t.Fatalf("err = %v, want ErrInvalid", err)
			}
		})
	}
}

const rolloutCanaryRunID = "run_0123456789abcdef0123456789abcdef"

type verifiedRolloutCanaryFixture struct {
	driver        driverFixture
	prepared      PreparedTargetV1
	admission     controlprotocol.ExecutorAdmissionProjectionV1
	commandRaw    []byte
	resultRaw     []byte
	checkpointRaw []byte
	receiptPublic ed25519.PublicKey
}

func newVerifiedRolloutCanaryFixture(t *testing.T) verifiedRolloutCanaryFixture {
	return newVerifiedRolloutCanaryFixtureForKind(
		t, agentrelease.CanaryKindHermesWorkspaceAuditV1,
	)
}

func newVerifiedRolloutCanaryFixtureForKind(
	t *testing.T,
	kind string,
) verifiedRolloutCanaryFixture {
	t.Helper()
	driver := newDriverFixtureForKind(t, kind)
	driver.now = time.Now().UTC().Truncate(time.Second)
	driver.plan.CreatedAt = driver.now.Add(-time.Minute).Format(time.RFC3339Nano)
	driver.plan.Deadline = driver.now.Add(time.Hour).Format(time.RFC3339Nano)
	driver.planRaw = mustRolloutPlan(t, driver.plan)
	prepared := driver.prepare(t)
	admission := driver.projection(prepared)
	artifacts, err := BuildCanaryCommandV1(CanaryInputV1{
		Prepared:              prepared,
		Admission:             admission,
		TaskKeyID:             driver.taskKeyID,
		TaskPrivateKey:        driver.taskPrivate,
		TaskPublicKey:         driver.taskPublic,
		OperationPolicyDigest: prepared.Target().OperationPolicyDigest,
		ReceiptAuthority:      driver.receiptAuthority(),
		Deadline:              driver.now.Add(4 * time.Minute),
		CommandWindow:         driver.commandWindow(5 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	context := activationcanary.AdmissionContextV1{
		NodeID: prepared.Target().NodeID, TenantID: prepared.Plan().TenantID,
		InstanceID: prepared.Target().InstanceID, Projection: admission,
	}
	verifiedCommand, err := activationcanary.VerifyHistoricalCommandV1(
		artifacts.CanaryRaw(), context, taskpermit.MaxValidity,
	)
	if err != nil {
		t.Fatal(err)
	}
	var terminal []byte
	switch kind {
	case agentrelease.CanaryKindHermesWorkspaceAuditV1:
		terminal = rolloutHermesTerminal(t, prepared.Target().ActivationID)
	case agentrelease.CanaryKindOpenClawWorkspaceAuditV1:
		terminal = rolloutOpenClawTerminal(t, prepared.Target().ActivationID)
	default:
		t.Fatal("unsupported fixture canary kind")
	}
	_, receiptPrivate := testKey(5)
	receipts := rolloutGatewayReceipts(
		t,
		verifiedCommand,
		terminal,
		driver.receiptAuthority(),
		driver.receiptPublic,
		receiptPrivate,
	)
	evidence, err := activationcanary.VerifyEvidenceV1(
		verifiedCommand,
		rolloutCanaryRunID,
		terminal,
		receipts,
		driver.receiptPublic,
	)
	if err != nil {
		t.Fatal(err)
	}
	checkpointRaw, err := activationcanary.BuildCheckpointV1(verifiedCommand, evidence)
	if err != nil {
		t.Fatal(err)
	}
	resultRaw, _, err := activationcanary.BuildResultV1(
		verifiedCommand,
		rolloutCanaryRunID,
		terminal,
		receipts,
		checkpointRaw,
		driver.receiptPublic,
	)
	if err != nil {
		t.Fatal(err)
	}
	return verifiedRolloutCanaryFixture{
		driver: driver, prepared: prepared, admission: admission,
		commandRaw: artifacts.CanaryRaw(), resultRaw: resultRaw,
		checkpointRaw: checkpointRaw,
		receiptPublic: append(ed25519.PublicKey(nil), driver.receiptPublic...),
	}
}

func (fixture verifiedRolloutCanaryFixture) input() VerifyCanaryInputV1 {
	return VerifyCanaryInputV1{
		Prepared:         fixture.prepared,
		Admission:        cloneAdmissionProjection(fixture.admission),
		CommandRaw:       append([]byte(nil), fixture.commandRaw...),
		ResultRaw:        append([]byte(nil), fixture.resultRaw...),
		ReceiptPublicKey: append(ed25519.PublicKey(nil), fixture.receiptPublic...),
	}
}

func cloneVerifyCanaryInput(input VerifyCanaryInputV1) VerifyCanaryInputV1 {
	input.Admission = cloneAdmissionProjection(input.Admission)
	input.CommandRaw = append([]byte(nil), input.CommandRaw...)
	input.ResultRaw = append([]byte(nil), input.ResultRaw...)
	input.ReceiptPublicKey = append(ed25519.PublicKey(nil), input.ReceiptPublicKey...)
	input.Prepared.executorBeginRaw = append([]byte(nil), input.Prepared.executorBeginRaw...)
	return input
}

func rolloutGatewayReceipts(
	t *testing.T,
	command activationcanary.VerifiedCommandV1,
	terminal []byte,
	authority activationcanary.ReceiptAuthorityV1,
	receiptPublic ed25519.PublicKey,
	receiptPrivate ed25519.PrivateKey,
) []byte {
	t.Helper()
	path := filepath.Join(t.TempDir(), "gateway.ndjson")
	log, err := connectorledger.Open(path, receiptPrivate, authority.NodeID, authority.Epoch)
	if err != nil {
		t.Fatal(err)
	}
	statement := command.Permit().Statement
	taskDigest := taskpermit.TaskDigest(statement.TenantID, statement.InstanceID, statement.TaskID)
	authorize := connectorledger.Event{
		Phase: connectorledger.Authorize, Outcome: connectorledger.Allowed,
		Kind: connectorledger.ServiceTask, TenantID: statement.TenantID,
		RuntimeRef: statement.RuntimeRef, CapsuleDigest: statement.CapsuleDigest,
		PolicyDigest: statement.PolicyDigest, RoutePolicyDigest: statement.RoutePolicyDigest,
		Generation: statement.Generation, GrantID: statement.GrantID,
		ServiceID: statement.ServiceID, OperationID: statement.OperationID,
		OperationPolicyDigest: statement.OperationPolicyDigest, TaskDigest: taskDigest,
		AuthorityKeyID: command.Permit().KeyID, PermitDigest: command.Permit().EnvelopeDigest,
		RequestDigest: statement.RequestDigest, RequestBytes: statement.RequestBytes,
		TaskProtocol: connectorledger.TaskProtocolLifecycleV1,
	}
	if _, err := log.Begin(authorize); err != nil {
		t.Fatal(err)
	}
	dispatch := authorize
	dispatch.Phase, dispatch.Outcome = connectorledger.Dispatch, connectorledger.Responded
	dispatch.HTTPStatus, dispatch.ResponseBytes = 202, 96
	dispatch.RunID = rolloutCanaryRunID
	if _, err := log.Dispatch(dispatch); err != nil {
		t.Fatal(err)
	}
	finished := dispatch
	finished.Phase, finished.Outcome = connectorledger.Terminal, connectorledger.Responded
	finished.HTTPStatus = 200
	finished.ResponseBytes = int64(len(terminal))
	finished.TaskStatus = connectorledger.TaskStatusAgentReportedCompleted
	finished.ResultDigest = dsse.Digest(terminal)
	if _, err := log.Finish(finished); err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}

	var selected []connectorledger.VerifiedReceipt
	if _, err := connectorledger.VerifyRecords(
		path,
		receiptPublic,
		authority.NodeID,
		authority.Epoch,
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

func rolloutHermesTerminal(t *testing.T, activationID string) []byte {
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
	workspaceRaw, err := json.Marshal(workspace)
	if err != nil {
		t.Fatal(err)
	}
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
		Object: activation.HermesRunObject, RunID: rolloutCanaryRunID,
		Status: activation.HermesCompletedStatus, UpdatedAt: 2, CreatedAt: 1,
		SessionID: agentrelease.HermesSessionIDPrefix + "-" + activationID,
		Model:     "steward-fixture-model", Output: string(workspaceRaw),
		LastEvent: activation.HermesCompletedEvent,
	}
	terminal.Usage.InputTokens = 2
	terminal.Usage.OutputTokens = 1
	terminal.Usage.TotalTokens = 3
	raw, err := json.Marshal(terminal)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func rolloutOpenClawTerminal(t *testing.T, activationID string) []byte {
	t.Helper()
	result := struct {
		Payloads []struct {
			Text     string          `json:"text"`
			MediaURL json.RawMessage `json:"media_url"`
		} `json:"payloads"`
		Meta struct {
			DurationMS   int64    `json:"duration_ms"`
			Model        string   `json:"model"`
			Provider     string   `json:"provider"`
			ToolCalls    int      `json:"tool_calls"`
			ToolFailures int      `json:"tool_failures"`
			Tools        []string `json:"tools"`
		} `json:"meta"`
	}{}
	result.Payloads = append(result.Payloads, struct {
		Text     string          `json:"text"`
		MediaURL json.RawMessage `json:"media_url"`
	}{Text: activation.OpenClawSuccessText, MediaURL: json.RawMessage("null")})
	result.Meta.DurationMS = 7701
	result.Meta.Model = "steward-openclaw-fixture"
	result.Meta.Provider = "steward"
	result.Meta.ToolCalls = 1
	result.Meta.Tools = []string{"exec"}
	resultRaw := mustJSON(t, result)
	var canonicalResult any
	if err := json.Unmarshal(resultRaw, &canonicalResult); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(mustJSON(t, canonicalResult))
	terminal := struct {
		RunID         string          `json:"run_id"`
		SessionID     string          `json:"session_id"`
		Status        string          `json:"status"`
		Result        json.RawMessage `json:"result"`
		ResultSHA256  string          `json:"result_sha256"`
		Qualification struct {
			FixtureID               string `json:"fixture_id"`
			WorkspaceManifestDigest string `json:"workspace_manifest_digest"`
		} `json:"qualification"`
	}{
		RunID:     rolloutCanaryRunID,
		SessionID: agentrelease.OpenClawSessionIDPrefix + "-" + activationID,
		Status:    activation.OpenClawCompletedStatus, Result: resultRaw,
		ResultSHA256: hex.EncodeToString(sum[:]),
	}
	terminal.Qualification.FixtureID = agentrelease.OpenClawWorkspaceAuditFixtureID
	terminal.Qualification.WorkspaceManifestDigest = agentrelease.OpenClawWorkspaceAuditManifestDigest
	return append(mustJSON(t, terminal), '\n')
}
