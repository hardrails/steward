package activation

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hardrails/steward/internal/connectorledger"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/taskpermit"
)

type gatewayEvidenceFixture struct {
	request GatewayEvidenceRequestV1
	path    string
}

func TestCollectAndVerifyGatewayEvidenceV1(t *testing.T) {
	fixture := newGatewayEvidenceFixture(t)
	collected, err := CollectGatewayEvidenceV1(fixture.request, fixture.path)
	if err != nil {
		t.Fatal(err)
	}
	if len(collected.Receipts) == 0 ||
		collected.Coordinate.ReceiptNodeID != "node-a/gateway" ||
		collected.Canary.TaskDigest != taskpermit.TaskDigest("tenant-a", "hermes-a", "activation-task") ||
		collected.Canary.ResultDigest != dsse.Digest(fixture.request.Result) ||
		collected.AuthorizedAt == "" || collected.TerminalAt == "" {
		t.Fatalf("collected Gateway evidence = %#v", collected)
	}
	verified, err := VerifyGatewayEvidenceV1(fixture.request, collected.Receipts)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Coordinate != collected.Coordinate ||
		verified.Canary != collected.Canary ||
		string(verified.Receipts) != string(collected.Receipts) {
		t.Fatalf("verified Gateway evidence = %#v, want %#v", verified, collected)
	}
}

func TestGatewayEvidenceV1RejectsSubstitution(t *testing.T) {
	fixture := newGatewayEvidenceFixture(t)
	collected, err := CollectGatewayEvidenceV1(fixture.request, fixture.path)
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]func(*GatewayEvidenceRequestV1, *[]byte){
		"changed result": func(request *GatewayEvidenceRequestV1, _ *[]byte) {
			request.Result = append(append([]byte(nil), request.Result...), ' ')
		},
		"changed run": func(request *GatewayEvidenceRequestV1, _ *[]byte) {
			request.RunID = "run_ffffffffffffffffffffffffffffffff"
		},
		"changed runtime": func(request *GatewayEvidenceRequestV1, _ *[]byte) {
			request.Task.Statement.RuntimeRef = "executor-" + strings.Repeat("f", 64)
		},
		"changed task": func(request *GatewayEvidenceRequestV1, _ *[]byte) {
			request.Task.Statement.TaskID = "other-task"
		},
		"changed receipts": func(_ *GatewayEvidenceRequestV1, receipts *[]byte) {
			changed := append([]byte(nil), (*receipts)...)
			changed[len(changed)-2] ^= 1
			*receipts = changed
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			request := fixture.request
			request.Result = append([]byte(nil), fixture.request.Result...)
			receipts := append([]byte(nil), collected.Receipts...)
			mutate(&request, &receipts)
			if _, err := VerifyGatewayEvidenceV1(request, receipts); err == nil {
				t.Fatal("substituted Gateway evidence accepted")
			} else if !errors.Is(err, ErrEvidenceInvalid) {
				t.Fatalf("substitution error = %v, want ErrEvidenceInvalid", err)
			}
		})
	}
}

func TestGatewayEvidenceV1KeepsIncompleteLifecycleRetryable(t *testing.T) {
	fixture := newGatewayEvidenceFixture(t)
	collected, err := CollectGatewayEvidenceV1(fixture.request, fixture.path)
	if err != nil {
		t.Fatal(err)
	}
	lastLine := bytes.LastIndex(
		collected.Receipts[:len(collected.Receipts)-1], []byte{'\n'},
	)
	if lastLine < 0 {
		t.Fatal("portable Gateway evidence has fewer than two records")
	}
	incomplete := append([]byte(nil), collected.Receipts[:lastLine+1]...)
	if _, err := VerifyGatewayEvidenceV1(
		fixture.request, incomplete,
	); err == nil {
		t.Fatal("incomplete Gateway lifecycle accepted")
	} else if errors.Is(err, ErrEvidenceInvalid) {
		t.Fatalf("incomplete lifecycle was classified as immutable contradiction: %v", err)
	}
}

func TestGatewayEvidenceV1TreatsClosedFailureLifecycleAsInvalid(t *testing.T) {
	fixture := newGatewayEvidenceFixtureWithDispatch(t, false)
	if _, err := CollectGatewayEvidenceV1(
		fixture.request, fixture.path,
	); err == nil {
		t.Fatal("closed Gateway failure lifecycle accepted during collection")
	} else if !errors.Is(err, ErrEvidenceInvalid) {
		t.Fatalf("collection error = %v, want ErrEvidenceInvalid", err)
	}

	var selected []connectorledger.VerifiedReceipt
	_, err := connectorledger.VerifyRecords(
		fixture.path, fixture.request.ReceiptPublicKey,
		"node-a/gateway", fixture.request.ReceiptEpoch,
		func(record connectorledger.VerifiedReceipt) error {
			if record.Receipt.Event.TaskDigest == taskpermit.TaskDigest(
				fixture.request.Task.Statement.TenantID,
				fixture.request.Task.Statement.InstanceID,
				fixture.request.Task.Statement.TaskID,
			) {
				selected = append(selected, record)
			}
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	receipts, err := connectorledger.MarshalPortableTaskEvidence(selected)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyGatewayEvidenceV1(
		fixture.request, receipts,
	); err == nil {
		t.Fatal("closed Gateway failure lifecycle accepted during verification")
	} else if !errors.Is(err, ErrEvidenceInvalid) {
		t.Fatalf("verification error = %v, want ErrEvidenceInvalid", err)
	}
}

func TestGatewayEvidenceV1HonorsCanceledContext(t *testing.T) {
	fixture := newGatewayEvidenceFixture(t)
	collected, err := CollectGatewayEvidenceV1(fixture.request, fixture.path)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := CollectGatewayEvidenceV1Context(
		ctx, fixture.request, fixture.path,
	); !errors.Is(err, context.Canceled) {
		t.Fatalf("collect error=%v, want context canceled", err)
	}
	if _, err := VerifyGatewayEvidenceV1Context(
		ctx, fixture.request, collected.Receipts,
	); !errors.Is(err, context.Canceled) {
		t.Fatalf("verify error=%v, want context canceled", err)
	}
}

func newGatewayEvidenceFixture(t *testing.T) gatewayEvidenceFixture {
	return newGatewayEvidenceFixtureWithDispatch(t, true)
}

func newGatewayEvidenceFixtureWithDispatch(
	t *testing.T,
	includeDispatch bool,
) gatewayEvidenceFixture {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	statement := taskpermit.Statement{
		SchemaVersion: taskpermit.SchemaV1,
		NodeID:        "node-a", TenantID: "tenant-a", InstanceID: "hermes-a",
		RuntimeRef: "executor-" + strings.Repeat("1", 64),
		GrantID:    "grant-" + strings.Repeat("d", 64),
		Generation: 7, CapsuleDigest: testSHA256('8'),
		PolicyDigest: testSHA256('2'), RoutePolicyDigest: testSHA256('9'),
		ServiceID: "hermes-api", OperationID: "hermes.run",
		OperationPolicyDigest: testSHA256('6'),
		TaskID:                "activation-task", RequestDigest: testSHA256('7'),
		RequestBytes: 84, ContentType: "application/json",
		NotBefore: "2026-07-16T12:00:00Z", ExpiresAt: "2026-07-16T12:05:00Z",
	}
	verifiedTask := taskpermit.Verified{
		Statement: statement, KeyID: "tenant-task",
		EnvelopeDigest: testSHA256('5'),
	}
	result := validHermesCanaryResult(t, "steward-activation-activation-001")
	runID := "run_0123456789abcdef0123456789abcdef"
	path := filepath.Join(t.TempDir(), "gateway.ndjson")
	log, err := connectorledger.Open(path, private, "node-a/gateway", 1)
	if err != nil {
		t.Fatal(err)
	}
	authorization := gatewayEvidenceEvent(verifiedTask)
	if _, err := log.Begin(authorization); err != nil {
		t.Fatal(err)
	}
	unrelated := authorization
	unrelated.TaskDigest = testSHA256('a')
	unrelated.PermitDigest = testSHA256('b')
	unrelated.RequestDigest = testSHA256('c')
	unrelated.Phase = connectorledger.Deny
	unrelated.Outcome = connectorledger.Denied
	unrelated.ErrorCode = "policy_denied"
	unrelated.TaskProtocol = ""
	unrelated.Kind = connectorledger.ConnectorCall
	unrelated.ConnectorID = "ticketing"
	unrelated.ServiceID = ""
	unrelated.OperationPolicyDigest = ""
	if _, err := log.Append(unrelated); err != nil {
		t.Fatal(err)
	}
	terminal := authorization
	if includeDispatch {
		dispatch := authorization
		dispatch.Phase, dispatch.Outcome = connectorledger.Dispatch, connectorledger.Responded
		dispatch.HTTPStatus, dispatch.ResponseBytes, dispatch.RunID = 202, 128, runID
		if _, err := log.Dispatch(dispatch); err != nil {
			t.Fatal(err)
		}
		unrelated.TaskDigest = testSHA256('d')
		if _, err := log.Append(unrelated); err != nil {
			t.Fatal(err)
		}
		terminal = dispatch
		terminal.Phase, terminal.HTTPStatus = connectorledger.Terminal, 200
		terminal.ResponseBytes = int64(len(result))
		terminal.TaskStatus = connectorledger.TaskStatusAgentReportedCompleted
		terminal.ResultDigest = dsse.Digest(result)
	} else {
		terminal.Phase = connectorledger.Terminal
		terminal.Outcome = connectorledger.Failed
		terminal.ErrorCode = "upstream_unavailable"
	}
	if _, err := log.Finish(terminal); err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	return gatewayEvidenceFixture{
		path: path,
		request: GatewayEvidenceRequestV1{
			Task:         verifiedTask,
			TaskProtocol: connectorledger.TaskProtocolLifecycleV1,
			RunID:        runID, Result: result,
			ReceiptPublicKey: public, ReceiptEpoch: 1,
		},
	}
}

func gatewayEvidenceEvent(task taskpermit.Verified) connectorledger.Event {
	statement := task.Statement
	return connectorledger.Event{
		Phase: connectorledger.Authorize, Outcome: connectorledger.Allowed,
		Kind:     connectorledger.ServiceTask,
		TenantID: statement.TenantID, RuntimeRef: statement.RuntimeRef,
		CapsuleDigest: statement.CapsuleDigest, PolicyDigest: statement.PolicyDigest,
		RoutePolicyDigest: statement.RoutePolicyDigest, Generation: statement.Generation,
		GrantID: statement.GrantID, ServiceID: statement.ServiceID,
		OperationID:           statement.OperationID,
		OperationPolicyDigest: statement.OperationPolicyDigest,
		TaskDigest:            taskpermit.TaskDigest(statement.TenantID, statement.InstanceID, statement.TaskID),
		AuthorityKeyID:        task.KeyID, PermitDigest: task.EnvelopeDigest,
		RequestDigest: statement.RequestDigest, RequestBytes: statement.RequestBytes,
		TaskProtocol: connectorledger.TaskProtocolLifecycleV1,
	}
}
