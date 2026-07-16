package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"path/filepath"
	"testing"

	"github.com/hardrails/steward/internal/activation"
	"github.com/hardrails/steward/internal/connectorledger"
	"github.com/hardrails/steward/internal/gateway"
	"github.com/hardrails/steward/internal/taskpermit"
)

func TestCollectActivationGatewayEvidenceMakesClosedFailureSticky(t *testing.T) {
	fixture, task := verifiedActivationRunTask(t)
	submit := activationSubmitForTask(task)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	submit.ReceiptPublicKeyBase64 = base64.StdEncoding.EncodeToString(public)

	path := filepath.Join(t.TempDir(), "gateway.ndjson")
	log, err := connectorledger.Open(
		path, private, submit.ReceiptNodeID, submit.ReceiptEpoch,
	)
	if err != nil {
		t.Fatal(err)
	}
	statement := task.Verified.Statement
	event := connectorledger.Event{
		Phase: connectorledger.Authorize, Outcome: connectorledger.Allowed,
		Kind:     connectorledger.ServiceTask,
		TenantID: statement.TenantID, RuntimeRef: statement.RuntimeRef,
		CapsuleDigest:         statement.CapsuleDigest,
		PolicyDigest:          statement.PolicyDigest,
		RoutePolicyDigest:     statement.RoutePolicyDigest,
		Generation:            statement.Generation,
		GrantID:               statement.GrantID,
		ServiceID:             statement.ServiceID,
		OperationID:           statement.OperationID,
		OperationPolicyDigest: statement.OperationPolicyDigest,
		TaskDigest: taskpermit.TaskDigest(
			statement.TenantID, statement.InstanceID, statement.TaskID,
		),
		AuthorityKeyID: task.Verified.KeyID,
		PermitDigest:   task.Verified.EnvelopeDigest,
		RequestDigest:  statement.RequestDigest,
		RequestBytes:   statement.RequestBytes,
		TaskProtocol:   task.Bundle.Operation.TaskProtocol,
	}
	if _, err := log.Begin(event); err != nil {
		t.Fatal(err)
	}
	event.Phase = connectorledger.Terminal
	event.Outcome = connectorledger.Failed
	event.ErrorCode = "upstream_unavailable"
	if _, err := log.Finish(event); err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}

	resultRaw := activationHermesResult(
		t, fixture.inputs.plan.ActivationID, submit.RunID,
	)
	_, err = collectActivationGatewayEvidence(
		context.Background(),
		newActivationRunStore(t),
		task,
		submit,
		resultRaw,
		activationGatewayLocal{
			config: gateway.Config{
				ConnectorReceiptFile:  path,
				ConnectorReceiptEpoch: submit.ReceiptEpoch,
			},
			receiptPublic: public,
		},
	)
	var retained *activationRetainedEvidenceInvalidError
	if !errors.Is(err, activation.ErrEvidenceInvalid) ||
		!errors.As(err, &retained) {
		t.Fatalf(
			"closed failure error = %v, want sticky retained ErrEvidenceInvalid",
			err,
		)
	}
}
