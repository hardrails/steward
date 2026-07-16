package activation

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/hardrails/steward/internal/connectorledger"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/gateway"
	"github.com/hardrails/steward/internal/taskpermit"
)

// GatewayEvidenceRequestV1 carries an already verified task permit and the
// exact terminal bytes independently checked against the closed Hermes canary.
type GatewayEvidenceRequestV1 struct {
	Task             taskpermit.Verified
	TaskProtocol     string
	RunID            string
	Result           []byte
	ReceiptPublicKey ed25519.PublicKey
	ReceiptEpoch     uint64
}

// GatewayEvidenceResultV1 retains only the three task-local signed receipts,
// their terminal coordinate, and the exact digests needed by ProofV1.
type GatewayEvidenceResultV1 struct {
	Receipts     []byte
	Coordinate   ReceiptCoordinateV1
	Canary       CanaryProofV1
	AuthorizedAt string
	TerminalAt   string
}

// CollectGatewayEvidenceV1 verifies the complete local Gateway ledger before
// extracting the exact authorize, dispatch, and terminal lines for one task.
func CollectGatewayEvidenceV1(
	request GatewayEvidenceRequestV1,
	receiptLedgerPath string,
) (GatewayEvidenceResultV1, error) {
	return CollectGatewayEvidenceV1Context(
		context.Background(), request, receiptLedgerPath,
	)
}

// CollectGatewayEvidenceV1Context is CollectGatewayEvidenceV1 with
// cancellation checks before validation, during every ledger visit, and before
// portable receipt verification.
func CollectGatewayEvidenceV1Context(
	ctx context.Context,
	request GatewayEvidenceRequestV1,
	receiptLedgerPath string,
) (GatewayEvidenceResultV1, error) {
	if err := activationContextError(ctx); err != nil {
		return GatewayEvidenceResultV1{}, err
	}
	expectation, err := validateGatewayEvidenceRequest(request)
	if err != nil {
		return GatewayEvidenceResultV1{}, invalidEvidence(err)
	}
	if receiptLedgerPath == "" {
		return GatewayEvidenceResultV1{}, errors.New("Gateway receipt ledger path is required")
	}
	info, err := os.Lstat(receiptLedgerPath)
	if err != nil {
		return GatewayEvidenceResultV1{}, fmt.Errorf("inspect Gateway receipt ledger: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 ||
		info.Size() < 0 || info.Size() > connectorledger.MaxLogBytes {
		return GatewayEvidenceResultV1{}, errors.New("Gateway receipt ledger must be a bounded owner-only regular file")
	}
	var selected []connectorledger.VerifiedReceipt
	_, err = connectorledger.VerifyRecords(
		receiptLedgerPath, request.ReceiptPublicKey,
		expectation.receiptNodeID, request.ReceiptEpoch,
		func(record connectorledger.VerifiedReceipt) error {
			if err := activationContextError(ctx); err != nil {
				return err
			}
			event := record.Receipt.Event
			taskMatch := event.TaskDigest == expectation.taskDigest
			permitMatch := event.PermitDigest == request.Task.EnvelopeDigest
			if taskMatch != permitMatch {
				return invalidEvidence(errors.New(
					"Gateway ledger contains a partial task or permit identity collision",
				))
			}
			if taskMatch {
				selected = append(selected, record)
			}
			return nil
		},
	)
	if err != nil {
		return GatewayEvidenceResultV1{}, fmt.Errorf("verify Gateway receipt ledger: %w", err)
	}
	raw, err := connectorledger.MarshalPortableTaskEvidence(selected)
	if err != nil {
		if errors.Is(err, connectorledger.ErrPortableTaskEvidenceIncomplete) {
			return GatewayEvidenceResultV1{}, err
		}
		return GatewayEvidenceResultV1{}, invalidEvidence(
			fmt.Errorf("extract portable Gateway task evidence: %w", err),
		)
	}
	return VerifyGatewayEvidenceV1Context(ctx, request, raw)
}

// VerifyGatewayEvidenceV1 authenticates a portable task-local receipt chain
// without requiring unrelated tenants' Gateway records.
func VerifyGatewayEvidenceV1(
	request GatewayEvidenceRequestV1,
	receipts []byte,
) (GatewayEvidenceResultV1, error) {
	return VerifyGatewayEvidenceV1Context(
		context.Background(), request, receipts,
	)
}

// VerifyGatewayEvidenceV1Context is VerifyGatewayEvidenceV1 with bounded
// cancellation checks around portable receipt verification.
func VerifyGatewayEvidenceV1Context(
	ctx context.Context,
	request GatewayEvidenceRequestV1,
	receipts []byte,
) (GatewayEvidenceResultV1, error) {
	if err := activationContextError(ctx); err != nil {
		return GatewayEvidenceResultV1{}, err
	}
	expectation, err := validateGatewayEvidenceRequest(request)
	if err != nil {
		return GatewayEvidenceResultV1{}, invalidEvidence(err)
	}
	verified, err := connectorledger.VerifyPortableTaskEvidence(
		receipts, request.ReceiptPublicKey,
		expectation.receiptNodeID, request.ReceiptEpoch,
		expectation.taskDigest, request.Task.EnvelopeDigest,
	)
	if err != nil {
		if errors.Is(err, connectorledger.ErrPortableTaskEvidenceIncomplete) {
			return GatewayEvidenceResultV1{}, err
		}
		return GatewayEvidenceResultV1{}, invalidEvidence(
			fmt.Errorf("verify portable Gateway task evidence: %w", err),
		)
	}
	if err := activationContextError(ctx); err != nil {
		return GatewayEvidenceResultV1{}, err
	}
	if len(verified.Records) != 3 {
		return GatewayEvidenceResultV1{}, invalidEvidence(
			errors.New("Gateway evidence does not prove authorize, dispatch, and terminal phases"),
		)
	}
	statement := request.Task.Statement
	for index, record := range verified.Records {
		if err := gatewayReceiptMatchesTask(
			record.Receipt.Event, statement, request.Task.KeyID,
			request.Task.EnvelopeDigest, request.TaskProtocol,
		); err != nil {
			return GatewayEvidenceResultV1{}, invalidEvidence(
				fmt.Errorf("Gateway task receipt %d: %w", index+1, err),
			)
		}
	}
	dispatch := verified.Records[1].Receipt.Event
	terminal := verified.Records[2].Receipt.Event
	authorizedAt, _ := time.Parse(
		time.RFC3339Nano, verified.Records[0].Receipt.ObservedAt,
	)
	dispatchedAt, _ := time.Parse(
		time.RFC3339Nano, verified.Records[1].Receipt.ObservedAt,
	)
	terminalAt, _ := time.Parse(
		time.RFC3339Nano, verified.Records[2].Receipt.ObservedAt,
	)
	if dispatchedAt.Before(authorizedAt) || terminalAt.Before(dispatchedAt) {
		return GatewayEvidenceResultV1{}, invalidEvidence(
			errors.New("Gateway task receipt times are not monotonic"),
		)
	}
	resultDigest := dsse.Digest(request.Result)
	if dispatch.Phase != connectorledger.Dispatch ||
		dispatch.RunID != request.RunID ||
		terminal.Phase != connectorledger.Terminal ||
		terminal.Outcome != connectorledger.Responded ||
		terminal.TaskStatus != connectorledger.TaskStatusAgentReportedCompleted ||
		terminal.RunID != request.RunID ||
		terminal.ResultDigest != resultDigest ||
		terminal.ResponseBytes != int64(len(request.Result)) {
		return GatewayEvidenceResultV1{}, invalidEvidence(
			errors.New("Gateway terminal evidence does not match the verified Hermes result"),
		)
	}
	coordinate := ReceiptCoordinateV1{
		ReceiptNodeID:   verified.Terminal.NodeID,
		ReceiptEpoch:    verified.Terminal.Epoch,
		Sequence:        verified.Terminal.Sequence,
		ChainHash:       verified.Terminal.ChainHash,
		PublicKeySHA256: publicKeySHA256(request.ReceiptPublicKey),
	}
	canary := CanaryProofV1{
		Kind:         CanaryHermesWorkspaceAuditV1,
		TaskDigest:   expectation.taskDigest,
		PermitDigest: request.Task.EnvelopeDigest,
		ResultDigest: resultDigest,
		ResultBytes:  int64(len(request.Result)),
	}
	return GatewayEvidenceResultV1{
		Receipts:     append([]byte(nil), receipts...),
		Coordinate:   coordinate,
		Canary:       canary,
		AuthorizedAt: verified.Records[0].Receipt.ObservedAt,
		TerminalAt:   verified.Records[2].Receipt.ObservedAt,
	}, nil
}

type gatewayEvidenceExpectation struct {
	taskDigest    string
	receiptNodeID string
}

func validateGatewayEvidenceRequest(
	request GatewayEvidenceRequestV1,
) (gatewayEvidenceExpectation, error) {
	statement := request.Task.Statement
	if request.TaskProtocol != connectorledger.TaskProtocolLifecycleV1 ||
		!identifier(request.RunID) ||
		len(request.Result) == 0 || int64(len(request.Result)) > MaxCanaryResultBytes ||
		len(request.ReceiptPublicKey) != ed25519.PublicKeySize ||
		request.ReceiptEpoch == 0 ||
		request.Task.KeyID == "" || !sha256Digest(request.Task.EnvelopeDigest) ||
		!publicIdentity(statement.NodeID, 128) ||
		!publicIdentity(statement.TenantID, 128) ||
		!publicIdentity(statement.InstanceID, 256) ||
		!runtimeRef(statement.RuntimeRef) ||
		!grantIDPattern.MatchString(statement.GrantID) ||
		statement.Generation == 0 ||
		!sha256Digest(statement.CapsuleDigest) ||
		!sha256Digest(statement.PolicyDigest) ||
		!sha256Digest(statement.RoutePolicyDigest) ||
		!sha256Digest(statement.OperationPolicyDigest) ||
		!sha256Digest(statement.RequestDigest) ||
		statement.ServiceID == "" || statement.OperationID == "" ||
		statement.TaskID == "" || statement.RequestBytes <= 0 {
		return gatewayEvidenceExpectation{}, errors.New("Gateway evidence request contains an invalid verified task binding")
	}
	return gatewayEvidenceExpectation{
		taskDigest: taskpermit.TaskDigest(
			statement.TenantID, statement.InstanceID, statement.TaskID,
		),
		receiptNodeID: gateway.ServiceTaskReceiptNodeID(statement.NodeID),
	}, nil
}

func gatewayReceiptMatchesTask(
	event connectorledger.Event,
	statement taskpermit.Statement,
	authorityKeyID string,
	permitDigest string,
	taskProtocol string,
) error {
	if event.Kind != connectorledger.ServiceTask ||
		event.TenantID != statement.TenantID ||
		event.RuntimeRef != statement.RuntimeRef ||
		event.CapsuleDigest != statement.CapsuleDigest ||
		event.PolicyDigest != statement.PolicyDigest ||
		event.RoutePolicyDigest != statement.RoutePolicyDigest ||
		event.Generation != statement.Generation ||
		event.GrantID != statement.GrantID ||
		event.ConnectorID != "" ||
		event.ServiceID != statement.ServiceID ||
		event.OperationID != statement.OperationID ||
		event.OperationPolicyDigest != statement.OperationPolicyDigest ||
		event.TaskDigest != taskpermit.TaskDigest(
			statement.TenantID, statement.InstanceID, statement.TaskID,
		) ||
		event.AuthorityKeyID != authorityKeyID ||
		event.PermitDigest != permitDigest ||
		event.RequestDigest != statement.RequestDigest ||
		event.RequestBytes != statement.RequestBytes ||
		event.TaskProtocol != taskProtocol {
		return errors.New("receipt does not match every task-permit binding")
	}
	return nil
}

func publicKeySHA256(public ed25519.PublicKey) string {
	sum := sha256.Sum256(public)
	return "sha256:" + hex.EncodeToString(sum[:])
}
