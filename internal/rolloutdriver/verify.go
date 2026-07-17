package rolloutdriver

import (
	"crypto/ed25519"
	"encoding/base64"
	"time"

	"github.com/hardrails/steward/internal/activation"
	"github.com/hardrails/steward/internal/activationcanary"
	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/gateway"
	"github.com/hardrails/steward/internal/taskpermit"
)

// VerifyCanaryInputV1 contains the retained, public companions needed to
// qualify one rollout target without contacting a node, controller, Gateway,
// or Hermes. CommandRaw and ResultRaw must be their exact canonical JSON
// encodings. ReceiptPublicKey is independent trust input, not a key learned
// from either retained projection.
type VerifyCanaryInputV1 struct {
	Prepared         PreparedTargetV1
	Admission        controlprotocol.ExecutorAdmissionProjectionV1
	CommandRaw       []byte
	ResultRaw        []byte
	ReceiptPublicKey ed25519.PublicKey
}

// VerifiedCanaryV1 is constructible only after the closed command, tenant
// permit, Hermes result, Gateway receipt chain, rollout bindings, and derived
// activation checkpoint all verify. Accessors return values or detached bytes.
type VerifiedCanaryV1 struct {
	command       activationcanary.CommandV1
	commandRaw    []byte
	result        activationcanary.ResultV1
	resultRaw     []byte
	checkpoint    activation.ExecutorCheckpointV1
	checkpointRaw []byte
}

// VerifyCanaryV1 independently verifies retained remote-canary artifacts for
// one prepared rollout target. It has no clock or I/O dependency: historical
// permit validity is established at the command deadline, while signed Gateway
// receipt times prove that execution occurred inside that authorized window.
func VerifyCanaryV1(input VerifyCanaryInputV1) (VerifiedCanaryV1, error) {
	prepared := input.Prepared
	admissionProjection := cloneAdmissionProjection(input.Admission)
	commandRaw := append([]byte(nil), input.CommandRaw...)
	resultRaw := append([]byte(nil), input.ResultRaw...)
	receiptPublic := append(ed25519.PublicKey(nil), input.ReceiptPublicKey...)
	if err := validateProjection(prepared, admissionProjection); err != nil {
		return VerifiedCanaryV1{}, err
	}
	if len(receiptPublic) != ed25519.PublicKeySize ||
		controlprotocol.ExecutorEvidencePublicKeySHA256(receiptPublic) !=
			prepared.target.GatewayReceiptPublicKeySHA256 {
		return VerifiedCanaryV1{}, invalid("Gateway receipt public key does not match the rollout target")
	}

	context := activationcanary.AdmissionContextV1{
		NodeID:     prepared.target.NodeID,
		TenantID:   prepared.plan.TenantID,
		InstanceID: prepared.target.InstanceID,
		Projection: admissionProjection,
	}
	verifiedCommand, err := activationcanary.VerifyHistoricalCommandV1(
		commandRaw,
		context,
		taskpermit.MaxValidity,
	)
	if err != nil {
		return VerifiedCanaryV1{}, invalid("historically verify closed canary: %v", err)
	}
	command := verifiedCommand.Command()
	permit := verifiedCommand.Permit().Statement
	if permit.TaskID != prepared.target.CanaryCommandID ||
		permit.OperationPolicyDigest != prepared.target.OperationPolicyDigest ||
		command.ReceiptAuthority.NodeID != gateway.ServiceTaskReceiptNodeID(prepared.target.NodeID) ||
		command.ReceiptAuthority.Epoch != prepared.target.GatewayReceiptEpoch ||
		command.ReceiptAuthority.PublicKeySHA256 != prepared.target.GatewayReceiptPublicKeySHA256 ||
		command.ExecutorBeginBase64 != base64.StdEncoding.EncodeToString(prepared.executorBeginRaw) {
		return VerifiedCanaryV1{}, invalid("closed canary does not match the prepared rollout target")
	}
	createdAt, createdErr := time.Parse(time.RFC3339Nano, prepared.plan.CreatedAt)
	deadline, deadlineErr := time.Parse(time.RFC3339Nano, prepared.plan.Deadline)
	permitNotBefore, notBeforeErr := time.Parse(time.RFC3339, permit.NotBefore)
	permitExpires, expiresErr := time.Parse(time.RFC3339, permit.ExpiresAt)
	canaryCeiling := permitNotBefore.Add(
		time.Duration(prepared.activationPlan.Timeouts.CanarySeconds)*time.Second +
			time.Second - time.Nanosecond,
	)
	// Task permits carry whole-second timestamps. Compare created_at at the
	// same precision so a command issued in the plan's first second remains
	// verifiable without accepting authority from an earlier second.
	createdAtPermitPrecision := createdAt.Truncate(time.Second)
	if createdErr != nil || deadlineErr != nil || notBeforeErr != nil || expiresErr != nil ||
		permitNotBefore.Before(createdAtPermitPrecision) || permitExpires.After(deadline) ||
		verifiedCommand.Deadline().After(deadline) || verifiedCommand.Deadline().After(canaryCeiling) ||
		(!prepared.capsuleExpiresAt.IsZero() && permitExpires.After(prepared.capsuleExpiresAt)) {
		return VerifiedCanaryV1{}, invalid("closed canary authority is outside the prepared rollout interval")
	}

	verifiedResult, err := activationcanary.VerifyResultV1(
		verifiedCommand,
		resultRaw,
		receiptPublic,
	)
	if err != nil {
		return VerifiedCanaryV1{}, invalid("verify closed canary result: %v", err)
	}
	checkpointRaw, err := activation.MarshalExecutorCheckpointV1(
		prepared.binding,
		admissionProjection.RuntimeRef,
		admissionProjection.CapsuleDigest,
		admissionProjection.RoutePolicyDigest,
		admissionProjection.GrantID,
		verifiedResult.Gateway(),
	)
	if err != nil {
		return VerifiedCanaryV1{}, invalid("reconstruct activation checkpoint: %v", err)
	}
	if err := activationcanary.VerifyCheckpointV1(
		verifiedCommand,
		verifiedResult,
		checkpointRaw,
	); err != nil {
		return VerifiedCanaryV1{}, invalid("verify reconstructed activation checkpoint: %v", err)
	}
	checkpoint, err := activation.ParseExecutorCheckpointV1(checkpointRaw)
	if err != nil {
		return VerifiedCanaryV1{}, invalid("parse reconstructed activation checkpoint: %v", err)
	}

	return VerifiedCanaryV1{
		command:       cloneCanary(command),
		commandRaw:    commandRaw,
		result:        verifiedResult.Result(),
		resultRaw:     resultRaw,
		checkpoint:    checkpoint,
		checkpointRaw: append([]byte(nil), checkpointRaw...),
	}, nil
}

// Command returns a deep copy of the verified closed command.
func (verified VerifiedCanaryV1) Command() activationcanary.CommandV1 {
	return cloneCanary(verified.command)
}

// CommandRaw returns a detached copy of the exact verified command JSON.
func (verified VerifiedCanaryV1) CommandRaw() []byte {
	return append([]byte(nil), verified.commandRaw...)
}

// Result returns the verified bounded result projection.
func (verified VerifiedCanaryV1) Result() activationcanary.ResultV1 {
	return verified.result
}

// ResultRaw returns a detached copy of the exact verified result JSON.
func (verified VerifiedCanaryV1) ResultRaw() []byte {
	return append([]byte(nil), verified.resultRaw...)
}

// Checkpoint returns the deterministic checkpoint reconstructed from the
// authenticated rollout, admission, Gateway, and Hermes evidence.
func (verified VerifiedCanaryV1) Checkpoint() activation.ExecutorCheckpointV1 {
	return verified.checkpoint
}

// CheckpointRaw returns a detached copy of the canonical checkpoint JSON.
func (verified VerifiedCanaryV1) CheckpointRaw() []byte {
	return append([]byte(nil), verified.checkpointRaw...)
}

func cloneAdmissionProjection(
	projection controlprotocol.ExecutorAdmissionProjectionV1,
) controlprotocol.ExecutorAdmissionProjectionV1 {
	projection.TaskAuthorities = append(
		[]controlprotocol.ExecutorTaskAuthorityV1(nil), projection.TaskAuthorities...,
	)
	projection.EgressRouteIDs = append([]string(nil), projection.EgressRouteIDs...)
	projection.ConnectorIDs = append([]string(nil), projection.ConnectorIDs...)
	return projection
}
