package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/hardrails/steward/internal/activation"
	"github.com/hardrails/steward/internal/agentrelease"
	"github.com/hardrails/steward/internal/connectorledger"
	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/gateway"
	"github.com/hardrails/steward/internal/taskpermit"
)

// verifyActivationTask authenticates a historical task bundle at its signed
// start time, then binds it to the exact post-admission activation challenge.
// Expiry prevents a new dispatch; it does not erase the durable proof identity
// of a task that Gateway already recorded.
func verifyActivationTask(
	raw []byte,
	challenge activation.CanaryChallengeV1,
	admitted permitAdmission,
	inputs verifiedActivationInputs,
	serviceTrustRaw, requestRaw []byte,
) (verifiedTaskBundle, error) {
	contract, err := activationCanaryContract(inputs)
	if err != nil {
		return verifiedTaskBundle{}, err
	}
	if err := challenge.Validate(); err != nil {
		return verifiedTaskBundle{}, err
	}
	if !gateway.TaskAuthoritiesValid(admitted.TaskAuthorities) {
		return verifiedTaskBundle{}, errors.New("activation admission has no valid task-authority set")
	}
	pins, err := activationTaskAuthorities(admitted)
	if err != nil {
		return verifiedTaskBundle{}, err
	}
	if !slices.Equal(pins, challenge.TaskAuthorities) {
		return verifiedTaskBundle{}, errors.New("activation challenge does not pin the exact admitted task authorities")
	}
	if challenge.ServiceTrustDigest != dsse.Digest(serviceTrustRaw) ||
		challenge.RequestDigest != taskpermit.RequestDigest(requestRaw) {
		return verifiedTaskBundle{}, errors.New("activation challenge does not bind the exact service trust and request bytes")
	}
	canonicalAdmission, err := json.Marshal(admitted)
	if err != nil || challenge.AdmissionDigest != dsse.Digest(canonicalAdmission) {
		return verifiedTaskBundle{}, errors.New("activation challenge does not bind the canonical admission response")
	}
	if challenge.ActivationID != inputs.plan.ActivationID ||
		challenge.PlanDigest != dsse.Digest(inputs.planRaw) ||
		challenge.ReleaseDigest != inputs.release.EnvelopeDigest ||
		challenge.IntentDigest != dsse.Digest(inputs.intentRaw) ||
		challenge.TenantID != inputs.intent.TenantID ||
		challenge.NodeID != inputs.intent.NodeID ||
		challenge.InstanceID != inputs.intent.InstanceID ||
		challenge.RuntimeRef != admitted.RuntimeRef ||
		challenge.Generation != inputs.intent.Generation ||
		challenge.GrantID != admitted.GrantID ||
		challenge.ServiceID != contract.ServiceID ||
		challenge.OperationID != contract.OperationID {
		return verifiedTaskBundle{}, errors.New("activation challenge does not match the verified release, intent, and admission")
	}

	var wire taskBundle
	if err := dsse.DecodeStrictInto(raw, maxTaskBundleBytes, &wire); err != nil {
		return verifiedTaskBundle{}, fmt.Errorf("decode activation task bundle: %w", err)
	}
	publicRaw, err := decodeCanonicalBase64(
		wire.Authority.PublicKey, ed25519.PublicKeySize, "task authority public key",
	)
	if err != nil || len(publicRaw) != ed25519.PublicKeySize {
		return verifiedTaskBundle{}, errors.New("activation task authority is not canonical base64 Ed25519")
	}
	public := ed25519.PublicKey(publicRaw)
	if !admissionTrustsTaskKey(admitted.TaskAuthorities, wire.Authority.KeyID, public) {
		return verifiedTaskBundle{}, errors.New("activation task authority is not present in the exact admission response")
	}
	publicDigest := controlprotocol.ExecutorEvidencePublicKeySHA256(public)
	pinned := false
	for _, authority := range challenge.TaskAuthorities {
		if authority.KeyID == wire.Authority.KeyID &&
			authority.PublicKeySHA256 == publicDigest {
			pinned = true
			break
		}
	}
	if !pinned {
		return verifiedTaskBundle{}, errors.New("activation task authority does not match the admitted challenge pin")
	}

	trusted := map[string]ed25519.PublicKey{wire.Authority.KeyID: public}
	permitRaw, err := decodeCanonicalBase64(wire.Permit, taskpermit.MaxEnvelopeBytes, "task permit")
	if err != nil {
		return verifiedTaskBundle{}, err
	}
	payload, keyID, err := dsse.Verify(permitRaw, taskpermit.PayloadType, trusted)
	if err != nil {
		return verifiedTaskBundle{}, fmt.Errorf("authenticate activation task permit: %w", err)
	}
	if keyID != wire.Authority.KeyID {
		return verifiedTaskBundle{}, errors.New("activation task permit key does not match its bundle authority")
	}
	var statement taskpermit.Statement
	if err := dsse.DecodeStrictInto(payload, taskpermit.MaxEnvelopeBytes, &statement); err != nil {
		return verifiedTaskBundle{}, fmt.Errorf("decode activation task permit: %w", err)
	}
	notBefore, err := parsePermitTime(statement.NotBefore)
	if err != nil {
		return verifiedTaskBundle{}, fmt.Errorf("activation task not_before: %w", err)
	}
	verified, err := decodeTaskBundle(raw, trusted, notBefore, taskpermit.MaxValidity)
	if err != nil {
		return verifiedTaskBundle{}, fmt.Errorf("verify historical activation task: %w", err)
	}
	if verified.Bundle.Operation.TaskProtocol != connectorledger.TaskProtocolLifecycleV1 {
		return verifiedTaskBundle{}, errors.New("activation task does not use the required lifecycle protocol")
	}

	operation, err := decodeServiceTrust(serviceTrustRaw, inputs.intent, contract.OperationID)
	if err != nil {
		return verifiedTaskBundle{}, err
	}
	expectedRequest, err := agentrelease.BuildCanaryRequest(
		inputs.release.Release.Canary.Request, inputs.plan.ActivationID,
	)
	if err != nil {
		return verifiedTaskBundle{}, err
	}
	if verified.Bundle.Operation != operation ||
		verified.Bundle.ServicePath != admitted.ServicePath ||
		!bytes.Equal(verified.Request, requestRaw) ||
		!bytes.Equal(requestRaw, expectedRequest) {
		return verifiedTaskBundle{}, errors.New("activation task transport does not match the exact trusted operation and canary request")
	}

	statement = verified.Verified.Statement
	if statement.NodeID != inputs.intent.NodeID ||
		statement.TenantID != inputs.intent.TenantID ||
		statement.InstanceID != inputs.intent.InstanceID ||
		statement.RuntimeRef != admitted.RuntimeRef ||
		statement.GrantID != admitted.GrantID ||
		statement.Generation != inputs.intent.Generation ||
		statement.CapsuleDigest != admitted.CapsuleDigest ||
		statement.PolicyDigest != admitted.PolicyDigest ||
		statement.RoutePolicyDigest != admitted.RoutePolicyDigest ||
		statement.ServiceID != contract.ServiceID ||
		statement.OperationID != contract.OperationID ||
		statement.OperationPolicyDigest != operation.PolicyDigest ||
		statement.RequestDigest != challenge.RequestDigest ||
		statement.RequestBytes != int64(len(requestRaw)) ||
		statement.ContentType != operation.ContentType {
		return verifiedTaskBundle{}, errors.New("activation task permit does not match every release, admission, service, and request binding")
	}
	challengeTime, err := time.Parse(time.RFC3339Nano, challenge.CreatedAt)
	if err != nil {
		return verifiedTaskBundle{}, errors.New("activation challenge time is invalid")
	}
	expiresAt, err := parsePermitTime(statement.ExpiresAt)
	if err != nil || !challengeTime.Before(expiresAt) {
		return verifiedTaskBundle{}, errors.New("activation task permit was not valid after the challenge was created")
	}
	capsuleExpiresAt, err := time.Parse(
		time.RFC3339Nano, inputs.release.Capsule.ExpiresAt,
	)
	if err != nil || expiresAt.After(capsuleExpiresAt) {
		return verifiedTaskBundle{}, errors.New(
			"activation task permit must expire no later than the signed capsule",
		)
	}
	return verified, nil
}

// verifyActivationTaskAt re-evaluates the exact retained task permit at a
// signed service-receipt time. The initial task verification establishes
// identity and activation bindings; this check proves the permit was valid
// when Gateway authorized it.
func verifyActivationTaskAt(
	task verifiedTaskBundle,
	observedAt string,
) error {
	at, err := time.Parse(time.RFC3339Nano, observedAt)
	if err != nil || at.UTC().Format(time.RFC3339Nano) != observedAt {
		return errors.New("Gateway authorization time is not canonical UTC RFC3339Nano")
	}
	verified, err := decodeTaskBundleRaw(
		bundleRaw(task.Bundle),
		map[string]ed25519.PublicKey{
			task.Bundle.Authority.KeyID: task.Public,
		},
		at,
		taskpermit.MaxValidity,
	)
	if err != nil {
		return fmt.Errorf("activation task permit was not valid at signed Gateway authorization time: %w", err)
	}
	if verified.Verified.EnvelopeDigest != task.Verified.EnvelopeDigest {
		return errors.New("activation task identity changed during signed-time verification")
	}
	return nil
}
