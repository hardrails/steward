package rollout

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/dsse"
)

const (
	PlanAuthorizationSchemaV1      = "steward.rollout-plan-authorization.v1"
	PlanAuthorizationPayloadTypeV1 = "application/vnd.steward.rollout-plan-authorization.v1+json"
	BatchPromotionSchemaV1         = "steward.rollout-batch-promotion.v1"
	BatchPromotionPayloadTypeV1    = "application/vnd.steward.rollout-batch-promotion.v1+json"

	MaxPlanAuthorizationEnvelopeBytes = 16 << 10
	MaxBatchPromotionEnvelopeBytes    = 128 << 10
)

var ErrInvalidAuthorization = errors.New("invalid rollout authorization")

// PlanAuthorizationV1 is the tenant command signer's exact authorization of
// one immutable rollout plan. It grants no authority outside the signed site
// policy scopes already held by the signing key.
type PlanAuthorizationV1 struct {
	SchemaVersion string `json:"schema_version"`
	CommandID     string `json:"command_id"`
	RolloutID     string `json:"rollout_id"`
	TenantID      string `json:"tenant_id"`
	PlanDigest    string `json:"plan_digest"`
	AuthorizedAt  string `json:"authorized_at"`
}

// BatchBoundaryV1 is one exact half-open range from PlanV1.Batches.
type BatchBoundaryV1 struct {
	Number uint16 `json:"number"`
	Start  uint16 `json:"start"`
	End    uint16 `json:"end"`
}

// CompletedPromotionTargetV1 binds the passed checkpoint and the two exact
// evidence exports whose verification qualified one prior-batch target.
type CompletedPromotionTargetV1 struct {
	TargetIndex           uint16 `json:"target_index"`
	NodeID                string `json:"node_id"`
	ActivationID          string `json:"activation_id"`
	TargetStateDigest     string `json:"target_state_digest"`
	ActivationProofDigest string `json:"activation_proof_digest"`
	CaptureExportDigest   string `json:"capture_export_digest"`
}

// BatchPromotionV1 authorizes entry into NextBatch and binds the exact passed
// evidence for the immediately preceding batch. PreviousPromotionDigest makes
// the sequence a single unambiguous authorization chain.
type BatchPromotionV1 struct {
	SchemaVersion           string                       `json:"schema_version"`
	CommandID               string                       `json:"command_id"`
	RolloutID               string                       `json:"rollout_id"`
	TenantID                string                       `json:"tenant_id"`
	PlanDigest              string                       `json:"plan_digest"`
	PlanAuthorizationDigest string                       `json:"plan_authorization_digest"`
	PreviousPromotionDigest string                       `json:"previous_promotion_digest"`
	CompletedBatch          BatchBoundaryV1              `json:"completed_batch"`
	CompletedTargets        []CompletedPromotionTargetV1 `json:"completed_targets"`
	NextBatch               BatchBoundaryV1              `json:"next_batch"`
	AuthorizedAt            string                       `json:"authorized_at"`
}

// VerifiedPlanAuthorizationV1 retains authenticated statement and envelope
// identity without exposing mutable aliases.
type VerifiedPlanAuthorizationV1 struct {
	Statement      PlanAuthorizationV1
	KeyID          string
	EnvelopeDigest string
}

// VerifiedBatchPromotionV1 retains authenticated statement and envelope
// identity without treating the envelope as execution evidence.
type VerifiedBatchPromotionV1 struct {
	Statement      BatchPromotionV1
	KeyID          string
	EnvelopeDigest string
}

func NewPlanAuthorizationV1(planRaw []byte, authorizedAt time.Time) (PlanAuthorizationV1, error) {
	plan, err := ParsePlanV1(planRaw)
	if err != nil {
		return PlanAuthorizationV1{}, invalidAuthorization("plan: %v", err)
	}
	planDigest := dsse.Digest(planRaw)
	statement := PlanAuthorizationV1{
		SchemaVersion: PlanAuthorizationSchemaV1,
		CommandID:     PlanAuthorizationCommandIDV1(plan.RolloutID, planDigest),
		RolloutID:     plan.RolloutID,
		TenantID:      plan.TenantID,
		PlanDigest:    planDigest,
		AuthorizedAt:  authorizedAt.UTC().Format(time.RFC3339Nano),
	}
	if err := CorrelatePlanAuthorizationV1(planRaw, statement); err != nil {
		return PlanAuthorizationV1{}, err
	}
	return statement, nil
}

func (statement PlanAuthorizationV1) Validate() error {
	if statement.SchemaVersion != PlanAuthorizationSchemaV1 ||
		!identifier(statement.CommandID) ||
		!identifier(statement.RolloutID) ||
		!publicIdentity(statement.TenantID, 128) ||
		!controlprotocol.ValidSHA256Digest(statement.PlanDigest) {
		return invalidAuthorization("plan authorization identity is invalid")
	}
	if _, ok := canonicalTimestamp(statement.AuthorizedAt); !ok {
		return invalidAuthorization("authorized_at must be canonical UTC RFC3339Nano")
	}
	return nil
}

func CorrelatePlanAuthorizationV1(planRaw []byte, statement PlanAuthorizationV1) error {
	plan, err := ParsePlanV1(planRaw)
	if err != nil {
		return invalidAuthorization("plan: %v", err)
	}
	if err := statement.Validate(); err != nil {
		return err
	}
	planDigest := dsse.Digest(planRaw)
	if statement.CommandID != PlanAuthorizationCommandIDV1(plan.RolloutID, planDigest) ||
		statement.RolloutID != plan.RolloutID ||
		statement.TenantID != plan.TenantID ||
		statement.PlanDigest != planDigest {
		return invalidAuthorization("plan authorization does not identify the exact rollout plan")
	}
	return validateAuthorizationTime(plan, statement.AuthorizedAt)
}

func SignPlanAuthorizationV1(
	statement PlanAuthorizationV1,
	keyID string,
	private ed25519.PrivateKey,
	public ed25519.PublicKey,
) ([]byte, error) {
	if err := statement.Validate(); err != nil {
		return nil, err
	}
	return signAuthorizationEnvelope(
		PlanAuthorizationPayloadTypeV1, statement, keyID, private, public,
		MaxPlanAuthorizationEnvelopeBytes,
	)
}

func VerifyPlanAuthorizationV1(
	planRaw []byte,
	raw []byte,
	trusted map[string]ed25519.PublicKey,
) (VerifiedPlanAuthorizationV1, error) {
	var statement PlanAuthorizationV1
	keyID, err := verifyAuthorizationEnvelope(
		raw, PlanAuthorizationPayloadTypeV1, trusted,
		MaxPlanAuthorizationEnvelopeBytes, &statement,
	)
	if err != nil {
		return VerifiedPlanAuthorizationV1{}, err
	}
	if err := CorrelatePlanAuthorizationV1(planRaw, statement); err != nil {
		return VerifiedPlanAuthorizationV1{}, err
	}
	return VerifiedPlanAuthorizationV1{
		Statement: statement, KeyID: keyID, EnvelopeDigest: dsse.Digest(raw),
	}, nil
}

func NewBatchPromotionV1(
	planRaw []byte,
	planAuthorizationRaw []byte,
	previousPromotionRaw []byte,
	nextBatchNumber uint16,
	targetStateRaws [][]byte,
	activationProofRaws [][]byte,
	captureExportRaws [][]byte,
	authorizedAt time.Time,
) (BatchPromotionV1, error) {
	plan, err := ParsePlanV1(planRaw)
	if err != nil {
		return BatchPromotionV1{}, invalidAuthorization("plan: %v", err)
	}
	batches, err := plan.Batches()
	if err != nil || nextBatchNumber == 0 || int(nextBatchNumber) >= len(batches) {
		return BatchPromotionV1{}, invalidAuthorization("next batch is outside the rollout plan")
	}
	if len(targetStateRaws) != len(plan.Targets) ||
		len(activationProofRaws) != len(plan.Targets) ||
		len(captureExportRaws) != len(plan.Targets) {
		return BatchPromotionV1{}, invalidAuthorization("promotion companions are incomplete")
	}
	completed := batches[int(nextBatchNumber)-1]
	next := batches[int(nextBatchNumber)]
	targets := make([]CompletedPromotionTargetV1, 0, completed.End-completed.Start)
	for index := completed.Start; index < completed.End; index++ {
		state, parseErr := ParseTargetStateV1(targetStateRaws[index])
		if parseErr != nil || state.Phase != PhasePassed ||
			CorrelateTargetStateV1(planRaw, state) != nil ||
			len(activationProofRaws[index]) == 0 || len(captureExportRaws[index]) == 0 {
			return BatchPromotionV1{}, invalidAuthorization("completed target %d companions are invalid", index)
		}
		target := plan.Targets[index]
		targets = append(targets, CompletedPromotionTargetV1{
			TargetIndex:           uint16(index),
			NodeID:                target.NodeID,
			ActivationID:          target.ActivationID,
			TargetStateDigest:     dsse.Digest(targetStateRaws[index]),
			ActivationProofDigest: dsse.Digest(activationProofRaws[index]),
			CaptureExportDigest:   dsse.Digest(captureExportRaws[index]),
		})
	}
	planDigest := dsse.Digest(planRaw)
	previousDigest := ""
	if len(previousPromotionRaw) != 0 {
		previousDigest = dsse.Digest(previousPromotionRaw)
	}
	statement := BatchPromotionV1{
		SchemaVersion:           BatchPromotionSchemaV1,
		CommandID:               BatchPromotionCommandIDV1(plan.RolloutID, planDigest, nextBatchNumber),
		RolloutID:               plan.RolloutID,
		TenantID:                plan.TenantID,
		PlanDigest:              planDigest,
		PlanAuthorizationDigest: dsse.Digest(planAuthorizationRaw),
		PreviousPromotionDigest: previousDigest,
		CompletedBatch:          batchBoundary(completed),
		CompletedTargets:        targets,
		NextBatch:               batchBoundary(next),
		AuthorizedAt:            authorizedAt.UTC().Format(time.RFC3339Nano),
	}
	if err := CorrelateBatchPromotionV1(
		planRaw, planAuthorizationRaw, previousPromotionRaw, statement,
		targetStateRaws, activationProofRaws, captureExportRaws,
	); err != nil {
		return BatchPromotionV1{}, err
	}
	return statement, nil
}

func (statement BatchPromotionV1) Validate() error {
	if statement.SchemaVersion != BatchPromotionSchemaV1 ||
		!identifier(statement.CommandID) || !identifier(statement.RolloutID) ||
		!publicIdentity(statement.TenantID, 128) ||
		!controlprotocol.ValidSHA256Digest(statement.PlanDigest) ||
		!controlprotocol.ValidSHA256Digest(statement.PlanAuthorizationDigest) ||
		(statement.PreviousPromotionDigest != "" &&
			!controlprotocol.ValidSHA256Digest(statement.PreviousPromotionDigest)) {
		return invalidAuthorization("batch promotion identity is invalid")
	}
	if !validBatchBoundary(statement.CompletedBatch) ||
		!validBatchBoundary(statement.NextBatch) ||
		statement.NextBatch.Number != statement.CompletedBatch.Number+1 ||
		statement.NextBatch.Start != statement.CompletedBatch.End {
		return invalidAuthorization("batch promotion boundaries are invalid")
	}
	count := int(statement.CompletedBatch.End - statement.CompletedBatch.Start)
	if len(statement.CompletedTargets) != count || count <= 0 || count > MaxBatchSize {
		return invalidAuthorization("completed target inventory is invalid")
	}
	for offset, target := range statement.CompletedTargets {
		expected := statement.CompletedBatch.Start + uint16(offset)
		if target.TargetIndex != expected || !publicIdentity(target.NodeID, 128) ||
			!identifier(target.ActivationID) ||
			!controlprotocol.ValidSHA256Digest(target.TargetStateDigest) ||
			!controlprotocol.ValidSHA256Digest(target.ActivationProofDigest) ||
			!controlprotocol.ValidSHA256Digest(target.CaptureExportDigest) {
			return invalidAuthorization("completed target %d is invalid or out of order", offset)
		}
	}
	if _, ok := canonicalTimestamp(statement.AuthorizedAt); !ok {
		return invalidAuthorization("authorized_at must be canonical UTC RFC3339Nano")
	}
	return nil
}

func CorrelateBatchPromotionV1(
	planRaw []byte,
	planAuthorizationRaw []byte,
	previousPromotionRaw []byte,
	statement BatchPromotionV1,
	targetStateRaws [][]byte,
	activationProofRaws [][]byte,
	captureExportRaws [][]byte,
) error {
	plan, err := ParsePlanV1(planRaw)
	if err != nil {
		return invalidAuthorization("plan: %v", err)
	}
	if err := statement.Validate(); err != nil {
		return err
	}
	batches, err := plan.Batches()
	if err != nil || statement.NextBatch.Number == 0 ||
		int(statement.NextBatch.Number) >= len(batches) {
		return invalidAuthorization("next batch is outside the rollout plan")
	}
	if len(targetStateRaws) != len(plan.Targets) ||
		len(activationProofRaws) != len(plan.Targets) ||
		len(captureExportRaws) != len(plan.Targets) {
		return invalidAuthorization("promotion companions are incomplete")
	}
	planDigest := dsse.Digest(planRaw)
	expectedPrevious := ""
	if statement.NextBatch.Number > 1 {
		if len(previousPromotionRaw) == 0 {
			return invalidAuthorization("previous promotion is missing")
		}
		expectedPrevious = dsse.Digest(previousPromotionRaw)
	} else if len(previousPromotionRaw) != 0 {
		return invalidAuthorization("first promotion has an unexpected predecessor")
	}
	completed := batches[int(statement.NextBatch.Number)-1]
	next := batches[int(statement.NextBatch.Number)]
	authorizedAt, _ := canonicalTimestamp(statement.AuthorizedAt)
	if statement.CommandID != BatchPromotionCommandIDV1(
		plan.RolloutID, planDigest, statement.NextBatch.Number,
	) || statement.RolloutID != plan.RolloutID || statement.TenantID != plan.TenantID ||
		statement.PlanDigest != planDigest ||
		statement.PlanAuthorizationDigest != dsse.Digest(planAuthorizationRaw) ||
		statement.PreviousPromotionDigest != expectedPrevious ||
		statement.CompletedBatch != batchBoundary(completed) ||
		statement.NextBatch != batchBoundary(next) {
		return invalidAuthorization("batch promotion does not match the exact authorization chain and plan boundary")
	}
	for index := completed.Start; index < completed.End; index++ {
		state, parseErr := ParseTargetStateV1(targetStateRaws[index])
		if parseErr != nil || state.Phase != PhasePassed ||
			CorrelateTargetStateV1(planRaw, state) != nil {
			return invalidAuthorization("completed target %d state is invalid", index)
		}
		stateAt, _ := canonicalTimestamp(state.UpdatedAt)
		if authorizedAt.Before(stateAt) {
			return invalidAuthorization("promotion authorization predates completed target %d state", index)
		}
		entry := statement.CompletedTargets[index-completed.Start]
		target := plan.Targets[index]
		if entry.TargetIndex != uint16(index) || entry.NodeID != target.NodeID ||
			entry.ActivationID != target.ActivationID ||
			entry.TargetStateDigest != dsse.Digest(targetStateRaws[index]) ||
			entry.ActivationProofDigest != dsse.Digest(activationProofRaws[index]) ||
			entry.CaptureExportDigest != dsse.Digest(captureExportRaws[index]) {
			return invalidAuthorization("completed target %d evidence binding changed", index)
		}
	}
	return validateAuthorizationTime(plan, statement.AuthorizedAt)
}

func SignBatchPromotionV1(
	statement BatchPromotionV1,
	keyID string,
	private ed25519.PrivateKey,
	public ed25519.PublicKey,
) ([]byte, error) {
	if err := statement.Validate(); err != nil {
		return nil, err
	}
	return signAuthorizationEnvelope(
		BatchPromotionPayloadTypeV1, statement, keyID, private, public,
		MaxBatchPromotionEnvelopeBytes,
	)
}

func VerifyBatchPromotionV1(
	planRaw []byte,
	planAuthorizationRaw []byte,
	previousPromotionRaw []byte,
	raw []byte,
	targetStateRaws [][]byte,
	activationProofRaws [][]byte,
	captureExportRaws [][]byte,
	trusted map[string]ed25519.PublicKey,
	expectedKeyID string,
) (VerifiedBatchPromotionV1, error) {
	var statement BatchPromotionV1
	keyID, err := verifyAuthorizationEnvelope(
		raw, BatchPromotionPayloadTypeV1, trusted,
		MaxBatchPromotionEnvelopeBytes, &statement,
	)
	if err != nil {
		return VerifiedBatchPromotionV1{}, err
	}
	if keyID != expectedKeyID {
		return VerifiedBatchPromotionV1{}, invalidAuthorization("batch promotion signer differs from plan authorization signer")
	}
	if err := CorrelateBatchPromotionV1(
		planRaw, planAuthorizationRaw, previousPromotionRaw, statement,
		targetStateRaws, activationProofRaws, captureExportRaws,
	); err != nil {
		return VerifiedBatchPromotionV1{}, err
	}
	return VerifiedBatchPromotionV1{
		Statement: statement, KeyID: keyID, EnvelopeDigest: dsse.Digest(raw),
	}, nil
}

func signAuthorizationEnvelope(
	payloadType string,
	statement any,
	keyID string,
	private ed25519.PrivateKey,
	public ed25519.PublicKey,
	maximum int,
) ([]byte, error) {
	if len(private) != ed25519.PrivateKeySize || len(public) != ed25519.PublicKeySize {
		return nil, invalidAuthorization("signing key is unavailable")
	}
	derived, ok := private.Public().(ed25519.PublicKey)
	if !ok || !bytes.Equal(derived, public) {
		return nil, invalidAuthorization("private and public signing keys differ")
	}
	payload, err := json.Marshal(statement)
	if err != nil {
		return nil, invalidAuthorization("marshal signed statement: %v", err)
	}
	envelope, err := dsse.Sign(payloadType, payload, keyID, private)
	if err != nil {
		return nil, invalidAuthorization("sign statement: %v", err)
	}
	raw, err := dsse.Marshal(envelope)
	if err != nil || len(raw) > maximum {
		return nil, invalidAuthorization("marshal bounded signed statement: %v", err)
	}
	verified, verifiedKeyID, err := dsse.Verify(
		raw, payloadType, map[string]ed25519.PublicKey{keyID: public},
	)
	if err != nil || verifiedKeyID != keyID || !bytes.Equal(verified, payload) {
		return nil, invalidAuthorization("self-verify signed statement: %v", err)
	}
	return raw, nil
}

func verifyAuthorizationEnvelope(
	raw []byte,
	payloadType string,
	trusted map[string]ed25519.PublicKey,
	maximum int,
	destination any,
) (string, error) {
	if len(raw) == 0 || len(raw) > maximum {
		return "", invalidAuthorization("signed envelope is empty or exceeds its limit")
	}
	payload, keyID, err := dsse.Verify(raw, payloadType, trusted)
	if err != nil {
		return "", invalidAuthorization("authenticate signed envelope: %v", err)
	}
	envelope, err := dsse.Parse(raw)
	if err != nil || len(envelope.Signatures) != 1 || envelope.Signatures[0].KeyID != keyID {
		return "", invalidAuthorization("signed envelope must contain exactly one trusted signature")
	}
	canonicalEnvelope, err := dsse.Marshal(envelope)
	if err != nil || !bytes.Equal(canonicalEnvelope, raw) {
		return "", invalidAuthorization("signed envelope is not canonical JSON")
	}
	if err := dsse.DecodeStrictInto(payload, maximum, destination); err != nil {
		return "", invalidAuthorization("decode signed statement: %v", err)
	}
	canonicalPayload, err := json.Marshal(reflect.ValueOf(destination).Elem().Interface())
	if err != nil || !bytes.Equal(canonicalPayload, payload) {
		return "", invalidAuthorization("signed statement is not canonical JSON")
	}
	return keyID, nil
}

func validateAuthorizationTime(plan PlanV1, value string) error {
	authorizedAt, ok := canonicalTimestamp(value)
	createdAt, createdOK := canonicalTimestamp(plan.CreatedAt)
	deadline, deadlineOK := canonicalTimestamp(plan.Deadline)
	if !ok || !createdOK || !deadlineOK || authorizedAt.Before(createdAt) ||
		!authorizedAt.Before(deadline) {
		return invalidAuthorization("authorization time is outside the rollout interval")
	}
	return nil
}

func batchBoundary(batch BatchV1) BatchBoundaryV1 {
	return BatchBoundaryV1{
		Number: batch.Number,
		Start:  uint16(batch.Start),
		End:    uint16(batch.End),
	}
}

func validBatchBoundary(boundary BatchBoundaryV1) bool {
	return boundary.Start < boundary.End && boundary.End <= MaxTargets
}

func invalidAuthorization(format string, arguments ...any) error {
	return fmt.Errorf(
		"%w: %s",
		ErrInvalidAuthorization,
		fmt.Sprintf(format, arguments...),
	)
}
