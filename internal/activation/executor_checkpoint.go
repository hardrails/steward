package activation

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/hardrails/steward/internal/dsse"
)

const (
	ExecutorBeginSchemaV1      = "steward.activation-executor-begin.v1"
	ExecutorCheckpointSchemaV1 = "steward.activation-executor-checkpoint.v1"
	MaxExecutorCheckpointBytes = 64 << 10
)

// ExecutorBeginV1 is hashed into a signed Executor receipt immediately before
// fresh admission. Its position prevents a later activation from reusing an
// older admission, start, or persistent-state lineage.
type ExecutorBeginV1 struct {
	SchemaVersion   string    `json:"schema_version"`
	Binding         BindingV1 `json:"binding"`
	RuntimeRef      string    `json:"runtime_ref"`
	StateRuntimeRef string    `json:"state_runtime_ref"`
	CapsuleDigest   string    `json:"capsule_digest"`
}

// ExecutorCheckpointV1 is the exact, content-free assertion whose digest is
// appended to the Executor's signed receipt stream after Gateway has produced
// terminal canary evidence. The signed receipt gives otherwise independent
// Gateway and Executor chains a causal join.
type ExecutorCheckpointV1 struct {
	SchemaVersion         string              `json:"schema_version"`
	Binding               BindingV1           `json:"binding"`
	RuntimeRef            string              `json:"runtime_ref"`
	CapsuleDigest         string              `json:"capsule_digest"`
	RoutePolicyDigest     string              `json:"route_policy_digest"`
	GrantID               string              `json:"grant_id"`
	GatewayReceiptsDigest string              `json:"gateway_receipts_digest"`
	GatewayEvidence       ReceiptCoordinateV1 `json:"gateway_evidence"`
	Canary                CanaryProofV1       `json:"canary"`
	AuthorizedAt          string              `json:"authorized_at"`
	TerminalAt            string              `json:"terminal_at"`
}

func MarshalExecutorBeginV1(
	binding BindingV1,
	runtimeRef, stateRuntimeRef, capsuleDigest string,
) ([]byte, error) {
	begin := ExecutorBeginV1{
		SchemaVersion:   ExecutorBeginSchemaV1,
		Binding:         binding,
		RuntimeRef:      runtimeRef,
		StateRuntimeRef: stateRuntimeRef,
		CapsuleDigest:   capsuleDigest,
	}
	if err := begin.Validate(); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(begin)
	if err != nil {
		return nil, fmt.Errorf("marshal activation Executor begin marker: %w", err)
	}
	if len(raw) > MaxExecutorCheckpointBytes {
		return nil, errors.New("activation Executor begin marker exceeds its size limit")
	}
	return raw, nil
}

func ParseExecutorBeginV1(raw []byte) (ExecutorBeginV1, error) {
	var begin ExecutorBeginV1
	if err := dsse.DecodeStrictInto(
		raw, MaxExecutorCheckpointBytes, &begin,
	); err != nil {
		return ExecutorBeginV1{}, fmt.Errorf("decode activation Executor begin marker: %w", err)
	}
	if err := begin.Validate(); err != nil {
		return ExecutorBeginV1{}, err
	}
	canonical, err := json.Marshal(begin)
	if err != nil || !equalBytes(canonical, raw) {
		return ExecutorBeginV1{}, errors.New("activation Executor begin marker is not canonical JSON")
	}
	return begin, nil
}

func ExecutorBeginDigestV1(raw []byte) (string, error) {
	if _, err := ParseExecutorBeginV1(raw); err != nil {
		return "", err
	}
	return dsse.Digest(raw), nil
}

func (begin ExecutorBeginV1) Validate() error {
	if begin.SchemaVersion != ExecutorBeginSchemaV1 {
		return errors.New("activation Executor begin marker has an unsupported schema")
	}
	if err := begin.Binding.validate(); err != nil {
		return fmt.Errorf("activation Executor begin marker binding: %w", err)
	}
	if !runtimeRef(begin.RuntimeRef) ||
		!stateRuntimeRef(begin.StateRuntimeRef) ||
		!sha256Digest(begin.CapsuleDigest) {
		return errors.New("activation Executor begin marker has invalid runtime or capsule bindings")
	}
	return nil
}

// MarshalExecutorCheckpointV1 returns the deterministic checkpoint bytes that
// both the live writer and offline verifier hash.
func MarshalExecutorCheckpointV1(
	binding BindingV1,
	runtimeRef, capsuleDigest, routePolicyDigest, grantID string,
	gateway GatewayEvidenceResultV1,
) ([]byte, error) {
	checkpoint := ExecutorCheckpointV1{
		SchemaVersion:         ExecutorCheckpointSchemaV1,
		Binding:               binding,
		RuntimeRef:            runtimeRef,
		CapsuleDigest:         capsuleDigest,
		RoutePolicyDigest:     routePolicyDigest,
		GrantID:               grantID,
		GatewayReceiptsDigest: dsse.Digest(gateway.Receipts),
		GatewayEvidence:       gateway.Coordinate,
		Canary:                gateway.Canary,
		AuthorizedAt:          gateway.AuthorizedAt,
		TerminalAt:            gateway.TerminalAt,
	}
	if err := checkpoint.Validate(); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(checkpoint)
	if err != nil {
		return nil, fmt.Errorf("marshal activation Executor checkpoint: %w", err)
	}
	if len(raw) > MaxExecutorCheckpointBytes {
		return nil, errors.New("activation Executor checkpoint exceeds its size limit")
	}
	return raw, nil
}

func ParseExecutorCheckpointV1(raw []byte) (ExecutorCheckpointV1, error) {
	var checkpoint ExecutorCheckpointV1
	if err := dsse.DecodeStrictInto(
		raw, MaxExecutorCheckpointBytes, &checkpoint,
	); err != nil {
		return ExecutorCheckpointV1{}, fmt.Errorf("decode activation Executor checkpoint: %w", err)
	}
	if err := checkpoint.Validate(); err != nil {
		return ExecutorCheckpointV1{}, err
	}
	canonical, err := json.Marshal(checkpoint)
	if err != nil || !equalBytes(canonical, raw) {
		return ExecutorCheckpointV1{}, errors.New("activation Executor checkpoint is not canonical JSON")
	}
	return checkpoint, nil
}

func ExecutorCheckpointDigestV1(raw []byte) (string, error) {
	if _, err := ParseExecutorCheckpointV1(raw); err != nil {
		return "", err
	}
	return dsse.Digest(raw), nil
}

func (checkpoint ExecutorCheckpointV1) Validate() error {
	if checkpoint.SchemaVersion != ExecutorCheckpointSchemaV1 {
		return errors.New("activation Executor checkpoint has an unsupported schema")
	}
	if err := checkpoint.Binding.validate(); err != nil {
		return fmt.Errorf("activation Executor checkpoint binding: %w", err)
	}
	if !runtimeRef(checkpoint.RuntimeRef) ||
		!sha256Digest(checkpoint.CapsuleDigest) ||
		!sha256Digest(checkpoint.RoutePolicyDigest) ||
		!grantIDPattern.MatchString(checkpoint.GrantID) ||
		!sha256Digest(checkpoint.GatewayReceiptsDigest) {
		return errors.New("activation Executor checkpoint has invalid runtime or digest bindings")
	}
	if err := checkpoint.GatewayEvidence.validate(); err != nil {
		return fmt.Errorf("activation Executor checkpoint Gateway evidence: %w", err)
	}
	if err := checkpoint.Canary.validate(); err != nil {
		return fmt.Errorf("activation Executor checkpoint canary: %w", err)
	}
	authorized, ok := canonicalTimestamp(checkpoint.AuthorizedAt)
	if !ok {
		return errors.New("activation Executor checkpoint authorized_at is not canonical UTC RFC3339Nano")
	}
	terminal, ok := canonicalTimestamp(checkpoint.TerminalAt)
	if !ok || terminal.Before(authorized) {
		return errors.New("activation Executor checkpoint terminal_at is invalid or predates authorization")
	}
	return nil
}

func equalBytes(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
