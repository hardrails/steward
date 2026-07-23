package controlprotocol

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"
)

const (
	InteractionRequestSchemaV1  = "steward.interaction-request.v1"
	InteractionBatchSchemaV1    = "steward.interaction-request-batch.v1"
	InteractionResponseSchemaV1 = "steward.interaction-response-delivery.v1"
	InteractionPollSchemaV1     = "steward.interaction-response-poll.v1"
	InteractionAckSchemaV1      = "steward.interaction-response-ack.v1"

	MaxInteractionBatch   = 64
	MaxInteractionOptions = 8
	MaxInteractionWait    = 7 * 24 * time.Hour
)

// InteractionRequestV1 is workflow data authored by an agent and stamped by
// its node Gateway. It is not command authority. The request digest binds the
// exact question so an off-controller response can be signed for only this
// interaction.
type InteractionRequestV1 struct {
	SchemaVersion  string   `json:"schema_version"`
	InteractionID  string   `json:"interaction_id"`
	IdempotencyKey string   `json:"idempotency_key"`
	Source         string   `json:"source"`
	TenantID       string   `json:"tenant_id"`
	NodeID         string   `json:"node_id"`
	InstanceID     string   `json:"instance_id"`
	Generation     uint64   `json:"generation"`
	RuntimeRef     string   `json:"runtime_ref"`
	GrantID        string   `json:"grant_id"`
	CapsuleDigest  string   `json:"capsule_digest"`
	PolicyDigest   string   `json:"policy_digest"`
	Kind           string   `json:"kind"`
	Title          string   `json:"title"`
	Prompt         string   `json:"prompt"`
	Options        []string `json:"options"`
	AllowText      bool     `json:"allow_text"`
	TaskID         string   `json:"task_id,omitempty"`
	RunID          string   `json:"run_id,omitempty"`
	ObservedAt     string   `json:"observed_at"`
	AcceptedAt     string   `json:"accepted_at"`
	ExpiresAt      string   `json:"expires_at"`
	RequestDigest  string   `json:"request_digest"`
}

type InteractionRequestBatchV1 struct {
	SchemaVersion string                 `json:"schema_version"`
	NodeID        string                 `json:"node_id"`
	Interactions  []InteractionRequestV1 `json:"interactions"`
}

// InteractionResponseDeliveryV1 is an opaque courier record. Control may
// inspect its signed statement for routing, but only Gateway verifies it
// against the authorities admitted with the workload.
type InteractionResponseDeliveryV1 struct {
	SchemaVersion  string `json:"schema_version"`
	InteractionID  string `json:"interaction_id"`
	PermitBase64   string `json:"permit_base64"`
	ResponseBase64 string `json:"response_base64"`
	PermitDigest   string `json:"permit_digest"`
}

type InteractionResponsePollRequestV1 struct {
	SchemaVersion string `json:"schema_version"`
	NodeID        string `json:"node_id"`
	Limit         int    `json:"limit"`
}

type InteractionResponsePollResponseV1 struct {
	SchemaVersion string                          `json:"schema_version"`
	Deliveries    []InteractionResponseDeliveryV1 `json:"deliveries"`
}

type InteractionResponseAckV1 struct {
	SchemaVersion string `json:"schema_version"`
	InteractionID string `json:"interaction_id"`
	PermitDigest  string `json:"permit_digest"`
}

func (request InteractionResponsePollRequestV1) Validate() error {
	if request.SchemaVersion != InteractionPollSchemaV1 || !recordID(request.NodeID, 128) ||
		request.Limit <= 0 || request.Limit > MaxInteractionBatch {
		return errors.New("interaction response poll is invalid")
	}
	return nil
}

func (batch InteractionRequestBatchV1) Validate() error {
	if batch.SchemaVersion != InteractionBatchSchemaV1 || !recordID(batch.NodeID, 128) ||
		len(batch.Interactions) == 0 || len(batch.Interactions) > MaxInteractionBatch {
		return errors.New("interaction request batch is invalid")
	}
	seen := make(map[string]struct{}, len(batch.Interactions))
	for _, interaction := range batch.Interactions {
		if interaction.NodeID != batch.NodeID || interaction.Validate() != nil {
			return errors.New("interaction request batch contains an invalid interaction")
		}
		if _, duplicate := seen[interaction.InteractionID]; duplicate {
			return errors.New("interaction request batch contains a duplicate interaction")
		}
		seen[interaction.InteractionID] = struct{}{}
	}
	return nil
}

func (interaction InteractionRequestV1) Validate() error {
	observed, observedErr := canonicalInteractionTime(interaction.ObservedAt, time.RFC3339)
	accepted, acceptedErr := canonicalInteractionTime(interaction.AcceptedAt, time.RFC3339Nano)
	expires, expiresErr := canonicalInteractionTime(interaction.ExpiresAt, time.RFC3339)
	if interaction.SchemaVersion != InteractionRequestSchemaV1 ||
		!interactionID(interaction.InteractionID) || !recordID(interaction.IdempotencyKey, 128) ||
		interaction.InteractionID != interactionRequestID(interaction.GrantID, interaction.IdempotencyKey) ||
		interaction.Source != "agent" || !recordID(interaction.TenantID, 128) ||
		!recordID(interaction.NodeID, 128) || !text(interaction.InstanceID, 256) ||
		interaction.Generation == 0 || !prefixedDigest(interaction.RuntimeRef, "executor-") ||
		!prefixedDigest(interaction.GrantID, "grant-") || !sha256Digest(interaction.CapsuleDigest) ||
		!sha256Digest(interaction.PolicyDigest) ||
		(interaction.Kind != "question" && interaction.Kind != "decision") ||
		!text(interaction.Title, 128) || !text(interaction.Prompt, 4096) ||
		len(interaction.Options) > MaxInteractionOptions ||
		interaction.TaskID != "" && !text(interaction.TaskID, 256) ||
		interaction.RunID != "" && !text(interaction.RunID, 256) ||
		observedErr != nil || acceptedErr != nil || expiresErr != nil ||
		observed.After(accepted.Add(5*time.Minute)) || !expires.After(accepted) ||
		expires.Sub(accepted) > MaxInteractionWait ||
		interaction.RequestDigest != InteractionRequestDigest(interaction) {
		return errors.New("interaction request is invalid")
	}
	if interaction.Kind == "decision" && len(interaction.Options) < 2 ||
		len(interaction.Options) == 0 && !interaction.AllowText {
		return errors.New("interaction request has no bounded response path")
	}
	seen := make(map[string]struct{}, len(interaction.Options))
	for _, option := range interaction.Options {
		if !text(option, 128) {
			return errors.New("interaction request option is invalid")
		}
		if _, duplicate := seen[option]; duplicate {
			return errors.New("interaction request contains a duplicate option")
		}
		seen[option] = struct{}{}
	}
	return nil
}

// InteractionRequestDigest is stable across Gateway and Control. It excludes
// courier state and response data.
func InteractionRequestDigest(value InteractionRequestV1) string {
	document := struct {
		SchemaVersion string   `json:"schema_version"`
		InteractionID string   `json:"interaction_id"`
		TenantID      string   `json:"tenant_id"`
		NodeID        string   `json:"node_id"`
		InstanceID    string   `json:"instance_id"`
		Generation    uint64   `json:"generation"`
		RuntimeRef    string   `json:"runtime_ref"`
		GrantID       string   `json:"grant_id"`
		CapsuleDigest string   `json:"capsule_digest"`
		PolicyDigest  string   `json:"policy_digest"`
		Kind          string   `json:"kind"`
		Title         string   `json:"title"`
		Prompt        string   `json:"prompt"`
		Options       []string `json:"options"`
		AllowText     bool     `json:"allow_text"`
		TaskID        string   `json:"task_id,omitempty"`
		RunID         string   `json:"run_id,omitempty"`
		ObservedAt    string   `json:"observed_at"`
		AcceptedAt    string   `json:"accepted_at"`
		ExpiresAt     string   `json:"expires_at"`
	}{
		SchemaVersion: value.SchemaVersion, InteractionID: value.InteractionID,
		TenantID: value.TenantID, NodeID: value.NodeID, InstanceID: value.InstanceID,
		Generation: value.Generation, RuntimeRef: value.RuntimeRef, GrantID: value.GrantID,
		CapsuleDigest: value.CapsuleDigest, PolicyDigest: value.PolicyDigest,
		Kind: value.Kind, Title: value.Title, Prompt: value.Prompt,
		Options: slices.Clone(value.Options), AllowText: value.AllowText,
		TaskID: value.TaskID, RunID: value.RunID, ObservedAt: value.ObservedAt,
		AcceptedAt: value.AcceptedAt, ExpiresAt: value.ExpiresAt,
	}
	raw, _ := json.Marshal(document)
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func canonicalInteractionTime(value, layout string) (time.Time, error) {
	parsed, err := time.Parse(layout, value)
	if err != nil || parsed.IsZero() || parsed.UTC().Format(layout) != value {
		return time.Time{}, errors.New("interaction timestamp is not canonical UTC")
	}
	return parsed, nil
}

func interactionRequestID(grantID, idempotencyKey string) string {
	sum := sha256.Sum256([]byte("steward-interaction-v1\x00" + grantID + "\x00" + idempotencyKey))
	return "interaction-" + hex.EncodeToString(sum[:])
}

func interactionID(value string) bool {
	if !strings.HasPrefix(value, "interaction-") || len(value) != len("interaction-")+64 {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "interaction-"))
	return err == nil
}
