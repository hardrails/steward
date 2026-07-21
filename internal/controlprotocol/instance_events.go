package controlprotocol

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	InstanceEventSchemaV1   = "steward.instance-event.v1"
	InstanceEventBatchV1    = "steward.instance-event-batch.v1"
	MaxInstanceEventBatch   = 64
	MaxInstanceEventAttrs   = 16
	MaxInstanceEventSummary = 1024
)

// InstanceEventV1 is an untrusted agent observation whose workload identity
// was derived and stamped by the node Gateway. It is telemetry, not evidence:
// accepting it never authorizes work or changes desired state.
type InstanceEventV1 struct {
	SchemaVersion  string            `json:"schema_version"`
	EventID        string            `json:"event_id"`
	IdempotencyKey string            `json:"idempotency_key"`
	Source         string            `json:"source"`
	TenantID       string            `json:"tenant_id"`
	NodeID         string            `json:"node_id"`
	InstanceID     string            `json:"instance_id"`
	Generation     uint64            `json:"generation"`
	RuntimeRef     string            `json:"runtime_ref"`
	GrantID        string            `json:"grant_id"`
	CapsuleDigest  string            `json:"capsule_digest"`
	PolicyDigest   string            `json:"policy_digest"`
	Kind           string            `json:"kind"`
	Code           string            `json:"code"`
	Severity       string            `json:"severity"`
	Summary        string            `json:"summary"`
	Attributes     map[string]string `json:"attributes,omitempty"`
	TaskID         string            `json:"task_id,omitempty"`
	RunID          string            `json:"run_id,omitempty"`
	ObservedAt     string            `json:"observed_at"`
	AcceptedAt     string            `json:"accepted_at"`
}

type InstanceEventBatchRequestV1 struct {
	SchemaVersion string            `json:"schema_version"`
	NodeID        string            `json:"node_id"`
	Events        []InstanceEventV1 `json:"events"`
}

func (batch InstanceEventBatchRequestV1) Validate() error {
	if batch.SchemaVersion != InstanceEventBatchV1 || !recordID(batch.NodeID, 128) ||
		len(batch.Events) == 0 || len(batch.Events) > MaxInstanceEventBatch {
		return errors.New("instance event batch is invalid")
	}
	seen := make(map[string]struct{}, len(batch.Events))
	for _, event := range batch.Events {
		if event.NodeID != batch.NodeID || event.Validate() != nil {
			return errors.New("instance event batch contains an invalid event")
		}
		if _, duplicate := seen[event.EventID]; duplicate {
			return errors.New("instance event batch contains a duplicate event")
		}
		seen[event.EventID] = struct{}{}
	}
	return nil
}

func (event InstanceEventV1) Validate() error {
	if event.SchemaVersion != InstanceEventSchemaV1 || !eventID(event.EventID) || !recordID(event.IdempotencyKey, 128) ||
		event.EventID != instanceEventID(event.GrantID, event.IdempotencyKey) ||
		event.Source != "agent" || !recordID(event.TenantID, 128) || !recordID(event.NodeID, 128) ||
		!text(event.InstanceID, 256) || event.Generation == 0 || !prefixedDigest(event.RuntimeRef, "executor-") ||
		!prefixedDigest(event.GrantID, "grant-") || !sha256Digest(event.CapsuleDigest) || !sha256Digest(event.PolicyDigest) ||
		(event.Kind != "status" && event.Kind != "finding") || !recordID(event.Code, 128) ||
		(event.Severity != "info" && event.Severity != "warning" && event.Severity != "critical") ||
		!text(event.Summary, MaxInstanceEventSummary) || event.TaskID != "" && !text(event.TaskID, 256) ||
		event.RunID != "" && !text(event.RunID, 256) || !timestamp(event.ObservedAt) || !timestamp(event.AcceptedAt) ||
		len(event.Attributes) > MaxInstanceEventAttrs {
		return errors.New("instance event is invalid")
	}
	total := 0
	for key, value := range event.Attributes {
		if !recordID(key, 128) || !text(value, 1024) {
			return errors.New("instance event attribute is invalid")
		}
		total += len(key) + len(value)
	}
	if total > 4<<10 {
		return errors.New("instance event attributes exceed limit")
	}
	return nil
}

func instanceEventID(grantID, idempotencyKey string) string {
	digest := sha256.Sum256([]byte("steward-instance-event-v1\x00" + grantID + "\x00" + idempotencyKey))
	return "event-" + hex.EncodeToString(digest[:])
}

func eventID(value string) bool {
	if !strings.HasPrefix(value, "event-") || len(value) != len("event-")+64 {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "event-"))
	return err == nil
}

func prefixedDigest(value, prefix string) bool {
	if !strings.HasPrefix(value, prefix) || len(value) != len(prefix)+64 {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, prefix))
	return err == nil
}

func sha256Digest(value string) bool { return prefixedDigest(value, "sha256:") }

func recordID(value string, limit int) bool {
	if value == "" || len(value) > limit {
		return false
	}
	for index, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || index > 0 && (character == '-' || character == '_' || character == '.') {
			continue
		}
		return false
	}
	return true
}

func text(value string, limit int) bool {
	if value == "" || len(value) > limit || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func timestamp(value string) bool {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	return err == nil && parsed.Format(time.RFC3339Nano) == value
}
