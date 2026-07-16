// Package controlprotocol defines the public, dependency-free wire records used
// between Steward nodes and a separately deployed control plane.
package controlprotocol

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/hardrails/steward/internal/dsse"
)

const (
	ExecutorProtocolV3       = 3
	MaxExecutorDeliveries    = 128
	MaxExecutorDeliveryBytes = 1 << 20

	ExecutorStatusDone           = "done"
	ExecutorStatusFailed         = "failed"
	ExecutorStatusRejected       = "rejected"
	ExecutorStatusOutcomeUnknown = "outcome_unknown"
)

// ExecutorDeliveryID binds one transport lease identity to the verified
// tenant, node, and signed command. Nodes recompute it after signature
// verification so an untrusted controller cannot replay one command through
// aliases in the delivery ledger.
func ExecutorDeliveryID(tenantID, nodeID, commandID string) (string, error) {
	if !boundedText(tenantID, 128) || !boundedText(nodeID, 128) || !boundedText(commandID, 256) {
		return "", errors.New("delivery tenant, node, and command identity must be bounded")
	}
	digest := sha256.New()
	_, _ = digest.Write([]byte("steward-control-delivery-v1\x00" + tenantID + "\x00" + nodeID + "\x00" + commandID))
	return "delivery-" + hex.EncodeToString(digest.Sum(nil)), nil
}

// ExecutorPollRequestV3 advertises support for lease-wrapped, tenant-signed
// Executor commands. The node bearer authenticates transport only.
type ExecutorPollRequestV3 struct {
	ProtocolVersion int      `json:"protocol_version"`
	NodeID          string   `json:"node_id"`
	CredentialScope string   `json:"credential_scope"`
	Capabilities    []string `json:"capabilities"`
}

// ExecutorPollResponseV3 keeps every delivery opaque until the node validates
// it independently. One malformed delivery can therefore be rejected without
// preventing a valid sibling from being processed.
type ExecutorPollResponseV3 struct {
	ProtocolVersion int               `json:"protocol_version"`
	Deliveries      []json.RawMessage `json:"deliveries"`
}

// ExecutorDeliveryV3 separates an unsigned control-plane lease from the exact
// tenant-signed v2 command bytes. DeliveryGeneration may change on reclaim;
// none of these outer fields grant command authority.
type ExecutorDeliveryV3 struct {
	DeliveryID         string `json:"delivery_id"`
	DeliveryGeneration uint64 `json:"delivery_generation"`
	CommandID          string `json:"command_id"`
	CommandDigest      string `json:"command_digest"`
	CommandDSSEBase64  string `json:"command_dsse_base64"`
}

type ExecutorReportResultV3 struct {
	RuntimeRef string `json:"runtime_ref,omitempty"`
	Error      string `json:"error,omitempty"`
	Replayed   bool   `json:"replayed,omitempty"`
	Absent     bool   `json:"absent,omitempty"`
}

// ExecutorReportV3 binds a terminal observation to the exact delivery lease.
// ClaimGeneration remains the tenant-signed lifecycle fence; the independent
// DeliveryGeneration fences stale transport reports after a lease reclaim.
type ExecutorReportV3 struct {
	ProtocolVersion    int                    `json:"protocol_version"`
	DeliveryID         string                 `json:"delivery_id"`
	DeliveryGeneration uint64                 `json:"delivery_generation"`
	CommandID          string                 `json:"command_id"`
	CommandDigest      string                 `json:"command_digest"`
	Status             string                 `json:"status"`
	ReportedStatus     string                 `json:"reported_status"`
	ClaimGeneration    uint64                 `json:"claim_generation"`
	ErrorCode          string                 `json:"error_code,omitempty"`
	Result             ExecutorReportResultV3 `json:"result"`
}

// ExecutorReportResponseV3 treats both Applied values as terminal
// acknowledgements for the presented generation. False means the report was
// stale or already stored, not that the node should execute again.
type ExecutorReportResponseV3 struct {
	ProtocolVersion int  `json:"protocol_version"`
	Applied         bool `json:"applied"`
}

// DecodeExecutorPollResponseV3 validates only the response container. It
// deliberately captures delivery members as raw JSON without recursively
// interpreting them, preserving per-delivery fault isolation.
func DecodeExecutorPollResponseV3(raw []byte, limit int) (ExecutorPollResponseV3, error) {
	if limit <= 0 || len(raw) == 0 || len(raw) > limit {
		return ExecutorPollResponseV3{}, errors.New("poll response is empty or exceeds its limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return ExecutorPollResponseV3{}, errors.New("poll response must be one JSON object")
	}
	var response ExecutorPollResponseV3
	seen := make(map[string]struct{}, 2)
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return ExecutorPollResponseV3{}, err
		}
		key, ok := keyToken.(string)
		if !ok {
			return ExecutorPollResponseV3{}, errors.New("poll response field name is invalid")
		}
		if _, duplicate := seen[key]; duplicate {
			return ExecutorPollResponseV3{}, fmt.Errorf("poll response contains duplicate field %q", key)
		}
		seen[key] = struct{}{}
		switch key {
		case "protocol_version":
			if err := decoder.Decode(&response.ProtocolVersion); err != nil {
				return ExecutorPollResponseV3{}, fmt.Errorf("decode protocol_version: %w", err)
			}
		case "deliveries":
			if err := decoder.Decode(&response.Deliveries); err != nil {
				return ExecutorPollResponseV3{}, fmt.Errorf("decode deliveries: %w", err)
			}
		default:
			return ExecutorPollResponseV3{}, fmt.Errorf("poll response contains unknown field %q", key)
		}
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim('}') {
		return ExecutorPollResponseV3{}, errors.New("poll response object is not terminated")
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return ExecutorPollResponseV3{}, errors.New("poll response contains trailing JSON")
	}
	if response.ProtocolVersion != ExecutorProtocolV3 {
		return ExecutorPollResponseV3{}, fmt.Errorf("poll response protocol_version is %d, want %d", response.ProtocolVersion, ExecutorProtocolV3)
	}
	if response.Deliveries == nil {
		return ExecutorPollResponseV3{}, errors.New("poll response must contain a deliveries array")
	}
	if len(response.Deliveries) > MaxExecutorDeliveries {
		return ExecutorPollResponseV3{}, fmt.Errorf("poll response contains %d deliveries, limit is %d", len(response.Deliveries), MaxExecutorDeliveries)
	}
	return response, nil
}

func DecodeExecutorDeliveryV3(raw []byte) (ExecutorDeliveryV3, error) {
	var delivery ExecutorDeliveryV3
	if err := dsse.DecodeStrictInto(raw, MaxExecutorDeliveryBytes, &delivery); err != nil {
		return ExecutorDeliveryV3{}, err
	}
	if err := delivery.Validate(); err != nil {
		return ExecutorDeliveryV3{}, err
	}
	return delivery, nil
}

func (d ExecutorDeliveryV3) Validate() error {
	if !boundedText(d.DeliveryID, 256) || !boundedText(d.CommandID, 256) || d.DeliveryGeneration == 0 {
		return errors.New("delivery identity and positive generation are required")
	}
	if !ValidSHA256Digest(d.CommandDigest) {
		return errors.New("delivery command_digest must be canonical SHA-256")
	}
	if strings.TrimSpace(d.CommandDSSEBase64) == "" || len(d.CommandDSSEBase64) > MaxExecutorDeliveryBytes {
		return errors.New("delivery command DSSE is empty or exceeds its limit")
	}
	return nil
}

func (r ExecutorReportV3) Validate() error {
	if r.ProtocolVersion != ExecutorProtocolV3 || !boundedText(r.DeliveryID, 256) ||
		r.DeliveryGeneration == 0 || !boundedText(r.CommandID, 256) || !ValidSHA256Digest(r.CommandDigest) {
		return errors.New("report delivery identity is invalid")
	}
	switch r.Status {
	case ExecutorStatusDone, ExecutorStatusFailed, ExecutorStatusRejected, ExecutorStatusOutcomeUnknown:
	default:
		return errors.New("report status is invalid")
	}
	if !boundedText(r.ReportedStatus, 64) || len(r.ErrorCode) > 128 || len(r.Result.Error) > 4096 ||
		len(r.Result.RuntimeRef) > 1024 {
		return errors.New("report outcome exceeds its limits")
	}
	return nil
}

func ValidSHA256Digest(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, char := range value[len("sha256:"):] {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return false
		}
	}
	return true
}

func boundedText(value string, limit int) bool {
	return strings.TrimSpace(value) != "" && len(value) <= limit && !strings.ContainsAny(value, "\r\n\x00")
}
