package controlprotocol

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/hardrails/steward/internal/dsse"
)

const (
	// ExecutorCapabilityActivationCanaryV1 is advertised only by protocol-4
	// nodes that can execute and durably retain the closed activation canary.
	ExecutorCapabilityActivationCanaryV1 = "activation-canary-v1"

	ExecutorActivationCanaryResultSchemaV1 = "steward.activation-canary-result.v1"
	MaxExecutorActivationCanaryResultBytes = 12 << 10

	maxExecutorActivationCanaryTerminalBytes = 4 << 10
	maxExecutorActivationCanaryEvidenceBytes = 8 << 10
)

// ExecutorActivationCanaryResultV1 is the typed, bounded protocol projection
// of activationcanary.ResultV1. The wire shape is repeated here intentionally:
// activationcanary verifies trusted execution evidence and already imports
// controlprotocol, while this dependency-free transport package cannot import
// it back. Neither type is an opaque byte wrapper.
type ExecutorActivationCanaryResultV1 struct {
	SchemaVersion              string `json:"schema_version"`
	ActivationID               string `json:"activation_id"`
	AdmissionDigest            string `json:"admission_digest"`
	TaskDigest                 string `json:"task_digest"`
	PermitDigest               string `json:"permit_digest"`
	RunID                      string `json:"run_id"`
	TerminalResultDigest       string `json:"terminal_result_digest"`
	TerminalResultBytes        int64  `json:"terminal_result_bytes"`
	TerminalResultBase64       string `json:"terminal_result_base64"`
	GatewayEvidenceBase64      string `json:"gateway_evidence_base64"`
	ActivationCheckpointDigest string `json:"activation_checkpoint_digest"`
	Qualified                  bool   `json:"qualified"`
}

// Validate enforces the projection's canonical companion encodings and
// self-declared digests without treating Qualified as independent proof. The
// Executor verifies the receipts before constructing this value; the
// controller retains the exact bounded observation.
func (result ExecutorActivationCanaryResultV1) Validate() error {
	if result.SchemaVersion != ExecutorActivationCanaryResultSchemaV1 ||
		!routeIdentifier(result.ActivationID) ||
		!ValidSHA256Digest(result.AdmissionDigest) ||
		!ValidSHA256Digest(result.TaskDigest) ||
		!ValidSHA256Digest(result.PermitDigest) ||
		!strings.HasPrefix(result.RunID, "run_") ||
		!lowerHex(strings.TrimPrefix(result.RunID, "run_"), 32) ||
		!ValidSHA256Digest(result.TerminalResultDigest) ||
		!ValidSHA256Digest(result.ActivationCheckpointDigest) ||
		!result.Qualified {
		return errors.New("activation canary result identity, digest, run, or qualification is invalid")
	}
	terminal, err := decodeExecutorCanaryBase64(
		result.TerminalResultBase64,
		maxExecutorActivationCanaryTerminalBytes,
	)
	if err != nil || result.TerminalResultBytes != int64(len(terminal)) ||
		result.TerminalResultDigest != dsse.Digest(terminal) {
		return errors.New("activation canary terminal result encoding, length, or digest is invalid")
	}
	receipts, err := decodeExecutorCanaryBase64(
		result.GatewayEvidenceBase64,
		maxExecutorActivationCanaryEvidenceBytes,
	)
	if err != nil || receipts[len(receipts)-1] != '\n' ||
		bytes.Count(receipts, []byte{'\n'}) != 3 || bytes.Contains(receipts, []byte{'\r'}) {
		return errors.New("activation canary evidence is not three canonical receipt lines")
	}
	raw, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("encode activation canary result: %w", err)
	}
	if len(raw) > MaxExecutorActivationCanaryResultBytes {
		return fmt.Errorf(
			"activation canary result contains %d bytes, limit is %d",
			len(raw),
			MaxExecutorActivationCanaryResultBytes,
		)
	}
	return nil
}

func decodeExecutorCanaryBase64(value string, maximum int) ([]byte, error) {
	if value == "" || maximum <= 0 || len(value) > base64.StdEncoding.EncodedLen(maximum) {
		return nil, errors.New("base64 value is empty or exceeds its limit")
	}
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(raw) == 0 || len(raw) > maximum ||
		base64.StdEncoding.EncodeToString(raw) != value {
		return nil, errors.New("base64 value is not one canonical standard encoding")
	}
	return raw, nil
}
