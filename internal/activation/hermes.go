package activation

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"

	"github.com/hardrails/steward/internal/agentrelease"
	"github.com/hardrails/steward/internal/dsse"
)

const (
	HermesRunObject         = "hermes.run"
	HermesCompletedStatus   = "completed"
	HermesCompletedEvent    = "run.completed"
	HermesWorkspaceRoot     = "workspace"
	HermesWorkspaceSchemaV1 = "steward.workspace-audit.result.v1"
)

var hermesRunIDPattern = regexp.MustCompile(`^run_[a-f0-9]{32}$`)

type hermesUsageV1 struct {
	InputTokens  int64 `json:"input_tokens"`
	OutputTokens int64 `json:"output_tokens"`
	TotalTokens  int64 `json:"total_tokens"`
}

type hermesTerminalV1 struct {
	Object    string          `json:"object"`
	RunID     string          `json:"run_id"`
	Status    string          `json:"status"`
	UpdatedAt json.RawMessage `json:"updated_at"`
	CreatedAt json.RawMessage `json:"created_at"`
	SessionID string          `json:"session_id"`
	Model     string          `json:"model"`
	Output    string          `json:"output"`
	Usage     hermesUsageV1   `json:"usage"`
	LastEvent string          `json:"last_event"`
}

type hermesWorkspaceEntryV1 struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type hermesWorkspaceResultV1 struct {
	Entries        []hermesWorkspaceEntryV1 `json:"entries"`
	FileCount      int                      `json:"file_count"`
	ManifestDigest string                   `json:"manifest_digest"`
	Root           string                   `json:"root"`
	SchemaVersion  string                   `json:"schema_version"`
	TotalBytes     int64                    `json:"total_bytes"`
}

// HermesCanaryResultV1 contains only the non-content identities needed by an
// activation proof. The raw terminal bytes remain a separate bounded companion
// whose digest is recorded by Gateway.
type HermesCanaryResultV1 struct {
	RunID          string `json:"run_id"`
	SessionID      string `json:"session_id"`
	ManifestDigest string `json:"manifest_digest"`
}

// VerifyHermesWorkspaceAuditResultV1 validates the exact closed fresh-state
// canary. Agent-reported completion alone is insufficient: this function also
// requires the activation-scoped session and the canonical, self-consistent
// empty-workspace result qualified by the signed release contract.
func VerifyHermesWorkspaceAuditResultV1(raw []byte, expectedSessionID string) (HermesCanaryResultV1, error) {
	if !identifier(expectedSessionID) {
		return HermesCanaryResultV1{}, errors.New("expected Hermes session ID is invalid")
	}
	var terminal hermesTerminalV1
	if err := dsse.DecodeStrictInto(raw, int(MaxCanaryResultBytes), &terminal); err != nil {
		return HermesCanaryResultV1{}, fmt.Errorf("decode Hermes terminal result: %w", err)
	}
	if terminal.Object != HermesRunObject || !hermesRunIDPattern.MatchString(terminal.RunID) ||
		terminal.Status != HermesCompletedStatus || terminal.LastEvent != HermesCompletedEvent ||
		terminal.SessionID != expectedSessionID || !publicIdentity(terminal.Model, 256) {
		return HermesCanaryResultV1{}, errors.New("Hermes terminal result does not match the closed completed run")
	}
	createdAt, err := decodeHermesTimestamp(terminal.CreatedAt)
	if err != nil {
		return HermesCanaryResultV1{}, fmt.Errorf("Hermes created_at: %w", err)
	}
	updatedAt, err := decodeHermesTimestamp(terminal.UpdatedAt)
	if err != nil {
		return HermesCanaryResultV1{}, fmt.Errorf("Hermes updated_at: %w", err)
	}
	if updatedAt < createdAt {
		return HermesCanaryResultV1{}, errors.New("Hermes terminal result has invalid run timestamps")
	}
	if terminal.Usage.InputTokens < 0 || terminal.Usage.OutputTokens < 0 ||
		terminal.Usage.TotalTokens < 0 ||
		terminal.Usage.TotalTokens != terminal.Usage.InputTokens+terminal.Usage.OutputTokens {
		return HermesCanaryResultV1{}, errors.New("Hermes terminal result has invalid token accounting")
	}
	if len(terminal.Output) == 0 || len(terminal.Output) > int(MaxCanaryResultBytes) {
		return HermesCanaryResultV1{}, errors.New("Hermes workspace-audit output is empty or oversized")
	}
	var workspace hermesWorkspaceResultV1
	if err := dsse.DecodeStrictInto([]byte(terminal.Output), int(MaxCanaryResultBytes), &workspace); err != nil {
		return HermesCanaryResultV1{}, fmt.Errorf("decode Hermes workspace-audit output: %w", err)
	}
	if workspace.Entries == nil || len(workspace.Entries) != 0 || workspace.FileCount != 0 ||
		workspace.ManifestDigest != agentrelease.HermesWorkspaceAuditEmptyManifestDigest ||
		workspace.Root != HermesWorkspaceRoot || workspace.SchemaVersion != HermesWorkspaceSchemaV1 ||
		workspace.TotalBytes != 0 {
		return HermesCanaryResultV1{}, errors.New("Hermes workspace-audit output is not the qualified empty-workspace result")
	}
	canonical, err := json.Marshal(workspace)
	if err != nil || !bytes.Equal(canonical, []byte(terminal.Output)) {
		return HermesCanaryResultV1{}, errors.New("Hermes workspace-audit output is not canonical JSON")
	}
	return HermesCanaryResultV1{
		RunID:          terminal.RunID,
		SessionID:      terminal.SessionID,
		ManifestDigest: workspace.ManifestDigest,
	}, nil
}

func decodeHermesTimestamp(raw json.RawMessage) (float64, error) {
	if len(raw) == 0 {
		return 0, errors.New("timestamp is absent")
	}
	var value float64
	if err := json.Unmarshal(raw, &value); err != nil || math.IsNaN(value) || math.IsInf(value, 0) || value <= 0 {
		return 0, errors.New("timestamp must be one positive finite JSON number")
	}
	return value, nil
}
