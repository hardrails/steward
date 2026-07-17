package activation

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"

	"github.com/hardrails/steward/internal/agentrelease"
	"github.com/hardrails/steward/internal/dsse"
)

const (
	OpenClawCompletedStatus = "completed"
	OpenClawSuccessText     = "STEWARD_OPENCLAW_WORKSPACE_AUDIT_OK"
)

var openClawRunIDPattern = regexp.MustCompile(`^run_[a-f0-9]{32}$`)

type openClawTerminalV1 struct {
	RunID         string                      `json:"run_id"`
	SessionID     string                      `json:"session_id"`
	Status        string                      `json:"status"`
	Result        json.RawMessage             `json:"result"`
	ResultSHA256  string                      `json:"result_sha256"`
	Qualification openClawQualificationResult `json:"qualification"`
}

type openClawQualificationResult struct {
	FixtureID               string `json:"fixture_id"`
	WorkspaceManifestDigest string `json:"workspace_manifest_digest"`
}

type openClawResultV1 struct {
	Payloads []openClawPayloadV1 `json:"payloads"`
	Meta     openClawMetaV1      `json:"meta"`
}

type openClawPayloadV1 struct {
	Text     string          `json:"text"`
	MediaURL json.RawMessage `json:"media_url"`
}

type openClawMetaV1 struct {
	DurationMS   int64    `json:"duration_ms"`
	Model        string   `json:"model"`
	Provider     string   `json:"provider"`
	ToolCalls    int      `json:"tool_calls"`
	ToolFailures int      `json:"tool_failures"`
	Tools        []string `json:"tools"`
}

// OpenClawCanaryResultV1 contains only the non-content identities needed by an
// activation proof. The exact terminal remains a separately hashed companion.
type OpenClawCanaryResultV1 struct {
	RunID          string `json:"run_id"`
	SessionID      string `json:"session_id"`
	ManifestDigest string `json:"manifest_digest"`
}

// CanaryResultV1 is the agent-neutral projection of either finite built-in
// workspace-audit recipe.
type CanaryResultV1 struct {
	Kind           string `json:"kind"`
	RunID          string `json:"run_id"`
	SessionID      string `json:"session_id"`
	ManifestDigest string `json:"manifest_digest"`
}

// VerifyCanaryResultV1 selects only a compiled-in verifier and derives its
// activation-scoped session. It never dispatches agent-controlled code.
func VerifyCanaryResultV1(kind string, raw []byte, activationID string) (CanaryResultV1, error) {
	sessionID, err := agentrelease.CanarySessionID(kind, activationID)
	if err != nil {
		return CanaryResultV1{}, err
	}
	switch kind {
	case agentrelease.CanaryKindHermesWorkspaceAuditV1:
		result, err := VerifyHermesWorkspaceAuditResultV1(raw, sessionID)
		if err != nil {
			return CanaryResultV1{}, err
		}
		return CanaryResultV1{Kind: kind, RunID: result.RunID, SessionID: result.SessionID, ManifestDigest: result.ManifestDigest}, nil
	case agentrelease.CanaryKindOpenClawWorkspaceAuditV1:
		result, err := VerifyOpenClawWorkspaceAuditResultV1(raw, sessionID)
		if err != nil {
			return CanaryResultV1{}, err
		}
		return CanaryResultV1{Kind: kind, RunID: result.RunID, SessionID: result.SessionID, ManifestDigest: result.ManifestDigest}, nil
	default:
		return CanaryResultV1{}, errors.New("activation canary kind is not supported")
	}
}

// VerifyOpenClawWorkspaceAuditResultV1 requires the exact lifecycle terminal,
// sanitized agent result, and descriptor-verified workspace identity emitted by
// the qualified OpenClaw adapter.
func VerifyOpenClawWorkspaceAuditResultV1(raw []byte, expectedSessionID string) (OpenClawCanaryResultV1, error) {
	if !identifier(expectedSessionID) {
		return OpenClawCanaryResultV1{}, errors.New("expected OpenClaw session ID is invalid")
	}
	var terminal openClawTerminalV1
	if err := dsse.DecodeStrictInto(raw, int(MaxCanaryResultBytes), &terminal); err != nil {
		return OpenClawCanaryResultV1{}, fmt.Errorf("decode OpenClaw terminal result: %w", err)
	}
	if !openClawRunIDPattern.MatchString(terminal.RunID) || terminal.SessionID != expectedSessionID ||
		terminal.Status != OpenClawCompletedStatus ||
		terminal.Qualification.FixtureID != agentrelease.OpenClawWorkspaceAuditFixtureID ||
		terminal.Qualification.WorkspaceManifestDigest != agentrelease.OpenClawWorkspaceAuditManifestDigest {
		return OpenClawCanaryResultV1{}, errors.New("OpenClaw terminal result does not match the closed completed workspace audit")
	}
	var result openClawResultV1
	if err := dsse.DecodeStrictInto(terminal.Result, int(MaxCanaryResultBytes), &result); err != nil {
		return OpenClawCanaryResultV1{}, fmt.Errorf("decode sanitized OpenClaw result: %w", err)
	}
	if len(result.Payloads) != 1 || result.Payloads[0].Text != OpenClawSuccessText ||
		!bytes.Equal(result.Payloads[0].MediaURL, []byte("null")) ||
		result.Meta.DurationMS < 0 || !publicIdentity(result.Meta.Model, 256) || result.Meta.Provider != "steward" ||
		result.Meta.ToolCalls != 1 || result.Meta.ToolFailures != 0 ||
		len(result.Meta.Tools) != 1 || result.Meta.Tools[0] != "exec" {
		return OpenClawCanaryResultV1{}, errors.New("OpenClaw sanitized result is outside the qualified shape")
	}
	var canonicalValue any
	if err := json.Unmarshal(terminal.Result, &canonicalValue); err != nil {
		return OpenClawCanaryResultV1{}, errors.New("OpenClaw sanitized result is invalid JSON")
	}
	canonicalResult, err := json.Marshal(canonicalValue)
	if err != nil {
		return OpenClawCanaryResultV1{}, errors.New("canonicalize OpenClaw sanitized result")
	}
	resultSum := sha256.Sum256(canonicalResult)
	if terminal.ResultSHA256 != hex.EncodeToString(resultSum[:]) {
		return OpenClawCanaryResultV1{}, errors.New("OpenClaw sanitized result digest is invalid")
	}
	canonicalTerminal, err := json.Marshal(terminal)
	if err != nil || !bytes.Equal(raw, append(canonicalTerminal, '\n')) {
		return OpenClawCanaryResultV1{}, errors.New("OpenClaw terminal result is not canonical JSON with one newline")
	}
	return OpenClawCanaryResultV1{
		RunID: terminal.RunID, SessionID: terminal.SessionID,
		ManifestDigest: terminal.Qualification.WorkspaceManifestDigest,
	}, nil
}
