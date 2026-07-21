package activation

import (
	"errors"

	"github.com/hardrails/steward/internal/agentrelease"
)

// CanaryResultV1 is the agent-neutral projection of the finite built-in
// Hermes workspace-audit recipe.
type CanaryResultV1 struct {
	Kind           string `json:"kind"`
	RunID          string `json:"run_id"`
	SessionID      string `json:"session_id"`
	ManifestDigest string `json:"manifest_digest"`
}

// VerifyCanaryResultV1 selects only the compiled-in Hermes verifier and
// derives its activation-scoped session. It never dispatches agent-controlled
// code.
func VerifyCanaryResultV1(kind string, raw []byte, activationID string) (CanaryResultV1, error) {
	sessionID, err := agentrelease.CanarySessionID(kind, activationID)
	if err != nil {
		return CanaryResultV1{}, err
	}
	if kind != agentrelease.CanaryKindHermesWorkspaceAuditV1 {
		return CanaryResultV1{}, errors.New("activation canary kind is not supported")
	}
	result, err := VerifyHermesWorkspaceAuditResultV1(raw, sessionID)
	if err != nil {
		return CanaryResultV1{}, err
	}
	return CanaryResultV1{
		Kind: kind, RunID: result.RunID, SessionID: result.SessionID,
		ManifestDigest: result.ManifestDigest,
	}, nil
}
