package activation

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/hardrails/steward/internal/agentrelease"
)

func TestVerifyOpenClawWorkspaceAuditResultV1(t *testing.T) {
	sessionID := "steward-activation-activation-001"
	raw := validOpenClawCanaryResult(t, sessionID)
	verified, err := VerifyOpenClawWorkspaceAuditResultV1(raw, sessionID)
	if err != nil {
		t.Fatal(err)
	}
	if verified.RunID != "run_0123456789abcdef0123456789abcdef" || verified.SessionID != sessionID ||
		verified.ManifestDigest != agentrelease.OpenClawWorkspaceAuditManifestDigest {
		t.Fatalf("verified = %#v", verified)
	}
	generic, err := VerifyCanaryResultV1(agentrelease.CanaryKindOpenClawWorkspaceAuditV1, raw, "activation-001")
	if err != nil || generic.RunID != verified.RunID || generic.ManifestDigest != verified.ManifestDigest {
		t.Fatalf("generic = %#v, err = %v", generic, err)
	}
}

func TestVerifyOpenClawWorkspaceAuditResultV1RejectsSubstitution(t *testing.T) {
	sessionID := "steward-activation-activation-001"
	base := validOpenClawTerminal(t, sessionID)
	tests := []struct {
		name   string
		mutate func(*openClawTerminalV1, *openClawResultV1)
	}{
		{"run ID", func(value *openClawTerminalV1, _ *openClawResultV1) { value.RunID = "run_other" }},
		{"session", func(value *openClawTerminalV1, _ *openClawResultV1) { value.SessionID = "steward-activation-other" }},
		{"status", func(value *openClawTerminalV1, _ *openClawResultV1) { value.Status = "running" }},
		{"fixture", func(value *openClawTerminalV1, _ *openClawResultV1) { value.Qualification.FixtureID = "other" }},
		{"manifest", func(value *openClawTerminalV1, _ *openClawResultV1) {
			value.Qualification.WorkspaceManifestDigest = "sha256:" + strings.Repeat("0", 64)
		}},
		{"success text", func(_ *openClawTerminalV1, value *openClawResultV1) { value.Payloads[0].Text = "done" }},
		{"media", func(_ *openClawTerminalV1, value *openClawResultV1) {
			value.Payloads[0].MediaURL = json.RawMessage(`"file:///secret"`)
		}},
		{"provider", func(_ *openClawTerminalV1, value *openClawResultV1) { value.Meta.Provider = "other" }},
		{"tools", func(_ *openClawTerminalV1, value *openClawResultV1) { value.Meta.Tools = []string{"read"} }},
		{"failures", func(_ *openClawTerminalV1, value *openClawResultV1) { value.Meta.ToolFailures = 1 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			terminal := base
			var result openClawResultV1
			if err := json.Unmarshal(base.Result, &result); err != nil {
				t.Fatal(err)
			}
			result.Payloads = append([]openClawPayloadV1(nil), result.Payloads...)
			result.Meta.Tools = append([]string(nil), result.Meta.Tools...)
			test.mutate(&terminal, &result)
			terminal.Result = mustOpenClawJSON(t, result)
			terminal.ResultSHA256 = canonicalOpenClawResultDigest(t, terminal.Result)
			raw := append(mustOpenClawJSON(t, terminal), '\n')
			if _, err := VerifyOpenClawWorkspaceAuditResultV1(raw, sessionID); err == nil {
				t.Fatal("substituted OpenClaw result accepted")
			}
		})
	}
	badDigest := base
	badDigest.ResultSHA256 = strings.Repeat("0", 64)
	if _, err := VerifyOpenClawWorkspaceAuditResultV1(append(mustOpenClawJSON(t, badDigest), '\n'), sessionID); err == nil {
		t.Fatal("invalid result digest accepted")
	}
	valid := validOpenClawCanaryResult(t, sessionID)
	if _, err := VerifyOpenClawWorkspaceAuditResultV1(valid[:len(valid)-1], sessionID); err == nil {
		t.Fatal("terminal without canonical newline accepted")
	}
	duplicate := strings.Replace(string(valid), `"status":"completed"`, `"status":"completed","status":"completed"`, 1)
	if _, err := VerifyOpenClawWorkspaceAuditResultV1([]byte(duplicate), sessionID); err == nil {
		t.Fatal("duplicate terminal field accepted")
	}
}

func validOpenClawCanaryResult(t *testing.T, sessionID string) []byte {
	t.Helper()
	return append(mustOpenClawJSON(t, validOpenClawTerminal(t, sessionID)), '\n')
}

func validOpenClawTerminal(t *testing.T, sessionID string) openClawTerminalV1 {
	t.Helper()
	result := openClawResultV1{
		Payloads: []openClawPayloadV1{{Text: OpenClawSuccessText, MediaURL: json.RawMessage("null")}},
		Meta: openClawMetaV1{
			DurationMS: 7701, Model: "steward-openclaw-fixture", Provider: "steward",
			ToolCalls: 1, ToolFailures: 0, Tools: []string{"exec"},
		},
	}
	resultRaw := mustOpenClawJSON(t, result)
	return openClawTerminalV1{
		RunID: "run_0123456789abcdef0123456789abcdef", SessionID: sessionID,
		Status: OpenClawCompletedStatus, Result: resultRaw,
		ResultSHA256: canonicalOpenClawResultDigest(t, resultRaw),
		Qualification: openClawQualificationResult{
			FixtureID:               agentrelease.OpenClawWorkspaceAuditFixtureID,
			WorkspaceManifestDigest: agentrelease.OpenClawWorkspaceAuditManifestDigest,
		},
	}
}

func canonicalOpenClawResultDigest(t *testing.T, raw []byte) string {
	t.Helper()
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatal(err)
	}
	canonical := mustOpenClawJSON(t, value)
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:])
}

func mustOpenClawJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
