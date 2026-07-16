package activation

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/hardrails/steward/internal/agentrelease"
)

func TestVerifyHermesWorkspaceAuditResultV1(t *testing.T) {
	sessionID := "steward-activation-activation-001"
	raw := validHermesCanaryResult(t, sessionID)
	verified, err := VerifyHermesWorkspaceAuditResultV1(raw, sessionID)
	if err != nil {
		t.Fatal(err)
	}
	if verified.RunID != "run_0123456789abcdef0123456789abcdef" ||
		verified.SessionID != sessionID ||
		verified.ManifestDigest != agentrelease.HermesWorkspaceAuditEmptyManifestDigest {
		t.Fatalf("verified result = %#v", verified)
	}
}

func TestVerifyHermesWorkspaceAuditResultV1RejectsSubstitution(t *testing.T) {
	sessionID := "steward-activation-activation-001"
	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"unknown top-level field", func(terminal map[string]any) { terminal["extra"] = true }},
		{"wrong object", func(terminal map[string]any) { terminal["object"] = "other.run" }},
		{"wrong run ID", func(terminal map[string]any) { terminal["run_id"] = "run_other" }},
		{"not completed", func(terminal map[string]any) { terminal["status"] = "failed" }},
		{"wrong event", func(terminal map[string]any) { terminal["last_event"] = "run.failed" }},
		{"wrong session", func(terminal map[string]any) { terminal["session_id"] = "steward-activation-other" }},
		{"backward time", func(terminal map[string]any) { terminal["updated_at"] = 0.5 }},
		{"bad token total", func(terminal map[string]any) {
			terminal["usage"].(map[string]any)["total_tokens"] = float64(4)
		}},
		{"nonempty workspace", func(terminal map[string]any) {
			output := terminal["output"].(map[string]any)
			output["entries"] = []any{map[string]any{
				"path": "secret", "sha256": strings.Repeat("a", 64), "size": float64(1),
			}}
			output["file_count"] = float64(1)
		}},
		{"wrong manifest", func(terminal map[string]any) {
			terminal["output"].(map[string]any)["manifest_digest"] = "sha256:" + strings.Repeat("a", 64)
		}},
		{"unknown workspace field", func(terminal map[string]any) {
			terminal["output"].(map[string]any)["extra"] = true
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := validHermesCanaryValue(sessionID)
			test.mutate(value)
			raw := marshalHermesCanaryValue(t, value)
			if _, err := VerifyHermesWorkspaceAuditResultV1(raw, sessionID); err == nil {
				t.Fatal("invalid Hermes result accepted")
			}
		})
	}
}

func TestVerifyHermesWorkspaceAuditResultV1RejectsAmbiguousOrNoncanonicalOutput(t *testing.T) {
	sessionID := "steward-activation-activation-001"
	raw := validHermesCanaryResult(t, sessionID)
	duplicate := strings.Replace(
		string(raw),
		`"status":"completed"`,
		`"status":"completed","status":"completed"`,
		1,
	)
	if _, err := VerifyHermesWorkspaceAuditResultV1([]byte(duplicate), sessionID); err == nil {
		t.Fatal("duplicate terminal field accepted")
	}

	value := validHermesCanaryValue(sessionID)
	outputRaw, err := json.Marshal(value["output"])
	if err != nil {
		t.Fatal(err)
	}
	value["output"] = " " + string(outputRaw)
	raw, err = json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyHermesWorkspaceAuditResultV1(raw, sessionID); err == nil ||
		!strings.Contains(err.Error(), "canonical") {
		t.Fatalf("noncanonical workspace output err = %v", err)
	}
}

func validHermesCanaryResult(t *testing.T, sessionID string) []byte {
	t.Helper()
	return marshalHermesCanaryValue(t, validHermesCanaryValue(sessionID))
}

func marshalHermesCanaryValue(t *testing.T, value map[string]any) []byte {
	t.Helper()
	output, ok := value["output"].(map[string]any)
	if ok {
		raw, err := json.Marshal(output)
		if err != nil {
			t.Fatal(err)
		}
		value["output"] = string(raw)
	}
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func validHermesCanaryValue(sessionID string) map[string]any {
	return map[string]any{
		"object":     HermesRunObject,
		"run_id":     "run_0123456789abcdef0123456789abcdef",
		"status":     HermesCompletedStatus,
		"updated_at": float64(2),
		"created_at": float64(1),
		"session_id": sessionID,
		"model":      "steward-fixture-model",
		"output": map[string]any{
			"entries":         []any{},
			"file_count":      float64(0),
			"manifest_digest": agentrelease.HermesWorkspaceAuditEmptyManifestDigest,
			"root":            HermesWorkspaceRoot,
			"schema_version":  HermesWorkspaceSchemaV1,
			"total_bytes":     float64(0),
		},
		"usage": map[string]any{
			"input_tokens": float64(2), "output_tokens": float64(1), "total_tokens": float64(3),
		},
		"last_event": HermesCompletedEvent,
	}
}
