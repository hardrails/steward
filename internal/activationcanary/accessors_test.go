package activationcanary

import (
	"testing"

	"github.com/hardrails/steward/internal/activation"
)

func TestVerifiedResultCanaryReturnsAgentNeutralObservation(t *testing.T) {
	want := activation.CanaryResultV1{RunID: "run-1", SessionID: "session-1"}
	verified := VerifiedResultV1{canary: want}
	if got := verified.Canary(); got != want {
		t.Fatalf("canary observation = %+v, want %+v", got, want)
	}
}
