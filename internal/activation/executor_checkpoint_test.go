package activation

import (
	"strings"
	"testing"
)

func TestExecutorBeginRoundTripDigestAndValidation(t *testing.T) {
	fixture := validProofFixture(t)
	raw, err := MarshalExecutorBeginV1(
		fixture.state.Binding,
		fixture.state.RuntimeRef,
		"steward-state-"+strings.Repeat("b", 64),
		testSHA256('c'),
	)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseExecutorBeginV1(raw)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Binding != fixture.state.Binding ||
		parsed.RuntimeRef != fixture.state.RuntimeRef ||
		parsed.StateRuntimeRef != "steward-state-"+strings.Repeat("b", 64) ||
		parsed.CapsuleDigest != testSHA256('c') {
		t.Fatalf("parsed begin=%#v", parsed)
	}
	if digest, err := ExecutorBeginDigestV1(raw); err != nil ||
		!sha256Digest(digest) {
		t.Fatalf("begin digest=%q err=%v", digest, err)
	}
	if _, err := ParseExecutorBeginV1(append(raw, '\n')); err == nil {
		t.Fatal("non-canonical begin marker accepted")
	}
	if _, err := ExecutorBeginDigestV1([]byte(`{}`)); err == nil {
		t.Fatal("invalid begin marker produced a digest")
	}

	valid := parsed
	for name, mutate := range map[string]func(*ExecutorBeginV1){
		"schema": func(value *ExecutorBeginV1) {
			value.SchemaVersion = "steward.activation-executor-begin.v2"
		},
		"binding": func(value *ExecutorBeginV1) {
			value.Binding.ActivationID = ""
		},
		"runtime": func(value *ExecutorBeginV1) {
			value.RuntimeRef = "latest"
		},
		"state runtime": func(value *ExecutorBeginV1) {
			value.StateRuntimeRef = "../state"
		},
		"capsule": func(value *ExecutorBeginV1) {
			value.CapsuleDigest = strings.Repeat("a", 64)
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			mutate(&candidate)
			if err := candidate.Validate(); err == nil {
				t.Fatal("invalid begin marker accepted")
			}
		})
	}
}

func TestExecutorCheckpointRoundTripDigestAndValidation(t *testing.T) {
	fixture := validProofFixture(t)
	gateway := GatewayEvidenceResultV1{
		Receipts:     []byte("signed gateway receipts"),
		Coordinate:   fixture.proof.GatewayEvidence,
		Canary:       fixture.proof.Canary,
		AuthorizedAt: "2026-07-16T10:00:20Z",
		TerminalAt:   "2026-07-16T10:00:21Z",
	}
	raw, err := MarshalExecutorCheckpointV1(
		fixture.state.Binding,
		fixture.state.RuntimeRef,
		testSHA256('c'),
		testSHA256('d'),
		"grant-"+strings.Repeat("e", 64),
		gateway,
	)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseExecutorCheckpointV1(raw)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Binding != fixture.state.Binding ||
		parsed.RuntimeRef != fixture.state.RuntimeRef ||
		parsed.GatewayEvidence != gateway.Coordinate ||
		parsed.Canary != gateway.Canary ||
		parsed.AuthorizedAt != gateway.AuthorizedAt ||
		parsed.TerminalAt != gateway.TerminalAt {
		t.Fatalf("parsed checkpoint=%#v", parsed)
	}
	if digest, err := ExecutorCheckpointDigestV1(raw); err != nil ||
		!sha256Digest(digest) {
		t.Fatalf("checkpoint digest=%q err=%v", digest, err)
	}
	if _, err := ParseExecutorCheckpointV1(append(raw, '\n')); err == nil {
		t.Fatal("non-canonical checkpoint accepted")
	}
	if _, err := ExecutorCheckpointDigestV1([]byte(`{}`)); err == nil {
		t.Fatal("invalid checkpoint produced a digest")
	}

	valid := parsed
	for name, mutate := range map[string]func(*ExecutorCheckpointV1){
		"schema": func(value *ExecutorCheckpointV1) {
			value.SchemaVersion = "steward.activation-executor-checkpoint.v2"
		},
		"binding": func(value *ExecutorCheckpointV1) {
			value.Binding.ActivationID = ""
		},
		"runtime": func(value *ExecutorCheckpointV1) {
			value.RuntimeRef = "latest"
		},
		"capsule": func(value *ExecutorCheckpointV1) {
			value.CapsuleDigest = strings.Repeat("a", 64)
		},
		"route policy": func(value *ExecutorCheckpointV1) {
			value.RoutePolicyDigest = strings.Repeat("a", 64)
		},
		"grant": func(value *ExecutorCheckpointV1) {
			value.GrantID = "../grant"
		},
		"receipts digest": func(value *ExecutorCheckpointV1) {
			value.GatewayReceiptsDigest = strings.Repeat("a", 64)
		},
		"gateway coordinate": func(value *ExecutorCheckpointV1) {
			value.GatewayEvidence.ReceiptEpoch = 0
		},
		"canary": func(value *ExecutorCheckpointV1) {
			value.Canary.ResultBytes = 0
		},
		"authorized time": func(value *ExecutorCheckpointV1) {
			value.AuthorizedAt = "not-a-time"
		},
		"terminal time": func(value *ExecutorCheckpointV1) {
			value.TerminalAt = "not-a-time"
		},
		"terminal predates authorization": func(value *ExecutorCheckpointV1) {
			value.TerminalAt = "2026-07-16T10:00:19Z"
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			mutate(&candidate)
			if err := candidate.Validate(); err == nil {
				t.Fatal("invalid checkpoint accepted")
			}
		})
	}
}

func TestVerifyExecutorWitnessPairV1(t *testing.T) {
	fixture := newExecutorEvidenceFixture(t)
	if err := VerifyExecutorWitnessPairV1(fixture.request); err != nil {
		t.Fatal(err)
	}
	invalid := fixture.request
	invalid.RuntimeRef = "latest"
	if err := VerifyExecutorWitnessPairV1(invalid); err == nil {
		t.Fatal("invalid witness pair accepted")
	}
}
