package activation

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

type proofFixture struct {
	plan     PlanV1
	planRaw  []byte
	state    StateV1
	stateRaw []byte
	proof    ProofV1
	proofRaw []byte
}

func validProofFixture(t *testing.T) proofFixture {
	t.Helper()
	plan := validPlan()
	planRaw := mustMarshalPlan(t, plan)
	state := StateV1{
		SchemaVersion: StateSchemaV1,
		Binding:       validBinding(t, planRaw),
		Phase:         PhasePassed,
		RuntimeRef:    testRuntimeRef('a'),
		UpdatedAt:     "2026-07-16T10:00:30Z",
	}
	stateRaw := mustMarshalState(t, state)
	stateDigest, err := StateDigestV1(stateRaw)
	if err != nil {
		t.Fatalf("StateDigestV1() error = %v", err)
	}
	executor := ReceiptCoordinateV1{
		ReceiptNodeID:   state.Binding.NodeID,
		ReceiptEpoch:    4,
		Sequence:        19,
		ChainHash:       testSHA256('5'),
		PublicKeySHA256: testSHA256('6'),
	}
	proof := ProofV1{
		SchemaVersion: ProofSchemaV1,
		Binding:       state.Binding,
		StateDigest:   stateDigest,
		RuntimeRef:    state.RuntimeRef,
		Canary: CanaryProofV1{
			Kind:         plan.Canary.Kind,
			TaskDigest:   testSHA256('c'),
			PermitDigest: testSHA256('d'),
			ResultDigest: testSHA256('e'),
			ResultBytes:  42,
		},
		ExecutorEvidence: executor,
		GatewayEvidence: ReceiptCoordinateV1{
			ReceiptNodeID:   state.Binding.NodeID + "/gateway",
			ReceiptEpoch:    8,
			Sequence:        23,
			ChainHash:       testSHA256('7'),
			PublicKeySHA256: testSHA256('8'),
		},
		Witness: WitnessCoordinateV1{
			ControllerInstanceID:   "controller-a",
			ControlNodeID:          "control-a",
			ReceiptNodeID:          executor.ReceiptNodeID,
			ReceiptEpoch:           executor.ReceiptEpoch,
			Sequence:               executor.Sequence,
			ChainHash:              executor.ChainHash,
			ReceiptPublicKeySHA256: executor.PublicKeySHA256,
			WitnessPublicKeySHA256: testSHA256('9'),
			WitnessExportDigest:    testSHA256('b'),
			WitnessedAt:            "2026-07-16T10:00:31Z",
		},
		CompletedAt: "2026-07-16T10:00:32Z",
	}
	proofRaw := mustMarshalProof(t, proof)
	return proofFixture{
		plan:     plan,
		planRaw:  planRaw,
		state:    state,
		stateRaw: stateRaw,
		proof:    proof,
		proofRaw: proofRaw,
	}
}

func mustMarshalProof(t *testing.T, proof ProofV1) []byte {
	t.Helper()
	raw, err := MarshalProofV1(proof)
	if err != nil {
		t.Fatalf("MarshalProofV1() error = %v", err)
	}
	return raw
}

func TestProofRoundTripDigestAndCorrelation(t *testing.T) {
	fixture := validProofFixture(t)
	parsed, err := ParseProofV1(fixture.proofRaw)
	if err != nil {
		t.Fatalf("ParseProofV1() error = %v", err)
	}
	if parsed != fixture.proof {
		t.Fatalf("ParseProofV1() = %#v, want %#v", parsed, fixture.proof)
	}
	digest, err := ProofDigestV1(fixture.proofRaw)
	if err != nil {
		t.Fatalf("ProofDigestV1() error = %v", err)
	}
	if !sha256Digest(digest) {
		t.Fatalf("ProofDigestV1() = %q, want canonical SHA-256", digest)
	}

	correlated, err := CorrelateProofV1(fixture.planRaw, fixture.stateRaw, fixture.proofRaw)
	if err != nil {
		t.Fatalf("CorrelateProofV1() error = %v", err)
	}
	if correlated != fixture.proof {
		t.Fatalf("CorrelateProofV1() = %#v, want %#v", correlated, fixture.proof)
	}
}

func TestProofValidationRejectsOutOfContractValues(t *testing.T) {
	tests := map[string]func(*ProofV1){
		"wrong schema": func(proof *ProofV1) {
			proof.SchemaVersion = "steward.activation-proof.v2"
		},
		"bad state digest": func(proof *ProofV1) {
			proof.StateDigest = strings.Repeat("a", 64)
		},
		"bad runtime reference": func(proof *ProofV1) {
			proof.RuntimeRef = "executor-latest"
		},
		"arbitrary canary": func(proof *ProofV1) {
			proof.Canary.Kind = "shell_command_v1"
		},
		"zero canary result bytes": func(proof *ProofV1) {
			proof.Canary.ResultBytes = 0
		},
		"oversize canary result": func(proof *ProofV1) {
			proof.Canary.ResultBytes = MaxCanaryResultBytes + 1
		},
		"foreign executor node": func(proof *ProofV1) {
			proof.ExecutorEvidence.ReceiptNodeID = "node-b"
			proof.Witness.ReceiptNodeID = "node-b"
		},
		"foreign gateway node": func(proof *ProofV1) {
			proof.GatewayEvidence.ReceiptNodeID = "node-b/gateway"
		},
		"zero receipt epoch": func(proof *ProofV1) {
			proof.ExecutorEvidence.ReceiptEpoch = 0
		},
		"witness sequence substitution": func(proof *ProofV1) {
			proof.Witness.Sequence++
		},
		"witness chain substitution": func(proof *ProofV1) {
			proof.Witness.ChainHash = testSHA256('a')
		},
		"witness receipt key substitution": func(proof *ProofV1) {
			proof.Witness.ReceiptPublicKeySHA256 = testSHA256('a')
		},
		"invalid controller identity": func(proof *ProofV1) {
			proof.Witness.ControllerInstanceID = " controller-a"
		},
		"noncanonical zero fraction witness time": func(proof *ProofV1) {
			proof.Witness.WitnessedAt = "2026-07-16T10:00:31.000Z"
		},
		"offset completion time": func(proof *ProofV1) {
			proof.CompletedAt = "2026-07-16T03:00:32-07:00"
		},
		"witness after completion": func(proof *ProofV1) {
			proof.Witness.WitnessedAt = "2026-07-16T10:00:33Z"
		},
	}

	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := validProofFixture(t)
			mutate(&fixture.proof)
			if err := fixture.proof.Validate(); !errors.Is(err, ErrInvalidProof) {
				t.Fatalf("Validate() error = %v, want ErrInvalidProof", err)
			}
			if _, err := MarshalProofV1(fixture.proof); !errors.Is(err, ErrInvalidProof) {
				t.Fatalf("MarshalProofV1() error = %v, want ErrInvalidProof", err)
			}
		})
	}
}

func TestParseProofV1RejectsNonExactOrOversizeJSON(t *testing.T) {
	raw := string(validProofFixture(t).proofRaw)
	tests := map[string][]byte{
		"unknown top-level url": []byte(strings.TrimSuffix(raw, "}") + `,"url":"https://invalid"}`),
		"duplicate completion": []byte(strings.Replace(raw,
			`"completed_at":"2026-07-16T10:00:32Z"`,
			`"completed_at":"2026-07-16T10:00:32Z","completed_at":"2026-07-16T10:00:32Z"`, 1)),
		"unknown nested canary command": []byte(strings.Replace(raw,
			`"result_bytes":42`, `"result_bytes":42,"command":"audit"`, 1)),
		"duplicate nested coordinate": []byte(strings.Replace(raw,
			`"receipt_epoch":4`, `"receipt_epoch":4,"receipt_epoch":4`, 1)),
		"oversize": bytes.Repeat([]byte{' '}, MaxProofBytes+1),
	}
	for name, candidate := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := ParseProofV1(candidate)
			if !errors.Is(err, ErrInvalidProof) {
				t.Fatalf("ParseProofV1() error = %v, want ErrInvalidProof", err)
			}
		})
	}
}

func TestCorrelateProofV1RejectsSubstitutionAndNonFinalState(t *testing.T) {
	tests := map[string]func(*testing.T, proofFixture) ([]byte, []byte, []byte){
		"cross-node substitution": func(t *testing.T, fixture proofFixture) ([]byte, []byte, []byte) {
			fixture.state.Binding.NodeID = "node-b"
			return fixture.planRaw, mustMarshalState(t, fixture.state), fixture.proofRaw
		},
		"generation substitution": func(t *testing.T, fixture proofFixture) ([]byte, []byte, []byte) {
			fixture.state.Binding.Generation++
			return fixture.planRaw, mustMarshalState(t, fixture.state), fixture.proofRaw
		},
		"release plan substitution": func(t *testing.T, fixture proofFixture) ([]byte, []byte, []byte) {
			fixture.plan.ReleaseDigest = testSHA256('a')
			return mustMarshalPlan(t, fixture.plan), fixture.stateRaw, fixture.proofRaw
		},
		"state byte substitution": func(t *testing.T, fixture proofFixture) ([]byte, []byte, []byte) {
			return fixture.planRaw, append(append([]byte(nil), fixture.stateRaw...), '\n'), fixture.proofRaw
		},
		"runtime reference substitution": func(t *testing.T, fixture proofFixture) ([]byte, []byte, []byte) {
			fixture.proof.RuntimeRef = testRuntimeRef('b')
			return fixture.planRaw, fixture.stateRaw, mustMarshalProof(t, fixture.proof)
		},
		"non-final state": func(t *testing.T, fixture proofFixture) ([]byte, []byte, []byte) {
			fixture.state.Phase = PhaseEvidenceCollected
			return fixture.planRaw, mustMarshalState(t, fixture.state), fixture.proofRaw
		},
		"completion before final state": func(t *testing.T, fixture proofFixture) ([]byte, []byte, []byte) {
			fixture.proof.Witness.WitnessedAt = "2026-07-16T10:00:28Z"
			fixture.proof.CompletedAt = "2026-07-16T10:00:29Z"
			return fixture.planRaw, fixture.stateRaw, mustMarshalProof(t, fixture.proof)
		},
	}

	for name, build := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := validProofFixture(t)
			planRaw, stateRaw, proofRaw := build(t, fixture)
			_, err := CorrelateProofV1(planRaw, stateRaw, proofRaw)
			if !errors.Is(err, ErrInvalidProof) {
				t.Fatalf("CorrelateProofV1() error = %v, want ErrInvalidProof", err)
			}
			switch name {
			case "cross-node substitution", "generation substitution", "release plan substitution",
				"state byte substitution", "runtime reference substitution":
				if !errors.Is(err, ErrBindingMismatch) {
					t.Fatalf("CorrelateProofV1() error = %v, want ErrBindingMismatch", err)
				}
			}
		})
	}
}

func TestProofBoundsAcceptMaximumCanaryResultSize(t *testing.T) {
	fixture := validProofFixture(t)
	fixture.proof.Canary.ResultBytes = MaxCanaryResultBytes
	if err := fixture.proof.Validate(); err != nil {
		t.Fatalf("Validate() maximum result size error = %v", err)
	}
}

func TestProofAcceptsCanonicalNanosecondTimes(t *testing.T) {
	fixture := validProofFixture(t)
	fixture.proof.Witness.WitnessedAt = "2026-07-16T10:00:31.000000001Z"
	fixture.proof.CompletedAt = "2026-07-16T10:00:31.000000002Z"
	if err := fixture.proof.Validate(); err != nil {
		t.Fatalf("Validate() nanosecond times error = %v", err)
	}
}
