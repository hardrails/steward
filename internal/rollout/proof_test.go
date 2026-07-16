package rollout

import (
	"strings"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/activation"
	"github.com/hardrails/steward/internal/dsse"
)

func TestCorrelateProofManifestV1AcceptsCompleteOrderedProof(t *testing.T) {
	fixture := rolloutProofFixture(t)
	manifest, err := CorrelateProofManifestV1(
		fixture.planRaw,
		[][]byte{fixture.targetStateRaw},
		[][]byte{fixture.activationPlanRaw},
		[][]byte{fixture.activationStateRaw},
		[][]byte{fixture.activationProofRaw},
		fixture.manifestRaw,
	)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.RolloutID != fixture.plan.RolloutID ||
		len(manifest.Targets) != 1 ||
		manifest.Targets[0].NodeID != fixture.plan.Targets[0].NodeID {
		t.Fatalf("manifest=%#v", manifest)
	}
}

func TestCorrelateProofManifestV1RejectsSubstitutionAndIncompleteTargets(t *testing.T) {
	t.Run("manifest proof digest", func(t *testing.T) {
		fixture := rolloutProofFixture(t)
		fixture.manifest.Targets[0].ActivationProofDigest = digest("9")
		fixture.manifestRaw, _ = MarshalProofManifestV1(fixture.manifest)
		if _, err := correlateProofFixture(fixture); err == nil {
			t.Fatal("substituted proof digest accepted")
		}
	})
	t.Run("node-local activation plan", func(t *testing.T) {
		fixture := rolloutProofFixture(t)
		fixture.activationPlan.Transport = activation.TransportNodeLocal
		fixture.activationPlanRaw, _ = activation.MarshalPlanV1(fixture.activationPlan)
		if _, err := correlateProofFixture(fixture); err == nil {
			t.Fatal("node-local activation plan accepted as remote rollout proof")
		}
	})
	t.Run("target action required", func(t *testing.T) {
		fixture := rolloutProofFixture(t)
		fixture.targetState.Phase = PhaseActionRequired
		fixture.targetState.ActionRequiredReason = "canary_terminal_failure"
		fixture.targetStateRaw, _ = MarshalTargetStateV1(fixture.targetState)
		if _, err := correlateProofFixture(fixture); err == nil {
			t.Fatal("action-required target accepted as passed")
		}
	})
	t.Run("completed before target", func(t *testing.T) {
		fixture := rolloutProofFixture(t)
		fixture.manifest.CompletedAt = planTime(5 * time.Second)
		fixture.manifestRaw, _ = MarshalProofManifestV1(fixture.manifest)
		if _, err := correlateProofFixture(fixture); err == nil {
			t.Fatal("premature rollout completion accepted")
		}
	})
	t.Run("missing companion", func(t *testing.T) {
		fixture := rolloutProofFixture(t)
		if _, err := CorrelateProofManifestV1(
			fixture.planRaw,
			nil,
			[][]byte{fixture.activationPlanRaw},
			[][]byte{fixture.activationStateRaw},
			[][]byte{fixture.activationProofRaw},
			fixture.manifestRaw,
		); err == nil {
			t.Fatal("missing target state accepted")
		}
	})
}

func TestProofManifestV1RejectsAmbiguousAndInvalidShape(t *testing.T) {
	fixture := rolloutProofFixture(t)
	for name, mutate := range map[string]func(*ProofManifestV1){
		"schema":  func(value *ProofManifestV1) { value.SchemaVersion = "other" },
		"rollout": func(value *ProofManifestV1) { value.RolloutID = "-bad" },
		"plan":    func(value *ProofManifestV1) { value.PlanDigest = "" },
		"empty":   func(value *ProofManifestV1) { value.Targets = nil },
		"index":   func(value *ProofManifestV1) { value.Targets[0].TargetIndex = 1 },
		"node":    func(value *ProofManifestV1) { value.Targets[0].NodeID = "" },
		"proof digest": func(value *ProofManifestV1) {
			value.Targets[0].ActivationProofDigest = "bad"
		},
		"completed": func(value *ProofManifestV1) { value.CompletedAt = "bad" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := fixture.manifest
			candidate.Targets = append([]TargetProofV1(nil), fixture.manifest.Targets...)
			mutate(&candidate)
			if err := candidate.Validate(); err == nil {
				t.Fatalf("invalid manifest accepted: %#v", candidate)
			}
		})
	}
	raw := fixture.manifestRaw
	for name, ambiguous := range map[string][]byte{
		"unknown": append(append([]byte(nil), raw[:len(raw)-1]...), []byte(`,"unknown":true}`)...),
		"duplicate": []byte(strings.Replace(
			string(raw),
			`"schema_version":"`+ProofManifestSchemaV1+`"`,
			`"schema_version":"`+ProofManifestSchemaV1+`","schema_version":"`+ProofManifestSchemaV1+`"`,
			1,
		)),
		"trailing": append(append([]byte(nil), raw...), []byte(` {}`)...),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseProofManifestV1(ambiguous); err == nil {
				t.Fatal("ambiguous proof manifest accepted")
			}
		})
	}
}

type proofFixture struct {
	plan               PlanV1
	planRaw            []byte
	targetState        TargetStateV1
	targetStateRaw     []byte
	activationPlan     activation.PlanV1
	activationPlanRaw  []byte
	activationStateRaw []byte
	activationProofRaw []byte
	manifest           ProofManifestV1
	manifestRaw        []byte
}

func rolloutProofFixture(t *testing.T) proofFixture {
	t.Helper()
	plan := rolloutPlanFixture(1)
	target := plan.Targets[0]
	activationPlan := activation.PlanV1{
		SchemaVersion: activation.PlanSchemaV1,
		ActivationID:  target.ActivationID,
		ReleaseDigest: plan.ReleaseDigest,
		PolicyDigest:  plan.PolicyDigest,
		IntentDigest:  target.IntentDigest,
		Archive:       plan.Archive,
		Transport:     activation.TransportControlUplink,
		Canary:        plan.Canary,
		Timeouts: activation.TimeoutsV1{
			PreflightSeconds:   60,
			ImageImportSeconds: 60,
			AdmissionSeconds:   60,
			StartupSeconds:     60,
			CanarySeconds:      60,
			EvidenceSeconds:    60,
		},
	}
	activationPlanRaw, err := activation.MarshalPlanV1(activationPlan)
	if err != nil {
		t.Fatal(err)
	}
	plan.Targets[0].ActivationPlanDigest = dsse.Digest(activationPlanRaw)
	planRaw, err := MarshalPlanV1(plan)
	if err != nil {
		t.Fatal(err)
	}
	target = plan.Targets[0]
	targetState := passedTargetState(initialTargetState(planRaw, plan, 0))
	targetState.UpdatedAt = planTime(11 * time.Second)
	targetStateRaw, err := MarshalTargetStateV1(targetState)
	if err != nil {
		t.Fatal(err)
	}

	activationBinding := activation.BindingV1{
		ActivationID:  target.ActivationID,
		PlanDigest:    dsse.Digest(activationPlanRaw),
		ReleaseDigest: plan.ReleaseDigest,
		PolicyDigest:  plan.PolicyDigest,
		IntentDigest:  target.IntentDigest,
		Archive:       plan.Archive,
		TenantID:      plan.TenantID,
		NodeID:        target.NodeID,
		InstanceID:    target.InstanceID,
		Generation:    target.InstanceGeneration,
	}
	activationState := activation.StateV1{
		SchemaVersion: activation.StateSchemaV1,
		Binding:       activationBinding,
		Phase:         activation.PhasePassed,
		RuntimeRef:    targetState.RuntimeRef,
		UpdatedAt:     planTime(10 * time.Second),
	}
	activationStateRaw, err := activation.MarshalStateV1(activationState)
	if err != nil {
		t.Fatal(err)
	}
	executorCoordinate := activation.ReceiptCoordinateV1{
		ReceiptNodeID:   target.NodeID,
		ReceiptEpoch:    1,
		Sequence:        8,
		ChainHash:       digest("1"),
		PublicKeySHA256: digest("2"),
	}
	activationProof := activation.ProofV1{
		SchemaVersion: activation.ProofSchemaV1,
		Binding:       activationBinding,
		StateDigest:   dsse.Digest(activationStateRaw),
		RuntimeRef:    targetState.RuntimeRef,
		Canary: activation.CanaryProofV1{
			Kind:         activation.CanaryHermesWorkspaceAuditV1,
			TaskDigest:   digest("3"),
			PermitDigest: digest("4"),
			ResultDigest: targetState.CanaryResultDigest,
			ResultBytes:  targetState.CanaryResultBytes,
		},
		ExecutorBeginDigest:      digest("5"),
		ExecutorCheckpointDigest: digest("6"),
		ExecutorEvidence:         executorCoordinate,
		GatewayEvidence: activation.ReceiptCoordinateV1{
			ReceiptNodeID:   target.NodeID + "/gateway",
			ReceiptEpoch:    1,
			Sequence:        3,
			ChainHash:       digest("7"),
			PublicKeySHA256: digest("8"),
		},
		Witness: activation.WitnessCoordinateV1{
			ControllerInstanceID:   "controller-1",
			ControlNodeID:          target.NodeID,
			ReceiptNodeID:          executorCoordinate.ReceiptNodeID,
			ReceiptEpoch:           executorCoordinate.ReceiptEpoch,
			Sequence:               executorCoordinate.Sequence,
			ChainHash:              executorCoordinate.ChainHash,
			ReceiptPublicKeySHA256: executorCoordinate.PublicKeySHA256,
			WitnessPublicKeySHA256: digest("9"),
			WitnessExportDigest:    digest("0"),
			WitnessedAt:            planTime(9 * time.Second),
		},
		CompletedAt: planTime(12 * time.Second),
	}
	activationProofRaw, err := activation.MarshalProofV1(activationProof)
	if err != nil {
		t.Fatal(err)
	}
	manifest := ProofManifestV1{
		SchemaVersion: ProofManifestSchemaV1,
		RolloutID:     plan.RolloutID,
		PlanDigest:    dsse.Digest(planRaw),
		Targets: []TargetProofV1{{
			TargetIndex:           0,
			NodeID:                target.NodeID,
			ActivationID:          target.ActivationID,
			ActivationPlanDigest:  target.ActivationPlanDigest,
			TargetStateDigest:     dsse.Digest(targetStateRaw),
			ActivationProofDigest: dsse.Digest(activationProofRaw),
		}},
		CompletedAt: planTime(13 * time.Second),
	}
	manifestRaw, err := MarshalProofManifestV1(manifest)
	if err != nil {
		t.Fatal(err)
	}
	return proofFixture{
		plan:               plan,
		planRaw:            planRaw,
		targetState:        targetState,
		targetStateRaw:     targetStateRaw,
		activationPlan:     activationPlan,
		activationPlanRaw:  activationPlanRaw,
		activationStateRaw: activationStateRaw,
		activationProofRaw: activationProofRaw,
		manifest:           manifest,
		manifestRaw:        manifestRaw,
	}
}

func correlateProofFixture(fixture proofFixture) (ProofManifestV1, error) {
	return CorrelateProofManifestV1(
		fixture.planRaw,
		[][]byte{fixture.targetStateRaw},
		[][]byte{fixture.activationPlanRaw},
		[][]byte{fixture.activationStateRaw},
		[][]byte{fixture.activationProofRaw},
		fixture.manifestRaw,
	)
}
