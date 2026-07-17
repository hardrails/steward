package rollout

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/activation"
	"github.com/hardrails/steward/internal/dsse"
)

func TestTargetStateSecurityBoundariesFailClosed(t *testing.T) {
	plan := rolloutPlanFixture(2)
	planRaw, err := MarshalPlanV1(plan)
	if err != nil {
		t.Fatal(err)
	}
	initial := initialTargetState(planRaw, plan, 0)
	initialRaw, err := MarshalTargetStateV1(initial)
	if err != nil {
		t.Fatal(err)
	}
	if digest, err := TargetStateDigestV1(initialRaw); err != nil || digest != dsse.Digest(initialRaw) {
		t.Fatalf("state digest=(%q, %v)", digest, err)
	}
	if _, err := TargetStateDigestV1([]byte(`{"schema_version":"unknown"}`)); err == nil {
		t.Fatal("invalid state bytes acquired a digest")
	}
	invalid := initial
	invalid.SchemaVersion = "unknown"
	if _, err := MarshalTargetStateV1(invalid); err == nil {
		t.Fatal("invalid state marshaled")
	}

	action := initial
	action.Phase = PhaseActionRequired
	action.ActionRequiredReason = "operator_review"
	action.CanaryResultDigest = digest("a")
	if err := action.Validate(); err == nil {
		t.Fatal("partial canary evidence accepted in action_required")
	}
	admitted := initial
	admitted.Phase = PhaseAdmitted
	admitted.UpdatedAt = nextStateTime(initial.UpdatedAt)
	if err := admitted.Validate(); err == nil {
		t.Fatal("admitted state without a runtime binding accepted")
	}
	terminal := passedTargetState(initial)
	terminal.Phase = PhaseAgentReportedTerminal
	terminal.CanaryResultBytes = activation.MaxCanaryResultBytes + 1
	if err := terminal.Validate(); err == nil {
		t.Fatal("oversized terminal result identity accepted")
	}

	next := initial
	next.Phase = PhasePreflightPassed
	next.UpdatedAt = nextStateTime(initial.UpdatedAt)
	if err := ValidateTargetTransitionV1(initial, initial); err != nil {
		t.Fatalf("exact transition replay rejected: %v", err)
	}
	for name, test := range map[string]struct {
		current     TargetStateV1
		next        TargetStateV1
		wantBinding bool
	}{
		"invalid current": {
			current: invalid,
			next:    next,
		},
		"invalid next": {
			current: initial,
			next:    invalid,
		},
		"changed binding": {
			current: initial,
			next: func() TargetStateV1 {
				value := next
				value.Binding.NodeID = "substituted"
				return value
			}(),
			wantBinding: true,
		},
		"passed is terminal": {
			current: passedTargetState(initial),
			next: func() TargetStateV1 {
				value := passedTargetState(next)
				value.UpdatedAt = nextStateTime(value.UpdatedAt)
				return value
			}(),
		},
		"time did not advance": {
			current: initial,
			next: func() TargetStateV1 {
				value := next
				value.UpdatedAt = initial.UpdatedAt
				return value
			}(),
		},
	} {
		t.Run(name, func(t *testing.T) {
			err := ValidateTargetTransitionV1(test.current, test.next)
			if err == nil {
				t.Fatal("unsafe transition accepted")
			}
			if test.wantBinding && !errors.Is(err, ErrBindingMismatch) {
				t.Fatalf("binding substitution error=%v", err)
			}
		})
	}

	canarySubmitted := passedTargetState(initial)
	canarySubmitted.Phase = PhaseCanarySubmitted
	canarySubmitted.CanaryResultDigest = ""
	canarySubmitted.CanaryResultBytes = 0
	observed := canarySubmitted
	observed.Phase = PhaseAgentReportedTerminal
	observed.UpdatedAt = nextStateTime(canarySubmitted.UpdatedAt)
	observed.CanaryResultDigest = digest("b")
	observed.CanaryResultBytes = 16
	if err := ValidateTargetTransitionV1(canarySubmitted, observed); err != nil {
		t.Fatalf("terminal evidence introduction rejected: %v", err)
	}
	changed := observed
	changed.Phase = PhaseEvidenceCollected
	changed.UpdatedAt = nextStateTime(observed.UpdatedAt)
	changed.CanaryResultDigest = digest("c")
	if err := ValidateTargetTransitionV1(observed, changed); err == nil {
		t.Fatal("terminal canary evidence changed")
	}
	earlyCanary := canarySubmitted
	earlyCanary.Phase = PhaseEvidenceCollected
	earlyCanary.UpdatedAt = nextStateTime(canarySubmitted.UpdatedAt)
	earlyCanary.CanaryResultDigest = digest("d")
	earlyCanary.CanaryResultBytes = 16
	if err := ValidateTargetTransitionV1(canarySubmitted, earlyCanary); err == nil {
		t.Fatal("canary result appeared before terminal observation")
	}

	if err := CorrelateTargetStateV1([]byte("not-json"), initial); err == nil {
		t.Fatal("state correlated to an invalid plan")
	}
	outside := initial
	outside.Binding.TargetIndex = uint16(len(plan.Targets))
	if err := CorrelateTargetStateV1(planRaw, outside); !errors.Is(err, ErrBindingMismatch) {
		t.Fatalf("out-of-range target error=%v", err)
	}
	substituted := initial
	substituted.Binding.InstanceID = plan.Targets[1].InstanceID
	if err := CorrelateTargetStateV1(planRaw, substituted); !errors.Is(err, ErrBindingMismatch) {
		t.Fatalf("substituted target error=%v", err)
	}
	late := initial
	late.UpdatedAt = planTime(2 * time.Hour)
	if err := CorrelateTargetStateV1(planRaw, late); err == nil {
		t.Fatal("normal progress after the rollout deadline accepted")
	}

	if err := ValidateFleetProgressV1([]byte("not-json"), nil); err == nil {
		t.Fatal("fleet progress accepted an invalid plan")
	}
	if err := ValidateFleetProgressV1(planRaw, []TargetStateV1{initial}); err == nil {
		t.Fatal("incomplete fleet progress accepted")
	}
	states := []TargetStateV1{
		initialTargetState(planRaw, plan, 0),
		initialTargetState(planRaw, plan, 1),
	}
	states[1].Binding.TargetIndex = 0
	if err := ValidateFleetProgressV1(planRaw, states); err == nil {
		t.Fatal("unordered fleet progress accepted")
	}
	states[1] = initialTargetState(planRaw, plan, 1)
	states[1].Binding.NodeID = "substituted"
	if err := ValidateFleetProgressV1(planRaw, states); err == nil {
		t.Fatal("uncorrelated fleet target accepted")
	}

	if runtimeRef("executor-" + strings.Repeat("g", 64)) {
		t.Fatal("non-hex runtime reference accepted")
	}
}

func TestRolloutAuthorizationSecurityBoundariesFailClosed(t *testing.T) {
	plan := rolloutPlanFixture(5)
	planRaw, err := MarshalPlanV1(plan)
	if err != nil {
		t.Fatal(err)
	}
	authorizedAt := time.Date(2026, 7, 16, 12, 1, 0, 0, time.UTC)
	statement, err := NewPlanAuthorizationV1(planRaw, authorizedAt)
	if err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherPublic, otherPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	authorizationRaw, err := SignPlanAuthorizationV1(statement, "command-key", private, public)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := NewPlanAuthorizationV1([]byte("not-json"), authorizedAt); err == nil {
		t.Fatal("invalid plan authorized")
	}
	for name, mutate := range map[string]func(*PlanAuthorizationV1){
		"identity":  func(value *PlanAuthorizationV1) { value.PlanDigest = "" },
		"timestamp": func(value *PlanAuthorizationV1) { value.AuthorizedAt = "not-time" },
	} {
		t.Run("plan statement "+name, func(t *testing.T) {
			changed := statement
			mutate(&changed)
			if changed.Validate() == nil {
				t.Fatal("invalid authorization statement accepted")
			}
			if _, err := SignPlanAuthorizationV1(changed, "command-key", private, public); err == nil {
				t.Fatal("invalid authorization statement signed")
			}
		})
	}
	if err := CorrelatePlanAuthorizationV1([]byte("not-json"), statement); err == nil {
		t.Fatal("authorization correlated to invalid plan")
	}
	invalidStatement := statement
	invalidStatement.CommandID = ""
	if err := CorrelatePlanAuthorizationV1(planRaw, invalidStatement); err == nil {
		t.Fatal("invalid authorization correlated")
	}
	if _, err := signAuthorizationEnvelope(
		PlanAuthorizationPayloadTypeV1, statement, "command-key",
		nil, nil, MaxPlanAuthorizationEnvelopeBytes,
	); err == nil {
		t.Fatal("missing signing key accepted")
	}
	if _, err := signAuthorizationEnvelope(
		PlanAuthorizationPayloadTypeV1, statement, "command-key",
		private, otherPublic, MaxPlanAuthorizationEnvelopeBytes,
	); err == nil {
		t.Fatal("mismatched signing key accepted")
	}
	if _, err := signAuthorizationEnvelope(
		PlanAuthorizationPayloadTypeV1, make(chan int), "command-key",
		private, public, MaxPlanAuthorizationEnvelopeBytes,
	); err == nil {
		t.Fatal("unmarshalable statement signed")
	}
	if _, err := signAuthorizationEnvelope(
		PlanAuthorizationPayloadTypeV1, statement, "command-key",
		private, public, 1,
	); err == nil {
		t.Fatal("oversized signed envelope accepted")
	}
	for name, test := range map[string]struct {
		raw     []byte
		trusted map[string]ed25519.PublicKey
	}{
		"empty":     {raw: nil, trusted: map[string]ed25519.PublicKey{"command-key": public}},
		"oversize":  {raw: make([]byte, MaxPlanAuthorizationEnvelopeBytes+1), trusted: map[string]ed25519.PublicKey{"command-key": public}},
		"untrusted": {raw: authorizationRaw, trusted: map[string]ed25519.PublicKey{"other": otherPublic}},
	} {
		t.Run("plan envelope "+name, func(t *testing.T) {
			if _, err := VerifyPlanAuthorizationV1(planRaw, test.raw, test.trusted); err == nil {
				t.Fatal("invalid authorization envelope accepted")
			}
		})
	}

	stateRaws, proofRaws, captureRaws := promotionCompanions(t, planRaw, plan)
	first, err := NewBatchPromotionV1(
		planRaw, authorizationRaw, nil, 1,
		stateRaws, proofRaws, captureRaws, authorizedAt.Add(time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	firstRaw, err := SignBatchPromotionV1(first, "command-key", private, public)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewBatchPromotionV1(
		planRaw, authorizationRaw, firstRaw, 2,
		stateRaws, proofRaws, captureRaws, authorizedAt.Add(2*time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}

	for name, mutate := range map[string]func(*BatchPromotionV1){
		"identity":  func(value *BatchPromotionV1) { value.PlanDigest = "" },
		"boundary":  func(value *BatchPromotionV1) { value.NextBatch.Start++ },
		"inventory": func(value *BatchPromotionV1) { value.CompletedTargets = nil },
		"target":    func(value *BatchPromotionV1) { value.CompletedTargets[0].NodeID = "" },
		"timestamp": func(value *BatchPromotionV1) { value.AuthorizedAt = "not-time" },
	} {
		t.Run("promotion statement "+name, func(t *testing.T) {
			changed := clonePromotion(t, first)
			mutate(&changed)
			if changed.Validate() == nil {
				t.Fatal("invalid promotion statement accepted")
			}
			if _, err := SignBatchPromotionV1(changed, "command-key", private, public); err == nil {
				t.Fatal("invalid promotion statement signed")
			}
		})
	}

	for name, invoke := range map[string]func() error{
		"invalid plan": func() error {
			_, err := NewBatchPromotionV1(
				[]byte("not-json"), authorizationRaw, nil, 1,
				stateRaws, proofRaws, captureRaws, authorizedAt,
			)
			return err
		},
		"outside batch": func() error {
			_, err := NewBatchPromotionV1(
				planRaw, authorizationRaw, nil, 0,
				stateRaws, proofRaws, captureRaws, authorizedAt,
			)
			return err
		},
		"incomplete companions": func() error {
			_, err := NewBatchPromotionV1(
				planRaw, authorizationRaw, nil, 1,
				nil, proofRaws, captureRaws, authorizedAt,
			)
			return err
		},
		"invalid completed state": func() error {
			changed := append([][]byte(nil), stateRaws...)
			changed[0] = []byte("not-json")
			_, err := NewBatchPromotionV1(
				planRaw, authorizationRaw, nil, 1,
				changed, proofRaws, captureRaws, authorizedAt,
			)
			return err
		},
		"empty completed proof": func() error {
			changed := append([][]byte(nil), proofRaws...)
			changed[0] = nil
			_, err := NewBatchPromotionV1(
				planRaw, authorizationRaw, nil, 1,
				stateRaws, changed, captureRaws, authorizedAt,
			)
			return err
		},
	} {
		t.Run("new promotion "+name, func(t *testing.T) {
			if err := invoke(); err == nil {
				t.Fatal("invalid promotion constructed")
			}
		})
	}

	if err := CorrelateBatchPromotionV1(
		[]byte("not-json"), authorizationRaw, nil, first,
		stateRaws, proofRaws, captureRaws,
	); err == nil {
		t.Fatal("promotion correlated to invalid plan")
	}
	invalidPromotion := first
	invalidPromotion.CommandID = ""
	if err := CorrelateBatchPromotionV1(
		planRaw, authorizationRaw, nil, invalidPromotion,
		stateRaws, proofRaws, captureRaws,
	); err == nil {
		t.Fatal("invalid promotion correlated")
	}
	if err := CorrelateBatchPromotionV1(
		planRaw, authorizationRaw, nil, second,
		stateRaws, proofRaws, captureRaws,
	); err == nil {
		t.Fatal("later promotion accepted without predecessor")
	}
	if err := CorrelateBatchPromotionV1(
		planRaw, authorizationRaw, []byte("unexpected"), first,
		stateRaws, proofRaws, captureRaws,
	); err == nil {
		t.Fatal("first promotion accepted a predecessor")
	}
	changedChain := first
	changedChain.PlanAuthorizationDigest = digest("9")
	if err := CorrelateBatchPromotionV1(
		planRaw, authorizationRaw, nil, changedChain,
		stateRaws, proofRaws, captureRaws,
	); err == nil {
		t.Fatal("promotion accepted changed authorization binding")
	}
	predates := first
	predates.AuthorizedAt = plan.CreatedAt
	if err := CorrelateBatchPromotionV1(
		planRaw, authorizationRaw, nil, predates,
		stateRaws, proofRaws, captureRaws,
	); err == nil {
		t.Fatal("promotion predating completed target accepted")
	}
	changedEvidence := clonePromotion(t, first)
	changedEvidence.CompletedTargets[0].CaptureExportDigest = digest("8")
	if err := CorrelateBatchPromotionV1(
		planRaw, authorizationRaw, nil, changedEvidence,
		stateRaws, proofRaws, captureRaws,
	); err == nil {
		t.Fatal("promotion accepted changed evidence binding")
	}
	if _, err := VerifyBatchPromotionV1(
		planRaw, authorizationRaw, nil, firstRaw,
		stateRaws, proofRaws, captureRaws,
		map[string]ed25519.PublicKey{"command-key": public}, "other-key",
	); err == nil {
		t.Fatal("promotion accepted a different expected signer")
	}
	if _, err := SignBatchPromotionV1(first, "command-key", otherPrivate, public); err == nil {
		t.Fatal("promotion signed with mismatched keypair")
	}
}

func TestRolloutProofAndPlanCompanionsFailClosed(t *testing.T) {
	fixture := rolloutProofFixture(t)
	if digest, err := PlanDigestV1(fixture.planRaw); err != nil || digest != dsse.Digest(fixture.planRaw) {
		t.Fatalf("plan digest=(%q, %v)", digest, err)
	}
	if _, err := PlanDigestV1([]byte("not-json")); err == nil {
		t.Fatal("invalid plan acquired a digest")
	}
	if digest, err := ProofManifestDigestV1(fixture.manifestRaw); err != nil ||
		digest != dsse.Digest(fixture.manifestRaw) {
		t.Fatalf("proof digest=(%q, %v)", digest, err)
	}
	if _, err := ProofManifestDigestV1([]byte("not-json")); err == nil {
		t.Fatal("invalid proof manifest acquired a digest")
	}
	invalidManifest := fixture.manifest
	invalidManifest.SchemaVersion = "unknown"
	if _, err := MarshalProofManifestV1(invalidManifest); err == nil {
		t.Fatal("invalid proof manifest marshaled")
	}
	invalidPromotionDigest := fixture.manifest
	invalidPromotionDigest.BatchPromotionDigests = []string{"invalid"}
	if err := invalidPromotionDigest.Validate(); err == nil {
		t.Fatal("invalid promotion digest inventory accepted")
	}
	invalidPlan := fixture.plan
	invalidPlan.SchemaVersion = "unknown"
	if _, err := MarshalPlanV1(invalidPlan); err == nil {
		t.Fatal("invalid plan marshaled")
	}
	if _, err := invalidPlan.Batches(); err == nil {
		t.Fatal("invalid plan produced rollout batches")
	}
	if publicIdentity("tenant\nother", 128) {
		t.Fatal("control character accepted in a public identity")
	}

	for name, mutate := range map[string]func(*proofFixture){
		"invalid plan": func(value *proofFixture) {
			value.planRaw = []byte("not-json")
		},
		"invalid manifest": func(value *proofFixture) {
			value.manifestRaw = []byte("not-json")
		},
		"missing plan authorization": func(value *proofFixture) {
			value.planAuthorizationRaw = nil
		},
		"empty admit command": func(value *proofFixture) {
			value.admitCommandRaw = nil
		},
		"invalid target state": func(value *proofFixture) {
			value.targetStateRaw = []byte("not-json")
		},
		"uncorrelated target state": func(value *proofFixture) {
			state := value.targetState
			state.Binding.NodeID = "substituted"
			value.targetStateRaw, _ = MarshalTargetStateV1(state)
		},
		"invalid activation plan": func(value *proofFixture) {
			value.activationPlanRaw = []byte("not-json")
		},
		"invalid activation proof": func(value *proofFixture) {
			value.activationProofRaw = []byte("not-json")
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := rolloutProofFixture(t)
			mutate(&changed)
			if _, err := correlateProofFixture(changed); err == nil {
				t.Fatal("invalid aggregate proof companions accepted")
			}
		})
	}
}

func clonePromotion(t *testing.T, value BatchPromotionV1) BatchPromotionV1 {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var cloned BatchPromotionV1
	if err := json.Unmarshal(raw, &cloned); err != nil {
		t.Fatal(err)
	}
	return cloned
}
