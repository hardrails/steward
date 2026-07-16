package main

import (
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/activation"
	"github.com/hardrails/steward/internal/activationstore"
	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/controlwitness"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/gateway"
)

func TestActivationTrustAndImmutableInputFailureCoverage(t *testing.T) {
	keyDirectory := t.TempDir()
	_, publisherPublic := generateTestKeyPair(t, keyDirectory, "publisher")
	_, sitePublic := generateTestKeyPair(t, keyDirectory, "site")

	trustCases := []struct {
		name     string
		pubID    string
		pubPath  string
		siteID   string
		site     string
		witness  string
		required bool
	}{
		{
			name: "missing required trust",
		},
		{
			name:    "publisher read",
			pubID:   "publisher-a",
			pubPath: filepath.Join(keyDirectory, "missing-publisher.pem"),
			siteID:  "site-root",
			site:    sitePublic,
		},
		{
			name:    "site root read",
			pubID:   "publisher-a",
			pubPath: publisherPublic,
			siteID:  "site-root",
			site:    filepath.Join(keyDirectory, "missing-site.pem"),
		},
		{
			name:     "witness read",
			pubID:    "publisher-a",
			pubPath:  publisherPublic,
			siteID:   "site-root",
			site:     sitePublic,
			witness:  filepath.Join(keyDirectory, "missing-witness.pem"),
			required: true,
		},
	}
	for _, test := range trustCases {
		t.Run(test.name, func(t *testing.T) {
			if _, err := loadActivationTrust(
				test.pubID, test.pubPath,
				test.siteID, test.site,
				test.witness, test.required,
			); err == nil {
				t.Fatal("invalid activation trust accepted")
			}
		})
	}

	fixture := newOfflineActivationFixture(t)
	trust, err := loadActivationTrust(
		"publisher-a", fixture.publisherPublicPath,
		"site-root", fixture.siteRootPublicPath,
		fixture.witnessPublicPath, true,
	)
	if err != nil {
		t.Fatal(err)
	}
	store, err := activationstore.Open(fixture.directory)
	if err != nil {
		t.Fatal(err)
	}
	inputs, err := loadVerifiedActivationInputs(store, trust, fixture.now)
	if err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	planRaw := append([]byte(nil), inputs.planRaw...)
	releaseRaw := append([]byte(nil), inputs.releaseRaw...)
	policyRaw := append([]byte(nil), inputs.policyRaw...)
	intentRaw := append([]byte(nil), inputs.intentRaw...)
	archivePath := inputs.archivePath
	verifyCases := []struct {
		name    string
		now     time.Time
		plan    []byte
		release []byte
		policy  []byte
		intent  []byte
		archive string
	}{
		{
			name: "missing verification time",
			plan: planRaw, release: releaseRaw, policy: policyRaw,
			intent: intentRaw, archive: archivePath,
		},
		{
			name: "invalid plan",
			now:  fixture.now, plan: []byte("{"), release: releaseRaw,
			policy: policyRaw, intent: intentRaw, archive: archivePath,
		},
		{
			name: "invalid release",
			now:  fixture.now, plan: planRaw, release: []byte("{"),
			policy: policyRaw, intent: intentRaw, archive: archivePath,
		},
		{
			name: "plan binding mismatch",
			now:  fixture.now,
			plan: mutateActivationPlan(t, planRaw, func(plan *activation.PlanV1) {
				plan.ReleaseDigest = activationTestDigest("f")
			}),
			release: releaseRaw, policy: policyRaw,
			intent: intentRaw, archive: archivePath,
		},
		{
			name: "policy authorization",
			now:  fixture.now,
			plan: mutateActivationPlan(t, planRaw, func(plan *activation.PlanV1) {
				plan.PolicyDigest = dsse.Digest([]byte("{}"))
			}),
			release: releaseRaw, policy: []byte("{}"),
			intent: intentRaw, archive: archivePath,
		},
		{
			name: "intent decode",
			now:  fixture.now,
			plan: mutateActivationPlan(t, planRaw, func(plan *activation.PlanV1) {
				plan.IntentDigest = dsse.Digest([]byte("{"))
			}),
			release: releaseRaw, policy: policyRaw,
			intent: []byte("{"), archive: archivePath,
		},
		{
			name: "admission intersection",
			now:  fixture.now,
			plan: mutateActivationPlan(t, planRaw, func(plan *activation.PlanV1) {
				changed := inputs.intent
				changed.TenantID = "tenant-b"
				raw, marshalErr := json.Marshal(changed)
				if marshalErr != nil {
					t.Fatal(marshalErr)
				}
				plan.IntentDigest = dsse.Digest(raw)
			}),
			release: releaseRaw, policy: policyRaw,
			intent: mutateActivationIntent(t, inputs.intent, func(intent *admission.InstanceIntent) {
				intent.TenantID = "tenant-b"
			}),
			archive: archivePath,
		},
		{
			name: "missing archive path",
			now:  fixture.now, plan: planRaw, release: releaseRaw,
			policy: policyRaw, intent: intentRaw,
		},
	}
	for _, test := range verifyCases {
		t.Run(test.name, func(t *testing.T) {
			if _, err := verifyActivationInputBytes(
				test.plan, test.release, test.policy, test.intent,
				test.archive, trust, test.now,
			); err == nil {
				t.Fatal("invalid immutable activation inputs accepted")
			}
		})
	}
}

func TestActivationWorkspaceInputAndHistoricalValidationFailures(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "activation")
	store, err := activationstore.Create(directory)
	if err != nil {
		t.Fatal(err)
	}
	trust := activationTrust{}
	if _, err := loadVerifiedActivationInputs(store, trust, time.Now()); err == nil {
		t.Fatal("missing plan accepted")
	}
	if err := store.WriteOnce(activationstore.PlanFileName, []byte("{}")); err != nil {
		t.Fatal(err)
	}
	if _, err := loadVerifiedActivationInputs(store, trust, time.Now()); err == nil {
		t.Fatal("missing release accepted")
	}
	if err := store.Import(activationstore.ReleaseFileName, []byte("{}")); err != nil {
		t.Fatal(err)
	}
	if _, err := loadVerifiedActivationInputs(store, trust, time.Now()); err == nil {
		t.Fatal("missing policy accepted")
	}
	if err := store.Import(activationstore.PolicyFileName, []byte("{}")); err != nil {
		t.Fatal(err)
	}
	if _, err := loadVerifiedActivationInputs(store, trust, time.Now()); err == nil {
		t.Fatal("missing intent accepted")
	}
	if err := store.Import(activationstore.IntentFileName, []byte("{}")); err != nil {
		t.Fatal(err)
	}
	if _, err := loadVerifiedActivationInputs(store, trust, time.Now()); err == nil {
		t.Fatal("missing archive accepted")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	fixture := newOfflineActivationFixture(t)
	validTrust, err := loadActivationTrust(
		"publisher-a", fixture.publisherPublicPath,
		"site-root", fixture.siteRootPublicPath,
		fixture.witnessPublicPath, true,
	)
	if err != nil {
		t.Fatal(err)
	}
	validStore, err := activationstore.Open(fixture.directory)
	if err != nil {
		t.Fatal(err)
	}
	inputs, err := loadVerifiedActivationInputs(validStore, validTrust, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyActivationInputsAt(
		validStore, validTrust, inputs, time.Time{},
	); err == nil {
		t.Fatal("zero historical authorization time accepted")
	}
	changed := inputs
	changed.planRaw = append(append([]byte(nil), changed.planRaw...), '\n')
	if err := verifyActivationInputsAt(
		validStore, validTrust, changed, fixture.now,
	); err == nil {
		t.Fatal("changed historical activation inputs accepted")
	}
	if err := verifyActivationInputsAtSignedTime(
		validStore, validTrust, inputs, "not-a-time",
	); err == nil {
		t.Fatal("invalid signed authorization time accepted")
	}
	if err := validStore.Close(); err != nil {
		t.Fatal(err)
	}
	if err := verifyActivationInputsAt(
		validStore, validTrust, inputs, fixture.now,
	); err == nil {
		t.Fatal("closed activation store accepted for historical validation")
	}
}

func TestActivationBaselineStateAndArtifactFailureCoverage(t *testing.T) {
	if _, err := validateBaselineWitness(
		[]byte("{"), nil, "node-a",
	); err == nil {
		t.Fatal("invalid baseline witness encoding accepted")
	}
	_, export, witnessPath := stewardctlEvidenceFixtures(t)
	exportRaw, err := json.Marshal(export)
	if err != nil {
		t.Fatal(err)
	}
	witnessPublic, err := controlwitness.LoadPublic(witnessPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := validateBaselineWitness(
		exportRaw, witnessPublic, "node-a",
	); err == nil {
		t.Fatal("baseline witness for another node accepted")
	}
	_, otherWitnessPath := generateTestKeyPair(t, t.TempDir(), "other-witness")
	otherWitness, err := readPublicKey(otherWitnessPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := validateBaselineWitness(
		exportRaw, otherWitness, "node-1",
	); err == nil {
		t.Fatal("baseline witness with the wrong signature key accepted")
	}

	emptyStore := newActivationRunStore(t)
	if _, err := loadActivationStateChain(
		emptyStore, verifiedActivationInputs{},
	); err == nil {
		t.Fatal("empty activation state chain accepted")
	}
	if err := emptyStore.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := loadActivationStateChain(
		emptyStore, verifiedActivationInputs{},
	); err == nil {
		t.Fatal("closed activation state store accepted")
	}

	parseStore := newActivationRunStore(t)
	if _, err := parseStore.AppendState(0, []byte("{}")); err != nil {
		t.Fatal(err)
	}
	if _, err := loadActivationStateChain(
		parseStore, verifiedActivationInputs{},
	); err == nil {
		t.Fatal("invalid activation state checkpoint accepted")
	}
	if err := parseStore.Close(); err != nil {
		t.Fatal(err)
	}

	transitionFixture := newActivationStatusFixture(t, activation.PhaseNew, "node-a")
	transitionStore, err := activationstore.Open(transitionFixture.directory)
	if err != nil {
		t.Fatal(err)
	}
	invalidNext := transitionFixture.states[0]
	invalidNext.Phase = activation.PhaseImageImported
	invalidNext.UpdatedAt = "2026-07-16T01:00:01Z"
	invalidNextRaw, err := activation.MarshalStateV1(invalidNext)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := transitionStore.AppendState(1, invalidNextRaw); err != nil {
		t.Fatal(err)
	}
	transitionInputs := activationStateFixtureInputs(transitionFixture)
	if _, err := loadActivationStateChain(
		transitionStore, transitionInputs,
	); err == nil {
		t.Fatal("invalid activation transition accepted")
	}
	if err := transitionStore.Close(); err != nil {
		t.Fatal(err)
	}

	bindingFixture := newActivationStatusFixture(t, activation.PhaseNew, "node-a")
	bindingStore, err := activationstore.Open(bindingFixture.directory)
	if err != nil {
		t.Fatal(err)
	}
	bindingInputs := activationStateFixtureInputs(bindingFixture)
	bindingInputs.intent.TenantID = "tenant-b"
	if _, err := loadActivationStateChain(
		bindingStore, bindingInputs,
	); err == nil {
		t.Fatal("initial state with a mismatched immutable binding accepted")
	}
	if err := bindingStore.Close(); err != nil {
		t.Fatal(err)
	}

	closedArtifactStore := newActivationRunStore(t)
	if err := closedArtifactStore.Close(); err != nil {
		t.Fatal(err)
	}
	if err := writeActivationArtifact(
		closedArtifactStore, activationstore.CanaryResultFileName,
		[]byte("{}"), false,
	); err == nil {
		t.Fatal("artifact write to a closed store accepted")
	}
	if _, _, err := readOptionalActivationArtifact(
		closedArtifactStore, activationstore.CanaryResultFileName, 1,
	); err == nil {
		t.Fatal("optional artifact read from a closed store accepted")
	}
	if _, err := activationTaskAuthorities(permitAdmission{
		TaskAuthorities: []gateway.TaskAuthority{{
			KeyID: "bad", PublicKey: "not-base64",
		}},
	}); err == nil {
		t.Fatal("invalid activation task authority accepted")
	}
}

func TestActivationStateTimeAndAppendFailureCoverage(t *testing.T) {
	if _, err := activationInputVerificationTime(
		activationStateChain{}, time.Time{},
	); err == nil {
		t.Fatal("zero activation verification-time ceiling accepted")
	}
	if _, err := activationInputVerificationTime(
		activationStateChain{states: []activation.StateV1{{
			Phase: activation.PhaseNew, UpdatedAt: "bad",
		}}},
		time.Now(),
	); err == nil {
		t.Fatal("invalid initial activation checkpoint time accepted")
	}
	initialAt := time.Date(2026, 7, 16, 1, 0, 0, 0, time.UTC)
	selected, err := activationInputVerificationTime(
		activationStateChain{states: []activation.StateV1{{
			Phase:     activation.PhaseNew,
			UpdatedAt: initialAt.Format(time.RFC3339Nano),
		}}},
		initialAt.Add(-time.Second),
	)
	if err != nil || !selected.After(initialAt) {
		t.Fatalf("selected verification time=%v err=%v", selected, err)
	}
	if _, err := activationInputVerificationTime(
		activationStateChain{states: []activation.StateV1{{
			Phase:     activation.PhasePreflightPassed,
			UpdatedAt: initialAt.Format(time.RFC3339Nano),
		}}},
		initialAt.Add(time.Minute),
	); err == nil {
		t.Fatal("non-new chain without release checkpoint accepted")
	}
	if _, err := activationInputVerificationTime(
		activationStateChain{states: []activation.StateV1{
			{Phase: activation.PhaseNew, UpdatedAt: initialAt.Format(time.RFC3339Nano)},
			{Phase: activation.PhaseReleaseVerified, UpdatedAt: "bad"},
		}},
		initialAt.Add(time.Minute),
	); err == nil {
		t.Fatal("invalid release checkpoint time accepted")
	}
	if _, err := activationInputVerificationTime(
		activationStateChain{states: []activation.StateV1{
			{Phase: activation.PhaseNew, UpdatedAt: initialAt.Format(time.RFC3339Nano)},
			{
				Phase:     activation.PhaseReleaseVerified,
				UpdatedAt: initialAt.Add(time.Minute).Format(time.RFC3339Nano),
			},
		}},
		initialAt.Add(30*time.Second),
	); err == nil {
		t.Fatal("release checkpoint after the verification ceiling accepted")
	}

	if activationStateChainsEqual(
		activationStateChain{names: []string{"a"}},
		activationStateChain{names: []string{"b"}},
	) {
		t.Fatal("state chains with different names reported equal")
	}
	if activationStateChainsEqual(
		activationStateChain{names: []string{"a"}, raw: [][]byte{[]byte("a")}},
		activationStateChain{names: []string{"a"}},
	) {
		t.Fatal("state chains with different lengths reported equal")
	}
	if activationStateChainsEqual(
		activationStateChain{names: []string{"a"}, raw: [][]byte{[]byte("a")}},
		activationStateChain{names: []string{"a"}, raw: [][]byte{[]byte("b")}},
	) {
		t.Fatal("state chains with different bytes reported equal")
	}
	if _, err := (activationStateChain{}).phaseTime(activation.PhasePassed); err == nil {
		t.Fatal("missing activation phase time accepted")
	}
	if err := appendActivationStateAt(
		nil, &activationStateChain{}, activation.PhaseReleaseVerified,
		"", "", time.Time{},
	); err == nil {
		t.Fatal("zero activation state update time accepted")
	}
	badTimeChain := activationStateChain{states: []activation.StateV1{{
		Phase: activation.PhaseNew, UpdatedAt: "bad",
	}}}
	if err := appendActivationStateAt(
		nil, &badTimeChain, activation.PhaseReleaseVerified,
		"", "", initialAt,
	); err == nil {
		t.Fatal("invalid current activation state time accepted")
	}

	fixture := newActivationStatusFixture(t, activation.PhaseNew, "node-a")
	store, err := activationstore.Open(fixture.directory)
	if err != nil {
		t.Fatal(err)
	}
	chain := activationStateChain{
		names:  append([]string(nil), "state-000000000000.json"),
		raw:    append([][]byte(nil), fixture.rawStates...),
		states: append([]activation.StateV1(nil), fixture.states...),
	}
	currentTime, err := time.Parse(time.RFC3339Nano, chain.latest().UpdatedAt)
	if err != nil {
		t.Fatal(err)
	}
	if err := appendActivationStateAt(
		store, &chain, activation.PhaseReleaseVerified,
		"", "", currentTime,
	); err != nil {
		t.Fatal(err)
	}
	if !timeMustParseActivation(chain.latest().UpdatedAt).After(currentTime) {
		t.Fatal("non-advancing selected time was not made monotonic")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	invalidFixture := newActivationStatusFixture(t, activation.PhaseNew, "node-a")
	invalidStore, err := activationstore.Open(invalidFixture.directory)
	if err != nil {
		t.Fatal(err)
	}
	invalidChain := activationStateChain{
		names:  []string{"state-000000000000.json"},
		raw:    append([][]byte(nil), invalidFixture.rawStates...),
		states: append([]activation.StateV1(nil), invalidFixture.states...),
	}
	if err := appendActivationStateAt(
		invalidStore, &invalidChain, activation.PhaseImageImported,
		"", "", initialAt.Add(time.Hour),
	); err == nil {
		t.Fatal("invalid activation state transition appended")
	}
	if err := invalidStore.Close(); err != nil {
		t.Fatal(err)
	}

	closedFixture := newActivationStatusFixture(t, activation.PhaseNew, "node-a")
	closedStore, err := activationstore.Open(closedFixture.directory)
	if err != nil {
		t.Fatal(err)
	}
	if err := closedStore.Close(); err != nil {
		t.Fatal(err)
	}
	closedChain := activationStateChain{
		names:  []string{"state-000000000000.json"},
		raw:    append([][]byte(nil), closedFixture.rawStates...),
		states: append([]activation.StateV1(nil), closedFixture.states...),
	}
	if err := appendActivationStateAt(
		closedStore, &closedChain, activation.PhaseReleaseVerified,
		"", "", initialAt.Add(time.Hour),
	); err == nil {
		t.Fatal("activation state append to a closed store accepted")
	}
}

func mutateActivationPlan(
	t *testing.T,
	raw []byte,
	mutate func(*activation.PlanV1),
) []byte {
	t.Helper()
	plan, err := activation.ParsePlanV1(raw)
	if err != nil {
		t.Fatal(err)
	}
	mutate(&plan)
	changed, err := activation.MarshalPlanV1(plan)
	if err != nil {
		t.Fatal(err)
	}
	return changed
}

func mutateActivationIntent(
	t *testing.T,
	intent admission.InstanceIntent,
	mutate func(*admission.InstanceIntent),
) []byte {
	t.Helper()
	mutate(&intent)
	raw, err := json.Marshal(intent)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func activationStateFixtureInputs(
	fixture activationStatusFixture,
) verifiedActivationInputs {
	return verifiedActivationInputs{
		planRaw: fixture.planRaw,
		plan:    fixture.plan,
		intent: admission.InstanceIntent{
			TenantID:   fixture.states[0].Binding.TenantID,
			NodeID:     fixture.states[0].Binding.NodeID,
			InstanceID: fixture.states[0].Binding.InstanceID,
			Generation: fixture.states[0].Binding.Generation,
		},
	}
}
