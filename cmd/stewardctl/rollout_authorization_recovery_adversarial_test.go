package main

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/activation"
	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/controlcapture"
	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/rollout"
	"github.com/hardrails/steward/internal/rolloutstore"
)

func TestRetainedRolloutRecoveryRejectsArtifactPhaseAndContentContradictions(t *testing.T) {
	base := newRolloutRunCompleteFixture(t)
	tests := []struct {
		name   string
		want   string
		mutate func(*testing.T, rolloutVerifyTestFixture, *verifiedRolloutRun, *rollout.TargetStateV1)
	}{
		{name: "unknown phase", want: "unknown retained phase", mutate: func(_ *testing.T, _ rolloutVerifyTestFixture, _ *verifiedRolloutRun, state *rollout.TargetStateV1) {
			state.Phase = "invented"
		}},
		{name: "admit signature", want: "admit command", mutate: replaceRolloutRecoveryArtifact(rolloutstore.TargetAdmitCommandKind, []byte(`{}`))},
		{name: "admit deterministic binding", want: "deterministic policy-authorized", mutate: func(t *testing.T, fixture rolloutVerifyTestFixture, _ *verifiedRolloutRun, _ *rollout.TargetStateV1) {
			replaceRolloutRecoveryArtifact(rolloutstore.TargetAdmitCommandKind, offlineRead(t, rolloutRunTargetPath(t, fixture.workspace, rolloutstore.TargetStartCommandKind)))(t, fixture, nil, nil)
		}},
		{name: "admission canonical form", want: "canonical JSON", mutate: replaceRolloutRecoveryArtifact(rolloutstore.TargetAdmissionKind, []byte("{}\n"))},
		{name: "admission state binding", want: "differs from target state", mutate: func(_ *testing.T, _ rolloutVerifyTestFixture, _ *verifiedRolloutRun, state *rollout.TargetStateV1) {
			state.RuntimeRef = "executor-" + strings.Repeat("0", 64)
		}},
		{name: "start signature", want: "start command", mutate: replaceRolloutRecoveryArtifact(rolloutstore.TargetStartCommandKind, []byte(`{}`))},
		{name: "canary without admission", want: "no authenticated admission", mutate: func(t *testing.T, fixture rolloutVerifyTestFixture, _ *verifiedRolloutRun, state *rollout.TargetStateV1) {
			state.Phase = rollout.PhaseActionRequired
			removeRolloutRecoveryArtifact(t, fixture, rolloutstore.TargetAdmissionKind)
		}},
		{name: "canary closed payload", want: "parse retained closed canary", mutate: func(t *testing.T, fixture rolloutVerifyTestFixture, _ *verifiedRolloutRun, state *rollout.TargetStateV1) {
			state.Phase = rollout.PhaseActionRequired
			replaceRolloutRecoveryArtifact(rolloutstore.TargetCanaryCommandKind, offlineRead(t, rolloutRunTargetPath(t, fixture.workspace, rolloutstore.TargetAdmitCommandKind)))(t, fixture, nil, nil)
		}},
		{name: "result without companions", want: "incomplete authenticated command companions", mutate: func(t *testing.T, fixture rolloutVerifyTestFixture, _ *verifiedRolloutRun, state *rollout.TargetStateV1) {
			state.Phase = rollout.PhaseActionRequired
			removeRolloutRecoveryArtifact(t, fixture, rolloutstore.TargetAdmissionKind)
			removeRolloutRecoveryArtifact(t, fixture, rolloutstore.TargetCanaryCommandKind)
		}},
		{name: "result signature", want: "retained canary result", mutate: replaceRolloutRecoveryArtifact(rolloutstore.TargetCanaryResultKind, []byte(`{}`))},
		{name: "result state binding", want: "differs from target state", mutate: func(_ *testing.T, _ rolloutVerifyTestFixture, _ *verifiedRolloutRun, state *rollout.TargetStateV1) {
			state.CanaryResultDigest = dsse.Digest([]byte("substituted"))
		}},
		{name: "capture without canary", want: "no authenticated canary companion", mutate: func(t *testing.T, fixture rolloutVerifyTestFixture, _ *verifiedRolloutRun, state *rollout.TargetStateV1) {
			state.Phase = rollout.PhaseActionRequired
			removeRolloutRecoveryArtifact(t, fixture, rolloutstore.TargetCanaryCommandKind)
			removeRolloutRecoveryArtifact(t, fixture, rolloutstore.TargetCanaryResultKind)
		}},
		{name: "capture signature", want: "retained evidence capture", mutate: replaceRolloutRecoveryArtifact(rolloutstore.TargetCaptureExportKind, []byte(`{}`))},
		{name: "proof without state", want: "no exact state companion", mutate: func(t *testing.T, fixture rolloutVerifyTestFixture, _ *verifiedRolloutRun, state *rollout.TargetStateV1) {
			state.Phase = rollout.PhaseActionRequired
			removeRolloutRecoveryArtifact(t, fixture, rolloutstore.TargetActivationStateKind)
		}},
		{name: "proof without capture", want: "incomplete evidence companions", mutate: func(t *testing.T, fixture rolloutVerifyTestFixture, _ *verifiedRolloutRun, state *rollout.TargetStateV1) {
			state.Phase = rollout.PhaseActionRequired
			removeRolloutRecoveryArtifact(t, fixture, rolloutstore.TargetCaptureExportKind)
		}},
		{name: "missing proof after passed", want: "partial activation state", mutate: func(t *testing.T, fixture rolloutVerifyTestFixture, _ *verifiedRolloutRun, _ *rollout.TargetStateV1) {
			removeRolloutRecoveryArtifact(t, fixture, rolloutstore.TargetActivationProofKind)
		}},
		{name: "invalid partial state", want: "partial activation state differs", mutate: func(t *testing.T, fixture rolloutVerifyTestFixture, _ *verifiedRolloutRun, state *rollout.TargetStateV1) {
			state.Phase = rollout.PhaseActionRequired
			removeRolloutRecoveryArtifact(t, fixture, rolloutstore.TargetActivationProofKind)
			replaceRolloutRecoveryArtifact(rolloutstore.TargetActivationStateKind, []byte(`{}`))(t, fixture, nil, nil)
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := cloneRolloutVerifyTestFixture(t, base)
			run := loadRolloutRunTestFixture(t, fixture)
			state := run.states[0]
			test.mutate(t, fixture, &run, &state)
			store, err := rolloutstore.Open(fixture.workspace)
			if err != nil {
				t.Fatal(err)
			}
			keys := rolloutRunTestKeys(t, fixture)
			err = verifyRetainedRolloutTarget(store, &run.targets[0], state, keys, run.witnessPublic)
			if closeErr := store.Close(); closeErr != nil {
				t.Fatal(closeErr)
			}
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("recovery error=%v, want %q", err, test.want)
			}
		})
	}
}

func TestRolloutCommandVerifierRejectsEveryAuthorityAndTimeSubstitution(t *testing.T) {
	fixture := newRolloutRunCompleteFixture(t)
	run := loadRolloutRunTestFixture(t, fixture)
	prepared := run.targets[0].prepared
	validRaw := offlineRead(t, rolloutRunTargetPath(t, fixture.workspace, rolloutstore.TargetAdmitCommandKind))
	valid := rolloutRunCommandStatement(t, validRaw)
	private, err := readPrivateKey(fixture.commandPrivatePath)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		want    string
		raw     func(*testing.T) []byte
		policy  func(admission.SitePolicy) admission.SitePolicy
		expect  []byte
		expires string
	}{
		{name: "missing trust", want: "load admit command trust", raw: func(*testing.T) []byte { return validRaw }, policy: func(policy admission.SitePolicy) admission.SitePolicy {
			policy.Tenants[0].CommandKeys = nil
			return policy
		}},
		{name: "invalid envelope", want: "authenticate retained admit", raw: func(*testing.T) []byte { return []byte(`{}`) }},
		{name: "multiple signatures", want: "exactly one trusted signature", raw: func(t *testing.T) []byte {
			envelope, err := dsse.Parse(validRaw)
			if err != nil {
				t.Fatal(err)
			}
			envelope.Signatures = append(envelope.Signatures, dsse.Signature{KeyID: "untrusted", Sig: envelope.Signatures[0].Sig})
			raw, err := dsse.Marshal(envelope)
			if err != nil {
				t.Fatal(err)
			}
			return raw
		}},
		{name: "noncanonical envelope", want: "envelope is not canonical", raw: func(*testing.T) []byte { return append(append([]byte(nil), validRaw...), '\n') }},
		{name: "undecodable statement", want: "decode retained admit", raw: func(t *testing.T) []byte {
			return signRolloutVerifierPayload(t, []byte(`{"broken":`), fixture.commandKeyID, private)
		}},
		{name: "noncanonical statement", want: "statement is not canonical", raw: func(t *testing.T) []byte {
			raw, err := json.MarshalIndent(valid, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			return signRolloutVerifierPayload(t, raw, fixture.commandKeyID, private)
		}},
		{name: "invalid statement", want: "validate retained admit", raw: func(t *testing.T) []byte {
			changed := valid
			changed.CommandID = ""
			return signRolloutVerifierStatement(t, changed, fixture.commandKeyID, private)
		}},
		{name: "changed target", want: "does not match the prepared rollout target", raw: func(t *testing.T) []byte {
			changed := valid
			changed.CommandID = "different"
			return signRolloutVerifierStatement(t, changed, fixture.commandKeyID, private)
		}},
		{name: "changed closed payload", want: "changed its closed payload", raw: func(t *testing.T) []byte {
			changed := valid
			changed.Payload = json.RawMessage(`{"changed":true}`)
			return signRolloutVerifierStatement(t, changed, fixture.commandKeyID, private)
		}},
		{name: "noncanonical issue time", want: "command issue time", raw: func(t *testing.T) []byte {
			changed := valid
			changed.IssuedAt = strings.Replace(changed.IssuedAt, "Z", "+00:00", 1)
			return signRolloutVerifierStatement(t, changed, fixture.commandKeyID, private)
		}},
		{name: "noncanonical expiry", want: "command expiry", raw: func(t *testing.T) []byte {
			changed := valid
			changed.ExpiresAt = strings.Replace(changed.ExpiresAt, "Z", "+00:00", 1)
			return signRolloutVerifierStatement(t, changed, fixture.commandKeyID, private)
		}},
		{name: "outside rollout interval", want: "outside the rollout interval", raw: func(t *testing.T) []byte {
			changed := valid
			issued, _ := time.Parse(time.RFC3339Nano, run.plan.CreatedAt)
			changed.IssuedAt = issued.Add(-time.Nanosecond).Format(time.RFC3339Nano)
			return signRolloutVerifierStatement(t, changed, fixture.commandKeyID, private)
		}},
		{name: "beyond capsule expiry", want: "exceeds the authenticated capsule expiry", raw: func(t *testing.T) []byte { return validRaw }, expires: run.plan.CreatedAt},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			policy := cloneRolloutRecoveryPolicy(run.verified.SitePolicy)
			if test.policy != nil {
				policy = test.policy(policy)
			}
			expected := prepared.AdmissionPayloadRaw()
			if test.expect != nil {
				expected = test.expect
			}
			expires := run.verified.Capsule.ExpiresAt
			if test.expires != "" {
				expires = test.expires
			}
			_, err := verifyRolloutCommand(test.raw(t), prepared, policy, "admit", prepared.Target().AdmitCommandID, 1, expected, expires)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("verify error=%v, want %q", err, test.want)
			}
		})
	}
}

func TestRolloutAuthorizationAndCaptureUtilitiesFailClosed(t *testing.T) {
	fixture := newRolloutRunCompleteFixture(t)
	run := loadRolloutExecutionTestFixture(t, fixture)
	keys := rolloutRunTestKeys(t, fixture)

	if err := authorizeRolloutRun(nil, &run, &keys); err == nil {
		t.Fatal("nil authorization store accepted")
	}
	wrongKeys := keys
	wrongKeys.commandID = "not-authorized"
	store, err := rolloutstore.Open(fixture.workspace)
	if err != nil {
		t.Fatal(err)
	}
	if err := authorizeRolloutRun(store, &run, &wrongKeys); err == nil {
		t.Fatal("wrong common command key accepted")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	policy := run.verified.SitePolicy
	noTenant := cloneRolloutRecoveryPolicy(policy)
	noTenant.Tenants[0].TenantID = "another"
	if _, err := commonRolloutCommandTrust(noTenant, run.plan.TenantID); err == nil {
		t.Fatal("missing tenant command trust accepted")
	}
	partial := cloneRolloutRecoveryPolicy(policy)
	partial.Tenants[0].CommandKeys[0].Operations = []string{"admit"}
	if _, err := commonRolloutCommandTrust(partial, run.plan.TenantID); err == nil {
		t.Fatal("partial operation trust accepted")
	}
	encoded := partial.Tenants[0].CommandKeys[0].PublicKey
	disjoint := cloneRolloutRecoveryPolicy(policy)
	disjoint.Tenants[0].CommandKeys = []admission.CommandKey{
		{KeyID: "admit-only", PublicKey: encoded, Operations: []string{"admit"}},
		{KeyID: "start-only", PublicKey: encoded, Operations: []string{"start"}},
		{KeyID: "canary-only", PublicKey: encoded, Operations: []string{"activation-canary"}},
	}
	if _, err := commonRolloutCommandTrust(disjoint, run.plan.TenantID); err == nil {
		t.Fatal("disjoint command authorities accepted")
	}

	if _, ok := commonRolloutSigner(rolloutAuthorizationChain{}); ok {
		t.Fatal("missing authorization signer accepted")
	}
	if err := requireExactRolloutPromotionInventory(rolloutAuthorizationChain{promotions: map[uint16]rollout.VerifiedBatchPromotionV1{}}, 1); err == nil {
		t.Fatal("missing promotion inventory accepted")
	}
	if err := requireExactRolloutPromotionInventory(rolloutAuthorizationChain{promotions: map[uint16]rollout.VerifiedBatchPromotionV1{2: {}}}, 1); err == nil {
		t.Fatal("noncontiguous promotion accepted")
	}
	if _, _, err := rolloutBatchAuthorization(rolloutAuthorizationChain{}, 1); err == nil {
		t.Fatal("missing batch authorization accepted")
	}
	badPlan := run.plan
	badPlan.BatchSize = 0
	if _, _, _, err := activeRolloutAuthorizationBatch(badPlan, run.states); err == nil {
		t.Fatal("invalid plan batch boundaries accepted")
	}
	actionStates := append([]rollout.TargetStateV1(nil), run.states...)
	actionStates[0].Phase = rollout.PhaseActionRequired
	if batch, active, action, err := activeRolloutAuthorizationBatch(run.plan, actionStates); err != nil || batch != 0 || !active || !action {
		t.Fatalf("action batch=(%d,%t,%t,%v)", batch, active, action, err)
	}
	if _, err := rolloutTargetBatchNumber([]rollout.BatchV1{{Number: 0, Start: 0, End: 1}}, 2); err == nil {
		t.Fatal("out-of-bound target got a batch")
	}
	if batchIsUntouched(badPlan, run.states, 0) {
		t.Fatal("invalid plan reported untouched")
	}
	if allRolloutTargetsPassed(actionStates) {
		t.Fatal("action-required fleet reported passed")
	}
	if err := requireLiveRolloutAuthorizationWindow(run.plan, time.Time{}); err == nil {
		t.Fatal("dead authorization window accepted")
	}

	chain := rolloutAuthorizationChain{plan: rollout.VerifiedPlanAuthorizationV1{Statement: rollout.PlanAuthorizationV1{AuthorizedAt: "invalid"}}}
	stateRaw, err := rollout.MarshalTargetStateV1(run.states[0])
	if err != nil {
		t.Fatal(err)
	}
	companions := rolloutPromotionCompanions{states: [][]byte{stateRaw}}
	if _, err := rolloutPromotionCausalFloor(chain, run, companions, 1); err == nil {
		t.Fatal("invalid plan signer time accepted")
	}
	chain.plan.Statement.AuthorizedAt = run.plan.CreatedAt
	if _, err := rolloutPromotionCausalFloor(chain, run, companions, 2); err == nil {
		t.Fatal("missing prior promotion accepted")
	}
	if _, err := rolloutPromotionCausalFloor(chain, run, companions, 0); err == nil {
		t.Fatal("invalid next batch accepted")
	}

	projection, err := parseCanonicalRolloutAdmission(run.targets[0].admissionRaw)
	if err != nil {
		t.Fatal(err)
	}
	capture, err := controlcapture.VerifyJSONV1(run.targets[0].captureRaw, run.witnessPublic)
	if err != nil {
		t.Fatal(err)
	}
	proofRaw := offlineRead(t, rolloutRunTargetPath(t, fixture.workspace, rolloutstore.TargetActivationProofKind))
	proof, err := activation.ParseProofV1(proofRaw)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint := proof.ExecutorCheckpointDigest
	if err := correlateVerifiedRolloutCapture(run.targets[0].captureRaw, capture, run.targets[0].prepared, projection, proof, checkpoint, run.witnessPublic); err != nil {
		t.Fatal(err)
	}
	changedCapture := capture
	changedCapture.Statement.TenantID = "other"
	if err := correlateVerifiedRolloutCapture(run.targets[0].captureRaw, changedCapture, run.targets[0].prepared, projection, proof, checkpoint, run.witnessPublic); err == nil {
		t.Fatal("changed capture binding accepted")
	}
	changedProjection := projection
	changedProjection.EvidenceKeyID = "evidence-" + strings.Repeat("0", 64)
	if err := correlateVerifiedRolloutCapture(run.targets[0].captureRaw, capture, run.targets[0].prepared, changedProjection, proof, checkpoint, run.witnessPublic); err == nil {
		t.Fatal("changed evidence identity accepted")
	}
	changedProof := proof
	changedProof.ExecutorEvidence.ChainHash = dsse.Digest([]byte("changed"))
	if err := correlateVerifiedRolloutCapture(run.targets[0].captureRaw, capture, run.targets[0].prepared, projection, changedProof, checkpoint, run.witnessPublic); err == nil {
		t.Fatal("changed executor coordinate accepted")
	}
	changedProof = proof
	changedProof.Witness.WitnessExportDigest = dsse.Digest([]byte("changed"))
	if err := correlateVerifiedRolloutCapture(run.targets[0].captureRaw, capture, run.targets[0].prepared, projection, changedProof, checkpoint, run.witnessPublic); err == nil {
		t.Fatal("changed witness coordinate accepted")
	}
	incompleteCapture := capture
	incompleteCapture.Begin.Receipt.Sequence++
	if err := correlateVerifiedRolloutCapture(run.targets[0].captureRaw, incompleteCapture, run.targets[0].prepared, projection, proof, checkpoint, run.witnessPublic); err == nil {
		t.Fatal("incomplete capture coordinates accepted")
	}
}

func TestOfflineRolloutTargetVerifierRejectsMissingMalformedAndNoncanonicalEvidence(t *testing.T) {
	base := newRolloutRunCompleteFixture(t)
	tests := []struct {
		name   string
		want   string
		mutate func(*testing.T, rolloutVerifyTestFixture, *verifiedRolloutRun)
	}{
		{name: "empty state chain", want: "state chain is empty", mutate: func(_ *testing.T, _ rolloutVerifyTestFixture, run *verifiedRolloutRun) { run.stateCounts[0] = 0 }},
		{name: "missing final state", want: "read final target state", mutate: func(t *testing.T, fixture rolloutVerifyTestFixture, run *verifiedRolloutRun) {
			name, err := rolloutstore.TargetStateName(0, run.stateCounts[0]-1)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(filepath.Join(fixture.workspace, name)); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "changed final state", want: "final target state changed", mutate: func(_ *testing.T, _ rolloutVerifyTestFixture, run *verifiedRolloutRun) {
			run.states[0].ActionRequiredReason = "substituted"
		}},
		{name: "missing admit", want: "admit-command", mutate: removeRolloutVerifierArtifact(rolloutstore.TargetAdmitCommandKind)},
		{name: "malformed admit", want: "authenticate retained admit", mutate: replaceRolloutVerifierArtifact(rolloutstore.TargetAdmitCommandKind, []byte(`{}`))},
		{name: "missing admission", want: "admission.json", mutate: removeRolloutVerifierArtifact(rolloutstore.TargetAdmissionKind)},
		{name: "malformed admission", want: "decode retained admission", mutate: replaceRolloutVerifierArtifact(rolloutstore.TargetAdmissionKind, []byte(`{"broken":`))},
		{name: "noncanonical admission", want: "not canonical JSON", mutate: func(t *testing.T, fixture rolloutVerifyTestFixture, _ *verifiedRolloutRun) {
			raw := offlineRead(t, rolloutRunTargetPath(t, fixture.workspace, rolloutstore.TargetAdmissionKind))
			replaceRolloutVerifierArtifact(rolloutstore.TargetAdmissionKind, append(raw, '\n'))(t, fixture, nil)
		}},
		{name: "invalid admission binding", want: "verify retained admission", mutate: func(t *testing.T, fixture rolloutVerifyTestFixture, _ *verifiedRolloutRun) {
			raw, err := json.Marshal(controlprotocol.ExecutorAdmissionProjectionV1{})
			if err != nil {
				t.Fatal(err)
			}
			replaceRolloutVerifierArtifact(rolloutstore.TargetAdmissionKind, raw)(t, fixture, nil)
		}},
		{name: "missing start", want: "start-command", mutate: removeRolloutVerifierArtifact(rolloutstore.TargetStartCommandKind)},
		{name: "malformed start", want: "authenticate retained start", mutate: replaceRolloutVerifierArtifact(rolloutstore.TargetStartCommandKind, []byte(`{}`))},
		{name: "missing canary", want: "canary-command", mutate: removeRolloutVerifierArtifact(rolloutstore.TargetCanaryCommandKind)},
		{name: "malformed canary", want: "authenticate retained activation-canary", mutate: replaceRolloutVerifierArtifact(rolloutstore.TargetCanaryCommandKind, []byte(`{}`))},
		{name: "missing result", want: "canary-result", mutate: removeRolloutVerifierArtifact(rolloutstore.TargetCanaryResultKind)},
		{name: "malformed result", want: "verify exact retained canary", mutate: replaceRolloutVerifierArtifact(rolloutstore.TargetCanaryResultKind, []byte(`{}`))},
		{name: "missing capture", want: "capture-export", mutate: removeRolloutVerifierArtifact(rolloutstore.TargetCaptureExportKind)},
		{name: "malformed capture", want: "decode retained controller capture", mutate: replaceRolloutVerifierArtifact(rolloutstore.TargetCaptureExportKind, []byte(`{}`))},
		{name: "noncanonical capture", want: "not canonical JSON", mutate: func(t *testing.T, fixture rolloutVerifyTestFixture, _ *verifiedRolloutRun) {
			raw := offlineRead(t, rolloutRunTargetPath(t, fixture.workspace, rolloutstore.TargetCaptureExportKind))
			replaceRolloutVerifierArtifact(rolloutstore.TargetCaptureExportKind, append(raw, '\n'))(t, fixture, nil)
		}},
		{name: "missing activation state", want: "activation-state", mutate: removeRolloutVerifierArtifact(rolloutstore.TargetActivationStateKind)},
		{name: "malformed activation state", want: "parse retained activation state", mutate: replaceRolloutVerifierArtifact(rolloutstore.TargetActivationStateKind, []byte(`{}`))},
		{name: "missing activation proof", want: "activation-proof", mutate: removeRolloutVerifierArtifact(rolloutstore.TargetActivationProofKind)},
		{name: "malformed activation proof", want: "correlate retained activation proof", mutate: replaceRolloutVerifierArtifact(rolloutstore.TargetActivationProofKind, []byte(`{}`))},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := cloneRolloutVerifyTestFixture(t, base)
			run := loadRolloutRunTestFixture(t, fixture)
			test.mutate(t, fixture, &run)
			store, err := rolloutstore.Open(fixture.workspace)
			if err != nil {
				t.Fatal(err)
			}
			_, err = verifyRolloutTarget(store, run, 0)
			if closeErr := store.Close(); closeErr != nil {
				t.Fatal(closeErr)
			}
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("target verification error=%v, want %q", err, test.want)
			}
		})
	}
}

func TestRolloutStateChainAndTopLevelRecoveryRejectContradictions(t *testing.T) {
	base := newRolloutRunCompleteFixture(t)

	t.Run("state chain empty", func(t *testing.T) {
		fixture := cloneRolloutVerifyTestFixture(t, base)
		run := loadRolloutRunTestFixture(t, fixture)
		run.stateCounts[0] = 0
		store, err := rolloutstore.Open(fixture.workspace)
		if err != nil {
			t.Fatal(err)
		}
		defer store.Close()
		if err := verifyCanonicalRolloutStateChains(store, run); err == nil {
			t.Fatal("empty canonical state chain accepted")
		}
	})
	t.Run("state chain missing tail", func(t *testing.T) {
		fixture := cloneRolloutVerifyTestFixture(t, base)
		run := loadRolloutRunTestFixture(t, fixture)
		run.stateCounts[0]++
		store, err := rolloutstore.Open(fixture.workspace)
		if err != nil {
			t.Fatal(err)
		}
		defer store.Close()
		if err := verifyCanonicalRolloutStateChains(store, run); err == nil {
			t.Fatal("missing state tail accepted")
		}
	})
	t.Run("state chain malformed", func(t *testing.T) {
		fixture := cloneRolloutVerifyTestFixture(t, base)
		run := loadRolloutRunTestFixture(t, fixture)
		name, err := rolloutstore.TargetStateName(0, 0)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(fixture.workspace, name), []byte(`{}`), 0o600); err != nil {
			t.Fatal(err)
		}
		store, err := rolloutstore.Open(fixture.workspace)
		if err != nil {
			t.Fatal(err)
		}
		defer store.Close()
		if err := verifyCanonicalRolloutStateChains(store, run); err == nil {
			t.Fatal("malformed state accepted")
		}
	})
	t.Run("state chain noncanonical", func(t *testing.T) {
		fixture := cloneRolloutVerifyTestFixture(t, base)
		run := loadRolloutRunTestFixture(t, fixture)
		name, err := rolloutstore.TargetStateName(0, 0)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(fixture.workspace, name)
		if err := os.WriteFile(path, append(offlineRead(t, path), '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
		store, err := rolloutstore.Open(fixture.workspace)
		if err != nil {
			t.Fatal(err)
		}
		defer store.Close()
		if err := verifyCanonicalRolloutStateChains(store, run); err == nil {
			t.Fatal("noncanonical state accepted")
		}
	})

	run := loadRolloutRunTestFixture(t, base)
	keys := rolloutRunTestKeys(t, base)
	if err := verifyRetainedRolloutExecution(nil, nil, keys); err == nil {
		t.Fatal("nil retained run accepted")
	}
	wrongCommand := keys
	wrongCommand.commandPublic = append(ed25519.PublicKey(nil), keys.taskPublic...)
	store, err := rolloutstore.Open(base.workspace)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyRetainedRolloutExecution(store, &run, wrongCommand); err == nil {
		t.Fatal("wrong command key accepted")
	}
	wrongTask := keys
	wrongTask.taskPublic = append(ed25519.PublicKey(nil), keys.commandPublic...)
	if err := verifyRetainedRolloutExecution(store, &run, wrongTask); err == nil {
		t.Fatal("wrong task key accepted")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := verifyRolloutTargets(nil, verifiedRolloutRun{states: []rollout.TargetStateV1{{}}}); err == nil {
		t.Fatal("mismatched fleet state inventory accepted")
	}
	incomplete := run
	incomplete.states = append([]rollout.TargetStateV1(nil), run.states...)
	incomplete.states[0].Phase = rollout.PhasePlanned
	store, err = rolloutstore.Open(base.workspace)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := verifyRolloutTargets(store, incomplete); err == nil {
		t.Fatal("incomplete fleet accepted")
	}
}

func replaceRolloutRecoveryArtifact(kind string, raw []byte) func(*testing.T, rolloutVerifyTestFixture, *verifiedRolloutRun, *rollout.TargetStateV1) {
	return func(t *testing.T, fixture rolloutVerifyTestFixture, _ *verifiedRolloutRun, _ *rollout.TargetStateV1) {
		if err := os.WriteFile(rolloutRunTargetPath(t, fixture.workspace, kind), raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func removeRolloutRecoveryArtifact(t *testing.T, fixture rolloutVerifyTestFixture, kind string) {
	t.Helper()
	if err := os.Remove(rolloutRunTargetPath(t, fixture.workspace, kind)); err != nil {
		t.Fatal(err)
	}
}

func replaceRolloutVerifierArtifact(kind string, raw []byte) func(*testing.T, rolloutVerifyTestFixture, *verifiedRolloutRun) {
	return func(t *testing.T, fixture rolloutVerifyTestFixture, _ *verifiedRolloutRun) {
		if err := os.WriteFile(rolloutRunTargetPath(t, fixture.workspace, kind), raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func removeRolloutVerifierArtifact(kind string) func(*testing.T, rolloutVerifyTestFixture, *verifiedRolloutRun) {
	return func(t *testing.T, fixture rolloutVerifyTestFixture, _ *verifiedRolloutRun) {
		removeRolloutRecoveryArtifact(t, fixture, kind)
	}
}

func signRolloutVerifierPayload(t *testing.T, payload []byte, keyID string, private ed25519.PrivateKey) []byte {
	t.Helper()
	envelope, err := dsse.Sign(admission.CommandPayloadType, payload, keyID, private)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := dsse.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func signRolloutVerifierStatement(t *testing.T, statement admission.CommandStatement, keyID string, private ed25519.PrivateKey) []byte {
	t.Helper()
	raw, err := json.Marshal(statement)
	if err != nil {
		t.Fatal(err)
	}
	return signRolloutVerifierPayload(t, raw, keyID, private)
}

func cloneRolloutRecoveryPolicy(policy admission.SitePolicy) admission.SitePolicy {
	cloned := policy
	cloned.Tenants = append([]admission.TenantRule(nil), policy.Tenants...)
	for index := range cloned.Tenants {
		cloned.Tenants[index].CommandKeys = append(
			[]admission.CommandKey(nil), policy.Tenants[index].CommandKeys...,
		)
		for keyIndex := range cloned.Tenants[index].CommandKeys {
			cloned.Tenants[index].CommandKeys[keyIndex].Operations = append(
				[]string(nil), policy.Tenants[index].CommandKeys[keyIndex].Operations...,
			)
		}
	}
	return cloned
}
