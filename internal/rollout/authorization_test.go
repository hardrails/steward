package rollout

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/dsse"
)

func TestSignedPlanAuthorizationAndPromotionBindExactChain(t *testing.T) {
	plan := rolloutPlanFixture(5)
	planRaw, err := MarshalPlanV1(plan)
	if err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	authorizedAt := time.Date(2026, 7, 16, 12, 1, 0, 0, time.UTC)
	authorization, err := NewPlanAuthorizationV1(planRaw, authorizedAt)
	if err != nil {
		t.Fatal(err)
	}
	authorizationRaw, err := SignPlanAuthorizationV1(
		authorization, "command-key", private, public,
	)
	if err != nil {
		t.Fatal(err)
	}
	verifiedAuthorization, err := VerifyPlanAuthorizationV1(
		planRaw, authorizationRaw,
		map[string]ed25519.PublicKey{"command-key": public},
	)
	if err != nil {
		t.Fatal(err)
	}
	if verifiedAuthorization.KeyID != "command-key" ||
		verifiedAuthorization.EnvelopeDigest != dsse.Digest(authorizationRaw) {
		t.Fatalf("verified authorization=%#v", verifiedAuthorization)
	}

	stateRaws, proofRaws, captureRaws := promotionCompanions(t, planRaw, plan)
	first, err := NewBatchPromotionV1(
		planRaw, authorizationRaw, nil, 1,
		stateRaws, proofRaws, captureRaws,
		authorizedAt.Add(time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	firstRaw, err := SignBatchPromotionV1(first, "command-key", private, public)
	if err != nil {
		t.Fatal(err)
	}
	verifiedFirst, err := VerifyBatchPromotionV1(
		planRaw, authorizationRaw, nil, firstRaw,
		stateRaws, proofRaws, captureRaws,
		map[string]ed25519.PublicKey{"command-key": public}, "command-key",
	)
	if err != nil {
		t.Fatal(err)
	}
	if verifiedFirst.Statement.NextBatch.Number != 1 ||
		verifiedFirst.Statement.CompletedBatch != (BatchBoundaryV1{Number: 0, Start: 0, End: 1}) ||
		verifiedFirst.Statement.CompletedTargets[0].ActivationProofDigest != dsse.Digest(proofRaws[0]) {
		t.Fatalf("verified first promotion=%#v", verifiedFirst)
	}

	second, err := NewBatchPromotionV1(
		planRaw, authorizationRaw, firstRaw, 2,
		stateRaws, proofRaws, captureRaws,
		authorizedAt.Add(2*time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	secondRaw, err := SignBatchPromotionV1(second, "command-key", private, public)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyBatchPromotionV1(
		planRaw, authorizationRaw, firstRaw, secondRaw,
		stateRaws, proofRaws, captureRaws,
		map[string]ed25519.PublicKey{"command-key": public}, "command-key",
	); err != nil {
		t.Fatal(err)
	}

	t.Run("changed completed proof", func(t *testing.T) {
		changed := append([][]byte(nil), proofRaws...)
		changed[1] = []byte(`{"changed":true}`)
		if _, err := VerifyBatchPromotionV1(
			planRaw, authorizationRaw, firstRaw, secondRaw,
			stateRaws, changed, captureRaws,
			map[string]ed25519.PublicKey{"command-key": public}, "command-key",
		); err == nil {
			t.Fatal("promotion accepted changed prior-batch proof bytes")
		}
	})

	t.Run("wrong predecessor", func(t *testing.T) {
		if _, err := VerifyBatchPromotionV1(
			planRaw, authorizationRaw, []byte(`{"other":true}`), secondRaw,
			stateRaws, proofRaws, captureRaws,
			map[string]ed25519.PublicKey{"command-key": public}, "command-key",
		); err == nil {
			t.Fatal("promotion accepted a different predecessor")
		}
	})

	t.Run("re-signed changed boundary", func(t *testing.T) {
		changed := first
		changed.NextBatch.End++
		changedRaw := mustSignPromotion(t, changed, private, public)
		if _, err := VerifyBatchPromotionV1(
			planRaw, authorizationRaw, nil, changedRaw,
			stateRaws, proofRaws, captureRaws,
			map[string]ed25519.PublicKey{"command-key": public}, "command-key",
		); err == nil {
			t.Fatal("promotion accepted a re-signed plan boundary change")
		}
	})

	t.Run("noncanonical envelope", func(t *testing.T) {
		changed := append(append([]byte(nil), authorizationRaw...), '\n')
		if _, err := VerifyPlanAuthorizationV1(
			planRaw, changed,
			map[string]ed25519.PublicKey{"command-key": public},
		); err == nil {
			t.Fatal("noncanonical authorization envelope accepted")
		}
	})
}

func TestAuthorizationRejectsPlanMutationAndDeadline(t *testing.T) {
	plan := rolloutPlanFixture(1)
	planRaw, err := MarshalPlanV1(plan)
	if err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	deadline, _ := time.Parse(time.RFC3339Nano, plan.Deadline)
	if _, err := NewPlanAuthorizationV1(planRaw, deadline); err == nil {
		t.Fatal("authorization at the deadline was accepted")
	}
	statement, err := NewPlanAuthorizationV1(planRaw, deadline.Add(-time.Second))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := SignPlanAuthorizationV1(statement, "command-key", private, public)
	if err != nil {
		t.Fatal(err)
	}
	mutated := plan
	mutated.Archive.Bytes++
	mutatedRaw, err := MarshalPlanV1(mutated)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyPlanAuthorizationV1(
		mutatedRaw, raw,
		map[string]ed25519.PublicKey{"command-key": public},
	); err == nil {
		t.Fatal("authorization accepted different plan bytes")
	}
}

func promotionCompanions(
	t *testing.T,
	planRaw []byte,
	plan PlanV1,
) ([][]byte, [][]byte, [][]byte) {
	t.Helper()
	states := make([][]byte, len(plan.Targets))
	proofs := make([][]byte, len(plan.Targets))
	captures := make([][]byte, len(plan.Targets))
	for index := range plan.Targets {
		state := passedTargetState(initialTargetState(planRaw, plan, index))
		state.UpdatedAt = planTime(time.Duration(index+1) * time.Second)
		raw, err := MarshalTargetStateV1(state)
		if err != nil {
			t.Fatal(err)
		}
		states[index] = raw
		proofs[index] = []byte(`{"proof":"` + strings.Repeat(string(rune('a'+index)), 4) + `"}`)
		captures[index] = []byte(`{"capture":"` + strings.Repeat(string(rune('a'+index)), 4) + `"}`)
	}
	return states, proofs, captures
}

func mustSignPromotion(
	t *testing.T,
	statement BatchPromotionV1,
	private ed25519.PrivateKey,
	public ed25519.PublicKey,
) []byte {
	t.Helper()
	payload, err := json.Marshal(statement)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := dsse.Sign(
		BatchPromotionPayloadTypeV1, payload, "command-key", private,
	)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := dsse.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	_ = public
	return raw
}
