package main

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/rollout"
	"github.com/hardrails/steward/internal/rolloutstore"
)

type rolloutAuthorizationChain struct {
	planRaw       []byte
	plan          rollout.VerifiedPlanAuthorizationV1
	planRawRecord []byte
	signerPublic  ed25519.PublicKey
	promotions    map[uint16]rollout.VerifiedBatchPromotionV1
	promotionRaws map[uint16][]byte
}

type rolloutPromotionCompanions struct {
	states   [][]byte
	proofs   [][]byte
	captures [][]byte
}

// authorizeRolloutRun creates only the authorization record for the still
// untouched batch, authenticates the entire retained authorization chain, and
// selects the exact digest that every command from this invocation must sign.
// It must run after retained execution verification and before client creation.
func authorizeRolloutRun(
	store *rolloutstore.Store,
	run *verifiedRolloutRun,
	keys *rolloutRunKeys,
) error {
	if store == nil || run == nil || keys == nil {
		return errors.New("rollout authorization inputs are unavailable")
	}
	trusted, err := commonRolloutCommandTrust(run.verified.SitePolicy, run.plan.TenantID)
	if err != nil {
		return err
	}
	authorizedPublic, ok := trusted[keys.commandID]
	if !ok || !bytes.Equal(authorizedPublic, keys.commandPublic) {
		return errors.New("rollout command key is not the same policy-authorized common command key")
	}

	_, present, err := optionalRolloutAuthorizationArtifact(
		store, rolloutstore.PlanAuthorizationFileName,
		rollout.MaxPlanAuthorizationEnvelopeBytes,
	)
	if err != nil {
		return err
	}
	if !present {
		for _, state := range run.states {
			if state.Phase != rollout.PhasePlanned {
				return errors.New("plan authorization is missing after rollout execution began")
			}
		}
		now := timeNow().UTC()
		if err := requireLiveRolloutAuthorizationWindow(run.plan, now); err != nil {
			return err
		}
		statement, err := rollout.NewPlanAuthorizationV1(run.planRaw, now)
		if err != nil {
			return err
		}
		authorizationRaw, err := rollout.SignPlanAuthorizationV1(
			statement,
			keys.commandID,
			keys.commandPrivate,
			keys.commandPublic,
		)
		if err != nil {
			return err
		}
		if err := store.WriteOnce(
			rolloutstore.PlanAuthorizationFileName, authorizationRaw,
		); err != nil {
			return fmt.Errorf("retain signed rollout plan authorization: %w", err)
		}
	}

	companions, err := loadRolloutPromotionCompanions(store, *run)
	if err != nil {
		return err
	}
	chain, err := loadRolloutAuthorizationChain(
		store, *run, trusted, companions,
	)
	if err != nil {
		return err
	}
	if chain.plan.KeyID != keys.commandID {
		return errors.New("retained plan authorization was signed by a different common command key")
	}

	batches, _ := run.plan.Batches()
	activeBatch, hasActive, actionRequired, err := activeRolloutAuthorizationBatch(run.plan, run.states)
	if err != nil {
		return err
	}
	requiredThrough := uint16(0)
	if hasActive {
		requiredThrough = activeBatch
	} else if allRolloutTargetsPassed(run.states) && len(batches) > 1 {
		requiredThrough = batches[len(batches)-1].Number
	}
	if hasActive && activeBatch > 0 {
		if _, exists := chain.promotions[activeBatch]; !exists {
			if actionRequired || !batchIsUntouched(run.plan, run.states, activeBatch) {
				return errors.New("batch promotion is missing after its next batch began")
			}
			previousRaw := chain.promotionRaws[activeBatch-1]
			now := timeNow().UTC()
			if err := requireLiveRolloutAuthorizationWindow(run.plan, now); err != nil {
				return err
			}
			causalFloor, err := rolloutPromotionCausalFloor(
				chain, *run, companions, activeBatch,
			)
			if err != nil {
				return err
			}
			if now.Before(causalFloor) {
				return errors.New("coordinator clock precedes the prior signed promotion or completed target checkpoint")
			}
			statement, err := rollout.NewBatchPromotionV1(
				run.planRaw,
				chain.planRawRecord,
				previousRaw,
				activeBatch,
				companions.states,
				companions.proofs,
				companions.captures,
				now,
			)
			if err != nil {
				return err
			}
			raw, err := rollout.SignBatchPromotionV1(
				statement,
				keys.commandID,
				keys.commandPrivate,
				keys.commandPublic,
			)
			if err != nil {
				return err
			}
			name, err := rolloutstore.BatchPromotionName(activeBatch)
			if err != nil {
				return err
			}
			if err := store.WriteOnce(name, raw); err != nil {
				return fmt.Errorf("retain signed batch promotion: %w", err)
			}
			chain, err = loadRolloutAuthorizationChain(
				store, *run, trusted, companions,
			)
			if err != nil {
				return err
			}
		}
	}
	if err := requireExactRolloutPromotionInventory(chain, requiredThrough); err != nil {
		return err
	}
	if err := verifyRolloutCommandAuthorizationContexts(store, *run, chain); err != nil {
		return err
	}
	run.authorization = &chain
	if hasActive && !actionRequired {
		now := timeNow().UTC()
		if err := requireLiveRolloutAuthorizationWindow(run.plan, now); err != nil {
			return err
		}
		contextDigest, authorizedAt, err := rolloutBatchAuthorization(chain, activeBatch)
		if err != nil {
			return err
		}
		if now.Before(authorizedAt) {
			return errors.New("active rollout authorization time is in the future")
		}
		keys.authorizationContextDigest = contextDigest
		keys.authorizationContextTime = authorizedAt
	}
	return nil
}

// verifyCompletedRolloutAuthorization authenticates the complete signer-
// authorized plan and batch sequence without writing or consulting a clock.
func verifyCompletedRolloutAuthorization(
	store *rolloutstore.Store,
	run verifiedRolloutRun,
) (rolloutAuthorizationChain, error) {
	trusted, err := commonRolloutCommandTrust(run.verified.SitePolicy, run.plan.TenantID)
	if err != nil {
		return rolloutAuthorizationChain{}, err
	}
	companions, err := loadRolloutPromotionCompanions(store, run)
	if err != nil {
		return rolloutAuthorizationChain{}, err
	}
	chain, err := loadRolloutAuthorizationChain(store, run, trusted, companions)
	if err != nil {
		return rolloutAuthorizationChain{}, err
	}
	batches, _ := run.plan.Batches()
	requiredThrough := uint16(0)
	if len(batches) > 1 {
		requiredThrough = batches[len(batches)-1].Number
	}
	if err := requireExactRolloutPromotionInventory(chain, requiredThrough); err != nil {
		return rolloutAuthorizationChain{}, err
	}
	if err := verifyRolloutCommandAuthorizationContexts(store, run, chain); err != nil {
		return rolloutAuthorizationChain{}, err
	}
	return chain, nil
}

func commonRolloutCommandTrust(
	policy admission.SitePolicy,
	tenantID string,
) (map[string]ed25519.PublicKey, error) {
	operations := []string{"admit", "start", "activation-canary"}
	trusted, err := policy.TrustedCommandKeys(tenantID, operations[0])
	if err != nil {
		return nil, fmt.Errorf("load common rollout command trust: %w", err)
	}
	common := make(map[string]ed25519.PublicKey, len(trusted))
	for keyID, public := range trusted {
		common[keyID] = append(ed25519.PublicKey(nil), public...)
	}
	for _, operation := range operations[1:] {
		operationKeys, err := policy.TrustedCommandKeys(tenantID, operation)
		if err != nil {
			return nil, fmt.Errorf("load %s rollout command trust: %w", operation, err)
		}
		for keyID, public := range common {
			candidate, ok := operationKeys[keyID]
			if !ok || !bytes.Equal(public, candidate) {
				delete(common, keyID)
			}
		}
	}
	if len(common) == 0 {
		return nil, errors.New("site policy has no one tenant command key authorized for all rollout operations")
	}
	return common, nil
}

func loadRolloutAuthorizationChain(
	store *rolloutstore.Store,
	run verifiedRolloutRun,
	trusted map[string]ed25519.PublicKey,
	companions rolloutPromotionCompanions,
) (rolloutAuthorizationChain, error) {
	authorizationRaw, err := store.Read(
		rolloutstore.PlanAuthorizationFileName,
		rollout.MaxPlanAuthorizationEnvelopeBytes,
	)
	if err != nil {
		return rolloutAuthorizationChain{}, fmt.Errorf("read rollout plan authorization: %w", err)
	}
	verifiedPlan, err := rollout.VerifyPlanAuthorizationV1(
		run.planRaw, authorizationRaw, trusted,
	)
	if err != nil {
		return rolloutAuthorizationChain{}, fmt.Errorf("authenticate rollout plan authorization: %w", err)
	}
	chain := rolloutAuthorizationChain{
		planRaw:       append([]byte(nil), run.planRaw...),
		plan:          verifiedPlan,
		planRawRecord: append([]byte(nil), authorizationRaw...),
		signerPublic:  append(ed25519.PublicKey(nil), trusted[verifiedPlan.KeyID]...),
		promotions:    make(map[uint16]rollout.VerifiedBatchPromotionV1),
		promotionRaws: make(map[uint16][]byte),
	}
	names, err := store.ListBatchPromotions()
	if err != nil {
		return rolloutAuthorizationChain{}, fmt.Errorf("list rollout batch promotions: %w", err)
	}
	var previousRaw []byte
	previousAt, _ := time.Parse(time.RFC3339Nano, verifiedPlan.Statement.AuthorizedAt)
	for position, name := range names {
		nextBatch := uint16(position + 1)
		expectedName, err := rolloutstore.BatchPromotionName(nextBatch)
		if err != nil || name != expectedName {
			return rolloutAuthorizationChain{}, errors.New("batch promotion inventory is not contiguous from batch one")
		}
		raw, err := store.Read(name, rollout.MaxBatchPromotionEnvelopeBytes)
		if err != nil {
			return rolloutAuthorizationChain{}, fmt.Errorf("read batch promotion %d: %w", nextBatch, err)
		}
		verified, err := rollout.VerifyBatchPromotionV1(
			run.planRaw,
			authorizationRaw,
			previousRaw,
			raw,
			companions.states,
			companions.proofs,
			companions.captures,
			trusted,
			verifiedPlan.KeyID,
		)
		if err != nil {
			return rolloutAuthorizationChain{}, fmt.Errorf("authenticate batch promotion %d: %w", nextBatch, err)
		}
		if verified.Statement.NextBatch.Number != nextBatch {
			return rolloutAuthorizationChain{}, errors.New("batch promotion filename and signed boundary disagree")
		}
		authorizedAt, _ := time.Parse(time.RFC3339Nano, verified.Statement.AuthorizedAt)
		if authorizedAt.Before(previousAt) {
			return rolloutAuthorizationChain{}, errors.New("batch promotion authorization times are not nondecreasing")
		}
		completed := verified.Statement.CompletedBatch
		for index := completed.Start; index < completed.End; index++ {
			state, parseErr := rollout.ParseTargetStateV1(companions.states[index])
			stateAt, timeErr := time.Parse(time.RFC3339Nano, state.UpdatedAt)
			if parseErr != nil || timeErr != nil || authorizedAt.Before(stateAt) {
				return rolloutAuthorizationChain{}, fmt.Errorf(
					"batch promotion %d predates completed target %d checkpoint",
					nextBatch, index,
				)
			}
		}
		chain.promotions[nextBatch] = verified
		chain.promotionRaws[nextBatch] = append([]byte(nil), raw...)
		previousRaw = raw
		previousAt = authorizedAt
	}
	return chain, nil
}

func loadRolloutPromotionCompanions(
	store *rolloutstore.Store,
	run verifiedRolloutRun,
) (rolloutPromotionCompanions, error) {
	count := len(run.plan.Targets)
	companions := rolloutPromotionCompanions{
		states: make([][]byte, count), proofs: make([][]byte, count), captures: make([][]byte, count),
	}
	for index := 0; index < count; index++ {
		if index >= len(run.stateCounts) || run.stateCounts[index] == 0 {
			return rolloutPromotionCompanions{}, fmt.Errorf("target %d has no retained state checkpoint", index)
		}
		stateName, err := rolloutstore.TargetStateName(
			uint16(index), run.stateCounts[index]-1,
		)
		if err != nil {
			return rolloutPromotionCompanions{}, err
		}
		companions.states[index], err = store.Read(stateName, rollout.MaxTargetStateBytes)
		if err != nil {
			return rolloutPromotionCompanions{}, fmt.Errorf("read target %d final state for promotion: %w", index, err)
		}
		if run.states[index].Phase != rollout.PhasePassed {
			continue
		}
		companions.proofs[index], err = readRolloutTargetArtifact(
			store, uint16(index), rolloutstore.TargetActivationProofKind, rolloutstore.MaxArtifactBytes,
		)
		if err != nil {
			return rolloutPromotionCompanions{}, err
		}
		companions.captures[index], err = readRolloutTargetArtifact(
			store, uint16(index), rolloutstore.TargetCaptureExportKind, rolloutstore.MaxArtifactBytes,
		)
		if err != nil {
			return rolloutPromotionCompanions{}, err
		}
	}
	return companions, nil
}

func verifyRolloutCommandAuthorizationContexts(
	store *rolloutstore.Store,
	run verifiedRolloutRun,
	chain rolloutAuthorizationChain,
) error {
	public, ok := commonRolloutSigner(chain)
	if !ok {
		return errors.New("rollout authorization signer is unavailable")
	}
	batches, _ := run.plan.Batches()
	for index := range run.plan.Targets {
		batchNumber, err := rolloutTargetBatchNumber(batches, index)
		if err != nil {
			return err
		}
		contextDigest, authorizedAt, err := rolloutBatchAuthorization(chain, batchNumber)
		if err != nil {
			// An untouched future target legitimately has no promotion yet.
			if run.states[index].Phase == rollout.PhasePlanned {
				continue
			}
			return err
		}
		for _, artifact := range []struct {
			kind string
			name string
		}{
			{rolloutstore.TargetAdmitCommandKind, "admit"},
			{rolloutstore.TargetStartCommandKind, "start"},
			{rolloutstore.TargetCanaryCommandKind, "activation-canary"},
		} {
			raw, present, err := optionalRolloutTargetArtifact(
				store, uint16(index), artifact.kind, rolloutstore.MaxArtifactBytes,
			)
			if err != nil {
				return err
			}
			if !present {
				continue
			}
			payload, keyID, err := dsse.Verify(
				raw,
				admission.CommandPayloadType,
				map[string]ed25519.PublicKey{chain.plan.KeyID: public},
			)
			if err != nil || keyID != chain.plan.KeyID {
				return fmt.Errorf("target %d %s command was not signed by the rollout authorization key", index, artifact.name)
			}
			var statement admission.CommandStatement
			if err := dsse.DecodeStrictInto(payload, dsse.MaxPayloadBytes, &statement); err != nil {
				return fmt.Errorf("decode target %d %s command authorization context: %w", index, artifact.name, err)
			}
			issuedAt, err := time.Parse(time.RFC3339Nano, statement.IssuedAt)
			if err != nil || statement.AuthorizationContextDigest != contextDigest || issuedAt.Before(authorizedAt) {
				return fmt.Errorf("target %d %s command does not bind the current signer-authorized batch", index, artifact.name)
			}
		}
	}
	return nil
}

func commonRolloutSigner(chain rolloutAuthorizationChain) (ed25519.PublicKey, bool) {
	if len(chain.signerPublic) != ed25519.PublicKeySize {
		return nil, false
	}
	return append(ed25519.PublicKey(nil), chain.signerPublic...), true
}

func requireExactRolloutPromotionInventory(
	chain rolloutAuthorizationChain,
	requiredThrough uint16,
) error {
	if len(chain.promotions) != int(requiredThrough) {
		return fmt.Errorf(
			"rollout requires exactly %d signed batch promotions, found %d",
			requiredThrough, len(chain.promotions),
		)
	}
	for number := uint16(1); number <= requiredThrough; number++ {
		if _, ok := chain.promotions[number]; !ok {
			return fmt.Errorf("signed batch promotion %d is missing", number)
		}
	}
	return nil
}

func orderedRolloutPromotionRaws(chain rolloutAuthorizationChain) [][]byte {
	raws := make([][]byte, len(chain.promotionRaws))
	for index := range raws {
		raws[index] = append([]byte(nil), chain.promotionRaws[uint16(index+1)]...)
	}
	return raws
}

func rolloutBatchAuthorization(
	chain rolloutAuthorizationChain,
	batchNumber uint16,
) (string, time.Time, error) {
	if batchNumber == 0 {
		authorizedAt, err := time.Parse(time.RFC3339Nano, chain.plan.Statement.AuthorizedAt)
		return chain.plan.EnvelopeDigest, authorizedAt, err
	}
	promotion, ok := chain.promotions[batchNumber]
	if !ok {
		return "", time.Time{}, fmt.Errorf("signed batch promotion %d is missing", batchNumber)
	}
	authorizedAt, err := time.Parse(time.RFC3339Nano, promotion.Statement.AuthorizedAt)
	return promotion.EnvelopeDigest, authorizedAt, err
}

func activeRolloutAuthorizationBatch(
	plan rollout.PlanV1,
	states []rollout.TargetStateV1,
) (uint16, bool, bool, error) {
	batches, err := plan.Batches()
	if err != nil {
		return 0, false, false, err
	}
	for index, state := range states {
		if state.Phase == rollout.PhaseActionRequired {
			batch, err := rolloutTargetBatchNumber(batches, index)
			return batch, true, true, err
		}
		if state.Phase != rollout.PhasePassed {
			batch, err := rolloutTargetBatchNumber(batches, index)
			return batch, true, false, err
		}
	}
	return 0, false, false, nil
}

func rolloutTargetBatchNumber(batches []rollout.BatchV1, target int) (uint16, error) {
	for _, batch := range batches {
		if target >= batch.Start && target < batch.End {
			return batch.Number, nil
		}
	}
	return 0, errors.New("rollout target is outside deterministic batch boundaries")
}

func batchIsUntouched(
	plan rollout.PlanV1,
	states []rollout.TargetStateV1,
	batchNumber uint16,
) bool {
	batches, err := plan.Batches()
	if err != nil || int(batchNumber) >= len(batches) {
		return false
	}
	batch := batches[batchNumber]
	for index := batch.Start; index < batch.End; index++ {
		if states[index].Phase != rollout.PhasePlanned {
			return false
		}
	}
	for index := 0; index < batch.Start; index++ {
		if states[index].Phase != rollout.PhasePassed {
			return false
		}
	}
	return true
}

func allRolloutTargetsPassed(states []rollout.TargetStateV1) bool {
	for _, state := range states {
		if state.Phase != rollout.PhasePassed {
			return false
		}
	}
	return true
}

func requireLiveRolloutAuthorizationWindow(plan rollout.PlanV1, now time.Time) error {
	createdAt, createdErr := time.Parse(time.RFC3339Nano, plan.CreatedAt)
	deadline, deadlineErr := time.Parse(time.RFC3339Nano, plan.Deadline)
	if createdErr != nil || deadlineErr != nil || now.Before(createdAt) || !now.Before(deadline) {
		return errors.New("rollout authorization window is not currently live")
	}
	return nil
}

func rolloutPromotionCausalFloor(
	chain rolloutAuthorizationChain,
	run verifiedRolloutRun,
	companions rolloutPromotionCompanions,
	nextBatch uint16,
) (time.Time, error) {
	floor, err := time.Parse(time.RFC3339Nano, chain.plan.Statement.AuthorizedAt)
	if err != nil {
		return time.Time{}, errors.New("plan authorization has an invalid signer time")
	}
	if nextBatch > 1 {
		previous, ok := chain.promotions[nextBatch-1]
		if !ok {
			return time.Time{}, errors.New("previous signed batch promotion is missing")
		}
		previousAt, err := time.Parse(time.RFC3339Nano, previous.Statement.AuthorizedAt)
		if err != nil {
			return time.Time{}, errors.New("previous batch promotion has an invalid signer time")
		}
		if previousAt.After(floor) {
			floor = previousAt
		}
	}
	batches, err := run.plan.Batches()
	if err != nil || nextBatch == 0 || int(nextBatch) >= len(batches) {
		return time.Time{}, errors.New("next batch is outside deterministic rollout boundaries")
	}
	completed := batches[nextBatch-1]
	for index := completed.Start; index < completed.End; index++ {
		state, err := rollout.ParseTargetStateV1(companions.states[index])
		if err != nil {
			return time.Time{}, fmt.Errorf("parse completed target %d checkpoint: %w", index, err)
		}
		updatedAt, err := time.Parse(time.RFC3339Nano, state.UpdatedAt)
		if err != nil {
			return time.Time{}, fmt.Errorf("parse completed target %d checkpoint time: %w", index, err)
		}
		if updatedAt.After(floor) {
			floor = updatedAt
		}
	}
	return floor, nil
}

func optionalRolloutAuthorizationArtifact(
	store *rolloutstore.Store,
	name string,
	limit int,
) ([]byte, bool, error) {
	raw, err := store.Read(name, int64(limit))
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("read optional rollout authorization %q: %w", name, err)
	}
	return raw, true, nil
}
