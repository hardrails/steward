package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/hardrails/steward/internal/activation"
	"github.com/hardrails/steward/internal/activationcanary"
	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/agentrelease"
	"github.com/hardrails/steward/internal/controlcapture"
	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/evidence"
	"github.com/hardrails/steward/internal/rollout"
	"github.com/hardrails/steward/internal/rolloutdriver"
	"github.com/hardrails/steward/internal/rolloutstore"
)

var rolloutPhaseRanks = map[string]int{
	rollout.PhasePlanned:               0,
	rollout.PhasePreflightPassed:       1,
	rollout.PhaseEvidenceCaptureArmed:  2,
	rollout.PhaseAdmitSubmitted:        3,
	rollout.PhaseAdmitted:              4,
	rollout.PhaseStartSubmitted:        5,
	rollout.PhaseRunning:               6,
	rollout.PhaseCanaryAuthorized:      7,
	rollout.PhaseCanarySubmitted:       8,
	rollout.PhaseAgentReportedTerminal: 9,
	rollout.PhaseEvidenceCollected:     10,
	rollout.PhasePassed:                11,
}

func verifyRetainedRolloutExecution(
	store *rolloutstore.Store,
	run *verifiedRolloutRun,
	keys rolloutRunKeys,
) error {
	if run == nil {
		return errors.New("rollout run is unavailable")
	}
	for _, kind := range []string{"admit", "start", "activation-canary"} {
		authorized, err := run.verified.SitePolicy.TrustedCommandKeys(run.plan.TenantID, kind)
		if err != nil || !bytes.Equal(authorized[keys.commandID], keys.commandPublic) {
			return fmt.Errorf("supplied common command key is not authorized for %s", kind)
		}
	}
	taskKeys, err := run.verified.SitePolicy.TrustedTaskKeys(
		run.plan.TenantID, agentrelease.HermesServiceID,
	)
	if err != nil || !bytes.Equal(taskKeys[keys.taskID], keys.taskPublic) {
		return errors.New("supplied task key is not authorized for the Hermes service")
	}
	for index := range run.targets {
		if err := verifyRetainedRolloutTarget(
			store, &run.targets[index], run.states[index], keys, run.witnessPublic,
		); err != nil {
			return fmt.Errorf("verify retained rollout target %d: %w", index, err)
		}
	}
	if proofRaw, present, err := optionalRolloutFixedArtifact(
		store, rolloutstore.ProofFileName, rollout.MaxProofManifestBytes,
	); err != nil {
		return err
	} else if present {
		proof, parseErr := rollout.ParseProofManifestV1(proofRaw)
		canonical, marshalErr := rollout.MarshalProofManifestV1(proof)
		if parseErr != nil || marshalErr != nil || !bytes.Equal(canonical, proofRaw) {
			return errors.New("retained aggregate rollout proof is not canonical JSON")
		}
		for _, state := range run.states {
			if state.Phase != rollout.PhasePassed {
				return errors.New("aggregate rollout proof appeared before every target passed")
			}
		}
		if err := ensureRolloutProofManifest(store, run, false); err != nil {
			return fmt.Errorf("verify retained aggregate rollout proof: %w", err)
		}
	}
	return nil
}

func verifyRetainedRolloutTarget(
	store *rolloutstore.Store,
	target *verifiedRolloutRunTarget,
	state rollout.TargetStateV1,
	keys rolloutRunKeys,
	witnessPublic ed25519.PublicKey,
) error {
	index := state.Binding.TargetIndex
	rank, normal := rolloutPhaseRanks[state.Phase]
	if !normal && state.Phase != rollout.PhaseActionRequired {
		return errors.New("target has an unknown retained phase")
	}

	admitRaw, admitPresent, err := optionalRolloutTargetArtifact(
		store, index, rolloutstore.TargetAdmitCommandKind, rolloutstore.MaxArtifactBytes,
	)
	if err != nil {
		return err
	}
	if err := requireRolloutArtifactPhase(
		"admit command", admitPresent, normal, rank, 1, 2,
	); err != nil {
		return err
	}
	if admitPresent {
		window, err := historicalRolloutCommandWindow(
			admitRaw, keys.commandID, keys.commandPublic,
		)
		if err != nil {
			return fmt.Errorf("admit command: %w", err)
		}
		window.PrivateKey = keys.commandPrivate
		expected, err := rolloutdriver.SignAdmissionCommandV1(target.prepared, window)
		if err != nil || !bytes.Equal(expected.Raw(), admitRaw) {
			return errors.New("retained admit command is not the deterministic policy-authorized command")
		}
		target.admitCommandRaw = admitRaw
	}

	admissionRaw, admissionPresent, err := optionalRolloutTargetArtifact(
		store, index, rolloutstore.TargetAdmissionKind, rolloutstore.MaxArtifactBytes,
	)
	if err != nil {
		return err
	}
	if err := requireRolloutArtifactPhase(
		"admission", admissionPresent, normal, rank, 3, 4,
	); err != nil {
		return err
	}
	if admissionPresent {
		admissionProjection, err := parseCanonicalRolloutAdmission(admissionRaw)
		if err != nil {
			return err
		}
		if err := rolloutdriver.VerifyAdmissionV1(target.prepared, admissionProjection); err != nil {
			return fmt.Errorf("retained admission: %w", err)
		}
		if state.RuntimeRef != "" &&
			(state.RuntimeRef != admissionProjection.RuntimeRef ||
				state.AdmissionDigest != dsse.Digest(admissionRaw)) {
			return errors.New("retained admission differs from target state")
		}
		target.admissionRaw = admissionRaw
		target.admission = &admissionProjection
	}

	startRaw, startPresent, err := optionalRolloutTargetArtifact(
		store, index, rolloutstore.TargetStartCommandKind, rolloutstore.MaxArtifactBytes,
	)
	if err != nil {
		return err
	}
	if err := requireRolloutArtifactPhase(
		"start command", startPresent, normal, rank, 4, 5,
	); err != nil {
		return err
	}
	if startPresent {
		window, err := historicalRolloutCommandWindow(
			startRaw, keys.commandID, keys.commandPublic,
		)
		if err != nil {
			return fmt.Errorf("start command: %w", err)
		}
		window.PrivateKey = keys.commandPrivate
		expected, err := rolloutdriver.SignStartCommandV1(target.prepared, window)
		if err != nil || !bytes.Equal(expected.Raw(), startRaw) {
			return errors.New("retained start command is not the deterministic policy-authorized command")
		}
		target.startCommandRaw = startRaw
	}

	canaryRaw, canaryPresent, err := optionalRolloutTargetArtifact(
		store, index, rolloutstore.TargetCanaryCommandKind, rolloutstore.MaxArtifactBytes,
	)
	if err != nil {
		return err
	}
	if err := requireRolloutArtifactPhase(
		"canary command", canaryPresent, normal, rank, 6, 7,
	); err != nil {
		return err
	}
	if canaryPresent {
		if target.admission == nil {
			return errors.New("retained canary command has no authenticated admission companion")
		}
		window, statement, err := historicalRolloutCommand(
			canaryRaw, keys.commandID, keys.commandPublic,
		)
		if err != nil {
			return fmt.Errorf("canary command: %w", err)
		}
		window.PrivateKey = keys.commandPrivate
		canary, err := activationcanary.ParseCommandV1(statement.Payload)
		if err != nil {
			return fmt.Errorf("parse retained closed canary: %w", err)
		}
		deadline, err := time.Parse(time.RFC3339Nano, canary.Deadline)
		if err != nil {
			return errors.New("retained closed canary has an invalid deadline")
		}
		expected, err := rolloutdriver.BuildCanaryCommandV1(rolloutdriver.CanaryInputV1{
			Prepared: target.prepared, Admission: *target.admission,
			TaskKeyID: keys.taskID, TaskPrivateKey: keys.taskPrivate,
			TaskPublicKey:         keys.taskPublic,
			OperationPolicyDigest: target.prepared.Target().OperationPolicyDigest,
			ReceiptAuthority: activationcanary.ReceiptAuthorityV1{
				NodeID:          canary.ReceiptAuthority.NodeID,
				Epoch:           canary.ReceiptAuthority.Epoch,
				PublicKeySHA256: canary.ReceiptAuthority.PublicKeySHA256,
			},
			Deadline: deadline, CommandWindow: window,
		})
		if err != nil || !bytes.Equal(expected.OuterCommand().Raw(), canaryRaw) {
			return errors.New("retained canary command is not the deterministic closed command")
		}
		target.canaryCommandRaw = canaryRaw
	}

	resultRaw, resultPresent, err := optionalRolloutTargetArtifact(
		store, index, rolloutstore.TargetCanaryResultKind, rolloutstore.MaxArtifactBytes,
	)
	if err != nil {
		return err
	}
	if err := requireRolloutArtifactPhase(
		"canary result", resultPresent, normal, rank, 8, 9,
	); err != nil {
		return err
	}
	if resultPresent {
		if target.admission == nil || len(target.canaryCommandRaw) == 0 {
			return errors.New("retained canary result has incomplete authenticated command companions")
		}
		canaryRaw, err := canaryOuterPayload(target.canaryCommandRaw, keys)
		if err != nil {
			return fmt.Errorf("retained canary command payload: %w", err)
		}
		verifiedCanary, err := rolloutdriver.VerifyCanaryV1(rolloutdriver.VerifyCanaryInputV1{
			Prepared: target.prepared, Admission: *target.admission,
			CommandRaw: canaryRaw, ResultRaw: resultRaw,
			ReceiptPublicKey: target.gatewayPublic,
		})
		if err != nil {
			return fmt.Errorf("retained canary result: %w", err)
		}
		verifiedResult := verifiedCanary.Result()
		if state.CanaryResultDigest != "" &&
			(state.CanaryResultDigest != verifiedResult.TerminalResultDigest ||
				state.CanaryResultBytes != verifiedResult.TerminalResultBytes) {
			return errors.New("retained canary result differs from target state")
		}
		target.canaryResultRaw = resultRaw
		target.verifiedCanary = &verifiedCanary
	}

	captureRaw, capturePresent, err := optionalRolloutTargetArtifact(
		store, index, rolloutstore.TargetCaptureExportKind, rolloutstore.MaxArtifactBytes,
	)
	if err != nil {
		return err
	}
	if err := requireRolloutArtifactPhase(
		"capture export", capturePresent, normal, rank, 9, 10,
	); err != nil {
		return err
	}
	if capturePresent {
		if target.verifiedCanary == nil {
			return errors.New("retained capture has no authenticated canary companion")
		}
		capture, err := controlcapture.VerifyJSONV1(captureRaw, witnessPublic)
		if err != nil {
			return fmt.Errorf("retained evidence capture: %w", err)
		}
		if err := correlateRolloutCapture(target, capture); err != nil {
			return err
		}
		target.captureRaw = captureRaw
	}

	activationStateRaw, statePresent, err := optionalRolloutTargetArtifact(
		store, index, rolloutstore.TargetActivationStateKind, activation.MaxStateBytes,
	)
	if err != nil {
		return err
	}
	activationProofRaw, proofPresent, err := optionalRolloutTargetArtifact(
		store, index, rolloutstore.TargetActivationProofKind, activation.MaxProofBytes,
	)
	if err != nil {
		return err
	}
	if proofPresent && !statePresent {
		return errors.New("retained activation proof has no exact state companion")
	}
	if err := requireRolloutArtifactPhase(
		"activation proof", statePresent, normal, rank, 10, 11,
	); err != nil {
		return err
	}
	if statePresent && proofPresent {
		if len(target.captureRaw) == 0 || target.verifiedCanary == nil {
			return errors.New("retained activation proof has incomplete evidence companions")
		}
		if err := verifyRetainedRolloutActivationProof(
			target, activationStateRaw, activationProofRaw,
		); err != nil {
			return err
		}
		target.activationState = activationStateRaw
		target.activationProof = activationProofRaw
	} else if statePresent {
		if normal && rank != rolloutPhaseRanks[rollout.PhaseEvidenceCollected] {
			return errors.New("partial activation state is valid only at the proof recovery point")
		}
		state, err := activation.ParseStateV1(activationStateRaw)
		if err != nil || state.Phase != activation.PhasePassed ||
			state.Binding != target.prepared.Binding() ||
			state.RuntimeRef != target.prepared.RuntimeRef() {
			return errors.New("retained partial activation state differs from verified target evidence")
		}
		target.activationState = activationStateRaw
	}
	return nil
}

func optionalRolloutTargetArtifact(
	store *rolloutstore.Store,
	target uint16,
	kind string,
	limit int64,
) ([]byte, bool, error) {
	name, err := rolloutstore.TargetArtifactName(target, kind)
	if err != nil {
		return nil, false, err
	}
	raw, err := store.Read(name, limit)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("read optional rollout artifact %q: %w", name, err)
	}
	return raw, true, nil
}

func requireRolloutArtifactPhase(
	name string,
	present bool,
	normal bool,
	rank int,
	minimumPresent int,
	minimumRequired int,
) error {
	if !normal {
		return nil
	}
	if present && rank < minimumPresent {
		return fmt.Errorf("%s appeared before its store-before-submit recovery point", name)
	}
	if !present && rank >= minimumRequired {
		return fmt.Errorf("%s is missing for the retained phase", name)
	}
	return nil
}

func historicalRolloutCommandWindow(
	raw []byte,
	keyID string,
	public ed25519.PublicKey,
) (rolloutdriver.SigningWindowV1, error) {
	window, _, err := historicalRolloutCommand(raw, keyID, public)
	return window, err
}

func historicalRolloutCommand(
	raw []byte,
	keyID string,
	public ed25519.PublicKey,
) (rolloutdriver.SigningWindowV1, admission.CommandStatement, error) {
	payload, verifiedKeyID, err := dsse.Verify(
		raw, admission.CommandPayloadType,
		map[string]ed25519.PublicKey{keyID: public},
	)
	if err != nil || verifiedKeyID != keyID {
		return rolloutdriver.SigningWindowV1{}, admission.CommandStatement{},
			fmt.Errorf("verify command signature: %w", err)
	}
	var statement admission.CommandStatement
	if err := dsse.DecodeStrictInto(payload, dsse.MaxPayloadBytes, &statement); err != nil {
		return rolloutdriver.SigningWindowV1{}, admission.CommandStatement{}, err
	}
	issued, issueErr := time.Parse(time.RFC3339Nano, statement.IssuedAt)
	expires, expiryErr := time.Parse(time.RFC3339Nano, statement.ExpiresAt)
	if issueErr != nil || expiryErr != nil || !expires.After(issued) ||
		statement.Validate(issued) != nil {
		return rolloutdriver.SigningWindowV1{}, admission.CommandStatement{},
			errors.New("command has an invalid historical signing window")
	}
	return rolloutdriver.SigningWindowV1{
		KeyID: keyID, PrivateKey: nil, PublicKey: public,
		IssuedAt: issued, ValidFor: expires.Sub(issued),
		AuthorizationContextDigest: statement.AuthorizationContextDigest,
	}, statement, nil
}

func parseCanonicalRolloutAdmission(
	raw []byte,
) (controlprotocol.ExecutorAdmissionProjectionV1, error) {
	var projection controlprotocol.ExecutorAdmissionProjectionV1
	if err := dsse.DecodeStrictInto(raw, int(rolloutstore.MaxArtifactBytes), &projection); err != nil {
		return projection, fmt.Errorf("decode retained admission: %w", err)
	}
	canonical, err := json.Marshal(projection)
	if err != nil || !bytes.Equal(canonical, raw) {
		return projection, errors.New("retained admission is not canonical JSON")
	}
	return projection, nil
}

func canaryOuterPayload(raw []byte, keys rolloutRunKeys) ([]byte, error) {
	_, statement, err := historicalRolloutCommand(raw, keys.commandID, keys.commandPublic)
	if err != nil {
		return nil, fmt.Errorf("extract canary outer payload: %w", err)
	}
	return append([]byte(nil), statement.Payload...), nil
}

func correlateRolloutCapture(
	target *verifiedRolloutRunTarget,
	capture controlcapture.ResultV1,
) error {
	statement := capture.Statement
	plan := target.prepared.Plan()
	indexed := target.prepared.Target()
	verified := target.verifiedCanary
	if target.admission == nil {
		return errors.New("retained evidence capture has no authenticated admission")
	}
	receiptPublicRaw, err := base64.StdEncoding.DecodeString(
		statement.IdentityProof.Claim.PublicKeyBase64,
	)
	if err != nil || len(receiptPublicRaw) != ed25519.PublicKeySize ||
		base64.StdEncoding.EncodeToString(receiptPublicRaw) != statement.IdentityProof.Claim.PublicKeyBase64 ||
		evidence.KeyID(ed25519.PublicKey(receiptPublicRaw)) != target.admission.EvidenceKeyID {
		return errors.New("retained evidence capture uses a different Executor evidence identity than admission")
	}
	if statement.CaptureID != rolloutCaptureID(plan, target.prepared.TargetIndex()) ||
		statement.NodeID != indexed.NodeID ||
		statement.TenantID != plan.TenantID ||
		statement.RuntimeRef != target.prepared.RuntimeRef() ||
		statement.Generation != indexed.InstanceGeneration ||
		statement.ActivationID != indexed.ActivationID ||
		statement.CanaryCommandID != indexed.CanaryCommandID ||
		statement.ActivationBeginDigest != target.prepared.ExecutorBeginDigest() ||
		statement.ActivationCheckpointDigest != dsse.Digest(verified.CheckpointRaw()) ||
		statement.CapsuleDigest != target.prepared.CapsuleDigest() ||
		statement.PolicyDigest != plan.PolicyDigest {
		return errors.New("retained evidence capture differs from the prepared target and verified canary")
	}
	return nil
}

func verifyRetainedRolloutActivationProof(
	target *verifiedRolloutRunTarget,
	stateRaw []byte,
	proofRaw []byte,
) error {
	state, err := activation.ParseStateV1(stateRaw)
	if err != nil {
		return fmt.Errorf("parse retained activation state: %w", err)
	}
	proof, err := activation.CorrelateProofV1(
		target.prepared.ActivationPlanRaw(), stateRaw, proofRaw,
	)
	if err != nil {
		return fmt.Errorf("correlate retained activation proof: %w", err)
	}
	var portable controlprotocol.ControllerEvidenceCaptureV1
	if err := dsse.DecodeStrictInto(
		target.captureRaw,
		controlprotocol.MaxControllerEvidenceCaptureJSONBytes,
		&portable,
	); err != nil {
		return fmt.Errorf("decode retained capture for proof correlation: %w", err)
	}
	statement := portable.Statement
	verifiedCanary := target.verifiedCanary
	executorCoordinate := activation.ReceiptCoordinateV1{
		ReceiptNodeID:   statement.FinalHead.ReceiptNodeID,
		ReceiptEpoch:    statement.FinalHead.ReceiptEpoch,
		Sequence:        statement.FinalHead.Sequence,
		ChainHash:       statement.FinalHead.ChainHash,
		PublicKeySHA256: statement.FinalHead.PublicKeySHA256,
	}
	witnessCoordinate := activation.WitnessCoordinateV1{
		ControllerInstanceID:   statement.ControllerInstanceID,
		ControlNodeID:          statement.NodeID,
		ReceiptNodeID:          statement.FinalHead.ReceiptNodeID,
		ReceiptEpoch:           statement.FinalHead.ReceiptEpoch,
		Sequence:               statement.FinalHead.Sequence,
		ChainHash:              statement.FinalHead.ChainHash,
		ReceiptPublicKeySHA256: statement.FinalHead.PublicKeySHA256,
		WitnessPublicKeySHA256: portable.WitnessPublicKeySHA256,
		WitnessExportDigest:    dsse.Digest(target.captureRaw),
		WitnessedAt:            statement.ExportedAt,
	}
	if state.Phase != activation.PhasePassed ||
		state.Binding != target.prepared.Binding() ||
		state.RuntimeRef != target.prepared.RuntimeRef() ||
		proof.Binding != state.Binding ||
		proof.RuntimeRef != state.RuntimeRef ||
		proof.ExecutorBeginDigest != target.prepared.ExecutorBeginDigest() ||
		proof.ExecutorCheckpointDigest != dsse.Digest(verifiedCanary.CheckpointRaw()) ||
		proof.ExecutorEvidence != executorCoordinate ||
		proof.Witness != witnessCoordinate {
		return errors.New("retained activation state or proof differs from verified rollout evidence")
	}
	verifiedGateway, err := gatewayResultFromVerifiedCanary(target)
	if err != nil {
		return err
	}
	if proof.GatewayEvidence != verifiedGateway.Coordinate ||
		proof.Canary != verifiedGateway.Canary {
		return errors.New("retained activation proof differs from verified Gateway evidence")
	}
	return nil
}

func gatewayResultFromVerifiedCanary(
	target *verifiedRolloutRunTarget,
) (activation.GatewayEvidenceResultV1, error) {
	if target == nil || target.admission == nil || len(target.canaryCommandRaw) == 0 ||
		len(target.canaryResultRaw) == 0 {
		return activation.GatewayEvidenceResultV1{},
			errors.New("verified canary companions are incomplete")
	}
	var outer admission.CommandStatement
	envelope, err := dsse.Parse(target.canaryCommandRaw)
	if err != nil {
		return activation.GatewayEvidenceResultV1{}, err
	}
	payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil || base64.StdEncoding.EncodeToString(payload) != envelope.Payload {
		return activation.GatewayEvidenceResultV1{}, errors.New("canary outer command payload is not canonical base64")
	}
	if err := dsse.DecodeStrictInto(payload, dsse.MaxPayloadBytes, &outer); err != nil {
		return activation.GatewayEvidenceResultV1{}, err
	}
	verifiedCommand, err := activationcanary.VerifyHistoricalCommandV1(
		outer.Payload,
		activationcanary.AdmissionContextV1{
			NodeID:     target.prepared.Target().NodeID,
			TenantID:   target.prepared.Plan().TenantID,
			InstanceID: target.prepared.Target().InstanceID,
			Projection: *target.admission,
		},
		rolloutCommandMaximumValidity,
	)
	if err != nil {
		return activation.GatewayEvidenceResultV1{}, err
	}
	verifiedResult, err := activationcanary.VerifyResultV1(
		verifiedCommand, target.canaryResultRaw, target.gatewayPublic,
	)
	if err != nil {
		return activation.GatewayEvidenceResultV1{}, err
	}
	return verifiedResult.Gateway(), nil
}
