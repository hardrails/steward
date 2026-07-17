package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/hardrails/steward/internal/activation"
	"github.com/hardrails/steward/internal/activationcanary"
	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/agentrelease"
	"github.com/hardrails/steward/internal/controlcapture"
	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/evidence"
	"github.com/hardrails/steward/internal/ocibundle"
	"github.com/hardrails/steward/internal/rollout"
	"github.com/hardrails/steward/internal/rolloutdriver"
	"github.com/hardrails/steward/internal/rolloutstore"
	"github.com/hardrails/steward/internal/taskpermit"
)

const rolloutVerificationSchemaV1 = "steward.rollout-verification.v1"

type rolloutVerificationOutput struct {
	SchemaVersion           string `json:"schema_version"`
	Valid                   bool   `json:"valid"`
	Verified                bool   `json:"verified"`
	RolloutID               string `json:"rollout_id"`
	VerifiedTargets         int    `json:"verified_targets"`
	PlanAuthorizationDigest string `json:"plan_authorization_digest"`
	VerifiedBatchPromotions int    `json:"verified_batch_promotions"`
	ProofDigest             string `json:"proof_digest"`
}

type rolloutVerifiedTargetArtifacts struct {
	admitCommandRaw   []byte
	startCommandRaw   []byte
	canaryCommandRaw  []byte
	stateRaw          []byte
	activationPlanRaw []byte
	activationState   []byte
	activationProof   []byte
}

// verifyRollout performs a complete historical verification from local,
// bounded artifacts. It deliberately exposes no controller, node, Gateway,
// Docker, socket, token, or other network/client flag.
func verifyRollout(arguments []string, stdout io.Writer) (resultErr error) {
	flags := flag.NewFlagSet("rollout verify", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	directoryFlag := flags.String("dir", "", "owner-only completed rollout workspace")
	archiveFlag := flags.String("archive", "", "exact offline OCI archive named by the release")
	publisherPublicPath := flags.String("publisher-public-key", "", "pinned publisher public key")
	publisherKeyID := flags.String("publisher-key-id", "", "publisher DSSE key ID")
	siteRootPublicPath := flags.String("site-root-public-key", "", "pinned site-root public key")
	siteRootKeyID := flags.String("site-root-key-id", "", "site-root DSSE key ID")
	witnessPublicPath := flags.String("witness-public-key", "", "pinned controller witness public key")
	jsonOutput := flags.Bool("json", false, "emit stable machine-readable verification")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *directoryFlag == "" || *archiveFlag == "" ||
		*publisherPublicPath == "" || *publisherKeyID == "" ||
		*siteRootPublicPath == "" || *siteRootKeyID == "" ||
		*witnessPublicPath == "" || flags.NArg() != 0 {
		return errors.New("rollout verify requires -dir, -archive, publisher/site-root/witness trust, and no positional arguments")
	}
	trust, err := loadActivationTrust(
		*publisherKeyID, *publisherPublicPath,
		*siteRootKeyID, *siteRootPublicPath,
		*witnessPublicPath, true,
	)
	if err != nil {
		return err
	}
	directory, err := filepath.Abs(*directoryFlag)
	if err != nil {
		return fmt.Errorf("resolve rollout workspace path: %w", err)
	}
	archivePath, err := filepath.Abs(*archiveFlag)
	if err != nil {
		return fmt.Errorf("resolve rollout archive path: %w", err)
	}
	store, err := rolloutstore.Open(directory)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, store.Close()) }()

	run, err := loadVerifiedRolloutRun(
		store,
		trust.publisherKeyID, trust.publisher,
		trust.siteRootKeyID, trust.siteRoot,
		trust.witness,
	)
	if err != nil {
		return err
	}
	if err := verifyRolloutArchive(archivePath, run, trust); err != nil {
		return err
	}
	artifacts, err := verifyRolloutTargets(store, run)
	if err != nil {
		return err
	}
	authorizationChain, err := verifyCompletedRolloutAuthorization(store, run)
	if err != nil {
		return fmt.Errorf("verify rollout authorization chain: %w", err)
	}

	proofRaw, err := store.Read(rolloutstore.ProofFileName, rollout.MaxProofManifestBytes)
	if err != nil {
		return fmt.Errorf("read rollout aggregate proof: %w", err)
	}
	proofManifest, err := rollout.ParseProofManifestV1(proofRaw)
	if err != nil {
		return fmt.Errorf("parse rollout aggregate proof: %w", err)
	}
	canonicalProof, err := rollout.MarshalProofManifestV1(proofManifest)
	if err != nil || !bytes.Equal(canonicalProof, proofRaw) {
		return errors.New("retained rollout aggregate proof is not canonical JSON")
	}
	targetStateRaws := make([][]byte, len(artifacts))
	admitCommandRaws := make([][]byte, len(artifacts))
	startCommandRaws := make([][]byte, len(artifacts))
	canaryCommandRaws := make([][]byte, len(artifacts))
	activationPlanRaws := make([][]byte, len(artifacts))
	activationStateRaws := make([][]byte, len(artifacts))
	activationProofRaws := make([][]byte, len(artifacts))
	for index := range artifacts {
		admitCommandRaws[index] = artifacts[index].admitCommandRaw
		startCommandRaws[index] = artifacts[index].startCommandRaw
		canaryCommandRaws[index] = artifacts[index].canaryCommandRaw
		targetStateRaws[index] = artifacts[index].stateRaw
		activationPlanRaws[index] = artifacts[index].activationPlanRaw
		activationStateRaws[index] = artifacts[index].activationState
		activationProofRaws[index] = artifacts[index].activationProof
	}
	if _, err := rollout.CorrelateProofManifestV1(
		run.planRaw,
		authorizationChain.planRawRecord,
		orderedRolloutPromotionRaws(authorizationChain),
		admitCommandRaws,
		startCommandRaws,
		canaryCommandRaws,
		targetStateRaws,
		activationPlanRaws,
		activationStateRaws,
		activationProofRaws,
		proofRaw,
	); err != nil {
		return fmt.Errorf("verify rollout aggregate proof: %w", err)
	}
	proofDigest, err := rollout.ProofManifestDigestV1(proofRaw)
	if err != nil {
		return err
	}
	if err := store.Close(); err != nil {
		return fmt.Errorf("close verified rollout workspace: %w", err)
	}
	output := rolloutVerificationOutput{
		SchemaVersion:           rolloutVerificationSchemaV1,
		Valid:                   true,
		Verified:                true,
		RolloutID:               run.plan.RolloutID,
		VerifiedTargets:         len(run.targets),
		PlanAuthorizationDigest: authorizationChain.plan.EnvelopeDigest,
		VerifiedBatchPromotions: len(authorizationChain.promotions),
		ProofDigest:             proofDigest,
	}
	if *jsonOutput {
		encoder := json.NewEncoder(stdout)
		encoder.SetEscapeHTML(false)
		return encoder.Encode(output)
	}
	_, err = fmt.Fprintf(
		stdout,
		"Rollout %s verified: %d targets, %d signed batch promotions, proof %s\n",
		output.RolloutID,
		output.VerifiedTargets,
		output.VerifiedBatchPromotions,
		output.ProofDigest,
	)
	return err
}

func verifyRolloutArchive(
	archivePath string,
	run verifiedRolloutRun,
	trust activationTrust,
) error {
	createdAt, err := canonicalActivationTime(run.plan.CreatedAt)
	if err != nil {
		return fmt.Errorf("parse rollout creation time: %w", err)
	}
	release, err := agentrelease.Verify(
		run.releaseRaw,
		map[string]ed25519.PublicKey{trust.publisherKeyID: trust.publisher},
		createdAt,
	)
	if err != nil {
		return fmt.Errorf("authenticate rollout release for archive verification: %w", err)
	}
	releaseArchive := release.Release.Archive
	if run.plan.Archive.Digest != releaseArchive.SHA256Digest ||
		run.plan.Archive.Bytes != releaseArchive.SizeBytes {
		return errors.New("rollout plan archive identity differs from the authenticated release")
	}
	expected := ocibundle.Identity{
		ManifestDigest: releaseArchive.Image.ManifestDigest,
		ConfigDigest:   releaseArchive.Image.ConfigDigest,
		Platform: ocibundle.Platform{
			OS:           releaseArchive.Image.Platform.OS,
			Architecture: releaseArchive.Image.Platform.Architecture,
			Variant:      releaseArchive.Image.Platform.Variant,
		},
	}
	prepared, err := ocibundle.PrepareBound(
		archivePath,
		expected,
		ocibundle.ArchiveIdentity{
			Digest: releaseArchive.SHA256Digest,
			Bytes:  releaseArchive.SizeBytes,
		},
		ocibundle.DefaultLimits(),
	)
	if err != nil {
		return fmt.Errorf("verify rollout archive: %w", err)
	}
	if err := prepared.Close(); err != nil {
		return fmt.Errorf("close verified rollout archive: %w", err)
	}
	return nil
}

func verifyRolloutTargets(
	store *rolloutstore.Store,
	run verifiedRolloutRun,
) ([]rolloutVerifiedTargetArtifacts, error) {
	if len(run.states) != len(run.targets) || len(run.states) != len(run.plan.Targets) {
		return nil, errors.New("rollout does not contain one final state per target")
	}
	for index, state := range run.states {
		if state.Phase != rollout.PhasePassed {
			return nil, fmt.Errorf("rollout target %d is incomplete", index)
		}
	}
	if err := rollout.ValidateFleetProgressV1(run.planRaw, run.states); err != nil {
		return nil, fmt.Errorf("verify complete fleet progress: %w", err)
	}
	if err := verifyCanonicalRolloutStateChains(store, run); err != nil {
		return nil, err
	}

	artifacts := make([]rolloutVerifiedTargetArtifacts, len(run.targets))
	for index := range run.targets {
		verified, err := verifyRolloutTarget(store, run, index)
		if err != nil {
			return nil, fmt.Errorf("verify rollout target %d: %w", index, err)
		}
		artifacts[index] = verified
	}
	return artifacts, nil
}

func verifyRolloutTarget(
	store *rolloutstore.Store,
	run verifiedRolloutRun,
	index int,
) (rolloutVerifiedTargetArtifacts, error) {
	targetIndex := uint16(index)
	target := run.plan.Targets[index]
	prepared := run.targets[index].prepared
	state := run.states[index]
	if run.stateCounts[index] == 0 {
		return rolloutVerifiedTargetArtifacts{}, errors.New("target state chain is empty")
	}
	stateName, err := rolloutstore.TargetStateName(targetIndex, run.stateCounts[index]-1)
	if err != nil {
		return rolloutVerifiedTargetArtifacts{}, err
	}
	stateRaw, err := store.Read(stateName, rollout.MaxTargetStateBytes)
	if err != nil {
		return rolloutVerifiedTargetArtifacts{}, fmt.Errorf("read final target state: %w", err)
	}
	parsedState, err := rollout.ParseTargetStateV1(stateRaw)
	if err != nil || parsedState != state {
		return rolloutVerifiedTargetArtifacts{}, errors.New("final target state changed after state-chain verification")
	}

	admitRaw, err := readRolloutTargetArtifact(
		store, targetIndex, rolloutstore.TargetAdmitCommandKind, dsse.DefaultMaxEnvelopeBytes,
	)
	if err != nil {
		return rolloutVerifiedTargetArtifacts{}, err
	}
	admit, err := verifyRolloutCommand(
		admitRaw,
		prepared,
		run.verified.SitePolicy,
		"admit",
		target.AdmitCommandID,
		1,
		prepared.AdmissionPayloadRaw(),
		run.verified.Capsule.ExpiresAt,
	)
	if err != nil {
		return rolloutVerifiedTargetArtifacts{}, err
	}

	admissionRaw, err := readRolloutTargetArtifact(
		store, targetIndex, rolloutstore.TargetAdmissionKind, controlprotocol.MaxExecutorReportBytes,
	)
	if err != nil {
		return rolloutVerifiedTargetArtifacts{}, err
	}
	var projection controlprotocol.ExecutorAdmissionProjectionV1
	if err := dsse.DecodeStrictInto(
		admissionRaw, controlprotocol.MaxExecutorReportBytes, &projection,
	); err != nil {
		return rolloutVerifiedTargetArtifacts{}, fmt.Errorf("decode retained admission: %w", err)
	}
	canonicalAdmission, err := json.Marshal(projection)
	if err != nil || !bytes.Equal(canonicalAdmission, admissionRaw) {
		return rolloutVerifiedTargetArtifacts{}, errors.New("retained admission is not canonical JSON")
	}
	if err := rolloutdriver.VerifyAdmissionV1(prepared, projection); err != nil {
		return rolloutVerifiedTargetArtifacts{}, fmt.Errorf("verify retained admission: %w", err)
	}
	if state.RuntimeRef != projection.RuntimeRef ||
		state.AdmissionDigest != dsse.Digest(admissionRaw) {
		return rolloutVerifiedTargetArtifacts{}, errors.New("target state does not identify the exact admission")
	}

	startRaw, err := readRolloutTargetArtifact(
		store, targetIndex, rolloutstore.TargetStartCommandKind, dsse.DefaultMaxEnvelopeBytes,
	)
	if err != nil {
		return rolloutVerifiedTargetArtifacts{}, err
	}
	start, err := verifyRolloutCommand(
		startRaw,
		prepared,
		run.verified.SitePolicy,
		"start",
		target.StartCommandID,
		2,
		[]byte(`{}`),
		run.verified.Capsule.ExpiresAt,
	)
	if err != nil {
		return rolloutVerifiedTargetArtifacts{}, err
	}

	canaryOuterRaw, err := readRolloutTargetArtifact(
		store, targetIndex, rolloutstore.TargetCanaryCommandKind, dsse.DefaultMaxEnvelopeBytes,
	)
	if err != nil {
		return rolloutVerifiedTargetArtifacts{}, err
	}
	canaryOuter, err := verifyRolloutCommand(
		canaryOuterRaw,
		prepared,
		run.verified.SitePolicy,
		"activation-canary",
		target.CanaryCommandID,
		3,
		nil,
		run.verified.Capsule.ExpiresAt,
	)
	if err != nil {
		return rolloutVerifiedTargetArtifacts{}, err
	}
	if err := verifyRolloutCommandOrder(admit, start, canaryOuter); err != nil {
		return rolloutVerifiedTargetArtifacts{}, err
	}
	resultRaw, err := readRolloutTargetArtifact(
		store,
		targetIndex,
		rolloutstore.TargetCanaryResultKind,
		controlprotocol.MaxExecutorActivationCanaryResultBytes,
	)
	if err != nil {
		return rolloutVerifiedTargetArtifacts{}, err
	}
	verifiedCanary, err := rolloutdriver.VerifyCanaryV1(rolloutdriver.VerifyCanaryInputV1{
		Prepared:         prepared,
		Admission:        projection,
		CommandRaw:       append([]byte(nil), canaryOuter.Payload...),
		ResultRaw:        resultRaw,
		ReceiptPublicKey: run.targets[index].gatewayPublic,
	})
	if err != nil {
		return rolloutVerifiedTargetArtifacts{}, fmt.Errorf("verify exact retained canary: %w", err)
	}
	commandContext := activationcanary.AdmissionContextV1{
		NodeID: target.NodeID, TenantID: run.plan.TenantID,
		InstanceID: target.InstanceID, Projection: projection,
	}
	verifiedCommand, err := activationcanary.VerifyHistoricalCommandV1(
		canaryOuter.Payload, commandContext, taskpermit.MaxValidity,
	)
	if err != nil {
		return rolloutVerifiedTargetArtifacts{}, fmt.Errorf("recover verified canary evidence: %w", err)
	}
	verifiedResult, err := activationcanary.VerifyResultV1(
		verifiedCommand, resultRaw, run.targets[index].gatewayPublic,
	)
	if err != nil {
		return rolloutVerifiedTargetArtifacts{}, fmt.Errorf("recover verified Gateway evidence: %w", err)
	}
	terminalResult := verifiedResult.TerminalResult()
	if state.CanaryResultDigest != dsse.Digest(terminalResult) ||
		state.CanaryResultBytes != int64(len(terminalResult)) {
		return rolloutVerifiedTargetArtifacts{}, errors.New("target state does not identify the exact verified Hermes terminal result")
	}

	captureRaw, err := readRolloutTargetArtifact(
		store,
		targetIndex,
		rolloutstore.TargetCaptureExportKind,
		controlprotocol.MaxControllerEvidenceCaptureJSONBytes,
	)
	if err != nil {
		return rolloutVerifiedTargetArtifacts{}, err
	}
	capture, err := controlprotocol.DecodeControllerEvidenceCaptureV1(captureRaw)
	if err != nil {
		return rolloutVerifiedTargetArtifacts{}, fmt.Errorf("decode retained controller capture: %w", err)
	}
	canonicalCapture, err := json.Marshal(capture)
	if err != nil || !bytes.Equal(canonicalCapture, captureRaw) {
		return rolloutVerifiedTargetArtifacts{}, errors.New("retained controller capture is not canonical JSON")
	}
	verifiedCapture, err := controlcapture.VerifyJSONV1(captureRaw, run.witnessPublic)
	if err != nil {
		return rolloutVerifiedTargetArtifacts{}, fmt.Errorf("verify retained controller capture: %w", err)
	}

	activationStateRaw, err := readRolloutTargetArtifact(
		store, targetIndex, rolloutstore.TargetActivationStateKind, activation.MaxStateBytes,
	)
	if err != nil {
		return rolloutVerifiedTargetArtifacts{}, err
	}
	activationState, err := activation.ParseStateV1(activationStateRaw)
	if err != nil {
		return rolloutVerifiedTargetArtifacts{}, fmt.Errorf("parse retained activation state: %w", err)
	}
	canonicalActivationState, err := activation.MarshalStateV1(activationState)
	if err != nil || !bytes.Equal(canonicalActivationState, activationStateRaw) ||
		activationState.Phase != activation.PhasePassed ||
		activationState.Binding != prepared.Binding() ||
		activationState.RuntimeRef != projection.RuntimeRef {
		return rolloutVerifiedTargetArtifacts{}, errors.New("retained activation state is not the exact passed target state")
	}

	activationProofRaw, err := readRolloutTargetArtifact(
		store, targetIndex, rolloutstore.TargetActivationProofKind, activation.MaxProofBytes,
	)
	if err != nil {
		return rolloutVerifiedTargetArtifacts{}, err
	}
	activationProof, err := activation.CorrelateProofV1(
		prepared.ActivationPlanRaw(), activationStateRaw, activationProofRaw,
	)
	if err != nil {
		return rolloutVerifiedTargetArtifacts{}, fmt.Errorf("correlate retained activation proof: %w", err)
	}
	canonicalActivationProof, err := activation.MarshalProofV1(activationProof)
	if err != nil || !bytes.Equal(canonicalActivationProof, activationProofRaw) {
		return rolloutVerifiedTargetArtifacts{}, errors.New("retained activation proof is not canonical JSON")
	}
	checkpointDigest, err := activation.ExecutorCheckpointDigestV1(
		verifiedCanary.CheckpointRaw(),
	)
	if err != nil {
		return rolloutVerifiedTargetArtifacts{}, err
	}
	if activationProof.ExecutorBeginDigest != prepared.ExecutorBeginDigest() ||
		activationProof.ExecutorCheckpointDigest != checkpointDigest ||
		activationProof.GatewayEvidence != verifiedResult.Gateway().Coordinate ||
		activationProof.Canary != verifiedResult.Gateway().Canary {
		return rolloutVerifiedTargetArtifacts{}, errors.New("activation proof does not match the verified canary and Gateway evidence")
	}
	if err := correlateVerifiedRolloutCapture(
		captureRaw,
		verifiedCapture,
		prepared,
		projection,
		activationProof,
		checkpointDigest,
		run.witnessPublic,
	); err != nil {
		return rolloutVerifiedTargetArtifacts{}, err
	}

	return rolloutVerifiedTargetArtifacts{
		admitCommandRaw:   admitRaw,
		startCommandRaw:   startRaw,
		canaryCommandRaw:  canaryOuterRaw,
		stateRaw:          stateRaw,
		activationPlanRaw: prepared.ActivationPlanRaw(),
		activationState:   activationStateRaw,
		activationProof:   activationProofRaw,
	}, nil
}

func verifyRolloutCommand(
	raw []byte,
	prepared rolloutdriver.PreparedTargetV1,
	policy admission.SitePolicy,
	kind string,
	commandID string,
	sequence uint64,
	expectedPayload []byte,
	capsuleExpiresAt string,
) (admission.CommandStatement, error) {
	plan := prepared.Plan()
	target := prepared.Target()
	trusted, err := policy.TrustedCommandKeys(plan.TenantID, kind)
	if err != nil || len(trusted) == 0 {
		return admission.CommandStatement{}, fmt.Errorf("load %s command trust: %w", kind, err)
	}
	payload, verifiedKeyID, err := dsse.Verify(raw, admission.CommandPayloadType, trusted)
	if err != nil {
		return admission.CommandStatement{}, fmt.Errorf("authenticate retained %s command: %w", kind, err)
	}
	envelope, err := dsse.Parse(raw)
	if err != nil {
		return admission.CommandStatement{}, err
	}
	if len(envelope.Signatures) != 1 || envelope.Signatures[0].KeyID != verifiedKeyID {
		return admission.CommandStatement{}, fmt.Errorf("retained %s command must contain exactly one trusted signature", kind)
	}
	canonicalEnvelope, err := dsse.Marshal(envelope)
	if err != nil || !bytes.Equal(canonicalEnvelope, raw) {
		return admission.CommandStatement{}, fmt.Errorf("retained %s command envelope is not canonical", kind)
	}
	var statement admission.CommandStatement
	if err := dsse.DecodeStrictInto(payload, dsse.MaxPayloadBytes, &statement); err != nil {
		return admission.CommandStatement{}, fmt.Errorf("decode retained %s command: %w", kind, err)
	}
	canonicalStatement, err := json.Marshal(statement)
	if err != nil || !bytes.Equal(canonicalStatement, payload) {
		return admission.CommandStatement{}, fmt.Errorf("retained %s command statement is not canonical", kind)
	}
	if err := statement.Validate(time.Time{}); err != nil {
		return admission.CommandStatement{}, fmt.Errorf("validate retained %s command: %w", kind, err)
	}
	if statement.CommandID != commandID ||
		statement.TenantID != plan.TenantID ||
		statement.NodeID != target.NodeID ||
		statement.InstanceID != target.InstanceID ||
		statement.RuntimeRef != prepared.OuterRuntimeRef() ||
		statement.Kind != kind ||
		statement.ClaimGeneration != target.ClaimGeneration ||
		statement.InstanceGeneration != target.InstanceGeneration ||
		statement.CommandSequence != sequence {
		return admission.CommandStatement{}, fmt.Errorf("retained %s command does not match the prepared rollout target", kind)
	}
	if expectedPayload != nil && !bytes.Equal(statement.Payload, expectedPayload) {
		return admission.CommandStatement{}, fmt.Errorf("retained %s command changed its closed payload", kind)
	}
	issuedAt, err := canonicalActivationTime(statement.IssuedAt)
	if err != nil {
		return admission.CommandStatement{}, fmt.Errorf("retained %s command issue time: %w", kind, err)
	}
	expiresAt, err := canonicalActivationTime(statement.ExpiresAt)
	if err != nil {
		return admission.CommandStatement{}, fmt.Errorf("retained %s command expiry: %w", kind, err)
	}
	createdAt, _ := canonicalActivationTime(plan.CreatedAt)
	deadline, _ := canonicalActivationTime(plan.Deadline)
	if issuedAt.Before(createdAt) || !expiresAt.After(issuedAt) || expiresAt.After(deadline) {
		return admission.CommandStatement{}, fmt.Errorf("retained %s command is outside the rollout interval", kind)
	}
	if capsuleExpiresAt != "" {
		capsuleExpiry, parseErr := time.Parse(time.RFC3339, capsuleExpiresAt)
		if parseErr != nil || expiresAt.After(capsuleExpiry.UTC()) {
			return admission.CommandStatement{}, fmt.Errorf("retained %s command exceeds the authenticated capsule expiry", kind)
		}
	}
	return statement, nil
}

func rejectExtraRolloutTargetArtifacts(
	store *rolloutstore.Store,
	targetCount int,
) error {
	kinds := [...]string{
		rolloutstore.TargetIntentKind,
		rolloutstore.TargetServiceTrustKind,
		rolloutstore.TargetActivationPlanKind,
		rolloutstore.TargetExecutorBeginKind,
		rolloutstore.TargetAdmitCommandKind,
		rolloutstore.TargetAdmissionKind,
		rolloutstore.TargetStartCommandKind,
		rolloutstore.TargetCanaryCommandKind,
		rolloutstore.TargetCanaryResultKind,
		rolloutstore.TargetCaptureExportKind,
		rolloutstore.TargetActivationStateKind,
		rolloutstore.TargetActivationProofKind,
		rolloutstore.TargetGatewayReceiptPublicKeyKind,
	}
	for index := targetCount; index < rolloutstore.MaxTargets; index++ {
		for _, kind := range kinds {
			name, err := rolloutstore.TargetArtifactName(uint16(index), kind)
			if err != nil {
				return err
			}
			if _, err := store.Read(name, rolloutstore.MaxArtifactBytes); err == nil {
				return fmt.Errorf("rollout contains artifact %q for a target outside the plan", name)
			} else if !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
	}
	return nil
}

func verifyRolloutCommandOrder(commands ...admission.CommandStatement) error {
	var previous time.Time
	for index, command := range commands {
		issued, err := canonicalActivationTime(command.IssuedAt)
		if err != nil {
			return err
		}
		if index > 0 && issued.Before(previous) {
			return errors.New("retained rollout commands are not issued in sequence order")
		}
		previous = issued
	}
	return nil
}

func correlateVerifiedRolloutCapture(
	captureRaw []byte,
	capture controlcapture.ResultV1,
	prepared rolloutdriver.PreparedTargetV1,
	projection controlprotocol.ExecutorAdmissionProjectionV1,
	proof activation.ProofV1,
	checkpointDigest string,
	witnessPublic ed25519.PublicKey,
) error {
	statement := capture.Statement
	plan := prepared.Plan()
	target := prepared.Target()
	if statement.CaptureID != rolloutCaptureID(plan, prepared.TargetIndex()) ||
		statement.NodeID != target.NodeID ||
		statement.TenantID != plan.TenantID ||
		statement.RuntimeRef != projection.RuntimeRef ||
		statement.Generation != target.InstanceGeneration ||
		statement.ActivationID != target.ActivationID ||
		statement.CanaryCommandID != target.CanaryCommandID ||
		statement.ActivationBeginDigest != prepared.ExecutorBeginDigest() ||
		statement.ActivationCheckpointDigest != checkpointDigest ||
		statement.CapsuleDigest != projection.CapsuleDigest ||
		statement.PolicyDigest != projection.PolicyDigest {
		return errors.New("controller capture does not match the exact prepared target and canary checkpoint")
	}
	receiptPublic, err := controlprotocol.VerifyExecutorEvidenceIdentityProofV1(
		statement.IdentityProof,
	)
	if err != nil || projection.EvidenceKeyID != evidence.KeyID(receiptPublic) {
		return errors.New("controller capture receipt identity differs from the admitted Executor evidence key")
	}
	executorCoordinate := activation.ReceiptCoordinateV1{
		ReceiptNodeID:   statement.FinalHead.ReceiptNodeID,
		ReceiptEpoch:    statement.FinalHead.ReceiptEpoch,
		Sequence:        statement.FinalHead.Sequence,
		ChainHash:       statement.FinalHead.ChainHash,
		PublicKeySHA256: statement.FinalHead.PublicKeySHA256,
	}
	if proof.ExecutorEvidence != executorCoordinate {
		return errors.New("activation proof Executor coordinate differs from the verified controller capture")
	}
	expectedWitness := activation.WitnessCoordinateV1{
		ControllerInstanceID:   statement.ControllerInstanceID,
		ControlNodeID:          statement.NodeID,
		ReceiptNodeID:          statement.FinalHead.ReceiptNodeID,
		ReceiptEpoch:           statement.FinalHead.ReceiptEpoch,
		Sequence:               statement.FinalHead.Sequence,
		ChainHash:              statement.FinalHead.ChainHash,
		ReceiptPublicKeySHA256: statement.FinalHead.PublicKeySHA256,
		WitnessPublicKeySHA256: controlprotocol.ExecutorEvidencePublicKeySHA256(witnessPublic),
		WitnessExportDigest:    dsse.Digest(captureRaw),
		WitnessedAt:            statement.ExportedAt,
	}
	if proof.Witness != expectedWitness {
		return errors.New("activation proof witness coordinate differs from the verified controller capture")
	}
	if capture.Begin.Receipt.Sequence != statement.ActivationBeginSequence ||
		capture.Checkpoint.Receipt.Sequence == 0 {
		return errors.New("verified controller capture marker coordinates are incomplete")
	}
	return nil
}

func verifyCanonicalRolloutStateChains(
	store *rolloutstore.Store,
	run verifiedRolloutRun,
) error {
	for index, count := range run.stateCounts {
		if count == 0 {
			return fmt.Errorf("rollout target %d state chain is empty", index)
		}
		for sequence := uint64(0); sequence < count; sequence++ {
			name, err := rolloutstore.TargetStateName(uint16(index), sequence)
			if err != nil {
				return err
			}
			raw, err := store.Read(name, rollout.MaxTargetStateBytes)
			if err != nil {
				return fmt.Errorf("read rollout target %d state %d: %w", index, sequence, err)
			}
			state, err := rollout.ParseTargetStateV1(raw)
			if err != nil {
				return fmt.Errorf("parse rollout target %d state %d: %w", index, sequence, err)
			}
			canonical, err := rollout.MarshalTargetStateV1(state)
			if err != nil || !bytes.Equal(canonical, raw) {
				return fmt.Errorf("rollout target %d state %d is not canonical JSON", index, sequence)
			}
		}
	}
	return nil
}
