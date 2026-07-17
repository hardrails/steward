package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"time"

	"github.com/hardrails/steward/internal/activation"
	"github.com/hardrails/steward/internal/activationstore"
	"github.com/hardrails/steward/internal/agentrelease"
	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/evidence"
	"github.com/hardrails/steward/internal/ocibundle"
)

const activationVerificationSchemaV1 = "steward.activation-verification.v1"

type activationVerificationOutput struct {
	SchemaVersion string `json:"schema_version"`
	Valid         bool   `json:"valid"`
	Verified      bool   `json:"verified"`
	ProofDigest   string `json:"proof_digest"`
}

// verifyActivation performs a complete offline verification. It intentionally
// has no client, socket, Docker, or network configuration surface.
func verifyActivation(arguments []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("activation verify", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	directoryFlag := flags.String("dir", "", "owner-only completed activation workspace")
	publisherPublicPath := flags.String("publisher-public-key", "", "pinned publisher public key")
	publisherKeyID := flags.String("publisher-key-id", "", "publisher DSSE key ID")
	siteRootPublicPath := flags.String("site-root-public-key", "", "pinned site-root public key")
	siteRootKeyID := flags.String("site-root-key-id", "", "site-root DSSE key ID")
	witnessPublicPath := flags.String("witness-public-key", "", "pinned controller witness public key")
	gatewayReceiptPublicPath := flags.String(
		"gateway-receipt-public-key", "", "pinned Gateway receipt public key",
	)
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *directoryFlag == "" || *gatewayReceiptPublicPath == "" || flags.NArg() != 0 {
		return errors.New("activation verify requires -dir, publisher and site-root trust keys, -witness-public-key, -gateway-receipt-public-key, and no positional arguments")
	}
	trust, err := loadActivationTrust(
		*publisherKeyID, *publisherPublicPath,
		*siteRootKeyID, *siteRootPublicPath,
		*witnessPublicPath, true,
	)
	if err != nil {
		return err
	}
	gatewayReceiptPublic, err := readPublicKey(*gatewayReceiptPublicPath)
	if err != nil {
		return fmt.Errorf("read Gateway receipt public key: %w", err)
	}
	directory, err := filepath.Abs(*directoryFlag)
	if err != nil {
		return fmt.Errorf("resolve activation workspace path: %w", err)
	}
	store, err := activationstore.Open(directory)
	if err != nil {
		return err
	}
	defer store.Close()

	proofRaw, err := store.Read(activationstore.ProofFileName, activation.MaxProofBytes)
	if err != nil {
		return fmt.Errorf("read activation proof: %w", err)
	}
	proof, err := activation.ParseProofV1(proofRaw)
	if err != nil {
		return err
	}
	completedAt, err := canonicalActivationTime(proof.CompletedAt)
	if err != nil {
		return err
	}
	_, preliminaryChain, err := loadUnverifiedActivationStateChain(store)
	if err != nil {
		return err
	}
	inputVerificationTime, err := activationInputVerificationTime(
		preliminaryChain, completedAt,
	)
	if err != nil {
		return err
	}
	inputs, err := loadVerifiedActivationInputs(
		store, trust, inputVerificationTime,
	)
	if err != nil {
		return err
	}
	chain, err := loadActivationStateChain(store, inputs)
	if err != nil {
		return err
	}
	if !activationStateChainsEqual(preliminaryChain, chain) {
		return errors.New("activation state changed between bootstrap and verified loading")
	}
	if chain.latest().Phase != activation.PhasePassed {
		return errors.New("activation state is not passed")
	}
	correlated, err := activation.CorrelateProofV1(
		inputs.planRaw, chain.latestRaw(), proofRaw,
	)
	if err != nil {
		return err
	}
	if correlated != proof {
		return errors.New("activation proof changed during correlation")
	}
	if err := verifyActivationArchive(inputs); err != nil {
		return err
	}

	baselineRaw, err := store.Read(
		activationstore.ExecutorBaselineWitnessFileName,
		controlprotocol.MaxExecutorEvidenceJSONBytes,
	)
	if err != nil {
		return fmt.Errorf("read baseline controller witness: %w", err)
	}
	baseline, err := validateBaselineWitness(
		baselineRaw, trust.witness, inputs.intent.NodeID,
	)
	if err != nil {
		return err
	}
	executorReceiptPublic, err := controlprotocol.VerifyExecutorEvidenceIdentityProofV1(
		baseline.Statement.IdentityProof,
	)
	if err != nil {
		return fmt.Errorf("verify activation Executor receipt identity: %w", err)
	}
	admissionRaw, err := store.Read(activationstore.AdmissionFileName, maxArtifactBytes)
	if err != nil {
		return fmt.Errorf("read activation admission: %w", err)
	}
	admitted, err := parseActivationAdmission(
		admissionRaw, inputs, evidence.KeyID(executorReceiptPublic), false,
	)
	if err != nil {
		return err
	}
	if admitted.RuntimeRef != chain.latest().RuntimeRef {
		return errors.New("activation admission runtime does not match the final state")
	}
	serviceTrustRaw, err := store.Read(
		activationstore.ServiceTrustFileName, maxServiceTrustBytes,
	)
	if err != nil {
		return fmt.Errorf("read activation service trust: %w", err)
	}
	requestRaw, err := store.Read(
		activationstore.CanaryRequestFileName, agentrelease.MaxCanaryRequestBytes,
	)
	if err != nil {
		return fmt.Errorf("read activation canary request: %w", err)
	}
	challengeRaw, err := store.Read(
		activationstore.CanaryChallengeFileName, activation.MaxChallengeBytes,
	)
	if err != nil {
		return fmt.Errorf("read activation canary challenge: %w", err)
	}
	challenge, err := activation.ParseChallengeV1(challengeRaw)
	if err != nil {
		return err
	}
	if err := verifyActivationChallenge(
		challenge, admissionRaw, serviceTrustRaw, requestRaw,
		admitted, inputs, chain, proof,
	); err != nil {
		return err
	}

	taskRaw, err := store.Read(activationstore.CanaryTaskFileName, maxTaskBundleBytes)
	if err != nil {
		return fmt.Errorf("read activation canary task: %w", err)
	}
	task, err := verifyActivationTask(
		taskRaw, challenge, admitted, inputs, serviceTrustRaw, requestRaw,
	)
	if err != nil {
		return err
	}
	submit, err := readActivationSubmit(store, task)
	if err != nil {
		return fmt.Errorf("read activation submit record: %w", err)
	}
	submitReceiptPublic, err := activationSubmitReceiptPublicKey(submit)
	if err != nil {
		return err
	}
	if submit.ReceiptEpoch != proof.GatewayEvidence.ReceiptEpoch ||
		!bytes.Equal(submitReceiptPublic, gatewayReceiptPublic) ||
		controlprotocol.ExecutorEvidencePublicKeySHA256(submitReceiptPublic) !=
			proof.GatewayEvidence.PublicKeySHA256 {
		return errors.New("activation submit receipt identity does not match the external trust key and proof")
	}
	resultRaw, err := store.Read(
		activationstore.CanaryResultFileName, activation.MaxCanaryResultBytes,
	)
	if err != nil {
		return fmt.Errorf("read activation canary result: %w", err)
	}
	canary, err := verifyActivationCanaryResult(inputs, resultRaw)
	if err != nil {
		return err
	}
	if canary.RunID != submit.RunID ||
		canary.ManifestDigest !=
			inputs.release.Release.Canary.ExpectedWorkspaceManifestDigest {
		return errors.New("agent result does not match the dispatched run and signed release qualification")
	}

	gatewayEvidence, err := verifyStoredActivationGatewayEvidence(
		context.Background(), store, task, submit, resultRaw,
	)
	if err != nil {
		return err
	}
	if gatewayEvidence.Coordinate != proof.GatewayEvidence ||
		gatewayEvidence.Canary != proof.Canary {
		return errors.New("verified Gateway evidence and canary identities do not match the activation proof")
	}
	if err := verifyActivationTaskAt(
		task, gatewayEvidence.AuthorizedAt,
	); err != nil {
		return err
	}
	if err := verifyActivationInputsAtSignedTime(
		store, trust, inputs, gatewayEvidence.AuthorizedAt,
	); err != nil {
		return err
	}
	beginDigest, err := verifyStoredActivationExecutorBegin(
		store, inputs, proof.Binding, admitted,
	)
	if err != nil {
		return err
	}
	if beginDigest != proof.ExecutorBeginDigest {
		return errors.New("verified Executor activation begin marker does not match the activation proof")
	}
	checkpointDigest, err := verifyStoredActivationExecutorCheckpoint(
		store, inputs, proof.Binding, admitted, gatewayEvidence,
	)
	if err != nil {
		return err
	}
	if checkpointDigest != proof.ExecutorCheckpointDigest {
		return errors.New("verified Executor activation checkpoint does not match the activation proof")
	}
	executorEvidence, err := verifyStoredActivationExecutorEvidence(
		context.Background(), store, inputs, proof.Binding, admitted,
		beginDigest, checkpointDigest, trust.witness,
	)
	if err != nil {
		return err
	}
	if executorEvidence.Coordinate != proof.ExecutorEvidence ||
		executorEvidence.Witness != proof.Witness {
		return errors.New("verified Executor evidence coordinates do not match the activation proof")
	}

	proofDigest, err := activation.ProofDigestV1(proofRaw)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(activationVerificationOutput{
		SchemaVersion: activationVerificationSchemaV1,
		Valid:         true,
		Verified:      true,
		ProofDigest:   proofDigest,
	})
}

func verifyActivationArchive(inputs verifiedActivationInputs) error {
	releaseArchive := inputs.release.Release.Archive
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
		inputs.archivePath,
		expected,
		ocibundle.ArchiveIdentity{
			Digest: releaseArchive.SHA256Digest,
			Bytes:  releaseArchive.SizeBytes,
		},
		ocibundle.DefaultLimits(),
	)
	if err != nil {
		return fmt.Errorf("verify activation archive: %w", err)
	}
	if err := prepared.Close(); err != nil {
		return fmt.Errorf("close verified activation archive: %w", err)
	}
	return nil
}

func verifyActivationChallenge(
	challenge activation.CanaryChallengeV1,
	admissionRaw, serviceTrustRaw, requestRaw []byte,
	admitted permitAdmission,
	inputs verifiedActivationInputs,
	chain activationStateChain,
	proof activation.ProofV1,
) error {
	contract, err := activationCanaryContract(inputs)
	if err != nil {
		return err
	}
	planDigest, err := activation.PlanDigestV1(inputs.planRaw)
	if err != nil {
		return err
	}
	pins, err := activationTaskAuthorities(admitted)
	if err != nil {
		return err
	}
	if challenge.ActivationID != inputs.plan.ActivationID ||
		challenge.PlanDigest != planDigest ||
		challenge.ReleaseDigest != inputs.release.EnvelopeDigest ||
		challenge.AdmissionDigest != dsse.Digest(admissionRaw) ||
		challenge.IntentDigest != dsse.Digest(inputs.intentRaw) ||
		challenge.ServiceTrustDigest != dsse.Digest(serviceTrustRaw) ||
		challenge.RequestDigest != dsse.Digest(requestRaw) ||
		challenge.TenantID != inputs.intent.TenantID ||
		challenge.NodeID != inputs.intent.NodeID ||
		challenge.InstanceID != inputs.intent.InstanceID ||
		challenge.RuntimeRef != admitted.RuntimeRef ||
		challenge.RuntimeRef != chain.latest().RuntimeRef ||
		challenge.Generation != inputs.intent.Generation ||
		challenge.GrantID != admitted.GrantID ||
		challenge.ServiceID != contract.ServiceID ||
		challenge.OperationID != contract.OperationID ||
		!slicesEqualTaskPins(challenge.TaskAuthorities, pins) {
		return errors.New("activation canary challenge does not match every retained activation binding")
	}
	createdAt, err := canonicalActivationTime(challenge.CreatedAt)
	if err != nil || createdAt.After(timeMustParseActivation(proof.CompletedAt)) {
		return errors.New("activation canary challenge has an invalid completion ordering")
	}
	return nil
}

func slicesEqualTaskPins(
	left, right []activation.TaskAuthorityPinV1,
) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func canonicalActivationTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.IsZero() ||
		parsed.UTC().Format(time.RFC3339Nano) != value {
		return time.Time{}, errors.New("activation time must be canonical UTC RFC3339Nano")
	}
	return parsed, nil
}

func timeMustParseActivation(value string) time.Time {
	parsed, _ := time.Parse(time.RFC3339Nano, value)
	return parsed
}
