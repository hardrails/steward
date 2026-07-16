package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
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
	"github.com/hardrails/steward/internal/securefile"
)

func createActivation(arguments []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("activation create", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	directoryFlag := flags.String("dir", "", "new owner-only activation workspace")
	activationIDFlag := flags.String("activation-id", "", "stable activation ID; generated when omitted")
	releasePath := flags.String("release", "", "publisher-signed agent release")
	policyPath := flags.String("policy", "", "site-root-signed policy")
	intentPath := flags.String("intent", "", "fresh-state Hermes instance intent")
	archiveFlag := flags.String("archive", "", "exact offline OCI archive")
	publisherPublicPath := flags.String("publisher-public-key", "", "pinned publisher public key")
	publisherKeyID := flags.String("publisher-key-id", "", "publisher DSSE key ID")
	siteRootPublicPath := flags.String("site-root-public-key", "", "pinned site-root public key")
	siteRootKeyID := flags.String("site-root-key-id", "", "site-root DSSE key ID")
	baselineWitnessPath := flags.String("baseline-witness", "", "signed controller evidence export captured before activation")
	witnessPublicPath := flags.String("witness-public-key", "", "pinned controller witness public key")
	preflightTimeout := flags.Duration("preflight-timeout", 30*time.Second, "preflight ceiling")
	importTimeout := flags.Duration("image-import-timeout", 30*time.Minute, "archive copy and Docker image import ceiling")
	admissionTimeout := flags.Duration("admission-timeout", time.Minute, "Executor admission ceiling")
	startupTimeout := flags.Duration("startup-timeout", 2*time.Minute, "runtime startup ceiling")
	canaryTimeout := flags.Duration("canary-timeout", 5*time.Minute, "Hermes canary ceiling")
	evidenceTimeout := flags.Duration("evidence-timeout", time.Minute, "evidence collection ceiling")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *directoryFlag == "" || *releasePath == "" || *policyPath == "" ||
		*intentPath == "" || *archiveFlag == "" ||
		*baselineWitnessPath == "" || flags.NArg() != 0 {
		return errors.New("activation create requires -dir, -release, -policy, -intent, -archive, -baseline-witness, trust keys, and no positional arguments")
	}
	trust, err := loadActivationTrust(
		*publisherKeyID, *publisherPublicPath,
		*siteRootKeyID, *siteRootPublicPath,
		*witnessPublicPath, true,
	)
	if err != nil {
		return err
	}
	timeouts, err := activationTimeouts(
		*preflightTimeout, *importTimeout, *admissionTimeout,
		*startupTimeout, *canaryTimeout, *evidenceTimeout,
	)
	if err != nil {
		return err
	}
	directory, err := filepath.Abs(*directoryFlag)
	if err != nil {
		return fmt.Errorf("resolve activation workspace path: %w", err)
	}
	archivePath, err := filepath.Abs(*archiveFlag)
	if err != nil {
		return fmt.Errorf("resolve activation archive path: %w", err)
	}
	activationID := *activationIDFlag
	if activationID == "" {
		activationID, err = randomActivationID()
		if err != nil {
			return err
		}
	}

	releaseRaw, err := securefile.Read(
		*releasePath, agentrelease.MaxEnvelopeBytes, securefile.TrustFile,
	)
	if err != nil {
		return fmt.Errorf("read activation release: %w", err)
	}
	release, err := agentrelease.Verify(
		releaseRaw,
		map[string]ed25519.PublicKey{trust.publisherKeyID: trust.publisher},
		timeNow().UTC(),
	)
	if err != nil {
		return fmt.Errorf("verify activation release: %w", err)
	}
	policyRaw, err := securefile.Read(*policyPath, maxArtifactBytes, securefile.TrustFile)
	if err != nil {
		return fmt.Errorf("read activation policy: %w", err)
	}
	intentRaw, err := securefile.Read(*intentPath, maxArtifactBytes, securefile.TrustFile)
	if err != nil {
		return fmt.Errorf("read activation intent: %w", err)
	}
	plan := activation.PlanV1{
		SchemaVersion: activation.PlanSchemaV1,
		ActivationID:  activationID,
		ReleaseDigest: release.EnvelopeDigest,
		PolicyDigest:  dsse.Digest(policyRaw),
		IntentDigest:  dsse.Digest(intentRaw),
		Archive: activation.ArchiveV1{
			Digest: release.Release.Archive.SHA256Digest,
			Bytes:  release.Release.Archive.SizeBytes,
		},
		Transport: activation.TransportNodeLocal,
		Canary:    activation.CanaryV1{Kind: release.Release.Canary.Kind},
		Timeouts:  timeouts,
	}
	planRaw, err := activation.MarshalPlanV1(plan)
	if err != nil {
		return err
	}
	inputs, err := verifyActivationInputBytes(
		planRaw, releaseRaw, policyRaw, intentRaw,
		archivePath, trust, timeNow().UTC(),
	)
	if err != nil {
		return err
	}
	baselineRaw, err := securefile.Read(
		*baselineWitnessPath,
		controlprotocol.MaxExecutorEvidenceJSONBytes,
		securefile.OwnerOnly,
	)
	if err != nil {
		return fmt.Errorf("read baseline controller witness: %w", err)
	}
	if _, err := validateBaselineWitness(baselineRaw, trust.witness, inputs.intent.NodeID); err != nil {
		return err
	}

	store, err := activationstore.Create(directory)
	if err != nil {
		return err
	}
	defer store.Close()
	for name, raw := range map[string][]byte{
		activationstore.ReleaseFileName: releaseRaw,
		activationstore.PolicyFileName:  policyRaw,
		activationstore.IntentFileName:  intentRaw,
	} {
		if err := store.Import(name, raw); err != nil {
			return fmt.Errorf("initialize activation artifact %q: %w", name, err)
		}
	}
	copyCtx, cancelCopy := context.WithTimeout(
		context.Background(),
		time.Duration(timeouts.ImageImportSeconds)*time.Second,
	)
	importErr := store.ImportArchiveContext(copyCtx, archivePath, inputs.plan.Archive)
	cancelCopy()
	if importErr != nil {
		return fmt.Errorf("initialize activation archive: %w", importErr)
	}
	storedArchivePath, err := store.Path(activationstore.ImageArchiveFileName)
	if err != nil {
		return fmt.Errorf("locate copied activation archive: %w", err)
	}
	inputs.archivePath = storedArchivePath
	archiveCtx, cancelArchive := context.WithTimeout(
		context.Background(),
		time.Duration(timeouts.PreflightSeconds)*time.Second,
	)
	preflightErr := preflightActivationArchive(archiveCtx, inputs)
	cancelArchive()
	if preflightErr != nil {
		return fmt.Errorf("verify copied activation archive: %w", preflightErr)
	}
	if err := store.WriteOnce(activationstore.PlanFileName, planRaw); err != nil {
		return fmt.Errorf("write activation plan: %w", err)
	}
	if err := store.WriteOnce(
		activationstore.ExecutorBaselineWitnessFileName, baselineRaw,
	); err != nil {
		return fmt.Errorf("write baseline controller witness: %w", err)
	}
	planDigest, _ := activation.PlanDigestV1(planRaw)
	initial := activation.StateV1{
		SchemaVersion: activation.StateSchemaV1,
		Binding: activation.BindingV1{
			ActivationID:  plan.ActivationID,
			PlanDigest:    planDigest,
			ReleaseDigest: plan.ReleaseDigest,
			PolicyDigest:  plan.PolicyDigest,
			IntentDigest:  plan.IntentDigest,
			Archive:       plan.Archive,
			TenantID:      inputs.intent.TenantID,
			NodeID:        inputs.intent.NodeID,
			InstanceID:    inputs.intent.InstanceID,
			Generation:    inputs.intent.Generation,
		},
		Phase:     activation.PhaseNew,
		UpdatedAt: timeNow().UTC().Format(time.RFC3339Nano),
	}
	initialRaw, err := activation.MarshalStateV1(initial)
	if err != nil {
		return err
	}
	if _, err := store.AppendState(0, initialRaw); err != nil {
		return fmt.Errorf("write initial activation state: %w", err)
	}
	chain := activationStateChain{
		names: []string{"state-000000000000.json"},
		raw:   [][]byte{initialRaw}, states: []activation.StateV1{initial},
	}
	return writeActivationStatus(
		stdout,
		inputs,
		chain,
		true,
		activationWaitingRun,
		activationResumeRunCommand,
		"",
	)
}

func activationTimeouts(values ...time.Duration) (activation.TimeoutsV1, error) {
	if len(values) != 6 {
		return activation.TimeoutsV1{}, errors.New("activation requires six timeout values")
	}
	seconds := make([]uint32, len(values))
	for index, value := range values {
		if value < time.Second || value > 24*time.Hour || value%time.Second != 0 {
			return activation.TimeoutsV1{}, errors.New("activation timeouts must be whole seconds from 1s through 24h")
		}
		seconds[index] = uint32(value / time.Second)
	}
	return activation.TimeoutsV1{
		PreflightSeconds: seconds[0], ImageImportSeconds: seconds[1],
		AdmissionSeconds: seconds[2], StartupSeconds: seconds[3],
		CanarySeconds: seconds[4], EvidenceSeconds: seconds[5],
	}, nil
}

func randomActivationID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate activation ID: %w", err)
	}
	return "activation-" + hex.EncodeToString(raw[:]), nil
}
