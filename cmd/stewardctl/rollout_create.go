package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/hardrails/steward/internal/activation"
	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/agentrelease"
	"github.com/hardrails/steward/internal/connectorledger"
	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/controlstore"
	"github.com/hardrails/steward/internal/controlwitness"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/ocibundle"
	"github.com/hardrails/steward/internal/rollout"
	"github.com/hardrails/steward/internal/rolloutdriver"
	"github.com/hardrails/steward/internal/rolloutstore"
	"github.com/hardrails/steward/internal/securefile"
)

const (
	rolloutInputsSchemaV1 = "steward.rollout-inputs.v1"
	maxRolloutInputsBytes = 128 << 10
)

type rolloutInputsV1 struct {
	SchemaVersion string                 `json:"schema_version"`
	Targets       []rolloutTargetInputV1 `json:"targets"`
}

type rolloutTargetInputV1 struct {
	IntentFile                  string `json:"intent_file"`
	ServiceTrustFile            string `json:"service_trust_file"`
	GatewayReceiptPublicKeyFile string `json:"gateway_receipt_public_key_file"`
	GatewayReceiptEpoch         uint64 `json:"gateway_receipt_epoch"`
	ClaimGeneration             uint64 `json:"claim_generation"`
	ActivationID                string `json:"activation_id,omitempty"`
}

type preparedRolloutCreateTarget struct {
	intentRaw        []byte
	serviceTrustRaw  []byte
	gatewayPublicRaw []byte
	prepared         rolloutdriver.PreparedTargetV1
}

func createRollout(arguments []string, stdout io.Writer) (resultErr error) {
	flags := flag.NewFlagSet("rollout create", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	directoryFlag := flags.String("dir", "", "new owner-only rollout workspace")
	rolloutIDFlag := flags.String("rollout-id", "", "stable rollout ID; generated when omitted")
	releasePath := flags.String("release", "", "publisher-signed agent release")
	policyPath := flags.String("policy", "", "site-root-signed policy")
	archivePath := flags.String("archive", "", "exact offline OCI archive used for preflight")
	inputsPath := flags.String("targets", "", "strict ordered rollout input manifest")
	publisherPublicPath := flags.String("publisher-public-key", "", "pinned publisher public key")
	publisherKeyID := flags.String("publisher-key-id", "", "publisher DSSE key ID")
	siteRootPublicPath := flags.String("site-root-public-key", "", "pinned site-root public key")
	siteRootKeyID := flags.String("site-root-key-id", "", "site-root DSSE key ID")
	witnessPublicPath := flags.String("witness-public-key", "", "pinned controller witness public key PEM")
	batchSize := flags.Uint("batch-size", 4, "targets per batch after the first canary")
	validFor := flags.Duration("valid-for", time.Hour, "absolute rollout window")
	preflightTimeout := flags.Duration("preflight-timeout", 30*time.Second, "archive and policy preflight ceiling")
	importTimeout := flags.Duration("image-import-timeout", 30*time.Minute, "reserved node image-import ceiling")
	admissionTimeout := flags.Duration("admission-timeout", 2*time.Minute, "remote admission ceiling")
	startupTimeout := flags.Duration("startup-timeout", 5*time.Minute, "remote startup ceiling")
	canaryTimeout := flags.Duration("canary-timeout", 5*time.Minute, "Hermes canary ceiling")
	evidenceTimeout := flags.Duration("evidence-timeout", 2*time.Minute, "controller evidence ceiling")
	jsonOutput := flags.Bool("json", false, "emit machine-readable status")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *directoryFlag == "" || *releasePath == "" || *policyPath == "" ||
		*archivePath == "" || *inputsPath == "" || *publisherKeyID == "" ||
		*publisherPublicPath == "" || *siteRootKeyID == "" ||
		*siteRootPublicPath == "" || *witnessPublicPath == "" ||
		*batchSize == 0 || *batchSize > rollout.MaxBatchSize ||
		*validFor < time.Second || *validFor > 24*time.Hour ||
		*validFor%time.Second != 0 || flags.NArg() != 0 {
		return errors.New("rollout create requires a new directory, release, policy, archive, targets, publisher/site-root/witness trust, a batch size from 1 through 16, and a whole-second window through 24h")
	}
	timeouts, err := activationTimeouts(
		*preflightTimeout,
		*importTimeout,
		*admissionTimeout,
		*startupTimeout,
		*canaryTimeout,
		*evidenceTimeout,
	)
	if err != nil {
		return err
	}
	if _, err := rolloutEvidenceCaptureTTL(timeouts); err != nil {
		return err
	}
	directory, err := filepath.Abs(*directoryFlag)
	if err != nil {
		return fmt.Errorf("resolve rollout workspace path: %w", err)
	}
	archive, err := filepath.Abs(*archivePath)
	if err != nil {
		return fmt.Errorf("resolve rollout archive path: %w", err)
	}
	inputManifestPath, err := filepath.Abs(*inputsPath)
	if err != nil {
		return fmt.Errorf("resolve rollout target input path: %w", err)
	}
	now := timeNow().UTC()
	rolloutID := *rolloutIDFlag
	if rolloutID == "" {
		rolloutID, err = randomRolloutID()
		if err != nil {
			return err
		}
	}

	publisherPublic, err := readPublicKey(*publisherPublicPath)
	if err != nil {
		return fmt.Errorf("read rollout publisher key: %w", err)
	}
	siteRootPublic, err := readPublicKey(*siteRootPublicPath)
	if err != nil {
		return fmt.Errorf("read rollout site-root key: %w", err)
	}
	witnessPublicRaw, err := securefile.Read(
		*witnessPublicPath,
		64<<10,
		securefile.TrustFile,
	)
	if err != nil {
		return fmt.Errorf("read rollout controller witness key bytes: %w", err)
	}
	if _, err := controlwitness.ParsePublic(witnessPublicRaw); err != nil {
		return fmt.Errorf("verify rollout controller witness key: %w", err)
	}

	releaseRaw, err := securefile.Read(
		*releasePath,
		agentrelease.MaxEnvelopeBytes,
		securefile.TrustFile,
	)
	if err != nil {
		return fmt.Errorf("read rollout release: %w", err)
	}
	verifiedRelease, err := agentrelease.Verify(
		releaseRaw,
		map[string]ed25519.PublicKey{*publisherKeyID: publisherPublic},
		now,
	)
	if err != nil {
		return fmt.Errorf("verify rollout release: %w", err)
	}
	policyRaw, err := securefile.Read(*policyPath, maxArtifactBytes, securefile.TrustFile)
	if err != nil {
		return fmt.Errorf("read rollout policy: %w", err)
	}
	verifiedImport, err := admission.VerifyCapsuleForImport(
		verifiedRelease.CapsuleEnvelope,
		policyRaw,
		map[string]ed25519.PublicKey{*siteRootKeyID: siteRootPublic},
		now,
		admission.DefaultProfiles(),
	)
	if err != nil {
		return fmt.Errorf("authorize rollout release under site policy: %w", err)
	}
	if verifiedRelease.PublisherKeyID != *publisherKeyID ||
		verifiedImport.CapsuleDigest != verifiedRelease.CapsuleEnvelopeDigest ||
		verifiedImport.PublisherKeyID != *publisherKeyID ||
		verifiedImport.SiteRootKeyID != *siteRootKeyID {
		return errors.New("rollout release, capsule, publisher, and site-policy trust disagree")
	}
	if err := requireDedicatedActivationPolicy(verifiedImport.SitePolicy); err != nil {
		return err
	}
	deadline := now.Add(*validFor)
	if verifiedImport.Capsule.ExpiresAt != "" {
		capsuleExpiry, parseErr := time.Parse(time.RFC3339, verifiedImport.Capsule.ExpiresAt)
		if parseErr != nil || deadline.After(capsuleExpiry) {
			return errors.New("rollout window extends beyond the authenticated capsule expiry")
		}
	}
	archiveIdentity := ocibundle.ArchiveIdentity{
		Digest: verifiedRelease.Release.Archive.SHA256Digest,
		Bytes:  verifiedRelease.Release.Archive.SizeBytes,
	}
	archiveExpected := ocibundle.Identity{
		ManifestDigest: verifiedRelease.Release.Archive.Image.ManifestDigest,
		ConfigDigest:   verifiedRelease.Release.Archive.Image.ConfigDigest,
		Platform: ocibundle.Platform{
			OS:           verifiedRelease.Release.Archive.Image.Platform.OS,
			Architecture: verifiedRelease.Release.Archive.Image.Platform.Architecture,
			Variant:      verifiedRelease.Release.Archive.Image.Platform.Variant,
		},
	}
	preflightContext, cancelPreflight := context.WithTimeout(
		context.Background(),
		time.Duration(timeouts.PreflightSeconds)*time.Second,
	)
	preparedArchive, err := ocibundle.PrepareBoundContext(
		preflightContext,
		archive,
		archiveExpected,
		archiveIdentity,
		ocibundle.DefaultLimits(),
	)
	cancelPreflight()
	if err != nil {
		return fmt.Errorf("preflight rollout archive: %w", err)
	}
	if err := preparedArchive.Close(); err != nil {
		return fmt.Errorf("close rollout archive preflight: %w", err)
	}

	inputDirectory := filepath.Dir(inputManifestPath)
	inputRoot, err := os.OpenRoot(inputDirectory)
	if err != nil {
		return fmt.Errorf("anchor rollout target input directory: %w", err)
	}
	defer func() {
		resultErr = errors.Join(resultErr, inputRoot.Close())
	}()
	inputsRaw, err := securefile.ReadRoot(
		inputRoot,
		filepath.Base(inputManifestPath),
		maxRolloutInputsBytes,
		securefile.TrustFile,
	)
	if err != nil {
		return fmt.Errorf("read rollout target inputs: %w", err)
	}
	inputs, err := parseRolloutInputsV1(inputsRaw)
	if err != nil {
		return err
	}
	targets := make([]rollout.TargetV1, len(inputs.Targets))
	targetInputs := make([]preparedRolloutCreateTarget, len(inputs.Targets))
	tenantID := ""
	for index, input := range inputs.Targets {
		intentRaw, readErr := readRolloutInputCompanion(
			inputRoot,
			input.IntentFile,
			maxArtifactBytes,
		)
		if readErr != nil {
			return fmt.Errorf("read rollout target %d intent: %w", index, readErr)
		}
		var intent admission.InstanceIntent
		if decodeErr := dsse.DecodeStrictInto(intentRaw, maxArtifactBytes, &intent); decodeErr != nil {
			return fmt.Errorf("decode rollout target %d intent: %w", index, decodeErr)
		}
		if tenantID == "" {
			tenantID = intent.TenantID
		}
		if intent.TenantID != tenantID {
			return fmt.Errorf("rollout target %d belongs to another tenant", index)
		}
		if intent.StateDisposition != "new" ||
			!intent.Capabilities.State ||
			!intent.Capabilities.Service ||
			intent.ServiceID != agentrelease.HermesServiceID {
			return fmt.Errorf("rollout target %d is not the fresh-state Hermes service contract", index)
		}
		serviceTrustRaw, readErr := readRolloutInputCompanion(
			inputRoot,
			input.ServiceTrustFile,
			rolloutstore.MaxArtifactBytes,
		)
		if readErr != nil {
			return fmt.Errorf("read rollout target %d service trust: %w", index, readErr)
		}
		operation, decodeErr := decodeServiceTrust(
			serviceTrustRaw,
			intent,
			agentrelease.HermesOperationID,
		)
		if decodeErr != nil {
			return fmt.Errorf("verify rollout target %d service trust: %w", index, decodeErr)
		}
		if operation.ServiceID != agentrelease.HermesServiceID ||
			operation.TaskProtocol != connectorledger.TaskProtocolLifecycleV1 ||
			operation.MaxRequestBytes < int64(agentrelease.MaxCanaryRequestBytes) {
			return fmt.Errorf("rollout target %d does not expose the closed Hermes lifecycle operation", index)
		}
		gatewayPublicRaw, readErr := readRolloutInputCompanion(
			inputRoot,
			input.GatewayReceiptPublicKeyFile,
			64<<10,
		)
		if readErr != nil {
			return fmt.Errorf("read rollout target %d Gateway receipt key: %w", index, readErr)
		}
		gatewayPublic, readErr := parseRolloutBase64PublicKey(gatewayPublicRaw)
		if readErr != nil {
			return fmt.Errorf("verify rollout target %d Gateway receipt key: %w", index, readErr)
		}
		activationID := input.ActivationID
		if activationID == "" {
			activationID = derivedRolloutIdentifier(
				"activation",
				rolloutID,
				index,
				intent.NodeID,
			)
		}
		activationPlan := activation.PlanV1{
			SchemaVersion: activation.PlanSchemaV1,
			ActivationID:  activationID,
			ReleaseDigest: verifiedRelease.EnvelopeDigest,
			PolicyDigest:  verifiedImport.PolicyDigest,
			IntentDigest:  dsse.Digest(intentRaw),
			Archive: activation.ArchiveV1{
				Digest: archiveIdentity.Digest,
				Bytes:  archiveIdentity.Bytes,
			},
			Transport: activation.TransportControlUplink,
			Canary: activation.CanaryV1{
				Kind: verifiedRelease.Release.Canary.Kind,
			},
			Timeouts: timeouts,
		}
		activationPlanRaw, marshalErr := activation.MarshalPlanV1(activationPlan)
		if marshalErr != nil {
			return fmt.Errorf("construct rollout target %d activation plan: %w", index, marshalErr)
		}
		commandPrefix := derivedRolloutIdentifier(
			"rollout-command",
			rolloutID,
			index,
			intent.NodeID,
		)
		targets[index] = rollout.TargetV1{
			NodeID:                        intent.NodeID,
			InstanceID:                    intent.InstanceID,
			ActivationID:                  activationID,
			IntentDigest:                  dsse.Digest(intentRaw),
			ActivationPlanDigest:          dsse.Digest(activationPlanRaw),
			GatewayReceiptEpoch:           input.GatewayReceiptEpoch,
			GatewayReceiptPublicKeySHA256: controlprotocol.ExecutorEvidencePublicKeySHA256(gatewayPublic),
			OperationPolicyDigest:         operation.PolicyDigest,
			ClaimGeneration:               input.ClaimGeneration,
			InstanceGeneration:            intent.Generation,
			AdmitCommandID:                commandPrefix + "-admit",
			StartCommandID:                commandPrefix + "-start",
			CanaryCommandID:               commandPrefix + "-canary",
		}
		targetInputs[index] = preparedRolloutCreateTarget{
			intentRaw:        intentRaw,
			serviceTrustRaw:  serviceTrustRaw,
			gatewayPublicRaw: gatewayPublicRaw,
		}
	}
	plan := rollout.PlanV1{
		SchemaVersion: rollout.PlanSchemaV1,
		RolloutID:     rolloutID,
		TenantID:      tenantID,
		ReleaseDigest: verifiedRelease.EnvelopeDigest,
		PolicyDigest:  verifiedImport.PolicyDigest,
		Archive:       archiveIdentity,
		Canary: activation.CanaryV1{
			Kind: verifiedRelease.Release.Canary.Kind,
		},
		BatchSize: uint16(*batchSize),
		CreatedAt: now.Format(time.RFC3339Nano),
		Deadline:  deadline.Format(time.RFC3339Nano),
		Targets:   targets,
	}
	planRaw, err := rollout.MarshalPlanV1(plan)
	if err != nil {
		return err
	}
	for index := range targetInputs {
		prepared, prepareErr := rolloutdriver.PrepareTargetV1(
			rolloutdriver.PrepareInputV1{
				PlanRaw:            planRaw,
				TargetIndex:        uint16(index),
				IntentRaw:          targetInputs[index].intentRaw,
				CapsuleEnvelope:    verifiedRelease.CapsuleEnvelope,
				VerifiedCapsule:    verifiedImport,
				ActivationTimeouts: timeouts,
			},
		)
		if prepareErr != nil {
			return fmt.Errorf("preflight rollout target %d: %w", index, prepareErr)
		}
		targetInputs[index].prepared = prepared
	}

	store, err := rolloutstore.Create(directory)
	if err != nil {
		return err
	}
	defer func() {
		resultErr = errors.Join(resultErr, store.Close())
	}()
	for _, artifact := range []struct {
		name string
		raw  []byte
	}{
		{rolloutstore.PlanFileName, planRaw},
		{rolloutstore.ReleaseFileName, releaseRaw},
		{rolloutstore.PolicyFileName, policyRaw},
		{rolloutstore.ControllerWitnessPublicKeyFileName, witnessPublicRaw},
	} {
		if err := store.Import(artifact.name, artifact.raw); err != nil {
			return fmt.Errorf("initialize rollout artifact %q: %w", artifact.name, err)
		}
	}
	planDigest, _ := rollout.PlanDigestV1(planRaw)
	states := make([]rollout.TargetStateV1, len(targetInputs))
	for index, targetInput := range targetInputs {
		for _, artifact := range []struct {
			kind string
			raw  []byte
		}{
			{rolloutstore.TargetIntentKind, targetInput.intentRaw},
			{rolloutstore.TargetServiceTrustKind, targetInput.serviceTrustRaw},
			{rolloutstore.TargetGatewayReceiptPublicKeyKind, targetInput.gatewayPublicRaw},
			{rolloutstore.TargetActivationPlanKind, targetInput.prepared.ActivationPlanRaw()},
			{rolloutstore.TargetExecutorBeginKind, targetInput.prepared.ExecutorBeginRaw()},
		} {
			name, nameErr := rolloutstore.TargetArtifactName(uint16(index), artifact.kind)
			if nameErr != nil {
				return nameErr
			}
			if err := store.Import(name, artifact.raw); err != nil {
				return fmt.Errorf("initialize rollout artifact %q: %w", name, err)
			}
		}
		target := plan.Targets[index]
		state := rollout.TargetStateV1{
			SchemaVersion: rollout.TargetStateSchemaV1,
			Binding: rollout.TargetBindingV1{
				PlanDigest:         planDigest,
				RolloutID:          plan.RolloutID,
				TargetIndex:        uint16(index),
				TenantID:           plan.TenantID,
				NodeID:             target.NodeID,
				InstanceID:         target.InstanceID,
				ActivationID:       target.ActivationID,
				ClaimGeneration:    target.ClaimGeneration,
				InstanceGeneration: target.InstanceGeneration,
			},
			Phase:     rollout.PhasePlanned,
			UpdatedAt: now.Format(time.RFC3339Nano),
		}
		stateRaw, marshalErr := rollout.MarshalTargetStateV1(state)
		if marshalErr != nil {
			return marshalErr
		}
		if _, err := store.AppendTargetState(uint16(index), 0, stateRaw); err != nil {
			return fmt.Errorf("initialize rollout target %d state: %w", index, err)
		}
		states[index] = state
	}
	summary, err := rollout.SummarizeFleetV1(planRaw, states)
	if err != nil {
		return err
	}
	output := newRolloutStatusOutput(summary)
	if *jsonOutput {
		encoder := json.NewEncoder(stdout)
		encoder.SetEscapeHTML(false)
		return encoder.Encode(output)
	}
	return writeHumanRolloutStatus(stdout, output)
}

func parseRolloutInputsV1(raw []byte) (rolloutInputsV1, error) {
	var inputs rolloutInputsV1
	if err := dsse.DecodeStrictInto(raw, maxRolloutInputsBytes, &inputs); err != nil {
		return rolloutInputsV1{}, fmt.Errorf("decode rollout inputs: %w", err)
	}
	if inputs.SchemaVersion != rolloutInputsSchemaV1 ||
		len(inputs.Targets) == 0 ||
		len(inputs.Targets) > rollout.MaxTargets {
		return rolloutInputsV1{}, fmt.Errorf(
			"rollout inputs require schema %q and 1 through %d ordered targets",
			rolloutInputsSchemaV1,
			rollout.MaxTargets,
		)
	}
	for index, target := range inputs.Targets {
		if !validRolloutCompanionName(target.IntentFile) ||
			!validRolloutCompanionName(target.ServiceTrustFile) ||
			!validRolloutCompanionName(target.GatewayReceiptPublicKeyFile) ||
			target.GatewayReceiptEpoch == 0 ||
			target.ClaimGeneration == 0 {
			return rolloutInputsV1{}, fmt.Errorf("rollout input target %d is invalid", index)
		}
	}
	return inputs, nil
}

func validRolloutCompanionName(name string) bool {
	return name != "" &&
		len(name) <= 255 &&
		!filepath.IsAbs(name) &&
		filepath.Clean(name) == name &&
		filepath.Base(name) == name &&
		name != "." &&
		!strings.ContainsRune(name, '\x00')
}

func readRolloutInputCompanion(
	root *os.Root,
	name string,
	maximum int64,
) ([]byte, error) {
	if !validRolloutCompanionName(name) {
		return nil, errors.New("rollout companion must be one clean relative filename")
	}
	return securefile.ReadRoot(
		root,
		name,
		maximum,
		securefile.TrustFile,
	)
}

func parseRolloutBase64PublicKey(raw []byte) (ed25519.PublicKey, error) {
	text := string(raw)
	encoded := strings.TrimSuffix(text, "\n")
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(decoded) != ed25519.PublicKeySize ||
		base64.StdEncoding.EncodeToString(decoded) != encoded ||
		(text != encoded && text != encoded+"\n") {
		return nil, errors.New("public key is not canonical base64 Ed25519")
	}
	return ed25519.PublicKey(append([]byte(nil), decoded...)), nil
}

// rolloutEvidenceCaptureTTL is derived entirely from the immutable activation
// plan so a retry after a coordinator crash presents the exact same arm
// request. The controller must still receive the matching checkpoint before
// the fixed expiry; the timeout is a ceiling, not proof that each phase used
// all of its allowance.
func rolloutEvidenceCaptureTTL(timeouts activation.TimeoutsV1) (time.Duration, error) {
	seconds := uint64(timeouts.AdmissionSeconds) +
		uint64(timeouts.StartupSeconds) +
		uint64(timeouts.CanarySeconds) +
		uint64(timeouts.EvidenceSeconds)
	ttl := time.Duration(seconds) * time.Second
	if ttl < controlstore.MinEvidenceCaptureTTL ||
		ttl > controlstore.MaxEvidenceCaptureTTL {
		return 0, fmt.Errorf(
			"rollout admission, startup, canary, and evidence timeouts must total from %s through %s so one bounded controller evidence capture can cover the remote activation",
			controlstore.MinEvidenceCaptureTTL,
			controlstore.MaxEvidenceCaptureTTL,
		)
	}
	return ttl, nil
}

func randomRolloutID() (string, error) {
	activationID, err := randomActivationID()
	if err != nil {
		return "", err
	}
	return "rollout-" + strings.TrimPrefix(activationID, "activation-"), nil
}

func derivedRolloutIdentifier(
	prefix string,
	rolloutID string,
	targetIndex int,
	nodeID string,
) string {
	hash := sha256.New()
	for _, value := range []string{
		"steward-rollout-identifier-v1",
		prefix,
		rolloutID,
		strconv.Itoa(targetIndex),
		nodeID,
	} {
		_, _ = hash.Write([]byte{byte(len(value) >> 8), byte(len(value))})
		_, _ = hash.Write([]byte(value))
	}
	return prefix + "-" + hex.EncodeToString(hash.Sum(nil)[:16])
}
