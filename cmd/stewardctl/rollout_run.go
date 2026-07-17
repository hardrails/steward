package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"time"

	"github.com/hardrails/steward/internal/activation"
	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/agentrelease"
	"github.com/hardrails/steward/internal/connectorledger"
	"github.com/hardrails/steward/internal/controlclient"
	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/controlwitness"
	"github.com/hardrails/steward/internal/rollout"
	"github.com/hardrails/steward/internal/rolloutdriver"
	"github.com/hardrails/steward/internal/rolloutstore"
)

const rolloutCommandMaximumValidity = 15 * time.Minute

var rolloutPollSleep = func(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

type verifiedRolloutRun struct {
	planRaw       []byte
	plan          rollout.PlanV1
	releaseRaw    []byte
	policyRaw     []byte
	witnessPublic ed25519.PublicKey
	verified      admission.VerifiedCapsuleImport
	targets       []verifiedRolloutRunTarget
	states        []rollout.TargetStateV1
	stateCounts   []uint64
	authorization *rolloutAuthorizationChain
}

type verifiedRolloutRunTarget struct {
	prepared      rolloutdriver.PreparedTargetV1
	serviceTrust  []byte
	gatewayRaw    []byte
	gatewayPublic ed25519.PublicKey
	timeouts      activation.TimeoutsV1

	admitCommandRaw  []byte
	admissionRaw     []byte
	admission        *controlprotocol.ExecutorAdmissionProjectionV1
	startCommandRaw  []byte
	canaryCommandRaw []byte
	canaryResultRaw  []byte
	verifiedCanary   *rolloutdriver.VerifiedCanaryV1
	captureRaw       []byte
	activationState  []byte
	activationProof  []byte
}

type rolloutRunKeys struct {
	commandID                  string
	commandPrivate             ed25519.PrivateKey
	commandPublic              ed25519.PublicKey
	authorizationContextDigest string
	authorizationContextTime   time.Time
	taskID                     string
	taskPrivate                ed25519.PrivateKey
	taskPublic                 ed25519.PublicKey
}

func runRollout(arguments []string, stdout io.Writer) (resultErr error) {
	flags := flag.NewFlagSet("rollout run", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	common := addControlFlags(flags, true)
	directoryFlag := flags.String("dir", "", "owner-only rollout workspace")
	publisherPublicPath := flags.String("publisher-public-key", "", "pinned publisher public key")
	publisherKeyID := flags.String("publisher-key-id", "", "publisher DSSE key ID")
	siteRootPublicPath := flags.String("site-root-public-key", "", "pinned site-root public key")
	siteRootKeyID := flags.String("site-root-key-id", "", "site-root DSSE key ID")
	witnessPublicPath := flags.String("witness-public-key", "", "pinned controller witness public key PEM")
	commandPrivatePath := flags.String("command-private-key", "", "owner-only common command private key PEM")
	commandKeyID := flags.String("command-key-id", "", "command key ID authorized for admit, start, and activation-canary")
	taskPrivatePath := flags.String("task-private-key", "", "owner-only Hermes task private key PEM")
	taskKeyID := flags.String("task-key-id", "", "Hermes task key ID")
	jsonOutput := flags.Bool("json", false, "emit stable machine-readable status")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *directoryFlag == "" || *publisherPublicPath == "" || *publisherKeyID == "" ||
		*siteRootPublicPath == "" || *siteRootKeyID == "" || *witnessPublicPath == "" ||
		*commandPrivatePath == "" || *commandKeyID == "" ||
		*taskPrivatePath == "" || *taskKeyID == "" || flags.NArg() != 0 {
		return errors.New("rollout run requires -dir, publisher/site-root/witness trust, one common command key, one Hermes task key, control credentials, and no positional arguments")
	}
	directory, err := filepath.Abs(*directoryFlag)
	if err != nil {
		return fmt.Errorf("resolve rollout workspace path: %w", err)
	}
	witnessPath, err := filepath.Abs(*witnessPublicPath)
	if err != nil {
		return fmt.Errorf("resolve rollout witness key path: %w", err)
	}
	publisherPublic, err := readPublicKey(*publisherPublicPath)
	if err != nil {
		return fmt.Errorf("read rollout publisher key: %w", err)
	}
	siteRootPublic, err := readPublicKey(*siteRootPublicPath)
	if err != nil {
		return fmt.Errorf("read rollout site-root key: %w", err)
	}
	witnessPublic, err := controlwitness.LoadPublic(witnessPath)
	if err != nil {
		return fmt.Errorf("read rollout witness key: %w", err)
	}
	commandPrivate, err := readPrivateKey(*commandPrivatePath)
	if err != nil {
		return fmt.Errorf("read rollout command private key: %w", err)
	}
	taskPrivate, err := readPrivateKey(*taskPrivatePath)
	if err != nil {
		return fmt.Errorf("read rollout task private key: %w", err)
	}
	keys := rolloutRunKeys{
		commandID: *commandKeyID, commandPrivate: commandPrivate,
		commandPublic: append(ed25519.PublicKey(nil), commandPrivate.Public().(ed25519.PublicKey)...),
		taskID:        *taskKeyID, taskPrivate: taskPrivate,
		taskPublic: append(ed25519.PublicKey(nil), taskPrivate.Public().(ed25519.PublicKey)...),
	}

	store, err := rolloutstore.Open(directory)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, store.Close()) }()
	run, err := loadVerifiedRolloutRun(
		store,
		*publisherKeyID, publisherPublic,
		*siteRootKeyID, siteRootPublic,
		witnessPublic,
	)
	if err != nil {
		return err
	}
	if err := verifyRetainedRolloutRun(store, &run, keys); err != nil {
		return err
	}
	if err := authorizeRolloutRun(store, &run, &keys); err != nil {
		return err
	}
	client, err := common.client(true)
	if err != nil {
		return err
	}
	if err := executeVerifiedRollout(store, &run, keys, client, stdout, *jsonOutput); err != nil {
		return err
	}
	return writeVerifiedRolloutRunStatus(stdout, run, *jsonOutput)
}

// loadVerifiedRolloutRun authenticates every immutable input before the
// coordinator is allowed to contact the controller. Release and policy are
// checked at the signed plan creation time, while the live deadline is checked
// immediately before each phase.
func loadVerifiedRolloutRun(
	store *rolloutstore.Store,
	publisherKeyID string,
	publisherPublic ed25519.PublicKey,
	siteRootKeyID string,
	siteRootPublic ed25519.PublicKey,
	witnessPublic ed25519.PublicKey,
) (verifiedRolloutRun, error) {
	planRaw, states, err := loadUnverifiedRolloutStates(store)
	if err != nil {
		return verifiedRolloutRun{}, err
	}
	plan, err := rollout.ParsePlanV1(planRaw)
	if err != nil {
		return verifiedRolloutRun{}, err
	}
	canonicalPlan, err := rollout.MarshalPlanV1(plan)
	if err != nil || !bytes.Equal(canonicalPlan, planRaw) {
		return verifiedRolloutRun{}, errors.New("retained rollout plan is not canonical JSON")
	}
	if err := rejectExtraRolloutTargetArtifacts(store, len(plan.Targets)); err != nil {
		return verifiedRolloutRun{}, err
	}
	createdAt, _ := time.Parse(time.RFC3339Nano, plan.CreatedAt)
	releaseRaw, err := store.Read(rolloutstore.ReleaseFileName, agentrelease.MaxEnvelopeBytes)
	if err != nil {
		return verifiedRolloutRun{}, fmt.Errorf("read rollout release: %w", err)
	}
	verifiedRelease, err := agentrelease.Verify(
		releaseRaw,
		map[string]ed25519.PublicKey{publisherKeyID: publisherPublic},
		createdAt,
	)
	if err != nil {
		return verifiedRolloutRun{}, fmt.Errorf("authenticate rollout release: %w", err)
	}
	policyRaw, err := store.Read(rolloutstore.PolicyFileName, rolloutstore.MaxArtifactBytes)
	if err != nil {
		return verifiedRolloutRun{}, fmt.Errorf("read rollout policy: %w", err)
	}
	verified, err := admission.VerifyCapsuleForImport(
		verifiedRelease.CapsuleEnvelope,
		policyRaw,
		map[string]ed25519.PublicKey{siteRootKeyID: siteRootPublic},
		createdAt,
		admission.DefaultProfiles(),
	)
	if err != nil {
		return verifiedRolloutRun{}, fmt.Errorf("authenticate rollout policy and capsule: %w", err)
	}
	if verifiedRelease.PublisherKeyID != publisherKeyID ||
		verified.PublisherKeyID != publisherKeyID ||
		verified.SiteRootKeyID != siteRootKeyID ||
		verifiedRelease.EnvelopeDigest != plan.ReleaseDigest ||
		verified.PolicyDigest != plan.PolicyDigest ||
		verified.CapsuleDigest != verifiedRelease.CapsuleEnvelopeDigest {
		return verifiedRolloutRun{}, errors.New("rollout plan, release, capsule, and policy trust disagree")
	}
	if plan.Archive.Digest != verifiedRelease.Release.Archive.SHA256Digest ||
		plan.Archive.Bytes != verifiedRelease.Release.Archive.SizeBytes {
		return verifiedRolloutRun{}, errors.New("rollout plan archive differs from the authenticated release")
	}
	if plan.Canary.Kind != activation.CanaryHermesWorkspaceAuditV1 ||
		verifiedRelease.Release.Canary.Kind != agentrelease.CanaryKindHermesWorkspaceAuditV1 {
		return verifiedRolloutRun{}, errors.New("rollout canary differs from the authenticated release recipe")
	}
	if err := requireDedicatedActivationPolicy(verified.SitePolicy); err != nil {
		return verifiedRolloutRun{}, err
	}
	storedWitnessRaw, err := store.Read(
		rolloutstore.ControllerWitnessPublicKeyFileName,
		64<<10,
	)
	if err != nil {
		return verifiedRolloutRun{}, fmt.Errorf("read retained rollout witness key: %w", err)
	}
	storedWitness, err := controlwitness.ParsePublic(storedWitnessRaw)
	if err != nil || !bytes.Equal(storedWitness, witnessPublic) {
		return verifiedRolloutRun{}, errors.New("retained rollout witness key differs from independently pinned trust")
	}

	run := verifiedRolloutRun{
		planRaw: planRaw, plan: plan,
		releaseRaw: releaseRaw, policyRaw: policyRaw,
		witnessPublic: append(ed25519.PublicKey(nil), witnessPublic...),
		verified:      verified,
		targets:       make([]verifiedRolloutRunTarget, len(plan.Targets)),
		states:        states,
		stateCounts:   make([]uint64, len(plan.Targets)),
	}
	for index := range plan.Targets {
		targetIndex := uint16(index)
		intentRaw, err := readRolloutTargetArtifact(
			store, targetIndex, rolloutstore.TargetIntentKind, rolloutstore.MaxArtifactBytes,
		)
		if err != nil {
			return verifiedRolloutRun{}, err
		}
		serviceTrustRaw, err := readRolloutTargetArtifact(
			store, targetIndex, rolloutstore.TargetServiceTrustKind, rolloutstore.MaxArtifactBytes,
		)
		if err != nil {
			return verifiedRolloutRun{}, err
		}
		gatewayRaw, err := readRolloutTargetArtifact(
			store, targetIndex, rolloutstore.TargetGatewayReceiptPublicKeyKind, 64<<10,
		)
		if err != nil {
			return verifiedRolloutRun{}, err
		}
		gatewayPublic, err := parseRolloutBase64PublicKey(gatewayRaw)
		if err != nil || controlprotocol.ExecutorEvidencePublicKeySHA256(gatewayPublic) !=
			plan.Targets[index].GatewayReceiptPublicKeySHA256 {
			return verifiedRolloutRun{}, fmt.Errorf("rollout target %d Gateway trust differs from the plan", index)
		}
		activationPlanRaw, err := readRolloutTargetArtifact(
			store, targetIndex, rolloutstore.TargetActivationPlanKind, activation.MaxPlanBytes,
		)
		if err != nil {
			return verifiedRolloutRun{}, err
		}
		activationPlan, err := activation.ParsePlanV1(activationPlanRaw)
		if err != nil {
			return verifiedRolloutRun{}, fmt.Errorf("parse rollout target %d activation plan: %w", index, err)
		}
		prepared, err := rolloutdriver.PrepareTargetV1(rolloutdriver.PrepareInputV1{
			PlanRaw: planRaw, TargetIndex: targetIndex, IntentRaw: intentRaw,
			CapsuleEnvelope: verifiedRelease.CapsuleEnvelope,
			VerifiedCapsule: verified, ActivationTimeouts: activationPlan.Timeouts,
		})
		if err != nil {
			return verifiedRolloutRun{}, fmt.Errorf("prepare rollout target %d: %w", index, err)
		}
		executorBeginRaw, err := readRolloutTargetArtifact(
			store, targetIndex, rolloutstore.TargetExecutorBeginKind, rolloutstore.MaxArtifactBytes,
		)
		if err != nil {
			return verifiedRolloutRun{}, err
		}
		if !bytes.Equal(activationPlanRaw, prepared.ActivationPlanRaw()) ||
			!bytes.Equal(executorBeginRaw, prepared.ExecutorBeginRaw()) {
			return verifiedRolloutRun{}, fmt.Errorf("rollout target %d deterministic activation companions changed", index)
		}
		intent := prepared.Intent()
		operation, err := decodeServiceTrust(serviceTrustRaw, intent, agentrelease.HermesOperationID)
		if err != nil || operation.ServiceID != agentrelease.HermesServiceID ||
			operation.TaskProtocol != connectorledger.TaskProtocolLifecycleV1 ||
			operation.MaxRequestBytes < int64(agentrelease.MaxCanaryRequestBytes) ||
			operation.PolicyDigest != plan.Targets[index].OperationPolicyDigest {
			return verifiedRolloutRun{}, fmt.Errorf("rollout target %d retained Hermes service trust differs from the plan", index)
		}
		stateNames, err := store.ListTargetStates(targetIndex)
		if err != nil {
			return verifiedRolloutRun{}, err
		}
		run.stateCounts[index] = uint64(len(stateNames))
		run.targets[index] = verifiedRolloutRunTarget{
			prepared: prepared, serviceTrust: serviceTrustRaw,
			gatewayRaw: gatewayRaw, gatewayPublic: gatewayPublic,
			timeouts: activationPlan.Timeouts,
		}
	}
	return run, nil
}

func readRolloutTargetArtifact(
	store *rolloutstore.Store,
	target uint16,
	kind string,
	limit int64,
) ([]byte, error) {
	name, err := rolloutstore.TargetArtifactName(target, kind)
	if err != nil {
		return nil, err
	}
	raw, err := store.Read(name, limit)
	if err != nil {
		return nil, fmt.Errorf("read rollout artifact %q: %w", name, err)
	}
	return raw, nil
}

func writeVerifiedRolloutRunStatus(
	stdout io.Writer,
	run verifiedRolloutRun,
	jsonOutput bool,
) error {
	summary, err := rollout.SummarizeFleetV1(run.planRaw, run.states)
	if err != nil {
		return err
	}
	output := newRolloutStatusOutput(summary)
	output.Verified = true
	output.Verification = "authenticated_retained_progress"
	if jsonOutput {
		encoder := json.NewEncoder(stdout)
		encoder.SetEscapeHTML(false)
		return encoder.Encode(output)
	}
	return writeHumanRolloutStatus(stdout, output)
}

func nodeSupportsRollout(node controlclient.Node, tenantID string, authorizedEffects bool) bool {
	base := node.State == "active" &&
		slices.Contains(node.TenantIDs, tenantID) &&
		slices.Contains(node.Capabilities, controlprotocol.ExecutorCapabilityAdmissionProjectionV1) &&
		slices.Contains(node.Capabilities, controlprotocol.ExecutorCapabilityActivationCanaryV1) &&
		slices.Contains(node.Capabilities, controlprotocol.ExecutorCapabilityRolloutAuthorizationContextV1)
	return base && (!authorizedEffects ||
		slices.Contains(node.Capabilities, controlprotocol.ExecutorCapabilityAuthorizedEffectsV1))
}

// These declarations live below the trust loader to keep the critical rule
// visible: no controller call occurs until every retained target has passed
// the same offline reconstruction checks.
func verifyRetainedRolloutRun(
	store *rolloutstore.Store,
	run *verifiedRolloutRun,
	keys rolloutRunKeys,
) error {
	return verifyRetainedRolloutExecution(store, run, keys)
}

func executeVerifiedRollout(
	store *rolloutstore.Store,
	run *verifiedRolloutRun,
	keys rolloutRunKeys,
	client *controlclient.Client,
	stdout io.Writer,
	jsonOutput bool,
) error {
	for _, state := range run.states {
		if state.Phase == rollout.PhaseActionRequired {
			return writeExistingRolloutActionRequired(stdout, *run, jsonOutput)
		}
	}
	for _, state := range run.states {
		if state.Phase != rollout.PhasePassed {
			now := timeNow().UTC()
			if keys.authorizationContextTime.IsZero() || now.Before(keys.authorizationContextTime) {
				return errors.New("coordinator clock precedes the active rollout authorization")
			}
			break
		}
	}
	return executeRolloutStateMachine(store, run, keys, client, stdout, jsonOutput)
}
