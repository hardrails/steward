package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"sort"
	"time"

	"github.com/hardrails/steward/internal/activation"
	"github.com/hardrails/steward/internal/activationstore"
	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/agentrelease"
	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/controlwitness"
	"github.com/hardrails/steward/internal/dsse"
)

const activationStatusSchemaV1 = "steward.activation-status.v1"

type activationTrust struct {
	publisherKeyID string
	publisher      ed25519.PublicKey
	siteRootKeyID  string
	siteRoot       ed25519.PublicKey
	witness        ed25519.PublicKey
}

type verifiedActivationInputs struct {
	planRaw []byte
	plan    activation.PlanV1

	releaseRaw []byte
	release    agentrelease.Verified

	policyRaw []byte
	intentRaw []byte
	intent    admission.InstanceIntent
	effective admission.EffectiveAdmission

	archivePath string
}

type activationStateChain struct {
	names  []string
	raw    [][]byte
	states []activation.StateV1
}

type activationStatusOutput struct {
	SchemaVersion string `json:"schema_version"`
	ActivationID  string `json:"activation_id"`
	Phase         string `json:"phase"`
	StateSequence uint64 `json:"state_sequence"`
	RuntimeRef    string `json:"runtime_ref,omitempty"`
	WaitingFor    string `json:"waiting_for,omitempty"`
	NextCommand   string `json:"next_command,omitempty"`
	ProofDigest   string `json:"proof_digest,omitempty"`
	Verified      bool   `json:"verified"`
}

func activationCommand(arguments []string, stdout io.Writer) error {
	if len(arguments) == 0 {
		return errors.New("activation command requires create, attach, run, status, or verify")
	}
	switch arguments[0] {
	case "create":
		return createActivation(arguments[1:], stdout)
	case "attach":
		return attachActivationArtifact(arguments[1:], stdout)
	case "run":
		return runActivation(arguments[1:], stdout)
	case "status":
		return statusActivation(arguments[1:], stdout)
	case "verify":
		return verifyActivation(arguments[1:], stdout)
	default:
		return errors.New("activation command requires create, attach, run, status, or verify")
	}
}

func loadActivationTrust(
	publisherKeyID, publisherPublicPath,
	siteRootKeyID, siteRootPublicPath,
	witnessPublicPath string,
	requireWitness bool,
) (activationTrust, error) {
	if publisherKeyID == "" || publisherPublicPath == "" ||
		siteRootKeyID == "" || siteRootPublicPath == "" ||
		requireWitness && witnessPublicPath == "" {
		return activationTrust{}, errors.New("activation trust requires publisher and site-root key IDs and public keys, plus the controller witness key")
	}
	publisher, err := readPublicKey(publisherPublicPath)
	if err != nil {
		return activationTrust{}, fmt.Errorf("read activation publisher key: %w", err)
	}
	siteRoot, err := readPublicKey(siteRootPublicPath)
	if err != nil {
		return activationTrust{}, fmt.Errorf("read activation site-root key: %w", err)
	}
	var witness ed25519.PublicKey
	if witnessPublicPath != "" {
		witness, err = controlwitness.LoadPublic(witnessPublicPath)
		if err != nil {
			return activationTrust{}, fmt.Errorf("read activation controller witness key: %w", err)
		}
	}
	return activationTrust{
		publisherKeyID: publisherKeyID, publisher: publisher,
		siteRootKeyID: siteRootKeyID, siteRoot: siteRoot,
		witness: witness,
	}, nil
}

func verifyActivationInputBytes(
	planRaw, releaseRaw, policyRaw, intentRaw []byte,
	archivePath string,
	trust activationTrust,
	now time.Time,
) (verifiedActivationInputs, error) {
	if now.IsZero() {
		return verifiedActivationInputs{}, errors.New("activation verification time is unavailable")
	}
	plan, err := activation.ParsePlanV1(planRaw)
	if err != nil {
		return verifiedActivationInputs{}, err
	}
	release, err := agentrelease.Verify(
		releaseRaw,
		map[string]ed25519.PublicKey{trust.publisherKeyID: trust.publisher},
		now.UTC(),
	)
	if err != nil {
		return verifiedActivationInputs{}, fmt.Errorf("verify agent release: %w", err)
	}
	if release.PublisherKeyID != trust.publisherKeyID ||
		plan.ReleaseDigest != release.EnvelopeDigest ||
		plan.PolicyDigest != dsse.Digest(policyRaw) ||
		plan.IntentDigest != dsse.Digest(intentRaw) ||
		plan.Archive.Digest != release.Release.Archive.SHA256Digest ||
		plan.Archive.Bytes != release.Release.Archive.SizeBytes ||
		plan.Canary.Kind != release.Release.Canary.Kind {
		return verifiedActivationInputs{}, errors.New("activation plan does not bind the exact release, policy, intent, archive, and canary")
	}
	verifiedImport, err := admission.VerifyCapsuleForImport(
		release.CapsuleEnvelope,
		policyRaw,
		map[string]ed25519.PublicKey{trust.siteRootKeyID: trust.siteRoot},
		now.UTC(),
		admission.DefaultProfiles(),
	)
	if err != nil {
		return verifiedActivationInputs{}, fmt.Errorf("authorize release capsule under site policy: %w", err)
	}
	if verifiedImport.CapsuleDigest != release.CapsuleEnvelopeDigest ||
		verifiedImport.PolicyDigest != plan.PolicyDigest ||
		verifiedImport.PublisherKeyID != release.PublisherKeyID ||
		verifiedImport.SiteRootKeyID != trust.siteRootKeyID {
		return verifiedActivationInputs{}, errors.New("release, capsule, and site-policy trust bindings disagree")
	}
	var intent admission.InstanceIntent
	if err := dsse.DecodeStrictInto(intentRaw, maxArtifactBytes, &intent); err != nil {
		return verifiedActivationInputs{}, fmt.Errorf("decode activation instance intent: %w", err)
	}
	effective, err := admission.Intersect(
		verifiedImport.Capsule, verifiedImport.CapsuleDigest,
		verifiedImport.SitePolicy, verifiedImport.PolicyDigest,
		verifiedImport.PublisherKeyID, verifiedImport.SiteRootKeyID,
		intent,
		admission.AuthenticatedIdentity{TenantID: intent.TenantID, NodeID: intent.NodeID},
		admission.PersistedFences{},
		admission.DefaultProfiles(),
	)
	if err != nil {
		return verifiedActivationInputs{}, fmt.Errorf("preflight activation admission: %w", err)
	}
	if err := requireDedicatedActivationPolicy(verifiedImport.SitePolicy); err != nil {
		return verifiedActivationInputs{}, err
	}
	if effective.Intent.StateDisposition != release.Release.Canary.RequiredStateDisposition ||
		!effective.Intent.Capabilities.State ||
		!effective.Intent.Capabilities.Service ||
		effective.Intent.ServiceID != agentrelease.HermesServiceID {
		return verifiedActivationInputs{}, errors.New("activation intent does not request the release's fresh-state Hermes service contract")
	}
	if archivePath == "" {
		return verifiedActivationInputs{}, errors.New("activation archive path is unavailable")
	}
	return verifiedActivationInputs{
		planRaw: planRaw, plan: plan,
		releaseRaw: releaseRaw, release: release,
		policyRaw: policyRaw, intentRaw: intentRaw, intent: intent,
		effective: effective, archivePath: archivePath,
	}, nil
}

func requireDedicatedActivationPolicy(policy admission.SitePolicy) error {
	if len(policy.Tenants) != 1 {
		return errors.New(
			"the Hermes activation recipe requires a one-tenant dedicated-host site policy because its persistent Docker volume has no hard byte or inode quota",
		)
	}
	return nil
}

func loadVerifiedActivationInputs(
	store *activationstore.Store,
	trust activationTrust,
	now time.Time,
) (verifiedActivationInputs, error) {
	planRaw, err := store.Read(activationstore.PlanFileName, activation.MaxPlanBytes)
	if err != nil {
		return verifiedActivationInputs{}, fmt.Errorf("read activation plan: %w", err)
	}
	releaseRaw, err := store.Read(activationstore.ReleaseFileName, agentrelease.MaxEnvelopeBytes)
	if err != nil {
		return verifiedActivationInputs{}, fmt.Errorf("read activation release: %w", err)
	}
	policyRaw, err := store.Read(activationstore.PolicyFileName, maxArtifactBytes)
	if err != nil {
		return verifiedActivationInputs{}, fmt.Errorf("read activation policy: %w", err)
	}
	intentRaw, err := store.Read(activationstore.IntentFileName, maxArtifactBytes)
	if err != nil {
		return verifiedActivationInputs{}, fmt.Errorf("read activation intent: %w", err)
	}
	archivePath, err := store.Path(activationstore.ImageArchiveFileName)
	if err != nil {
		return verifiedActivationInputs{}, fmt.Errorf("locate activation archive: %w", err)
	}
	return verifyActivationInputBytes(
		planRaw, releaseRaw, policyRaw, intentRaw, archivePath, trust, now,
	)
}

// verifyActivationInputsAt re-evaluates the immutable release, capsule, and
// site-policy inputs at an authenticated receipt time. Local state checkpoints
// remain useful for resumability, but they are not proof of historical
// authorization.
func verifyActivationInputsAt(
	store *activationstore.Store,
	trust activationTrust,
	expected verifiedActivationInputs,
	at time.Time,
) error {
	if at.IsZero() {
		return errors.New("activation authorization time is unavailable")
	}
	verified, err := loadVerifiedActivationInputs(store, trust, at.UTC())
	if err != nil {
		return fmt.Errorf("activation inputs were not valid at authorization time: %w", err)
	}
	if !bytes.Equal(verified.planRaw, expected.planRaw) ||
		!bytes.Equal(verified.releaseRaw, expected.releaseRaw) ||
		!bytes.Equal(verified.policyRaw, expected.policyRaw) ||
		!bytes.Equal(verified.intentRaw, expected.intentRaw) ||
		verified.archivePath != expected.archivePath {
		return errors.New("activation inputs changed during authorization-time verification")
	}
	return nil
}

func verifyActivationInputsAtSignedTime(
	store *activationstore.Store,
	trust activationTrust,
	expected verifiedActivationInputs,
	observedAt string,
) error {
	at, err := canonicalActivationTime(observedAt)
	if err != nil {
		return fmt.Errorf("parse signed Gateway authorization time: %w", err)
	}
	return verifyActivationInputsAt(store, trust, expected, at)
}

func validateBaselineWitness(
	raw []byte,
	witnessPublic ed25519.PublicKey,
	nodeID string,
) (controlprotocol.ExecutorEvidenceExportV1, error) {
	export, err := controlprotocol.DecodeExecutorEvidenceExportV1(raw)
	if err != nil {
		return controlprotocol.ExecutorEvidenceExportV1{}, fmt.Errorf("decode baseline controller witness: %w", err)
	}
	if err := controlprotocol.VerifyExecutorEvidenceExportV1(export, witnessPublic); err != nil {
		return controlprotocol.ExecutorEvidenceExportV1{}, fmt.Errorf("verify baseline controller witness: %w", err)
	}
	status := export.Statement.Status
	if status.State != controlprotocol.ExecutorEvidenceStatusCurrent ||
		status.Head == nil || status.Finding != nil ||
		status.Head.ReceiptNodeID != nodeID {
		return controlprotocol.ExecutorEvidenceExportV1{}, errors.New("baseline controller witness is not a current finding-free checkpoint for this node")
	}
	return export, nil
}

func loadActivationStateChain(
	store *activationstore.Store,
	inputs verifiedActivationInputs,
) (activationStateChain, error) {
	names, err := store.ListStateCheckpoints()
	if err != nil {
		return activationStateChain{}, err
	}
	if len(names) == 0 {
		return activationStateChain{}, errors.New("activation workspace has no state checkpoint")
	}
	chain := activationStateChain{names: names}
	for index, name := range names {
		expected, err := activationstore.StateCheckpointName(uint64(index))
		if err != nil || name != expected {
			return activationStateChain{}, errors.New("activation state checkpoints are not contiguous from zero")
		}
		raw, err := store.Read(name, activation.MaxStateBytes)
		if err != nil {
			return activationStateChain{}, fmt.Errorf("read activation state %q: %w", name, err)
		}
		state, err := activation.ParseStateV1(raw)
		if err != nil {
			return activationStateChain{}, fmt.Errorf("parse activation state %q: %w", name, err)
		}
		if index > 0 {
			if err := activation.ValidateStateTransitionV1(chain.states[index-1], state); err != nil {
				return activationStateChain{}, fmt.Errorf("validate activation state %q: %w", name, err)
			}
		}
		chain.raw = append(chain.raw, raw)
		chain.states = append(chain.states, state)
	}
	initial := chain.states[0]
	planDigest, _ := activation.PlanDigestV1(inputs.planRaw)
	if initial.Phase != activation.PhaseNew ||
		initial.Binding.ActivationID != inputs.plan.ActivationID ||
		initial.Binding.PlanDigest != planDigest ||
		initial.Binding.ReleaseDigest != inputs.plan.ReleaseDigest ||
		initial.Binding.PolicyDigest != inputs.plan.PolicyDigest ||
		initial.Binding.IntentDigest != inputs.plan.IntentDigest ||
		initial.Binding.Archive != inputs.plan.Archive ||
		initial.Binding.TenantID != inputs.intent.TenantID ||
		initial.Binding.NodeID != inputs.intent.NodeID ||
		initial.Binding.InstanceID != inputs.intent.InstanceID ||
		initial.Binding.Generation != inputs.intent.Generation {
		return activationStateChain{}, errors.New("initial activation state does not match the immutable plan and intent")
	}
	return chain, nil
}

// activationInputVerificationTime selects the local release-verification
// checkpoint used to resume an activation. This timestamp is not proof of
// historical authorization: completed evidence is re-evaluated at Gateway's
// signed authorization receipt time.
func activationInputVerificationTime(
	chain activationStateChain,
	latestAllowed time.Time,
) (time.Time, error) {
	if latestAllowed.IsZero() {
		return time.Time{}, errors.New("activation verification-time ceiling is unavailable")
	}
	initialAt, err := canonicalActivationTime(chain.states[0].UpdatedAt)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse initial activation checkpoint time: %w", err)
	}
	if chain.latest().Phase == activation.PhaseNew {
		selected := latestAllowed.UTC()
		if !selected.After(initialAt) {
			selected = initialAt.Add(time.Nanosecond)
		}
		return selected, nil
	}
	if len(chain.states) < 2 ||
		chain.states[1].Phase != activation.PhaseReleaseVerified {
		return time.Time{}, errors.New("activation has no release_verified authority checkpoint")
	}
	verifiedAt, err := canonicalActivationTime(chain.states[1].UpdatedAt)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse release verification checkpoint time: %w", err)
	}
	if verifiedAt.After(latestAllowed.UTC()) {
		return time.Time{}, errors.New("release verification checkpoint is after the verification-time ceiling")
	}
	return verifiedAt, nil
}

func activationStateChainsEqual(
	left, right activationStateChain,
) bool {
	if !slices.Equal(left.names, right.names) ||
		len(left.raw) != len(right.raw) {
		return false
	}
	for index := range left.raw {
		if !bytes.Equal(left.raw[index], right.raw[index]) {
			return false
		}
	}
	return true
}

func appendActivationStateAt(
	store *activationstore.Store,
	chain *activationStateChain,
	phase string,
	runtimeReference string,
	reason string,
	selectedTime time.Time,
) error {
	if selectedTime.IsZero() {
		return errors.New("activation state update time is unavailable")
	}
	current := chain.latest()
	next := current
	next.Phase = phase
	next.ActionRequiredReason = reason
	if runtimeReference != "" {
		next.RuntimeRef = runtimeReference
	}
	currentTime, err := time.Parse(time.RFC3339Nano, current.UpdatedAt)
	if err != nil {
		return err
	}
	nextTime := selectedTime.UTC()
	if !nextTime.After(currentTime) {
		nextTime = currentTime.Add(time.Nanosecond)
	}
	next.UpdatedAt = nextTime.Format(time.RFC3339Nano)
	raw, err := activation.MarshalStateV1(next)
	if err != nil {
		return err
	}
	if err := activation.ValidateStateTransitionV1(current, next); err != nil {
		return err
	}
	name, err := store.AppendState(uint64(len(chain.states)), raw)
	if err != nil {
		return err
	}
	chain.names = append(chain.names, name)
	chain.raw = append(chain.raw, raw)
	chain.states = append(chain.states, next)
	return nil
}

func appendActivationState(
	store *activationstore.Store,
	chain *activationStateChain,
	phase string,
	runtimeReference string,
	reason string,
) error {
	return appendActivationStateAt(
		store, chain, phase, runtimeReference, reason, timeNow().UTC(),
	)
}

func (chain activationStateChain) latest() activation.StateV1 {
	return chain.states[len(chain.states)-1]
}

func (chain activationStateChain) latestRaw() []byte {
	return chain.raw[len(chain.raw)-1]
}

func (chain activationStateChain) phaseTime(phase string) (string, error) {
	for _, state := range chain.states {
		if state.Phase == phase {
			return state.UpdatedAt, nil
		}
	}
	return "", fmt.Errorf("activation state chain has no %s checkpoint", phase)
}

func writeActivationArtifact(
	store *activationstore.Store,
	name string,
	raw []byte,
	external bool,
) error {
	var err error
	if external {
		err = store.Import(name, raw)
	} else {
		err = store.WriteOnce(name, raw)
	}
	if !errors.Is(err, activationstore.ErrAlreadyExists) {
		return err
	}
	existing, readErr := store.Read(name, activationstore.MaxSmallArtifactBytes)
	if readErr != nil {
		return readErr
	}
	if !bytes.Equal(existing, raw) {
		return &activationArtifactConflictError{name: name}
	}
	return nil
}

type activationArtifactConflictError struct {
	name string
}

func (err *activationArtifactConflictError) Error() string {
	return fmt.Sprintf(
		"activation artifact %q already exists with different bytes",
		err.name,
	)
}

func readOptionalActivationArtifact(
	store *activationstore.Store,
	name string,
	limit int64,
) ([]byte, bool, error) {
	raw, err := store.Read(name, limit)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return raw, true, nil
}

func activationTaskAuthorities(state permitAdmission) ([]activation.TaskAuthorityPinV1, error) {
	authorities := make([]activation.TaskAuthorityPinV1, 0, len(state.TaskAuthorities))
	for _, authority := range state.TaskAuthorities {
		raw, err := base64.StdEncoding.DecodeString(authority.PublicKey)
		if err != nil || len(raw) != ed25519.PublicKeySize ||
			base64.StdEncoding.EncodeToString(raw) != authority.PublicKey {
			return nil, errors.New("admission returned an invalid task-authority public key")
		}
		authorities = append(authorities, activation.TaskAuthorityPinV1{
			KeyID:           authority.KeyID,
			PublicKeySHA256: controlprotocol.ExecutorEvidencePublicKeySHA256(ed25519.PublicKey(raw)),
		})
	}
	sort.Slice(authorities, func(i, j int) bool {
		return authorities[i].KeyID < authorities[j].KeyID
	})
	return authorities, nil
}

func writeActivationStatus(
	stdout io.Writer,
	inputs verifiedActivationInputs,
	chain activationStateChain,
	verified bool,
	waitingFor, nextCommand, proofDigest string,
) error {
	output := activationStatusOutput{
		SchemaVersion: activationStatusSchemaV1,
		ActivationID:  inputs.plan.ActivationID,
		Phase:         chain.latest().Phase,
		StateSequence: uint64(len(chain.states) - 1),
		RuntimeRef:    chain.latest().RuntimeRef,
		WaitingFor:    waitingFor, NextCommand: nextCommand,
		ProofDigest: proofDigest, Verified: verified,
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(output)
}
