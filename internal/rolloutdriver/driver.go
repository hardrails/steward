// Package rolloutdriver constructs the finite signed artifacts used by the
// trusted, owner-side rollout coordinator. It performs no I/O and exposes no
// generic command, workflow, or agent execution surface.
package rolloutdriver

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"sort"
	"time"

	"github.com/hardrails/steward/internal/activation"
	"github.com/hardrails/steward/internal/activationcanary"
	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/agentrelease"
	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/executor"
	"github.com/hardrails/steward/internal/executoruplink"
	"github.com/hardrails/steward/internal/gateway"
	"github.com/hardrails/steward/internal/rollout"
	"github.com/hardrails/steward/internal/taskpermit"
)

const (
	activationAdmissionSchemaV1 = "steward.executor-activation-admission.v1"
	maxAdmissionPayloadBytes    = 256 << 10

	egressProxyV1  = "http://steward-relay:8082"
	connectorURLV1 = "http://steward-relay:8081"
)

var ErrInvalid = errors.New("invalid rollout driver input")

// PrepareInputV1 contains authenticated, immutable companions for one indexed
// rollout target. VerifiedCapsule must be the value returned by
// admission.VerifyCapsuleForImport for the exact CapsuleEnvelope bytes.
type PrepareInputV1 struct {
	PlanRaw            []byte
	TargetIndex        uint16
	IntentRaw          []byte
	CapsuleEnvelope    []byte
	VerifiedCapsule    admission.VerifiedCapsuleImport
	ActivationTimeouts activation.TimeoutsV1
}

// PreparedTargetV1 is an opaque, immutable preparation result. Byte accessors
// return detached copies so signed inputs cannot change after validation.
type PreparedTargetV1 struct {
	plan                rollout.PlanV1
	target              rollout.TargetV1
	targetIndex         uint16
	intent              admission.InstanceIntent
	activationPlan      activation.PlanV1
	activationPlanRaw   []byte
	binding             activation.BindingV1
	executorBeginRaw    []byte
	executorBeginDigest string
	admissionPayloadRaw []byte
	runtimeRef          string
	outerRuntimeRef     string
	stateRuntimeRef     string
	capsuleDigest       string
	capsuleExpiresAt    time.Time
	expectedTaskKeys    []controlprotocol.ExecutorTaskAuthorityV1
	commandAuthorities  map[string]map[string]ed25519.PublicKey
}

type activationAdmissionV1 struct {
	SchemaVersion string `json:"schema_version"`
	ActivationID  string `json:"activation_id"`
	BeginDigest   string `json:"begin_digest"`
}

type admissionPayloadV1 struct {
	CapsuleDSSEBase64 string                   `json:"capsule_dsse_base64"`
	Intent            admission.InstanceIntent `json:"intent"`
	Activation        activationAdmissionV1    `json:"activation"`
}

// PrepareTargetV1 validates every available rollout, admission, capsule, and
// policy binding before constructing the exact deterministic artifacts needed
// by protocol 4 admission.
func PrepareTargetV1(input PrepareInputV1) (PreparedTargetV1, error) {
	plan, err := rollout.ParsePlanV1(input.PlanRaw)
	if err != nil {
		return PreparedTargetV1{}, invalid("rollout plan: %v", err)
	}
	if int(input.TargetIndex) >= len(plan.Targets) {
		return PreparedTargetV1{}, invalid("target index is outside the rollout plan")
	}
	target := plan.Targets[input.TargetIndex]

	if target.IntentDigest != dsse.Digest(input.IntentRaw) {
		return PreparedTargetV1{}, invalid("target does not identify the exact intent bytes")
	}
	var intent admission.InstanceIntent
	if err := dsse.DecodeStrictInto(input.IntentRaw, dsse.MaxPayloadBytes, &intent); err != nil {
		return PreparedTargetV1{}, invalid("decode instance intent: %v", err)
	}
	caller := admission.AuthenticatedIdentity{TenantID: plan.TenantID, NodeID: target.NodeID}
	if err := intent.Validate(caller); err != nil {
		return PreparedTargetV1{}, invalid("validate instance intent: %v", err)
	}
	if intent.TenantID != plan.TenantID || intent.NodeID != target.NodeID ||
		intent.InstanceID != target.InstanceID || intent.Generation != target.InstanceGeneration {
		return PreparedTargetV1{}, invalid("intent identity or generation does not match the indexed target")
	}

	if err := validateVerifiedCapsule(input.CapsuleEnvelope, input.VerifiedCapsule); err != nil {
		return PreparedTargetV1{}, err
	}
	if input.VerifiedCapsule.PolicyDigest != plan.PolicyDigest ||
		intent.CapsuleDigest != input.VerifiedCapsule.CapsuleDigest {
		return PreparedTargetV1{}, invalid("capsule, policy, and intent digests disagree")
	}
	effective, err := admission.Intersect(
		input.VerifiedCapsule.Capsule,
		input.VerifiedCapsule.CapsuleDigest,
		input.VerifiedCapsule.SitePolicy,
		input.VerifiedCapsule.PolicyDigest,
		input.VerifiedCapsule.PublisherKeyID,
		input.VerifiedCapsule.SiteRootKeyID,
		intent,
		caller,
		admission.PersistedFences{},
		admission.DefaultProfiles(),
	)
	if err != nil {
		return PreparedTargetV1{}, invalid("preflight signed admission: %v", err)
	}
	if effective.Intent.StateDisposition != "new" ||
		!effective.Intent.Capabilities.State || !effective.Intent.Capabilities.Service ||
		effective.Intent.ServiceID != agentrelease.HermesServiceID ||
		!effective.Capsule.Capabilities.State || !effective.Capsule.Capabilities.Service ||
		effective.Capsule.Service.ID != agentrelease.HermesServiceID {
		return PreparedTargetV1{}, invalid("target is not the fresh-state Hermes service contract")
	}

	activationPlan := activation.PlanV1{
		SchemaVersion: activation.PlanSchemaV1,
		ActivationID:  target.ActivationID,
		ReleaseDigest: plan.ReleaseDigest,
		PolicyDigest:  plan.PolicyDigest,
		IntentDigest:  target.IntentDigest,
		Archive:       plan.Archive,
		Transport:     activation.TransportControlUplink,
		Canary:        plan.Canary,
		Timeouts:      input.ActivationTimeouts,
	}
	activationPlanRaw, err := activation.MarshalPlanV1(activationPlan)
	if err != nil {
		return PreparedTargetV1{}, invalid("construct activation plan: %v", err)
	}
	if dsse.Digest(activationPlanRaw) != target.ActivationPlanDigest {
		return PreparedTargetV1{}, invalid("constructed activation plan does not match target activation_plan_digest")
	}
	binding := activation.BindingV1{
		ActivationID:  target.ActivationID,
		PlanDigest:    target.ActivationPlanDigest,
		ReleaseDigest: plan.ReleaseDigest,
		PolicyDigest:  plan.PolicyDigest,
		IntentDigest:  target.IntentDigest,
		Archive:       plan.Archive,
		TenantID:      plan.TenantID,
		NodeID:        target.NodeID,
		InstanceID:    target.InstanceID,
		Generation:    target.InstanceGeneration,
	}
	runtimeRef := executor.RuntimeRef(plan.TenantID, target.InstanceID)
	stateRuntimeRef := executor.StateVolumeName(plan.TenantID, intent.LineageID)
	executorBeginRaw, err := activation.MarshalExecutorBeginV1(
		binding, runtimeRef, stateRuntimeRef, input.VerifiedCapsule.CapsuleDigest,
	)
	if err != nil {
		return PreparedTargetV1{}, invalid("construct Executor begin marker: %v", err)
	}
	executorBeginDigest, err := activation.ExecutorBeginDigestV1(executorBeginRaw)
	if err != nil {
		return PreparedTargetV1{}, invalid("validate Executor begin marker: %v", err)
	}
	outerRuntimeRef, err := executoruplink.RuntimeRefV2(
		plan.TenantID, target.NodeID, target.InstanceID,
	)
	if err != nil {
		return PreparedTargetV1{}, invalid("construct signed-command runtime reference: %v", err)
	}

	payload := admissionPayloadV1{
		CapsuleDSSEBase64: base64.StdEncoding.EncodeToString(input.CapsuleEnvelope),
		Intent:            intent,
		Activation: activationAdmissionV1{
			SchemaVersion: activationAdmissionSchemaV1,
			ActivationID:  target.ActivationID,
			BeginDigest:   executorBeginDigest,
		},
	}
	admissionPayloadRaw, err := json.Marshal(payload)
	if err != nil || len(admissionPayloadRaw) > maxAdmissionPayloadBytes {
		return PreparedTargetV1{}, invalid("construct bounded signed-admission payload")
	}
	var parsedPayload admissionPayloadV1
	if err := dsse.DecodeStrictInto(admissionPayloadRaw, maxAdmissionPayloadBytes, &parsedPayload); err != nil ||
		!reflect.DeepEqual(parsedPayload, payload) {
		return PreparedTargetV1{}, invalid("self-verify signed-admission payload: %v", err)
	}

	expectedTaskKeys, err := taskAuthorities(effective.SitePolicy, plan.TenantID)
	if err != nil {
		return PreparedTargetV1{}, err
	}
	commandAuthorities := make(map[string]map[string]ed25519.PublicKey, 3)
	for _, kind := range []string{"admit", "start", "activation-canary"} {
		trusted, err := effective.SitePolicy.TrustedCommandKeys(plan.TenantID, kind)
		if err != nil || len(trusted) == 0 {
			return PreparedTargetV1{}, invalid("site policy has no command authority for %s: %v", kind, err)
		}
		commandAuthorities[kind] = cloneKeys(trusted)
	}
	var capsuleExpiresAt time.Time
	if effective.Capsule.ExpiresAt != "" {
		capsuleExpiresAt, err = time.Parse(time.RFC3339, effective.Capsule.ExpiresAt)
		if err != nil {
			return PreparedTargetV1{}, invalid("authenticated capsule expiry is invalid: %v", err)
		}
		capsuleExpiresAt = capsuleExpiresAt.UTC()
	}

	return PreparedTargetV1{
		plan:                clonePlan(plan),
		target:              target,
		targetIndex:         input.TargetIndex,
		intent:              cloneIntent(intent),
		activationPlan:      activationPlan,
		activationPlanRaw:   append([]byte(nil), activationPlanRaw...),
		binding:             binding,
		executorBeginRaw:    append([]byte(nil), executorBeginRaw...),
		executorBeginDigest: executorBeginDigest,
		admissionPayloadRaw: append([]byte(nil), admissionPayloadRaw...),
		runtimeRef:          runtimeRef,
		outerRuntimeRef:     outerRuntimeRef,
		stateRuntimeRef:     stateRuntimeRef,
		capsuleDigest:       input.VerifiedCapsule.CapsuleDigest,
		capsuleExpiresAt:    capsuleExpiresAt,
		expectedTaskKeys:    append([]controlprotocol.ExecutorTaskAuthorityV1(nil), expectedTaskKeys...),
		commandAuthorities:  commandAuthorities,
	}, nil
}

func validateVerifiedCapsule(raw []byte, verified admission.VerifiedCapsuleImport) error {
	if len(raw) == 0 || len(raw) > dsse.DefaultMaxEnvelopeBytes ||
		verified.CapsuleDigest != dsse.Digest(raw) || verified.PublisherKeyID == "" ||
		verified.SiteRootKeyID == "" {
		return invalid("authenticated capsule identity does not match the exact envelope")
	}
	envelope, err := dsse.Parse(raw)
	if err != nil || envelope.PayloadType != admission.CapsulePayloadType {
		return invalid("parse authenticated capsule envelope: %v", err)
	}
	payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil || base64.StdEncoding.EncodeToString(payload) != envelope.Payload {
		return invalid("authenticated capsule payload is not canonical base64")
	}
	var capsule admission.ProfileCapsule
	if err := dsse.DecodeStrictInto(payload, dsse.MaxPayloadBytes, &capsule); err != nil {
		return invalid("decode authenticated capsule payload: %v", err)
	}
	if !reflect.DeepEqual(capsule, verified.Capsule) || capsule.PublisherKeyID != verified.PublisherKeyID {
		return invalid("authenticated capsule value does not match the exact envelope payload")
	}
	if err := verified.SitePolicy.Validate(); err != nil {
		return invalid("authenticated site policy: %v", err)
	}
	return nil
}

func taskAuthorities(policy admission.SitePolicy, tenantID string) ([]controlprotocol.ExecutorTaskAuthorityV1, error) {
	keys, err := policy.TrustedTaskKeys(tenantID, agentrelease.HermesServiceID)
	if err != nil || len(keys) == 0 {
		return nil, invalid("site policy has no Hermes task authority: %v", err)
	}
	ids := make([]string, 0, len(keys))
	for id := range keys {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	authorities := make([]controlprotocol.ExecutorTaskAuthorityV1, 0, len(ids))
	for _, id := range ids {
		authorities = append(authorities, controlprotocol.ExecutorTaskAuthorityV1{
			KeyID: id, PublicKey: base64.StdEncoding.EncodeToString(keys[id]),
		})
	}
	return authorities, nil
}

func clonePlan(plan rollout.PlanV1) rollout.PlanV1 {
	plan.Targets = append([]rollout.TargetV1(nil), plan.Targets...)
	return plan
}

func cloneIntent(intent admission.InstanceIntent) admission.InstanceIntent {
	intent.EgressRouteIDs = append([]string(nil), intent.EgressRouteIDs...)
	intent.ConnectorIDs = append([]string(nil), intent.ConnectorIDs...)
	return intent
}

func cloneKeys(keys map[string]ed25519.PublicKey) map[string]ed25519.PublicKey {
	cloned := make(map[string]ed25519.PublicKey, len(keys))
	for id, key := range keys {
		cloned[id] = append(ed25519.PublicKey(nil), key...)
	}
	return cloned
}

// Accessors return validated values or detached byte/slice copies.
func (prepared PreparedTargetV1) Plan() rollout.PlanV1     { return clonePlan(prepared.plan) }
func (prepared PreparedTargetV1) Target() rollout.TargetV1 { return prepared.target }
func (prepared PreparedTargetV1) TargetIndex() uint16      { return prepared.targetIndex }
func (prepared PreparedTargetV1) Intent() admission.InstanceIntent {
	return cloneIntent(prepared.intent)
}
func (prepared PreparedTargetV1) ActivationPlan() activation.PlanV1 { return prepared.activationPlan }
func (prepared PreparedTargetV1) ActivationPlanRaw() []byte {
	return append([]byte(nil), prepared.activationPlanRaw...)
}
func (prepared PreparedTargetV1) Binding() activation.BindingV1 { return prepared.binding }
func (prepared PreparedTargetV1) ExecutorBeginRaw() []byte {
	return append([]byte(nil), prepared.executorBeginRaw...)
}
func (prepared PreparedTargetV1) ExecutorBeginDigest() string { return prepared.executorBeginDigest }
func (prepared PreparedTargetV1) AdmissionPayloadRaw() []byte {
	return append([]byte(nil), prepared.admissionPayloadRaw...)
}
func (prepared PreparedTargetV1) RuntimeRef() string      { return prepared.runtimeRef }
func (prepared PreparedTargetV1) OuterRuntimeRef() string { return prepared.outerRuntimeRef }
func (prepared PreparedTargetV1) StateRuntimeRef() string { return prepared.stateRuntimeRef }
func (prepared PreparedTargetV1) CapsuleDigest() string   { return prepared.capsuleDigest }

// SigningWindowV1 supplies one policy-authorized command key and a bounded
// validity window. IssuedAt is the coordinator's trusted current time.
type SigningWindowV1 struct {
	KeyID      string
	PrivateKey ed25519.PrivateKey
	PublicKey  ed25519.PublicKey
	IssuedAt   time.Time
	ValidFor   time.Duration
}

// SignedCommandV1 retains the exact canonical DSSE bytes and their self-verified
// statement.
type SignedCommandV1 struct {
	raw       []byte
	statement admission.CommandStatement
}

func (command SignedCommandV1) Raw() []byte { return append([]byte(nil), command.raw...) }
func (command SignedCommandV1) Statement() admission.CommandStatement {
	statement := command.statement
	statement.Payload = append(json.RawMessage(nil), command.statement.Payload...)
	return statement
}

// SignAdmissionCommandV1 signs the exact prepared protocol-4 admission as
// sequence one and the target's predetermined admission command identity.
func SignAdmissionCommandV1(prepared PreparedTargetV1, window SigningWindowV1) (SignedCommandV1, error) {
	return signCommand(prepared, "admit", prepared.target.AdmitCommandID, 1, prepared.admissionPayloadRaw, window)
}

// SignStartCommandV1 signs only the exact empty lifecycle object as sequence
// two and the target's predetermined start command identity.
func SignStartCommandV1(prepared PreparedTargetV1, window SigningWindowV1) (SignedCommandV1, error) {
	return signCommand(prepared, "start", prepared.target.StartCommandID, 2, []byte(`{}`), window)
}

func signCommand(
	prepared PreparedTargetV1,
	kind, commandID string,
	sequence uint64,
	payload []byte,
	window SigningWindowV1,
) (SignedCommandV1, error) {
	issued, expires, err := validateSigningWindow(prepared, kind, window)
	if err != nil {
		return SignedCommandV1{}, err
	}
	statement := admission.CommandStatement{
		SchemaVersion:      admission.CommandSchemaV2,
		CommandID:          commandID,
		TenantID:           prepared.plan.TenantID,
		NodeID:             prepared.target.NodeID,
		InstanceID:         prepared.target.InstanceID,
		RuntimeRef:         prepared.outerRuntimeRef,
		Kind:               kind,
		ClaimGeneration:    prepared.target.ClaimGeneration,
		InstanceGeneration: prepared.target.InstanceGeneration,
		CommandSequence:    sequence,
		IssuedAt:           issued.Format(time.RFC3339Nano),
		ExpiresAt:          expires.Format(time.RFC3339Nano),
		Payload:            append(json.RawMessage(nil), payload...),
	}
	if err := statement.Validate(issued); err != nil {
		return SignedCommandV1{}, invalid("validate %s command: %v", kind, err)
	}
	payloadRaw, err := json.Marshal(statement)
	if err != nil {
		return SignedCommandV1{}, invalid("marshal %s command: %v", kind, err)
	}
	envelope, err := dsse.Sign(admission.CommandPayloadType, payloadRaw, window.KeyID, window.PrivateKey)
	if err != nil {
		return SignedCommandV1{}, invalid("sign %s command: %v", kind, err)
	}
	raw, err := dsse.Marshal(envelope)
	if err != nil {
		return SignedCommandV1{}, invalid("marshal %s command envelope: %v", kind, err)
	}
	verifiedPayload, keyID, err := dsse.Verify(
		raw, admission.CommandPayloadType,
		map[string]ed25519.PublicKey{window.KeyID: window.PublicKey},
	)
	if err != nil || keyID != window.KeyID || !bytes.Equal(verifiedPayload, payloadRaw) {
		return SignedCommandV1{}, invalid("self-verify %s command signature: %v", kind, err)
	}
	var parsed admission.CommandStatement
	if err := dsse.DecodeStrictInto(verifiedPayload, dsse.MaxPayloadBytes, &parsed); err != nil ||
		!reflect.DeepEqual(parsed, statement) {
		return SignedCommandV1{}, invalid("self-verify %s command statement: %v", kind, err)
	}
	canonical, err := dsse.Marshal(envelope)
	if err != nil || !bytes.Equal(canonical, raw) {
		return SignedCommandV1{}, invalid("%s command envelope is not canonical", kind)
	}
	return SignedCommandV1{raw: raw, statement: statement}, nil
}

func validateSigningWindow(
	prepared PreparedTargetV1,
	kind string,
	window SigningWindowV1,
) (time.Time, time.Time, error) {
	if len(window.PrivateKey) != ed25519.PrivateKeySize || len(window.PublicKey) != ed25519.PublicKeySize ||
		window.IssuedAt.IsZero() || window.ValidFor <= 0 {
		return time.Time{}, time.Time{}, invalid("%s signing key or validity window is unavailable", kind)
	}
	derived, ok := window.PrivateKey.Public().(ed25519.PublicKey)
	if !ok || !bytes.Equal(derived, window.PublicKey) {
		return time.Time{}, time.Time{}, invalid("%s private and public command keys do not match", kind)
	}
	trusted, ok := prepared.commandAuthorities[kind]
	if !ok {
		return time.Time{}, time.Time{}, invalid("unsupported rollout command kind %q", kind)
	}
	authorized, ok := trusted[window.KeyID]
	if !ok || !bytes.Equal(authorized, window.PublicKey) {
		return time.Time{}, time.Time{}, invalid("command key is not authorized by the authenticated site policy for %s", kind)
	}
	issued := window.IssuedAt.UTC()
	expires := issued.Add(window.ValidFor)
	rolloutCreated, createdErr := time.Parse(time.RFC3339Nano, prepared.plan.CreatedAt)
	rolloutDeadline, err := time.Parse(time.RFC3339Nano, prepared.plan.Deadline)
	if createdErr != nil || err != nil || issued.Before(rolloutCreated) ||
		!rolloutDeadline.After(issued) || expires.After(rolloutDeadline) {
		return time.Time{}, time.Time{}, invalid("%s command validity is outside the rollout interval", kind)
	}
	if !prepared.capsuleExpiresAt.IsZero() && expires.After(prepared.capsuleExpiresAt) {
		return time.Time{}, time.Time{}, invalid("%s command validity exceeds the authenticated capsule expiry", kind)
	}
	return issued, expires, nil
}

// CanaryInputV1 supplies only the finite authorities needed for the closed
// Hermes workspace-audit canary.
type CanaryInputV1 struct {
	Prepared              PreparedTargetV1
	Admission             controlprotocol.ExecutorAdmissionProjectionV1
	TaskKeyID             string
	TaskPrivateKey        ed25519.PrivateKey
	TaskPublicKey         ed25519.PublicKey
	OperationPolicyDigest string
	ReceiptAuthority      activationcanary.ReceiptAuthorityV1
	Deadline              time.Time
	CommandWindow         SigningWindowV1
}

// CanaryArtifactsV1 contains the exact task permit, closed canary payload, and
// outer sequence-three command. Every component has been verified both live
// and historically before it is returned.
type CanaryArtifactsV1 struct {
	taskStatement taskpermit.Statement
	taskPermitRaw []byte
	canary        activationcanary.CommandV1
	canaryRaw     []byte
	outer         SignedCommandV1
}

func (artifacts CanaryArtifactsV1) TaskStatement() taskpermit.Statement {
	return artifacts.taskStatement
}
func (artifacts CanaryArtifactsV1) TaskPermitRaw() []byte {
	return append([]byte(nil), artifacts.taskPermitRaw...)
}
func (artifacts CanaryArtifactsV1) Canary() activationcanary.CommandV1 {
	return cloneCanary(artifacts.canary)
}
func (artifacts CanaryArtifactsV1) CanaryRaw() []byte {
	return append([]byte(nil), artifacts.canaryRaw...)
}
func (artifacts CanaryArtifactsV1) OuterCommand() SignedCommandV1 { return artifacts.outer }

// BuildCanaryCommandV1 creates the fixed Hermes request permit, the closed
// activation-canary payload, and the outer sequence-three command.
func BuildCanaryCommandV1(input CanaryInputV1) (CanaryArtifactsV1, error) {
	prepared := input.Prepared
	issued, outerExpires, err := validateSigningWindow(prepared, "activation-canary", input.CommandWindow)
	if err != nil {
		return CanaryArtifactsV1{}, err
	}
	if err := validateProjection(prepared, input.Admission); err != nil {
		return CanaryArtifactsV1{}, err
	}
	if len(input.TaskPrivateKey) != ed25519.PrivateKeySize || len(input.TaskPublicKey) != ed25519.PublicKeySize {
		return CanaryArtifactsV1{}, invalid("task signing key is unavailable")
	}
	derived, ok := input.TaskPrivateKey.Public().(ed25519.PublicKey)
	if !ok || !bytes.Equal(derived, input.TaskPublicKey) ||
		!projectionTrustsTaskKey(input.Admission, input.TaskKeyID, input.TaskPublicKey) {
		return CanaryArtifactsV1{}, invalid("task key does not match an admitted task authority")
	}
	if input.OperationPolicyDigest != prepared.target.OperationPolicyDigest {
		return CanaryArtifactsV1{}, invalid("operation policy digest does not match the rollout target")
	}
	if input.ReceiptAuthority.Epoch != prepared.target.GatewayReceiptEpoch ||
		input.ReceiptAuthority.PublicKeySHA256 != prepared.target.GatewayReceiptPublicKeySHA256 {
		return CanaryArtifactsV1{}, invalid("Gateway receipt authority does not match the rollout target")
	}
	if input.Deadline.IsZero() {
		return CanaryArtifactsV1{}, invalid("canary deadline is unavailable")
	}
	deadline := input.Deadline.UTC()
	permitNotBefore := issued.Truncate(time.Second)
	permitExpires := outerExpires.Truncate(time.Second)
	rolloutDeadline, _ := time.Parse(time.RFC3339Nano, prepared.plan.Deadline)
	canaryCeiling := issued.Add(
		time.Duration(prepared.activationPlan.Timeouts.CanarySeconds) * time.Second,
	)
	if !deadline.After(issued) || deadline.After(permitExpires) || deadline.After(outerExpires) ||
		deadline.After(rolloutDeadline) || deadline.After(canaryCeiling) ||
		!permitExpires.After(permitNotBefore) {
		return CanaryArtifactsV1{}, invalid("canary deadline, task permit, outer command, and rollout windows are incoherent")
	}
	request, err := agentrelease.BuildCanaryRequest(
		agentrelease.RequestRecipe{
			Input:           agentrelease.HermesWorkspaceAuditInput,
			SessionIDPrefix: agentrelease.HermesSessionIDPrefix,
		},
		prepared.target.ActivationID,
	)
	if err != nil {
		return CanaryArtifactsV1{}, invalid("construct fixed Hermes request: %v", err)
	}
	statement := taskpermit.Statement{
		SchemaVersion:         taskpermit.SchemaV1,
		NodeID:                prepared.target.NodeID,
		TenantID:              prepared.plan.TenantID,
		InstanceID:            prepared.target.InstanceID,
		RuntimeRef:            input.Admission.RuntimeRef,
		GrantID:               input.Admission.GrantID,
		Generation:            prepared.target.InstanceGeneration,
		CapsuleDigest:         input.Admission.CapsuleDigest,
		PolicyDigest:          input.Admission.PolicyDigest,
		RoutePolicyDigest:     input.Admission.RoutePolicyDigest,
		ServiceID:             agentrelease.HermesServiceID,
		OperationID:           agentrelease.HermesOperationID,
		OperationPolicyDigest: input.OperationPolicyDigest,
		TaskID:                prepared.target.CanaryCommandID,
		RequestDigest:         taskpermit.RequestDigest(request),
		RequestBytes:          int64(len(request)),
		ContentType:           "application/json",
		NotBefore:             permitNotBefore.Format(time.RFC3339),
		ExpiresAt:             permitExpires.Format(time.RFC3339),
	}
	statementRaw, err := json.Marshal(statement)
	if err != nil {
		return CanaryArtifactsV1{}, invalid("marshal task permit: %v", err)
	}
	permitEnvelope, err := dsse.Sign(
		taskpermit.PayloadType, statementRaw, input.TaskKeyID, input.TaskPrivateKey,
	)
	if err != nil {
		return CanaryArtifactsV1{}, invalid("sign task permit: %v", err)
	}
	permitRaw, err := dsse.Marshal(permitEnvelope)
	if err != nil {
		return CanaryArtifactsV1{}, invalid("marshal task permit: %v", err)
	}
	verifiedPermit, err := taskpermit.Verify(
		permitRaw,
		map[string]ed25519.PublicKey{input.TaskKeyID: input.TaskPublicKey},
		issued,
		taskpermit.MaxValidity,
	)
	if err != nil || verifiedPermit.Statement != statement || verifiedPermit.KeyID != input.TaskKeyID {
		return CanaryArtifactsV1{}, invalid("self-verify task permit: %v", err)
	}

	canaryRaw, canary, err := activationcanary.BuildCommandV1(activationcanary.CommandInputV1{
		ActivationID:       prepared.target.ActivationID,
		Admission:          input.Admission,
		ExecutorBegin:      prepared.executorBeginRaw,
		TaskPermitEnvelope: permitRaw,
		Deadline:           deadline,
		ReceiptAuthority:   input.ReceiptAuthority,
	})
	if err != nil {
		return CanaryArtifactsV1{}, invalid("construct closed canary: %v", err)
	}
	context := activationcanary.AdmissionContextV1{
		NodeID:     prepared.target.NodeID,
		TenantID:   prepared.plan.TenantID,
		InstanceID: prepared.target.InstanceID,
		Projection: input.Admission,
	}
	verifiedLive, err := activationcanary.VerifyCommandV1(
		canaryRaw, context, issued, taskpermit.MaxValidity,
	)
	if err != nil || verifiedLive.Permit().Statement != statement {
		return CanaryArtifactsV1{}, invalid("live self-verify closed canary: %v", err)
	}
	verifiedHistorical, err := activationcanary.VerifyHistoricalCommandV1(
		canaryRaw, context, taskpermit.MaxValidity,
	)
	if err != nil || verifiedHistorical.Permit().Statement != statement {
		return CanaryArtifactsV1{}, invalid("historical self-verify closed canary: %v", err)
	}
	outer, err := signCommand(
		prepared,
		"activation-canary",
		prepared.target.CanaryCommandID,
		3,
		canaryRaw,
		input.CommandWindow,
	)
	if err != nil {
		return CanaryArtifactsV1{}, err
	}
	return CanaryArtifactsV1{
		taskStatement: statement,
		taskPermitRaw: append([]byte(nil), permitRaw...),
		canary:        cloneCanary(canary),
		canaryRaw:     append([]byte(nil), canaryRaw...),
		outer:         outer,
	}, nil
}

// VerifyAdmissionV1 checks that a retained protocol-4 admission projection is
// the exact runtime, policy, grant, service, task-authority, route, and
// activation binding derived for prepared. It is intentionally side-effect
// free so a coordinator can qualify a terminal admit report before issuing a
// start command.
func VerifyAdmissionV1(
	prepared PreparedTargetV1,
	projection controlprotocol.ExecutorAdmissionProjectionV1,
) error {
	return validateProjection(prepared, projection)
}

func validateProjection(prepared PreparedTargetV1, projection controlprotocol.ExecutorAdmissionProjectionV1) error {
	if err := projection.Validate(); err != nil {
		return invalid("admission projection: %v", err)
	}
	expectedGrant := gateway.GrantID(
		prepared.plan.TenantID, prepared.target.InstanceID, prepared.target.InstanceGeneration,
	)
	if (projection.Status != "created" && projection.Status != "running") ||
		projection.RuntimeRef != prepared.runtimeRef || projection.CapsuleDigest != prepared.capsuleDigest ||
		projection.PolicyDigest != prepared.plan.PolicyDigest ||
		projection.Generation != prepared.target.InstanceGeneration ||
		projection.GrantID != expectedGrant ||
		projection.ServicePath != "/v1/services/"+expectedGrant+"/" ||
		projection.ServiceID != agentrelease.HermesServiceID ||
		!slices.Equal(projection.TaskAuthorities, prepared.expectedTaskKeys) ||
		projection.ActivationID != prepared.target.ActivationID ||
		projection.ActivationBeginDigest != prepared.executorBeginDigest {
		return invalid("admission projection does not match the exact prepared activation")
	}
	intent := prepared.intent
	if intent.Capabilities.Egress {
		if projection.EgressProxy != egressProxyV1 ||
			!slices.Equal(projection.EgressRouteIDs, admission.CanonicalRouteIDs(intent.EgressRouteIDs)) {
			return invalid("admission projection changed the requested egress grant")
		}
	} else if projection.EgressProxy != "" || len(projection.EgressRouteIDs) != 0 {
		return invalid("admission projection added unrequested egress authority")
	}
	if intent.Capabilities.Connector {
		if projection.ConnectorURL != connectorURLV1 ||
			!slices.Equal(projection.ConnectorIDs, admission.CanonicalConnectorIDs(intent.ConnectorIDs)) {
			return invalid("admission projection changed the requested connector grant")
		}
	} else if projection.ConnectorURL != "" || len(projection.ConnectorIDs) != 0 {
		return invalid("admission projection added unrequested connector authority")
	}
	return nil
}

func projectionTrustsTaskKey(
	projection controlprotocol.ExecutorAdmissionProjectionV1,
	keyID string,
	public ed25519.PublicKey,
) bool {
	encoded := base64.StdEncoding.EncodeToString(public)
	for _, authority := range projection.TaskAuthorities {
		if authority.KeyID == keyID && authority.PublicKey == encoded {
			return true
		}
	}
	return false
}

func cloneCanary(command activationcanary.CommandV1) activationcanary.CommandV1 {
	command.Admission.TaskAuthorities = append(
		[]controlprotocol.ExecutorTaskAuthorityV1(nil), command.Admission.TaskAuthorities...,
	)
	command.Admission.EgressRouteIDs = append([]string(nil), command.Admission.EgressRouteIDs...)
	command.Admission.ConnectorIDs = append([]string(nil), command.Admission.ConnectorIDs...)
	return command
}

func invalid(format string, arguments ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, arguments...))
}
