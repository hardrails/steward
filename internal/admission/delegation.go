package admission

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/dsse"
)

const (
	CommandDelegationPayloadType   = "application/vnd.steward.executor-command-delegation.v1+json"
	CommandDelegationSchemaV1      = "steward.executor-command-delegation.v1"
	maxCommandDelegationBytes      = 64 << 10
	maxCommandDelegationLifetime   = 24 * time.Hour
	maxForkDelegationLifetime      = 31 * 24 * time.Hour
	maxCommandDelegationNodes      = 64
	maxCommandDelegationInstances  = 128
	maxCommandPlacementLabels      = 32
	maxCommandPlacementTolerations = 32
)

// CommandDelegation grants one online controller key a finite subset of a
// tenant command key's authority. Executor verifies both signatures and every
// constraint locally; the controller cannot widen this statement.
type CommandDelegation struct {
	SchemaVersion       string                              `json:"schema_version"`
	DelegationID        string                              `json:"delegation_id"`
	TenantID            string                              `json:"tenant_id"`
	ControllerKeyID     string                              `json:"controller_key_id"`
	ControllerPublicKey string                              `json:"controller_public_key"`
	Operations          []string                            `json:"operations"`
	NodeIDs             []string                            `json:"node_ids"`
	Instances           []CommandDelegationInstance         `json:"instances"`
	ClaimGeneration     uint64                              `json:"claim_generation"`
	Admission           *CommandDelegationAdmissionTemplate `json:"admission,omitempty"`
	IssuedAt            string                              `json:"issued_at"`
	ExpiresAt           string                              `json:"expires_at"`
}

// CommandDelegationInstance is one exact workload identity and lineage the
// controller may place on an allowed node. A finite list makes the replica
// ceiling independently enforceable by every Executor without shared state.
type CommandDelegationInstance struct {
	InstanceID            string `json:"instance_id"`
	LineageID             string `json:"lineage_id"`
	MinInstanceGeneration uint64 `json:"min_instance_generation"`
	MaxInstanceGeneration uint64 `json:"max_instance_generation"`
}

// CommandDelegationAdmissionTemplate fixes every non-identity admission choice.
// The controller may select an allowed node and instance, but it cannot change
// resources, capabilities, routes, connectors, or state disposition.
type CommandDelegationAdmissionTemplate struct {
	CapsuleDigest    string                      `json:"capsule_digest"`
	Resources        ResourceLimits              `json:"resources"`
	Capabilities     Capabilities                `json:"capabilities"`
	StateDisposition string                      `json:"state_disposition"`
	InferenceRouteID string                      `json:"inference_route_id,omitempty"`
	ModelAlias       string                      `json:"model_alias,omitempty"`
	ServiceID        string                      `json:"service_id,omitempty"`
	EgressRouteIDs   []string                    `json:"egress_route_ids,omitempty"`
	ConnectorIDs     []string                    `json:"connector_ids,omitempty"`
	EffectMode       string                      `json:"effect_mode,omitempty"`
	Placement        *CommandDelegationPlacement `json:"placement,omitempty"`
}

// CommandDelegationPlacement is tenant-signed scheduling intent. It narrows
// where Control may place an instance but does not grant Executor authority.
type CommandDelegationPlacement struct {
	RequiredIsolation string                   `json:"required_isolation,omitempty"`
	RequiredAssurance string                   `json:"required_assurance,omitempty"`
	RequiredLabels    []CommandDelegationLabel `json:"required_labels"`
	PreferredLabels   []CommandDelegationLabel `json:"preferred_labels,omitempty"`
	SpreadBy          string                   `json:"spread_by,omitempty"`
	Tolerations       []string                 `json:"tolerations"`
}

type CommandDelegationLabel struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type VerifiedCommandDelegation struct {
	Statement      CommandDelegation
	EnvelopeDigest string
	SignerKeyID    string
	ControllerKey  ed25519.PublicKey
}

func (delegation CommandDelegation) Validate(now time.Time) error {
	if delegation.SchemaVersion != CommandDelegationSchemaV1 ||
		!routeID(delegation.DelegationID) || !bounded(delegation.TenantID, 128) ||
		!bounded(delegation.ControllerKeyID, 256) ||
		!bounded(delegation.ControllerPublicKey, 1024) {
		return deny("invalid command delegation identity")
	}
	if _, err := decodePublicKey(delegation.ControllerPublicKey); err != nil {
		return deny("invalid command delegation controller key")
	}
	controllerKey, _ := decodePublicKey(delegation.ControllerPublicKey)
	if base64.StdEncoding.EncodeToString(controllerKey) != delegation.ControllerPublicKey {
		return deny("command delegation controller key is not canonical base64")
	}
	if len(delegation.Operations) == 0 || len(delegation.Operations) > len(commandOperations) ||
		len(delegation.NodeIDs) == 0 || len(delegation.NodeIDs) > maxCommandDelegationNodes ||
		len(delegation.Instances) == 0 || len(delegation.Instances) > maxCommandDelegationInstances {
		return deny("invalid command delegation scope")
	}
	for index, operation := range delegation.Operations {
		if _, ok := commandOperations[operation]; !ok ||
			index > 0 && delegation.Operations[index-1] >= operation {
			return deny("command delegation operations are invalid or non-canonical")
		}
	}
	for index, nodeID := range delegation.NodeIDs {
		if !bounded(nodeID, 128) || index > 0 && delegation.NodeIDs[index-1] >= nodeID {
			return deny("command delegation nodes are invalid or non-canonical")
		}
	}
	lineages := make(map[string]struct{}, len(delegation.Instances))
	for index, instance := range delegation.Instances {
		if !bounded(instance.InstanceID, 256) || !bounded(instance.LineageID, 256) ||
			instance.MinInstanceGeneration == 0 ||
			instance.MaxInstanceGeneration < instance.MinInstanceGeneration ||
			index > 0 && delegation.Instances[index-1].InstanceID >= instance.InstanceID {
			return deny("command delegation instances are invalid or non-canonical")
		}
		if _, duplicate := lineages[instance.LineageID]; duplicate {
			return deny("command delegation lineages must be unique")
		}
		lineages[instance.LineageID] = struct{}{}
	}
	if delegation.ClaimGeneration == 0 {
		return deny("invalid command delegation claim generation")
	}
	if contains(delegation.Operations, "admit") != (delegation.Admission != nil) {
		return deny("command delegation admission template must match admit authority")
	}
	if delegation.Admission != nil {
		if err := delegation.Admission.Validate(); err != nil {
			return err
		}
	}
	issued, err := time.Parse(time.RFC3339Nano, delegation.IssuedAt)
	if err != nil {
		return deny("invalid command delegation issue time")
	}
	expires, err := time.Parse(time.RFC3339Nano, delegation.ExpiresAt)
	maxLifetime := maxCommandDelegationLifetime
	if len(delegation.NodeIDs) == 1 && len(delegation.Instances) == 1 && delegation.Admission != nil &&
		delegation.Admission.StateDisposition == "resume" &&
		contains(delegation.Operations, "clone-state") && contains(delegation.Operations, "purge") {
		maxLifetime = maxForkDelegationLifetime
	}
	if err != nil || !expires.After(issued) || expires.Sub(issued) > maxLifetime {
		return deny("invalid command delegation expiry")
	}
	if !now.IsZero() {
		if issued.After(now.Add(maxCommandClockSkew)) {
			return deny("command delegation issue time is too far in the future")
		}
		if !expires.After(now) {
			return deny("command delegation has expired according to node time")
		}
	}
	return nil
}

// Validate checks that a delegated admission template has one canonical,
// finite representation. Site policy and the signed capsule remain the final
// authority for whether the exact request is admissible.
func (template CommandDelegationAdmissionTemplate) Validate() error {
	if !digest(template.CapsuleDigest) || template.Resources.Validate() != nil ||
		!validDelegatedCapabilityFields(template) ||
		!canonicalDelegatedIDs(template.EgressRouteIDs, 32) ||
		!canonicalDelegatedIDs(template.ConnectorIDs, 32) {
		return deny("invalid command delegation admission template")
	}
	if template.Placement != nil && !validCommandDelegationPlacement(*template.Placement) {
		return deny("invalid command delegation placement")
	}
	return nil
}

func validCommandDelegationPlacement(placement CommandDelegationPlacement) bool {
	if placement.RequiredIsolation != "" && placement.RequiredIsolation != "gvisor" ||
		placement.RequiredAssurance != "" && placement.RequiredAssurance != controlprotocol.RuntimeAssuranceSharedHost &&
			placement.RequiredAssurance != controlprotocol.RuntimeAssuranceDedicatedHost ||
		placement.RequiredLabels == nil || len(placement.RequiredLabels) > maxCommandPlacementLabels ||
		len(placement.PreferredLabels) > maxCommandPlacementLabels ||
		placement.SpreadBy != "" && !controlprotocol.ValidSchedulingAttribute(placement.SpreadBy) ||
		placement.Tolerations == nil || len(placement.Tolerations) > maxCommandPlacementTolerations {
		return false
	}
	for _, labels := range [][]CommandDelegationLabel{placement.RequiredLabels, placement.PreferredLabels} {
		for index, label := range labels {
			if !controlprotocol.ValidSchedulingAttribute(label.Key) ||
				!controlprotocol.ValidSchedulingAttribute(label.Value) ||
				index > 0 && labels[index-1].Key >= label.Key {
				return false
			}
		}
	}
	for index, value := range placement.Tolerations {
		if !controlprotocol.ValidSchedulingAttribute(value) ||
			index > 0 && placement.Tolerations[index-1] >= value {
			return false
		}
	}
	return true
}

func validDelegatedCapabilityFields(template CommandDelegationAdmissionTemplate) bool {
	if template.Capabilities.State {
		if template.StateDisposition != "new" && template.StateDisposition != "resume" {
			return false
		}
	} else if template.StateDisposition != "none" {
		return false
	}
	if template.Capabilities.Inference {
		if !bounded(template.InferenceRouteID, 128) || !bounded(template.ModelAlias, 256) {
			return false
		}
	} else if template.InferenceRouteID != "" || template.ModelAlias != "" {
		return false
	}
	if template.Capabilities.Service {
		if !bounded(template.ServiceID, 128) {
			return false
		}
	} else if template.ServiceID != "" {
		return false
	}
	if template.Capabilities.Egress != (len(template.EgressRouteIDs) > 0) ||
		template.Capabilities.Connector != (len(template.ConnectorIDs) > 0) {
		return false
	}
	if template.EffectMode != "" && template.EffectMode != EffectModeStandard &&
		template.EffectMode != EffectModeAuthorized {
		return false
	}
	return template.EffectMode != EffectModeAuthorized ||
		template.Capabilities.Connector && !template.Capabilities.Egress
}

func canonicalDelegatedIDs(values []string, limit int) bool {
	if len(values) > limit {
		return false
	}
	for index, value := range values {
		if !routeID(value) || index > 0 && values[index-1] >= value {
			return false
		}
	}
	return true
}

func VerifyCommandDelegation(raw []byte, policy SitePolicy, now time.Time) (VerifiedCommandDelegation, error) {
	if len(raw) == 0 || len(raw) > maxCommandDelegationBytes {
		return VerifiedCommandDelegation{}, deny("command delegation envelope exceeds its limit")
	}
	envelope, err := dsse.Parse(raw)
	if err != nil || envelope.PayloadType != CommandDelegationPayloadType {
		return VerifiedCommandDelegation{}, deny("parse command delegation envelope")
	}
	untrustedPayload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		return VerifiedCommandDelegation{}, deny("decode command delegation routing payload")
	}
	var routed CommandDelegation
	if err := dsse.DecodeStrictInto(untrustedPayload, maxCommandDelegationBytes, &routed); err != nil {
		return VerifiedCommandDelegation{}, deny("decode command delegation routing fields")
	}
	if err := routed.Validate(now); err != nil {
		return VerifiedCommandDelegation{}, err
	}
	keys, err := delegationSignerKeys(policy, routed.TenantID, routed.Operations)
	if err != nil {
		return VerifiedCommandDelegation{}, err
	}
	verifiedPayload, signerKeyID, err := dsse.Verify(raw, CommandDelegationPayloadType, keys)
	if err != nil {
		return VerifiedCommandDelegation{}, deny("verify command delegation: %v", err)
	}
	var statement CommandDelegation
	if err := dsse.DecodeStrictInto(verifiedPayload, maxCommandDelegationBytes, &statement); err != nil {
		return VerifiedCommandDelegation{}, deny("decode verified command delegation")
	}
	if err := statement.Validate(now); err != nil {
		return VerifiedCommandDelegation{}, err
	}
	controllerKey, err := decodePublicKey(statement.ControllerPublicKey)
	if err != nil {
		return VerifiedCommandDelegation{}, err
	}
	return VerifiedCommandDelegation{
		Statement: statement, EnvelopeDigest: dsse.Digest(raw),
		SignerKeyID: signerKeyID, ControllerKey: controllerKey,
	}, nil
}

// InspectCommandDelegation decodes and validates the bounded routing statement
// without treating its signature as trusted. Control uses this to retain and
// reconcile desired state; Executor remains the authority that verifies the
// tenant signature against authenticated site policy before executing a
// delegated command.
func InspectCommandDelegation(raw []byte, now time.Time) (CommandDelegation, error) {
	if len(raw) == 0 || len(raw) > maxCommandDelegationBytes {
		return CommandDelegation{}, deny("command delegation envelope exceeds its limit")
	}
	envelope, err := dsse.Parse(raw)
	if err != nil || envelope.PayloadType != CommandDelegationPayloadType {
		return CommandDelegation{}, deny("parse command delegation envelope")
	}
	payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil || base64.StdEncoding.EncodeToString(payload) != envelope.Payload {
		return CommandDelegation{}, deny("decode command delegation payload")
	}
	var statement CommandDelegation
	if err := dsse.DecodeStrictInto(payload, maxCommandDelegationBytes, &statement); err != nil {
		return CommandDelegation{}, deny("decode command delegation statement")
	}
	if err := statement.Validate(now); err != nil {
		return CommandDelegation{}, err
	}
	return statement, nil
}

func VerifyDelegatedCommand(commandRaw, delegationRaw []byte, policy SitePolicy, now time.Time) (CommandStatement, error) {
	delegation, err := VerifyCommandDelegation(delegationRaw, policy, now)
	if err != nil {
		return CommandStatement{}, err
	}
	verifiedPayload, _, err := dsse.Verify(commandRaw, CommandPayloadType, map[string]ed25519.PublicKey{
		delegation.Statement.ControllerKeyID: delegation.ControllerKey,
	})
	if err != nil {
		return CommandStatement{}, deny("verify delegated command: %v", err)
	}
	var command CommandStatement
	if err := dsse.DecodeStrictInto(verifiedPayload, dsse.MaxPayloadBytes, &command); err != nil {
		return CommandStatement{}, deny("decode verified delegated command")
	}
	if err := command.Validate(now); err != nil {
		return CommandStatement{}, err
	}
	if err := delegation.Authorize(command, delegationRaw); err != nil {
		return CommandStatement{}, err
	}
	return command, nil
}

// VerifyControllerCommand authenticates the controller signature and exact
// delegated scope without asserting that the delegation's tenant signature is
// trusted. Control uses this before durable command submission. Executor still
// calls VerifyDelegatedCommand with authenticated site policy and is the final
// execution authority.
func VerifyControllerCommand(commandRaw, delegationRaw []byte, now time.Time) (CommandStatement, error) {
	statement, err := InspectCommandDelegation(delegationRaw, now)
	if err != nil {
		return CommandStatement{}, err
	}
	controllerKey, err := decodePublicKey(statement.ControllerPublicKey)
	if err != nil {
		return CommandStatement{}, deny("decode delegated controller key")
	}
	payload, _, err := dsse.Verify(commandRaw, CommandPayloadType, map[string]ed25519.PublicKey{
		statement.ControllerKeyID: controllerKey,
	})
	if err != nil {
		return CommandStatement{}, deny("verify controller command: %v", err)
	}
	var command CommandStatement
	if err := dsse.DecodeStrictInto(payload, dsse.MaxPayloadBytes, &command); err != nil {
		return CommandStatement{}, deny("decode verified controller command")
	}
	if err := command.Validate(now); err != nil {
		return CommandStatement{}, err
	}
	verified := VerifiedCommandDelegation{
		Statement: statement, EnvelopeDigest: dsse.Digest(delegationRaw),
		ControllerKey: controllerKey,
	}
	if err := verified.Authorize(command, delegationRaw); err != nil {
		return CommandStatement{}, err
	}
	return command, nil
}

func DecodeCommandDelegationEnvelope(encoded string) ([]byte, error) {
	if encoded == "" || len(encoded) > base64.StdEncoding.EncodedLen(maxCommandDelegationBytes) {
		return nil, errors.New("signed command delegation exceeds its limit")
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || base64.StdEncoding.EncodeToString(raw) != encoded {
		return nil, errors.New("signed command delegation is not canonical base64")
	}
	return raw, nil
}

func (delegation VerifiedCommandDelegation) Authorize(command CommandStatement, raw []byte) error {
	statement := delegation.Statement
	instance, ok := delegatedInstance(statement.Instances, command.InstanceID)
	embedded, embeddedErr := DecodeCommandDelegationEnvelope(command.DelegationDSSEBase64)
	if command.AuthorizationContextDigest != delegation.EnvelopeDigest ||
		dsse.Digest(raw) != delegation.EnvelopeDigest || embeddedErr != nil || !bytes.Equal(embedded, raw) ||
		command.TenantID != statement.TenantID ||
		!slices.Contains(statement.NodeIDs, command.NodeID) ||
		!slices.Contains(statement.Operations, command.Kind) ||
		!ok ||
		command.ClaimGeneration != statement.ClaimGeneration ||
		command.InstanceGeneration < instance.MinInstanceGeneration ||
		command.InstanceGeneration > instance.MaxInstanceGeneration {
		return deny("delegated command exceeds its signed scope")
	}
	commandIssued, _ := time.Parse(time.RFC3339Nano, command.IssuedAt)
	commandExpires, _ := time.Parse(time.RFC3339Nano, command.ExpiresAt)
	delegationIssued, _ := time.Parse(time.RFC3339Nano, statement.IssuedAt)
	delegationExpires, _ := time.Parse(time.RFC3339Nano, statement.ExpiresAt)
	if commandIssued.Before(delegationIssued) || commandExpires.After(delegationExpires) {
		return deny("delegated command validity exceeds its signed delegation")
	}
	if command.Kind == "admit" {
		var payload struct {
			Capsule string         `json:"capsule_dsse_base64"`
			Intent  InstanceIntent `json:"intent"`
		}
		if err := dsse.DecodeStrictInto(command.Payload, maxCommandPayloadBytes, &payload); err != nil {
			return deny("decode delegated admission payload")
		}
		capsule, err := base64.StdEncoding.DecodeString(payload.Capsule)
		if err != nil || base64.StdEncoding.EncodeToString(capsule) != payload.Capsule ||
			statement.Admission == nil || dsse.Digest(capsule) != statement.Admission.CapsuleDigest {
			return deny("delegated admission capsule differs from its signed scope")
		}
		if !statement.Admission.matches(payload.Intent, statement.TenantID, command.NodeID, instance) ||
			payload.Intent.InstanceID != command.InstanceID ||
			payload.Intent.Generation != command.InstanceGeneration {
			return deny("delegated admission intent differs from its signed scope")
		}
	}
	return nil
}

func delegatedInstance(instances []CommandDelegationInstance, instanceID string) (CommandDelegationInstance, bool) {
	index, found := slices.BinarySearchFunc(instances, instanceID, func(instance CommandDelegationInstance, wanted string) int {
		if instance.InstanceID < wanted {
			return -1
		}
		if instance.InstanceID > wanted {
			return 1
		}
		return 0
	})
	if !found {
		return CommandDelegationInstance{}, false
	}
	return instances[index], true
}

func (template CommandDelegationAdmissionTemplate) matches(
	intent InstanceIntent,
	tenantID, nodeID string,
	instance CommandDelegationInstance,
) bool {
	return intent.TenantID == tenantID && intent.NodeID == nodeID &&
		intent.InstanceID == instance.InstanceID && intent.LineageID == instance.LineageID &&
		intent.Generation >= instance.MinInstanceGeneration &&
		intent.Generation <= instance.MaxInstanceGeneration &&
		intent.CapsuleDigest == template.CapsuleDigest && intent.Resources == template.Resources &&
		intent.Capabilities == template.Capabilities &&
		intent.StateDisposition == template.StateDisposition &&
		intent.InferenceRouteID == template.InferenceRouteID && intent.ModelAlias == template.ModelAlias &&
		intent.ServiceID == template.ServiceID && slices.Equal(intent.EgressRouteIDs, template.EgressRouteIDs) &&
		slices.Equal(intent.ConnectorIDs, template.ConnectorIDs) && intent.EffectMode == template.EffectMode
}

func delegationSignerKeys(policy SitePolicy, tenantID string, operations []string) (map[string]ed25519.PublicKey, error) {
	tenant, ok := policy.tenant(tenantID)
	if !ok {
		return nil, errors.New("unknown command delegation tenant")
	}
	keys := make(map[string]ed25519.PublicKey)
	for _, commandKey := range tenant.CommandKeys {
		if !slices.ContainsFunc(operations, func(operation string) bool {
			return !contains(commandKey.Operations, operation)
		}) {
			key, err := decodePublicKey(commandKey.PublicKey)
			if err != nil {
				return nil, deny("decode tenant delegation key: %v", err)
			}
			keys[commandKey.KeyID] = key
		}
	}
	if len(keys) == 0 {
		return nil, errors.New("no tenant command key is authorized for every delegated operation")
	}
	return keys, nil
}

func MarshalCommandDelegation(statement CommandDelegation) ([]byte, error) {
	if err := statement.Validate(time.Time{}); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(statement)
	if err != nil {
		return nil, fmt.Errorf("encode command delegation: %w", err)
	}
	return raw, nil
}
