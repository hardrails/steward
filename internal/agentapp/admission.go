package agentapp

import (
	"errors"
	"fmt"
	"strings"

	"github.com/hardrails/steward/internal/admission"
)

// BuildIntent joins a portable agent bundle to one already authenticated
// capsule and site policy. It does not sign, persist, or execute anything. The
// returned intent can be rechecked by admission.Intersect before any mutation.
func BuildIntent(
	bundle Bundle,
	verified admission.VerifiedCapsuleImport,
	tenantID, nodeID, instanceID, lineageID string,
	generation uint64,
) (admission.InstanceIntent, error) {
	if err := bundle.Validate(); err != nil {
		return admission.InstanceIntent{}, err
	}
	if generation == 0 {
		return admission.InstanceIntent{}, errors.New("agent admission generation must be positive")
	}
	capsule := verified.Capsule
	profileID := map[string]string{"hermes": "hermes-v1"}[bundle.Definition.Runtime.Engine]
	serviceID := map[string]string{"hermes": "hermes-api"}[bundle.Definition.Runtime.Engine]
	if capsule.Profile != (admission.ProfileRef{ID: profileID, Version: "v1"}) {
		return admission.InstanceIntent{}, errors.New("agent runtime does not match the authenticated capsule profile")
	}
	expectedImage := capsule.Image.Repository + "@" + capsule.Image.ManifestDigest
	if bundle.Definition.Runtime.Image != expectedImage {
		return admission.InstanceIntent{}, errors.New("agent image does not match the authenticated capsule image")
	}
	wantedResources := admission.ResourceLimits{
		MemoryBytes: bundle.Definition.Resources.MemoryMiB * 1024 * 1024,
		CPUMillis:   bundle.Definition.Resources.CPUMillis,
		PIDs:        bundle.Definition.Resources.PIDs,
	}
	if capsule.Service.ID != serviceID || capsule.Service.Port == 0 {
		return admission.InstanceIntent{}, errors.New("agent runtime service does not match the authenticated capsule")
	}
	routeID, modelAlias, err := ParseModelRoute(bundle.Definition.Model.Route)
	if err != nil {
		return admission.InstanceIntent{}, err
	}
	capabilities := admission.Capabilities{
		State:     bundle.Definition.State.Persistent,
		Inference: true,
		Service:   true,
		Egress:    len(bundle.Definition.Capabilities.EgressRouteIDs) > 0,
		Connector: len(bundle.Definition.Capabilities.ConnectorIDs) > 0,
	}
	if !capabilities.SubsetOf(capsule.Capabilities) {
		return admission.InstanceIntent{}, errors.New("agent capabilities exceed the authenticated capsule ceiling")
	}
	stateDisposition := "none"
	if capabilities.State {
		stateDisposition = "new"
		if bundle.Definition.State.SnapshotID != "" {
			stateDisposition = "resume"
		}
	}
	effectMode, err := defaultEffectMode(verified.SitePolicy, tenantID)
	if err != nil {
		return admission.InstanceIntent{}, err
	}
	intent := admission.InstanceIntent{
		TenantID: tenantID, NodeID: nodeID, InstanceID: instanceID, LineageID: lineageID,
		Generation: generation, CapsuleDigest: verified.CapsuleDigest,
		Resources: wantedResources, Capabilities: capabilities, StateDisposition: stateDisposition,
		InferenceRouteID: routeID, ModelAlias: modelAlias, ServiceID: serviceID,
		EgressRouteIDs: append([]string(nil), bundle.Definition.Capabilities.EgressRouteIDs...),
		ConnectorIDs:   append([]string(nil), bundle.Definition.Capabilities.ConnectorIDs...),
		EffectMode:     effectMode,
	}
	caller := admission.AuthenticatedIdentity{TenantID: tenantID, NodeID: nodeID}
	if err := intent.Validate(caller); err != nil {
		return admission.InstanceIntent{}, fmt.Errorf("agent admission identity: %w", err)
	}
	if _, err := admission.Intersect(
		capsule, verified.CapsuleDigest, verified.SitePolicy, verified.PolicyDigest,
		verified.PublisherKeyID, verified.SiteRootKeyID, intent, caller,
		admission.PersistedFences{}, admission.DefaultProfiles(),
	); err != nil {
		return admission.InstanceIntent{}, fmt.Errorf("agent admission policy: %w", err)
	}
	return intent, nil
}

func defaultEffectMode(policy admission.SitePolicy, tenantID string) (string, error) {
	for _, tenant := range policy.Tenants {
		if tenant.TenantID != tenantID {
			continue
		}
		if tenant.AuthorizedEffects == nil {
			return "", nil
		}
		switch tenant.AuthorizedEffects.Mode {
		case admission.AuthorizedEffectsOptional:
			return admission.EffectModeStandard, nil
		case admission.AuthorizedEffectsRequired:
			return admission.EffectModeAuthorized, nil
		default:
			return "", errors.New("tenant authorized effects policy mode is invalid")
		}
	}
	return "", fmt.Errorf("tenant %q is not present in the authenticated site policy", strings.TrimSpace(tenantID))
}
