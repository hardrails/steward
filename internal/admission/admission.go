// Package admission defines Steward's offline, signed admission contracts.
// It is intentionally a finite typed policy intersection, not a general policy
// language or a Docker API wrapper.
package admission

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/hardrails/steward/internal/dsse"
)

const (
	CapsulePayloadType  = "application/vnd.steward.capsule.v1+json"
	PolicyPayloadType   = "application/vnd.steward.site-policy.v1+json"
	CommandPayloadType  = "application/vnd.steward.executor-command.v2+json"
	SchemaV1            = "steward.admission.v1"
	CommandSchemaV2     = "steward.executor-command.v2"
	maxAllowedArtifacts = 128
)

var (
	ErrDenied          = errors.New("admission denied")
	sha256DigestPrefix = "sha256:"
)

// ProfileCapsule is reusable publisher-signed artifact/profile authority. It
// intentionally cannot name tenants, nodes, arbitrary paths, environment, or
// network destinations; those authorities are owned by InstanceIntent and site
// policy respectively.
type ProfileCapsule struct {
	SchemaVersion  string           `json:"schema_version"`
	CapsuleID      string           `json:"capsule_id"`
	PublisherKeyID string           `json:"publisher_key_id"`
	IssuedAt       string           `json:"issued_at,omitempty"`
	ExpiresAt      string           `json:"expires_at,omitempty"`
	Profile        ProfileRef       `json:"profile"`
	Image          ImageIdentity    `json:"image"`
	Command        []string         `json:"command"`
	Resources      ResourceLimits   `json:"resources"`
	Capabilities   Capabilities     `json:"capabilities"`
	Artifacts      []ArtifactDigest `json:"artifacts,omitempty"`
	State          StateShape       `json:"state"`
	Service        ServiceShape     `json:"service"`
}

type ProfileRef struct {
	ID      string `json:"id"`
	Version string `json:"version"`
}

type ImageIdentity struct {
	Repository     string   `json:"repository"`
	ManifestDigest string   `json:"manifest_digest"`
	ConfigDigest   string   `json:"config_digest"`
	Platform       Platform `json:"platform"`
}

type Platform struct {
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
	Variant      string `json:"variant,omitempty"`
}

type ResourceLimits struct {
	MemoryBytes int64 `json:"memory_bytes"`
	CPUMillis   int64 `json:"cpu_millis"`
	PIDs        int64 `json:"pids"`
}

type Capabilities struct {
	State     bool `json:"state"`
	Inference bool `json:"inference"`
	Service   bool `json:"service"`
	Egress    bool `json:"egress"`
	Connector bool `json:"connector"`
}

type ArtifactDigest struct {
	Kind   string `json:"kind"`
	Digest string `json:"digest"`
}

type StateShape struct {
	SchemaVersion string `json:"schema_version"`
	Path          string `json:"path"`
}

type ServiceShape struct {
	ID   string `json:"id,omitempty"`
	Port int    `json:"port,omitempty"`
}

// InstanceIntent is supplied by an authenticated control-plane caller. Its
// tenant/node fields are checked against AuthenticatedIdentity rather than
// trusted merely because they occur in a request body.
type InstanceIntent struct {
	TenantID         string         `json:"tenant_id"`
	NodeID           string         `json:"node_id"`
	InstanceID       string         `json:"instance_id"`
	LineageID        string         `json:"lineage_id"`
	Generation       uint64         `json:"generation"`
	CapsuleDigest    string         `json:"capsule_digest"`
	Resources        ResourceLimits `json:"resources"`
	Capabilities     Capabilities   `json:"capabilities"`
	StateDisposition string         `json:"state_disposition"`
	InferenceRouteID string         `json:"inference_route_id,omitempty"`
	ModelAlias       string         `json:"model_alias,omitempty"`
	ServiceID        string         `json:"service_id,omitempty"`
	EgressRouteIDs   []string       `json:"egress_route_ids,omitempty"`
	ConnectorIDs     []string       `json:"connector_ids,omitempty"`
}

type AuthenticatedIdentity struct {
	TenantID string
	NodeID   string
}

// SitePolicy is site-root-signed. It constrains publisher authority and binds
// scheduling policy to tenants without requiring a site co-signature on every
// reusable publisher capsule.
type SitePolicy struct {
	SchemaVersion          string          `json:"schema_version"`
	PolicyID               string          `json:"policy_id"`
	PolicyEpoch            uint64          `json:"policy_epoch"`
	SiteCleanupCommandKeys []CommandKey    `json:"site_cleanup_command_keys,omitempty"`
	Publishers             []PublisherRule `json:"publishers"`
	Tenants                []TenantRule    `json:"tenants"`
}

type PublisherRule struct {
	KeyID                  string           `json:"key_id"`
	PublicKey              string           `json:"public_key"`
	Revoked                bool             `json:"revoked"`
	AllowedProfiles        []ProfileRef     `json:"allowed_profiles"`
	AllowedRepositories    []string         `json:"allowed_repositories"`
	AllowedManifestDigests []string         `json:"allowed_manifest_digests,omitempty"`
	AllowedArtifacts       []ArtifactDigest `json:"allowed_artifacts,omitempty"`
	ResourceCeiling        ResourceLimits   `json:"resource_ceiling"`
}

type TenantRule struct {
	TenantID              string           `json:"tenant_id"`
	PublisherKeyIDs       []string         `json:"publisher_key_ids"`
	ResourceCeiling       ResourceLimits   `json:"resource_ceiling"`
	AllowedArtifacts      []ArtifactDigest `json:"allowed_artifacts,omitempty"`
	InferenceRouteIDs     []string         `json:"inference_route_ids,omitempty"`
	InferenceModelAliases []string         `json:"inference_model_aliases,omitempty"`
	ServiceIDs            []string         `json:"service_ids,omitempty"`
	EgressRouteIDs        []string         `json:"egress_route_ids,omitempty"`
	ConnectorIDs          []string         `json:"connector_ids,omitempty"`
	CommandKeys           []CommandKey     `json:"command_keys,omitempty"`
	TaskKeys              []TaskKey        `json:"task_keys,omitempty"`
}

// TaskKey grants one tenant-owned Ed25519 key authority to submit exact,
// short-lived task bytes to only the named service identities. The private key
// remains off-node; Executor passes this signed public authority to Gateway as
// part of the workload grant.
type TaskKey struct {
	KeyID      string   `json:"key_id"`
	PublicKey  string   `json:"public_key"`
	ServiceIDs []string `json:"service_ids"`
}

// CommandKey grants one Ed25519 key authority over only the named Executor
// operations. Tenant command keys live inside a tenant rule; site cleanup keys
// live at the policy root and are further restricted to cleanup operations.
// Keeping command authority in signed site policy lets a node-scoped uplink
// transport commands without turning its bearer token into execution authority.
type CommandKey struct {
	KeyID      string   `json:"key_id"`
	PublicKey  string   `json:"public_key"`
	Operations []string `json:"operations"`
}

// CommandStatement is the exact payload carried by a DSSE command envelope.
// Identity, ordering, validity time, operation, and payload are signed as one
// bounded statement; none may be supplied by an unsigned transport wrapper.
type CommandStatement struct {
	SchemaVersion      string          `json:"schema_version"`
	CommandID          string          `json:"command_id"`
	TenantID           string          `json:"tenant_id"`
	NodeID             string          `json:"node_id"`
	InstanceID         string          `json:"instance_id"`
	RuntimeRef         string          `json:"runtime_ref"`
	Kind               string          `json:"kind"`
	ClaimGeneration    uint64          `json:"claim_generation"`
	InstanceGeneration uint64          `json:"instance_generation"`
	CommandSequence    uint64          `json:"command_sequence"`
	IssuedAt           string          `json:"issued_at"`
	ExpiresAt          string          `json:"expires_at"`
	Payload            json.RawMessage `json:"payload"`
}

// PersistedFences are supplied by the durable executor journal. Equality is
// allowed for idempotent reconciliation; a lower generation or policy epoch is
// always rejected as rollback.
type PersistedFences struct {
	Generation  uint64
	PolicyEpoch uint64
}

type EffectiveAdmission struct {
	Capsule            ProfileCapsule
	SitePolicy         SitePolicy
	Intent             InstanceIntent
	Profile            Profile
	CapsuleDigest      string
	PolicyDigest       string
	PublisherKeyID     string
	SiteRootKeyID      string
	EffectiveResources ResourceLimits
}

// VerifiedCapsuleImport is the tenant-independent result of authenticating an
// offline capsule against a site-root-signed policy. It is suitable for an OCI
// import gate: artifact and publisher authority are established here, while a
// later admission still must bind a tenant, node, instance, and generation.
type VerifiedCapsuleImport struct {
	Capsule        ProfileCapsule
	SitePolicy     SitePolicy
	Profile        Profile
	CapsuleDigest  string
	PolicyDigest   string
	PublisherKeyID string
	SiteRootKeyID  string
}

// VerifiedSitePolicy is the authenticated result of opening a site-policy DSSE
// envelope with an operator-provided site root. Callers wiring command transport
// should pass Policy to the uplink only from this result, never from raw JSON.
type VerifiedSitePolicy struct {
	Policy        SitePolicy
	PolicyDigest  string
	SiteRootKeyID string
}

func VerifySitePolicy(policyEnvelope []byte, siteRoots map[string]ed25519.PublicKey) (VerifiedSitePolicy, error) {
	policyPayload, siteRootKeyID, err := dsse.Verify(policyEnvelope, PolicyPayloadType, siteRoots)
	if err != nil {
		return VerifiedSitePolicy{}, deny("verify site policy: %v", err)
	}
	var policy SitePolicy
	if err := dsse.DecodeStrictInto(policyPayload, dsse.DefaultMaxEnvelopeBytes, &policy); err != nil {
		return VerifiedSitePolicy{}, deny("decode site policy: %v", err)
	}
	if err := policy.Validate(); err != nil {
		return VerifiedSitePolicy{}, err
	}
	return VerifiedSitePolicy{
		Policy: policy, PolicyDigest: dsse.Digest(policyEnvelope), SiteRootKeyID: siteRootKeyID,
	}, nil
}

// VerifyCapsuleForImport verifies the site policy, publisher signature,
// revocation state, built-in profile shape, repository, optional manifest
// allowlist, and exact publisher artifact authority without selecting a tenant
// or accepting an instance intent.
func VerifyCapsuleForImport(capsuleEnvelope, policyEnvelope []byte, siteRoots map[string]ed25519.PublicKey, now time.Time, profiles Registry) (VerifiedCapsuleImport, error) {
	verifiedPolicy, err := VerifySitePolicy(policyEnvelope, siteRoots)
	if err != nil {
		return VerifiedCapsuleImport{}, err
	}
	policy := verifiedPolicy.Policy
	publisherKeys, err := policy.PublisherKeys()
	if err != nil {
		return VerifiedCapsuleImport{}, err
	}
	capsulePayload, publisherKeyID, err := dsse.Verify(capsuleEnvelope, CapsulePayloadType, publisherKeys)
	if err != nil {
		return VerifiedCapsuleImport{}, deny("verify profile capsule: %v", err)
	}
	var capsule ProfileCapsule
	if err := dsse.DecodeStrictInto(capsulePayload, dsse.DefaultMaxEnvelopeBytes, &capsule); err != nil {
		return VerifiedCapsuleImport{}, deny("decode profile capsule: %v", err)
	}
	if err := capsule.Validate(now); err != nil {
		return VerifiedCapsuleImport{}, err
	}
	if capsule.PublisherKeyID != publisherKeyID {
		return VerifiedCapsuleImport{}, deny("capsule publisher key ID does not match verified signature")
	}
	publisher, ok := policy.publisher(publisherKeyID)
	if !ok || publisher.Revoked {
		return VerifiedCapsuleImport{}, deny("publisher is absent or revoked")
	}
	if !containsProfile(publisher.AllowedProfiles, capsule.Profile) {
		return VerifiedCapsuleImport{}, deny("profile is not authorized for publisher")
	}
	if !contains(publisher.AllowedRepositories, capsule.Image.Repository) {
		return VerifiedCapsuleImport{}, deny("image repository is not authorized")
	}
	if len(publisher.AllowedManifestDigests) > 0 && !contains(publisher.AllowedManifestDigests, capsule.Image.ManifestDigest) {
		return VerifiedCapsuleImport{}, deny("image manifest digest is not authorized")
	}
	if !artifactsAllowed(capsule.Artifacts, publisher.AllowedArtifacts) {
		return VerifiedCapsuleImport{}, deny("capsule artifact is not authorized for publisher")
	}
	profile, ok := profiles.Lookup(capsule.Profile)
	if !ok {
		return VerifiedCapsuleImport{}, deny("unknown built-in profile")
	}
	if capsule.State.Path != profile.StatePath || capsule.State.SchemaVersion != profile.StateSchemaVersion {
		return VerifiedCapsuleImport{}, deny("capsule state shape differs from built-in profile")
	}
	return VerifiedCapsuleImport{
		Capsule: capsule, SitePolicy: policy, Profile: profile,
		CapsuleDigest: dsse.Digest(capsuleEnvelope), PolicyDigest: verifiedPolicy.PolicyDigest,
		PublisherKeyID: publisherKeyID, SiteRootKeyID: verifiedPolicy.SiteRootKeyID,
	}, nil
}

// VerifyAndAdmit authenticates the signed policy first, verifies a capsule only
// with a policy-authorized publisher key, then applies finite authority
// intersection to a caller-bound intent.
func VerifyAndAdmit(capsuleEnvelope, policyEnvelope []byte, siteRoots map[string]ed25519.PublicKey, intent InstanceIntent, caller AuthenticatedIdentity, fences PersistedFences, now time.Time, profiles Registry) (EffectiveAdmission, error) {
	verified, err := VerifyCapsuleForImport(capsuleEnvelope, policyEnvelope, siteRoots, now, profiles)
	if err != nil {
		return EffectiveAdmission{}, err
	}
	return Intersect(
		verified.Capsule, verified.CapsuleDigest, verified.SitePolicy, verified.PolicyDigest,
		verified.PublisherKeyID, verified.SiteRootKeyID, intent, caller, fences, profiles,
	)
}

// Intersect applies only deterministic local checks, making it reusable by an
// executor after signatures have been verified elsewhere.
func Intersect(capsule ProfileCapsule, capsuleDigest string, policy SitePolicy, policyDigest, publisherKeyID, siteRootKeyID string, intent InstanceIntent, caller AuthenticatedIdentity, fences PersistedFences, profiles Registry) (EffectiveAdmission, error) {
	if err := capsule.Validate(time.Time{}); err != nil {
		return EffectiveAdmission{}, err
	}
	if err := policy.Validate(); err != nil {
		return EffectiveAdmission{}, err
	}
	if err := intent.Validate(caller); err != nil {
		return EffectiveAdmission{}, err
	}
	if intent.CapsuleDigest != capsuleDigest {
		return EffectiveAdmission{}, deny("intent capsule digest does not identify the verified envelope")
	}
	if policy.PolicyEpoch < fences.PolicyEpoch {
		return EffectiveAdmission{}, deny("site policy epoch rollback")
	}
	if intent.Generation < fences.Generation {
		return EffectiveAdmission{}, deny("instance generation rollback")
	}
	publisher, ok := policy.publisher(publisherKeyID)
	if !ok || publisher.Revoked {
		return EffectiveAdmission{}, deny("publisher is absent or revoked")
	}
	tenant, ok := policy.tenant(intent.TenantID)
	if !ok || !contains(tenant.PublisherKeyIDs, publisherKeyID) {
		return EffectiveAdmission{}, deny("publisher is not authorized for tenant")
	}
	if !containsProfile(publisher.AllowedProfiles, capsule.Profile) {
		return EffectiveAdmission{}, deny("profile is not authorized for publisher")
	}
	if !contains(publisher.AllowedRepositories, capsule.Image.Repository) {
		return EffectiveAdmission{}, deny("image repository is not authorized")
	}
	if len(publisher.AllowedManifestDigests) > 0 && !contains(publisher.AllowedManifestDigests, capsule.Image.ManifestDigest) {
		return EffectiveAdmission{}, deny("image manifest digest is not authorized")
	}
	if !artifactsAllowed(capsule.Artifacts, publisher.AllowedArtifacts) {
		return EffectiveAdmission{}, deny("capsule artifact is not authorized for publisher")
	}
	if !artifactsAllowed(capsule.Artifacts, tenant.AllowedArtifacts) {
		return EffectiveAdmission{}, deny("capsule artifact is not authorized for tenant")
	}
	profile, ok := profiles.Lookup(capsule.Profile)
	if !ok {
		return EffectiveAdmission{}, deny("unknown built-in profile")
	}
	if capsule.State.Path != profile.StatePath || capsule.State.SchemaVersion != profile.StateSchemaVersion {
		return EffectiveAdmission{}, deny("capsule state shape differs from built-in profile")
	}
	if !intent.Capabilities.SubsetOf(capsule.Capabilities) {
		return EffectiveAdmission{}, deny("intent requests a capability outside capsule ceiling")
	}
	if !within(intent.Resources, capsule.Resources) || !within(intent.Resources, publisher.ResourceCeiling) || !within(intent.Resources, tenant.ResourceCeiling) {
		return EffectiveAdmission{}, deny("resource request exceeds an admission ceiling")
	}
	if err := validateRequestedCapabilities(intent, capsule, tenant); err != nil {
		return EffectiveAdmission{}, err
	}
	intent.ConnectorIDs = CanonicalConnectorIDs(intent.ConnectorIDs)
	return EffectiveAdmission{
		Capsule: capsule, SitePolicy: policy, Intent: intent, Profile: profile,
		CapsuleDigest: capsuleDigest, PolicyDigest: policyDigest,
		PublisherKeyID: publisherKeyID, SiteRootKeyID: siteRootKeyID,
		EffectiveResources: intent.Resources,
	}, nil
}

func validateRequestedCapabilities(intent InstanceIntent, capsule ProfileCapsule, tenant TenantRule) error {
	if intent.Capabilities.State {
		if intent.StateDisposition != "new" && intent.StateDisposition != "resume" {
			return deny("state capability requires new or resume disposition")
		}
	} else if intent.StateDisposition != "none" {
		return deny("state disposition requires state capability")
	}
	if intent.Capabilities.Inference {
		if !bounded(intent.InferenceRouteID, 128) || !bounded(intent.ModelAlias, 256) ||
			!contains(tenant.InferenceRouteIDs, intent.InferenceRouteID) || !contains(tenant.InferenceModelAliases, intent.ModelAlias) {
			return deny("inference route or model alias is not authorized")
		}
	} else if intent.InferenceRouteID != "" || intent.ModelAlias != "" {
		return deny("inference route requires inference capability")
	}
	if intent.Capabilities.Service {
		if intent.ServiceID == "" || intent.ServiceID != capsule.Service.ID || !contains(tenant.ServiceIDs, intent.ServiceID) {
			return deny("service is not authorized")
		}
	} else if intent.ServiceID != "" {
		return deny("service ID requires service capability")
	}
	if intent.Capabilities.Egress {
		if len(intent.EgressRouteIDs) == 0 || len(intent.EgressRouteIDs) > 32 {
			return deny("egress capability requires 1 to 32 route IDs")
		}
		seen := make(map[string]struct{}, len(intent.EgressRouteIDs))
		for _, route := range intent.EgressRouteIDs {
			if !routeID(route) || !contains(tenant.EgressRouteIDs, route) {
				return deny("egress route is not authorized")
			}
			if _, exists := seen[route]; exists {
				return deny("duplicate egress route")
			}
			seen[route] = struct{}{}
		}
	} else if len(intent.EgressRouteIDs) != 0 {
		return deny("egress routes require egress capability")
	}
	if intent.Capabilities.Connector {
		if len(intent.ConnectorIDs) == 0 || len(intent.ConnectorIDs) > 32 {
			return deny("connector capability requires 1 to 32 connector IDs")
		}
		seen := make(map[string]struct{}, len(intent.ConnectorIDs))
		for _, connector := range intent.ConnectorIDs {
			if !routeID(connector) || !contains(tenant.ConnectorIDs, connector) {
				return deny("connector is not authorized")
			}
			if _, exists := seen[connector]; exists {
				return deny("duplicate connector ID")
			}
			seen[connector] = struct{}{}
		}
	} else if len(intent.ConnectorIDs) != 0 {
		return deny("connector IDs require connector capability")
	}
	return nil
}

func (c Capabilities) SubsetOf(maximum Capabilities) bool {
	return (!c.State || maximum.State) && (!c.Inference || maximum.Inference) &&
		(!c.Service || maximum.Service) && (!c.Egress || maximum.Egress) &&
		(!c.Connector || maximum.Connector)
}

// CanonicalRouteIDs returns a detached, sorted route set for fingerprints and
// gateway grants. Admission rejects duplicates, so sorting cannot change meaning.
func CanonicalRouteIDs(routes []string) []string {
	result := append([]string(nil), routes...)
	slices.Sort(result)
	return result
}

// CanonicalConnectorIDs returns a detached, sorted and de-duplicated connector
// set for runtime grants. Signed admission rejects duplicate requests, while the
// de-duplication keeps this helper safe for callers operating on retained state.
func CanonicalConnectorIDs(connectors []string) []string {
	result := append([]string(nil), connectors...)
	slices.Sort(result)
	return slices.Compact(result)
}

func (c ProfileCapsule) Validate(now time.Time) error {
	if c.SchemaVersion != SchemaV1 || !bounded(c.CapsuleID, 128) || !bounded(c.PublisherKeyID, 256) {
		return deny("invalid capsule identity")
	}
	if err := c.Profile.Validate(); err != nil {
		return err
	}
	if err := c.Image.Validate(); err != nil {
		return err
	}
	if err := c.Resources.Validate(); err != nil {
		return err
	}
	if len(c.Command) == 0 || len(c.Command) > 64 {
		return deny("capsule command must contain 1 to 64 arguments")
	}
	for _, argument := range c.Command {
		if len(argument) > 4096 || strings.ContainsRune(argument, '\x00') {
			return deny("invalid capsule command argument")
		}
	}
	if !bounded(c.State.SchemaVersion, 128) || !absolutePath(c.State.Path) {
		return deny("invalid capsule state shape")
	}
	if c.Capabilities.Service {
		if !bounded(c.Service.ID, 128) || c.Service.Port < 1 || c.Service.Port > 65535 {
			return deny("invalid capsule service shape")
		}
	} else if c.Service.ID != "" || c.Service.Port != 0 {
		return deny("service shape requires service capability")
	}
	if len(c.Artifacts) > 32 {
		return deny("too many capsule artifacts")
	}
	artifactKinds := make(map[string]struct{}, len(c.Artifacts))
	for _, artifact := range c.Artifacts {
		if !bounded(artifact.Kind, 128) || !digest(artifact.Digest) {
			return deny("invalid capsule artifact")
		}
		if _, duplicate := artifactKinds[artifact.Kind]; duplicate {
			return deny("duplicate capsule artifact kind")
		}
		artifactKinds[artifact.Kind] = struct{}{}
	}
	if c.IssuedAt != "" {
		if _, err := time.Parse(time.RFC3339, c.IssuedAt); err != nil {
			return deny("invalid capsule issue time")
		}
	}
	if c.ExpiresAt != "" {
		expires, err := time.Parse(time.RFC3339, c.ExpiresAt)
		if err != nil {
			return deny("invalid capsule expiry")
		}
		if !now.IsZero() && !expires.After(now) {
			return deny("capsule has expired according to node time")
		}
	}
	return nil
}

func (p SitePolicy) Validate() error {
	if p.SchemaVersion != SchemaV1 || !bounded(p.PolicyID, 128) || p.PolicyEpoch == 0 || len(p.Publishers) == 0 || len(p.Publishers) > 128 || len(p.Tenants) > 1024 {
		return deny("invalid site policy identity")
	}
	seenPublishers := map[string]struct{}{}
	for _, publisher := range p.Publishers {
		if !bounded(publisher.KeyID, 256) || !bounded(publisher.PublicKey, 1024) {
			return deny("invalid publisher identity")
		}
		if _, ok := seenPublishers[publisher.KeyID]; ok {
			return deny("duplicate publisher key ID")
		}
		seenPublishers[publisher.KeyID] = struct{}{}
		if _, err := decodePublicKey(publisher.PublicKey); err != nil {
			return deny("invalid publisher public key")
		}
		if err := publisher.ResourceCeiling.Validate(); err != nil {
			return err
		}
		if len(publisher.AllowedProfiles) == 0 || len(publisher.AllowedProfiles) > 32 || len(publisher.AllowedRepositories) == 0 || len(publisher.AllowedRepositories) > 64 {
			return deny("publisher has invalid allowlist")
		}
		for _, profile := range publisher.AllowedProfiles {
			if err := profile.Validate(); err != nil {
				return err
			}
		}
		for _, repository := range publisher.AllowedRepositories {
			if !repositoryName(repository) {
				return deny("invalid allowed repository")
			}
		}
		for _, imageDigest := range publisher.AllowedManifestDigests {
			if !digest(imageDigest) {
				return deny("invalid allowed manifest digest")
			}
		}
		if err := validateAllowedArtifacts(publisher.AllowedArtifacts, "publisher"); err != nil {
			return err
		}
		if len(publisher.AllowedArtifacts) > 0 && len(publisher.AllowedManifestDigests) == 0 {
			return deny("publisher artifact authority requires an exact allowed manifest digest")
		}
	}
	if len(p.SiteCleanupCommandKeys) > 32 {
		return deny("site has too many cleanup command keys")
	}
	seenSiteCleanupKeys := make(map[string]struct{}, len(p.SiteCleanupCommandKeys))
	for _, commandKey := range p.SiteCleanupCommandKeys {
		if !bounded(commandKey.KeyID, 256) || !bounded(commandKey.PublicKey, 1024) {
			return deny("invalid site cleanup command key")
		}
		if _, exists := seenSiteCleanupKeys[commandKey.KeyID]; exists {
			return deny("duplicate site cleanup command key ID")
		}
		seenSiteCleanupKeys[commandKey.KeyID] = struct{}{}
		if _, err := decodePublicKey(commandKey.PublicKey); err != nil {
			return deny("invalid site cleanup command public key")
		}
		if len(commandKey.Operations) == 0 || len(commandKey.Operations) > len(cleanupCommandOperations) {
			return deny("site cleanup command key has invalid operation scope")
		}
		seenOperations := make(map[string]struct{}, len(commandKey.Operations))
		for _, operation := range commandKey.Operations {
			if !bounded(operation, 32) {
				return deny("site cleanup command key has invalid operation")
			}
			if _, supported := cleanupCommandOperations[operation]; !supported {
				return deny("site cleanup command key names non-cleanup operation")
			}
			if _, exists := seenOperations[operation]; exists {
				return deny("site cleanup command key has duplicate operation")
			}
			seenOperations[operation] = struct{}{}
		}
	}
	// A cleanup-key-bearing policy may deliberately contain zero tenants as an
	// emergency admission lockdown. Existing signed workloads remain removable,
	// while no tenant can admit or restart work under the replacement policy.
	if len(p.Tenants) == 0 && len(p.SiteCleanupCommandKeys) == 0 {
		return deny("invalid site policy identity")
	}
	seenTenants := map[string]struct{}{}
	taskPublicKeyOwners := make(map[string]string)
	for _, tenant := range p.Tenants {
		if !bounded(tenant.TenantID, 128) || len(tenant.PublisherKeyIDs) == 0 || len(tenant.PublisherKeyIDs) > 64 {
			return deny("invalid tenant policy")
		}
		if _, ok := seenTenants[tenant.TenantID]; ok {
			return deny("duplicate tenant policy")
		}
		seenTenants[tenant.TenantID] = struct{}{}
		if err := tenant.ResourceCeiling.Validate(); err != nil {
			return err
		}
		for _, keyID := range tenant.PublisherKeyIDs {
			if _, ok := seenPublishers[keyID]; !ok {
				return deny("tenant names unknown publisher")
			}
		}
		if err := validateAllowedArtifacts(tenant.AllowedArtifacts, "tenant"); err != nil {
			return err
		}
		if len(tenant.InferenceRouteIDs) > 128 || len(tenant.InferenceModelAliases) > 128 ||
			(len(tenant.InferenceRouteIDs) == 0) != (len(tenant.InferenceModelAliases) == 0) {
			return deny("tenant inference routes and model aliases must be configured together")
		}
		seenInferenceRoutes := make(map[string]struct{}, len(tenant.InferenceRouteIDs))
		for _, route := range tenant.InferenceRouteIDs {
			if !bounded(route, 128) {
				return deny("invalid inference route")
			}
			if _, exists := seenInferenceRoutes[route]; exists {
				return deny("duplicate tenant inference route")
			}
			seenInferenceRoutes[route] = struct{}{}
		}
		seenModelAliases := make(map[string]struct{}, len(tenant.InferenceModelAliases))
		for _, alias := range tenant.InferenceModelAliases {
			if !bounded(alias, 256) {
				return deny("invalid inference model alias")
			}
			if _, exists := seenModelAliases[alias]; exists {
				return deny("duplicate tenant inference model alias")
			}
			seenModelAliases[alias] = struct{}{}
		}
		for _, service := range tenant.ServiceIDs {
			if !bounded(service, 128) {
				return deny("invalid service ID")
			}
		}
		if len(tenant.EgressRouteIDs) > 128 {
			return deny("tenant has too many egress routes")
		}
		seenRoutes := make(map[string]struct{}, len(tenant.EgressRouteIDs))
		for _, route := range tenant.EgressRouteIDs {
			if !routeID(route) {
				return deny("invalid egress route")
			}
			if _, exists := seenRoutes[route]; exists {
				return deny("duplicate tenant egress route")
			}
			seenRoutes[route] = struct{}{}
		}
		if len(tenant.ConnectorIDs) > 32 {
			return deny("tenant has too many connector IDs")
		}
		seenConnectors := make(map[string]struct{}, len(tenant.ConnectorIDs))
		for _, connector := range tenant.ConnectorIDs {
			if !routeID(connector) {
				return deny("invalid connector ID")
			}
			if _, exists := seenConnectors[connector]; exists {
				return deny("duplicate tenant connector ID")
			}
			seenConnectors[connector] = struct{}{}
		}
		if len(tenant.CommandKeys) > 32 {
			return deny("tenant has too many command keys")
		}
		seenCommandKeys := make(map[string]struct{}, len(tenant.CommandKeys))
		for _, commandKey := range tenant.CommandKeys {
			if !bounded(commandKey.KeyID, 256) || !bounded(commandKey.PublicKey, 1024) {
				return deny("invalid tenant command key")
			}
			if _, exists := seenCommandKeys[commandKey.KeyID]; exists {
				return deny("duplicate tenant command key ID")
			}
			if _, exists := seenSiteCleanupKeys[commandKey.KeyID]; exists {
				return deny("tenant command key ID collides with site cleanup command key")
			}
			seenCommandKeys[commandKey.KeyID] = struct{}{}
			if _, err := decodePublicKey(commandKey.PublicKey); err != nil {
				return deny("invalid tenant command public key")
			}
			if len(commandKey.Operations) == 0 || len(commandKey.Operations) > len(commandOperations) {
				return deny("tenant command key has invalid operation scope")
			}
			seenOperations := make(map[string]struct{}, len(commandKey.Operations))
			for _, operation := range commandKey.Operations {
				if !bounded(operation, 32) {
					return deny("tenant command key has invalid operation")
				}
				if _, supported := commandOperations[operation]; !supported {
					return deny("tenant command key names unsupported operation")
				}
				if _, exists := seenOperations[operation]; exists {
					return deny("tenant command key has duplicate operation")
				}
				seenOperations[operation] = struct{}{}
			}
		}
		if len(tenant.TaskKeys) > 8 {
			return deny("tenant has too many task keys")
		}
		seenTaskKeys := make(map[string]struct{}, len(tenant.TaskKeys))
		seenTaskPublicKeys := make(map[string]struct{}, len(tenant.TaskKeys))
		for _, taskKey := range tenant.TaskKeys {
			if !routeID(taskKey.KeyID) || !bounded(taskKey.PublicKey, 1024) ||
				len(taskKey.ServiceIDs) == 0 || len(taskKey.ServiceIDs) > 32 {
				return deny("invalid tenant task key")
			}
			if _, exists := seenTaskKeys[taskKey.KeyID]; exists {
				return deny("duplicate tenant task key ID")
			}
			seenTaskKeys[taskKey.KeyID] = struct{}{}
			public, err := decodePublicKey(taskKey.PublicKey)
			if err != nil || base64.StdEncoding.EncodeToString(public) != taskKey.PublicKey {
				return deny("invalid tenant task public key")
			}
			if _, exists := seenTaskPublicKeys[string(public)]; exists {
				return deny("tenant task public key is assigned more than once")
			}
			seenTaskPublicKeys[string(public)] = struct{}{}
			if owner, exists := taskPublicKeyOwners[string(public)]; exists && owner != tenant.TenantID {
				return deny("tenant task public key is assigned to multiple tenants")
			}
			taskPublicKeyOwners[string(public)] = tenant.TenantID
			seenServices := make(map[string]struct{}, len(taskKey.ServiceIDs))
			for index, serviceID := range taskKey.ServiceIDs {
				if !routeID(serviceID) || !contains(tenant.ServiceIDs, serviceID) ||
					index > 0 && taskKey.ServiceIDs[index-1] >= serviceID {
					return deny("tenant task key service IDs must be authorized, unique, and sorted")
				}
				if _, exists := seenServices[serviceID]; exists {
					return deny("tenant task key has duplicate service ID")
				}
				seenServices[serviceID] = struct{}{}
			}
		}
	}
	return nil
}

var routeIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

var commandOperations = map[string]struct{}{
	"admit": {}, "start": {}, "stop": {}, "destroy": {}, "read": {}, "purge": {},
	"activation-canary": {},
}

var cleanupCommandOperations = map[string]struct{}{
	"stop": {}, "destroy": {}, "purge": {},
}

func routeID(value string) bool { return routeIDPattern.MatchString(value) }

func (i InstanceIntent) Validate(caller AuthenticatedIdentity) error {
	if !bounded(i.TenantID, 128) || !bounded(i.NodeID, 128) || !bounded(i.InstanceID, 256) || !bounded(i.LineageID, 256) || i.Generation == 0 || !digest(i.CapsuleDigest) {
		return deny("invalid instance intent identity")
	}
	if caller.TenantID != i.TenantID || caller.NodeID != i.NodeID {
		return deny("authenticated caller does not own intent tenant/node")
	}
	if err := i.Resources.Validate(); err != nil {
		return err
	}
	return nil
}

func (r ResourceLimits) Validate() error {
	if r.MemoryBytes <= 0 || r.CPUMillis <= 0 || r.PIDs <= 0 {
		return deny("resource limits must all be positive")
	}
	return nil
}

func (p ProfileRef) Validate() error {
	if !bounded(p.ID, 128) || !bounded(p.Version, 128) {
		return deny("invalid profile")
	}
	return nil
}

func (i ImageIdentity) Validate() error {
	if !repositoryName(i.Repository) || !digest(i.ManifestDigest) || !digest(i.ConfigDigest) || !bounded(i.Platform.OS, 32) || !bounded(i.Platform.Architecture, 32) || len(i.Platform.Variant) > 32 || strings.ContainsRune(i.Platform.Variant, '\x00') {
		return deny("invalid immutable image identity")
	}
	return nil
}

func (p SitePolicy) PublisherKeys() (map[string]ed25519.PublicKey, error) {
	keys := make(map[string]ed25519.PublicKey, len(p.Publishers))
	for _, publisher := range p.Publishers {
		key, err := decodePublicKey(publisher.PublicKey)
		if err != nil {
			return nil, deny("decode publisher key: %v", err)
		}
		keys[publisher.KeyID] = key
	}
	return keys, nil
}

// TrustedCommandKeys returns tenant keys whose signed policy scope includes the
// operation and, for stop/destroy/purge only, site-owned cleanup keys. Cleanup
// keys are independent of tenant rules so the site can contain or remove a
// workload after revoking that tenant's compromised authority. Callers should
// pass this result directly to DSSE verification; selecting a tenant or
// operation from an unverified command is safe only for key routing, never as
// authorization by itself.
func (p SitePolicy) TrustedCommandKeys(tenantID, operation string) (map[string]ed25519.PublicKey, error) {
	if _, ok := commandOperations[operation]; !ok {
		return nil, deny("unsupported command operation")
	}
	tenant, ok := p.tenant(tenantID)
	_, cleanupOperation := cleanupCommandOperations[operation]
	if !ok && !cleanupOperation {
		return nil, deny("unknown command tenant")
	}
	keys := make(map[string]ed25519.PublicKey)
	if ok {
		for _, commandKey := range tenant.CommandKeys {
			if !contains(commandKey.Operations, operation) {
				continue
			}
			key, err := decodePublicKey(commandKey.PublicKey)
			if err != nil {
				return nil, deny("decode tenant command key: %v", err)
			}
			keys[commandKey.KeyID] = key
		}
	}
	if cleanupOperation {
		for _, commandKey := range p.SiteCleanupCommandKeys {
			if !contains(commandKey.Operations, operation) {
				continue
			}
			if _, exists := keys[commandKey.KeyID]; exists {
				return nil, deny("command key ID collision")
			}
			key, err := decodePublicKey(commandKey.PublicKey)
			if err != nil {
				return nil, deny("decode site cleanup command key: %v", err)
			}
			keys[commandKey.KeyID] = key
		}
	}
	if len(keys) == 0 {
		return nil, deny("site policy has no key authorized for command tenant and operation")
	}
	return keys, nil
}

// TrustedTaskKeys returns only the tenant-owned keys whose signed scope names
// the exact service. An empty result is valid and keeps task admission opt-in;
// callers must not infer task authority from a command key or transport token.
func (p SitePolicy) TrustedTaskKeys(tenantID, serviceID string) (map[string]ed25519.PublicKey, error) {
	if !routeID(serviceID) {
		return nil, deny("invalid task service ID")
	}
	tenant, ok := p.tenant(tenantID)
	if !ok || !contains(tenant.ServiceIDs, serviceID) {
		return nil, deny("unknown task tenant or service")
	}
	keys := make(map[string]ed25519.PublicKey)
	for _, taskKey := range tenant.TaskKeys {
		if !contains(taskKey.ServiceIDs, serviceID) {
			continue
		}
		key, err := decodePublicKey(taskKey.PublicKey)
		if err != nil {
			return nil, deny("decode tenant task key: %v", err)
		}
		keys[taskKey.KeyID] = key
	}
	return keys, nil
}

const (
	maxCommandPayloadBytes = 256 << 10
	maxCommandLifetime     = 15 * time.Minute
	maxCommandClockSkew    = 2 * time.Minute
)

// Validate checks the signed command's finite schema and validity window. The
// runtime-reference grammar is deliberately validated by the uplink package,
// which owns that wire namespace; this method still bounds it before routing.
func (c CommandStatement) Validate(now time.Time) error {
	if c.SchemaVersion != CommandSchemaV2 || !bounded(c.CommandID, 256) ||
		!bounded(c.TenantID, 128) || !bounded(c.NodeID, 128) ||
		!bounded(c.InstanceID, 256) || !bounded(c.RuntimeRef, 1024) {
		return deny("invalid command identity")
	}
	if _, ok := commandOperations[c.Kind]; !ok {
		return deny("unsupported command operation")
	}
	if c.ClaimGeneration == 0 || c.InstanceGeneration == 0 || c.CommandSequence == 0 {
		return deny("command generations and sequence must be positive")
	}
	if len(c.Payload) == 0 || len(c.Payload) > maxCommandPayloadBytes || !json.Valid(c.Payload) {
		return deny("invalid command payload")
	}
	issued, err := time.Parse(time.RFC3339Nano, c.IssuedAt)
	if err != nil {
		return deny("invalid command issue time")
	}
	expires, err := time.Parse(time.RFC3339Nano, c.ExpiresAt)
	if err != nil || !expires.After(issued) || expires.Sub(issued) > maxCommandLifetime {
		return deny("invalid command expiry")
	}
	if !now.IsZero() {
		if issued.After(now.Add(maxCommandClockSkew)) {
			return deny("command issue time is too far in the future")
		}
		if !expires.After(now) {
			return deny("command has expired according to node time")
		}
	}
	return nil
}

func (p SitePolicy) publisher(keyID string) (PublisherRule, bool) {
	for _, publisher := range p.Publishers {
		if publisher.KeyID == keyID {
			return publisher, true
		}
	}
	return PublisherRule{}, false
}
func (p SitePolicy) tenant(id string) (TenantRule, bool) {
	for _, tenant := range p.Tenants {
		if tenant.TenantID == id {
			return tenant, true
		}
	}
	return TenantRule{}, false
}

func decodePublicKey(encoded string) (ed25519.PublicKey, error) {
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(decoded) != ed25519.PublicKeySize {
		return nil, errors.New("not an Ed25519 public key")
	}
	return ed25519.PublicKey(decoded), nil
}

func within(request, ceiling ResourceLimits) bool {
	return request.MemoryBytes <= ceiling.MemoryBytes && request.CPUMillis <= ceiling.CPUMillis && request.PIDs <= ceiling.PIDs
}
func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
func containsProfile(values []ProfileRef, wanted ProfileRef) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
func artifactsAllowed(artifacts, rules []ArtifactDigest) bool {
	for _, artifact := range artifacts {
		if !slices.Contains(rules, artifact) {
			return false
		}
	}
	return true
}
func validateAllowedArtifacts(rules []ArtifactDigest, authority string) error {
	if len(rules) > maxAllowedArtifacts {
		return deny("%s has too many allowed artifacts", authority)
	}
	seen := make(map[ArtifactDigest]struct{}, len(rules))
	for _, rule := range rules {
		if !bounded(rule.Kind, 128) || !digest(rule.Digest) {
			return deny("%s has invalid allowed artifact", authority)
		}
		if _, duplicate := seen[rule]; duplicate {
			return deny("%s has duplicate allowed artifact", authority)
		}
		seen[rule] = struct{}{}
	}
	return nil
}
func bounded(value string, limit int) bool {
	return strings.TrimSpace(value) != "" && len(value) <= limit && !strings.ContainsRune(value, '\x00')
}
func absolutePath(value string) bool {
	return len(value) <= 512 && strings.HasPrefix(value, "/") && !strings.Contains(value, "//") && !strings.Contains(value, "..") && !strings.ContainsRune(value, '\x00')
}

var repositoryComponent = regexp.MustCompile(`^[a-z0-9]+(?:[._-]+[a-z0-9]+)*$`)

func repositoryName(value string) bool {
	if !bounded(value, 512) || strings.ContainsAny(value, "@\\") || strings.Contains(value, "://") ||
		strings.HasPrefix(value, "/") || strings.HasSuffix(value, "/") || strings.Contains(value, "//") {
		return false
	}
	parts := strings.Split(value, "/")
	for index, part := range parts {
		if index == 0 && strings.Contains(part, ":") {
			host, port, ok := strings.Cut(part, ":")
			value, err := strconv.Atoi(port)
			if !ok || strings.Contains(port, ":") || !repositoryComponent.MatchString(host) || err != nil || value < 1 || value > 65535 {
				return false
			}
			continue
		}
		if !repositoryComponent.MatchString(part) {
			return false
		}
	}
	return true
}
func digest(value string) bool {
	if !strings.HasPrefix(value, sha256DigestPrefix) || len(value) != len(sha256DigestPrefix)+64 {
		return false
	}
	for _, char := range value[len(sha256DigestPrefix):] {
		if !(char >= 'a' && char <= 'f' || char >= '0' && char <= '9') {
			return false
		}
	}
	return true
}
func deny(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrDenied}, args...)...)
}

// Profile describes a built-in runtime adapter. The registry deliberately has no
// dynamic loading mechanism: policy may select only profiles compiled into the
// release being verified.
type Profile struct {
	Ref                ProfileRef
	UID                int
	GID                int
	StatePath          string
	StateSchemaVersion string
}

type Registry interface {
	Lookup(ProfileRef) (Profile, bool)
}

type StaticRegistry []Profile

func (r StaticRegistry) Lookup(ref ProfileRef) (Profile, bool) {
	for _, profile := range r {
		if profile.Ref == ref {
			return profile, true
		}
	}
	return Profile{}, false
}

func DefaultProfiles() StaticRegistry {
	return StaticRegistry{
		{Ref: ProfileRef{ID: "generic-v1", Version: "v1"}, UID: 65532, GID: 65532, StatePath: "/state", StateSchemaVersion: "v1"},
		{Ref: ProfileRef{ID: "hermes-v1", Version: "v1"}, UID: 65532, GID: 65532, StatePath: "/opt/data", StateSchemaVersion: "v1"},
		{Ref: ProfileRef{ID: "openclaw-v1", Version: "v1"}, UID: 65532, GID: 65532, StatePath: "/home/node/.openclaw", StateSchemaVersion: "v1"},
	}
}
