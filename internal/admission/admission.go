// Package admission defines Steward's offline, signed admission contracts.
// It is intentionally a finite typed policy intersection, not a general policy
// language or a Docker API wrapper.
package admission

import (
	"crypto/ed25519"
	"encoding/base64"
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
	CapsulePayloadType = "application/vnd.steward.capsule.v1+json"
	PolicyPayloadType  = "application/vnd.steward.site-policy.v1+json"
	SchemaV1           = "steward.admission.v1"
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
}

type AuthenticatedIdentity struct {
	TenantID string
	NodeID   string
}

// SitePolicy is site-root-signed. It constrains publisher authority and binds
// scheduling policy to tenants without requiring a site co-signature on every
// reusable publisher capsule.
type SitePolicy struct {
	SchemaVersion string          `json:"schema_version"`
	PolicyID      string          `json:"policy_id"`
	PolicyEpoch   uint64          `json:"policy_epoch"`
	Publishers    []PublisherRule `json:"publishers"`
	Tenants       []TenantRule    `json:"tenants"`
}

type PublisherRule struct {
	KeyID                  string         `json:"key_id"`
	PublicKey              string         `json:"public_key"`
	Revoked                bool           `json:"revoked"`
	AllowedProfiles        []ProfileRef   `json:"allowed_profiles"`
	AllowedRepositories    []string       `json:"allowed_repositories"`
	AllowedManifestDigests []string       `json:"allowed_manifest_digests,omitempty"`
	ResourceCeiling        ResourceLimits `json:"resource_ceiling"`
}

type TenantRule struct {
	TenantID          string         `json:"tenant_id"`
	PublisherKeyIDs   []string       `json:"publisher_key_ids"`
	ResourceCeiling   ResourceLimits `json:"resource_ceiling"`
	InferenceRouteIDs []string       `json:"inference_route_ids,omitempty"`
	ServiceIDs        []string       `json:"service_ids,omitempty"`
	EgressRouteIDs    []string       `json:"egress_route_ids,omitempty"`
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

// VerifyAndAdmit authenticates the signed policy first, verifies a capsule only
// with a policy-authorized publisher key, then applies finite authority
// intersection to a caller-bound intent.
func VerifyAndAdmit(capsuleEnvelope, policyEnvelope []byte, siteRoots map[string]ed25519.PublicKey, intent InstanceIntent, caller AuthenticatedIdentity, fences PersistedFences, now time.Time, profiles Registry) (EffectiveAdmission, error) {
	policyPayload, siteRootKeyID, err := dsse.Verify(policyEnvelope, PolicyPayloadType, siteRoots)
	if err != nil {
		return EffectiveAdmission{}, deny("verify site policy: %v", err)
	}
	var policy SitePolicy
	if err := dsse.DecodeStrictInto(policyPayload, dsse.DefaultMaxEnvelopeBytes, &policy); err != nil {
		return EffectiveAdmission{}, deny("decode site policy: %v", err)
	}
	if err := policy.Validate(); err != nil {
		return EffectiveAdmission{}, err
	}
	publisherKeys, err := policy.PublisherKeys()
	if err != nil {
		return EffectiveAdmission{}, err
	}
	capsulePayload, publisherKeyID, err := dsse.Verify(capsuleEnvelope, CapsulePayloadType, publisherKeys)
	if err != nil {
		return EffectiveAdmission{}, deny("verify profile capsule: %v", err)
	}
	var capsule ProfileCapsule
	if err := dsse.DecodeStrictInto(capsulePayload, dsse.DefaultMaxEnvelopeBytes, &capsule); err != nil {
		return EffectiveAdmission{}, deny("decode profile capsule: %v", err)
	}
	if err := capsule.Validate(now); err != nil {
		return EffectiveAdmission{}, err
	}
	if capsule.PublisherKeyID != publisherKeyID {
		return EffectiveAdmission{}, deny("capsule publisher key ID does not match verified signature")
	}
	return Intersect(capsule, dsse.Digest(capsuleEnvelope), policy, dsse.Digest(policyEnvelope), publisherKeyID, siteRootKeyID, intent, caller, fences, profiles)
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
		if !bounded(intent.InferenceRouteID, 128) || !bounded(intent.ModelAlias, 256) || !contains(tenant.InferenceRouteIDs, intent.InferenceRouteID) {
			return deny("inference route is not authorized")
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
	return nil
}

func (c Capabilities) SubsetOf(maximum Capabilities) bool {
	return (!c.State || maximum.State) && (!c.Inference || maximum.Inference) &&
		(!c.Service || maximum.Service) && (!c.Egress || maximum.Egress)
}

// CanonicalRouteIDs returns a detached, sorted route set for fingerprints and
// gateway grants. Admission rejects duplicates, so sorting cannot change meaning.
func CanonicalRouteIDs(routes []string) []string {
	result := append([]string(nil), routes...)
	slices.Sort(result)
	return result
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
	for _, artifact := range c.Artifacts {
		if !bounded(artifact.Kind, 128) || !digest(artifact.Digest) {
			return deny("invalid capsule artifact")
		}
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
	if p.SchemaVersion != SchemaV1 || !bounded(p.PolicyID, 128) || p.PolicyEpoch == 0 || len(p.Publishers) == 0 || len(p.Publishers) > 128 || len(p.Tenants) == 0 || len(p.Tenants) > 1024 {
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
	}
	seenTenants := map[string]struct{}{}
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
		for _, route := range tenant.InferenceRouteIDs {
			if !bounded(route, 128) {
				return deny("invalid inference route")
			}
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
	}
	return nil
}

var routeIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

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
