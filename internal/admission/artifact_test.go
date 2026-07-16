package admission

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"
)

func TestIntersectRequiresExactArtifactAuthority(t *testing.T) {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name       string
		mutate     func(*SitePolicy)
		wantDenied string
	}{
		{name: "success"},
		{
			name: "missing publisher rule",
			mutate: func(policy *SitePolicy) {
				policy.Publishers[0].AllowedArtifacts = nil
			},
			wantDenied: "publisher",
		},
		{
			name: "missing tenant rule",
			mutate: func(policy *SitePolicy) {
				policy.Tenants[0].AllowedArtifacts = nil
			},
			wantDenied: "tenant",
		},
		{
			name: "publisher wrong digest",
			mutate: func(policy *SitePolicy) {
				policy.Publishers[0].AllowedArtifacts[0].Digest = testDigest('d')
			},
			wantDenied: "publisher",
		},
		{
			name: "tenant wrong digest",
			mutate: func(policy *SitePolicy) {
				policy.Tenants[0].AllowedArtifacts[0].Digest = testDigest('d')
			},
			wantDenied: "tenant",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			capsule, policy := testCapsule(), testPolicy(public)
			if test.mutate != nil {
				test.mutate(&policy)
			}
			intent := testIntent(testDigest('d'))
			_, err := Intersect(
				capsule, intent.CapsuleDigest, policy, testDigest('e'), "publisher-1", "site-root",
				intent, AuthenticatedIdentity{TenantID: "tenant-a", NodeID: "node-a"},
				PersistedFences{}, DefaultProfiles(),
			)
			if test.wantDenied == "" {
				if err != nil {
					t.Fatalf("exact artifact authority rejected: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), "artifact") || !strings.Contains(err.Error(), test.wantDenied) {
				t.Fatalf("artifact authority err=%v, want %q denial", err, test.wantDenied)
			}
		})
	}
}

func TestVerifyCapsuleForImportRequiresPublisherArtifactAuthority(t *testing.T) {
	rootPublic, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publisherPublic, publisherPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	capsule := testCapsule()
	capsuleRaw := signJSON(t, CapsulePayloadType, capsule, "publisher-1", publisherPrivate)
	policy := testPolicy(publisherPublic)
	policy.Publishers[0].AllowedArtifacts = nil
	policyRaw := signJSON(t, PolicyPayloadType, policy, "site-root", rootPrivate)

	_, err = VerifyCapsuleForImport(
		capsuleRaw, policyRaw, map[string]ed25519.PublicKey{"site-root": rootPublic},
		time.Date(2026, 7, 16, 0, 0, 0, 0, time.UTC), DefaultProfiles(),
	)
	if err == nil || !strings.Contains(err.Error(), "artifact is not authorized for publisher") {
		t.Fatalf("missing publisher artifact authority err=%v", err)
	}
}

func TestSitePolicyValidatesExactAllowedArtifactRules(t *testing.T) {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	policy := testPolicy(public)
	policy.Publishers[0].AllowedArtifacts = append(
		policy.Publishers[0].AllowedArtifacts,
		ArtifactDigest{Kind: "sbom", Digest: testDigest('d')},
	)
	policy.Tenants[0].AllowedArtifacts = append(
		policy.Tenants[0].AllowedArtifacts,
		ArtifactDigest{Kind: "sbom", Digest: testDigest('d')},
	)
	if err := policy.Validate(); err != nil {
		t.Fatalf("same kind with a distinct exact digest should be valid: %v", err)
	}

	for _, test := range []struct {
		name   string
		mutate func(*SitePolicy)
		want   string
	}{
		{
			name: "duplicate publisher rule",
			mutate: func(policy *SitePolicy) {
				policy.Publishers[0].AllowedArtifacts = append(
					policy.Publishers[0].AllowedArtifacts,
					policy.Publishers[0].AllowedArtifacts[0],
				)
			},
			want: "publisher has duplicate allowed artifact",
		},
		{
			name: "duplicate tenant rule",
			mutate: func(policy *SitePolicy) {
				policy.Tenants[0].AllowedArtifacts = append(
					policy.Tenants[0].AllowedArtifacts,
					policy.Tenants[0].AllowedArtifacts[0],
				)
			},
			want: "tenant has duplicate allowed artifact",
		},
		{
			name: "invalid publisher rule",
			mutate: func(policy *SitePolicy) {
				policy.Publishers[0].AllowedArtifacts[0].Digest = "sha256:not-a-digest"
			},
			want: "publisher has invalid allowed artifact",
		},
		{
			name: "invalid tenant rule",
			mutate: func(policy *SitePolicy) {
				policy.Tenants[0].AllowedArtifacts[0].Kind = ""
			},
			want: "tenant has invalid allowed artifact",
		},
		{
			name: "publisher rule bound",
			mutate: func(policy *SitePolicy) {
				policy.Publishers[0].AllowedArtifacts = make([]ArtifactDigest, 129)
			},
			want: "publisher has too many allowed artifacts",
		},
		{
			name: "tenant rule bound",
			mutate: func(policy *SitePolicy) {
				policy.Tenants[0].AllowedArtifacts = make([]ArtifactDigest, 129)
			},
			want: "tenant has too many allowed artifacts",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			policy := testPolicy(public)
			test.mutate(&policy)
			if err := policy.Validate(); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("allowed artifact validation err=%v, want %q", err, test.want)
			}
		})
	}
}
