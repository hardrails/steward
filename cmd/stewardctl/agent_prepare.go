package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/agentapp"
)

type agentAdmissionInputs struct {
	Bundle        agentapp.Bundle
	CapsulePath   string
	PolicyPath    string
	SiteRootPath  string
	SiteRootKeyID string
	TenantID      string
	NodeID        string
	InstanceID    string
	LineageID     string
	Generation    uint64
}

type preparedAgentAdmission struct {
	Bundle       agentapp.Bundle
	BundleDigest string
	CapsuleRaw   []byte
	Intent       admission.InstanceIntent
	SitePolicy   admission.SitePolicy
	InstanceID   string
	LineageID    string
}

// prepareAgentAdmission validates every operator-controlled artifact and joins
// a portable application to its authenticated authority without making a
// network request. Both local apply and fleet deploy use this exact path.
func prepareAgentAdmission(input agentAdmissionInputs) (preparedAgentAdmission, error) {
	if err := input.Bundle.Validate(); err != nil {
		return preparedAgentAdmission{}, err
	}
	if input.InstanceID == "" {
		input.InstanceID = input.Bundle.Definition.Name
	}
	bundleDigest, err := agentapp.DigestJSON(input.Bundle)
	if err != nil {
		return preparedAgentAdmission{}, err
	}
	if input.LineageID == "" {
		input.LineageID = defaultAgentLineage(bundleDigest, input.TenantID, input.InstanceID, input.Generation)
	}
	capsuleRaw, err := readCLIArtifact(input.CapsulePath)
	if err != nil {
		return preparedAgentAdmission{}, fmt.Errorf("read workload capsule: %w", err)
	}
	policyRaw, err := readCLIArtifact(input.PolicyPath)
	if err != nil {
		return preparedAgentAdmission{}, fmt.Errorf("read site policy: %w", err)
	}
	siteRoot, err := readPublicKey(input.SiteRootPath)
	if err != nil {
		return preparedAgentAdmission{}, fmt.Errorf("read site root: %w", err)
	}
	verified, err := admission.VerifyCapsuleForImport(
		capsuleRaw, policyRaw, map[string]ed25519.PublicKey{input.SiteRootKeyID: siteRoot},
		timeNow().UTC(), admission.DefaultProfiles(),
	)
	if err != nil {
		return preparedAgentAdmission{}, err
	}
	intent, err := agentapp.BuildIntent(
		input.Bundle, verified, input.TenantID, input.NodeID, input.InstanceID, input.LineageID, input.Generation,
	)
	if err != nil {
		return preparedAgentAdmission{}, err
	}
	return preparedAgentAdmission{
		Bundle: input.Bundle, BundleDigest: bundleDigest, CapsuleRaw: capsuleRaw, Intent: intent,
		SitePolicy: verified.SitePolicy,
		InstanceID: input.InstanceID, LineageID: input.LineageID,
	}, nil
}

func defaultAgentLineage(bundleDigest, tenantID, instanceID string, generation uint64) string {
	identity := fmt.Sprintf("%s\x00%s\x00%s\x00%d", bundleDigest, tenantID, instanceID, generation)
	sum := sha256.Sum256([]byte(identity))
	return fmt.Sprintf("lineage-%x", sum[:])
}
