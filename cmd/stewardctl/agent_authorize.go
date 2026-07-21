package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/agentapp"
	"github.com/hardrails/steward/internal/dsse"
)

type agentAuthorizeSummary struct {
	AgentName        string   `json:"agent_name"`
	Deployment       string   `json:"deployment"`
	TenantID         string   `json:"tenant_id"`
	NodeIDs          []string `json:"node_ids"`
	InstanceID       string   `json:"instance_id"`
	LineageID        string   `json:"lineage_id"`
	Generation       uint64   `json:"generation"`
	ClaimGeneration  uint64   `json:"claim_generation"`
	Delegation       string   `json:"delegation"`
	DelegationDigest string   `json:"delegation_digest"`
	ExpiresAt        string   `json:"expires_at"`
}

func agentAuthorize(arguments []string, stdout io.Writer) error {
	arguments = sitePositionalLast(arguments)
	flags := flag.NewFlagSet("agent authorize", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	bundlePath := flags.String("bundle", "agent.bundle.json", "portable agent bundle")
	capsulePath := flags.String("capsule", "capsule.dsse.json", "publisher-signed workload capsule")
	controllerPublicPath := flags.String("controller-public-key", "controller.public.pem", "Control controller Ed25519 public key")
	controllerKeyID := flags.String("controller-key-id", "controller-default", "Control controller signing key ID")
	nodeIDsValue := flags.String("node-ids", "", "comma-separated eligible node identities")
	deploymentID := flags.String("deployment", "", "stable deployment authority identity")
	instanceID := flags.String("instance-id", "", "stable workload instance identity")
	lineageID := flags.String("lineage-id", "", "stable state lineage identity")
	generation := flags.Uint64("generation", 1, "authorized instance generation")
	claimGeneration := flags.Uint64("claim-generation", 1, "tenant command authority generation")
	validFor := flags.Duration("valid-for", defaultExecutorDelegationValidity, "finite controller authority lifetime")
	outputPath := flags.String("out", "delegation.dsse.json", "new tenant-signed controller delegation")
	pinnedRoot := flags.String("site-root-public-key", "", "independently pinned site-root public key")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 1 || *nodeIDsValue == "" || *controllerPublicPath == "" || *outputPath == "" ||
		*generation == 0 || *claimGeneration == 0 || *validFor < time.Second || *validFor > 24*time.Hour || *validFor%time.Second != 0 {
		return errors.New("agent authorize requires one site package, node IDs, controller public key, positive generations, output, and a whole-second lifetime up to 24 hours")
	}
	nodeIDs, err := canonicalCommandDelegationList(*nodeIDsValue)
	if err != nil {
		return fmt.Errorf("parse authorized node IDs: %w", err)
	}
	if len(nodeIDs) > 64 {
		return errors.New("agent authorization permits at most 64 nodes")
	}
	for _, nodeID := range nodeIDs {
		if !validOptionalControlIdentifier(nodeID, 128) {
			return errors.New("agent authorization contains an invalid node identity")
		}
	}
	siteDirectory, err := filepath.Abs(flags.Arg(0))
	if err != nil {
		return errors.New("site package directory is invalid")
	}
	verifiedSite, err := verifySitePackage(siteDirectory, *pinnedRoot)
	if err != nil {
		return err
	}
	bundleRaw, err := readCLIArtifact(*bundlePath)
	if err != nil {
		return fmt.Errorf("read agent bundle: %w", err)
	}
	bundle, err := agentapp.DecodeBundle(bundleRaw)
	if err != nil {
		return err
	}
	if *deploymentID == "" {
		*deploymentID = bundle.Definition.Name + "-deployment"
	}
	if *instanceID == "" {
		*instanceID = bundle.Definition.Name
	}
	prepared, err := prepareAgentAdmission(agentAdmissionInputs{
		Bundle: bundle, CapsulePath: *capsulePath,
		PolicyPath:   filepath.Join(siteDirectory, "public", "site-policy.dsse.json"),
		SiteRootPath: filepath.Join(siteDirectory, "public", "site-root.public"), SiteRootKeyID: "site-root-1",
		TenantID: verifiedSite.inventory.TenantID, NodeID: nodeIDs[0], InstanceID: *instanceID,
		LineageID: *lineageID, Generation: *generation,
	})
	if err != nil {
		return err
	}
	controllerPublic, err := readPublicKey(*controllerPublicPath)
	if err != nil {
		return fmt.Errorf("read Control controller public key: %w", err)
	}
	issuedAt := timeNow().UTC()
	statement := admission.CommandDelegation{
		SchemaVersion: admission.CommandDelegationSchemaV1, DelegationID: *deploymentID,
		TenantID: verifiedSite.inventory.TenantID, ControllerKeyID: *controllerKeyID,
		ControllerPublicKey: base64.StdEncoding.EncodeToString(controllerPublic),
		Operations:          []string{"admit", "destroy", "renew", "start", "stop"}, NodeIDs: nodeIDs,
		Instances: []admission.CommandDelegationInstance{{
			InstanceID: prepared.InstanceID, LineageID: prepared.LineageID,
			MinInstanceGeneration: *generation, MaxInstanceGeneration: *generation,
		}},
		ClaimGeneration: *claimGeneration, Admission: agentDelegationTemplate(prepared.Intent, bundle.Definition.Placement),
		IssuedAt: issuedAt.Format(time.RFC3339Nano), ExpiresAt: issuedAt.Add(*validFor).Format(time.RFC3339Nano),
	}
	payload, err := admission.MarshalCommandDelegation(statement)
	if err != nil {
		return err
	}
	commandKey, err := readPrivateKey(filepath.Join(siteDirectory, "private", "tenant-command.private.pem"))
	if err != nil {
		return fmt.Errorf("read tenant command key: %w", err)
	}
	if err := validateGeneratedTenantCommandKey(verifiedSite.policy, commandKey); err != nil {
		return err
	}
	envelope, err := dsse.Sign(admission.CommandDelegationPayloadType, payload, "tenant-command-1", commandKey)
	if err != nil {
		return err
	}
	raw, err := dsse.Marshal(envelope)
	if err != nil {
		return err
	}
	if _, err := admission.VerifyCommandDelegation(raw, verifiedSite.policy, issuedAt); err != nil {
		return fmt.Errorf("verify generated controller delegation: %w", err)
	}
	if err := writeNewFile(*outputPath, raw, 0o600); err != nil {
		return fmt.Errorf("write controller delegation: %w", err)
	}
	return writeAgentJSON(stdout, agentAuthorizeSummary{
		AgentName: bundle.Definition.Name, Deployment: *deploymentID, TenantID: verifiedSite.inventory.TenantID,
		NodeIDs: nodeIDs, InstanceID: prepared.InstanceID, LineageID: prepared.LineageID,
		Generation: *generation, ClaimGeneration: *claimGeneration, Delegation: *outputPath,
		DelegationDigest: dsse.Digest(raw), ExpiresAt: statement.ExpiresAt,
	})
}

func agentDelegationTemplate(intent admission.InstanceIntent, placement agentapp.Placement) *admission.CommandDelegationAdmissionTemplate {
	required := make([]admission.CommandDelegationLabel, 0, len(placement.RequiredLabels))
	for _, label := range placement.RequiredLabels {
		required = append(required, admission.CommandDelegationLabel{Key: label.Key, Value: label.Value})
	}
	preferred := make([]admission.CommandDelegationLabel, 0, len(placement.PreferredLabels))
	for _, label := range placement.PreferredLabels {
		preferred = append(preferred, admission.CommandDelegationLabel{Key: label.Key, Value: label.Value})
	}
	slices.SortFunc(required, compareDelegationLabels)
	slices.SortFunc(preferred, compareDelegationLabels)
	tolerations := append([]string{}, placement.Tolerations...)
	slices.Sort(tolerations)
	requiredIsolation := ""
	if placement.Isolation == "hardened" {
		requiredIsolation = "gvisor"
	}
	return &admission.CommandDelegationAdmissionTemplate{
		CapsuleDigest: intent.CapsuleDigest, Resources: intent.Resources, Capabilities: intent.Capabilities,
		StateDisposition: intent.StateDisposition, InferenceRouteID: intent.InferenceRouteID,
		ModelAlias: intent.ModelAlias, ServiceID: intent.ServiceID,
		EgressRouteIDs: append([]string(nil), intent.EgressRouteIDs...),
		ConnectorIDs:   append([]string(nil), intent.ConnectorIDs...), EffectMode: intent.EffectMode,
		Placement: &admission.CommandDelegationPlacement{
			RequiredIsolation: requiredIsolation, RequiredLabels: required, PreferredLabels: preferred,
			SpreadBy: placement.SpreadBy, Tolerations: tolerations,
		},
	}
}

func compareDelegationLabels(left, right admission.CommandDelegationLabel) int {
	if compared := strings.Compare(left.Key, right.Key); compared != 0 {
		return compared
	}
	return strings.Compare(left.Value, right.Value)
}

func validateGeneratedTenantCommandKey(policy admission.SitePolicy, key ed25519.PrivateKey) error {
	for _, tenant := range policy.Tenants {
		for _, commandKey := range tenant.CommandKeys {
			if commandKey.KeyID != "tenant-command-1" {
				continue
			}
			public, err := base64.StdEncoding.Strict().DecodeString(commandKey.PublicKey)
			if err == nil && slices.Equal(public, key.Public().(ed25519.PublicKey)) {
				return nil
			}
		}
	}
	return errors.New("tenant command key does not match signed site policy authority")
}
