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
	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/controlstore"
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
	forkPlanPath := flags.String("fork-plan", "", "fork plan whose fresh identity and cleanup lifecycle to authorize")
	outputPath := flags.String("out", "delegation.dsse.json", "new tenant-signed controller delegation")
	pinnedRoot := flags.String("site-root-public-key", "", "independently pinned site-root public key")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 1 || *controllerPublicPath == "" || *outputPath == "" ||
		*generation == 0 || *claimGeneration == 0 || *validFor < time.Second || *validFor%time.Second != 0 {
		return errors.New("agent authorize requires one site package, a controller public key, positive generations, output, and a positive whole-second lifetime")
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
	bundleDigest, err := agentapp.DigestJSON(bundle)
	if err != nil {
		return err
	}
	var forkPlan *agentapp.ForkPlan
	if *forkPlanPath != "" {
		generationExplicit := false
		flags.Visit(func(current *flag.Flag) {
			generationExplicit = generationExplicit || current.Name == "generation"
		})
		raw, readErr := readCLIArtifact(*forkPlanPath)
		if readErr != nil {
			return fmt.Errorf("read fork plan: %w", readErr)
		}
		plan, decodeErr := agentapp.DecodeForkPlan(raw)
		if decodeErr != nil {
			return decodeErr
		}
		if plan.BundleDigest != bundleDigest {
			return errors.New("fork plan does not bind the selected agent bundle")
		}
		forkPlan = &plan
		if *deploymentID != "" && *deploymentID != plan.DeploymentID ||
			*instanceID != "" && *instanceID != plan.InstanceID ||
			*lineageID != "" && *lineageID != plan.LineageID ||
			generationExplicit && *generation != plan.Generation {
			return errors.New("fork plan conflicts with an explicitly selected deployment, instance, lineage, or generation")
		}
		*deploymentID, *instanceID, *lineageID = plan.DeploymentID, plan.InstanceID, plan.LineageID
		*generation = plan.Generation
		if *nodeIDsValue == "" {
			*nodeIDsValue = plan.SourceNodeID
		}
	}
	if *nodeIDsValue == "" {
		return errors.New("agent authorize requires node IDs, or a fork plan that binds its source node")
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
	if forkPlan != nil && (len(nodeIDs) != 1 || nodeIDs[0] != forkPlan.SourceNodeID) {
		return errors.New("fork authorization must name only the source node bound into the fork plan")
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
		LineageID: *lineageID, Generation: *generation, ResumeState: forkPlan != nil,
	})
	if err != nil {
		return err
	}
	operations := []string{"admit", "destroy", "renew", "start", "stop"}
	if forkPlan != nil {
		operations = []string{"admit", "clone-state", "destroy", "purge", "renew", "start", "stop"}
	}
	controllerPublic, err := readPublicKey(*controllerPublicPath)
	if err != nil {
		return fmt.Errorf("read Control controller public key: %w", err)
	}
	issuedAt := timeNow().UTC()
	maxValidity := 24 * time.Hour
	if forkPlan != nil {
		maxValidity = 31 * 24 * time.Hour
		if forkPlan.ExpiresAt != "" {
			expires, parseErr := time.Parse(time.RFC3339Nano, forkPlan.ExpiresAt)
			if parseErr != nil || !expires.After(issuedAt) {
				return errors.New("fork plan has already expired")
			}
			minimum := expires.Sub(issuedAt) + controlstore.MinDeploymentForkCleanupWindow
			explicit := false
			flags.Visit(func(current *flag.Flag) { explicit = explicit || current.Name == "valid-for" })
			if !explicit {
				*validFor = minimum
			} else if *validFor < minimum {
				return fmt.Errorf("fork authorization must remain valid through cleanup; use -valid-for %s or longer", minimum.Round(time.Second))
			}
		}
	}
	if *validFor > maxValidity {
		return fmt.Errorf("agent authorization lifetime exceeds %s", maxValidity)
	}
	statement := admission.CommandDelegation{
		SchemaVersion: admission.CommandDelegationSchemaV1, DelegationID: *deploymentID,
		TenantID: verifiedSite.inventory.TenantID, ControllerKeyID: *controllerKeyID,
		ControllerPublicKey: base64.StdEncoding.EncodeToString(controllerPublic),
		Operations:          operations, NodeIDs: nodeIDs,
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
	requiredAssurance := ""
	if placement.Isolation == "hardened" {
		requiredIsolation = "gvisor"
		requiredAssurance = controlprotocol.RuntimeAssuranceSharedHost
	}
	return &admission.CommandDelegationAdmissionTemplate{
		CapsuleDigest: intent.CapsuleDigest, Resources: intent.Resources, Capabilities: intent.Capabilities,
		StateDisposition: intent.StateDisposition, InferenceRouteID: intent.InferenceRouteID,
		ModelAlias: intent.ModelAlias, ServiceID: intent.ServiceID,
		EgressRouteIDs: append([]string(nil), intent.EgressRouteIDs...),
		ConnectorIDs:   append([]string(nil), intent.ConnectorIDs...), EffectMode: intent.EffectMode,
		Placement: &admission.CommandDelegationPlacement{
			RequiredIsolation: requiredIsolation, RequiredAssurance: requiredAssurance,
			RequiredLabels: required, PreferredLabels: preferred,
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
