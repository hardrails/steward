package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/agentapp"
	"github.com/hardrails/steward/internal/nodeclient"
)

type agentApplyResult struct {
	AgentName    string                    `json:"agent_name"`
	BundleDigest string                    `json:"bundle_digest"`
	TenantID     string                    `json:"tenant_id"`
	NodeID       string                    `json:"node_id"`
	InstanceID   string                    `json:"instance_id"`
	LineageID    string                    `json:"lineage_id"`
	Generation   uint64                    `json:"generation"`
	RuntimeRef   string                    `json:"runtime_ref,omitempty"`
	Status       string                    `json:"status"`
	Intent       *admission.InstanceIntent `json:"intent,omitempty"`
}

func agentApply(arguments []string, stdout io.Writer) error {
	hydrated, err := applyNodeCLIContext(append([]string{"apply"}, arguments...))
	if err != nil {
		return err
	}
	arguments = hydrated[1:]
	flags := flag.NewFlagSet("agent apply", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	bundlePath := flags.String("bundle", "agent.bundle.json", "portable agent bundle")
	capsulePath := flags.String("capsule", "", "publisher-signed workload capsule")
	policyPath := flags.String("policy", "", "site-root-signed site policy")
	siteRootPath := flags.String("site-root-public-key", "", "base64 Ed25519 site-root public key")
	siteRootKeyID := flags.String("site-root-key-id", "", "site-root DSSE key ID")
	nodesPath := flags.String("nodes", "", "optional bounded node inventory for placement")
	var tenantID string
	flags.StringVar(&tenantID, "tenant", "", "tenant admission identity")
	flags.StringVar(&tenantID, "tenant-id", "", "alias for -tenant")
	nodeID := flags.String("node-id", "", "node admission identity")
	instanceID := flags.String("instance-id", "", "stable instance identity; defaults to the agent name")
	lineageID := flags.String("lineage-id", "", "state lineage identity; derived deterministically when omitted")
	generation := flags.Uint64("generation", 1, "instance generation")
	nodeURL := flags.String("node-url", "http://127.0.0.1:8090", "loopback Executor origin")
	tokenFile := flags.String("token-file", "", "owner-only Executor token")
	timeout := flags.Duration("timeout", 2*time.Minute, "bounded admit and start timeout")
	planOnly := flags.Bool("plan-only", false, "verify and print the exact intent without mutating the node")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || *capsulePath == "" || *policyPath == "" || *siteRootPath == "" ||
		*siteRootKeyID == "" || tenantID == "" || *generation == 0 || *timeout <= 0 || *timeout > 30*time.Minute ||
		(!*planOnly && *tokenFile == "") {
		return errors.New("agent apply requires capsule, policy, site root, tenant, positive generation and timeout, plus a node token unless -plan-only is used")
	}
	bundleRaw, err := readCLIArtifact(*bundlePath)
	if err != nil {
		return fmt.Errorf("read agent bundle: %w", err)
	}
	bundle, err := agentapp.DecodeBundle(bundleRaw)
	if err != nil {
		return err
	}
	if *nodesPath != "" {
		inventoryRaw, err := readCLIArtifact(*nodesPath)
		if err != nil {
			return fmt.Errorf("read node inventory: %w", err)
		}
		inventory, err := agentapp.DecodeInventory(inventoryRaw)
		if err != nil {
			return err
		}
		placement, err := agentapp.Schedule(bundle, tenantID, inventory)
		if err != nil {
			return err
		}
		if *nodeID == "" {
			*nodeID = placement.SelectedNode
		} else if *nodeID != placement.SelectedNode {
			return fmt.Errorf("requested node %q differs from the deterministic placement %q", *nodeID, placement.SelectedNode)
		}
	}
	if *nodeID == "" {
		return errors.New("agent apply requires -node-id or a -nodes inventory with an eligible node")
	}
	prepared, err := prepareAgentAdmission(agentAdmissionInputs{
		Bundle: bundle, CapsulePath: *capsulePath, PolicyPath: *policyPath,
		SiteRootPath: *siteRootPath, SiteRootKeyID: *siteRootKeyID,
		TenantID: tenantID, NodeID: *nodeID, InstanceID: *instanceID,
		LineageID: *lineageID, Generation: *generation,
	})
	if err != nil {
		return err
	}
	result := agentApplyResult{
		AgentName: prepared.Bundle.Definition.Name, BundleDigest: prepared.BundleDigest,
		TenantID: tenantID, NodeID: *nodeID, InstanceID: prepared.InstanceID,
		LineageID: prepared.LineageID, Generation: *generation, Status: "planned",
	}
	if *planOnly {
		result.Intent = &prepared.Intent
		return writeAgentJSON(stdout, result)
	}
	client, err := nodeclient.NewFromTokenFile(*nodeURL, *tokenFile)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	state, err := client.Admit(ctx, prepared.CapsuleRaw, prepared.Intent)
	if err != nil {
		return fmt.Errorf("admit agent: %w", err)
	}
	if state.Status != "running" {
		state, err = client.Start(ctx, state.RuntimeRef)
		if err != nil {
			return fmt.Errorf("start admitted agent %s: %w", state.RuntimeRef, err)
		}
	}
	if state.RuntimeRef == "" || state.Status != "running" {
		return fmt.Errorf("executor returned incomplete running state for agent %q", bundle.Definition.Name)
	}
	result.RuntimeRef = state.RuntimeRef
	result.Status = state.Status
	return writeAgentJSON(stdout, result)
}
