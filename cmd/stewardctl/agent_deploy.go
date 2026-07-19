package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"strings"
	"time"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/agentapp"
	"github.com/hardrails/steward/internal/controlclient"
	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/executoruplink"
)

const agentDeployCommandValidity = 14 * time.Minute

type agentDeployResult struct {
	AgentName      string `json:"agent_name"`
	BundleDigest   string `json:"bundle_digest"`
	TenantID       string `json:"tenant_id"`
	NodeID         string `json:"node_id"`
	InstanceID     string `json:"instance_id"`
	LineageID      string `json:"lineage_id"`
	Generation     uint64 `json:"generation"`
	RuntimeRef     string `json:"runtime_ref"`
	Status         string `json:"status"`
	AdmitCommandID string `json:"admit_command_id"`
	StartCommandID string `json:"start_command_id,omitempty"`
}

func agentDeploy(arguments []string, stdout io.Writer) error {
	hydrated, err := applyAgentControlContext(arguments)
	if err != nil {
		return err
	}
	flags := flag.NewFlagSet("agent deploy", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	common := addControlFlags(flags, true)
	bundlePath := flags.String("bundle", "agent.bundle.json", "portable agent bundle")
	capsulePath := flags.String("capsule", "", "publisher-signed workload capsule")
	policyPath := flags.String("policy", "", "site-root-signed site policy")
	siteRootPath := flags.String("site-root-public-key", "", "base64 Ed25519 site-root public key")
	siteRootKeyID := flags.String("site-root-key-id", "", "site-root DSSE key ID")
	nodesPath := flags.String("nodes", "", "optional bounded node inventory for placement")
	var tenantID string
	flags.StringVar(&tenantID, "tenant", "", "tenant admission identity")
	flags.StringVar(&tenantID, "tenant-id", "", "alias for -tenant")
	nodeID := flags.String("node-id", "", "destination node identity")
	instanceID := flags.String("instance-id", "", "stable instance identity; defaults to the agent name")
	lineageID := flags.String("lineage-id", "", "state lineage identity; derived deterministically when omitted")
	generation := flags.Uint64("generation", 1, "instance generation")
	claimGeneration := flags.Uint64("claim-generation", 1, "tenant lifecycle authority generation")
	commandKeyPath := flags.String("command-key", "", "owner-only Ed25519 tenant command private key")
	commandKeyID := flags.String("command-key-id", "", "tenant command key ID from site policy")
	timeout := flags.Duration("timeout", 5*time.Minute, "bounded time to wait for node reports")
	planOnly := flags.Bool("plan-only", false, "verify and print the exact intent without signing or submitting commands")
	if err := flags.Parse(hydrated); err != nil {
		return err
	}
	if flags.NArg() != 0 || *capsulePath == "" || *policyPath == "" || *siteRootPath == "" ||
		*siteRootKeyID == "" || tenantID == "" || *generation == 0 || *claimGeneration == 0 ||
		*timeout <= 0 || *timeout > 14*time.Minute ||
		(!*planOnly && (*commandKeyPath == "" || *commandKeyID == "")) {
		return errors.New("agent deploy requires capsule, policy, site root, tenant, positive generations and timeout, plus a command key unless -plan-only is used")
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
		return errors.New("agent deploy requires -node-id or a -nodes inventory with an eligible node")
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
	if *planOnly {
		return writeAgentJSON(stdout, agentApplyResult{
			AgentName: prepared.Bundle.Definition.Name, BundleDigest: prepared.BundleDigest,
			TenantID: tenantID, NodeID: *nodeID, InstanceID: prepared.InstanceID,
			LineageID: prepared.LineageID, Generation: *generation, Status: "planned", Intent: &prepared.Intent,
		})
	}
	privateKey, err := readPrivateKey(*commandKeyPath)
	if err != nil {
		return fmt.Errorf("read tenant command private key: %w", err)
	}
	for _, operation := range []string{"admit", "start"} {
		trusted, err := prepared.SitePolicy.TrustedCommandKeys(tenantID, operation)
		if err != nil {
			return fmt.Errorf("validate tenant command authority for %s: %w", operation, err)
		}
		public, ok := trusted[*commandKeyID]
		if !ok || !bytes.Equal(public, privateKey.Public().(ed25519.PublicKey)) {
			return fmt.Errorf("tenant command key %q is not authorized for %s by the authenticated site policy", *commandKeyID, operation)
		}
	}
	client, err := common.client(true)
	if err != nil {
		return err
	}
	now := timeNow().UTC()
	if now.UnixNano() <= 0 || now.UnixNano() >= math.MaxInt64-2 {
		return errors.New("current time cannot produce a bounded monotonic command sequence")
	}
	sequence := uint64(now.UnixNano())
	admitID, err := randomAgentID("agent-admit")
	if err != nil {
		return err
	}
	admitPayload, err := json.Marshal(struct {
		Capsule string                   `json:"capsule_dsse_base64"`
		Intent  admission.InstanceIntent `json:"intent"`
	}{Capsule: base64.StdEncoding.EncodeToString(prepared.CapsuleRaw), Intent: prepared.Intent})
	if err != nil {
		return err
	}
	admitRaw, err := signAgentCommand(
		admitID, tenantID, *nodeID, prepared.InstanceID, "admit", *claimGeneration,
		*generation, sequence, admitPayload, *commandKeyID, privateKey, now,
	)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	admit, err := submitAndWaitAgentCommand(ctx, client, tenantID, *nodeID, admitRaw, admitID)
	if err != nil {
		return fmt.Errorf("admit agent through control: %w", err)
	}
	if admit.DeliveryProtocol != controlprotocol.ExecutorProtocolV4 || admit.Result == nil || admit.Result.Admission == nil {
		return errors.New("node completed admission without the protocol-4 admission projection required by agent deploy")
	}
	projection := admit.Result.Admission
	result := agentDeployResult{
		AgentName: prepared.Bundle.Definition.Name, BundleDigest: prepared.BundleDigest,
		TenantID: tenantID, NodeID: *nodeID, InstanceID: prepared.InstanceID,
		LineageID: prepared.LineageID, Generation: *generation,
		RuntimeRef: projection.RuntimeRef, Status: projection.Status, AdmitCommandID: admitID,
	}
	if projection.Status == "running" {
		result.Status = "running"
		return writeAgentJSON(stdout, result)
	}
	startID, err := randomAgentID("agent-start")
	if err != nil {
		return err
	}
	startIssuedAt := timeNow().UTC()
	startRaw, err := signAgentCommand(
		startID, tenantID, *nodeID, prepared.InstanceID, "start", *claimGeneration,
		*generation, sequence+1, []byte(`{}`), *commandKeyID, privateKey, startIssuedAt,
	)
	if err != nil {
		return err
	}
	started, err := submitAndWaitAgentCommand(ctx, client, tenantID, *nodeID, startRaw, startID)
	if err != nil {
		return fmt.Errorf("start agent through control: %w", err)
	}
	if started.ReportedStatus != "running" {
		return fmt.Errorf("node reported %q after successful start", started.ReportedStatus)
	}
	result.StartCommandID = startID
	result.Status = "running"
	return writeAgentJSON(stdout, result)
}

func signAgentCommand(
	commandID, tenantID, nodeID, instanceID, kind string,
	claimGeneration, instanceGeneration, sequence uint64,
	payload []byte, keyID string, privateKey ed25519.PrivateKey, issuedAt time.Time,
) ([]byte, error) {
	runtimeRef, err := executoruplink.RuntimeRefV2(tenantID, nodeID, instanceID)
	if err != nil {
		return nil, err
	}
	statement := admission.CommandStatement{
		SchemaVersion: admission.CommandSchemaV2, CommandID: commandID,
		TenantID: tenantID, NodeID: nodeID, InstanceID: instanceID, RuntimeRef: runtimeRef,
		Kind: kind, ClaimGeneration: claimGeneration, InstanceGeneration: instanceGeneration,
		CommandSequence: sequence, IssuedAt: issuedAt.Format(time.RFC3339Nano),
		ExpiresAt: issuedAt.Add(agentDeployCommandValidity).Format(time.RFC3339Nano), Payload: json.RawMessage(payload),
	}
	if err := statement.Validate(issuedAt); err != nil {
		return nil, err
	}
	statementRaw, err := json.Marshal(statement)
	if err != nil {
		return nil, err
	}
	envelope, err := dsse.Sign(admission.CommandPayloadType, statementRaw, keyID, privateKey)
	if err != nil {
		return nil, err
	}
	return dsse.Marshal(envelope)
}

func submitAndWaitAgentCommand(
	ctx context.Context,
	client *controlclient.Client,
	tenantID, nodeID string,
	commandRaw []byte,
	commandID string,
) (controlclient.Command, error) {
	command, err := client.SubmitCommand(ctx, tenantID, nodeID, commandRaw)
	if err != nil {
		return controlclient.Command{}, err
	}
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		if command.State == "terminal" {
			if command.TerminalStatus != controlprotocol.ExecutorStatusDone {
				message := command.TerminalStatus
				if command.Result != nil && command.Result.Error != "" {
					message += ": " + command.Result.Error
				}
				return controlclient.Command{}, errors.New(strings.TrimSpace(message))
			}
			return command, nil
		}
		select {
		case <-ctx.Done():
			return controlclient.Command{}, ctx.Err()
		case <-ticker.C:
			command, err = client.GetCommand(ctx, tenantID, nodeID, commandID)
			if err != nil {
				return controlclient.Command{}, err
			}
		}
	}
}

func applyAgentControlContext(arguments []string) ([]string, error) {
	arguments, disabled, err := stripNoContextFlag(arguments)
	if err != nil || disabled {
		return arguments, err
	}
	config, _, err := loadCLIContextConfig()
	if err != nil {
		return nil, err
	}
	if config.Current == "" && strings.TrimSpace(os.Getenv("STEWARD_CONTEXT")) == "" {
		return arguments, nil
	}
	selected, err := selectedCLIContext(config)
	if err != nil {
		return nil, err
	}
	result := append([]string(nil), arguments...)
	for _, value := range []struct{ name, content string }{
		{"control-url", selected.ControlURL}, {"token-file", selected.TokenFile},
		{"ca-file", selected.CAFile}, {"node-id", selected.NodeID},
	} {
		if value.content != "" && !hasNamedFlag(result, value.name) {
			result = append(result, "-"+value.name, value.content)
		}
	}
	if selected.TenantID != "" && !hasNamedFlag(result, "tenant") && !hasNamedFlag(result, "tenant-id") {
		result = append(result, "-tenant", selected.TenantID)
	}
	return result, nil
}
