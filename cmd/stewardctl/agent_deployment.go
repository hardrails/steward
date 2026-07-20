package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/agentapp"
	"github.com/hardrails/steward/internal/controlclient"
	"github.com/hardrails/steward/internal/controlstore"
	"github.com/hardrails/steward/internal/dsse"
)

func agentDeployment(arguments []string, stdout io.Writer) error {
	if len(arguments) == 0 {
		return errors.New("agent deployment requires apply, status, list, or remove")
	}
	switch arguments[0] {
	case "apply":
		return agentDeploymentApply(arguments[1:], stdout)
	case "status":
		return agentDeploymentStatus(arguments[1:], stdout)
	case "list":
		return agentDeploymentList(arguments[1:], stdout)
	case "remove":
		return agentDeploymentRemove(arguments[1:], stdout)
	default:
		return fmt.Errorf("unknown agent deployment command %q; expected apply, status, list, or remove", arguments[0])
	}
}

func agentDeploymentApply(arguments []string, stdout io.Writer) error {
	leadingName, arguments := deploymentLeadingName(arguments)
	hydrated, err := applyAgentDeploymentContext(arguments)
	if err != nil {
		return err
	}
	flags := flag.NewFlagSet("agent deployment apply", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	common := addControlFlags(flags, true)
	bundlePath := flags.String("bundle", "agent.bundle.json", "portable agent bundle")
	capsulePath := flags.String("capsule", "capsule.dsse.json", "publisher-signed workload capsule")
	delegationPath := flags.String("delegation", "delegation.dsse.json", "tenant-signed controller delegation")
	var tenantID string
	flags.StringVar(&tenantID, "tenant", "", "tenant identity")
	flags.StringVar(&tenantID, "tenant-id", "", "alias for -tenant")
	generation := flags.Uint64("generation", 0, "desired generation; inferred when omitted")
	revision := flags.Uint64("revision", 0, "last observed revision; fetched when omitted")
	if err := flags.Parse(hydrated); err != nil {
		return err
	}
	if tenantID == "" || flags.NArg() > 1 || leadingName != "" && flags.NArg() != 0 {
		return errors.New("agent deployment apply requires a tenant and accepts at most one deployment name")
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
	deploymentID := bundle.Definition.Name
	if leadingName != "" {
		deploymentID = leadingName
	} else if flags.NArg() == 1 {
		deploymentID = flags.Arg(0)
	}
	capsuleRaw, err := readCLIArtifact(*capsulePath)
	if err != nil {
		return fmt.Errorf("read workload capsule: %w", err)
	}
	delegationRaw, err := readCLIArtifact(*delegationPath)
	if err != nil {
		return fmt.Errorf("read controller delegation: %w", err)
	}
	delegation, err := admission.InspectCommandDelegation(delegationRaw, timeNow().UTC())
	if err != nil {
		return fmt.Errorf("inspect controller delegation: %w", err)
	}
	if delegation.TenantID != tenantID || delegation.Admission == nil ||
		delegation.Admission.CapsuleDigest != dsse.Digest(capsuleRaw) ||
		!deploymentLifecycleGranted(delegation.Operations) {
		return errors.New("controller delegation does not bind this tenant, capsule, and complete agent lifecycle")
	}
	if envelope, err := dsse.Parse(capsuleRaw); err != nil || envelope.PayloadType != admission.CapsulePayloadType {
		return errors.New("workload capsule is not a Steward capsule envelope")
	}
	client, err := common.client(true)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	current, found, err := loadCurrentDeployment(ctx, client, tenantID, deploymentID)
	if err != nil {
		return err
	}
	if *revision == 0 && found {
		*revision = current.Revision
	}
	if *generation == 0 {
		*generation = 1
		if found {
			*generation = current.Generation
			if current.BundleDigest != bundleDigest || current.CapsuleDigest != dsse.Digest(capsuleRaw) ||
				current.DelegationDigest != dsse.Digest(delegationRaw) || current.DesiredState != controlstore.DeploymentRunning {
				if current.Generation == ^uint64(0) {
					return errors.New("deployment generation is exhausted")
				}
				*generation++
			}
		}
	}
	deployed, err := client.ApplyDeployment(ctx, tenantID, deploymentID, controlclient.DeploymentApply{
		Generation: *generation, ExpectedRevision: *revision,
		AgentName: bundle.Definition.Name, BundleDigest: bundleDigest,
		CapsuleDSSE: capsuleRaw, DelegationDSSE: delegationRaw,
	})
	if err != nil {
		return err
	}
	return writeAgentJSON(stdout, deployed)
}

func agentDeploymentStatus(arguments []string, stdout io.Writer) error {
	leadingName, arguments := deploymentLeadingName(arguments)
	hydrated, err := applyAgentDeploymentContext(arguments)
	if err != nil {
		return err
	}
	flags := flag.NewFlagSet("agent deployment status", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	common := addControlFlags(flags, true)
	tenantID := deploymentTenantFlags(flags)
	if err := flags.Parse(hydrated); err != nil {
		return err
	}
	if *tenantID == "" || leadingName == "" && flags.NArg() != 1 || leadingName != "" && flags.NArg() != 0 {
		return errors.New("agent deployment status requires a tenant and one deployment name")
	}
	deploymentID := leadingName
	if deploymentID == "" {
		deploymentID = flags.Arg(0)
	}
	client, err := common.client(true)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	deployment, err := client.GetDeployment(ctx, *tenantID, deploymentID)
	if err != nil {
		return err
	}
	return writeAgentJSON(stdout, deployment)
}

func agentDeploymentList(arguments []string, stdout io.Writer) error {
	hydrated, err := applyAgentDeploymentContext(arguments)
	if err != nil {
		return err
	}
	flags := flag.NewFlagSet("agent deployment list", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	common := addControlFlags(flags, true)
	tenantID := deploymentTenantFlags(flags)
	after := flags.String("after", "", "continue after this deployment name")
	limit := flags.Int("limit", 100, "maximum deployments, from 1 to 500")
	if err := flags.Parse(hydrated); err != nil {
		return err
	}
	if *tenantID == "" || flags.NArg() != 0 || *limit < 1 || *limit > 500 {
		return errors.New("agent deployment list requires a tenant, no positional arguments, and a limit from 1 to 500")
	}
	client, err := common.client(true)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	page, err := client.ListDeployments(ctx, *tenantID, *after, *limit)
	if err != nil {
		return err
	}
	return writeAgentJSON(stdout, page)
}

func agentDeploymentRemove(arguments []string, stdout io.Writer) error {
	leadingName, arguments := deploymentLeadingName(arguments)
	hydrated, err := applyAgentDeploymentContext(arguments)
	if err != nil {
		return err
	}
	flags := flag.NewFlagSet("agent deployment remove", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	common := addControlFlags(flags, true)
	tenantID := deploymentTenantFlags(flags)
	revision := flags.Uint64("revision", 0, "last observed revision; fetched when omitted")
	if err := flags.Parse(hydrated); err != nil {
		return err
	}
	if *tenantID == "" || leadingName == "" && flags.NArg() != 1 || leadingName != "" && flags.NArg() != 0 {
		return errors.New("agent deployment remove requires a tenant and one deployment name")
	}
	deploymentID := leadingName
	if deploymentID == "" {
		deploymentID = flags.Arg(0)
	}
	client, err := common.client(true)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if *revision == 0 {
		current, err := client.GetDeployment(ctx, *tenantID, deploymentID)
		if err != nil {
			return err
		}
		*revision = current.Revision
	}
	deployment, err := client.RemoveDeployment(ctx, *tenantID, deploymentID, *revision)
	if err != nil {
		return err
	}
	return writeAgentJSON(stdout, deployment)
}

func deploymentLeadingName(arguments []string) (string, []string) {
	if len(arguments) == 0 || strings.HasPrefix(arguments[0], "-") {
		return "", arguments
	}
	return arguments[0], arguments[1:]
}

func deploymentTenantFlags(flags *flag.FlagSet) *string {
	var tenantID string
	flags.StringVar(&tenantID, "tenant", "", "tenant identity")
	flags.StringVar(&tenantID, "tenant-id", "", "alias for -tenant")
	return &tenantID
}

func deploymentLifecycleGranted(operations []string) bool {
	for _, operation := range []string{"admit", "destroy", "start", "stop"} {
		if !slices.Contains(operations, operation) {
			return false
		}
	}
	return true
}

func loadCurrentDeployment(
	ctx context.Context,
	client *controlclient.Client,
	tenantID, deploymentID string,
) (controlclient.Deployment, bool, error) {
	current, err := client.GetDeployment(ctx, tenantID, deploymentID)
	if err == nil {
		return current, true, nil
	}
	var apiError *controlclient.APIError
	if errors.As(err, &apiError) && apiError.Status == http.StatusNotFound {
		return controlclient.Deployment{}, false, nil
	}
	return controlclient.Deployment{}, false, err
}

func applyAgentDeploymentContext(arguments []string) ([]string, error) {
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
	prefix := make([]string, 0, 8)
	for _, value := range []struct{ name, content string }{
		{"control-url", selected.ControlURL}, {"token-file", selected.TokenFile}, {"ca-file", selected.CAFile},
	} {
		if value.content != "" && !hasNamedFlag(arguments, value.name) {
			prefix = append(prefix, "-"+value.name, value.content)
		}
	}
	if selected.TenantID != "" && !hasNamedFlag(arguments, "tenant") && !hasNamedFlag(arguments, "tenant-id") {
		prefix = append(prefix, "-tenant", selected.TenantID)
	}
	return append(prefix, arguments...), nil
}
