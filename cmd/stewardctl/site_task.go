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

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/gatewayclient"
	"github.com/hardrails/steward/internal/nodeclient"
	"github.com/hardrails/steward/internal/securefile"
)

type siteTaskConnectionSummary struct {
	SiteID           string `json:"site_id"`
	TenantID         string `json:"tenant_id"`
	NodeID           string `json:"node_id"`
	Context          string `json:"context"`
	GatewayURL       string `json:"gateway_url"`
	GatewayTokenFile string `json:"gateway_token_file"`
	ServiceTrustFile string `json:"service_trust_file"`
	TaskKeyFile      string `json:"task_key_file"`
	TaskKeyID        string `json:"task_key_id"`
	CurrentContext   bool   `json:"current_context"`
}

func siteTaskCommand(arguments []string, stdout io.Writer) error {
	if len(arguments) == 0 || arguments[0] != "connect" {
		return errors.New("site task requires connect")
	}
	return siteTaskConnect(arguments[1:], stdout)
}

func siteTaskConnect(arguments []string, stdout io.Writer) error {
	arguments = siteNodePositionalsLast(arguments, 1)
	flags := flag.NewFlagSet("site task connect", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	contextName := flags.String("context", "", "existing tenant operator CLI context")
	trustPath := flags.String("trust", "", "exported Gateway service trust inventory")
	gatewayURL := flags.String("gateway-url", "http://127.0.0.1:8091", "Gateway service origin")
	gatewayTokenPath := flags.String("gateway-token-file", "", "owner-only Gateway service token")
	taskKeyPath := flags.String("task-key", "", "owner-only tenant task private key")
	taskKeyID := flags.String("task-key-id", "tenant-task-1", "tenant task key ID from signed site policy")
	pinnedRoot := flags.String("site-root-public-key", "", "independently pinned site-root public key")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 1 || *trustPath == "" || *gatewayTokenPath == "" || *gatewayURL == "" || !taskIdentifier(*taskKeyID) {
		return errors.New("site task connect requires one site package, service trust, Gateway token, and a valid task key ID")
	}
	siteDirectory, err := filepath.Abs(flags.Arg(0))
	if err != nil {
		return errors.New("site package directory is invalid")
	}
	verifiedSite, err := verifySitePackage(siteDirectory, *pinnedRoot)
	if err != nil {
		return err
	}
	resolvedTrust, err := absoluteContextPath(*trustPath, true)
	if err != nil {
		return fmt.Errorf("resolve service trust: %w", err)
	}
	resolvedGatewayToken, err := absoluteContextPath(*gatewayTokenPath, true)
	if err != nil {
		return fmt.Errorf("resolve Gateway token: %w", err)
	}
	if *taskKeyPath == "" {
		*taskKeyPath = filepath.Join(siteDirectory, "private", "tenant-task.private.pem")
	}
	resolvedTaskKey, err := absoluteContextPath(*taskKeyPath, true)
	if err != nil {
		return fmt.Errorf("resolve task key: %w", err)
	}
	trustRaw, err := securefile.Read(resolvedTrust, maxServiceTrustBytes, securefile.TrustFile)
	if err != nil {
		return fmt.Errorf("read service trust: %w", err)
	}
	trust, err := decodeServiceTrustInventory(trustRaw)
	if err != nil {
		return err
	}
	if trust.TenantID != verifiedSite.inventory.TenantID {
		return errors.New("service trust tenant does not match the signed site package")
	}
	privateKey, err := readPrivateKey(resolvedTaskKey)
	if err != nil {
		return fmt.Errorf("read tenant task key: %w", err)
	}
	services := make([]string, 0, len(trust.Services))
	for _, service := range trust.Services {
		services = append(services, service.ServiceID)
	}
	if err := validateSiteTaskKey(verifiedSite.policy, trust.TenantID, *taskKeyID, privateKey, services); err != nil {
		return err
	}
	token, err := nodeclient.ReadToken(resolvedGatewayToken)
	if err != nil {
		return fmt.Errorf("validate Gateway token: %w", err)
	}
	if _, err := gatewayclient.New(*gatewayURL, token); err != nil {
		return fmt.Errorf("validate Gateway connection: %w", err)
	}
	config, _, err := loadCLIContextConfig()
	if err != nil {
		return err
	}
	if *contextName == "" {
		selected, err := selectedCLIContext(config)
		if err != nil {
			return errors.New("site task connect requires an existing tenant operator context or -context")
		}
		*contextName = selected.Name
	}
	if err := saveSiteTaskContext(
		*contextName, trust.TenantID, trust.NodeID, *gatewayURL, resolvedGatewayToken,
		resolvedTrust, resolvedTaskKey, *taskKeyID,
	); err != nil {
		return fmt.Errorf("save site task context: %w", err)
	}
	return writeAgentJSON(stdout, siteTaskConnectionSummary{
		SiteID: verifiedSite.inventory.SiteID, TenantID: trust.TenantID, NodeID: trust.NodeID,
		Context: *contextName, GatewayURL: *gatewayURL, GatewayTokenFile: resolvedGatewayToken,
		ServiceTrustFile: resolvedTrust, TaskKeyFile: resolvedTaskKey, TaskKeyID: *taskKeyID,
		CurrentContext: true,
	})
}

func validateSiteTaskKey(policy admission.SitePolicy, tenantID, keyID string, privateKey ed25519.PrivateKey, services []string) error {
	for _, tenant := range policy.Tenants {
		if tenant.TenantID != tenantID {
			continue
		}
		for _, taskKey := range tenant.TaskKeys {
			if taskKey.KeyID != keyID {
				continue
			}
			public, err := base64.StdEncoding.Strict().DecodeString(taskKey.PublicKey)
			if err != nil || !slices.Equal(public, privateKey.Public().(ed25519.PublicKey)) {
				break
			}
			for _, serviceID := range services {
				if !slices.Contains(taskKey.ServiceIDs, serviceID) {
					return fmt.Errorf("tenant task key %q is not authorized for service %q", keyID, serviceID)
				}
			}
			return nil
		}
	}
	return errors.New("tenant task key does not match signed site policy authority")
}

func saveSiteTaskContext(name, tenantID, nodeID, gatewayURL, gatewayToken, trustFile, taskKeyFile, taskKeyID string) error {
	return withCLIContextConfigMutation(func(config *cliContextConfig, path string) error {
		next, found := findCLIContext(*config, name)
		if !found || next.ControlURL == "" || next.TokenFile == "" || next.TenantID != tenantID {
			return fmt.Errorf("context %q is not the matching tenant operator context", name)
		}
		for _, owned := range []struct {
			label    string
			existing string
			wanted   string
		}{
			{label: "node", existing: next.NodeID, wanted: nodeID},
			{label: "Gateway URL", existing: next.GatewayURL, wanted: gatewayURL},
			{label: "Gateway token", existing: next.GatewayTokenFile, wanted: gatewayToken},
			{label: "service trust", existing: next.ServiceTrustFile, wanted: trustFile},
			{label: "task key", existing: next.TaskKeyFile, wanted: taskKeyFile},
			{label: "task key ID", existing: next.TaskKeyID, wanted: taskKeyID},
		} {
			if owned.existing != "" && owned.existing != owned.wanted {
				return fmt.Errorf("context %q already has a different %s", name, owned.label)
			}
		}
		next.NodeID = nodeID
		next.GatewayURL = gatewayURL
		next.GatewayTokenFile = gatewayToken
		next.ServiceTrustFile = trustFile
		next.TaskKeyFile = taskKeyFile
		next.TaskKeyID = taskKeyID
		upsertCLIContext(config, next)
		config.Current = name
		return writeCLIContextConfig(path, *config)
	})
}
