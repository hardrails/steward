package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"

	"github.com/hardrails/steward/internal/agentapp"
	"github.com/hardrails/steward/internal/gateway"
	"github.com/hardrails/steward/internal/securefile"
)

type agentServiceActivationSummary struct {
	AgentName       string `json:"agent_name"`
	Runtime         string `json:"runtime"`
	ServiceID       string `json:"service_id"`
	TenantID        string `json:"tenant_id"`
	NodeID          string `json:"node_id"`
	TrustFile       string `json:"trust_file"`
	Activation      string `json:"activation"`
	ServiceReplaced bool   `json:"service_replaced"`
}

func agentServiceCommand(arguments []string, stdout io.Writer) error {
	if len(arguments) == 0 || arguments[0] != "activate" {
		return errors.New("agent service requires activate")
	}
	return agentServiceActivate(arguments[1:], stdout)
}

func agentServiceActivate(arguments []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("agent service activate", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	bundlePath := flags.String("bundle", "agent.bundle.json", "portable agent bundle")
	configPath := flags.String("config", "/etc/steward/gateway.json", "Gateway configuration")
	tenantID := flags.String("tenant-id", "", "exact tenant identity")
	nodeID := flags.String("node-id", "", "exact enrolled node identity")
	tenantBudget := flags.Int64("tenant-budget-bytes", 4<<20, "durable receipt byte budget for this tenant")
	trustOutput := flags.String("trust-out", "service-trust.json", "new or identical exported service trust inventory")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || !validOptionalControlIdentifier(*tenantID, 128) || *tenantID == "" ||
		!validOptionalControlIdentifier(*nodeID, 128) || *nodeID == "" || *tenantBudget < 4096 ||
		*tenantBudget > 1<<40 || *trustOutput == "" {
		return errors.New("agent service activate requires tenant, node, a receipt budget from 4096 bytes through 1 TiB, and a trust output")
	}
	bundleRaw, err := readCLIArtifact(*bundlePath)
	if err != nil {
		return fmt.Errorf("read agent bundle: %w", err)
	}
	bundle, err := agentapp.DecodeBundle(bundleRaw)
	if err != nil {
		return err
	}
	contract, ok := agentPublicationContractFor(bundle.Definition.Runtime.Engine, bundle.Definition.EffectiveToolProfile())
	if !ok || contract.serviceID == "" {
		return errors.New("agent runtime has no activatable Steward service contract")
	}
	trustPath, err := filepath.Abs(*trustOutput)
	if err != nil || trustPath == string(filepath.Separator) {
		return errors.New("service trust output path is invalid")
	}
	stagedConfigPath, originalConfig, err := stageAgentServiceGatewayConfig(*configPath)
	if err != nil {
		return fmt.Errorf("stage agent Gateway configuration: %w", err)
	}
	defer os.Remove(stagedConfigPath)
	var configured bytes.Buffer
	if err := gatewayServiceCommand([]string{
		"set", "-config", stagedConfigPath, "-agent", bundle.Definition.Runtime.Engine,
		"-tenant-budget", *tenantID + "=" + strconv.FormatInt(*tenantBudget, 10),
	}, &configured); err != nil {
		return fmt.Errorf("configure agent Gateway service: %w", err)
	}
	var gatewayResult struct {
		ServiceID  string `json:"service_id"`
		Replaced   bool   `json:"replaced"`
		Activation string `json:"activation"`
	}
	if err := json.Unmarshal(configured.Bytes(), &gatewayResult); err != nil ||
		gatewayResult.ServiceID != contract.serviceID || gatewayResult.Activation == "" {
		return errors.New("Gateway returned an invalid service activation result")
	}
	var trust bytes.Buffer
	if err := gatewayServiceCommand([]string{
		"trust", "-config", stagedConfigPath, "-node-id", *nodeID, "-tenant-id", *tenantID,
	}, &trust); err != nil {
		return fmt.Errorf("export agent service trust: %w", err)
	}
	if err := writeOrVerifyAgentServiceTrust(trustPath, trust.Bytes()); err != nil {
		return err
	}
	currentConfig, err := readCLIArtifact(*configPath)
	if err != nil {
		return fmt.Errorf("re-read agent Gateway configuration: %w", err)
	}
	if !bytes.Equal(currentConfig, originalConfig) {
		return errors.New("Gateway configuration changed while agent service activation was being prepared")
	}
	plannedConfig, _, _, _, err := gateway.LoadConfig(stagedConfigPath)
	if err != nil {
		return fmt.Errorf("load staged agent Gateway configuration: %w", err)
	}
	if err := writeGatewayConfig(*configPath, plannedConfig); err != nil {
		return fmt.Errorf("commit agent Gateway configuration: %w", err)
	}
	return writeAgentJSON(stdout, agentServiceActivationSummary{
		AgentName: bundle.Definition.Name, Runtime: bundle.Definition.Runtime.Engine,
		ServiceID: contract.serviceID, TenantID: *tenantID, NodeID: *nodeID, TrustFile: trustPath,
		Activation: gatewayResult.Activation, ServiceReplaced: gatewayResult.Replaced,
	})
}

func stageAgentServiceGatewayConfig(path string) (string, []byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 || info.Size() <= 0 || info.Size() > maxArtifactBytes {
		return "", nil, errors.New("gateway config must be a bounded regular file with no group/world write permission")
	}
	original, err := readCLIArtifact(path)
	if err != nil {
		return "", nil, err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".gateway-agent-service.*")
	if err != nil {
		return "", nil, err
	}
	temporaryPath := temporary.Name()
	cleanup := func(cause error) (string, []byte, error) {
		return "", nil, errors.Join(cause, temporary.Close(), os.Remove(temporaryPath))
	}
	if err := temporary.Chmod(info.Mode().Perm()); err != nil {
		return cleanup(err)
	}
	if _, err := temporary.Write(original); err != nil {
		return cleanup(err)
	}
	if err := temporary.Sync(); err != nil {
		return cleanup(err)
	}
	if err := temporary.Close(); err != nil {
		_ = os.Remove(temporaryPath)
		return "", nil, err
	}
	return temporaryPath, original, nil
}

func writeOrVerifyAgentServiceTrust(path string, contents []byte) error {
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		parent := filepath.Dir(path)
		if err := os.MkdirAll(parent, 0o700); err != nil {
			return err
		}
		info, err := os.Lstat(parent)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
			return errors.New("service trust parent must be a real directory that is not group- or world-writable")
		}
		if err := writeNewFile(path, contents, 0o644); err != nil {
			return fmt.Errorf("write service trust inventory: %w", err)
		}
		return nil
	} else if err != nil {
		return err
	}
	retained, err := securefile.Read(path, maxServiceTrustBytes, securefile.TrustFile)
	if err != nil {
		return fmt.Errorf("read retained service trust inventory: %w", err)
	}
	if !bytes.Equal(retained, contents) {
		return errors.New("service trust output already contains a different inventory")
	}
	return nil
}
