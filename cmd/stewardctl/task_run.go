package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hardrails/steward/internal/dsse"
)

const taskRunSchema = "steward.task-run.v1"

type taskRunResult struct {
	SchemaVersion string          `json:"schema_version"`
	Deployment    string          `json:"deployment,omitempty"`
	RunDirectory  string          `json:"run_directory,omitempty"`
	RequestPath   string          `json:"request_path,omitempty"`
	BundlePath    string          `json:"bundle_path"`
	ResultPath    string          `json:"result_path,omitempty"`
	Issue         json.RawMessage `json:"issue"`
	Submission    json.RawMessage `json:"submission"`
	Status        json.RawMessage `json:"status"`
}

func runTask(arguments []string, stdout io.Writer) error {
	leadingDeployment, arguments := deploymentLeadingName(arguments)
	hydrated, err := applyTaskRunContext(arguments)
	if err != nil {
		return err
	}
	flags := flag.NewFlagSet("task run", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	deploymentPath := flags.String("deployment", "", "task-ready deployment file; omit when naming a durable deployment")
	instanceID := flags.String("instance-id", "", "exact durable deployment instance")
	trustPath := flags.String("trust", "", "exported Gateway service-trust inventory")
	requestPath := flags.String("request", "", "exact JSON task request")
	operationID := flags.String("operation-id", "", "exact service operation ID")
	taskID := flags.String("task-id", "", "one-use task ID; generated when omitted")
	validFor := flags.Duration("valid-for", 5*time.Minute, "permit validity window")
	clockSkew := flags.Duration("clock-skew", 5*time.Second, "bounded allowance for node clock skew")
	privateKeyPath := flags.String("key", "", "owner-only task-authority private key")
	keyID := flags.String("key-id", "", "admitted task-authority key ID")
	bundlePath := flags.String("bundle-out", "", "new owner-only signed task bundle written before dispatch")
	resultPath := flags.String("result-out", "", "new owner-only terminal result file")
	discardResult := flags.Bool("discard-result", false, "verify and discard the terminal result")
	runDirectory := flags.String("run-dir", "", "new owner-only directory for automatic prompt artifacts")
	gatewayURL := flags.String("gateway-url", "http://127.0.0.1:8091", "literal-loopback Gateway service origin")
	gatewayTokenPath := flags.String("gateway-token-file", "", "owner-only Gateway service token")
	waitTimeout := flags.Duration("wait-timeout", 3*time.Minute, "bounded total task wait")
	deploymentTimeout := flags.Duration("deployment-timeout", 5*time.Minute, "bounded wait for a durable deployment")
	controlURL := flags.String("control-url", "http://127.0.0.1:8443", "Steward Control origin")
	controlTokenPath := flags.String("control-token-file", "", "owner-only Control operator token")
	caFile := flags.String("ca-file", "", "optional private Control CA PEM bundle")
	var tenantID string
	flags.StringVar(&tenantID, "tenant", "", "durable deployment tenant")
	flags.StringVar(&tenantID, "tenant-id", "", "alias for -tenant")
	if err := flags.Parse(hydrated); err != nil {
		return err
	}
	promptMode := leadingDeployment != "" && flags.NArg() == 1
	if flags.NArg() != 0 && !promptMode || (leadingDeployment == "") == (*deploymentPath == "") ||
		*trustPath == "" || *privateKeyPath == "" || *keyID == "" || *gatewayTokenPath == "" ||
		*waitTimeout <= 0 || *waitTimeout > maxTaskWait ||
		*deploymentTimeout <= 0 || *deploymentTimeout > 30*time.Minute {
		return errors.New("task run requires a deployment, trust, task key, Gateway token, and bounded timeouts; pass one prompt or the expert request, operation, bundle, and result flags")
	}
	if promptMode {
		if *requestPath != "" || *operationID != "" || *bundlePath != "" || *resultPath != "" || *discardResult || *deploymentPath != "" {
			return errors.New("task run prompt mode creates its own request, bundle, and result artifacts; do not mix prompt and expert artifact flags")
		}
	} else if *runDirectory != "" || *requestPath == "" || *operationID == "" || *bundlePath == "" ||
		(*resultPath != "") == *discardResult {
		return errors.New("task run expert mode requires request, operation, bundle output, and exactly one result disposition; -run-dir is only for prompt mode")
	}
	if leadingDeployment != "" && (tenantID == "" || *controlTokenPath == "") {
		return errors.New("task run with a durable deployment requires a tenant and Control operator token")
	}
	resolvedDeploymentPath := *deploymentPath
	if leadingDeployment != "" {
		var cleanup func()
		resolvedDeploymentPath, cleanup, err = exportTaskRunDeployment(
			*controlURL, *controlTokenPath, *caFile, tenantID,
			leadingDeployment, *instanceID, *deploymentTimeout,
		)
		if err != nil {
			return err
		}
		defer cleanup()
	}
	resolvedRunDirectory := ""
	if promptMode {
		selectedTaskID := *taskID
		if selectedTaskID == "" {
			selectedTaskID, err = randomTaskID()
			if err != nil {
				return err
			}
			*taskID = selectedTaskID
		}
		artifacts, err := createPromptTaskArtifacts(
			resolvedDeploymentPath, flags.Arg(0), selectedTaskID, *runDirectory,
		)
		if err != nil {
			return err
		}
		resolvedRunDirectory = artifacts.Directory
		*requestPath = artifacts.Request
		*operationID = artifacts.OperationID
		*bundlePath = artifacts.Bundle
		*resultPath = artifacts.Result
	}

	issueArguments := []string{
		"-deployment", resolvedDeploymentPath, "-trust", *trustPath, "-request", *requestPath,
		"-operation-id", *operationID, "-valid-for", validFor.String(), "-clock-skew", clockSkew.String(),
		"-key", *privateKeyPath, "-key-id", *keyID, "-out", *bundlePath,
	}
	if *taskID != "" {
		issueArguments = append(issueArguments, "-task-id", *taskID)
	}
	var issueOutput bytes.Buffer
	if err := issueTask(issueArguments, &issueOutput); err != nil {
		return err
	}
	var submissionOutput bytes.Buffer
	if err := submitTask([]string{
		"-bundle", *bundlePath, "-gateway-url", *gatewayURL, "-token-file", *gatewayTokenPath,
	}, &submissionOutput); err != nil {
		return fmt.Errorf("dispatch task (signed bundle retained at %s; resume with 'stewardctl task submit' and 'stewardctl task wait'): %w", *bundlePath, err)
	}
	waitArguments := []string{
		"-bundle", *bundlePath, "-gateway-url", *gatewayURL, "-token-file", *gatewayTokenPath,
		"-wait-timeout", waitTimeout.String(),
	}
	if *resultPath != "" {
		waitArguments = append(waitArguments, "-result-out", *resultPath)
	} else {
		waitArguments = append(waitArguments, "-discard-result")
	}
	var statusOutput bytes.Buffer
	if err := waitTask(waitArguments, &statusOutput); err != nil {
		return fmt.Errorf("wait for task (signed bundle retained at %s; resume with 'stewardctl task wait'): %w", *bundlePath, err)
	}
	if !json.Valid(issueOutput.Bytes()) || !json.Valid(submissionOutput.Bytes()) || !json.Valid(statusOutput.Bytes()) {
		return errors.New("task run received an invalid internal JSON result")
	}
	return writeAgentJSON(stdout, taskRunResult{
		SchemaVersion: taskRunSchema, Deployment: leadingDeployment,
		RunDirectory: resolvedRunDirectory, RequestPath: *requestPath,
		BundlePath: *bundlePath, ResultPath: *resultPath,
		Issue:      json.RawMessage(bytes.TrimSpace(issueOutput.Bytes())),
		Submission: json.RawMessage(bytes.TrimSpace(submissionOutput.Bytes())),
		Status:     json.RawMessage(bytes.TrimSpace(statusOutput.Bytes())),
	})
}

type promptTaskArtifacts struct {
	Directory   string
	Request     string
	Bundle      string
	Result      string
	OperationID string
}

func createPromptTaskArtifacts(deploymentPath, prompt, taskID, requestedDirectory string) (promptTaskArtifacts, error) {
	if strings.TrimSpace(prompt) == "" || len([]byte(prompt)) > 32<<10 {
		return promptTaskArtifacts{}, errors.New("task prompt must contain text and be at most 32 KiB")
	}
	if !taskIdentifier(taskID) {
		return promptTaskArtifacts{}, errors.New("task ID is invalid")
	}
	raw, err := readCLIArtifact(deploymentPath)
	if err != nil {
		return promptTaskArtifacts{}, fmt.Errorf("read task-ready deployment: %w", err)
	}
	var deployment agentDeployResult
	if err := dsse.DecodeStrictInto(raw, maxArtifactBytes, &deployment); err != nil {
		return promptTaskArtifacts{}, fmt.Errorf("decode task-ready deployment: %w", err)
	}
	var operationID, requestField string
	switch deployment.Admission.ServiceID {
	case "hermes-api":
		operationID, requestField = "hermes.run", "input"
	default:
		return promptTaskArtifacts{}, fmt.Errorf("task prompt mode does not recognize admitted service %q; use expert request flags", deployment.Admission.ServiceID)
	}
	request, err := json.Marshal(map[string]string{requestField: prompt, "session_id": taskID})
	if err != nil {
		return promptTaskArtifacts{}, err
	}
	if len(request) > 64<<10 {
		return promptTaskArtifacts{}, errors.New("generated task request exceeds 64 KiB")
	}
	directory, err := createTaskRunDirectory(requestedDirectory, taskID)
	if err != nil {
		return promptTaskArtifacts{}, err
	}
	artifacts := promptTaskArtifacts{
		Directory: directory, OperationID: operationID,
		Request: filepath.Join(directory, "request.json"),
		Bundle:  filepath.Join(directory, "task.bundle.json"),
		Result:  filepath.Join(directory, "result.json"),
	}
	if err := writeNewFile(artifacts.Request, append(request, '\n'), 0o600); err != nil {
		return promptTaskArtifacts{}, fmt.Errorf("write exact task request: %w", err)
	}
	return artifacts, nil
}

func createTaskRunDirectory(requestedDirectory, taskID string) (string, error) {
	directory := requestedDirectory
	if directory == "" {
		contextPath, err := cliContextFilePath()
		if err != nil {
			return "", err
		}
		base := filepath.Join(filepath.Dir(contextPath), "runs")
		if err := ensureCLIContextDirectory(base); err != nil {
			return "", fmt.Errorf("prepare task run directory: %w", err)
		}
		directory = filepath.Join(base, taskID)
	} else {
		absolute, err := filepath.Abs(directory)
		if err != nil {
			return "", fmt.Errorf("resolve task run directory: %w", err)
		}
		directory = filepath.Clean(absolute)
		if err := ensureCLIContextDirectory(filepath.Dir(directory)); err != nil {
			return "", fmt.Errorf("prepare task run parent: %w", err)
		}
	}
	if err := os.Mkdir(directory, 0o700); err != nil {
		return "", fmt.Errorf("create new task run directory: %w", err)
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return "", errors.New("task run directory must be a new owner-only real directory")
	}
	if err := syncOutputDirectory(directory); err != nil {
		return "", fmt.Errorf("sync task run parent: %w", err)
	}
	return directory, nil
}

func exportTaskRunDeployment(
	controlURL, tokenPath, caFile, tenantID, deploymentID, instanceID string,
	timeout time.Duration,
) (string, func(), error) {
	flags := flag.NewFlagSet("task run control", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	common := addControlFlags(flags, true)
	*common.url, *common.tokenFile, *common.caFile = controlURL, tokenPath, caFile
	client, err := common.client(true)
	if err != nil {
		return "", func() {}, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	ready, err := waitForTaskReadyDeployment(ctx, client, tenantID, deploymentID, instanceID)
	if err != nil {
		return "", func() {}, err
	}
	directory, err := os.MkdirTemp("", "steward-task-run-")
	if err != nil {
		return "", func() {}, fmt.Errorf("create task-run workspace: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(directory) }
	path := filepath.Join(directory, "agent.deployment.json")
	raw, err := json.Marshal(ready)
	if err != nil {
		cleanup()
		return "", func() {}, err
	}
	if err := writeNewFile(path, append(raw, '\n'), 0o600); err != nil {
		cleanup()
		return "", func() {}, err
	}
	return path, cleanup, nil
}

func applyTaskRunContext(arguments []string) ([]string, error) {
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
		{"control-url", selected.ControlURL}, {"control-token-file", selected.TokenFile}, {"ca-file", selected.CAFile},
		{"gateway-url", selected.GatewayURL}, {"gateway-token-file", selected.GatewayTokenFile},
		{"trust", selected.ServiceTrustFile}, {"key", selected.TaskKeyFile}, {"key-id", selected.TaskKeyID},
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
