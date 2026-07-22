package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"io"
	"os"
	"strings"
	"time"

	"github.com/hardrails/steward/internal/controlstore"
	"github.com/hardrails/steward/internal/taskpermit"
)

const taskEnqueueSchema = "steward.task-enqueue.v1"

type taskEnqueueResult struct {
	SchemaVersion string                   `json:"schema_version"`
	Deployment    string                   `json:"deployment,omitempty"`
	RunDirectory  string                   `json:"run_directory,omitempty"`
	RequestPath   string                   `json:"request_path,omitempty"`
	BundlePath    string                   `json:"bundle_path"`
	Task          controlstore.TaskRequest `json:"task"`
}

func enqueueTask(arguments []string, stdout io.Writer) error {
	leadingDeployment, arguments := deploymentLeadingName(arguments)
	arguments, err := applyAsyncTaskContext(arguments)
	if err != nil {
		return err
	}
	flags := flag.NewFlagSet("task enqueue", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	common := addControlFlags(flags, true)
	tenantID := flags.String("tenant-id", "", "tenant scope")
	bundlePath := flags.String("bundle", "", "owner-only lifecycle task bundle")
	instanceID := flags.String("instance-id", "", "exact durable deployment instance")
	trustPath := flags.String("trust", "", "exported Gateway service-trust inventory")
	taskID := flags.String("task-id", "", "one-use task ID; generated when omitted")
	validFor := flags.Duration("valid-for", 5*time.Minute, "permit validity window")
	clockSkew := flags.Duration("clock-skew", 5*time.Second, "bounded allowance for node clock skew")
	privateKeyPath := flags.String("key", "", "owner-only task-authority private key")
	keyID := flags.String("key-id", "", "admitted task-authority key ID")
	runDirectory := flags.String("run-dir", "", "new owner-only directory for automatic prompt artifacts")
	deploymentTimeout := flags.Duration("deployment-timeout", 5*time.Minute, "bounded wait for a durable deployment")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	promptMode := leadingDeployment != "" && flags.NArg() == 1
	bundleMode := leadingDeployment == "" && flags.NArg() == 0 && *bundlePath != ""
	if *tenantID == "" || promptMode == bundleMode || *deploymentTimeout <= 0 || *deploymentTimeout > 30*time.Minute {
		return errors.New("task enqueue requires a tenant and either DEPLOYMENT \"prompt\" or -bundle")
	}
	resolvedRunDirectory := ""
	resolvedRequestPath := ""
	if promptMode {
		if *bundlePath != "" || *trustPath == "" || *privateKeyPath == "" || *keyID == "" {
			return errors.New("task enqueue prompt mode requires task trust and signing authority; do not also pass -bundle")
		}
		selectedTaskID := *taskID
		if selectedTaskID == "" {
			selectedTaskID, err = randomTaskID()
			if err != nil {
				return err
			}
			*taskID = selectedTaskID
		}
		deploymentPath, cleanup, err := exportTaskRunDeployment(
			*common.url, *common.tokenFile, *common.caFile, *tenantID,
			leadingDeployment, *instanceID, *deploymentTimeout,
		)
		if err != nil {
			return err
		}
		defer cleanup()
		artifacts, err := createPromptTaskArtifacts(deploymentPath, flags.Arg(0), selectedTaskID, *runDirectory)
		if err != nil {
			return err
		}
		resolvedRunDirectory, resolvedRequestPath, *bundlePath = artifacts.Directory, artifacts.Request, artifacts.Bundle
		issueArguments := []string{
			"-deployment", deploymentPath, "-trust", *trustPath, "-request", artifacts.Request,
			"-operation-id", artifacts.OperationID, "-task-id", selectedTaskID,
			"-valid-for", validFor.String(), "-clock-skew", clockSkew.String(),
			"-key", *privateKeyPath, "-key-id", *keyID, "-out", artifacts.Bundle,
		}
		if err := issueTask(issueArguments, &bytes.Buffer{}); err != nil {
			return err
		}
	}
	bundle, err := readCurrentLifecycleTaskBundle(*bundlePath)
	if err != nil {
		return err
	}
	if bundle.Verified.Statement.TenantID != *tenantID {
		return errors.New("task bundle tenant does not match the selected Control tenant")
	}
	permit, err := taskpermit.EncodeHeader(bundle.Permit)
	if err != nil {
		return err
	}
	client, err := common.client(true)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	task, err := client.SubmitTaskRequest(ctx, *tenantID, permit, bundle.Request)
	if err != nil {
		return err
	}
	if !promptMode {
		return writeControlJSON(stdout, task)
	}
	return writeControlJSON(stdout, taskEnqueueResult{
		SchemaVersion: taskEnqueueSchema, Deployment: leadingDeployment,
		RunDirectory: resolvedRunDirectory,
		RequestPath:  resolvedRequestPath,
		BundlePath:   *bundlePath, Task: task,
	})
}

func listAsyncTasks(arguments []string, stdout io.Writer) error {
	arguments, err := applyAsyncTaskContext(arguments)
	if err != nil {
		return err
	}
	flags := flag.NewFlagSet("task list", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	common := addControlFlags(flags, true)
	tenantID := flags.String("tenant-id", "", "tenant scope")
	after := flags.String("after", "", "exclusive task ID cursor")
	limit := flags.Int("limit", 100, "maximum tasks to return")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *tenantID == "" || *limit <= 0 || *limit > 100 || flags.NArg() != 0 {
		return errors.New("task list requires a tenant and a limit between 1 and 100")
	}
	client, err := common.client(true)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	page, err := client.ListTaskRequests(ctx, *tenantID, *after, *limit)
	if err != nil {
		return err
	}
	return writeControlJSON(stdout, page)
}

func getAsyncTask(arguments []string, stdout io.Writer) error {
	return asyncTaskByID("task get", arguments, stdout, false)
}

type taskResultFile struct {
	TaskID        string `json:"task_id"`
	ResultDigest  string `json:"result_digest"`
	ResponseBytes int64  `json:"response_bytes"`
	ResultPath    string `json:"result_path"`
}

func getAsyncTaskResult(arguments []string, stdout io.Writer) error {
	leadingTaskID, arguments := deploymentLeadingName(arguments)
	arguments, err := applyAsyncTaskContext(arguments)
	if err != nil {
		return err
	}
	flags := flag.NewFlagSet("task result", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	common := addControlFlags(flags, true)
	tenantID := flags.String("tenant-id", "", "tenant scope")
	output := flags.String("out", "", "new owner-only terminal result file")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	taskID := leadingTaskID
	if taskID == "" && flags.NArg() == 1 {
		taskID = flags.Arg(0)
	}
	if *tenantID == "" || *output == "" || taskID == "" || flags.NArg() != 0 && leadingTaskID != "" || flags.NArg() > 1 {
		return errors.New("task result requires a tenant, one task ID, and -out")
	}
	client, err := common.client(true)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	raw, result, err := client.GetTaskResult(ctx, *tenantID, taskID)
	if err != nil {
		return err
	}
	if err := writeNewFile(*output, raw, 0o600); err != nil {
		return err
	}
	return writeControlJSON(stdout, taskResultFile{
		TaskID: result.TaskID, ResultDigest: result.ResultDigest,
		ResponseBytes: result.ResponseBytes, ResultPath: *output,
	})
}

func cancelAsyncTask(arguments []string, stdout io.Writer) error {
	return asyncTaskByID("task cancel", arguments, stdout, true)
}

func asyncTaskByID(name string, arguments []string, stdout io.Writer, cancelTask bool) error {
	leadingTaskID, arguments := deploymentLeadingName(arguments)
	arguments, err := applyAsyncTaskContext(arguments)
	if err != nil {
		return err
	}
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	common := addControlFlags(flags, true)
	tenantID := flags.String("tenant-id", "", "tenant scope")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	taskID := leadingTaskID
	if taskID == "" && flags.NArg() == 1 {
		taskID = flags.Arg(0)
	}
	if *tenantID == "" || taskID == "" || flags.NArg() != 0 && leadingTaskID != "" || flags.NArg() > 1 {
		return errors.New(name + " requires a tenant and one task ID")
	}
	client, err := common.client(true)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var task any
	if cancelTask {
		task, err = client.CancelTaskRequest(ctx, *tenantID, taskID)
	} else {
		task, err = client.GetTaskRequest(ctx, *tenantID, taskID)
	}
	if err != nil {
		return err
	}
	return writeControlJSON(stdout, task)
}

func applyAsyncTaskContext(arguments []string) ([]string, error) {
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
		{"trust", selected.ServiceTrustFile}, {"key", selected.TaskKeyFile}, {"key-id", selected.TaskKeyID},
	} {
		if value.content != "" && !hasNamedFlag(arguments, value.name) {
			prefix = append(prefix, "-"+value.name, value.content)
		}
	}
	if selected.TenantID != "" && !hasNamedFlag(arguments, "tenant-id") {
		prefix = append(prefix, "-tenant-id", selected.TenantID)
	}
	return append(prefix, arguments...), nil
}
