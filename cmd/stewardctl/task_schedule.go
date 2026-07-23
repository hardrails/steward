package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/hardrails/steward/internal/schedulepermit"
	"github.com/hardrails/steward/internal/taskpermit"
)

func taskScheduleCommand(arguments []string, stdout io.Writer) error {
	if len(arguments) == 0 {
		return errors.New("task schedule requires a deployment prompt, or list, show, or cancel")
	}
	switch arguments[0] {
	case "create":
		return createTaskSchedule(arguments[1:], stdout)
	case "list":
		return listTaskSchedules(arguments[1:], stdout)
	case "show":
		return taskScheduleByID("task schedule show", arguments[1:], stdout, false)
	case "cancel":
		return taskScheduleByID("task schedule cancel", arguments[1:], stdout, true)
	default:
		// The short path intentionally omits a ceremonial "create":
		// stewardctl task schedule DEPLOYMENT [flags] "prompt"
		return createTaskSchedule(arguments, stdout)
	}
}

func createTaskSchedule(arguments []string, stdout io.Writer) error {
	deploymentID, arguments := deploymentLeadingName(arguments)
	hydrated, err := applyAsyncTaskContext(arguments)
	if err != nil {
		return err
	}
	flags := flag.NewFlagSet("task schedule", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	common := addControlFlags(flags, true)
	tenantID := flags.String("tenant-id", "", "tenant scope")
	instanceID := flags.String("instance-id", "", "exact durable deployment instance")
	trustPath := flags.String("trust", "", "exported Gateway service-trust inventory")
	privateKeyPath := flags.String("key", "", "owner-only task-authority private key")
	keyID := flags.String("key-id", "", "admitted task-authority key ID")
	scheduleID := flags.String("id", "", "stable schedule ID; generated when omitted")
	startIn := flags.Duration("start-in", 10*time.Second, "delay before the first run")
	every := flags.Duration("every", 0, "recurring interval; omit for one run")
	runs := flags.Uint64("runs", 1, "finite number of runs")
	window := flags.Duration("window", 0, "dispatch window; defaults to the operation maximum up to 5m")
	maxConcurrency := flags.Int("max-concurrency", 1, "maximum unfinished runs")
	overlap := flags.String("overlap", "skip", "skip or queue when concurrency is full")
	missed := flags.String("missed", "skip", "missed-run policy; currently skip")
	projectID := flags.String("project", "", "optional Workroom project")
	sessionID := flags.String("session", "", "optional Workroom session")
	deploymentTimeout := flags.Duration("deployment-timeout", 5*time.Minute, "bounded wait for a task-ready instance")
	if err := flags.Parse(hydrated); err != nil {
		return err
	}
	if deploymentID == "" || *tenantID == "" || *trustPath == "" ||
		*privateKeyPath == "" || *keyID == "" || flags.NArg() != 1 ||
		strings.TrimSpace(flags.Arg(0)) == "" ||
		(*projectID == "") != (*sessionID == "") {
		return errors.New("task schedule requires DEPLOYMENT \"prompt\", a tenant, service trust, and task signing authority")
	}
	if *startIn < time.Second || *startIn > 30*24*time.Hour || *startIn%time.Second != 0 {
		return errors.New("task schedule -start-in must be whole seconds from 1s through 720h")
	}
	if *runs == 0 || *runs > schedulepermit.MaxRuns ||
		(*every == 0 && *runs != 1) ||
		(*every != 0 && (*every < time.Minute || *every > 30*24*time.Hour || *every%time.Second != 0)) {
		return errors.New("task schedule requires one run without -every, or 1 to 10000 runs every 1m through 720h")
	}
	if *window < 0 || *window > schedulepermit.MaxWindow || *window%time.Second != 0 ||
		*maxConcurrency < 1 || *maxConcurrency > schedulepermit.MaxConcurrency ||
		(*overlap != "skip" && *overlap != "queue") ||
		*missed != "skip" ||
		*deploymentTimeout <= 0 || *deploymentTimeout > 30*time.Minute {
		return errors.New("task schedule window, concurrency, overlap, missed-run policy, or deployment timeout is invalid")
	}
	selectedID := *scheduleID
	if selectedID == "" {
		selectedID, err = randomTaskID()
		if err != nil {
			return err
		}
	}
	if len(selectedID) > 96 || !taskIdentifier(selectedID) {
		return errors.New("task schedule ID must use 1 to 96 letters, digits, dots, underscores, or dashes")
	}
	deploymentPath, cleanup, err := exportTaskRunDeployment(
		*common.url, *common.tokenFile, *common.caFile, *tenantID,
		deploymentID, *instanceID, *deploymentTimeout,
	)
	if err != nil {
		return err
	}
	defer cleanup()
	admitted, intent, err := readTaskDeployment(deploymentPath)
	if err != nil {
		return err
	}
	if intent.TenantID != *tenantID {
		return errors.New("task-ready deployment tenant does not match the selected Control tenant")
	}
	operationID, requestField, err := promptOperation(intent.ServiceID)
	if err != nil {
		return err
	}
	operation, err := readServiceTrust(*trustPath, intent, operationID)
	if err != nil {
		return err
	}
	dispatchWindow := *window
	operationMaximum := time.Duration(operation.MaxPermitSeconds) * time.Second
	if dispatchWindow == 0 {
		dispatchWindow = min(5*time.Minute, operationMaximum)
	}
	if dispatchWindow < time.Second || dispatchWindow > operationMaximum {
		return fmt.Errorf("task schedule window %s exceeds service operation maximum %s", dispatchWindow, operationMaximum)
	}
	request, err := json.Marshal(map[string]string{
		requestField: flags.Arg(0), "session_id": selectedID,
	})
	if err != nil {
		return err
	}
	if int64(len(request)) > operation.MaxRequestBytes ||
		!validExactTaskJSON(request, int(operation.MaxRequestBytes)) {
		return errors.New("generated schedule request is empty, oversized, or not one JSON value")
	}
	privateKey, err := readPrivateKey(*privateKeyPath)
	if err != nil {
		return err
	}
	if !admissionTrustsTaskKey(
		admitted.TaskAuthorities, *keyID,
		privateKey.Public().(ed25519.PublicKey),
	) {
		return errors.New("admission response does not bind this task-authority key to the service")
	}
	now := timeNow().UTC().Truncate(time.Second)
	statement := schedulepermit.Statement{
		SchemaVersion: schedulepermit.SchemaV1, ScheduleID: selectedID,
		NodeID: intent.NodeID, TenantID: intent.TenantID, InstanceID: intent.InstanceID,
		RuntimeRef: admitted.RuntimeRef, GrantID: admitted.GrantID, Generation: intent.Generation,
		CapsuleDigest: admitted.CapsuleDigest, PolicyDigest: admitted.PolicyDigest,
		RoutePolicyDigest: admitted.RoutePolicyDigest, ServiceID: intent.ServiceID,
		OperationID: operation.ID, OperationPolicyDigest: operation.PolicyDigest,
		RequestDigest: taskpermit.RequestDigest(request), RequestBytes: int64(len(request)),
		ContentType: operation.ContentType, StartsAt: now.Add(*startIn).Format(time.RFC3339),
		IntervalSeconds: int64(*every / time.Second), RunCount: *runs,
		WindowSeconds:  int64(dispatchWindow / time.Second),
		MaxConcurrency: *maxConcurrency, OverlapPolicy: *overlap, MissedRunPolicy: *missed,
		ProjectID: *projectID, SessionID: *sessionID,
	}
	permit, err := schedulepermit.Sign(statement, *keyID, privateKey)
	if err != nil {
		return err
	}
	client, err := common.client(true)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	schedule, err := client.CreateTaskSchedule(ctx, *tenantID, permit, request)
	if err != nil {
		return err
	}
	return writeControlJSON(stdout, schedule)
}

func promptOperation(serviceID string) (string, string, error) {
	switch serviceID {
	case "hermes-api":
		return "hermes.run", "input", nil
	default:
		return "", "", fmt.Errorf(
			"task prompt mode does not recognize admitted service %q; use an exact schedule envelope through the Control API",
			serviceID,
		)
	}
}

func listTaskSchedules(arguments []string, stdout io.Writer) error {
	hydrated, err := applyAsyncTaskContext(arguments)
	if err != nil {
		return err
	}
	flags := flag.NewFlagSet("task schedule list", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	common := addControlFlags(flags, true)
	tenantID := flags.String("tenant-id", "", "tenant scope")
	after := flags.String("after", "", "exclusive schedule ID cursor")
	limit := flags.Int("limit", 100, "maximum schedules to return")
	if err := flags.Parse(hydrated); err != nil {
		return err
	}
	if *tenantID == "" || *limit <= 0 || *limit > 100 || flags.NArg() != 0 {
		return errors.New("task schedule list requires a tenant and a limit between 1 and 100")
	}
	client, err := common.client(true)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	page, err := client.ListTaskSchedules(ctx, *tenantID, *after, *limit)
	if err != nil {
		return err
	}
	return writeControlJSON(stdout, page)
}

func taskScheduleByID(name string, arguments []string, stdout io.Writer, cancelSchedule bool) error {
	scheduleID, arguments := deploymentLeadingName(arguments)
	hydrated, err := applyAsyncTaskContext(arguments)
	if err != nil {
		return err
	}
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	common := addControlFlags(flags, true)
	tenantID := flags.String("tenant-id", "", "tenant scope")
	if err := flags.Parse(hydrated); err != nil {
		return err
	}
	if scheduleID == "" && flags.NArg() == 1 {
		scheduleID = flags.Arg(0)
	}
	if *tenantID == "" || scheduleID == "" ||
		flags.NArg() != 0 && scheduleID != flags.Arg(0) || flags.NArg() > 1 {
		return errors.New(name + " requires a tenant and one schedule ID")
	}
	client, err := common.client(true)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var schedule any
	if cancelSchedule {
		schedule, err = client.CancelTaskSchedule(ctx, *tenantID, scheduleID)
	} else {
		schedule, err = client.GetTaskSchedule(ctx, *tenantID, scheduleID)
	}
	if err != nil {
		return err
	}
	return writeControlJSON(stdout, schedule)
}
