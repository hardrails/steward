package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/hardrails/steward/internal/controlclient"
	"github.com/hardrails/steward/internal/controlstore"
	"github.com/hardrails/steward/internal/nodeclient"
)

const (
	operatorStatusSchema         = "steward.operator-status.v1"
	maxOperatorAttentionFindings = 32768
)

type operatorFinding struct {
	Code        string   `json:"code"`
	Severity    string   `json:"severity"`
	Resource    string   `json:"resource"`
	ResourceID  string   `json:"resource_id,omitempty"`
	Title       string   `json:"title"`
	Explanation string   `json:"explanation"`
	Impact      string   `json:"impact"`
	NextStep    string   `json:"next_step"`
	Blocked     []string `json:"blocked_actions,omitempty"`
}

type operatorStatus struct {
	SchemaVersion string                          `json:"schema_version"`
	GeneratedAt   string                          `json:"generated_at"`
	Context       string                          `json:"context,omitempty"`
	State         string                          `json:"state"`
	Control       *controlstore.OperationsSummary `json:"control,omitempty"`
	Node          *nodeclient.Readiness           `json:"node,omitempty"`
	Findings      []operatorFinding               `json:"findings"`
	SourceErrors  []string                        `json:"source_errors,omitempty"`
}

type operatorConnections struct {
	contextName   string
	controlURL    string
	controlToken  string
	caFile        string
	tenantID      string
	nodeURL       string
	nodeToken     string
	output        string
	watchInterval time.Duration
}

func statusCommand(arguments []string, stdout io.Writer) error {
	connections, err := parseOperatorConnections("status", arguments, true)
	if err != nil {
		return err
	}
	if connections.watchInterval == 0 {
		status := collectOperatorStatus(connections, "")
		return writeOperatorStatus(stdout, status, connections.output, false)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ticker := time.NewTicker(connections.watchInterval)
	defer ticker.Stop()
	for {
		status := collectOperatorStatus(connections, "")
		if err := writeOperatorStatus(stdout, status, connections.output, true); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func explainCommand(arguments []string, stdout io.Writer) error {
	connections, positionals, err := parseExplainConnections(arguments)
	if err != nil {
		return err
	}
	target := ""
	if len(positionals) == 1 {
		target = positionals[0]
	}
	status := collectOperatorStatus(connections, target)
	if len(positionals) == 1 {
		target := positionals[0]
		filtered := status.Findings[:0]
		for _, finding := range status.Findings {
			if finding.ResourceID == target {
				filtered = append(filtered, finding)
			}
		}
		status.Findings = filtered
		if len(status.Findings) == 0 && len(status.SourceErrors) == 0 {
			return fmt.Errorf("no current diagnostic finding matches %q", target)
		}
	}
	return writeOperatorStatus(stdout, status, connections.output, false)
}

func recoverCommand(arguments []string, stdout io.Writer) error {
	arguments, err := applyNodeCLIContext(arguments)
	if err != nil {
		return err
	}
	flags := flag.NewFlagSet("recover", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	nodeURL := flags.String("node-url", "http://127.0.0.1:8090", "loopback Executor origin")
	tokenFile := flags.String("token-file", "", "owner-only Executor token")
	apply := flags.Bool("apply", false, "apply the recovery after rechecking every precondition")
	output := flags.String("output", "human", "human or json output")
	ordered, err := normalizeRecoverArguments(arguments)
	if err != nil {
		return err
	}
	if err := flags.Parse(ordered); err != nil {
		return err
	}
	if flags.NArg() != 1 || *tokenFile == "" || !validOperatorOutput(*output) {
		return errors.New("recover requires one runtime reference, a node context or -token-file, and optional -apply or -output human|json")
	}
	runtimeRef := flags.Arg(0)
	client, err := nodeclient.NewFromTokenFile(*nodeURL, *tokenFile)
	if err != nil {
		return err
	}
	previewCtx, previewCancel := context.WithTimeout(context.Background(), 30*time.Second)
	readiness, err := client.Readiness(previewCtx)
	previewCancel()
	if err != nil {
		return fmt.Errorf("inspect node recovery state: %w", err)
	}
	plan := missingWorkloadRecoveryPlan(runtimeRef, readiness)
	if !plan.Safe {
		if err := writeRecoveryPlan(stdout, plan, *output); err != nil {
			return err
		}
		return errors.New("node cannot currently prove a safe automatic recovery for this runtime")
	}
	if !*apply {
		return writeRecoveryPlan(stdout, plan, *output)
	}
	mutationCtx, mutationCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer mutationCancel()
	if err := client.Destroy(mutationCtx, runtimeRef); err != nil {
		return fmt.Errorf("apply bounded missing-workload recovery: %w", err)
	}
	plan.Applied = true
	plan.Result = "recovered"
	return writeRecoveryPlan(stdout, plan, *output)
}

func normalizeRecoverArguments(arguments []string) ([]string, error) {
	flagArguments := make([]string, 0, len(arguments))
	positionals := make([]string, 0, 1)
	for index := 0; index < len(arguments); index++ {
		argument := arguments[index]
		if argument == "-apply" || argument == "--apply" || strings.HasPrefix(argument, "-apply=") || strings.HasPrefix(argument, "--apply=") {
			flagArguments = append(flagArguments, argument)
			continue
		}
		matchedValueFlag := false
		for _, name := range []string{"output", "node-url", "token-file"} {
			if argument == "-"+name || argument == "--"+name {
				if index+1 >= len(arguments) {
					return nil, fmt.Errorf("%s requires a value", argument)
				}
				flagArguments = append(flagArguments, argument, arguments[index+1])
				index++
				matchedValueFlag = true
				break
			}
			if strings.HasPrefix(argument, "-"+name+"=") || strings.HasPrefix(argument, "--"+name+"=") {
				flagArguments = append(flagArguments, argument)
				matchedValueFlag = true
				break
			}
		}
		if matchedValueFlag {
			continue
		}
		if strings.HasPrefix(argument, "-") {
			return nil, fmt.Errorf("unknown recover option %s", argument)
		}
		positionals = append(positionals, argument)
	}
	return append(flagArguments, positionals...), nil
}

type recoveryPlan struct {
	SchemaVersion string `json:"schema_version"`
	RuntimeRef    string `json:"runtime_ref"`
	Action        string `json:"action"`
	Reason        string `json:"reason"`
	Safe          bool   `json:"safe"`
	Applied       bool   `json:"applied"`
	Result        string `json:"result"`
	Explanation   string `json:"explanation"`
	NextStep      string `json:"next_step"`
}

func missingWorkloadRecoveryPlan(runtimeRef string, readiness nodeclient.Readiness) recoveryPlan {
	plan := recoveryPlan{
		SchemaVersion: "steward.recovery-plan.v1", RuntimeRef: runtimeRef,
		Action: "recover_missing_workload", Reason: "preconditions_not_proven", Result: "planned",
		Explanation: "Steward only automates recovery when reconciliation proves one signed workload is absent and no host mutation is pending.",
		NextStep:    "Run stewardctl explain for the current failure and preserve evidence before manual intervention.",
	}
	report := readiness.Reconciliation
	if readiness.Status != "degraded" || report.DroppedFailures != 0 || len(report.Failures) != 1 {
		return plan
	}
	failure := report.Failures[0]
	if failure.RuntimeRef != runtimeRef || failure.Code != "workload_missing" {
		return plan
	}
	plan.Safe = true
	plan.Reason = failure.Code
	plan.Explanation = "Reconciliation proved that the signed agent container is absent and identified no competing ambiguity. Executor will recheck this proof before removing its remaining relay, network, grant, and fence state."
	plan.NextStep = "Review this plan, then repeat the command with --apply."
	return plan
}

func parseOperatorConnections(command string, arguments []string, allowWatch bool) (operatorConnections, error) {
	connections, positionals, err := parseOperatorConnectionFlags(command, arguments, allowWatch)
	if err != nil {
		return operatorConnections{}, err
	}
	if len(positionals) != 0 {
		return operatorConnections{}, fmt.Errorf("%s accepts only named flags", command)
	}
	return connections, nil
}

func parseExplainConnections(arguments []string) (operatorConnections, []string, error) {
	connections, positionals, err := parseOperatorConnectionFlags("explain", arguments, false)
	if err != nil {
		return operatorConnections{}, nil, err
	}
	if len(positionals) > 1 {
		return operatorConnections{}, nil, errors.New("explain accepts at most one exact resource identity")
	}
	return connections, positionals, nil
}

func parseOperatorConnectionFlags(command string, arguments []string, allowWatch bool) (operatorConnections, []string, error) {
	disabled := false
	clean := make([]string, 0, len(arguments))
	for _, argument := range arguments {
		if argument == "-no-context" || argument == "--no-context" {
			if disabled {
				return operatorConnections{}, nil, errors.New("-no-context may be supplied only once")
			}
			disabled = true
			continue
		}
		clean = append(clean, argument)
	}
	var selected cliContext
	contextName := ""
	if !disabled {
		config, _, err := loadCLIContextConfig()
		if err != nil {
			return operatorConnections{}, nil, err
		}
		if config.Current != "" || os.Getenv("STEWARD_CONTEXT") != "" {
			selected, err = selectedCLIContext(config)
			if err != nil {
				return operatorConnections{}, nil, err
			}
			contextName = selected.Name
		}
	}
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	controlURL := flags.String("control-url", selected.ControlURL, "Steward Control origin")
	controlToken := flags.String("token-file", selected.TokenFile, "operator token file")
	caFile := flags.String("ca-file", selected.CAFile, "private CA PEM bundle")
	tenantID := flags.String("tenant-id", selected.TenantID, "tenant scope")
	nodeURL := flags.String("node-url", selected.NodeURL, "loopback Executor origin")
	nodeToken := flags.String("node-token-file", selected.NodeTokenFile, "owner-only Executor token")
	output := flags.String("output", "human", "human or json output")
	watch := time.Duration(0)
	if allowWatch {
		flags.DurationVar(&watch, "watch", 0, "refresh interval between 1s and 5m")
	}
	if err := flags.Parse(clean); err != nil {
		return operatorConnections{}, nil, err
	}
	if !validOperatorOutput(*output) || watch < 0 || watch > 0 && (watch < time.Second || watch > 5*time.Minute) {
		return operatorConnections{}, nil, errors.New("output must be human or json and watch must be between 1s and 5m")
	}
	if (*controlURL == "") != (*controlToken == "") || (*nodeURL == "") != (*nodeToken == "") {
		return operatorConnections{}, nil, errors.New("each configured Control or node connection requires both its URL and token file")
	}
	if *controlURL == "" && *nodeURL == "" {
		return operatorConnections{}, nil, errors.New("no Control or node connection is configured; select a context or pass explicit connection flags")
	}
	return operatorConnections{
		contextName: contextName, controlURL: *controlURL, controlToken: *controlToken,
		caFile: *caFile, tenantID: *tenantID, nodeURL: *nodeURL, nodeToken: *nodeToken,
		output: *output, watchInterval: watch,
	}, flags.Args(), nil
}

func collectOperatorStatus(connections operatorConnections, target string) operatorStatus {
	status := operatorStatus{
		SchemaVersion: operatorStatusSchema, GeneratedAt: time.Now().UTC().Format(time.RFC3339Nano),
		Context: connections.contextName, State: "healthy", Findings: []operatorFinding{},
	}
	if connections.controlURL != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		client, err := controlclient.NewFromFiles(connections.controlURL, connections.controlToken, connections.caFile)
		if err == nil {
			var summary controlstore.OperationsSummary
			summary, err = client.GetOperationsSummary(ctx, connections.tenantID)
			if err == nil {
				status.Control = &summary
				var findings []operatorFinding
				var truncated bool
				findings, truncated, err = collectControlAttention(ctx, client, connections.tenantID, target)
				status.Findings = append(status.Findings, findings...)
				if truncated {
					status.SourceErrors = append(status.SourceErrors, "Control has more attention findings; use 'stewardctl control attention list' to page the complete bounded inventory.")
				}
			}
		}
		if err != nil {
			status.SourceErrors = append(status.SourceErrors, "Control: "+err.Error())
		}
		cancel()
	}
	if connections.nodeURL != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		client, err := nodeclient.NewFromTokenFile(connections.nodeURL, connections.nodeToken)
		if err == nil {
			var readiness nodeclient.Readiness
			readiness, err = client.Readiness(ctx)
			if err == nil {
				status.Node = &readiness
				for _, failure := range readiness.Reconciliation.Failures {
					status.Findings = append(status.Findings, nodeReconcileFinding(failure))
				}
				if readiness.Reconciliation.DroppedFailures != 0 {
					status.SourceErrors = append(status.SourceErrors, "Executor omitted additional failures after reaching its bounded diagnostic limit.")
				}
			}
		}
		if err != nil {
			status.SourceErrors = append(status.SourceErrors, "Executor: "+err.Error())
		}
		cancel()
	}
	for _, finding := range status.Findings {
		if finding.Severity == "critical" {
			status.State = "critical"
			break
		}
		status.State = "attention"
	}
	if len(status.SourceErrors) != 0 && status.State == "healthy" {
		status.State = "unavailable"
	}
	return status
}

func collectControlAttention(
	ctx context.Context,
	client *controlclient.Client,
	tenantID string,
	target string,
) ([]operatorFinding, bool, error) {
	limit := controlstore.DefaultInventoryPageLimit
	if target != "" {
		limit = controlstore.MaxInventoryPageLimit
	}
	findings := make([]operatorFinding, 0)
	cursor := ""
	seen := 0
	for {
		var page controlstore.AttentionPage
		var err error
		if target == "" {
			page, err = client.ListAttention(ctx, tenantID, "", cursor, limit)
		} else {
			page, err = client.ListAttentionForResource(ctx, tenantID, target, cursor, limit)
		}
		if err != nil {
			return findings, false, err
		}
		seen += len(page.Items)
		if seen > maxOperatorAttentionFindings {
			return findings, false, errors.New("Control attention inventory exceeds the bounded diagnostic scan limit")
		}
		for _, item := range page.Items {
			finding := controlAttentionFinding(item)
			if target != "" && finding.ResourceID != target {
				return findings, false, errors.New("Control returned an attention finding outside the requested resource filter")
			}
			findings = append(findings, finding)
		}
		if page.NextCursor == "" {
			return findings, false, nil
		}
		if target == "" {
			return findings, true, nil
		}
		if len(page.Items) == 0 || page.NextCursor == cursor {
			return findings, false, errors.New("Control attention pagination did not make progress")
		}
		cursor = page.NextCursor
	}
}

func controlAttentionFinding(item controlstore.AttentionItem) operatorFinding {
	resourceID := item.NodeID
	switch item.Resource {
	case controlstore.AttentionResourceCapacity:
		resourceID = string(item.CapacityResource)
	case controlstore.AttentionResourceQuota:
		resourceID = item.QuotaResource
	case controlstore.AttentionResourceCommand:
		resourceID = item.CommandID
	}
	return operatorFinding{
		Code: string(item.Reason), Severity: string(item.Severity), Resource: string(item.Resource),
		ResourceID: resourceID, Title: item.Title, Explanation: item.Explanation,
		Impact: item.Impact, NextStep: item.NextStep,
	}
}

func nodeReconcileFinding(failure nodeclient.ReconcileFailure) operatorFinding {
	title, explanation, impact, nextStep, blocked, critical := nodeFailureGuidance(failure.Code)
	severity := "warning"
	if critical {
		severity = "critical"
	}
	if explanation == "" {
		title = "Node reconciliation needs attention"
		explanation = "Executor could not prove the signed runtime matches its fail-closed desired state."
		impact = "Mutating operations remain blocked until the ambiguity is resolved."
		nextStep = "Inspect node readiness and preserve evidence before changing host state."
	}
	return operatorFinding{
		Code: failure.Code, Severity: severity, Resource: "runtime", ResourceID: failure.RuntimeRef,
		Title: title, Explanation: explanation, Impact: impact, NextStep: nextStep, Blocked: blocked,
	}
}

func nodeFailureGuidance(code string) (title, explanation, impact, nextStep string, blocked []string, critical bool) {
	blocked = []string{"start", "renew", "admit"}
	switch code {
	case "workload_missing":
		return "Signed workload is missing", "Executor proved that a present signed workload has no agent container.", "The instance cannot run and its remaining authority must be retired before replacement.", "Preview the bounded cleanup with 'stewardctl recover RUNTIME_REF'.", blocked, false
	case "workload_drift", "workload_identity_drift":
		return "Workload identity drift detected", "The observed container no longer matches the signed workload identity or hardened configuration.", "Executor contains expansion and blocks lifecycle changes.", "Preserve Docker inspection and Steward evidence, then restore the exact signed topology or retire the node.", blocked, true
	case "journal_pending", "journal_ambiguous", "journal_unavailable":
		return "A host mutation is unresolved", "Steward cannot prove the terminal result of a previously prepared host mutation.", "Further host mutations are blocked to prevent duplicate or contradictory effects.", "Preserve the journal and evidence, determine the external result, and follow the operation-specific recovery procedure.", blocked, true
	case "evidence_ambiguous", "evidence_unavailable":
		return "Evidence persistence is unresolved", "Executor could not prove that the lifecycle evidence record was durably retained.", "Steward cannot safely claim or repeat the affected operation.", "Preserve the evidence store and repair its availability before retrying any authority-bearing action.", blocked, true
	case "workload_inspect", "verification_ambiguous", "repair_ambiguous", "lease_cleanup_ambiguous":
		return "Runtime state cannot be verified", "Executor could not obtain a conclusive observation of the managed runtime topology.", "Lifecycle expansion remains blocked because current state is uncertain.", "Restore Docker and Gateway inspection, then allow reconciliation to run again.", blocked, true
	case "secure_admission_unavailable":
		return "Signed admission is unavailable", "Executor started without a usable signed-admission configuration.", "The node cannot enforce the production workload contract.", "Run the node doctor and restore the signed admission configuration before admitting workloads.", blocked, true
	case "record_limit":
		return "Reconciliation record limit reached", "The node retains more present signed workload records than one bounded scan accepts.", "Executor cannot prove the complete host state.", "Drain eligible workloads and preserve evidence before removing retired records.", blocked, true
	case "operation_identity", "invalid_context", "context_done", "reconciliation_failed":
		return "Reconciliation did not complete", "Executor could not complete a bounded reconciliation scan.", "The node remains degraded and blocks authority expansion.", "Check Executor health and logs, then let the periodic reconciler retry.", blocked, false
	default:
		return "", "", "", "", blocked, true
	}
}

func validOperatorOutput(value string) bool { return value == "human" || value == "json" }

func writeOperatorStatus(writer io.Writer, status operatorStatus, output string, watched bool) error {
	if output == "json" {
		encoder := json.NewEncoder(writer)
		encoder.SetEscapeHTML(false)
		return encoder.Encode(status)
	}
	if watched {
		fmt.Fprintf(writer, "\n%s\n", status.GeneratedAt)
	}
	fmt.Fprintf(writer, "Steward: %s", strings.ToUpper(status.State))
	if status.Context != "" {
		fmt.Fprintf(writer, "  context %s", status.Context)
	}
	fmt.Fprintln(writer)
	if status.Control != nil {
		fmt.Fprintf(writer, "Control: %d attention (%d critical), %d active nodes, %d pending commands\n",
			status.Control.Attention.Total, status.Control.Attention.Critical,
			status.Control.Evidence.ActiveNodes, status.Control.Commands.Pending)
	}
	if status.Node != nil {
		fmt.Fprintf(writer, "Executor: %s, %d signed runtimes checked, %d changed\n",
			status.Node.Status, status.Node.Reconciliation.Checked, status.Node.Reconciliation.Changed)
	}
	for _, finding := range status.Findings {
		identity := finding.Resource
		if finding.ResourceID != "" {
			identity += " " + finding.ResourceID
		}
		fmt.Fprintf(writer, "\n[%s] %s — %s\n", strings.ToUpper(finding.Severity), finding.Title, identity)
		fmt.Fprintf(writer, "  Cause: %s\n  Impact: %s\n  Next: %s\n", finding.Explanation, finding.Impact, finding.NextStep)
	}
	for _, sourceError := range status.SourceErrors {
		fmt.Fprintf(writer, "\n[UNAVAILABLE] %s\n", sourceError)
	}
	if len(status.Findings) == 0 && len(status.SourceErrors) == 0 {
		fmt.Fprintln(writer, "No current findings require operator attention.")
	}
	return nil
}

func writeRecoveryPlan(writer io.Writer, plan recoveryPlan, output string) error {
	if output == "json" {
		encoder := json.NewEncoder(writer)
		encoder.SetEscapeHTML(false)
		return encoder.Encode(plan)
	}
	fmt.Fprintf(writer, "Recovery: %s\nRuntime:  %s\nSafe:     %t\nApplied:  %t\n\n%s\nNext: %s\n",
		plan.Action, plan.RuntimeRef, plan.Safe, plan.Applied, plan.Explanation, plan.NextStep)
	return nil
}
