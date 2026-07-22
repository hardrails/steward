package main

import (
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
	"path/filepath"
	"strings"
	"time"

	"github.com/hardrails/steward/internal/controlauth"
	"github.com/hardrails/steward/internal/controlclient"
	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/controlstore"
	"github.com/hardrails/steward/internal/nodeclient"
	"github.com/hardrails/steward/internal/securefile"
)

func controlCommand(arguments []string, stdout io.Writer) error {
	if len(arguments) < 2 {
		return controlUsageError()
	}
	var err error
	arguments, err = applyCLIContext(arguments)
	if err != nil {
		return err
	}
	if len(arguments) < 2 {
		return controlUsageError()
	}
	switch arguments[0] + " " + arguments[1] {
	case "pki create":
		return controlPKICreate(arguments[2:], stdout)
	case "tenant create":
		return controlTenantCreate(arguments[2:], stdout)
	case "tenant list":
		return controlTenantList(arguments[2:], stdout)
	case "operator issue":
		return controlOperatorIssue(arguments[2:], stdout)
	case "operator revoke":
		return controlOperatorRevoke(arguments[2:], stdout)
	case "enrollment create":
		return controlEnrollmentCreate(arguments[2:], stdout)
	case "enrollment exchange":
		return controlEnrollmentExchange(arguments[2:], stdout)
	case "node list":
		return controlNodeList(arguments[2:], stdout)
	case "node status":
		return controlNodeStatus(arguments[2:], stdout)
	case "node revoke":
		return controlNodeRevoke(arguments[2:], stdout)
	case "node cordon":
		return controlNodePlacement(arguments[2:], stdout, controlstore.NodePlacementCordon)
	case "node uncordon":
		return controlNodePlacement(arguments[2:], stdout, controlstore.NodePlacementUncordon)
	case "node quarantine":
		return controlNodePlacement(arguments[2:], stdout, controlstore.NodePlacementQuarantine)
	case "node unquarantine":
		return controlNodePlacement(arguments[2:], stdout, controlstore.NodePlacementUnquarantine)
	case "node drain":
		return controlNodeDrain(arguments[2:], stdout, false)
	case "node cancel-drain":
		return controlNodeDrain(arguments[2:], stdout, true)
	case "node-credential revoke":
		return controlNodeCredentialRevoke(arguments[2:], stdout)
	case "snapshot status":
		return controlSnapshotQuarantineStatus(arguments[2:], stdout)
	case "snapshot quarantine":
		return controlSnapshotQuarantineChange(arguments[2:], stdout, controlstore.SnapshotQuarantineActionSet)
	case "snapshot unquarantine":
		return controlSnapshotQuarantineChange(arguments[2:], stdout, controlstore.SnapshotQuarantineActionClear)
	case "operations status":
		return controlOperationsStatus(arguments[2:], stdout)
	case "quota status":
		return controlTenantQuotaStatus(arguments[2:], stdout)
	case "quota set":
		return controlTenantQuotaChange(arguments[2:], stdout, controlstore.TenantQuotaActionSet)
	case "quota clear":
		return controlTenantQuotaChange(arguments[2:], stdout, controlstore.TenantQuotaActionClear)
	case "freeze status":
		return controlFreezeStatus(arguments[2:], stdout)
	case "freeze set":
		return controlFreezeChange(arguments[2:], stdout, controlstore.OperationalFreezeActionFreeze)
	case "freeze clear":
		return controlFreezeChange(arguments[2:], stdout, controlstore.OperationalFreezeActionUnfreeze)
	case "attention list":
		return controlAttentionList(arguments[2:], stdout)
	case "incident timeline":
		return controlIncidentTimeline(arguments[2:], stdout)
	case "agent list":
		return controlAgentList(arguments[2:], stdout)
	case "event list":
		return controlEventList(arguments[2:], stdout)
	case "task list":
		return controlTaskList(arguments[2:], stdout)
	case "command submit":
		return controlCommandSubmit(arguments[2:], stdout)
	case "command status":
		return controlCommandStatus(arguments[2:], stdout)
	case "command list":
		return controlCommandList(arguments[2:], stdout)
	case "credential list":
		return controlCredentialList(arguments[2:], stdout)
	case "evidence status":
		return controlEvidenceStatus(arguments[2:], stdout)
	case "evidence export":
		return controlEvidenceExport(arguments[2:], stdout)
	case "evidence verify":
		return controlEvidenceVerify(arguments[2:], stdout)
	case "evidence-capture arm":
		return controlEvidenceCaptureArm(arguments[2:], stdout)
	case "evidence-capture status":
		return controlEvidenceCaptureStatus(arguments[2:], stdout)
	case "evidence-capture seal":
		return controlEvidenceCaptureSeal(arguments[2:], stdout)
	case "evidence-capture export":
		return controlEvidenceCaptureExport(arguments[2:], stdout)
	case "evidence-capture verify":
		return controlEvidenceCaptureVerify(arguments[2:], stdout)
	case "evidence-capture delete":
		return controlEvidenceCaptureDelete(arguments[2:], stdout)
	case "support-bundle create", "support-bundle verify":
		return controlSupportBundleCommand(arguments[1:], stdout)
	default:
		return controlUsageError()
	}
}

func controlUsageError() error {
	return errors.New("control requires pki create, tenant create|list, operator issue|revoke, enrollment create|exchange, node list|status|cordon|uncordon|quarantine|unquarantine|drain|cancel-drain|revoke, node-credential revoke, snapshot status|quarantine|unquarantine, operations status, quota status|set|clear, freeze status|set|clear, attention list, incident timeline, agent list, event list, task list, command submit|status|list, credential list, evidence status|export|verify, evidence-capture arm|status|seal|export|verify|delete, or support-bundle create|verify")
}

func controlEventList(arguments []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("control event list", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	common := addControlFlags(flags, true)
	tenantID := flags.String("tenant-id", "", "tenant scope")
	after := flags.String("after", "", "exclusive event ID cursor")
	limit := flags.Int("limit", 100, "maximum events to return")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *tenantID == "" || *limit <= 0 || *limit > 100 || flags.NArg() != 0 {
		return errors.New("control event list requires tenant and a limit between 1 and 100")
	}
	client, err := common.client(true)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	events, err := client.ListInstanceEvents(ctx, *tenantID, *after, *limit)
	if err != nil {
		return err
	}
	return writeControlJSON(stdout, events)
}

func controlTaskList(arguments []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("control task list", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	common := addControlFlags(flags, true)
	tenantID := flags.String("tenant-id", "", "tenant scope")
	after := flags.String("after", "", "exclusive task projection cursor")
	limit := flags.Int("limit", 100, "maximum task projections to return")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *tenantID == "" || *limit <= 0 || *limit > 100 || flags.NArg() != 0 {
		return errors.New("control task list requires tenant and a limit between 1 and 100")
	}
	client, err := common.client(true)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	tasks, err := client.ListTaskProjections(ctx, *tenantID, *after, *limit)
	if err != nil {
		return err
	}
	return writeControlJSON(stdout, tasks)
}

type controlFlags struct {
	url       *string
	tokenFile *string
	caFile    *string
}

func addControlFlags(flags *flag.FlagSet, requireToken bool) controlFlags {
	values := controlFlags{
		url:    flags.String("control-url", "http://127.0.0.1:8443", "Steward Control origin (HTTPS except literal loopback)"),
		caFile: flags.String("ca-file", "", "optional private CA PEM bundle"),
	}
	if requireToken {
		values.tokenFile = flags.String("token-file", "", "owner-only control operator token")
	}
	return values
}

func (values controlFlags) client(requireToken bool) (*controlclient.Client, error) {
	tokenFile := ""
	if values.tokenFile != nil {
		tokenFile = *values.tokenFile
	}
	if requireToken && tokenFile == "" {
		return nil, errors.New("control operator token file is required")
	}
	return controlclient.NewFromFiles(*values.url, tokenFile, *values.caFile)
}

func controlTenantCreate(arguments []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("control tenant create", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	common := addControlFlags(flags, true)
	tenantID := flags.String("tenant-id", "", "new tenant identity")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *tenantID == "" || flags.NArg() != 0 {
		return errors.New("control tenant create requires -tenant-id")
	}
	client, err := common.client(true)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	tenant, err := client.CreateTenant(ctx, *tenantID)
	if err != nil {
		return err
	}
	return writeControlJSON(stdout, tenant)
}

func controlTenantList(arguments []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("control tenant list", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	common := addControlFlags(flags, true)
	after := flags.String("after", "", "exclusive tenant ID cursor")
	limit := flags.Int("limit", 100, "maximum tenants to return")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *limit <= 0 || *limit > 500 || flags.NArg() != 0 {
		return errors.New("control tenant list requires a limit between 1 and 500 and no positional arguments")
	}
	client, err := common.client(true)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	tenants, err := client.ListTenants(ctx, *after, *limit)
	if err != nil {
		return err
	}
	return writeControlJSON(stdout, tenants)
}

func controlOperatorIssue(arguments []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("control operator issue", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	common := addControlFlags(flags, true)
	requestID := flags.String("request-id", "", "stable idempotency identity")
	role := flags.String("role", "", "site_admin or tenant_operator")
	tenantID := flags.String("tenant-id", "", "tenant scope for a tenant operator")
	output := flags.String("token-out", "", "new owner-only operator token file")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || *requestID == "" || *output == "" || (*role != "site_admin" && *role != "tenant_operator") ||
		(*role == "site_admin" && *tenantID != "") || (*role == "tenant_operator" && *tenantID == "") {
		return errors.New("control operator issue requires request ID, a valid role, matching tenant scope, and token output")
	}
	client, err := common.client(true)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	operator, err := client.IssueOperator(ctx, *requestID, *role, *tenantID)
	if err != nil {
		return err
	}
	if operator.Token == "" || operator.CredentialID == "" {
		return errors.New("control plane returned an incomplete operator credential")
	}
	if err := writeNewFile(*output, []byte(operator.Token+"\n"), 0o600); err != nil {
		return fmt.Errorf("write operator token: %w", err)
	}
	_, err = fmt.Fprintln(stdout, operator.CredentialID)
	return err
}

func controlOperatorRevoke(arguments []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("control operator revoke", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	common := addControlFlags(flags, true)
	credentialID := flags.String("credential-id", "", "operator credential identity")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *credentialID == "" || flags.NArg() != 0 {
		return errors.New("control operator revoke requires -credential-id")
	}
	client, err := common.client(true)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := client.RevokeOperator(ctx, *credentialID); err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, *credentialID)
	return err
}

func controlEnrollmentCreate(arguments []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("control enrollment create", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	common := addControlFlags(flags, true)
	requestID := flags.String("request-id", "", "stable idempotency identity")
	nodeID := flags.String("node-id", "", "node identity")
	tenantList := flags.String("tenant-ids", "", "comma-separated tenant bindings")
	validFor := flags.Duration("valid-for", 15*time.Minute, "one-time enrollment lifetime")
	output := flags.String("out", "", "new owner-only enrollment capability file")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	tenantIDs, err := parseTenantIDs(*tenantList)
	if err != nil {
		return err
	}
	if *requestID == "" || *nodeID == "" || *output == "" || *validFor <= 0 || flags.NArg() != 0 {
		return errors.New("control enrollment create requires request ID, node, tenants, positive validity, and output")
	}
	client, err := common.client(true)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	enrollment, err := client.CreateEnrollment(ctx, *requestID, *nodeID, tenantIDs, *validFor)
	if err != nil {
		return err
	}
	raw, err := json.MarshalIndent(enrollment, "", "  ")
	if err != nil {
		return err
	}
	if err := writeNewFile(*output, append(raw, '\n'), 0o600); err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, enrollment.EnrollmentID)
	return err
}

func controlEnrollmentExchange(arguments []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("control enrollment exchange", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	common := addControlFlags(flags, false)
	enrollmentPath := flags.String("enrollment", "", "owner-only enrollment capability file")
	requestID := flags.String("request-id", "", "stable idempotency identity")
	evidencePrivateKeyPath := flags.String("executor-evidence-private-key", "", "owner-only Executor receipt key")
	evidenceEpoch := flags.Uint64("executor-evidence-epoch", 1, "Executor receipt epoch")
	output := flags.String("credential-out", "", "new owner-only Executor credential file")
	evidenceConfigOutput := flags.String("executor-evidence-config-out", "", "new owner-only Executor evidence enrollment config")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *enrollmentPath == "" || *requestID == "" || *evidencePrivateKeyPath == "" || *evidenceEpoch != 1 ||
		*output == "" || *evidenceConfigOutput == "" || flags.NArg() != 0 {
		return errors.New("control enrollment exchange requires enrollment, request-id, an Executor evidence private key at epoch 1, credential output, and evidence config output")
	}
	raw, err := securefile.Read(*enrollmentPath, 64<<10, securefile.OwnerOnly)
	if err != nil {
		return err
	}
	enrollment, err := controlclient.DecodeEnrollmentCapability(raw)
	if err != nil {
		return fmt.Errorf("enrollment capability file is invalid: %w", err)
	}
	evidencePrivate, err := readPrivateKey(*evidencePrivateKeyPath)
	if err != nil {
		return fmt.Errorf("read Executor evidence private key: %w", err)
	}
	claim, err := controlprotocol.NewExecutorEvidenceIdentityClaimV1(
		enrollment.ControllerInstanceID, enrollment.EnrollmentID, enrollment.NodeID, enrollment.NodeID,
		*evidenceEpoch, evidencePrivate.Public().(ed25519.PublicKey),
	)
	if err != nil {
		return fmt.Errorf("create Executor evidence identity claim: %w", err)
	}
	proof, err := controlprotocol.SignExecutorEvidenceIdentityClaimV1(claim, evidencePrivate)
	if err != nil {
		return fmt.Errorf("sign Executor evidence identity claim: %w", err)
	}
	client, err := common.client(false)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	credential, err := client.Enroll(ctx, enrollment.EnrollmentToken, *requestID, proof)
	if err != nil {
		return err
	}
	credentialID, err := validateEnrollmentCredential(enrollment, credential)
	if err != nil {
		return err
	}
	credentialRaw, err := json.Marshal(credential)
	if err != nil {
		return err
	}
	evidenceConfig := fmt.Appendf(nil,
		"STEWARD_EXECUTOR_EVIDENCE_CONFIG_VERSION=1\n"+
			"STEWARD_EXECUTOR_EVIDENCE_CONTROLLER_INSTANCE_ID=%s\n"+
			"STEWARD_EXECUTOR_EVIDENCE_NODE_ID=%s\n"+
			"STEWARD_EXECUTOR_EVIDENCE_RECEIPT_EPOCH=%d\n"+
			"STEWARD_EXECUTOR_EVIDENCE_PUBLIC_KEY_BASE64=%s\n",
		enrollment.ControllerInstanceID, enrollment.NodeID, *evidenceEpoch, claim.PublicKeyBase64,
	)
	if err := writeEnrollmentOutputs(
		*output, append(credentialRaw, '\n'),
		*evidenceConfigOutput, evidenceConfig,
	); err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, credentialID)
	return err
}

func writeEnrollmentOutputs(credentialPath string, credential []byte, configPath string, config []byte) error {
	credentialClean, err := filepath.Abs(credentialPath)
	if err != nil {
		return err
	}
	configClean, err := filepath.Abs(configPath)
	if err != nil {
		return err
	}
	if filepath.Clean(credentialClean) == filepath.Clean(configClean) {
		return errors.New("credential output and evidence config output must name different files")
	}
	for _, path := range []string{credentialPath, configPath} {
		if _, err := os.Lstat(path); err == nil {
			return fmt.Errorf("enrollment output already exists: %s", path)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if err := writeNewFile(configPath, config, 0o600); err != nil {
		return err
	}
	if err := writeNewFile(credentialPath, credential, 0o600); err != nil {
		removeErr := os.Remove(configPath)
		syncErr := syncOutputDirectory(configPath)
		return errors.Join(err, removeErr, syncErr)
	}
	return nil
}

func validateEnrollmentCredential(enrollment controlclient.Enrollment, credential controlclient.NodeCredential) (string, error) {
	if credential.Version != 2 || credential.Scope != "node" || credential.TenantID != "" ||
		credential.NodeID != enrollment.NodeID {
		return "", errors.New("control plane returned a node credential outside the enrollment identity")
	}
	credentialID, err := controlauth.ParseNodeCredentialID(credential.Credential)
	if err != nil {
		return "", errors.New("control plane returned an invalid node credential")
	}
	return credentialID, nil
}

func controlNodeList(arguments []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("control node list", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	common := addControlFlags(flags, true)
	tenantID := flags.String("tenant-id", "", "tenant scope")
	after := flags.String("after", "", "exclusive node ID cursor")
	limit := flags.Int("limit", 100, "maximum nodes to return")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *tenantID == "" || *limit <= 0 || *limit > 500 || flags.NArg() != 0 {
		return errors.New("control node list requires tenant and a limit between 1 and 500")
	}
	client, err := common.client(true)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	nodes, err := client.ListNodes(ctx, *tenantID, *after, *limit)
	if err != nil {
		return err
	}
	return writeControlJSON(stdout, nodes)
}

func controlNodeStatus(arguments []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("control node status", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	common := addControlFlags(flags, true)
	tenantID := flags.String("tenant-id", "", "tenant scope")
	nodeID := flags.String("node-id", "", "node identity")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *tenantID == "" || *nodeID == "" || flags.NArg() != 0 {
		return errors.New("control node status requires tenant and node")
	}
	client, err := common.client(true)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	node, err := client.GetNode(ctx, *tenantID, *nodeID)
	if err != nil {
		return err
	}
	return writeControlJSON(stdout, node)
}

func controlNodeRevoke(arguments []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("control node revoke", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	common := addControlFlags(flags, true)
	nodeID := flags.String("node-id", "", "node identity")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *nodeID == "" || flags.NArg() != 0 {
		return errors.New("control node revoke requires -node-id")
	}
	client, err := common.client(true)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	revocation, err := client.RevokeNode(ctx, *nodeID)
	if err != nil {
		return err
	}
	return writeControlJSON(stdout, revocation)
}

func controlNodePlacement(
	arguments []string,
	stdout io.Writer,
	action controlstore.NodePlacementAction,
) error {
	name := "control node " + string(action)
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	common := addControlFlags(flags, true)
	nodeID := flags.String("node-id", "", "node identity (or pass it as the final argument)")
	reason := flags.String("reason", "", "bounded operator reason")
	flagArguments, positional := placementFlagArguments(arguments)
	if err := flags.Parse(flagArguments); err != nil {
		return err
	}
	if *nodeID == "" && len(positional) == 1 {
		*nodeID = positional[0]
	} else if len(positional) != 0 {
		return fmt.Errorf("%s accepts one node ID", name)
	}
	requiresReason := action == controlstore.NodePlacementCordon || action == controlstore.NodePlacementQuarantine
	if *nodeID == "" {
		return fmt.Errorf("%s requires a node ID", name)
	}
	if requiresReason && *reason == "" {
		return fmt.Errorf("%s requires -reason", name)
	}
	if !requiresReason && *reason != "" {
		return fmt.Errorf("%s does not accept -reason", name)
	}
	client, err := common.client(true)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	change, err := client.ChangeNodePlacement(ctx, *nodeID, action, *reason)
	if err != nil {
		return err
	}
	return writeControlJSON(stdout, change)
}

func controlNodeDrain(arguments []string, stdout io.Writer, cancelDrain bool) error {
	name := "control node drain"
	if cancelDrain {
		name = "control node cancel-drain"
	}
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	common := addControlFlags(flags, true)
	nodeID := flags.String("node-id", "", "node identity (or pass it as the final argument)")
	requestID := flags.String("request-id", "", "stable drain identity; generated when starting and omitted")
	reason := flags.String("reason", "", "bounded maintenance reason")
	flagArguments, positional := placementFlagArguments(arguments)
	if err := flags.Parse(flagArguments); err != nil {
		return err
	}
	if *nodeID == "" && len(positional) == 1 {
		*nodeID = positional[0]
	} else if len(positional) != 0 {
		return fmt.Errorf("%s accepts one node ID", name)
	}
	if *nodeID == "" {
		return fmt.Errorf("%s requires a node ID", name)
	}
	if cancelDrain {
		if *requestID == "" || *reason != "" {
			return fmt.Errorf("%s requires -request-id and does not accept -reason", name)
		}
	} else {
		if *reason == "" {
			return fmt.Errorf("%s requires -reason", name)
		}
		if *requestID == "" {
			generated, err := randomAgentID("drain")
			if err != nil {
				return err
			}
			*requestID = generated
		}
	}
	client, err := common.client(true)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var change controlclient.NodeDrainChange
	if cancelDrain {
		change, err = client.CancelNodeDrain(ctx, *nodeID, *requestID)
	} else {
		change, err = client.StartNodeDrain(ctx, *nodeID, *requestID, *reason)
	}
	if err != nil {
		return err
	}
	return writeControlJSON(stdout, change)
}

// placementFlagArguments lets the ergonomic positional node ID coexist with
// context flags appended by applyCLIContext. Every flag in this command takes
// exactly one value; flag.Parse still rejects unknown or malformed flags.
func placementFlagArguments(arguments []string) ([]string, []string) {
	flagArguments := make([]string, 0, len(arguments))
	positionals := make([]string, 0, 1)
	for index := 0; index < len(arguments); index++ {
		argument := arguments[index]
		if !strings.HasPrefix(argument, "-") {
			positionals = append(positionals, argument)
			continue
		}
		flagArguments = append(flagArguments, argument)
		if !strings.Contains(argument, "=") && index+1 < len(arguments) {
			index++
			flagArguments = append(flagArguments, arguments[index])
		}
	}
	return flagArguments, positionals
}

func controlNodeCredentialRevoke(arguments []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("control node-credential revoke", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	common := addControlFlags(flags, true)
	credentialID := flags.String("credential-id", "", "node credential identity")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *credentialID == "" || flags.NArg() != 0 {
		return errors.New("control node-credential revoke requires -credential-id")
	}
	client, err := common.client(true)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	revocation, err := client.RevokeNodeCredential(ctx, *credentialID)
	if err != nil {
		return err
	}
	return writeControlJSON(stdout, revocation)
}

func controlOperationsStatus(arguments []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("control operations status", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	common := addControlFlags(flags, true)
	tenantID := flags.String("tenant-id", "", "optional tenant-projected scope")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if !validOptionalControlIdentifier(*tenantID, 128) || flags.NArg() != 0 {
		return errors.New("control operations status accepts only an optional bounded -tenant-id")
	}
	client, err := common.client(true)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	summary, err := client.GetOperationsSummary(ctx, *tenantID)
	if err != nil {
		return err
	}
	return writeControlJSON(stdout, summary)
}

func controlTenantQuotaStatus(arguments []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("control quota status", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	common := addControlFlags(flags, true)
	tenantID := flags.String("tenant-id", "", "tenant scope")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if !validOptionalControlIdentifier(*tenantID, 128) || *tenantID == "" || flags.NArg() != 0 {
		return errors.New("control quota status requires -tenant-id")
	}
	client, err := common.client(true)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	status, err := client.GetTenantResourceQuota(ctx, *tenantID)
	if err != nil {
		return err
	}
	return writeControlJSON(stdout, status)
}

func controlTenantQuotaChange(
	arguments []string,
	stdout io.Writer,
	action controlstore.TenantQuotaAction,
) error {
	command := "control quota set"
	if action == controlstore.TenantQuotaActionClear {
		command = "control quota clear"
	}
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	common := addControlFlags(flags, true)
	tenantID := flags.String("tenant-id", "", "tenant scope")
	revision := flags.Uint64("revision", 0, "expected retained revision; zero discovers it safely")
	memoryMiB := flags.Int64("memory-mib", 0, "maximum total requested memory in MiB")
	cpuMillis := flags.Int64("cpu-millis", 0, "maximum total requested CPU in millicores")
	pids := flags.Int64("pids", 0, "maximum total requested process count")
	workloads := flags.Int64("workloads", 0, "maximum total workload count")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	resources := controlprotocol.ExecutorSchedulingResourcesV1{}
	if action == controlstore.TenantQuotaActionSet {
		if *memoryMiB <= 0 || *memoryMiB > math.MaxInt64/(1<<20) || *cpuMillis <= 0 ||
			*cpuMillis > math.MaxInt64/1_000_000 || *pids <= 0 || *workloads <= 0 {
			return errors.New("control quota set requires positive -memory-mib, -cpu-millis, -pids, and -workloads")
		}
		resources = controlprotocol.ExecutorSchedulingResourcesV1{
			MemoryBytes: *memoryMiB * (1 << 20), CPUMillis: *cpuMillis, PIDs: *pids, Workloads: *workloads,
		}
	} else if *memoryMiB != 0 || *cpuMillis != 0 || *pids != 0 || *workloads != 0 {
		return errors.New("control quota clear accepts only tenant scope and revision")
	}
	if !validOptionalControlIdentifier(*tenantID, 128) || *tenantID == "" || flags.NArg() != 0 {
		return errors.New("control quota set and clear require -tenant-id and no positional arguments")
	}
	client, err := common.client(true)
	if err != nil {
		return err
	}
	expectedRevision := *revision
	if expectedRevision == 0 {
		discoveryContext, cancelDiscovery := context.WithTimeout(context.Background(), 30*time.Second)
		status, err := client.GetTenantResourceQuota(discoveryContext, *tenantID)
		cancelDiscovery()
		if err != nil {
			return err
		}
		if status.Quota != nil {
			expectedRevision = status.Quota.Revision
		}
	}
	changeContext, cancelChange := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelChange()
	change, err := client.ChangeTenantResourceQuota(changeContext, *tenantID, action, expectedRevision, resources)
	if err != nil {
		return err
	}
	return writeControlJSON(stdout, change)
}

func controlFreezeStatus(arguments []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("control freeze status", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	common := addControlFlags(flags, true)
	tenantID := flags.String("tenant-id", "", "optional tenant scope; omit for the whole site")
	site := flags.Bool("site", false, "inspect the site scope even when the current context has a tenant")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if !validOptionalControlIdentifier(*tenantID, 128) || *site && *tenantID != "" || flags.NArg() != 0 {
		return errors.New("control freeze status accepts only an optional bounded -tenant-id")
	}
	client, err := common.client(true)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	status, err := client.GetOperationalFreeze(ctx, *tenantID)
	if err != nil {
		return err
	}
	return writeControlJSON(stdout, status)
}

func controlFreezeChange(
	arguments []string,
	stdout io.Writer,
	action controlstore.OperationalFreezeAction,
) error {
	name := controlFreezeChangeCommand(action)
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	common := addControlFlags(flags, true)
	tenantID := flags.String("tenant-id", "", "optional tenant scope; omit for the whole site")
	site := flags.Bool("site", false, "change the site scope even when the current context has a tenant")
	reason := flags.String("reason", "", "short incident reason required when setting a freeze")
	revision := flags.Uint64("revision", 0, "expected retained revision; zero discovers it safely")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if !validOptionalControlIdentifier(*tenantID, 128) || *site && *tenantID != "" || flags.NArg() != 0 ||
		action == controlstore.OperationalFreezeActionFreeze && *reason == "" ||
		action == controlstore.OperationalFreezeActionUnfreeze && *reason != "" {
		return errors.New("control freeze set requires -reason; status and clear accept only scope and revision")
	}
	client, err := common.client(true)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	expectedRevision := *revision
	if expectedRevision == 0 {
		status, err := client.GetOperationalFreeze(ctx, *tenantID)
		if err != nil {
			return err
		}
		retained := status.Site
		if *tenantID != "" {
			retained = status.Tenant
		}
		if retained != nil {
			expectedRevision = retained.Revision
		}
	}
	change, err := client.ChangeOperationalFreeze(ctx, *tenantID, action, expectedRevision, *reason)
	if err != nil {
		return err
	}
	return writeControlJSON(stdout, change)
}

func controlFreezeChangeCommand(action controlstore.OperationalFreezeAction) string {
	name := "control freeze set"
	if action == controlstore.OperationalFreezeActionUnfreeze {
		name = "control freeze clear"
	}
	return name
}

func controlAttentionList(arguments []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("control attention list", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	common := addControlFlags(flags, true)
	tenantID := flags.String("tenant-id", "", "optional tenant-projected scope")
	reason := flags.String("reason", "", "optional exact attention reason")
	cursor := flags.String("cursor", "", "opaque continuation cursor")
	limit := flags.Int("limit", controlstore.DefaultInventoryPageLimit, "maximum attention items to return")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if !validOptionalControlIdentifier(*tenantID, 128) ||
		!validControlAttentionReason(*reason) ||
		!validControlInventoryPage(*cursor, *limit, false) ||
		flags.NArg() != 0 {
		return errors.New("control attention list accepts optional bounded tenant, reason, cursor, and a limit between 1 and 500")
	}
	client, err := common.client(true)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	page, err := client.ListAttention(ctx, *tenantID, *reason, *cursor, *limit)
	if err != nil {
		return err
	}
	return writeControlJSON(stdout, page)
}

func controlIncidentTimeline(arguments []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("control incident timeline", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	common := addControlFlags(flags, true)
	tenantID := flags.String("tenant-id", "", "optional tenant-projected scope")
	nodeID := flags.String("node-id", "", "optional exact node identity")
	kind := flags.String("kind", "", "optional containment, evidence, access, or workload category")
	severity := flags.String("severity", "", "optional info, warning, or critical severity")
	cursor := flags.String("cursor", "", "opaque continuation cursor")
	limit := flags.Int("limit", controlstore.DefaultInventoryPageLimit, "maximum incident facts to return")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	validKind := *kind == "" || *kind == string(controlstore.IncidentContainment) ||
		*kind == string(controlstore.IncidentEvidence) || *kind == string(controlstore.IncidentAccess) ||
		*kind == string(controlstore.IncidentWorkload)
	validSeverity := *severity == "" || *severity == string(controlstore.IncidentInfo) ||
		*severity == string(controlstore.IncidentWarning) || *severity == string(controlstore.IncidentCritical)
	if !validOptionalControlIdentifier(*tenantID, 128) ||
		!validOptionalControlIdentifier(*nodeID, 128) || !validKind || !validSeverity ||
		!validControlInventoryPage(*cursor, *limit, false) || flags.NArg() != 0 {
		return errors.New("control incident timeline accepts bounded tenant, node, category, severity, cursor, and a limit between 1 and 500")
	}
	client, err := common.client(true)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	page, err := client.ListIncidentTimeline(
		ctx, *tenantID, *nodeID, *kind, *severity, *cursor, *limit,
	)
	if err != nil {
		return err
	}
	return writeControlJSON(stdout, page)
}

func controlAgentList(arguments []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("control agent list", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	common := addControlFlags(flags, true)
	tenantID := flags.String("tenant-id", "", "optional tenant-projected scope")
	nodeID := flags.String("node-id", "", "optional exact node identity")
	status := flags.String("status", "", "optional unknown, provisioning, running, stopped, or hibernated status")
	cursor := flags.String("cursor", "", "opaque continuation cursor")
	limit := flags.Int("limit", controlstore.DefaultInventoryPageLimit, "maximum agent runtimes to return")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if !validOptionalControlIdentifier(*tenantID, 128) ||
		!validOptionalControlIdentifier(*nodeID, 128) ||
		!validControlAgentStatus(*status) ||
		!validControlInventoryPage(*cursor, *limit, false) || flags.NArg() != 0 {
		return errors.New("control agent list accepts bounded tenant, node, observed status, cursor, and a limit between 1 and 500")
	}
	client, err := common.client(true)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	page, err := client.ListAgentInventory(ctx, *tenantID, *nodeID, *status, *cursor, *limit)
	if err != nil {
		return err
	}
	return writeControlJSON(stdout, page)
}

func controlCommandSubmit(arguments []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("control command submit", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	common := addControlFlags(flags, true)
	tenantID := flags.String("tenant-id", "", "command tenant")
	nodeID := flags.String("node-id", "", "destination node")
	commandPath := flags.String("command", "", "signed Executor command DSSE file")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *tenantID == "" || *nodeID == "" || *commandPath == "" || flags.NArg() != 0 {
		return errors.New("control command submit requires tenant, node, and signed command")
	}
	commandRaw, err := nodeclient.ReadBounded(*commandPath, 1<<20)
	if err != nil {
		return err
	}
	client, err := common.client(true)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	command, err := client.SubmitCommand(ctx, *tenantID, *nodeID, commandRaw)
	if err != nil {
		return err
	}
	return writeControlJSON(stdout, command)
}

func controlCommandStatus(arguments []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("control command status", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	common := addControlFlags(flags, true)
	tenantID := flags.String("tenant-id", "", "command tenant")
	nodeID := flags.String("node-id", "", "destination node")
	commandID := flags.String("command-id", "", "signed command identity")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *tenantID == "" || *nodeID == "" || *commandID == "" || flags.NArg() != 0 {
		return errors.New("control command status requires tenant, node, and command ID")
	}
	client, err := common.client(true)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	command, err := client.GetCommand(ctx, *tenantID, *nodeID, *commandID)
	if err != nil {
		return err
	}
	return writeControlJSON(stdout, command)
}

func controlCommandList(arguments []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("control command list", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	common := addControlFlags(flags, true)
	tenantID := flags.String("tenant-id", "", "optional tenant-projected scope")
	nodeID := flags.String("node-id", "", "optional exact node identity")
	state := flags.String("state", "", "optional pending, leased, or terminal state")
	terminalStatus := flags.String("terminal-status", "", "optional done, failed, rejected, or outcome_unknown status")
	cursor := flags.String("cursor", "", "opaque continuation cursor")
	limit := flags.Int("limit", controlstore.DefaultInventoryPageLimit, "maximum commands to return")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if !validOptionalControlIdentifier(*tenantID, 128) ||
		!validOptionalControlIdentifier(*nodeID, 128) ||
		!validControlCommandState(*state) ||
		!validControlTerminalStatus(*terminalStatus) ||
		(*terminalStatus != "" && *state != string(controlstore.CommandTerminal)) ||
		!validControlInventoryPage(*cursor, *limit, false) ||
		flags.NArg() != 0 {
		return errors.New("control command list accepts bounded tenant, node, state, terminal status, cursor, and a limit between 1 and 500; terminal status requires state=terminal")
	}
	client, err := common.client(true)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	page, err := client.ListCommandInventory(
		ctx, *tenantID, *nodeID, *state, *terminalStatus, *cursor, *limit,
	)
	if err != nil {
		return err
	}
	return writeControlJSON(stdout, page)
}

func controlCredentialList(arguments []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("control credential list", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	common := addControlFlags(flags, true)
	tenantID := flags.String("tenant-id", "", "optional tenant-projected scope")
	kind := flags.String("kind", "", "optional operator or node credential kind")
	role := flags.String("role", "", "optional site_admin or tenant_operator role")
	nodeID := flags.String("node-id", "", "optional exact node identity")
	revokedValue := flags.String("revoked", "any", "any, true, or false revocation state")
	cursor := flags.String("cursor", "", "opaque continuation cursor")
	limit := flags.Int("limit", controlstore.DefaultInventoryPageLimit, "maximum credentials to return")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	revoked, revokedErr := parseControlRevoked(*revokedValue)
	if !validOptionalControlIdentifier(*tenantID, 128) ||
		!validControlCredentialKind(*kind) ||
		!validControlCredentialRole(*role) ||
		!validOptionalControlIdentifier(*nodeID, 128) ||
		(*kind == string(controlauth.KindNode) && *role != "") ||
		(*kind == string(controlauth.KindOperator) && *nodeID != "") ||
		(*role != "" && *nodeID != "") ||
		revokedErr != nil ||
		!validControlInventoryPage(*cursor, *limit, false) ||
		flags.NArg() != 0 {
		return errors.New("control credential list accepts bounded tenant, kind, role, node, revoked, cursor, and a limit between 1 and 500; role and node filters cannot be combined")
	}
	client, err := common.client(true)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	page, err := client.ListCredentialInventory(
		ctx, *tenantID, *kind, *role, *nodeID, revoked, *cursor, *limit,
	)
	if err != nil {
		return err
	}
	return writeControlJSON(stdout, page)
}

func writeControlJSON(stdout io.Writer, value any) error {
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(value)
}

func validOptionalControlIdentifier(value string, maximum int) bool {
	if value == "" {
		return true
	}
	if maximum < 1 || len(value) > maximum || strings.TrimSpace(value) != value {
		return false
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		if (character >= 'A' && character <= 'Z') ||
			(character >= 'a' && character <= 'z') ||
			(character >= '0' && character <= '9') ||
			(index > 0 && (character == '.' || character == '_' || character == '-')) {
			continue
		}
		return false
	}
	return true
}

func validControlInventoryPage(cursor string, limit int, allowDefault bool) bool {
	if allowDefault {
		if limit < 0 || limit > controlstore.MaxInventoryPageLimit {
			return false
		}
	} else if limit < 1 || limit > controlstore.MaxInventoryPageLimit {
		return false
	}
	if cursor == "" {
		return true
	}
	if len(cursor) > base64.RawURLEncoding.EncodedLen(4096) ||
		strings.ContainsAny(cursor, "\r\n\x00") {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(cursor)
	return err == nil && len(raw) > 0 && len(raw) <= 4096 &&
		base64.RawURLEncoding.EncodeToString(raw) == cursor
}

func validControlAttentionReason(value string) bool {
	switch controlstore.AttentionReason(value) {
	case "", controlstore.AttentionNodeNeverSeen, controlstore.AttentionNodeStale,
		controlstore.AttentionEvidenceUnwitnessed, controlstore.AttentionEvidenceStale,
		controlstore.AttentionRollbackDetected, controlstore.AttentionEquivocationDetected,
		controlstore.AttentionCommandPendingOverdue, controlstore.AttentionCommandLeaseExpired,
		controlstore.AttentionCommandFailed, controlstore.AttentionCommandOutcomeUnknown,
		controlstore.AttentionCapacityWarning, controlstore.AttentionTenantQuotaWarning,
		controlstore.AttentionTenantQuotaExceeded:
		return true
	default:
		return false
	}
}

func validControlCommandState(value string) bool {
	switch controlstore.CommandState(value) {
	case "", controlstore.CommandPending, controlstore.CommandLeased, controlstore.CommandTerminal:
		return true
	default:
		return false
	}
}

func validControlAgentStatus(value string) bool {
	switch value {
	case "", "unknown", "provisioning", "running", "stopped", "hibernated":
		return true
	default:
		return false
	}
}

func validControlTerminalStatus(value string) bool {
	switch value {
	case "", controlprotocol.ExecutorStatusDone, controlprotocol.ExecutorStatusFailed,
		controlprotocol.ExecutorStatusRejected, controlprotocol.ExecutorStatusOutcomeUnknown:
		return true
	default:
		return false
	}
}

func validControlCredentialKind(value string) bool {
	switch controlauth.CredentialKind(value) {
	case "", controlauth.KindOperator, controlauth.KindNode:
		return true
	default:
		return false
	}
}

func validControlCredentialRole(value string) bool {
	switch controlauth.Role(value) {
	case "", controlauth.RoleSiteAdmin, controlauth.RoleTenantOperator:
		return true
	default:
		return false
	}
}

func parseControlRevoked(value string) (*bool, error) {
	switch value {
	case "any":
		return nil, nil
	case "true":
		revoked := true
		return &revoked, nil
	case "false":
		revoked := false
		return &revoked, nil
	default:
		return nil, errors.New("revoked filter must be any, true, or false")
	}
}

func parseTenantIDs(value string) ([]string, error) {
	parts := strings.Split(value, ",")
	seen := make(map[string]struct{}, len(parts))
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" || len(part) > 128 || strings.ContainsRune(part, '\x00') {
			return nil, errors.New("tenant IDs must be a non-empty comma-separated list")
		}
		if _, duplicate := seen[part]; duplicate {
			return nil, errors.New("tenant IDs must not contain duplicates")
		}
		seen[part] = struct{}{}
		result = append(result, part)
	}
	if len(result) == 0 || len(result) > 128 {
		return nil, errors.New("tenant binding count must be between 1 and 128")
	}
	return result, nil
}
