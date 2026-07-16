package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hardrails/steward/internal/controlauth"
	"github.com/hardrails/steward/internal/controlclient"
	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/nodeclient"
	"github.com/hardrails/steward/internal/securefile"
)

func controlCommand(arguments []string, stdout io.Writer) error {
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
	case "node-credential revoke":
		return controlNodeCredentialRevoke(arguments[2:], stdout)
	case "command submit":
		return controlCommandSubmit(arguments[2:], stdout)
	case "command status":
		return controlCommandStatus(arguments[2:], stdout)
	case "evidence status":
		return controlEvidenceStatus(arguments[2:], stdout)
	case "evidence export":
		return controlEvidenceExport(arguments[2:], stdout)
	case "evidence verify":
		return controlEvidenceVerify(arguments[2:], stdout)
	default:
		return controlUsageError()
	}
}

func controlUsageError() error {
	return errors.New("control requires pki create, tenant create|list, operator issue|revoke, enrollment create|exchange, node list|status|revoke, node-credential revoke, command submit|status, or evidence status|export|verify")
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

func writeControlJSON(stdout io.Writer, value any) error {
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(value)
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
