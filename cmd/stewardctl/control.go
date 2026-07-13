package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/hardrails/steward/internal/controlclient"
	"github.com/hardrails/steward/internal/nodeclient"
	"github.com/hardrails/steward/internal/securefile"
)

func controlCommand(arguments []string, stdout io.Writer) error {
	if len(arguments) < 2 {
		return errors.New("control requires tenant create, enrollment create|exchange, or command submit|status")
	}
	switch arguments[0] + " " + arguments[1] {
	case "tenant create":
		return controlTenantCreate(arguments[2:], stdout)
	case "enrollment create":
		return controlEnrollmentCreate(arguments[2:], stdout)
	case "enrollment exchange":
		return controlEnrollmentExchange(arguments[2:], stdout)
	case "command submit":
		return controlCommandSubmit(arguments[2:], stdout)
	case "command status":
		return controlCommandStatus(arguments[2:], stdout)
	default:
		return errors.New("control requires tenant create, enrollment create|exchange, or command submit|status")
	}
}

type controlFlags struct {
	url       *string
	tokenFile *string
	caFile    *string
}

func addControlFlags(flags *flag.FlagSet, requireToken bool) controlFlags {
	values := controlFlags{
		url:    flags.String("control-url", "https://127.0.0.1:8443", "Steward Control HTTPS origin"),
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

func controlEnrollmentCreate(arguments []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("control enrollment create", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	common := addControlFlags(flags, true)
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
	if *nodeID == "" || *output == "" || *validFor <= 0 || flags.NArg() != 0 {
		return errors.New("control enrollment create requires node, tenants, positive validity, and output")
	}
	client, err := common.client(true)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	enrollment, err := client.CreateEnrollment(ctx, *nodeID, tenantIDs, *validFor)
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
	output := flags.String("credential-out", "", "new owner-only Executor credential file")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *enrollmentPath == "" || *requestID == "" || *output == "" || flags.NArg() != 0 {
		return errors.New("control enrollment exchange requires enrollment, request-id, and credential output")
	}
	raw, err := securefile.Read(*enrollmentPath, 64<<10, securefile.OwnerOnly)
	if err != nil {
		return err
	}
	enrollment, err := controlclient.DecodeEnrollmentCapability(raw)
	if err != nil {
		return fmt.Errorf("enrollment capability file is invalid: %w", err)
	}
	client, err := common.client(false)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	credential, err := client.Enroll(ctx, enrollment.EnrollmentToken, *requestID)
	if err != nil {
		return err
	}
	credentialRaw, err := json.Marshal(credential)
	if err != nil {
		return err
	}
	if err := writeNewFile(*output, append(credentialRaw, '\n'), 0o600); err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, credential.NodeID)
	return err
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
