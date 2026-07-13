package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/executoruplink"
)

const defaultExecutorCommandValidity = 5 * time.Minute

func executorCommand(arguments []string, stdout io.Writer) error {
	if len(arguments) == 0 {
		return errors.New("executor-command requires issue or verify")
	}
	switch arguments[0] {
	case "issue":
		return issueExecutorCommand(arguments[1:], stdout)
	case "verify":
		return verifyArtifact(arguments[1:], stdout, admission.CommandPayloadType)
	default:
		return errors.New("executor-command requires issue or verify")
	}
}

func issueExecutorCommand(arguments []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("executor-command issue", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	commandID := flags.String("command-id", "", "unique signed command identity")
	tenantID := flags.String("tenant-id", "", "tenant identity")
	nodeID := flags.String("node-id", "", "destination node identity")
	instanceID := flags.String("instance-id", "", "destination instance identity")
	kind := flags.String("kind", "", "admit, start, stop, destroy, read, or purge")
	claimGeneration := flags.Uint64("claim-generation", 1, "signed authorization generation")
	instanceGeneration := flags.Uint64("instance-generation", 0, "instance lineage generation")
	commandSequence := flags.Uint64("sequence", 0, "monotonic instance command sequence")
	validFor := flags.Duration("valid-for", defaultExecutorCommandValidity, "signed command lifetime")
	payloadPath := flags.String("payload", "", "bounded JSON operation payload")
	privateKeyPath := flags.String("key", "", "PEM Ed25519 command private key")
	keyID := flags.String("key-id", "", "command signing key ID")
	outputPath := flags.String("out", "", "new owner-only DSSE command file")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *commandID == "" || *tenantID == "" || *nodeID == "" || *instanceID == "" || *kind == "" ||
		*instanceGeneration == 0 || *commandSequence == 0 || *payloadPath == "" || *privateKeyPath == "" ||
		*keyID == "" || *outputPath == "" || flags.NArg() != 0 {
		return errors.New("executor-command issue requires command, tenant, node, instance, kind, generation, sequence, payload, key, key-id, and output")
	}
	if *validFor <= 0 {
		return errors.New("executor-command validity must be positive")
	}
	payload, err := readBounded(*payloadPath)
	if err != nil {
		return fmt.Errorf("read executor command payload: %w", err)
	}
	if err := validateArbitraryCommandPayload(payload); err != nil {
		return fmt.Errorf("validate executor command payload: %w", err)
	}
	runtimeRef, err := executoruplink.RuntimeRefV2(*tenantID, *nodeID, *instanceID)
	if err != nil {
		return err
	}
	issuedAt := timeNow().UTC()
	statement := admission.CommandStatement{
		SchemaVersion: admission.CommandSchemaV2,
		CommandID:     *commandID, TenantID: *tenantID, NodeID: *nodeID, InstanceID: *instanceID,
		RuntimeRef: runtimeRef, Kind: *kind, ClaimGeneration: *claimGeneration,
		InstanceGeneration: *instanceGeneration, CommandSequence: *commandSequence,
		IssuedAt: issuedAt.Format(time.RFC3339Nano), ExpiresAt: issuedAt.Add(*validFor).Format(time.RFC3339Nano),
		Payload: json.RawMessage(payload),
	}
	if err := statement.Validate(issuedAt); err != nil {
		return err
	}
	privateKey, err := readPrivateKey(*privateKeyPath)
	if err != nil {
		return fmt.Errorf("read executor command private key: %w", err)
	}
	statementRaw, err := json.Marshal(statement)
	if err != nil {
		return err
	}
	envelope, err := dsse.Sign(admission.CommandPayloadType, statementRaw, *keyID, privateKey)
	if err != nil {
		return err
	}
	envelopeRaw, err := dsse.Marshal(envelope)
	if err != nil {
		return err
	}
	if err := writeNewFile(*outputPath, envelopeRaw, 0o600); err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, dsse.Digest(envelopeRaw))
	return err
}

func validateArbitraryCommandPayload(payload []byte) error {
	// Decode through a RawMessage field so the shared strict decoder recursively
	// rejects duplicate keys, excessive nesting, and trailing JSON without
	// imposing one operation's schema on every command kind.
	wrapper := append([]byte(`{"payload":`), payload...)
	wrapper = append(wrapper, '}')
	var decoded struct {
		Payload json.RawMessage `json:"payload"`
	}
	return dsse.DecodeStrictInto(wrapper, maxArtifactBytes, &decoded)
}
