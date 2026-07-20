package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/executoruplink"
)

const defaultExecutorCommandValidity = 5 * time.Minute
const defaultExecutorDelegationValidity = time.Hour

func executorCommand(arguments []string, stdout io.Writer) error {
	if len(arguments) == 0 {
		return errors.New("executor-command requires issue, verify, or delegation")
	}
	switch arguments[0] {
	case "issue":
		return issueExecutorCommand(arguments[1:], stdout)
	case "verify":
		return verifyArtifact(arguments[1:], stdout, admission.CommandPayloadType)
	case "delegation":
		return executorCommandDelegation(arguments[1:], stdout)
	default:
		return errors.New("executor-command requires issue, verify, or delegation")
	}
}

func issueExecutorCommand(arguments []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("executor-command issue", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	commandID := flags.String("command-id", "", "unique signed command identity")
	tenantID := flags.String("tenant-id", "", "tenant identity")
	nodeID := flags.String("node-id", "", "destination node identity")
	instanceID := flags.String("instance-id", "", "destination instance identity")
	kind := flags.String("kind", "", "admit, renew, start, stop, destroy, read, purge, snapshot-state, clone-state, delete-snapshot, or activation-canary")
	claimGeneration := flags.Uint64("claim-generation", 1, "signed authorization generation")
	instanceGeneration := flags.Uint64("instance-generation", 0, "instance lineage generation")
	commandSequence := flags.Uint64("sequence", 0, "monotonic instance command sequence")
	validFor := flags.Duration("valid-for", defaultExecutorCommandValidity, "signed command lifetime")
	payloadPath := flags.String("payload", "", "bounded JSON operation payload")
	privateKeyPath := flags.String("key", "", "PEM Ed25519 command private key")
	keyID := flags.String("key-id", "", "command signing key ID")
	delegationPath := flags.String("delegation", "", "optional tenant-signed controller delegation")
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
	var delegation admission.CommandDelegation
	if *delegationPath != "" {
		delegationRaw, err := readBounded(*delegationPath)
		if err != nil {
			return fmt.Errorf("read executor command delegation: %w", err)
		}
		delegation, err = decodeUnverifiedCommandDelegation(delegationRaw)
		if err != nil {
			return err
		}
		statement.AuthorizationContextDigest = dsse.Digest(delegationRaw)
		statement.DelegationDSSEBase64 = base64.StdEncoding.EncodeToString(delegationRaw)
	}
	privateKey, err := readPrivateKey(*privateKeyPath)
	if err != nil {
		return fmt.Errorf("read executor command private key: %w", err)
	}
	if *delegationPath != "" {
		controllerPublic, err := base64.StdEncoding.DecodeString(delegation.ControllerPublicKey)
		if err != nil || !ed25519.PublicKey(controllerPublic).Equal(privateKey.Public()) ||
			delegation.ControllerKeyID != *keyID {
			return errors.New("executor command key does not match the embedded controller delegation")
		}
	}
	if err := statement.Validate(issuedAt); err != nil {
		return err
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

func executorCommandDelegation(arguments []string, stdout io.Writer) error {
	if len(arguments) == 0 {
		return errors.New("executor-command delegation requires issue or verify")
	}
	switch arguments[0] {
	case "issue":
		return issueExecutorCommandDelegation(arguments[1:], stdout)
	case "verify":
		return verifyArtifact(arguments[1:], stdout, admission.CommandDelegationPayloadType)
	default:
		return errors.New("executor-command delegation requires issue or verify")
	}
}

func issueExecutorCommandDelegation(arguments []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("executor-command delegation issue", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	delegationID := flags.String("delegation-id", "", "unique delegation identity")
	tenantID := flags.String("tenant-id", "", "tenant identity")
	controllerPublicPath := flags.String("controller-public-key", "", "controller Ed25519 public key")
	controllerKeyID := flags.String("controller-key-id", "", "controller signing key ID")
	operationsValue := flags.String("operations", "", "comma-separated delegated operations")
	nodeIDsValue := flags.String("node-ids", "", "comma-separated eligible node identities")
	instancesPath := flags.String("instances", "", "JSON object containing exact delegated instances")
	claimGeneration := flags.Uint64("claim-generation", 1, "signed authorization generation")
	admissionPath := flags.String("admission-template", "", "optional exact admission template JSON")
	validFor := flags.Duration("valid-for", defaultExecutorDelegationValidity, "delegation lifetime")
	privateKeyPath := flags.String("key", "", "tenant PEM Ed25519 command private key")
	keyID := flags.String("key-id", "", "tenant command signing key ID")
	outputPath := flags.String("out", "", "new owner-only DSSE delegation file")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *delegationID == "" || *tenantID == "" || *controllerPublicPath == "" ||
		*controllerKeyID == "" || *operationsValue == "" || *nodeIDsValue == "" ||
		*instancesPath == "" || *claimGeneration == 0 || *privateKeyPath == "" ||
		*keyID == "" || *outputPath == "" || flags.NArg() != 0 {
		return errors.New("delegation issue requires delegation, tenant, controller key, operations, nodes, instances, claim generation, tenant key, key-id, and output")
	}
	operations, err := canonicalCommandDelegationList(*operationsValue)
	if err != nil {
		return fmt.Errorf("parse delegation operations: %w", err)
	}
	nodeIDs, err := canonicalCommandDelegationList(*nodeIDsValue)
	if err != nil {
		return fmt.Errorf("parse delegation node IDs: %w", err)
	}
	instancesRaw, err := readBounded(*instancesPath)
	if err != nil {
		return fmt.Errorf("read delegation instances: %w", err)
	}
	var instancesDocument struct {
		Instances []admission.CommandDelegationInstance `json:"instances"`
	}
	if err := dsse.DecodeStrictInto(instancesRaw, maxArtifactBytes, &instancesDocument); err != nil {
		return fmt.Errorf("decode delegation instances: %w", err)
	}
	instances := instancesDocument.Instances
	slices.SortFunc(instances, func(left, right admission.CommandDelegationInstance) int {
		return strings.Compare(left.InstanceID, right.InstanceID)
	})
	var admissionTemplate *admission.CommandDelegationAdmissionTemplate
	if *admissionPath != "" {
		raw, err := readBounded(*admissionPath)
		if err != nil {
			return fmt.Errorf("read delegation admission template: %w", err)
		}
		var decoded admission.CommandDelegationAdmissionTemplate
		if err := dsse.DecodeStrictInto(raw, maxArtifactBytes, &decoded); err != nil {
			return fmt.Errorf("decode delegation admission template: %w", err)
		}
		admissionTemplate = &decoded
	}
	controllerPublic, err := readPublicKey(*controllerPublicPath)
	if err != nil {
		return fmt.Errorf("read controller public key: %w", err)
	}
	issuedAt := timeNow().UTC()
	statement := admission.CommandDelegation{
		SchemaVersion: admission.CommandDelegationSchemaV1,
		DelegationID:  *delegationID, TenantID: *tenantID,
		ControllerKeyID:     *controllerKeyID,
		ControllerPublicKey: base64.StdEncoding.EncodeToString(controllerPublic),
		Operations:          operations, NodeIDs: nodeIDs, Instances: instances,
		ClaimGeneration: *claimGeneration, Admission: admissionTemplate,
		IssuedAt:  issuedAt.Format(time.RFC3339Nano),
		ExpiresAt: issuedAt.Add(*validFor).Format(time.RFC3339Nano),
	}
	payload, err := admission.MarshalCommandDelegation(statement)
	if err != nil {
		return err
	}
	privateKey, err := readPrivateKey(*privateKeyPath)
	if err != nil {
		return fmt.Errorf("read tenant command private key: %w", err)
	}
	envelope, err := dsse.Sign(admission.CommandDelegationPayloadType, payload, *keyID, privateKey)
	if err != nil {
		return err
	}
	raw, err := dsse.Marshal(envelope)
	if err != nil {
		return err
	}
	if err := writeNewFile(*outputPath, raw, 0o600); err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, dsse.Digest(raw))
	return err
}

func canonicalCommandDelegationList(value string) ([]string, error) {
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, errors.New("list contains an empty value")
		}
		result = append(result, part)
	}
	slices.Sort(result)
	if len(slices.Compact(result)) != len(result) {
		return nil, errors.New("list contains a duplicate value")
	}
	return result, nil
}

func decodeUnverifiedCommandDelegation(raw []byte) (admission.CommandDelegation, error) {
	envelope, err := dsse.Parse(raw)
	if err != nil || envelope.PayloadType != admission.CommandDelegationPayloadType {
		return admission.CommandDelegation{}, errors.New("executor command delegation is not a typed DSSE envelope")
	}
	payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		return admission.CommandDelegation{}, errors.New("decode executor command delegation payload")
	}
	var statement admission.CommandDelegation
	if err := dsse.DecodeStrictInto(payload, maxArtifactBytes, &statement); err != nil {
		return admission.CommandDelegation{}, fmt.Errorf("decode executor command delegation: %w", err)
	}
	if err := statement.Validate(timeNow().UTC()); err != nil {
		return admission.CommandDelegation{}, err
	}
	return statement, nil
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
