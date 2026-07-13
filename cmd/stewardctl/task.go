package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/connectorledger"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/gateway"
	"github.com/hardrails/steward/internal/securefile"
	"github.com/hardrails/steward/internal/taskpermit"
)

const (
	taskBundleSchemaV2 = "steward.task-bundle.v2"
	maxTaskBundleBytes = 128 << 10
	maxTaskServices    = 128
	maxTaskOperations  = 128
	maxTaskClockSkew   = 5 * time.Minute
)

func (operation serviceTrustOperation) gatewayOperation() gateway.ServiceOperation {
	return gateway.ServiceOperation{
		ServiceID: operation.ServiceID, ID: operation.ID, Method: operation.Method, Path: operation.Path,
		ContentType: operation.ContentType, MaxRequestBytes: operation.MaxRequestBytes,
		MaxResponseBytes: operation.MaxResponseBytes, MaxSeconds: operation.MaxSeconds,
		MaxPermitSeconds: operation.MaxPermitSeconds,
		TaskProtocol:     operation.TaskProtocol, StatusPathPrefix: operation.StatusPathPrefix,
		StatusMaxSeconds: operation.StatusMaxSeconds, PollIntervalSeconds: operation.PollIntervalSeconds,
	}
}

type taskBundleAuthority struct {
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key"`
}

type taskBundle struct {
	SchemaVersion string                `json:"schema_version"`
	ServicePath   string                `json:"service_path"`
	Operation     serviceTrustOperation `json:"operation"`
	Request       string                `json:"request_base64"`
	Permit        string                `json:"permit_base64"`
	Authority     taskBundleAuthority   `json:"authority"`
}

type verifiedTaskBundle struct {
	Bundle   taskBundle
	Request  []byte
	Permit   []byte
	Public   ed25519.PublicKey
	Verified taskpermit.Verified
}

func taskCommand(arguments []string, stdout io.Writer) error {
	if len(arguments) == 0 {
		return errors.New("task command requires issue, verify, audit, submit, status, observe, or wait")
	}
	switch arguments[0] {
	case "issue":
		return issueTask(arguments[1:], stdout)
	case "verify":
		return verifyTask(arguments[1:], stdout)
	case "audit":
		return auditTask(arguments[1:], stdout)
	case "submit":
		return submitTask(arguments[1:], stdout)
	case "status":
		return statusTask(arguments[1:], stdout)
	case "observe":
		return observeTask(arguments[1:], stdout)
	case "wait":
		return waitTask(arguments[1:], stdout)
	default:
		return errors.New("task command requires issue, verify, audit, submit, status, observe, or wait")
	}
}

func issueTask(arguments []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("task issue", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	admissionPath := flags.String("admission", "", "exact Executor admission response JSON")
	intentPath := flags.String("intent", "", "instance intent JSON used for admission")
	trustPath := flags.String("trust", "", "exported Gateway service-trust inventory")
	requestPath := flags.String("request", "", "exact JSON task request")
	operationID := flags.String("operation-id", "", "exact service operation ID")
	taskID := flags.String("task-id", "", "one-use task ID; generated when omitted")
	validFor := flags.Duration("valid-for", 5*time.Minute, "permit validity window")
	clockSkew := flags.Duration("clock-skew", 5*time.Second, "bounded allowance for node clock skew")
	privateKeyPath := flags.String("key", "", "owner-only PEM Ed25519 task-authority private key")
	keyID := flags.String("key-id", "", "admitted task-authority key ID")
	output := flags.String("out", "", "new owner-only task bundle")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *admissionPath == "" || *intentPath == "" || *trustPath == "" || *requestPath == "" ||
		*operationID == "" || *privateKeyPath == "" || *keyID == "" || *output == "" || flags.NArg() != 0 {
		return errors.New("task issue requires -admission, -intent, -trust, -request, -operation-id, -key, -key-id, and -out")
	}
	if *validFor < time.Second || *validFor > taskpermit.MaxValidity || *validFor%time.Second != 0 {
		return fmt.Errorf("task validity must be whole seconds from 1s through %s", taskpermit.MaxValidity)
	}
	if *clockSkew < 0 || *clockSkew > maxTaskClockSkew || *clockSkew%time.Second != 0 {
		return fmt.Errorf("task clock skew must be whole seconds from 0s through %s", maxTaskClockSkew)
	}
	if *clockSkew >= *validFor {
		return errors.New("task clock skew must be shorter than the validity interval")
	}

	admissionRaw, err := securefile.Read(*admissionPath, maxArtifactBytes, securefile.TrustFile)
	if err != nil {
		return fmt.Errorf("read admission response: %w", err)
	}
	var admitted permitAdmission
	if err := dsse.DecodeStrictInto(admissionRaw, maxArtifactBytes, &admitted); err != nil {
		return fmt.Errorf("decode admission response: %w", err)
	}
	intentRaw, err := securefile.Read(*intentPath, maxArtifactBytes, securefile.TrustFile)
	if err != nil {
		return fmt.Errorf("read instance intent: %w", err)
	}
	var intent admission.InstanceIntent
	if err := dsse.DecodeStrictInto(intentRaw, maxArtifactBytes, &intent); err != nil {
		return fmt.Errorf("decode instance intent: %w", err)
	}
	if err := intent.Validate(admission.AuthenticatedIdentity{TenantID: intent.TenantID, NodeID: intent.NodeID}); err != nil {
		return fmt.Errorf("validate instance intent: %w", err)
	}
	if !intent.Capabilities.Service || intent.ServiceID == "" || admitted.ServiceID != intent.ServiceID ||
		admitted.Generation != intent.Generation || admitted.CapsuleDigest != intent.CapsuleDigest ||
		admitted.PolicyDigest == "" || admitted.RoutePolicyDigest == "" || admitted.RuntimeRef == "" ||
		admitted.GrantID != gateway.GrantID(intent.TenantID, intent.InstanceID, intent.Generation) ||
		admitted.ServicePath != "/v1/services/"+admitted.GrantID+"/" ||
		!gateway.TaskAuthoritiesValid(admitted.TaskAuthorities) {
		return errors.New("admission response and instance intent do not bind one task-enabled service")
	}
	privateKey, err := readPrivateKey(*privateKeyPath)
	if err != nil {
		return err
	}
	public := privateKey.Public().(ed25519.PublicKey)
	if !admissionTrustsTaskKey(admitted.TaskAuthorities, *keyID, public) {
		return errors.New("admission response does not bind this task-authority key to the service")
	}
	operation, err := readServiceTrust(*trustPath, intent, *operationID)
	if err != nil {
		return err
	}
	if *validFor > time.Duration(operation.MaxPermitSeconds)*time.Second {
		return fmt.Errorf("task validity %s exceeds service operation maximum %s", *validFor,
			time.Duration(operation.MaxPermitSeconds)*time.Second)
	}
	request, err := securefile.Read(*requestPath, taskpermit.MaxRequestBytes, securefile.TrustFile)
	if err != nil {
		return fmt.Errorf("read exact task request: %w", err)
	}
	if int64(len(request)) > operation.MaxRequestBytes || !validExactTaskJSON(request, int(operation.MaxRequestBytes)) {
		return errors.New("exact task request is empty, oversized, ambiguous, or not one JSON value")
	}
	selectedTaskID := *taskID
	if selectedTaskID == "" {
		selectedTaskID, err = randomTaskID()
		if err != nil {
			return err
		}
	}
	now := timeNow().UTC().Truncate(time.Second)
	notBefore := now.Add(-*clockSkew)
	statement := taskpermit.Statement{
		SchemaVersion: taskpermit.SchemaV1, NodeID: intent.NodeID, TenantID: intent.TenantID,
		InstanceID: intent.InstanceID, RuntimeRef: admitted.RuntimeRef, GrantID: admitted.GrantID,
		Generation: intent.Generation, CapsuleDigest: admitted.CapsuleDigest, PolicyDigest: admitted.PolicyDigest,
		RoutePolicyDigest: admitted.RoutePolicyDigest, ServiceID: intent.ServiceID, OperationID: operation.ID,
		OperationPolicyDigest: operation.PolicyDigest, TaskID: selectedTaskID,
		RequestDigest: taskpermit.RequestDigest(request), RequestBytes: int64(len(request)), ContentType: operation.ContentType,
		NotBefore: notBefore.Format(time.RFC3339), ExpiresAt: notBefore.Add(*validFor).Format(time.RFC3339),
	}
	payload, err := json.Marshal(statement)
	if err != nil {
		return err
	}
	envelope, err := dsse.Sign(taskpermit.PayloadType, payload, *keyID, privateKey)
	if err != nil {
		return err
	}
	permitRaw, err := dsse.Marshal(envelope)
	if err != nil {
		return err
	}
	bundle := taskBundle{
		SchemaVersion: taskBundleSchemaV2, ServicePath: admitted.ServicePath, Operation: operation,
		Request: base64.StdEncoding.EncodeToString(request), Permit: base64.StdEncoding.EncodeToString(permitRaw),
		Authority: taskBundleAuthority{KeyID: *keyID, PublicKey: base64.StdEncoding.EncodeToString(public)},
	}
	bundleRaw, err := json.Marshal(bundle)
	if err != nil {
		return err
	}
	verified, err := decodeTaskBundle(bundleRaw, map[string]ed25519.PublicKey{*keyID: public}, now, taskpermit.MaxValidity)
	if err != nil {
		return fmt.Errorf("self-verify task bundle: %w", err)
	}
	if verified.Verified.Statement != statement || !slices.Equal(verified.Request, request) ||
		!slices.Equal(verified.Permit, permitRaw) {
		return errors.New("self-verified task bundle changed an exact binding")
	}
	bundleRaw = append(bundleRaw, '\n')
	if len(bundleRaw) > maxTaskBundleBytes {
		return fmt.Errorf("task bundle exceeds %d bytes", maxTaskBundleBytes)
	}
	if err := writeNewFile(*output, bundleRaw, 0o600); err != nil {
		return err
	}
	return json.NewEncoder(stdout).Encode(struct {
		BundlePath    string `json:"bundle_path"`
		TaskID        string `json:"task_id"`
		PermitDigest  string `json:"permit_digest"`
		RequestDigest string `json:"request_digest"`
	}{BundlePath: *output, TaskID: selectedTaskID, PermitDigest: verified.Verified.EnvelopeDigest,
		RequestDigest: statement.RequestDigest})
}

func verifyTask(arguments []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("task verify", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	input := flags.String("in", "", "owner-only task bundle")
	publicKeyPath := flags.String("public-key", "", "external base64 Ed25519 task-authority public key")
	keyID := flags.String("key-id", "", "external task-authority key ID")
	requestPath := flags.String("request", "", "optional exact request body to compare")
	maxValidity := flags.Duration("max-validity", taskpermit.MaxValidity, "local maximum permit validity")
	evaluatedAtText := flags.String("at", "", "canonical UTC RFC3339-seconds evaluation time")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *input == "" || *publicKeyPath == "" || *keyID == "" || flags.NArg() != 0 {
		return errors.New("task verify requires -in, -public-key, and -key-id")
	}
	public, err := readPublicKey(*publicKeyPath)
	if err != nil {
		return err
	}
	evaluatedAt, err := permitEvaluationTime(*evaluatedAtText)
	if err != nil {
		return err
	}
	verified, err := readTaskBundle(*input, map[string]ed25519.PublicKey{*keyID: public}, evaluatedAt, *maxValidity)
	if err != nil {
		return err
	}
	if *requestPath != "" {
		request, err := securefile.Read(*requestPath, taskpermit.MaxRequestBytes, securefile.TrustFile)
		if err != nil {
			return err
		}
		if !slices.Equal(request, verified.Request) {
			return errors.New("task bundle does not contain the supplied exact request bytes")
		}
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(struct {
		Valid          bool                  `json:"valid"`
		EvaluatedAt    string                `json:"evaluated_at"`
		KeyID          string                `json:"key_id"`
		EnvelopeDigest string                `json:"envelope_digest"`
		ServicePath    string                `json:"service_path"`
		Operation      serviceTrustOperation `json:"operation"`
		Statement      taskpermit.Statement  `json:"statement"`
	}{Valid: true, EvaluatedAt: evaluatedAt.Format(time.RFC3339), KeyID: verified.Verified.KeyID,
		EnvelopeDigest: verified.Verified.EnvelopeDigest, ServicePath: verified.Bundle.ServicePath,
		Operation: verified.Bundle.Operation, Statement: verified.Verified.Statement})
}

type taskAuditRecord struct {
	SchemaVersion    string                `json:"schema_version"`
	Sequence         uint64                `json:"sequence"`
	ChainHash        string                `json:"chain_hash"`
	TaskSequence     uint64                `json:"task_sequence,omitempty"`
	PreviousTaskHash string                `json:"previous_task_hash,omitempty"`
	ObservedAt       string                `json:"observed_at"`
	Event            connectorledger.Event `json:"event"`
}

func auditTask(arguments []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("task audit", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	input := flags.String("in", "", "owner-only task bundle")
	publicKeyPath := flags.String("public-key", "", "external base64 Ed25519 task-authority public key")
	keyID := flags.String("key-id", "", "external task-authority key ID")
	receiptsPath := flags.String("receipts", "", "signed connector and service-task receipt ledger")
	receiptPublicKeyPath := flags.String("receipt-public-key", "", "base64 Ed25519 receipt public key")
	receiptNodeID := flags.String("receipt-node-id", "", "expected receipt node ID")
	receiptEpoch := flags.Uint64("receipt-epoch", 1, "expected receipt key epoch")
	requestPath := flags.String("request", "", "optional exact request body to compare")
	maxValidity := flags.Duration("max-validity", taskpermit.MaxValidity, "local maximum permit validity")
	expectedSequence := flags.String("expected-sequence", "", "externally retained final receipt sequence")
	expectedChainHash := flags.String("expected-chain-hash", "", "externally retained sha256 receipt chain hash")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *input == "" || *publicKeyPath == "" || *keyID == "" || *receiptsPath == "" ||
		*receiptPublicKeyPath == "" || *receiptNodeID == "" || flags.NArg() != 0 {
		return errors.New("task audit requires -in, -public-key, -key-id, -receipts, -receipt-public-key, and -receipt-node-id")
	}
	public, err := readPublicKey(*publicKeyPath)
	if err != nil {
		return err
	}
	bundle, err := readTaskBundleForAudit(*input, map[string]ed25519.PublicKey{*keyID: public}, *maxValidity)
	if err != nil {
		return err
	}
	if *requestPath != "" {
		request, err := securefile.Read(*requestPath, taskpermit.MaxRequestBytes, securefile.TrustFile)
		if err != nil {
			return err
		}
		if !slices.Equal(request, bundle.Request) {
			return errors.New("task bundle does not contain the supplied exact request bytes")
		}
	}
	receiptPublic, err := readPublicKey(*receiptPublicKeyPath)
	if err != nil {
		return err
	}
	statement := bundle.Verified.Statement
	if *receiptNodeID != gateway.ServiceTaskReceiptNodeID(statement.NodeID) {
		return errors.New("receipt node ID does not match the task permit node")
	}
	expectedTaskDigest := taskpermit.TaskDigest(statement.TenantID, statement.InstanceID, statement.TaskID)
	var authorization, dispatch, terminal *taskAuditRecord
	var matchedTaskSequence uint64
	previousTaskHash := "sha256:" + strings.Repeat("0", 64)
	head, err := connectorledger.VerifyRecords(*receiptsPath, receiptPublic, *receiptNodeID, *receiptEpoch,
		func(record connectorledger.VerifiedReceipt) error {
			event := record.Receipt.Event
			if event.PermitDigest != bundle.Verified.EnvelopeDigest || event.TaskDigest != expectedTaskDigest {
				return nil
			}
			if err := checkTaskReceiptBindings(statement, bundle.Verified.KeyID, bundle.Verified.EnvelopeDigest,
				bundle.Bundle.Operation.TaskProtocol, event); err != nil {
				return fmt.Errorf("service-task receipt sequence %d: %w", record.Receipt.Sequence, err)
			}
			matchedTaskSequence++
			if record.Receipt.SchemaVersion != connectorledger.SchemaV4 ||
				record.Receipt.TaskSequence != matchedTaskSequence || record.Receipt.PreviousTaskHash != previousTaskHash {
				return fmt.Errorf("service-task receipt sequence %d has an invalid task-local chain coordinate", record.Receipt.Sequence)
			}
			previousTaskHash = record.Hash
			matched := &taskAuditRecord{
				SchemaVersion: record.Receipt.SchemaVersion, Sequence: record.Receipt.Sequence, ChainHash: record.Hash,
				TaskSequence: record.Receipt.TaskSequence, PreviousTaskHash: record.Receipt.PreviousTaskHash,
				ObservedAt: record.Receipt.ObservedAt, Event: event,
			}
			switch event.Phase {
			case connectorledger.Authorize:
				if authorization != nil || dispatch != nil || terminal != nil {
					return errors.New("receipt chain contains multiple authorizations for the task permit")
				}
				authorization = matched
			case connectorledger.Dispatch:
				if authorization == nil || dispatch != nil || terminal != nil {
					return errors.New("receipt chain contains an invalid dispatch for the task permit")
				}
				dispatch = matched
			case connectorledger.Terminal:
				if authorization == nil || terminal != nil {
					return errors.New("receipt chain contains an invalid terminal record for the task permit")
				}
				terminal = matched
			default:
				return errors.New("receipt correlates a task permit with an unsupported event phase")
			}
			return nil
		})
	if err != nil {
		return err
	}
	if err := checkExpectedConnectorHead(head, *expectedSequence, *expectedChainHash); err != nil {
		return err
	}
	if authorization == nil {
		return errors.New("receipt chain has no authorization for the exact task permit")
	}
	authorizedAt, err := time.Parse(time.RFC3339Nano, authorization.ObservedAt)
	if err != nil {
		return errors.New("task authorization has an invalid observation time")
	}
	if _, err := decodeTaskBundleRaw(bundleRaw(bundle.Bundle), map[string]ed25519.PublicKey{*keyID: public},
		authorizedAt, *maxValidity); err != nil {
		return fmt.Errorf("task permit was not valid at service authorization time: %w", err)
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(struct {
		Valid         bool                 `json:"valid"`
		PermitDigest  string               `json:"permit_digest"`
		RequestDigest string               `json:"request_digest"`
		PermitKeyID   string               `json:"permit_key_id"`
		Statement     taskpermit.Statement `json:"statement"`
		Authorization *taskAuditRecord     `json:"authorization"`
		Dispatch      *taskAuditRecord     `json:"dispatch,omitempty"`
		Terminal      *taskAuditRecord     `json:"terminal"`
		Head          connectorledger.Head `json:"head"`
	}{Valid: true, PermitDigest: bundle.Verified.EnvelopeDigest, RequestDigest: statement.RequestDigest,
		PermitKeyID: bundle.Verified.KeyID, Statement: statement, Authorization: authorization,
		Dispatch: dispatch, Terminal: terminal, Head: head})
}

func checkTaskReceiptBindings(
	statement taskpermit.Statement,
	authorityKeyID, permitDigest, taskProtocol string,
	event connectorledger.Event,
) error {
	if event.Kind != connectorledger.ServiceTask || event.TenantID != statement.TenantID ||
		event.RuntimeRef != statement.RuntimeRef || event.CapsuleDigest != statement.CapsuleDigest ||
		event.PolicyDigest != statement.PolicyDigest || event.RoutePolicyDigest != statement.RoutePolicyDigest ||
		event.Generation != statement.Generation || event.GrantID != statement.GrantID || event.ConnectorID != "" ||
		event.ServiceID != statement.ServiceID || event.OperationID != statement.OperationID ||
		event.OperationPolicyDigest != statement.OperationPolicyDigest ||
		event.TaskDigest != taskpermit.TaskDigest(statement.TenantID, statement.InstanceID, statement.TaskID) ||
		event.AuthorityKeyID != authorityKeyID || event.PermitDigest != permitDigest ||
		event.RequestDigest != statement.RequestDigest || event.RequestBytes != statement.RequestBytes ||
		event.TaskProtocol != taskProtocol {
		return errors.New("service-task receipt does not match every task-permit binding")
	}
	return nil
}

func admissionTrustsTaskKey(authorities []gateway.TaskAuthority, keyID string, public ed25519.PublicKey) bool {
	want := base64.StdEncoding.EncodeToString(public)
	for _, authority := range authorities {
		if authority.KeyID == keyID && authority.PublicKey == want {
			return true
		}
	}
	return false
}

func readServiceTrust(path string, intent admission.InstanceIntent, operationID string) (serviceTrustOperation, error) {
	raw, err := securefile.Read(path, maxServiceTrustBytes, securefile.TrustFile)
	if err != nil {
		return serviceTrustOperation{}, fmt.Errorf("read service trust inventory: %w", err)
	}
	var inventory serviceTrustInventory
	if err := dsse.DecodeStrictInto(raw, maxServiceTrustBytes, &inventory); err != nil {
		return serviceTrustOperation{}, fmt.Errorf("decode service trust inventory: %w", err)
	}
	if inventory.SchemaVersion != serviceTrustSchemaV2 || inventory.NodeID != intent.NodeID ||
		inventory.TenantID != intent.TenantID || len(inventory.Services) == 0 || len(inventory.Services) > maxTaskServices {
		return serviceTrustOperation{}, errors.New("service trust inventory does not match the instance node and tenant")
	}
	var selected *serviceTrustOperation
	totalOperations := 0
	for serviceIndex, service := range inventory.Services {
		if !taskIdentifier(service.ServiceID) || len(service.Operations) == 0 || len(service.Operations) > maxTaskOperations ||
			serviceIndex > 0 && inventory.Services[serviceIndex-1].ServiceID >= service.ServiceID {
			return serviceTrustOperation{}, errors.New("service trust inventory services must be non-empty, unique, and sorted")
		}
		totalOperations += len(service.Operations)
		if totalOperations > maxTaskOperations {
			return serviceTrustOperation{}, fmt.Errorf("service trust inventory permits at most %d total operations", maxTaskOperations)
		}
		paths := make(map[string]struct{}, len(service.Operations))
		for operationIndex, operation := range service.Operations {
			if operation.ServiceID != service.ServiceID || !validTrustedServiceOperation(operation) ||
				operationIndex > 0 && service.Operations[operationIndex-1].ID >= operation.ID {
				return serviceTrustOperation{}, errors.New("service trust inventory operations are invalid or not uniquely sorted")
			}
			methodPath := operation.Method + "\x00" + operation.Path
			if _, duplicate := paths[methodPath]; duplicate {
				return serviceTrustOperation{}, errors.New("service trust inventory maps one method and path to multiple operations")
			}
			paths[methodPath] = struct{}{}
			if service.ServiceID == intent.ServiceID && operation.ID == operationID {
				copy := operation
				selected = &copy
			}
		}
	}
	if selected == nil {
		return serviceTrustOperation{}, errors.New("service trust inventory does not contain the admitted service operation")
	}
	return *selected, nil
}

func validTrustedServiceOperation(operation serviceTrustOperation) bool {
	gatewayOperation := operation.gatewayOperation()
	return gateway.ValidateServiceOperation(gatewayOperation) == nil &&
		operation.PolicyDigest == gateway.ServiceOperationDigest(gatewayOperation)
}

func taskIdentifier(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for index, character := range value {
		if character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' ||
			character >= '0' && character <= '9' || index > 0 && (character == '.' || character == '_' || character == '-') {
			continue
		}
		return false
	}
	return true
}

func randomTaskID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", fmt.Errorf("generate task ID: %w", err)
	}
	return "task-" + hex.EncodeToString(value[:]), nil
}

func validExactTaskJSON(raw []byte, limit int) bool {
	if len(raw) == 0 || len(raw) > limit {
		return false
	}
	wrapper := make([]byte, 0, len(raw)+10)
	wrapper = append(wrapper, `{"value":`...)
	wrapper = append(wrapper, raw...)
	wrapper = append(wrapper, '}')
	var decoded struct {
		Value json.RawMessage `json:"value"`
	}
	return dsse.DecodeStrictInto(wrapper, limit+10, &decoded) == nil
}

func readTaskBundle(path string, trusted map[string]ed25519.PublicKey, at time.Time, maxValidity time.Duration) (verifiedTaskBundle, error) {
	raw, err := securefile.Read(path, maxTaskBundleBytes, securefile.OwnerOnly)
	if err != nil {
		return verifiedTaskBundle{}, fmt.Errorf("read task bundle: %w", err)
	}
	return decodeTaskBundle(raw, trusted, at, maxValidity)
}

func readTaskBundleForAudit(path string, trusted map[string]ed25519.PublicKey, maxValidity time.Duration) (verifiedTaskBundle, error) {
	raw, err := securefile.Read(path, maxTaskBundleBytes, securefile.OwnerOnly)
	if err != nil {
		return verifiedTaskBundle{}, fmt.Errorf("read task bundle: %w", err)
	}
	var wire taskBundle
	if err := dsse.DecodeStrictInto(raw, maxTaskBundleBytes, &wire); err != nil {
		return verifiedTaskBundle{}, fmt.Errorf("decode task bundle: %w", err)
	}
	permitRaw, err := decodeCanonicalBase64(wire.Permit, taskpermit.MaxEnvelopeBytes, "task permit")
	if err != nil {
		return verifiedTaskBundle{}, err
	}
	payload, _, err := dsse.Verify(permitRaw, taskpermit.PayloadType, trusted)
	if err != nil {
		return verifiedTaskBundle{}, err
	}
	var statement taskpermit.Statement
	if err := dsse.DecodeStrictInto(payload, taskpermit.MaxEnvelopeBytes, &statement); err != nil {
		return verifiedTaskBundle{}, fmt.Errorf("decode signed task permit: %w", err)
	}
	notBefore, err := parsePermitTime(statement.NotBefore)
	if err != nil {
		return verifiedTaskBundle{}, fmt.Errorf("task permit not_before: %w", err)
	}
	return decodeTaskBundle(raw, trusted, notBefore, maxValidity)
}

func decodeTaskBundle(raw []byte, trusted map[string]ed25519.PublicKey, at time.Time, maxValidity time.Duration) (verifiedTaskBundle, error) {
	var bundle taskBundle
	if err := dsse.DecodeStrictInto(raw, maxTaskBundleBytes, &bundle); err != nil {
		return verifiedTaskBundle{}, fmt.Errorf("decode task bundle: %w", err)
	}
	return decodeTaskBundleValue(bundle, trusted, at, maxValidity)
}

func decodeTaskBundleRaw(raw []byte, trusted map[string]ed25519.PublicKey, at time.Time, maxValidity time.Duration) (verifiedTaskBundle, error) {
	return decodeTaskBundle(raw, trusted, at, maxValidity)
}

func decodeTaskBundleValue(bundle taskBundle, trusted map[string]ed25519.PublicKey, at time.Time, maxValidity time.Duration) (verifiedTaskBundle, error) {
	if bundle.SchemaVersion != taskBundleSchemaV2 ||
		bundle.Operation.TaskProtocol != connectorledger.TaskProtocolLifecycleV1 || !validTrustedServiceOperation(bundle.Operation) {
		return verifiedTaskBundle{}, errors.New("task bundle has an unsupported schema or invalid service operation")
	}
	publicRaw, err := decodeCanonicalBase64(bundle.Authority.PublicKey, ed25519.PublicKeySize, "task authority public key")
	if err != nil || len(publicRaw) != ed25519.PublicKeySize {
		return verifiedTaskBundle{}, errors.New("task bundle authority is not canonical base64 Ed25519")
	}
	public := ed25519.PublicKey(publicRaw)
	trustedPublic, ok := trusted[bundle.Authority.KeyID]
	if !ok || !slices.Equal(trustedPublic, public) || len(trusted) != 1 {
		return verifiedTaskBundle{}, errors.New("task bundle authority does not match the external trust anchor")
	}
	request, err := decodeCanonicalBase64(bundle.Request, int(taskpermit.MaxRequestBytes), "task request")
	if err != nil || int64(len(request)) > bundle.Operation.MaxRequestBytes ||
		!validExactTaskJSON(request, int(bundle.Operation.MaxRequestBytes)) {
		return verifiedTaskBundle{}, errors.New("task bundle request is not exact bounded JSON")
	}
	permitRaw, err := decodeCanonicalBase64(bundle.Permit, taskpermit.MaxEnvelopeBytes, "task permit")
	if err != nil {
		return verifiedTaskBundle{}, err
	}
	if maxValidity <= 0 || maxValidity > taskpermit.MaxValidity {
		return verifiedTaskBundle{}, fmt.Errorf("maximum task validity must be positive and at most %s", taskpermit.MaxValidity)
	}
	operationValidity := time.Duration(bundle.Operation.MaxPermitSeconds) * time.Second
	if maxValidity > operationValidity {
		maxValidity = operationValidity
	}
	verified, err := taskpermit.Verify(permitRaw, trusted, at, maxValidity)
	if err != nil {
		return verifiedTaskBundle{}, err
	}
	statement := verified.Statement
	if verified.KeyID != bundle.Authority.KeyID ||
		statement.GrantID != gateway.GrantID(statement.TenantID, statement.InstanceID, statement.Generation) ||
		bundle.ServicePath != "/v1/services/"+statement.GrantID+"/" ||
		statement.ServiceID != bundle.Operation.ServiceID || statement.OperationID != bundle.Operation.ID ||
		statement.OperationPolicyDigest != bundle.Operation.PolicyDigest || statement.ContentType != bundle.Operation.ContentType ||
		statement.RequestDigest != taskpermit.RequestDigest(request) || statement.RequestBytes != int64(len(request)) {
		return verifiedTaskBundle{}, errors.New("task bundle transport does not match every signed permit binding")
	}
	return verifiedTaskBundle{Bundle: bundle, Request: request, Permit: permitRaw, Public: public, Verified: verified}, nil
}

func decodeCanonicalBase64(value string, maximum int, field string) ([]byte, error) {
	if value == "" || len(value) > base64.StdEncoding.EncodedLen(maximum) {
		return nil, fmt.Errorf("%s is empty or oversized", field)
	}
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(raw) == 0 || len(raw) > maximum || base64.StdEncoding.EncodeToString(raw) != value {
		return nil, fmt.Errorf("%s is not canonical base64", field)
	}
	return raw, nil
}

func bundleRaw(bundle taskBundle) []byte {
	raw, _ := json.Marshal(bundle)
	return raw
}
