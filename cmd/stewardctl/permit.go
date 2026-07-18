package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/hardrails/steward/internal/actionpermit"
	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/connectorledger"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/gateway"
	"github.com/hardrails/steward/internal/influence"
	"github.com/hardrails/steward/internal/securefile"
)

const (
	maxPermitRequestBytes = 4 << 20
	maxPermitClockSkew    = 5 * time.Minute
)

type permitAdmission struct {
	RuntimeRef              string                         `json:"runtime_ref"`
	Status                  string                         `json:"status"`
	CapsuleDigest           string                         `json:"capsule_digest"`
	PolicyDigest            string                         `json:"policy_digest"`
	Generation              uint64                         `json:"generation"`
	EvidenceKeyID           string                         `json:"evidence_key_id"`
	GrantID                 string                         `json:"grant_id,omitempty"`
	ServicePath             string                         `json:"service_path,omitempty"`
	ServiceID               string                         `json:"service_id,omitempty"`
	TaskAuthorities         []gateway.TaskAuthority        `json:"task_authorities,omitempty"`
	EgressProxy             string                         `json:"egress_proxy,omitempty"`
	EgressRouteIDs          []string                       `json:"egress_route_ids,omitempty"`
	ConnectorURL            string                         `json:"connector_url,omitempty"`
	ConnectorIDs            []string                       `json:"connector_ids,omitempty"`
	RoutePolicyDigest       string                         `json:"route_policy_digest,omitempty"`
	EffectMode              string                         `json:"effect_mode,omitempty"`
	ActionApprovalThreshold int                            `json:"action_approval_threshold,omitempty"`
	ActionContextRequired   bool                           `json:"action_context_required,omitempty"`
	ActionAuthorities       []gateway.GrantActionAuthority `json:"action_authorities,omitempty"`
}

func permitCommand(arguments []string, stdout, stderr io.Writer) error {
	if len(arguments) == 0 {
		return errors.New("permit command requires context, bundle, issue, approve, verify, or audit")
	}
	switch arguments[0] {
	case "context":
		return permitContextCommand(arguments[1:], stdout)
	case "bundle":
		return permitBundleCommand(arguments[1:], stdout, stderr)
	case "issue":
		return issuePermit(arguments[1:], stdout, stderr)
	case "approve":
		return approvePermit(arguments[1:], stdout, stderr)
	case "verify":
		return verifyPermit(arguments[1:], stdout)
	case "audit":
		return auditPermit(arguments[1:], stdout)
	default:
		return errors.New("permit command requires context, bundle, issue, approve, verify, or audit")
	}
}

func permitContextCommand(arguments []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("permit context", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	admissionPath := flags.String("admission", "", "Executor admission response JSON")
	intentPath := flags.String("intent", "", "instance intent JSON used for admission")
	receiptsPath := flags.String("receipts", "", "signed connector receipt ledger")
	receiptPublicKeyPath := flags.String("receipt-public-key", "", "base64 Ed25519 connector receipt public key")
	receiptNodeID := flags.String("receipt-node-id", "", "expected connector receipt node ID")
	receiptEpoch := flags.Uint64("receipt-epoch", 1, "expected connector receipt key epoch")
	expectedSequence := flags.String("expected-sequence", "", "externally retained final receipt sequence")
	expectedChainHash := flags.String("expected-chain-hash", "", "externally retained final receipt chain hash")
	output := flags.String("out", "", "new verified effect-context JSON output")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *admissionPath == "" || *intentPath == "" || *receiptsPath == "" || *receiptPublicKeyPath == "" ||
		*receiptNodeID == "" || *receiptEpoch == 0 || *output == "" || flags.NArg() != 0 {
		return errors.New("permit context requires -admission, -intent, -receipts, -receipt-public-key, -receipt-node-id, and -out")
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
		return err
	}
	grantID := gateway.GrantID(intent.TenantID, intent.InstanceID, intent.Generation)
	if !admitted.ActionContextRequired || admitted.EffectMode != admission.EffectModeAuthorized ||
		intent.EffectMode != admission.EffectModeAuthorized || admitted.Generation != intent.Generation ||
		admitted.CapsuleDigest != intent.CapsuleDigest || admitted.PolicyDigest == "" || admitted.RoutePolicyDigest == "" ||
		admitted.GrantID != grantID {
		return errors.New("admission response and instance intent do not identify one context-locked grant")
	}
	receiptPublic, err := readPublicKey(*receiptPublicKeyPath)
	if err != nil {
		return err
	}
	current, err := influence.Genesis(intent.TenantID, grantID, intent.Generation)
	if err != nil {
		return err
	}
	pending := make(map[string]struct{})
	ledgerHead, err := connectorledger.VerifyRecords(
		*receiptsPath, receiptPublic, *receiptNodeID, *receiptEpoch,
		func(record connectorledger.VerifiedReceipt) error {
			event := record.Receipt.Event
			if event.Kind != connectorledger.ConnectorCall || event.GrantID != grantID || event.Phase == connectorledger.Deny {
				return nil
			}
			if event.TenantID != intent.TenantID || event.Generation != intent.Generation || event.InfluenceHash == "" ||
				event.InfluenceSequence != current.Sequence || event.InfluenceHash != current.ChainHash {
				return fmt.Errorf("receipt sequence %d does not continue the admitted grant's effect context", record.Receipt.Sequence)
			}
			switch event.Phase {
			case connectorledger.Authorize:
				if len(pending) != 0 {
					return errors.New("context-locked grant has overlapping connector authorizations")
				}
				pending[event.TaskDigest] = struct{}{}
			case connectorledger.Terminal:
				if _, ok := pending[event.TaskDigest]; !ok {
					return errors.New("context-locked terminal receipt has no matching authorization")
				}
				delete(pending, event.TaskDigest)
				next, err := influence.Advance(current, record.Hash)
				if err != nil {
					return err
				}
				current = next
			default:
				return errors.New("context-locked connector receipt has an unsupported phase")
			}
			return nil
		},
	)
	if err != nil {
		return fmt.Errorf("verify effect-context receipts: %w", err)
	}
	if err := checkExpectedConnectorHead(ledgerHead, *expectedSequence, *expectedChainHash); err != nil {
		return err
	}
	if len(pending) != 0 {
		return errors.New("context-locked grant has an in-flight connector call; wait for a terminal receipt")
	}
	raw, err := json.Marshal(current)
	if err != nil {
		return err
	}
	if err := writePermitOutputs([]permitOutput{{path: *output, contents: append(raw, '\n')}}); err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, current.ChainHash)
	return err
}

func issuePermit(arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("permit issue", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	admissionPath := flags.String("admission", "", "Executor admission response JSON")
	intentPath := flags.String("intent", "", "instance intent JSON used for admission")
	trustPath := flags.String("trust", "", "exported Gateway action-trust inventory")
	requestPath := flags.String("request", "", "exact connector request body; omit only for an empty body")
	contextPath := flags.String("context", "", "verified current effect-context JSON")
	connectorID := flags.String("connector-id", "", "admitted connector ID")
	operationID := flags.String("operation-id", "", "exact connector operation ID")
	taskID := flags.String("task-id", "", "one-use task ID")
	validFor := flags.Duration("valid-for", 5*time.Minute, "permit validity window")
	clockSkew := flags.Duration("clock-skew", 5*time.Second, "bounded allowance for node clock skew")
	privateKeyPath := flags.String("key", "", "PEM Ed25519 action-authority private key")
	keyID := flags.String("key-id", "", "configured action-authority key ID")
	output := flags.String("out", "", "new DSSE permit output")
	headerOutput := flags.String("header-out", "", "optional new file containing the HTTP header value")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *admissionPath == "" || *intentPath == "" || *trustPath == "" || *connectorID == "" || *operationID == "" || *taskID == "" ||
		*privateKeyPath == "" || *keyID == "" || *output == "" || flags.NArg() != 0 {
		return errors.New("permit issue requires -admission, -intent, -trust, -connector-id, -operation-id, -task-id, -key, -key-id, and -out")
	}
	if *validFor < time.Second || *validFor > actionpermit.MaxValidity || *validFor%time.Second != 0 {
		return fmt.Errorf("permit validity must be whole seconds from 1s through %s", actionpermit.MaxValidity)
	}
	if *clockSkew < 0 || *clockSkew > maxPermitClockSkew || *clockSkew%time.Second != 0 {
		return fmt.Errorf("permit clock skew must be whole seconds from 0s through %s", maxPermitClockSkew)
	}
	if *clockSkew >= *validFor {
		return errors.New("permit clock skew must be shorter than the validity interval")
	}
	if *headerOutput != "" && *headerOutput == *output {
		return errors.New("permit and header outputs must be different files")
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
		return err
	}
	if admitted.EffectMode != intent.EffectMode {
		return errors.New("admission response effect mode does not match the instance intent")
	}
	if admitted.ActionContextRequired && *contextPath == "" {
		return errors.New("context-locked admission requires -context from stewardctl permit context")
	}
	if !admitted.ActionContextRequired && *contextPath != "" {
		return errors.New("-context is valid only when the admission requires context-locked effects")
	}
	approvalThreshold := admitted.ActionApprovalThreshold
	if intent.EffectMode == admission.EffectModeAuthorized && approvalThreshold == 0 {
		approvalThreshold = 1
	}
	if intent.EffectMode == admission.EffectModeAuthorized &&
		(approvalThreshold < 1 || (approvalThreshold > 1 && approvalThreshold > len(admitted.ActionAuthorities))) {
		return errors.New("admission response contains an invalid action approval threshold")
	}
	if admitted.Generation != intent.Generation || admitted.CapsuleDigest != intent.CapsuleDigest ||
		admitted.PolicyDigest == "" || admitted.RoutePolicyDigest == "" || admitted.GrantID == "" ||
		admitted.GrantID != gateway.GrantID(intent.TenantID, intent.InstanceID, intent.Generation) ||
		!slices.Contains(admitted.ConnectorIDs, *connectorID) || !slices.Contains(intent.ConnectorIDs, *connectorID) {
		return errors.New("admission response and instance intent do not bind the requested connector authority")
	}
	privateKey, err := readPrivateKey(*privateKeyPath)
	if err != nil {
		return err
	}
	public, ok := privateKey.Public().(ed25519.PublicKey)
	if !ok {
		return errors.New("action-authority private key does not contain an Ed25519 public key")
	}
	if approvalThreshold > 1 {
		admittedSigner := false
		for _, authority := range admitted.ActionAuthorities {
			decoded, decodeErr := base64.StdEncoding.DecodeString(authority.PublicKey)
			if authority.KeyID == *keyID && decodeErr == nil &&
				base64.StdEncoding.EncodeToString(decoded) == authority.PublicKey && ed25519.PublicKey(decoded).Equal(public) &&
				slices.Contains(authority.ConnectorIDs, *connectorID) {
				admittedSigner = true
				break
			}
		}
		if !admittedSigner {
			return errors.New("first approval key does not match the admitted connector authority")
		}
	}
	trustedOperation, err := validateActionTrust(*trustPath, intent, *connectorID, *operationID, *keyID, public, *validFor)
	if err != nil {
		return err
	}

	var request []byte
	if *requestPath != "" {
		if trustedOperation.ContentType == "" {
			return errors.New("the trusted connector operation does not accept a request body")
		}
		request, err = securefile.Read(*requestPath, maxPermitRequestBytes, securefile.TrustFile)
		if err != nil {
			return fmt.Errorf("read exact connector request: %w", err)
		}
		if err := validatePermitRequest(request); err != nil {
			return err
		}
	} else if trustedOperation.ContentType != "" {
		return errors.New("the trusted connector operation requires -request with one JSON value")
	}
	now := timeNow().UTC().Truncate(time.Second)
	notBefore := now.Add(-*clockSkew)
	payloadType, schemaVersion, effectMode := actionpermit.PayloadTypeV1, actionpermit.SchemaV1, ""
	if intent.EffectMode == admission.EffectModeAuthorized {
		payloadType, schemaVersion, effectMode = actionpermit.PayloadTypeV2, actionpermit.SchemaV2, actionpermit.EffectModeAuthorized
		if approvalThreshold > 1 {
			payloadType, schemaVersion = actionpermit.PayloadTypeV3, actionpermit.SchemaV3
		}
		if admitted.ActionContextRequired {
			payloadType, schemaVersion = actionpermit.PayloadTypeV5, actionpermit.SchemaV5
		}
	}
	statement := actionpermit.Statement{
		SchemaVersion: schemaVersion, EffectMode: effectMode, NodeID: intent.NodeID, TenantID: intent.TenantID,
		InstanceID: intent.InstanceID, Generation: intent.Generation, CapsuleDigest: admitted.CapsuleDigest,
		PolicyDigest: admitted.PolicyDigest, RoutePolicyDigest: admitted.RoutePolicyDigest,
		ConnectorID: *connectorID, OperationID: *operationID, OperationDigest: trustedOperation.PolicyDigest, TaskID: *taskID,
		RequestDigest: actionpermit.RequestDigest(request), RequestBytes: int64(len(request)), ContentType: trustedOperation.ContentType,
		NotBefore: notBefore.Format(time.RFC3339), ExpiresAt: notBefore.Add(*validFor).Format(time.RFC3339),
	}
	if approvalThreshold > 1 {
		statement.ApprovalThreshold = approvalThreshold
	}
	if admitted.ActionContextRequired {
		contextRaw, err := securefile.Read(*contextPath, maxArtifactBytes, securefile.TrustFile)
		if err != nil {
			return fmt.Errorf("read effect context: %w", err)
		}
		var head influence.Head
		if err := dsse.DecodeStrictInto(contextRaw, maxArtifactBytes, &head); err != nil || head.Validate() != nil {
			return errors.New("effect context is invalid")
		}
		if head.TenantID != intent.TenantID || head.GrantID != admitted.GrantID || head.Generation != intent.Generation {
			return errors.New("effect context does not match the admitted grant")
		}
		statement.ApprovalThreshold = approvalThreshold
		statement.InfluenceSequence = head.Sequence
		statement.InfluenceHash = head.ChainHash
	}
	payload, err := actionpermit.MarshalStatement(statement, payloadType)
	if err != nil {
		return err
	}
	envelope, err := dsse.Sign(payloadType, payload, *keyID, privateKey)
	if err != nil {
		return err
	}
	raw, err := dsse.Marshal(envelope)
	if err != nil {
		return err
	}
	verified, err := actionpermit.VerifyPartial(raw, map[string]ed25519.PublicKey{*keyID: public}, now, *validFor)
	if err != nil {
		return fmt.Errorf("self-verify action permit: %w", err)
	}
	outputs := []permitOutput{{path: *output, contents: raw}}
	if *headerOutput != "" {
		if !verified.Complete {
			return errors.New("header output requires a complete multi-party permit; add the remaining approvals first")
		}
		header, err := actionpermit.EncodeHeader(raw)
		if err != nil {
			return err
		}
		outputs = append(outputs, permitOutput{path: *headerOutput, contents: []byte(header + "\n")})
	}
	if err := writePermitApprovalSummary(stderr, verified, trustedOperation); err != nil {
		return fmt.Errorf("write action-permit approval summary: %w", err)
	}
	if err := writePermitOutputs(outputs); err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, verified.EnvelopeDigest)
	return err
}

func approvePermit(arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("permit approve", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	input := flags.String("in", "", "existing partial multi-party permit")
	admissionPath := flags.String("admission", "", "Executor admission response JSON")
	intentPath := flags.String("intent", "", "instance intent JSON used for admission")
	trustPath := flags.String("trust", "", "exported Gateway action-trust inventory")
	requestPath := flags.String("request", "", "exact connector request body; omit only for an empty body")
	privateKeyPath := flags.String("key", "", "PEM Ed25519 action-authority private key")
	keyID := flags.String("key-id", "", "configured action-authority key ID")
	output := flags.String("out", "", "new approval artifact output")
	headerOutput := flags.String("header-out", "", "optional complete HTTP header value output")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *input == "" || *admissionPath == "" || *intentPath == "" || *trustPath == "" ||
		*privateKeyPath == "" || *keyID == "" || *output == "" || flags.NArg() != 0 {
		return errors.New("permit approve requires -in, -admission, -intent, -trust, -key, -key-id, and -out")
	}
	if *output == *input || *headerOutput != "" && (*headerOutput == *input || *headerOutput == *output) {
		return errors.New("approval input, output, and header output must name different files")
	}

	raw, err := readBounded(*input)
	if err != nil {
		return err
	}
	envelope, err := dsse.Parse(raw)
	if err != nil || envelope.PayloadType != actionpermit.PayloadTypeV3 && envelope.PayloadType != actionpermit.PayloadTypeV5 {
		return errors.New("permit approve requires a canonical multi-party approval artifact")
	}
	payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil || base64.StdEncoding.EncodeToString(payload) != envelope.Payload {
		return errors.New("multi-party approval payload is not canonical base64")
	}
	var statement actionpermit.Statement
	if err := dsse.DecodeStrictInto(payload, actionpermit.MaxEnvelopeBytes, &statement); err != nil {
		return fmt.Errorf("decode multi-party approval statement: %w", err)
	}
	notBefore, err := parsePermitTime(statement.NotBefore)
	if err != nil {
		return fmt.Errorf("approval not_before: %w", err)
	}
	expiresAt, err := parsePermitTime(statement.ExpiresAt)
	if err != nil || !expiresAt.After(notBefore) {
		return errors.New("approval expiry is invalid")
	}
	validFor := expiresAt.Sub(notBefore)

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
		return err
	}
	contextBound := envelope.PayloadType == actionpermit.PayloadTypeV5
	if intent.EffectMode != admission.EffectModeAuthorized || admitted.EffectMode != intent.EffectMode ||
		admitted.ActionContextRequired != contextBound ||
		admitted.ActionApprovalThreshold != statement.ApprovalThreshold || statement.ApprovalThreshold < 2 ||
		admitted.Generation != intent.Generation || statement.Generation != intent.Generation ||
		admitted.CapsuleDigest != intent.CapsuleDigest || statement.CapsuleDigest != admitted.CapsuleDigest ||
		statement.PolicyDigest != admitted.PolicyDigest || statement.RoutePolicyDigest != admitted.RoutePolicyDigest ||
		statement.NodeID != intent.NodeID || statement.TenantID != intent.TenantID || statement.InstanceID != intent.InstanceID ||
		!slices.Contains(intent.ConnectorIDs, statement.ConnectorID) || !slices.Contains(admitted.ConnectorIDs, statement.ConnectorID) {
		return errors.New("approval artifact does not match the admitted authorized-effects instance")
	}

	var request []byte
	if *requestPath != "" {
		request, err = securefile.Read(*requestPath, maxPermitRequestBytes, securefile.TrustFile)
		if err != nil {
			return fmt.Errorf("read exact connector request: %w", err)
		}
		if err := validatePermitRequest(request); err != nil {
			return err
		}
	}
	if statement.RequestDigest != actionpermit.RequestDigest(request) || statement.RequestBytes != int64(len(request)) {
		return errors.New("approval artifact does not bind the supplied exact request bytes")
	}

	privateKey, err := readPrivateKey(*privateKeyPath)
	if err != nil {
		return err
	}
	newPublic, ok := privateKey.Public().(ed25519.PublicKey)
	if !ok {
		return errors.New("action-authority private key does not contain an Ed25519 public key")
	}
	trusted := make(map[string]ed25519.PublicKey, len(admitted.ActionAuthorities))
	var operation validatedActionTrust
	for _, authority := range admitted.ActionAuthorities {
		if !slices.Contains(authority.ConnectorIDs, statement.ConnectorID) {
			continue
		}
		public, decodeErr := base64.StdEncoding.DecodeString(authority.PublicKey)
		if decodeErr != nil || len(public) != ed25519.PublicKeySize || base64.StdEncoding.EncodeToString(public) != authority.PublicKey {
			return errors.New("admission response contains an invalid action authority")
		}
		validated, validateErr := validateActionTrust(
			*trustPath, intent, statement.ConnectorID, statement.OperationID, authority.KeyID,
			ed25519.PublicKey(public), validFor,
		)
		if validateErr != nil {
			return validateErr
		}
		if operation.PolicyDigest != "" && operation != validated {
			return errors.New("action authorities do not agree on one trusted connector operation")
		}
		operation = validated
		trusted[authority.KeyID] = ed25519.PublicKey(append([]byte(nil), public...))
	}
	configuredPublic, exists := trusted[*keyID]
	if !exists || !configuredPublic.Equal(newPublic) {
		return errors.New("new approval key does not match the admitted connector authority")
	}
	approvalTime := timeNow().UTC().Truncate(time.Second)
	before, err := actionpermit.VerifyPartial(raw, trusted, approvalTime, validFor)
	if err != nil {
		return err
	}
	if before.Complete {
		return errors.New("multi-party permit is already complete")
	}
	for _, existing := range before.KeyIDs {
		if existing == *keyID {
			return errors.New("the selected action authority has already approved this permit")
		}
	}
	if statement.OperationDigest != operation.PolicyDigest || statement.ContentType != operation.ContentType {
		return errors.New("approval artifact does not match the trusted connector operation")
	}

	nextEnvelope, err := dsse.AddSignature(envelope, *keyID, privateKey)
	if err != nil {
		return err
	}
	nextRaw, err := dsse.Marshal(nextEnvelope)
	if err != nil {
		return err
	}
	next, err := actionpermit.VerifyPartial(nextRaw, trusted, approvalTime, validFor)
	if err != nil {
		return err
	}
	if next.Complete {
		if _, err := actionpermit.Verify(nextRaw, trusted, approvalTime, validFor); err != nil {
			return fmt.Errorf("verify complete multi-party permit: %w", err)
		}
	}
	outputs := []permitOutput{{path: *output, contents: nextRaw}}
	if *headerOutput != "" {
		if !next.Complete {
			return errors.New("header output requires a complete multi-party permit")
		}
		header, err := actionpermit.EncodeHeader(nextRaw)
		if err != nil {
			return err
		}
		outputs = append(outputs, permitOutput{path: *headerOutput, contents: []byte(header + "\n")})
	}
	if err := writePermitApprovalSummary(stderr, next, operation); err != nil {
		return fmt.Errorf("write action-permit approval summary: %w", err)
	}
	if err := writePermitOutputs(outputs); err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, next.EnvelopeDigest)
	return err
}

type permitApprovalSummary struct {
	SchemaVersion      string   `json:"schema_version"`
	PermitDigest       string   `json:"permit_digest"`
	EffectMode         string   `json:"effect_mode"`
	TenantID           string   `json:"tenant_id"`
	NodeID             string   `json:"node_id"`
	InstanceID         string   `json:"instance_id"`
	Generation         uint64   `json:"generation"`
	ConnectorID        string   `json:"connector_id"`
	OperationID        string   `json:"operation_id"`
	Method             string   `json:"method"`
	Path               string   `json:"path"`
	TaskID             string   `json:"task_id"`
	RequestDigest      string   `json:"request_digest"`
	RequestBytes       int64    `json:"request_bytes"`
	NotBefore          string   `json:"not_before"`
	ExpiresAt          string   `json:"expires_at"`
	AuthorityKey       string   `json:"authority_key_id"`
	AuthorityKeys      []string `json:"authority_key_ids"`
	ApprovalThreshold  int      `json:"approval_threshold"`
	ApprovalsCollected int      `json:"approvals_collected"`
	Complete           bool     `json:"complete"`
	InfluenceSequence  uint64   `json:"influence_sequence,omitempty"`
	InfluenceHash      string   `json:"influence_hash,omitempty"`
}

func writePermitApprovalSummary(writer io.Writer, verified actionpermit.Verified, operation validatedActionTrust) error {
	effectMode := verified.Statement.EffectMode
	if effectMode == "" {
		effectMode = admission.EffectModeStandard
	}
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(permitApprovalSummary{
		SchemaVersion: "steward.action-permit-approval-summary.v1", PermitDigest: verified.EnvelopeDigest,
		EffectMode: effectMode, TenantID: verified.Statement.TenantID, NodeID: verified.Statement.NodeID,
		InstanceID: verified.Statement.InstanceID, Generation: verified.Statement.Generation,
		ConnectorID: verified.Statement.ConnectorID, OperationID: verified.Statement.OperationID,
		Method: operation.Method, Path: operation.Path, TaskID: verified.Statement.TaskID,
		RequestDigest: verified.Statement.RequestDigest, RequestBytes: verified.Statement.RequestBytes,
		NotBefore: verified.Statement.NotBefore, ExpiresAt: verified.Statement.ExpiresAt,
		AuthorityKey: verified.KeyID, AuthorityKeys: append([]string(nil), verified.KeyIDs...),
		ApprovalThreshold:  max(1, verified.Statement.ApprovalThreshold),
		ApprovalsCollected: len(verified.KeyIDs), Complete: verified.Complete,
		InfluenceSequence: verified.Statement.InfluenceSequence, InfluenceHash: verified.Statement.InfluenceHash,
	})
}

func verifyPermit(arguments []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("permit verify", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	input := flags.String("in", "", "signed action permit DSSE envelope")
	publicKeyPath := flags.String("public-key", "", "base64 Ed25519 action-authority public key")
	keyID := flags.String("key-id", "", "trusted action-authority key ID")
	var authorityFlags repeatedFlag
	flags.Var(&authorityFlags, "authority", "trusted KEY_ID=PUBLIC_KEY_FILE; repeat for multi-party permits")
	requestPath := flags.String("request", "", "optional exact request body to compare")
	maxValidity := flags.Duration("max-validity", actionpermit.MaxValidity, "local maximum permit validity")
	evaluatedAtText := flags.String("at", "", "canonical UTC RFC3339-seconds evaluation time")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *input == "" || flags.NArg() != 0 {
		return errors.New("permit verify requires -in and either -public-key with -key-id or repeated -authority")
	}
	raw, err := readBounded(*input)
	if err != nil {
		return err
	}
	trusted, err := readPermitAuthorities(*publicKeyPath, *keyID, authorityFlags)
	if err != nil {
		return err
	}
	evaluatedAt, err := permitEvaluationTime(*evaluatedAtText)
	if err != nil {
		return err
	}
	verified, err := actionpermit.Verify(raw, trusted, evaluatedAt, *maxValidity)
	if err != nil {
		return err
	}
	if *requestPath != "" {
		request, err := securefile.Read(*requestPath, maxPermitRequestBytes, securefile.TrustFile)
		if err != nil {
			return fmt.Errorf("read exact connector request: %w", err)
		}
		if verified.Statement.RequestDigest != actionpermit.RequestDigest(request) || verified.Statement.RequestBytes != int64(len(request)) {
			return errors.New("action permit does not bind the supplied request bytes")
		}
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(struct {
		Valid          bool                   `json:"valid"`
		EvaluatedAt    string                 `json:"evaluated_at"`
		KeyID          string                 `json:"key_id"`
		KeyIDs         []string               `json:"key_ids"`
		EnvelopeDigest string                 `json:"envelope_digest"`
		Statement      actionpermit.Statement `json:"statement"`
	}{Valid: true, EvaluatedAt: evaluatedAt.Format(time.RFC3339), KeyID: verified.KeyID, KeyIDs: verified.KeyIDs,
		EnvelopeDigest: verified.EnvelopeDigest, Statement: verified.Statement})
}

type permitAuditRecord struct {
	Sequence   uint64                `json:"sequence"`
	ChainHash  string                `json:"chain_hash"`
	ObservedAt string                `json:"observed_at"`
	Event      connectorledger.Event `json:"event"`
}

func auditPermit(arguments []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("permit audit", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	input := flags.String("in", "", "signed action permit DSSE envelope")
	publicKeyPath := flags.String("public-key", "", "base64 Ed25519 action-authority public key")
	keyID := flags.String("key-id", "", "trusted action-authority key ID")
	var authorityFlags repeatedFlag
	flags.Var(&authorityFlags, "authority", "trusted KEY_ID=PUBLIC_KEY_FILE; repeat for multi-party permits")
	receiptsPath := flags.String("receipts", "", "signed connector receipt ledger")
	receiptPublicKeyPath := flags.String("receipt-public-key", "", "base64 Ed25519 connector receipt public key")
	receiptNodeID := flags.String("receipt-node-id", "", "expected connector receipt node ID")
	receiptEpoch := flags.Uint64("receipt-epoch", 1, "expected connector receipt key epoch")
	requestPath := flags.String("request", "", "optional exact request body to compare")
	maxValidity := flags.Duration("max-validity", actionpermit.MaxValidity, "local maximum permit validity")
	expectedSequence := flags.String("expected-sequence", "", "externally retained final receipt sequence")
	expectedChainHash := flags.String("expected-chain-hash", "", "externally retained sha256 receipt chain hash")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *input == "" || *receiptsPath == "" ||
		*receiptPublicKeyPath == "" || *receiptNodeID == "" || flags.NArg() != 0 {
		return errors.New("permit audit requires -in, approval authorities, -receipts, -receipt-public-key, and -receipt-node-id")
	}

	raw, err := readBounded(*input)
	if err != nil {
		return err
	}
	trusted, err := readPermitAuthorities(*publicKeyPath, *keyID, authorityFlags)
	if err != nil {
		return err
	}
	verified, err := verifyPermitForAudit(raw, trusted, *maxValidity)
	if err != nil {
		return err
	}
	if *requestPath != "" {
		request, err := securefile.Read(*requestPath, maxPermitRequestBytes, securefile.TrustFile)
		if err != nil {
			return fmt.Errorf("read exact connector request: %w", err)
		}
		if verified.Statement.RequestDigest != actionpermit.RequestDigest(request) ||
			verified.Statement.RequestBytes != int64(len(request)) {
			return errors.New("action permit does not bind the supplied request bytes")
		}
	}
	receiptPublic, err := readPublicKey(*receiptPublicKeyPath)
	if err != nil {
		return err
	}

	var authorization *permitAuditRecord
	var terminal *permitAuditRecord
	head, err := connectorledger.VerifyRecords(*receiptsPath, receiptPublic, *receiptNodeID, *receiptEpoch,
		func(record connectorledger.VerifiedReceipt) error {
			event := record.Receipt.Event
			if event.PermitDigest != verified.EnvelopeDigest {
				return nil
			}
			if err := checkPermitReceiptBindings(verified.Statement, verified.KeyIDs, event); err != nil {
				return fmt.Errorf("connector receipt sequence %d: %w", record.Receipt.Sequence, err)
			}
			matched := &permitAuditRecord{Sequence: record.Receipt.Sequence, ChainHash: record.Hash,
				ObservedAt: record.Receipt.ObservedAt, Event: event}
			switch event.Phase {
			case connectorledger.Authorize:
				if authorization != nil {
					return errors.New("connector receipt chain contains multiple authorizations for the action permit")
				}
				authorization = matched
			case connectorledger.Terminal:
				if terminal != nil {
					return errors.New("connector receipt chain contains multiple terminal records for the action permit")
				}
				terminal = matched
			default:
				return errors.New("connector receipt correlates an action permit with an unsupported event phase")
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
		return errors.New("connector receipt chain has no authorization for the exact action permit")
	}
	authorizedAt, err := time.Parse(time.RFC3339Nano, authorization.ObservedAt)
	if err != nil {
		return errors.New("connector authorization has an invalid observation time")
	}
	if _, err := actionpermit.Verify(raw, trusted, authorizedAt, *maxValidity); err != nil {
		return fmt.Errorf("action permit was not valid at connector authorization time: %w", err)
	}

	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(struct {
		Valid         bool                   `json:"valid"`
		PermitDigest  string                 `json:"permit_digest"`
		RequestDigest string                 `json:"request_digest"`
		PermitKeyID   string                 `json:"permit_key_id"`
		PermitKeyIDs  []string               `json:"permit_key_ids"`
		Statement     actionpermit.Statement `json:"statement"`
		Authorization *permitAuditRecord     `json:"authorization"`
		Terminal      *permitAuditRecord     `json:"terminal"`
		Head          connectorledger.Head   `json:"head"`
	}{Valid: true, PermitDigest: verified.EnvelopeDigest, RequestDigest: verified.Statement.RequestDigest,
		PermitKeyID: verified.KeyID, PermitKeyIDs: verified.KeyIDs, Statement: verified.Statement,
		Authorization: authorization, Terminal: terminal, Head: head})
}

func verifyPermitForAudit(raw []byte, trusted map[string]ed25519.PublicKey, maxValidity time.Duration) (actionpermit.Verified, error) {
	// Historical audit cannot use the current wall clock: an authentic permit
	// may have expired long before its receipt is inspected. Decode the bounded,
	// untrusted payload only to select its signed not_before as a provisional
	// verification time. actionpermit.Verify then authenticates the complete
	// statement and every signature before any decoded field is returned. The
	// caller separately re-verifies the permit at the signed receipt's observed_at,
	// which is the authoritative proof that execution occurred inside the window.
	envelope, err := dsse.Parse(raw)
	if err != nil {
		return actionpermit.Verified{}, err
	}
	if envelope.PayloadType != actionpermit.PayloadTypeV1 && envelope.PayloadType != actionpermit.PayloadTypeV2 &&
		envelope.PayloadType != actionpermit.PayloadTypeV3 && envelope.PayloadType != actionpermit.PayloadTypeV5 {
		return actionpermit.Verified{}, errors.New("unsupported action permit payload type")
	}
	payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil || base64.StdEncoding.EncodeToString(payload) != envelope.Payload {
		return actionpermit.Verified{}, errors.New("action permit payload is not canonical base64")
	}
	var statement actionpermit.Statement
	if err := dsse.DecodeStrictInto(payload, actionpermit.MaxEnvelopeBytes, &statement); err != nil {
		return actionpermit.Verified{}, fmt.Errorf("decode signed action permit: %w", err)
	}
	notBefore, err := parsePermitTime(statement.NotBefore)
	if err != nil {
		return actionpermit.Verified{}, fmt.Errorf("action permit not_before: %w", err)
	}
	return actionpermit.Verify(raw, trusted, notBefore, maxValidity)
}

func checkPermitReceiptBindings(statement actionpermit.Statement, authorityKeyIDs []string, event connectorledger.Event) error {
	taskDigest := gateway.ConnectorCallDigest(statement.TenantID, statement.InstanceID, statement.TaskID,
		statement.ConnectorID, statement.OperationID)
	authorityKeyID, authorityKeySet, approvalThreshold := "", "", 0
	if statement.ApprovalThreshold > 1 {
		authorityKeySet = strings.Join(authorityKeyIDs, ",")
		approvalThreshold = statement.ApprovalThreshold
	} else if len(authorityKeyIDs) == 1 {
		authorityKeyID = authorityKeyIDs[0]
	}
	if event.TenantID != statement.TenantID || event.CapsuleDigest != statement.CapsuleDigest ||
		event.PolicyDigest != statement.PolicyDigest || event.RoutePolicyDigest != statement.RoutePolicyDigest ||
		event.Generation != statement.Generation || event.GrantID != gateway.GrantID(statement.TenantID, statement.InstanceID, statement.Generation) ||
		event.ConnectorID != statement.ConnectorID || event.OperationID != statement.OperationID ||
		event.TaskDigest != taskDigest || event.AuthorityKeyID != authorityKeyID || event.AuthorityKeySet != authorityKeySet ||
		event.ApprovalThreshold != approvalThreshold || event.RequestDigest != statement.RequestDigest ||
		event.RequestBytes != statement.RequestBytes || event.EffectMode != statement.EffectMode ||
		event.InfluenceSequence != statement.InfluenceSequence || event.InfluenceHash != statement.InfluenceHash ||
		(statement.EffectMode != "" && event.OperationPolicyDigest != statement.OperationDigest) {
		return errors.New("connector receipt does not match every available action-permit binding")
	}
	return nil
}

type validatedActionTrust struct {
	PolicyDigest string
	ContentType  string
	Method       string
	Path         string
}

func validateActionTrust(
	path string,
	intent admission.InstanceIntent,
	connectorID, operationID, keyID string,
	public ed25519.PublicKey,
	validFor time.Duration,
) (validatedActionTrust, error) {
	raw, err := securefile.Read(path, maxActionTrustBytes, securefile.TrustFile)
	if err != nil {
		return validatedActionTrust{}, fmt.Errorf("read action trust inventory: %w", err)
	}
	var inventory actionTrustInventory
	if err := dsse.DecodeStrictInto(raw, maxActionTrustBytes, &inventory); err != nil {
		return validatedActionTrust{}, fmt.Errorf("decode action trust inventory: %w", err)
	}
	if inventory.SchemaVersion != actionTrustSchemaV1 || inventory.NodeID != intent.NodeID || inventory.TenantID != intent.TenantID {
		return validatedActionTrust{}, errors.New("action trust inventory does not match the instance node and tenant")
	}
	var authority *actionTrustAuthority
	for index := range inventory.Authorities {
		if inventory.Authorities[index].KeyID != keyID {
			continue
		}
		if authority != nil {
			return validatedActionTrust{}, fmt.Errorf("action trust inventory duplicates authority %q", keyID)
		}
		authority = &inventory.Authorities[index]
	}
	if authority == nil || authority.TenantID != intent.TenantID || authority.PublicKeyDigest != dsse.Digest(public) ||
		!slices.Contains(authority.ConnectorIDs, connectorID) {
		return validatedActionTrust{}, errors.New("action trust inventory does not bind the signing key to this tenant and connector")
	}
	var connector *actionTrustConnector
	for index := range inventory.Connectors {
		if inventory.Connectors[index].ConnectorID != connectorID {
			continue
		}
		if connector != nil {
			return validatedActionTrust{}, fmt.Errorf("action trust inventory duplicates connector %q", connectorID)
		}
		connector = &inventory.Connectors[index]
	}
	if connector == nil || connector.CredentialEpoch == 0 || connector.MaxPermitSeconds < 1 ||
		connector.MaxPermitSeconds > int(actionpermit.MaxValidity/time.Second) || !slices.Contains(connector.AuthorityKeyIDs, keyID) {
		return validatedActionTrust{}, errors.New("action trust inventory does not bind the connector to the signing authority")
	}
	if validFor > time.Duration(connector.MaxPermitSeconds)*time.Second {
		return validatedActionTrust{}, fmt.Errorf("permit validity %s exceeds connector maximum %s", validFor, time.Duration(connector.MaxPermitSeconds)*time.Second)
	}
	var operation *actionTrustOperation
	for index := range connector.Operations {
		if connector.Operations[index].ID != operationID {
			continue
		}
		if operation != nil {
			return validatedActionTrust{}, fmt.Errorf("action trust inventory duplicates operation %q", operationID)
		}
		operation = &connector.Operations[index]
	}
	if operation == nil {
		return validatedActionTrust{}, errors.New("action trust inventory does not contain the requested connector operation")
	}
	policyDigest, err := gateway.ConnectorOperationPolicyDigest(
		connector.BaseURL, connector.CredentialMode, connector.CredentialEpoch, connector.ConnectorID,
		gateway.ConnectorOperation{ID: operation.ID, Method: operation.Method, Path: operation.Path},
	)
	if err != nil || policyDigest != operation.PolicyDigest {
		return validatedActionTrust{}, errors.New("action trust inventory contains inconsistent connector operation policy")
	}
	contentType, err := gateway.ConnectorOperationContentType(operation.Method)
	if err != nil {
		return validatedActionTrust{}, errors.New("action trust inventory contains an unsupported connector operation method")
	}
	return validatedActionTrust{PolicyDigest: policyDigest, ContentType: contentType, Method: operation.Method, Path: operation.Path}, nil
}

func permitEvaluationTime(value string) (time.Time, error) {
	if value == "" {
		return timeNow().UTC().Truncate(time.Second), nil
	}
	return parsePermitTime(value)
}

func parsePermitTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil || parsed.IsZero() || parsed.UTC().Format(time.RFC3339) != value {
		return time.Time{}, errors.New("time must be canonical UTC RFC3339 seconds")
	}
	return parsed, nil
}

func readPermitAuthorities(publicKeyPath, keyID string, authorityFlags []string) (map[string]ed25519.PublicKey, error) {
	if len(authorityFlags) == 0 {
		if publicKeyPath == "" || keyID == "" {
			return nil, errors.New("one -public-key and -key-id pair or repeated -authority KEY_ID=PUBLIC_KEY_FILE values are required")
		}
		public, err := readPublicKey(publicKeyPath)
		if err != nil {
			return nil, err
		}
		return map[string]ed25519.PublicKey{keyID: public}, nil
	}
	if publicKeyPath != "" || keyID != "" {
		return nil, errors.New("legacy -public-key/-key-id and repeated -authority values cannot be combined")
	}
	if len(authorityFlags) > 8 {
		return nil, errors.New("at most eight approval authorities are supported")
	}
	trusted := make(map[string]ed25519.PublicKey, len(authorityFlags))
	for _, value := range authorityFlags {
		id, path, ok := strings.Cut(value, "=")
		if !ok || id == "" || path == "" {
			return nil, errors.New("approval authority must be KEY_ID=PUBLIC_KEY_FILE")
		}
		if _, duplicate := trusted[id]; duplicate {
			return nil, fmt.Errorf("approval authority %q is repeated", id)
		}
		public, err := readPublicKey(path)
		if err != nil {
			return nil, fmt.Errorf("read approval authority %q: %w", id, err)
		}
		trusted[id] = public
	}
	return trusted, nil
}

func validatePermitRequest(raw []byte) error {
	wrapper := make([]byte, 0, len(raw)+10)
	wrapper = append(wrapper, `{"value":`...)
	wrapper = append(wrapper, raw...)
	wrapper = append(wrapper, '}')
	var decoded struct {
		Value json.RawMessage `json:"value"`
	}
	if err := dsse.DecodeStrictInto(wrapper, maxPermitRequestBytes+10, &decoded); err != nil {
		return fmt.Errorf("exact connector request must contain one valid JSON value: %w", err)
	}
	return nil
}

type permitOutput struct {
	path     string
	contents []byte
}

func writePermitOutputs(outputs []permitOutput) error {
	seen := make(map[string]struct{}, len(outputs))
	for _, output := range outputs {
		if output.path == "" {
			return errors.New("permit output path is empty")
		}
		cleaned, err := filepathAbsClean(output.path)
		if err != nil {
			return err
		}
		if _, duplicate := seen[cleaned]; duplicate {
			return errors.New("permit outputs must name different files")
		}
		seen[cleaned] = struct{}{}
		if _, err := os.Lstat(output.path); err == nil {
			return fmt.Errorf("permit output already exists: %s", output.path)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	written := make([]string, 0, len(outputs))
	for _, output := range outputs {
		if err := writeNewFile(output.path, output.contents, 0o600); err != nil {
			rollbackErrors := []error{err}
			for index := len(written) - 1; index >= 0; index-- {
				if removeErr := os.Remove(written[index]); removeErr != nil {
					rollbackErrors = append(rollbackErrors, fmt.Errorf("remove partial permit output %s: %w", written[index], removeErr))
				}
				if syncErr := syncOutputDirectory(written[index]); syncErr != nil {
					rollbackErrors = append(rollbackErrors, fmt.Errorf("sync permit output rollback %s: %w", written[index], syncErr))
				}
			}
			return errors.Join(rollbackErrors...)
		}
		written = append(written, output.path)
	}
	return nil
}

func filepathAbsClean(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	return filepath.Clean(absolute), nil
}
