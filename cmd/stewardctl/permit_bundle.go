package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"time"

	"github.com/hardrails/steward/internal/actionpermit"
	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/gateway"
	"github.com/hardrails/steward/internal/securefile"
)

const effectBundleInputSchemaV1 = "steward.effect-bundle-input.v1"

type effectBundlePlan struct {
	SchemaVersion string                 `json:"schema_version"`
	BundleID      string                 `json:"bundle_id"`
	Steps         []effectBundlePlanStep `json:"steps"`
}

type effectBundlePlanStep struct {
	StepID      string `json:"step_id"`
	ConnectorID string `json:"connector_id"`
	OperationID string `json:"operation_id"`
	TaskID      string `json:"task_id"`
	RequestPath string `json:"request_path,omitempty"`
}

type effectBundleContext struct {
	admitted  permitAdmission
	intent    admission.InstanceIntent
	threshold int
}

type effectBundlePreparedStep struct {
	signed    actionpermit.BundleStep
	operation validatedActionTrust
}

type effectBundleApprovalSummary struct {
	SchemaVersion      string                       `json:"schema_version"`
	PermitDigest       string                       `json:"permit_digest"`
	Bundle             actionpermit.BundleStatement `json:"bundle"`
	Steps              []effectBundleStepSummary    `json:"steps"`
	AuthorityKey       string                       `json:"authority_key_id"`
	AuthorityKeys      []string                     `json:"authority_key_ids"`
	ApprovalsCollected int                          `json:"approvals_collected"`
	Complete           bool                         `json:"complete"`
}

type effectBundleStepSummary struct {
	StepID      string `json:"step_id"`
	ConnectorID string `json:"connector_id"`
	OperationID string `json:"operation_id"`
	Method      string `json:"method"`
	Path        string `json:"path"`
	TaskID      string `json:"task_id"`
}

func permitBundleCommand(arguments []string, stdout, stderr io.Writer) error {
	if len(arguments) == 0 {
		return errors.New("permit bundle command requires issue, approve, verify, or audit")
	}
	switch arguments[0] {
	case "issue":
		return issueEffectBundle(arguments[1:], stdout, stderr)
	case "approve":
		return approveEffectBundle(arguments[1:], stdout, stderr)
	case "verify":
		return verifyEffectBundle(arguments[1:], stdout)
	case "audit":
		return auditEffectBundle(arguments[1:], stdout)
	default:
		return errors.New("permit bundle command requires issue, approve, verify, or audit")
	}
}

func issueEffectBundle(arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("permit bundle issue", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	admissionPath := flags.String("admission", "", "Executor admission response JSON")
	intentPath := flags.String("intent", "", "instance intent JSON used for admission")
	trustPath := flags.String("trust", "", "exported Gateway action-trust inventory")
	planPath := flags.String("plan", "", "owner-only exact effect bundle plan")
	validFor := flags.Duration("valid-for", 5*time.Minute, "bundle validity window")
	clockSkew := flags.Duration("clock-skew", 5*time.Second, "bounded allowance for node clock skew")
	privateKeyPath := flags.String("key", "", "PEM Ed25519 action-authority private key")
	keyID := flags.String("key-id", "", "configured action-authority key ID")
	output := flags.String("out", "", "new DSSE bundle output")
	headerOutput := flags.String("header-out", "", "optional complete HTTP header value output")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *admissionPath == "" || *intentPath == "" || *trustPath == "" || *planPath == "" ||
		*privateKeyPath == "" || *keyID == "" || *output == "" || flags.NArg() != 0 {
		return errors.New("permit bundle issue requires -admission, -intent, -trust, -plan, -key, -key-id, and -out")
	}
	if err := validateEffectBundleTiming(*validFor, *clockSkew); err != nil {
		return err
	}
	if *headerOutput != "" && *headerOutput == *output {
		return errors.New("bundle and header outputs must be different files")
	}

	context, err := loadEffectBundleContext(*admissionPath, *intentPath)
	if err != nil {
		return err
	}
	plan, err := loadEffectBundlePlan(*planPath)
	if err != nil {
		return err
	}
	privateKey, err := readPrivateKey(*privateKeyPath)
	if err != nil {
		return err
	}
	public, ok := privateKey.Public().(ed25519.PublicKey)
	if !ok {
		return errors.New("action-authority private key does not contain an Ed25519 public key")
	}
	if err := requireAdmittedBundleAuthority(context.admitted, *keyID, public, effectBundleConnectorIDs(plan)); err != nil {
		return err
	}
	prepared, err := prepareEffectBundleSteps(plan, context, *trustPath, *keyID, public, *validFor)
	if err != nil {
		return err
	}
	now := timeNow().UTC().Truncate(time.Second)
	notBefore := now.Add(-*clockSkew)
	bundle := buildEffectBundleStatement(context, plan.BundleID, prepared,
		notBefore.Format(time.RFC3339), notBefore.Add(*validFor).Format(time.RFC3339))
	payload, err := json.Marshal(bundle)
	if err != nil {
		return err
	}
	envelope, err := dsse.Sign(actionpermit.PayloadTypeV4, payload, *keyID, privateKey)
	if err != nil {
		return err
	}
	raw, err := dsse.Marshal(envelope)
	if err != nil {
		return err
	}
	verified, err := actionpermit.VerifyPartial(raw, map[string]ed25519.PublicKey{*keyID: public}, now, *validFor)
	if err != nil {
		return fmt.Errorf("self-verify exact effect bundle: %w", err)
	}
	if verified.Bundle == nil || !reflect.DeepEqual(*verified.Bundle, bundle) {
		return errors.New("self-verified effect bundle changed its signed bindings")
	}
	outputs, err := effectBundleOutputs(raw, verified.Complete, *output, *headerOutput)
	if err != nil {
		return err
	}
	if err := writeEffectBundleApprovalSummary(stderr, verified, prepared); err != nil {
		return fmt.Errorf("write effect-bundle approval summary: %w", err)
	}
	if err := writePermitOutputs(outputs); err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, verified.EnvelopeDigest)
	return err
}

func approveEffectBundle(arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("permit bundle approve", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	input := flags.String("in", "", "existing partial exact effect bundle")
	admissionPath := flags.String("admission", "", "Executor admission response JSON")
	intentPath := flags.String("intent", "", "instance intent JSON used for admission")
	trustPath := flags.String("trust", "", "exported Gateway action-trust inventory")
	planPath := flags.String("plan", "", "owner-only exact effect bundle plan")
	privateKeyPath := flags.String("key", "", "PEM Ed25519 action-authority private key")
	keyID := flags.String("key-id", "", "configured action-authority key ID")
	output := flags.String("out", "", "new approval artifact output")
	headerOutput := flags.String("header-out", "", "optional complete HTTP header value output")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *input == "" || *admissionPath == "" || *intentPath == "" || *trustPath == "" || *planPath == "" ||
		*privateKeyPath == "" || *keyID == "" || *output == "" || flags.NArg() != 0 {
		return errors.New("permit bundle approve requires -in, -admission, -intent, -trust, -plan, -key, -key-id, and -out")
	}
	if *output == *input || *headerOutput != "" && (*headerOutput == *input || *headerOutput == *output) {
		return errors.New("bundle approval input, output, and header output must name different files")
	}
	raw, err := readBounded(*input)
	if err != nil {
		return err
	}
	envelope, err := dsse.Parse(raw)
	if err != nil || envelope.PayloadType != actionpermit.PayloadTypeV4 {
		return errors.New("permit bundle approve requires a canonical version-4 bundle artifact")
	}
	payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil || base64.StdEncoding.EncodeToString(payload) != envelope.Payload {
		return errors.New("effect bundle payload is not canonical base64")
	}
	var decoded actionpermit.BundleStatement
	if err := dsse.DecodeStrictInto(payload, actionpermit.MaxEnvelopeBytes, &decoded); err != nil {
		return fmt.Errorf("decode exact effect bundle: %w", err)
	}
	notBefore, err := parsePermitTime(decoded.NotBefore)
	if err != nil {
		return fmt.Errorf("bundle not_before: %w", err)
	}
	expiresAt, err := parsePermitTime(decoded.ExpiresAt)
	if err != nil || !expiresAt.After(notBefore) {
		return errors.New("bundle expiry is invalid")
	}
	validFor := expiresAt.Sub(notBefore)

	context, err := loadEffectBundleContext(*admissionPath, *intentPath)
	if err != nil {
		return err
	}
	plan, err := loadEffectBundlePlan(*planPath)
	if err != nil {
		return err
	}
	trusted, prepared, err := trustedEffectBundleAuthorities(context, plan, *trustPath, validFor)
	if err != nil {
		return err
	}
	privateKey, err := readPrivateKey(*privateKeyPath)
	if err != nil {
		return err
	}
	newPublic, ok := privateKey.Public().(ed25519.PublicKey)
	if !ok {
		return errors.New("action-authority private key does not contain an Ed25519 public key")
	}
	configuredPublic, exists := trusted[*keyID]
	if !exists || !configuredPublic.Equal(newPublic) {
		return errors.New("new approval key does not match an admitted authority for every bundled connector")
	}
	approvalTime := timeNow().UTC().Truncate(time.Second)
	before, err := actionpermit.VerifyPartial(raw, trusted, approvalTime, validFor)
	if err != nil {
		return err
	}
	expected := buildEffectBundleStatement(context, plan.BundleID, prepared, decoded.NotBefore, decoded.ExpiresAt)
	if before.Bundle == nil || !reflect.DeepEqual(*before.Bundle, expected) {
		return errors.New("approval artifact does not match the admitted exact effect plan")
	}
	if before.Complete {
		return errors.New("exact effect bundle is already complete")
	}
	if slices.Contains(before.KeyIDs, *keyID) {
		return errors.New("the selected action authority has already approved this bundle")
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
			return fmt.Errorf("verify complete exact effect bundle: %w", err)
		}
	}
	outputs, err := effectBundleOutputs(nextRaw, next.Complete, *output, *headerOutput)
	if err != nil {
		return err
	}
	if err := writeEffectBundleApprovalSummary(stderr, next, prepared); err != nil {
		return fmt.Errorf("write effect-bundle approval summary: %w", err)
	}
	if err := writePermitOutputs(outputs); err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, next.EnvelopeDigest)
	return err
}

func verifyEffectBundle(arguments []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("permit bundle verify", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	input := flags.String("in", "", "signed exact effect bundle DSSE envelope")
	publicKeyPath := flags.String("public-key", "", "base64 Ed25519 action-authority public key")
	keyID := flags.String("key-id", "", "trusted action-authority key ID")
	var authorityFlags repeatedFlag
	flags.Var(&authorityFlags, "authority", "trusted KEY_ID=PUBLIC_KEY_FILE; repeat for multi-party bundles")
	planPath := flags.String("plan", "", "optional exact effect plan and request files to compare")
	maxValidity := flags.Duration("max-validity", actionpermit.MaxValidity, "local maximum bundle validity")
	evaluatedAtText := flags.String("at", "", "canonical UTC RFC3339-seconds evaluation time")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *input == "" || flags.NArg() != 0 {
		return errors.New("permit bundle verify requires -in and approval authorities")
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
	if verified.PayloadType != actionpermit.PayloadTypeV4 || verified.Bundle == nil {
		return errors.New("artifact is not an exact effect bundle")
	}
	if *planPath != "" {
		plan, err := loadEffectBundlePlan(*planPath)
		if err != nil {
			return err
		}
		if err := compareEffectBundlePlan(plan, *verified.Bundle); err != nil {
			return err
		}
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(struct {
		Valid          bool                         `json:"valid"`
		EvaluatedAt    string                       `json:"evaluated_at"`
		KeyIDs         []string                     `json:"key_ids"`
		EnvelopeDigest string                       `json:"envelope_digest"`
		Bundle         actionpermit.BundleStatement `json:"bundle"`
	}{Valid: true, EvaluatedAt: evaluatedAt.Format(time.RFC3339), KeyIDs: verified.KeyIDs,
		EnvelopeDigest: verified.EnvelopeDigest, Bundle: *verified.Bundle})
}

func validateEffectBundleTiming(validFor, clockSkew time.Duration) error {
	if validFor < time.Second || validFor > actionpermit.MaxValidity || validFor%time.Second != 0 {
		return fmt.Errorf("bundle validity must be whole seconds from 1s through %s", actionpermit.MaxValidity)
	}
	if clockSkew < 0 || clockSkew > maxPermitClockSkew || clockSkew%time.Second != 0 {
		return fmt.Errorf("bundle clock skew must be whole seconds from 0s through %s", maxPermitClockSkew)
	}
	if clockSkew >= validFor {
		return errors.New("bundle clock skew must be shorter than the validity interval")
	}
	return nil
}

func loadEffectBundleContext(admissionPath, intentPath string) (effectBundleContext, error) {
	admissionRaw, err := securefile.Read(admissionPath, maxArtifactBytes, securefile.TrustFile)
	if err != nil {
		return effectBundleContext{}, fmt.Errorf("read admission response: %w", err)
	}
	var admitted permitAdmission
	if err := dsse.DecodeStrictInto(admissionRaw, maxArtifactBytes, &admitted); err != nil {
		return effectBundleContext{}, fmt.Errorf("decode admission response: %w", err)
	}
	intentRaw, err := securefile.Read(intentPath, maxArtifactBytes, securefile.TrustFile)
	if err != nil {
		return effectBundleContext{}, fmt.Errorf("read instance intent: %w", err)
	}
	var intent admission.InstanceIntent
	if err := dsse.DecodeStrictInto(intentRaw, maxArtifactBytes, &intent); err != nil {
		return effectBundleContext{}, fmt.Errorf("decode instance intent: %w", err)
	}
	if err := intent.Validate(admission.AuthenticatedIdentity{TenantID: intent.TenantID, NodeID: intent.NodeID}); err != nil {
		return effectBundleContext{}, err
	}
	threshold := admitted.ActionApprovalThreshold
	if threshold == 0 {
		threshold = 1
	}
	if intent.EffectMode != admission.EffectModeAuthorized || admitted.EffectMode != admission.EffectModeAuthorized ||
		admitted.Generation != intent.Generation || admitted.CapsuleDigest != intent.CapsuleDigest || admitted.PolicyDigest == "" ||
		admitted.RoutePolicyDigest == "" || admitted.GrantID != gateway.GrantID(intent.TenantID, intent.InstanceID, intent.Generation) ||
		threshold < 1 || threshold > actionpermit.MaxBundleSteps || len(admitted.ActionAuthorities) < threshold {
		return effectBundleContext{}, errors.New("admission response and intent do not bind a valid authorized-effects instance")
	}
	return effectBundleContext{admitted: admitted, intent: intent, threshold: threshold}, nil
}

func loadEffectBundlePlan(path string) (effectBundlePlan, error) {
	raw, err := securefile.Read(path, maxArtifactBytes, securefile.TrustFile)
	if err != nil {
		return effectBundlePlan{}, fmt.Errorf("read exact effect plan: %w", err)
	}
	var plan effectBundlePlan
	if err := dsse.DecodeStrictInto(raw, maxArtifactBytes, &plan); err != nil {
		return effectBundlePlan{}, fmt.Errorf("decode exact effect plan: %w", err)
	}
	if plan.SchemaVersion != effectBundleInputSchemaV1 || !effectBundleRouteID(plan.BundleID) ||
		len(plan.Steps) < 1 || len(plan.Steps) > actionpermit.MaxBundleSteps {
		return effectBundlePlan{}, fmt.Errorf("exact effect plan must use %s and contain 1 through %d steps", effectBundleInputSchemaV1, actionpermit.MaxBundleSteps)
	}
	seenSteps := make(map[string]struct{}, len(plan.Steps))
	seenTasks := make(map[string]struct{}, len(plan.Steps))
	for index := range plan.Steps {
		step := &plan.Steps[index]
		if !effectBundleRouteID(step.StepID) || !effectBundleRouteID(step.ConnectorID) ||
			!effectBundleRouteID(step.OperationID) || !effectBundleRouteID(step.TaskID) {
			return effectBundlePlan{}, fmt.Errorf("exact effect plan step %d contains an invalid identifier", index)
		}
		if _, duplicate := seenSteps[step.StepID]; duplicate {
			return effectBundlePlan{}, fmt.Errorf("exact effect plan repeats step ID %q", step.StepID)
		}
		if _, duplicate := seenTasks[step.TaskID]; duplicate {
			return effectBundlePlan{}, fmt.Errorf("exact effect plan repeats task ID %q", step.TaskID)
		}
		seenSteps[step.StepID] = struct{}{}
		seenTasks[step.TaskID] = struct{}{}
		if step.RequestPath != "" && (!filepath.IsAbs(step.RequestPath) || filepath.Clean(step.RequestPath) != step.RequestPath) {
			return effectBundlePlan{}, fmt.Errorf("exact effect plan step %q request_path must be absolute and clean", step.StepID)
		}
	}
	sort.Slice(plan.Steps, func(left, right int) bool { return plan.Steps[left].StepID < plan.Steps[right].StepID })
	return plan, nil
}

func effectBundleRouteID(value string) bool {
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	for index, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || index > 0 && (character == '.' || character == '_' || character == '-') {
			continue
		}
		return false
	}
	return true
}

func effectBundleConnectorIDs(plan effectBundlePlan) []string {
	seen := make(map[string]struct{}, len(plan.Steps))
	for _, step := range plan.Steps {
		seen[step.ConnectorID] = struct{}{}
	}
	connectors := make([]string, 0, len(seen))
	for connectorID := range seen {
		connectors = append(connectors, connectorID)
	}
	slices.Sort(connectors)
	return connectors
}

func requireAdmittedBundleAuthority(admitted permitAdmission, keyID string, public ed25519.PublicKey, connectorIDs []string) error {
	matched := false
	for _, authority := range admitted.ActionAuthorities {
		if !effectBundleRouteID(authority.KeyID) {
			return errors.New("admission response contains an invalid action authority ID")
		}
		decoded, err := base64.StdEncoding.DecodeString(authority.PublicKey)
		if err != nil || len(decoded) != ed25519.PublicKeySize || base64.StdEncoding.EncodeToString(decoded) != authority.PublicKey {
			return errors.New("admission response contains an invalid action authority")
		}
		if authority.KeyID != keyID {
			continue
		}
		if matched || !ed25519.PublicKey(decoded).Equal(public) {
			return errors.New("signing key does not uniquely match the admitted action authority")
		}
		for _, connectorID := range connectorIDs {
			if !slices.Contains(authority.ConnectorIDs, connectorID) {
				return errors.New("signing authority is not admitted for every bundled connector")
			}
		}
		matched = true
	}
	if !matched {
		return errors.New("signing key does not match an admitted action authority")
	}
	return nil
}

func prepareEffectBundleSteps(
	plan effectBundlePlan,
	context effectBundleContext,
	trustPath, keyID string,
	public ed25519.PublicKey,
	validFor time.Duration,
) ([]effectBundlePreparedStep, error) {
	prepared := make([]effectBundlePreparedStep, 0, len(plan.Steps))
	for _, planned := range plan.Steps {
		if !slices.Contains(context.intent.ConnectorIDs, planned.ConnectorID) ||
			!slices.Contains(context.admitted.ConnectorIDs, planned.ConnectorID) {
			return nil, fmt.Errorf("bundle connector %q is not bound by intent and admission", planned.ConnectorID)
		}
		operation, err := validateActionTrust(
			trustPath, context.intent, planned.ConnectorID, planned.OperationID, keyID, public, validFor,
		)
		if err != nil {
			return nil, fmt.Errorf("bundle step %q: %w", planned.StepID, err)
		}
		var request []byte
		if planned.RequestPath != "" {
			if operation.ContentType == "" {
				return nil, fmt.Errorf("bundle step %q operation does not accept a request body", planned.StepID)
			}
			request, err = securefile.Read(planned.RequestPath, maxPermitRequestBytes, securefile.TrustFile)
			if err != nil {
				return nil, fmt.Errorf("read bundle step %q request: %w", planned.StepID, err)
			}
			if err := validatePermitRequest(request); err != nil {
				return nil, fmt.Errorf("bundle step %q: %w", planned.StepID, err)
			}
		} else if operation.ContentType != "" {
			return nil, fmt.Errorf("bundle step %q operation requires request_path", planned.StepID)
		}
		prepared = append(prepared, effectBundlePreparedStep{
			signed: actionpermit.BundleStep{
				StepID: planned.StepID, ConnectorID: planned.ConnectorID, OperationID: planned.OperationID,
				OperationDigest: operation.PolicyDigest, TaskID: planned.TaskID,
				RequestDigest: actionpermit.RequestDigest(request), RequestBytes: int64(len(request)), ContentType: operation.ContentType,
			},
			operation: operation,
		})
	}
	return prepared, nil
}

func trustedEffectBundleAuthorities(
	context effectBundleContext,
	plan effectBundlePlan,
	trustPath string,
	validFor time.Duration,
) (map[string]ed25519.PublicKey, []effectBundlePreparedStep, error) {
	connectorIDs := effectBundleConnectorIDs(plan)
	trusted := make(map[string]ed25519.PublicKey)
	var baseline []effectBundlePreparedStep
	for _, authority := range context.admitted.ActionAuthorities {
		if !effectBundleRouteID(authority.KeyID) {
			return nil, nil, errors.New("admission response contains an invalid action authority ID")
		}
		public, err := base64.StdEncoding.DecodeString(authority.PublicKey)
		if err != nil || len(public) != ed25519.PublicKeySize || base64.StdEncoding.EncodeToString(public) != authority.PublicKey {
			return nil, nil, errors.New("admission response contains an invalid action authority")
		}
		coversAll := true
		for _, connectorID := range connectorIDs {
			if !slices.Contains(authority.ConnectorIDs, connectorID) {
				coversAll = false
				break
			}
		}
		if !coversAll {
			continue
		}
		if _, duplicate := trusted[authority.KeyID]; duplicate {
			return nil, nil, fmt.Errorf("admission response repeats action authority %q", authority.KeyID)
		}
		prepared, err := prepareEffectBundleSteps(plan, context, trustPath, authority.KeyID, ed25519.PublicKey(public), validFor)
		if err != nil {
			return nil, nil, err
		}
		if baseline == nil {
			baseline = prepared
		} else if !reflect.DeepEqual(baseline, prepared) {
			return nil, nil, errors.New("admitted authorities do not agree on every trusted bundled operation")
		}
		trusted[authority.KeyID] = ed25519.PublicKey(append([]byte(nil), public...))
	}
	if len(trusted) < context.threshold || baseline == nil {
		return nil, nil, errors.New("fewer admitted authorities cover every bundled connector than the approval threshold")
	}
	return trusted, baseline, nil
}

func buildEffectBundleStatement(
	context effectBundleContext,
	bundleID string,
	prepared []effectBundlePreparedStep,
	notBefore, expiresAt string,
) actionpermit.BundleStatement {
	steps := make([]actionpermit.BundleStep, len(prepared))
	for index := range prepared {
		steps[index] = prepared[index].signed
	}
	return actionpermit.BundleStatement{
		SchemaVersion: actionpermit.SchemaV4, EffectMode: actionpermit.EffectModeAuthorized,
		ApprovalThreshold: context.threshold, NodeID: context.intent.NodeID, TenantID: context.intent.TenantID,
		InstanceID: context.intent.InstanceID, Generation: context.intent.Generation,
		CapsuleDigest: context.admitted.CapsuleDigest, PolicyDigest: context.admitted.PolicyDigest,
		RoutePolicyDigest: context.admitted.RoutePolicyDigest, BundleID: bundleID, Steps: steps,
		NotBefore: notBefore, ExpiresAt: expiresAt,
	}
}

func effectBundleOutputs(raw []byte, complete bool, output, headerOutput string) ([]permitOutput, error) {
	outputs := []permitOutput{{path: output, contents: raw}}
	if headerOutput == "" {
		return outputs, nil
	}
	if !complete {
		return nil, errors.New("header output requires a complete exact effect bundle")
	}
	header, err := actionpermit.EncodeHeader(raw)
	if err != nil {
		return nil, err
	}
	return append(outputs, permitOutput{path: headerOutput, contents: []byte(header + "\n")}), nil
}

func writeEffectBundleApprovalSummary(writer io.Writer, verified actionpermit.Verified, prepared []effectBundlePreparedStep) error {
	if verified.Bundle == nil {
		return errors.New("verified artifact does not contain an exact effect bundle")
	}
	steps := make([]effectBundleStepSummary, len(prepared))
	for index := range prepared {
		steps[index] = effectBundleStepSummary{
			StepID: prepared[index].signed.StepID, ConnectorID: prepared[index].signed.ConnectorID,
			OperationID: prepared[index].signed.OperationID, Method: prepared[index].operation.Method,
			Path: prepared[index].operation.Path, TaskID: prepared[index].signed.TaskID,
		}
	}
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(effectBundleApprovalSummary{
		SchemaVersion: "steward.effect-bundle-approval-summary.v1", PermitDigest: verified.EnvelopeDigest,
		Bundle: *verified.Bundle, Steps: steps, AuthorityKey: verified.KeyID,
		AuthorityKeys: append([]string(nil), verified.KeyIDs...), ApprovalsCollected: len(verified.KeyIDs), Complete: verified.Complete,
	})
}

func compareEffectBundlePlan(plan effectBundlePlan, bundle actionpermit.BundleStatement) error {
	if plan.BundleID != bundle.BundleID || len(plan.Steps) != len(bundle.Steps) {
		return errors.New("exact effect bundle does not match the supplied plan")
	}
	for index, planned := range plan.Steps {
		signed := bundle.Steps[index]
		if planned.StepID != signed.StepID || planned.ConnectorID != signed.ConnectorID ||
			planned.OperationID != signed.OperationID || planned.TaskID != signed.TaskID {
			return fmt.Errorf("exact effect bundle step %d does not match the supplied plan", index)
		}
		var request []byte
		var err error
		if planned.RequestPath != "" {
			request, err = securefile.Read(planned.RequestPath, maxPermitRequestBytes, securefile.TrustFile)
			if err != nil {
				return fmt.Errorf("read bundle step %q request: %w", planned.StepID, err)
			}
			if err := validatePermitRequest(request); err != nil {
				return fmt.Errorf("bundle step %q: %w", planned.StepID, err)
			}
		}
		if signed.RequestDigest != actionpermit.RequestDigest(request) || signed.RequestBytes != int64(len(request)) {
			return fmt.Errorf("exact effect bundle step %q does not bind the supplied request bytes", planned.StepID)
		}
	}
	return nil
}

// auditEffectBundle is implemented with receipt correlation below the issuance
// helpers so issue and approval never depend on online Gateway state.
func auditEffectBundle(arguments []string, stdout io.Writer) error {
	return auditExactEffectBundle(arguments, stdout)
}
