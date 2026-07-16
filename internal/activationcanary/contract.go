// Package activationcanary defines the closed remote activation canary
// contract. It validates and correlates data only; it does not contact Gateway,
// Hermes, Docker, or the controller and it exposes no generic execution
// surface.
package activationcanary

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/hardrails/steward/internal/activation"
	"github.com/hardrails/steward/internal/agentrelease"
	"github.com/hardrails/steward/internal/connectorledger"
	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/gateway"
	"github.com/hardrails/steward/internal/taskpermit"
)

const (
	CommandSchemaV1 = "steward.activation-canary-command.v1"
	ResultSchemaV1  = "steward.activation-canary-result.v1"

	// MaxCommandBytes accommodates one maximally sized task permit and the
	// much smaller fixed Hermes request without inheriting the generic command
	// payload ceiling.
	MaxCommandBytes = 32 << 10
	// The qualified empty-workspace response and its three task-local receipts
	// are intentionally narrower than their generic Gateway counterparts. The
	// complete canonical projection must fit with protocol-4 report framing.
	MaxTerminalResultBytes   = 4 << 10
	MaxGatewayEvidenceBytes  = 8 << 10
	MaxResultBytes           = 12 << 10
	maxReceiptAuthorityBytes = 256
)

var (
	ErrInvalidCommand = errors.New("invalid activation canary command")
	ErrInvalidResult  = errors.New("invalid activation canary result")

	identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	grantIDPattern    = regexp.MustCompile(`^grant-[a-f0-9]{64}$`)
	hermesRunPattern  = regexp.MustCompile(`^run_[a-f0-9]{32}$`)
)

// ReceiptAuthorityV1 pins the Gateway receipt identity expected for this
// activation. The public key is supplied independently at verification time;
// placing only its digest here avoids treating this unsigned payload as trust.
type ReceiptAuthorityV1 struct {
	NodeID          string `json:"node_id"`
	Epoch           uint64 `json:"epoch"`
	PublicKeySHA256 string `json:"public_key_sha256"`
}

// CommandV1 is the only remote activation canary recipe. RequestBase64 is the
// exact canonical Hermes workspace-audit request. ExecutorBeginBase64 is the
// exact admission-bound activation begin marker. TaskPermit is the canonical
// HTTP-header representation of one tenant-signed permit. There is no URL,
// path, method, prompt, command, environment, or extension field.
type CommandV1 struct {
	SchemaVersion       string                                        `json:"schema_version"`
	ActivationID        string                                        `json:"activation_id"`
	AdmissionDigest     string                                        `json:"admission_digest"`
	Admission           controlprotocol.ExecutorAdmissionProjectionV1 `json:"admission"`
	ExecutorBeginBase64 string                                        `json:"executor_begin_base64"`
	GrantID             string                                        `json:"grant_id"`
	OperationID         string                                        `json:"operation_id"`
	TaskPermit          string                                        `json:"task_permit"`
	RequestBase64       string                                        `json:"request_base64"`
	Deadline            string                                        `json:"deadline"`
	ReceiptAuthority    ReceiptAuthorityV1                            `json:"receipt_authority"`
}

// AdmissionContextV1 is trusted local context, not wire data. Projection must
// be the exact protocol-v4 admission projection retained for the successful
// admission report. The workload identities come from the already verified
// outer tenant command. The projection's begin digest is resolved through the
// command's exact canonical Executor begin marker.
type AdmissionContextV1 struct {
	NodeID     string
	TenantID   string
	InstanceID string
	Projection controlprotocol.ExecutorAdmissionProjectionV1
}

// VerifiedCommandV1 is constructible only by VerifyCommandV1. Accessors return
// copies so later mutation cannot change the verified request or authority.
type VerifiedCommandV1 struct {
	command    CommandV1
	commandKey string
	permit     taskpermit.Verified
	request    []byte
	deadline   time.Time
	checkpoint checkpointExpectationV1
}

type checkpointExpectationV1 struct {
	Binding           activation.BindingV1
	RuntimeRef        string
	CapsuleDigest     string
	RoutePolicyDigest string
	GrantID           string
}

// ResultV1 carries the bounded raw terminal observation and the original
// signed Gateway receipt lines. Qualified is meaningful only after
// VerifyResultV1 authenticates those receipts and independently verifies the
// closed Hermes result.
type ResultV1 struct {
	SchemaVersion              string `json:"schema_version"`
	ActivationID               string `json:"activation_id"`
	AdmissionDigest            string `json:"admission_digest"`
	TaskDigest                 string `json:"task_digest"`
	PermitDigest               string `json:"permit_digest"`
	RunID                      string `json:"run_id"`
	TerminalResultDigest       string `json:"terminal_result_digest"`
	TerminalResultBytes        int64  `json:"terminal_result_bytes"`
	TerminalResultBase64       string `json:"terminal_result_base64"`
	GatewayEvidenceBase64      string `json:"gateway_evidence_base64"`
	ActivationCheckpointDigest string `json:"activation_checkpoint_digest"`
	Qualified                  bool   `json:"qualified"`
}

// VerifiedResultV1 retains decoded companions and their semantic verification
// results. Receipt and result bytes are copied from the parsed projection.
type VerifiedResultV1 struct {
	result          ResultV1
	commandKey      string
	terminalResult  []byte
	gatewayReceipts []byte
	hermes          activation.HermesCanaryResultV1
	gateway         activation.GatewayEvidenceResultV1
}

// VerifiedEvidenceV1 is constructible only by VerifyEvidenceV1. It retains the
// qualified canary evidence needed to construct the existing activation
// Executor checkpoint before building the terminal report.
type VerifiedEvidenceV1 struct {
	commandKey      string
	terminalResult  []byte
	gatewayReceipts []byte
	hermes          activation.HermesCanaryResultV1
	gateway         activation.GatewayEvidenceResultV1
}

// ParseCommandV1 requires the deterministic MarshalCommandV1 spelling. This
// makes AdmissionDigest and the outer signed command bind one exact byte string,
// rather than any semantically equivalent JSON encoding.
func ParseCommandV1(raw []byte) (CommandV1, error) {
	var command CommandV1
	if err := dsse.DecodeStrictInto(raw, MaxCommandBytes, &command); err != nil {
		return CommandV1{}, invalidCommand("decode: %v", err)
	}
	if err := command.Validate(); err != nil {
		return CommandV1{}, err
	}
	canonical, err := json.Marshal(command)
	if err != nil || !bytes.Equal(canonical, raw) {
		return CommandV1{}, invalidCommand("command is not canonical JSON")
	}
	return command, nil
}

// MarshalCommandV1 emits the only accepted command JSON spelling.
func MarshalCommandV1(command CommandV1) ([]byte, error) {
	if err := command.Validate(); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(command)
	if err != nil {
		return nil, invalidCommand("marshal: %v", err)
	}
	if len(raw) > MaxCommandBytes {
		return nil, invalidCommand("encoded command exceeds %d bytes", MaxCommandBytes)
	}
	return raw, nil
}

// Validate checks the closed command shape without asserting permit authority.
// VerifyCommandV1 must still be called before any Gateway interaction.
func (command CommandV1) Validate() error {
	if command.SchemaVersion != CommandSchemaV1 || !identifier(command.ActivationID) ||
		!digest(command.AdmissionDigest) || !grantIDPattern.MatchString(command.GrantID) ||
		command.OperationID != agentrelease.HermesOperationID {
		return invalidCommand("identity or fixed operation is invalid")
	}
	if err := command.Admission.Validate(); err != nil {
		return invalidCommand("admission projection: %v", err)
	}
	admissionRaw, err := json.Marshal(command.Admission)
	if err != nil || command.AdmissionDigest != dsse.Digest(admissionRaw) {
		return invalidCommand("admission digest does not identify the exact projection")
	}
	deadline, ok := canonicalTimestamp(command.Deadline)
	if !ok || deadline.IsZero() {
		return invalidCommand("deadline is not canonical UTC RFC3339Nano")
	}
	if err := command.ReceiptAuthority.validate(); err != nil {
		return invalidCommand("receipt authority: %v", err)
	}
	rawPermit, err := taskpermit.DecodeHeader(command.TaskPermit)
	if err != nil {
		return invalidCommand("task permit header: %v", err)
	}
	envelope, err := dsse.Parse(rawPermit)
	if err != nil || envelope.PayloadType != taskpermit.PayloadType || len(envelope.Signatures) != 1 {
		return invalidCommand("task permit is not one canonical task-permit envelope")
	}
	canonicalPermit, err := dsse.Marshal(envelope)
	if err != nil || !bytes.Equal(canonicalPermit, rawPermit) {
		return invalidCommand("task permit envelope is not canonical")
	}
	request, err := decodeCanonicalBase64(command.RequestBase64, agentrelease.MaxCanaryRequestBytes)
	if err != nil {
		return invalidCommand("request: %v", err)
	}
	expected, err := fixedHermesRequest(command.ActivationID)
	if err != nil || !bytes.Equal(request, expected) {
		return invalidCommand("request is not the exact Hermes workspace-audit request")
	}
	beginRaw, err := decodeCanonicalBase64(
		command.ExecutorBeginBase64,
		activation.MaxExecutorCheckpointBytes,
	)
	if err != nil {
		return invalidCommand("Executor begin marker: %v", err)
	}
	begin, err := activation.ParseExecutorBeginV1(beginRaw)
	if err != nil || begin.Binding.ActivationID != command.ActivationID {
		return invalidCommand("Executor begin marker does not match the activation: %v", err)
	}
	return nil
}

func (authority ReceiptAuthorityV1) validate() error {
	if !publicIdentity(authority.NodeID, maxReceiptAuthorityBytes) || authority.Epoch == 0 ||
		!digest(authority.PublicKeySHA256) {
		return errors.New("identity, epoch, or public-key digest is invalid")
	}
	return nil
}

// VerifyCommandV1 authenticates the tenant permit exclusively with public keys
// retained in the exact admission projection, then compares every available
// workload, policy, service, request, activation, and receipt binding.
func VerifyCommandV1(
	raw []byte,
	admission AdmissionContextV1,
	now time.Time,
	maxPermitValidity time.Duration,
) (VerifiedCommandV1, error) {
	command, err := ParseCommandV1(raw)
	if err != nil {
		return VerifiedCommandV1{}, err
	}
	if now.IsZero() {
		return VerifiedCommandV1{}, invalidCommand("node time is unavailable")
	}
	if err := admission.validate(); err != nil {
		return VerifiedCommandV1{}, invalidCommand("admission context: %v", err)
	}
	projectionRaw, err := json.Marshal(admission.Projection)
	if err != nil {
		return VerifiedCommandV1{}, invalidCommand("marshal trusted admission projection: %v", err)
	}
	commandProjectionRaw, err := json.Marshal(command.Admission)
	if err != nil || command.AdmissionDigest != dsse.Digest(projectionRaw) ||
		!bytes.Equal(projectionRaw, commandProjectionRaw) ||
		command.ActivationID != admission.Projection.ActivationID ||
		command.GrantID != admission.Projection.GrantID {
		return VerifiedCommandV1{}, invalidCommand("command does not bind the exact admission projection")
	}
	beginRaw, _ := decodeCanonicalBase64(
		command.ExecutorBeginBase64,
		activation.MaxExecutorCheckpointBytes,
	)
	begin, err := activation.ParseExecutorBeginV1(beginRaw)
	if err != nil || dsse.Digest(beginRaw) != admission.Projection.ActivationBeginDigest ||
		begin.Binding.ActivationID != command.ActivationID ||
		begin.Binding.NodeID != admission.NodeID ||
		begin.Binding.TenantID != admission.TenantID ||
		begin.Binding.InstanceID != admission.InstanceID ||
		begin.Binding.Generation != admission.Projection.Generation ||
		begin.Binding.PolicyDigest != admission.Projection.PolicyDigest ||
		begin.RuntimeRef != admission.Projection.RuntimeRef ||
		begin.CapsuleDigest != admission.Projection.CapsuleDigest {
		return VerifiedCommandV1{}, invalidCommand("Executor begin marker does not match the admitted activation")
	}
	request, _ := decodeCanonicalBase64(command.RequestBase64, agentrelease.MaxCanaryRequestBytes)
	rawPermit, _ := taskpermit.DecodeHeader(command.TaskPermit)
	trusted, err := admittedTaskAuthorities(admission.Projection.TaskAuthorities)
	if err != nil {
		return VerifiedCommandV1{}, invalidCommand("admitted task authorities: %v", err)
	}
	verified, err := taskpermit.Verify(rawPermit, trusted, now.UTC(), maxPermitValidity)
	if err != nil {
		return VerifiedCommandV1{}, invalidCommand("verify task permit: %v", err)
	}
	statement := verified.Statement
	if statement.NodeID != admission.NodeID || statement.TenantID != admission.TenantID ||
		statement.InstanceID != admission.InstanceID ||
		statement.RuntimeRef != admission.Projection.RuntimeRef ||
		statement.GrantID != admission.Projection.GrantID ||
		statement.Generation != admission.Projection.Generation ||
		statement.CapsuleDigest != admission.Projection.CapsuleDigest ||
		statement.PolicyDigest != admission.Projection.PolicyDigest ||
		statement.RoutePolicyDigest != admission.Projection.RoutePolicyDigest ||
		statement.ServiceID != agentrelease.HermesServiceID ||
		statement.ServiceID != admission.Projection.ServiceID ||
		statement.OperationID != agentrelease.HermesOperationID ||
		statement.RequestDigest != taskpermit.RequestDigest(request) ||
		statement.RequestBytes != int64(len(request)) ||
		statement.ContentType != "application/json" {
		return VerifiedCommandV1{}, invalidCommand("task permit does not match every admitted Hermes request binding")
	}
	if command.ReceiptAuthority.NodeID != gateway.ServiceTaskReceiptNodeID(statement.NodeID) {
		return VerifiedCommandV1{}, invalidCommand("Gateway receipt authority belongs to another node")
	}
	deadline, _ := canonicalTimestamp(command.Deadline)
	expiresAt, err := time.Parse(time.RFC3339, statement.ExpiresAt)
	if err != nil || !deadline.After(now.UTC()) || deadline.After(expiresAt) {
		return VerifiedCommandV1{}, invalidCommand("deadline is expired or exceeds the task permit")
	}
	return VerifiedCommandV1{
		command: cloneCommand(command), commandKey: dsse.Digest(raw), permit: verified,
		request: append([]byte(nil), request...), deadline: deadline,
		checkpoint: checkpointExpectationV1{
			Binding:           begin.Binding,
			RuntimeRef:        admission.Projection.RuntimeRef,
			CapsuleDigest:     admission.Projection.CapsuleDigest,
			RoutePolicyDigest: admission.Projection.RoutePolicyDigest,
			GrantID:           admission.Projection.GrantID,
		},
	}, nil
}

// VerifyHistoricalCommandV1 authenticates an immutable command without making
// an old proof depend on the auditor's wall clock. It verifies the permit at
// the final instant before the command deadline; VerifyResultV1 must then
// authenticate Gateway authorization and terminal receipt times inside the
// signed permit and command interval. This is not a live-execution admission
// check: nodes must use VerifyCommandV1 with their current clock.
func VerifyHistoricalCommandV1(
	raw []byte,
	admission AdmissionContextV1,
	maxPermitValidity time.Duration,
) (VerifiedCommandV1, error) {
	command, err := ParseCommandV1(raw)
	if err != nil {
		return VerifiedCommandV1{}, err
	}
	deadline, _ := canonicalTimestamp(command.Deadline)
	return VerifyCommandV1(
		raw,
		admission,
		deadline.Add(-time.Nanosecond),
		maxPermitValidity,
	)
}

func (admission AdmissionContextV1) validate() error {
	if !publicIdentity(admission.NodeID, 128) || !publicIdentity(admission.TenantID, 128) ||
		!publicIdentity(admission.InstanceID, 256) {
		return errors.New("workload identity is invalid")
	}
	if err := admission.Projection.Validate(); err != nil {
		return err
	}
	projection := admission.Projection
	if projection.Status != "created" && projection.Status != "running" ||
		projection.GrantID == "" || projection.ServiceID != agentrelease.HermesServiceID ||
		len(projection.TaskAuthorities) == 0 || projection.RoutePolicyDigest == "" ||
		projection.ActivationID == "" || projection.ActivationBeginDigest == "" {
		return errors.New("projection is not a usable Hermes activation admission")
	}
	return nil
}

func admittedTaskAuthorities(authorities []controlprotocol.ExecutorTaskAuthorityV1) (map[string]ed25519.PublicKey, error) {
	trusted := make(map[string]ed25519.PublicKey, len(authorities))
	for _, authority := range authorities {
		public, err := base64.StdEncoding.DecodeString(authority.PublicKey)
		if err != nil || len(public) != ed25519.PublicKeySize ||
			base64.StdEncoding.EncodeToString(public) != authority.PublicKey {
			return nil, errors.New("task authority is not canonical Ed25519")
		}
		trusted[authority.KeyID] = ed25519.PublicKey(append([]byte(nil), public...))
	}
	if len(trusted) == 0 {
		return nil, errors.New("task authority set is empty")
	}
	return trusted, nil
}

// Command returns a deep copy of the validated wire value.
func (verified VerifiedCommandV1) Command() CommandV1 { return cloneCommand(verified.command) }

// Permit returns the authenticated task permit and its exact envelope digest.
func (verified VerifiedCommandV1) Permit() taskpermit.Verified { return verified.permit }

// Request returns a copy of the exact request bytes bound by the permit.
func (verified VerifiedCommandV1) Request() []byte {
	return append([]byte(nil), verified.request...)
}

// Deadline returns the absolute canary deadline in UTC.
func (verified VerifiedCommandV1) Deadline() time.Time { return verified.deadline }

// Result returns the authenticated bounded projection.
func (verified VerifiedResultV1) Result() ResultV1 { return verified.result }

// TerminalResult returns a copy of the exact verified Hermes terminal bytes.
func (verified VerifiedResultV1) TerminalResult() []byte {
	return append([]byte(nil), verified.terminalResult...)
}

// GatewayReceipts returns a copy of the three verified portable receipt lines.
func (verified VerifiedResultV1) GatewayReceipts() []byte {
	return append([]byte(nil), verified.gatewayReceipts...)
}

// Hermes returns the closed Hermes workspace-audit observation.
func (verified VerifiedResultV1) Hermes() activation.HermesCanaryResultV1 {
	return verified.hermes
}

// Gateway returns a copy of the verified Gateway evidence projection.
func (verified VerifiedResultV1) Gateway() activation.GatewayEvidenceResultV1 {
	result := verified.gateway
	result.Receipts = append([]byte(nil), verified.gateway.Receipts...)
	return result
}

// ParseResultV1 requires deterministic JSON and verifies all self-contained
// digests and encodings. It does not authenticate Gateway receipts.
func ParseResultV1(raw []byte) (ResultV1, error) {
	var result ResultV1
	if err := dsse.DecodeStrictInto(raw, MaxResultBytes, &result); err != nil {
		return ResultV1{}, invalidResult("decode: %v", err)
	}
	if err := result.Validate(); err != nil {
		return ResultV1{}, err
	}
	canonical, err := json.Marshal(result)
	if err != nil || !bytes.Equal(canonical, raw) {
		return ResultV1{}, invalidResult("result is not canonical JSON")
	}
	return result, nil
}

// MarshalResultV1 emits the only accepted result JSON spelling. Successful
// parsing is not proof; VerifyResultV1 is the trust-boundary operation.
func MarshalResultV1(result ResultV1) ([]byte, error) {
	if err := result.Validate(); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(result)
	if err != nil {
		return nil, invalidResult("marshal: %v", err)
	}
	if len(raw) > MaxResultBytes {
		return nil, invalidResult("encoded result exceeds %d bytes", MaxResultBytes)
	}
	return raw, nil
}

// Validate checks result bounds, canonical companion encodings, and exact
// self-declared digest and length values without trusting Qualified.
func (result ResultV1) Validate() error {
	if result.SchemaVersion != ResultSchemaV1 || !identifier(result.ActivationID) ||
		!digest(result.AdmissionDigest) || !digest(result.TaskDigest) ||
		!digest(result.PermitDigest) || !hermesRunPattern.MatchString(result.RunID) ||
		!digest(result.TerminalResultDigest) || !digest(result.ActivationCheckpointDigest) ||
		!result.Qualified {
		return invalidResult("identity, digest, run, or qualification field is invalid")
	}
	terminal, err := decodeCanonicalBase64(result.TerminalResultBase64, MaxTerminalResultBytes)
	if err != nil || result.TerminalResultBytes != int64(len(terminal)) ||
		result.TerminalResultDigest != dsse.Digest(terminal) {
		return invalidResult("terminal result encoding, length, or digest is invalid")
	}
	receipts, err := decodeCanonicalBase64(result.GatewayEvidenceBase64, MaxGatewayEvidenceBytes)
	if err != nil || len(receipts) == 0 || receipts[len(receipts)-1] != '\n' ||
		bytes.Count(receipts, []byte{'\n'}) != 3 || bytes.Contains(receipts, []byte{'\r'}) {
		return invalidResult("Gateway evidence is not three canonical receipt lines")
	}
	return nil
}

// VerifyEvidenceV1 authenticates and qualifies the raw canary companions before
// an Executor checkpoint exists. It also proves that the eventual canonical
// result projection can fit its protocol-4 report budget. Callers may then use
// the returned Gateway value with activation.MarshalExecutorCheckpointV1, but
// must not append that checkpoint until BuildResultV1 succeeds.
func VerifyEvidenceV1(
	command VerifiedCommandV1,
	runID string,
	terminal []byte,
	receipts []byte,
	receiptPublic ed25519.PublicKey,
) (VerifiedEvidenceV1, error) {
	result := projectedResult(command, runID, terminal, receipts, "sha256:"+strings.Repeat("0", 64))
	if _, err := MarshalResultV1(result); err != nil {
		return VerifiedEvidenceV1{}, err
	}
	hermes, gatewayResult, err := verifyProjectedEvidence(
		command, result, terminal, receipts, receiptPublic,
	)
	if err != nil {
		return VerifiedEvidenceV1{}, err
	}
	return VerifiedEvidenceV1{
		commandKey:      command.commandKey,
		terminalResult:  append([]byte(nil), terminal...),
		gatewayReceipts: append([]byte(nil), receipts...),
		hermes:          hermes,
		gateway:         cloneGatewayEvidence(gatewayResult),
	}, nil
}

// BuildCheckpointV1 constructs the only activation checkpoint that can match
// this verified command and evidence. It does not append the checkpoint to the
// Executor receipt stream; callers must first pass the returned bytes through
// BuildResultV1, then request the existing closed Executor checkpoint endpoint.
func BuildCheckpointV1(
	command VerifiedCommandV1,
	evidence VerifiedEvidenceV1,
) ([]byte, error) {
	if !digest(command.commandKey) || command.command.SchemaVersion != CommandSchemaV1 ||
		evidence.commandKey != command.commandKey ||
		len(evidence.terminalResult) == 0 || len(evidence.gatewayReceipts) == 0 ||
		!bytes.Equal(evidence.gatewayReceipts, evidence.gateway.Receipts) {
		return nil, invalidResult("verified command or Gateway evidence is unavailable")
	}
	expected := command.checkpoint
	return activation.MarshalExecutorCheckpointV1(
		expected.Binding,
		expected.RuntimeRef,
		expected.CapsuleDigest,
		expected.RoutePolicyDigest,
		expected.GrantID,
		cloneGatewayEvidence(evidence.gateway),
	)
}

// VerifyResultV1 authenticates all three portable Gateway receipts with the
// independently supplied key and expected node/epoch, correlates their full
// task-permit bindings, and verifies the terminal Hermes workspace audit. Use
// VerifyCheckpointV1 as well when the checkpoint companion is available.
func VerifyResultV1(
	command VerifiedCommandV1,
	raw []byte,
	receiptPublic ed25519.PublicKey,
) (VerifiedResultV1, error) {
	result, err := ParseResultV1(raw)
	if err != nil {
		return VerifiedResultV1{}, err
	}
	if command.command.SchemaVersion != CommandSchemaV1 || !digest(command.commandKey) ||
		command.permit.EnvelopeDigest == "" ||
		len(command.request) == 0 || command.deadline.IsZero() {
		return VerifiedResultV1{}, invalidResult("verified command is unavailable")
	}
	statement := command.permit.Statement
	expectedTaskDigest := taskpermit.TaskDigest(statement.TenantID, statement.InstanceID, statement.TaskID)
	if result.ActivationID != command.command.ActivationID ||
		result.AdmissionDigest != command.command.AdmissionDigest ||
		result.TaskDigest != expectedTaskDigest ||
		result.PermitDigest != command.permit.EnvelopeDigest {
		return VerifiedResultV1{}, invalidResult("result does not match the verified command and task permit")
	}
	terminal, _ := decodeCanonicalBase64(result.TerminalResultBase64, MaxTerminalResultBytes)
	receipts, _ := decodeCanonicalBase64(result.GatewayEvidenceBase64, MaxGatewayEvidenceBytes)
	hermes, gatewayResult, err := verifyProjectedEvidence(
		command, result, terminal, receipts, receiptPublic,
	)
	if err != nil {
		return VerifiedResultV1{}, err
	}
	return VerifiedResultV1{
		result:          result,
		commandKey:      command.commandKey,
		terminalResult:  append([]byte(nil), terminal...),
		gatewayReceipts: append([]byte(nil), receipts...),
		hermes:          hermes, gateway: cloneGatewayEvidence(gatewayResult),
	}, nil
}

func verifyProjectedEvidence(
	command VerifiedCommandV1,
	result ResultV1,
	terminal []byte,
	receipts []byte,
	receiptPublic ed25519.PublicKey,
) (activation.HermesCanaryResultV1, activation.GatewayEvidenceResultV1, error) {
	if len(receiptPublic) != ed25519.PublicKeySize ||
		controlprotocol.ExecutorEvidencePublicKeySHA256(receiptPublic) != command.command.ReceiptAuthority.PublicKeySHA256 {
		return activation.HermesCanaryResultV1{}, activation.GatewayEvidenceResultV1{},
			invalidResult("Gateway receipt public key does not match its pin")
	}
	hermes, err := activation.VerifyHermesWorkspaceAuditResultV1(
		terminal,
		agentrelease.HermesSessionIDPrefix+"-"+command.command.ActivationID,
	)
	if err != nil {
		return activation.HermesCanaryResultV1{}, activation.GatewayEvidenceResultV1{},
			invalidResult("verify Hermes workspace audit: %v", err)
	}
	if hermes.RunID != result.RunID {
		return activation.HermesCanaryResultV1{}, activation.GatewayEvidenceResultV1{},
			invalidResult("Hermes run ID does not match the projected result")
	}
	gatewayResult, err := activation.VerifyGatewayEvidenceV1(
		activation.GatewayEvidenceRequestV1{
			Task: command.permit, TaskProtocol: connectorledger.TaskProtocolLifecycleV1,
			RunID: result.RunID, Result: terminal,
			ReceiptPublicKey: receiptPublic,
			ReceiptEpoch:     command.command.ReceiptAuthority.Epoch,
		},
		receipts,
	)
	if err != nil {
		return activation.HermesCanaryResultV1{}, activation.GatewayEvidenceResultV1{},
			invalidResult("verify Gateway task evidence: %v", err)
	}
	coordinate := gatewayResult.Coordinate
	if coordinate.ReceiptNodeID != command.command.ReceiptAuthority.NodeID ||
		coordinate.ReceiptEpoch != command.command.ReceiptAuthority.Epoch ||
		coordinate.PublicKeySHA256 != command.command.ReceiptAuthority.PublicKeySHA256 ||
		gatewayResult.Canary.TaskDigest != result.TaskDigest ||
		gatewayResult.Canary.PermitDigest != result.PermitDigest ||
		gatewayResult.Canary.ResultDigest != result.TerminalResultDigest ||
		gatewayResult.Canary.ResultBytes != result.TerminalResultBytes {
		return activation.HermesCanaryResultV1{}, activation.GatewayEvidenceResultV1{},
			invalidResult("verified Gateway evidence does not match the projected result")
	}
	authorizedAt, err := time.Parse(time.RFC3339Nano, gatewayResult.AuthorizedAt)
	if err != nil {
		return activation.HermesCanaryResultV1{}, activation.GatewayEvidenceResultV1{},
			invalidResult("Gateway authorization time is invalid")
	}
	terminalAt, err := time.Parse(time.RFC3339Nano, gatewayResult.TerminalAt)
	if err != nil {
		return activation.HermesCanaryResultV1{}, activation.GatewayEvidenceResultV1{},
			invalidResult("Gateway terminal time is invalid")
	}
	notBefore, err := time.Parse(time.RFC3339, command.permit.Statement.NotBefore)
	if err != nil || authorizedAt.Before(notBefore) ||
		authorizedAt.After(command.deadline) || terminalAt.After(command.deadline) {
		return activation.HermesCanaryResultV1{}, activation.GatewayEvidenceResultV1{},
			invalidResult("Gateway evidence falls outside the authorized canary deadline")
	}
	return hermes, gatewayResult, nil
}

// VerifyCheckpointV1 binds one canonical existing activation checkpoint to the
// verified result, exact Gateway receipts, admission projection, and outer
// workload identity. It does not assert that the checkpoint was appended to an
// Executor receipt stream; the later Executor evidence verifier proves that.
func VerifyCheckpointV1(
	command VerifiedCommandV1,
	result VerifiedResultV1,
	checkpointRaw []byte,
) error {
	checkpoint, err := activation.ParseExecutorCheckpointV1(checkpointRaw)
	if err != nil {
		return invalidResult("parse activation checkpoint: %v", err)
	}
	expected := command.checkpoint
	if !digest(command.commandKey) || result.commandKey != command.commandKey ||
		result.result.ActivationID != command.command.ActivationID ||
		result.result.AdmissionDigest != command.command.AdmissionDigest ||
		checkpoint.Binding.ActivationID != command.command.ActivationID ||
		checkpoint.Binding != expected.Binding ||
		checkpoint.RuntimeRef != expected.RuntimeRef ||
		checkpoint.CapsuleDigest != expected.CapsuleDigest ||
		checkpoint.RoutePolicyDigest != expected.RoutePolicyDigest ||
		checkpoint.GrantID != expected.GrantID ||
		checkpoint.GatewayReceiptsDigest != dsse.Digest(result.gatewayReceipts) ||
		checkpoint.GatewayEvidence != result.gateway.Coordinate ||
		checkpoint.Canary != result.gateway.Canary ||
		checkpoint.AuthorizedAt != result.gateway.AuthorizedAt ||
		checkpoint.TerminalAt != result.gateway.TerminalAt ||
		result.result.ActivationCheckpointDigest != dsse.Digest(checkpointRaw) {
		return invalidResult("activation checkpoint does not match the qualified canary and admission")
	}
	return nil
}

// BuildResultV1 verifies raw Gateway and Hermes evidence, requires an exact
// matching canonical activation checkpoint, and then returns the bounded
// qualified projection. Compute checkpointRaw with BuildCheckpointV1 but append
// it only after this function succeeds, so projection overflow can never claim
// a checkpoint.
func BuildResultV1(
	command VerifiedCommandV1,
	runID string,
	terminal []byte,
	receipts []byte,
	checkpointRaw []byte,
	receiptPublic ed25519.PublicKey,
) ([]byte, VerifiedResultV1, error) {
	if _, err := VerifyEvidenceV1(command, runID, terminal, receipts, receiptPublic); err != nil {
		return nil, VerifiedResultV1{}, err
	}
	checkpointDigest, err := activation.ExecutorCheckpointDigestV1(checkpointRaw)
	if err != nil {
		return nil, VerifiedResultV1{}, invalidResult("activation checkpoint: %v", err)
	}
	result := projectedResult(command, runID, terminal, receipts, checkpointDigest)
	raw, err := MarshalResultV1(result)
	if err != nil {
		return nil, VerifiedResultV1{}, err
	}
	verified, err := VerifyResultV1(command, raw, receiptPublic)
	if err != nil {
		return nil, VerifiedResultV1{}, err
	}
	if err := VerifyCheckpointV1(command, verified, checkpointRaw); err != nil {
		return nil, VerifiedResultV1{}, err
	}
	return raw, verified, nil
}

func projectedResult(
	command VerifiedCommandV1,
	runID string,
	terminal []byte,
	receipts []byte,
	checkpointDigest string,
) ResultV1 {
	statement := command.permit.Statement
	return ResultV1{
		SchemaVersion:              ResultSchemaV1,
		ActivationID:               command.command.ActivationID,
		AdmissionDigest:            command.command.AdmissionDigest,
		TaskDigest:                 taskpermit.TaskDigest(statement.TenantID, statement.InstanceID, statement.TaskID),
		PermitDigest:               command.permit.EnvelopeDigest,
		RunID:                      runID,
		TerminalResultDigest:       dsse.Digest(terminal),
		TerminalResultBytes:        int64(len(terminal)),
		TerminalResultBase64:       base64.StdEncoding.EncodeToString(terminal),
		GatewayEvidenceBase64:      base64.StdEncoding.EncodeToString(receipts),
		ActivationCheckpointDigest: checkpointDigest,
		Qualified:                  true,
	}
}

func cloneGatewayEvidence(
	result activation.GatewayEvidenceResultV1,
) activation.GatewayEvidenceResultV1 {
	result.Receipts = append([]byte(nil), result.Receipts...)
	return result
}

func cloneCommand(command CommandV1) CommandV1 {
	command.Admission.TaskAuthorities = append(
		[]controlprotocol.ExecutorTaskAuthorityV1(nil),
		command.Admission.TaskAuthorities...,
	)
	command.Admission.EgressRouteIDs = append(
		[]string(nil),
		command.Admission.EgressRouteIDs...,
	)
	command.Admission.ConnectorIDs = append(
		[]string(nil),
		command.Admission.ConnectorIDs...,
	)
	return command
}

func fixedHermesRequest(activationID string) ([]byte, error) {
	return agentrelease.BuildCanaryRequest(agentrelease.RequestRecipe{
		Input:           agentrelease.HermesWorkspaceAuditInput,
		SessionIDPrefix: agentrelease.HermesSessionIDPrefix,
	}, activationID)
}

func decodeCanonicalBase64(value string, maximum int) ([]byte, error) {
	if value == "" || maximum <= 0 || len(value) > base64.StdEncoding.EncodedLen(maximum) {
		return nil, errors.New("base64 value is empty or exceeds its limit")
	}
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(raw) == 0 || len(raw) > maximum ||
		base64.StdEncoding.EncodeToString(raw) != value {
		return nil, errors.New("base64 value is not one canonical standard encoding")
	}
	return raw, nil
}

func identifier(value string) bool { return identifierPattern.MatchString(value) }

func digest(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+64 {
		return false
	}
	for _, character := range value[len("sha256:"):] {
		if character < '0' || character > '9' && character < 'a' || character > 'f' {
			return false
		}
	}
	return true
}

func publicIdentity(value string, maximum int) bool {
	if value == "" || len(value) > maximum || !utf8.ValidString(value) ||
		strings.TrimSpace(value) != value || strings.ContainsRune(value, '\x00') {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func canonicalTimestamp(value string) (time.Time, bool) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.IsZero() || parsed.UTC().Format(time.RFC3339Nano) != value {
		return time.Time{}, false
	}
	return parsed.UTC(), true
}

func invalidCommand(format string, arguments ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidCommand, fmt.Sprintf(format, arguments...))
}

func invalidResult(format string, arguments ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidResult, fmt.Sprintf(format, arguments...))
}
