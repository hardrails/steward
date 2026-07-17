package executoruplink

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/gateway"
	stewarduplink "github.com/hardrails/steward/internal/uplink"
)

const maxWireBytes = 1 << 20
const maxCommandsPerPoll = 128
const maxBackoff = 5 * time.Minute

type pollResponse struct {
	ProtocolVersion int               `json:"protocol_version,omitempty"`
	Commands        []json.RawMessage `json:"commands"`
}

type pollRequest struct {
	ProtocolVersion int      `json:"protocol_version"`
	NodeID          string   `json:"node_id"`
	CredentialScope string   `json:"credential_scope"`
	Capabilities    []string `json:"capabilities"`
}

type reportResponse struct {
	Applied bool `json:"applied"`
}

// Config enables the optional generic Executor uplink. Plain HTTP is refused for
// remote hosts unless the operator explicitly acknowledges it; loopback remains
// available for local development and appliance-side reverse proxies.
type Config struct {
	BaseURL           string
	CredentialPath    string
	PollInterval      time.Duration
	AllowInsecureHTTP bool
	HTTPClient        *http.Client
	Logger            *slog.Logger
	Handler           http.Handler
	LocalToken        string
	State             *StateStore
	// SecureExecutor, SecureNodeID, and ProtectedTransport are explicit
	// trust-boundary guards required for a node-scoped v2 credential.
	// ProtectedTransport is accepted only with an HTTPS URL; SecureExecutor and
	// SecureNodeID must describe the successfully enabled signed-admission path.
	SecureExecutor     bool
	SecureNodeID       string
	ProtectedTransport bool
	CommandPolicy      *admission.SitePolicy
	Now                func() time.Time
	// ProtocolVersion zero preserves tenant v1 and selects node v3 only when a
	// DeliveryState store is present. Explicit 2 keeps the signed-command v2
	// compatibility protocol; explicit 3 or 4 requires DeliveryState. Protocol
	// 4 is never selected implicitly.
	ProtocolVersion int
	DeliveryState   *DeliveryStore
	// GatewayControl enables only the finite activation-canary protocol. The
	// node advertises that capability only for protocol 4 when this exact
	// host-local client is configured.
	GatewayControl *gateway.ControlClient
	// ValidateOnly checks delivery state without converting pre-crash executing
	// records into outcome_unknown. Normal startup leaves this false.
	ValidateOnly bool
}

type Poller struct {
	pollURL, reportURL string
	credentialPath     string
	expected           *stewarduplink.Credential
	interval           time.Duration
	client             *http.Client
	logger             *slog.Logger
	dispatcher         dispatcher
	security           stewarduplink.CredentialSecurity
	commandPolicy      *admission.SitePolicy
	now                func() time.Time
	protocolVersion    int
	deliveryState      *DeliveryStore
	canaryRunner       *activationCanaryRunner
}

func NewPoller(cfg Config) (*Poller, error) {
	if cfg.PollInterval <= 0 || cfg.Handler == nil || cfg.LocalToken == "" || cfg.State == nil {
		return nil, errors.New("uplink requires a positive poll interval, local handler/token, and state store")
	}
	base, err := url.Parse(cfg.BaseURL)
	if err != nil || base.Host == "" || (base.Scheme != "https" && base.Scheme != "http") {
		return nil, fmt.Errorf("uplink URL must be an absolute http(s) URL")
	}
	if base.Scheme == "http" && !cfg.AllowInsecureHTTP && !isLoopbackHost(base.Hostname()) {
		return nil, errors.New("remote uplink HTTP is disabled; use HTTPS or explicitly allow insecure HTTP")
	}
	security := stewarduplink.CredentialSecurity{
		SecureExecutor: cfg.SecureExecutor, ProtectedTransport: cfg.ProtectedTransport && base.Scheme == "https",
	}
	credential, err := stewarduplink.LoadCredentialWithSecurity(cfg.CredentialPath, security)
	if err != nil {
		return nil, err
	}
	if credential.NodeScoped() {
		if cfg.SecureNodeID == "" || cfg.SecureNodeID != credential.NodeID {
			return nil, errors.New("node-scoped uplink credential node_id must match the configured secure Executor node")
		}
		if !cfg.ProtectedTransport || base.Scheme != "https" {
			return nil, errors.New("node-scoped uplink requires caller-confirmed protected transport and an HTTPS URL")
		}
		if cfg.CommandPolicy == nil {
			return nil, errors.New("node-scoped uplink requires a verified site command policy")
		}
		if err := cfg.CommandPolicy.Validate(); err != nil {
			return nil, fmt.Errorf("invalid node-scoped command policy: %w", err)
		}
		if len(cfg.CommandPolicy.SiteCleanupCommandKeys) == 0 {
			return nil, errors.New("node-scoped uplink site policy has no site cleanup command key")
		}
	}
	protocolVersion := cfg.ProtocolVersion
	if credential.NodeScoped() {
		if protocolVersion == 0 {
			protocolVersion = 2
			if cfg.DeliveryState != nil {
				protocolVersion = controlprotocol.ExecutorProtocolV3
			}
		}
		if protocolVersion != 2 &&
			protocolVersion != controlprotocol.ExecutorProtocolV3 &&
			protocolVersion != controlprotocol.ExecutorProtocolV4 {
			return nil, fmt.Errorf(
				"node-scoped uplink protocol version must be 2, %d, or %d",
				controlprotocol.ExecutorProtocolV3,
				controlprotocol.ExecutorProtocolV4,
			)
		}
		if protocolVersion == controlprotocol.ExecutorProtocolV3 ||
			protocolVersion == controlprotocol.ExecutorProtocolV4 {
			if cfg.DeliveryState == nil {
				return nil, fmt.Errorf(
					"executor uplink protocol %d requires durable delivery state",
					protocolVersion,
				)
			}
			if cfg.DeliveryState.NodeID() != credential.NodeID {
				return nil, errors.New("executor delivery state node ID does not match the uplink credential")
			}
			if err := cfg.DeliveryState.PrepareProtocol(protocolVersion, true); err != nil {
				return nil, fmt.Errorf("validate executor delivery protocol state: %w", err)
			}
			if !cfg.ValidateOnly {
				if err := cfg.DeliveryState.PrepareProtocol(protocolVersion, false); err != nil {
					return nil, fmt.Errorf("prepare executor delivery protocol state: %w", err)
				}
				if err := cfg.DeliveryState.MigrateFormat(); err != nil {
					return nil, fmt.Errorf("migrate executor delivery state: %w", err)
				}
				if err := cfg.DeliveryState.RecoverExecuting(); err != nil {
					return nil, fmt.Errorf("recover executor delivery state: %w", err)
				}
			}
		} else if cfg.DeliveryState != nil {
			return nil, errors.New("executor delivery state is only valid with uplink protocol 3 or 4")
		}
	} else {
		if protocolVersion != 0 && protocolVersion != 1 {
			return nil, errors.New("tenant-scoped uplink only supports protocol version 1")
		}
		if cfg.DeliveryState != nil {
			return nil, errors.New("tenant-scoped uplink cannot use node delivery state")
		}
		protocolVersion = 1
	}
	pollURL, _ := url.JoinPath(cfg.BaseURL, "executor-uplink", "poll")
	reportURL, _ := url.JoinPath(cfg.BaseURL, "executor-uplink", "report")
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	now := cfg.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	activationGateway := activationGatewayForProtocol(
		protocolVersion,
		cfg.GatewayControl,
	)
	return &Poller{
		pollURL: pollURL, reportURL: reportURL, credentialPath: cfg.CredentialPath,
		expected: credential, interval: cfg.PollInterval, client: client, logger: logger,
		security: security, commandPolicy: cfg.CommandPolicy, now: now,
		protocolVersion: protocolVersion, deliveryState: cfg.DeliveryState,
		canaryRunner: newActivationCanaryRunner(
			activationGateway != nil,
		),
		dispatcher: dispatcher{
			handler: cfg.Handler, token: cfg.LocalToken, tenantID: credential.TenantID,
			nodeID: credential.NodeID, nodeScoped: credential.NodeScoped(), state: cfg.State,
			projectAdmission:  protocolVersion == controlprotocol.ExecutorProtocolV4,
			activationGateway: activationGateway,
			now:               now,
		},
	}, nil
}

func activationGatewayForProtocol(
	protocolVersion int,
	client *gateway.ControlClient,
) activationCanaryGateway {
	if protocolVersion != controlprotocol.ExecutorProtocolV4 || client == nil {
		return nil
	}
	return client
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (p *Poller) Run(ctx context.Context) {
	failures := 0
	for {
		if err := p.pollOnce(ctx); err != nil {
			if ctx.Err() != nil {
				return
			}
			failures++
			p.logger.Warn("executor uplink poll failed", "error", err, "failures", failures)
		} else {
			failures = 0
		}
		wait := p.interval
		for i := 0; i < failures && wait < maxBackoff; i++ {
			wait *= 2
			if wait > maxBackoff {
				wait = maxBackoff
			}
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func (p *Poller) pollOnce(ctx context.Context) error {
	credential, err := stewarduplink.LoadCredentialWithSecurity(p.credentialPath, p.security)
	if err != nil {
		return err
	}
	if credential.Version != p.expected.Version || credential.Scope != p.expected.Scope ||
		credential.TenantID != p.expected.TenantID || credential.NodeID != p.expected.NodeID {
		return errors.New("rotated uplink credential changed version, scope, tenant_id, or node_id; refusing it")
	}
	if p.protocolVersion == controlprotocol.ExecutorProtocolV3 ||
		p.protocolVersion == controlprotocol.ExecutorProtocolV4 {
		drained, err := p.retryUnacknowledgedReports(ctx, credential.Credential)
		if err != nil {
			return err
		}
		if !drained {
			return nil
		}
	}
	requestBody := []byte(`{}`)
	if credential.NodeScoped() {
		switch p.protocolVersion {
		case controlprotocol.ExecutorProtocolV3:
			requestBody, err = json.Marshal(controlprotocol.ExecutorPollRequestV3{
				ProtocolVersion: controlprotocol.ExecutorProtocolV3,
				NodeID:          credential.NodeID, CredentialScope: "node",
				Capabilities: []string{
					"signed-commands-v2", "delivery-leases-v3",
					controlprotocol.ExecutorCapabilityAuthorizedEffectsV1,
					"multi-tenant", "read", "state-purge",
				},
			})
		case controlprotocol.ExecutorProtocolV4:
			capabilities := []string{
				"signed-commands-v2",
				"delivery-leases-v3",
				controlprotocol.ExecutorCapabilityAdmissionProjectionV1,
				controlprotocol.ExecutorCapabilityAuthorizedEffectsV1,
				controlprotocol.ExecutorCapabilityRolloutAuthorizationContextV1,
				"multi-tenant",
				"read",
				"state-purge",
			}
			if p.canaryRunner.available() {
				capabilities = append(
					capabilities,
					controlprotocol.ExecutorCapabilityActivationCanaryV1,
				)
			}
			requestBody, err = json.Marshal(controlprotocol.ExecutorPollRequestV4{
				ProtocolVersion: controlprotocol.ExecutorProtocolV4,
				NodeID:          credential.NodeID, CredentialScope: "node",
				Capabilities: capabilities,
			})
		default:
			requestBody, err = json.Marshal(pollRequest{
				ProtocolVersion: 2, NodeID: credential.NodeID, CredentialScope: "node",
				Capabilities: []string{
					"signed-commands-v2",
					controlprotocol.ExecutorCapabilityAuthorizedEffectsV1,
					"multi-tenant", "read", "state-purge",
				},
			})
		}
		if err != nil {
			return err
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.pollURL, bytes.NewReader(requestBody))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+credential.Credential)
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return wireError("poll", resp)
	}
	raw, err := readBounded(resp.Body, maxWireBytes)
	if err != nil {
		return fmt.Errorf("read poll response: %w", err)
	}
	switch p.protocolVersion {
	case controlprotocol.ExecutorProtocolV3:
		return p.processPollV3(ctx, credential, raw)
	case controlprotocol.ExecutorProtocolV4:
		return p.processPollV4(ctx, credential, raw)
	}
	var payload pollResponse
	if err := dsse.DecodeStrictInto(raw, maxWireBytes, &payload); err != nil {
		return fmt.Errorf("decode poll response: %w", err)
	}
	if credential.NodeScoped() && payload.ProtocolVersion != 2 {
		return fmt.Errorf("node-scoped poll requires protocol_version 2, got %d", payload.ProtocolVersion)
	}
	if !credential.NodeScoped() && payload.ProtocolVersion != 0 && payload.ProtocolVersion != 1 {
		return fmt.Errorf("tenant-scoped poll received incompatible protocol_version %d", payload.ProtocolVersion)
	}
	if payload.Commands == nil {
		return errors.New("poll response must contain a commands array")
	}
	if len(payload.Commands) > maxCommandsPerPoll {
		return fmt.Errorf("poll returned %d commands, limit is %d", len(payload.Commands), maxCommandsPerPoll)
	}
	for index, rawCommand := range payload.Commands {
		cmd, err := p.decodeCommand(rawCommand, credential)
		if err != nil {
			return fmt.Errorf("decode poll command %d: %w", index, err)
		}
		rep := p.dispatcher.execute(ctx, cmd)
		if err := p.sendReport(ctx, credential.Credential, rep); err != nil {
			return err
		}
	}
	return nil
}

func (p *Poller) retryUnacknowledgedReports(ctx context.Context, credential string) (bool, error) {
	if p.protocolVersion == controlprotocol.ExecutorProtocolV4 {
		return p.retryUnacknowledgedReportsV4(ctx, credential)
	}
	return p.retryUnacknowledgedReportsV3(ctx, credential)
}

func (p *Poller) retryUnacknowledgedReportsV3(ctx context.Context, credential string) (bool, error) {
	reports, more, err := p.deliveryState.UnacknowledgedReports(maxCommandsPerPoll)
	if err != nil {
		return false, fmt.Errorf("list unacknowledged executor reports: %w", err)
	}
	var failures []error
	for index, report := range reports {
		if err := p.sendReportV3(ctx, credential, report); err != nil {
			failures = append(failures, fmt.Errorf("retry terminal report %d: %w", index, err))
		}
	}
	if err := errors.Join(failures...); err != nil {
		return false, err
	}
	return !more, nil
}

func (p *Poller) retryUnacknowledgedReportsV4(ctx context.Context, credential string) (bool, error) {
	reports, more, err := p.deliveryState.UnacknowledgedReportsV4(maxCommandsPerPoll)
	if err != nil {
		return false, fmt.Errorf("list unacknowledged executor reports v4: %w", err)
	}
	var failures []error
	for index, report := range reports {
		if err := p.sendReportV4(ctx, credential, report); err != nil {
			failures = append(failures, fmt.Errorf("retry terminal report v4 %d: %w", index, err))
		}
	}
	if err := errors.Join(failures...); err != nil {
		return false, err
	}
	return !more, nil
}

func (p *Poller) processPollV3(ctx context.Context, credential *stewarduplink.Credential, raw []byte) error {
	payload, err := controlprotocol.DecodeExecutorPollResponseV3(raw, maxWireBytes)
	if err != nil {
		return fmt.Errorf("decode executor poll v3 response: %w", err)
	}
	var failures []error
	for index, rawDelivery := range payload.Deliveries {
		if err := p.processDeliveryV3(ctx, credential, rawDelivery); err != nil {
			failures = append(failures, fmt.Errorf("delivery %d: %w", index, err))
		}
	}
	return errors.Join(failures...)
}

func (p *Poller) processPollV4(ctx context.Context, credential *stewarduplink.Credential, raw []byte) error {
	payload, err := controlprotocol.DecodeExecutorPollResponseV4(raw, maxWireBytes)
	if err != nil {
		return fmt.Errorf("decode executor poll v4 response: %w", err)
	}
	var failures []error
	for index, rawDelivery := range payload.Deliveries {
		if err := p.processDeliveryV4(ctx, credential, rawDelivery); err != nil {
			failures = append(failures, fmt.Errorf("delivery %d: %w", index, err))
		}
	}
	return errors.Join(failures...)
}

func (p *Poller) processDeliveryV3(ctx context.Context, credential *stewarduplink.Credential, raw []byte) error {
	delivery, err := controlprotocol.DecodeExecutorDeliveryV3(raw)
	if err != nil {
		return fmt.Errorf("decode wrapper: %w", err)
	}
	commandRaw, err := base64.StdEncoding.DecodeString(delivery.CommandDSSEBase64)
	if err != nil || base64.StdEncoding.EncodeToString(commandRaw) != delivery.CommandDSSEBase64 {
		return p.rejectDeliveryV3(ctx, credential.Credential, delivery, "invalid_command_encoding", "signed command encoding is invalid", err)
	}
	if dsse.Digest(commandRaw) != delivery.CommandDigest {
		return p.rejectDeliveryV3(ctx, credential.Credential, delivery, "command_digest_mismatch", "signed command digest does not match its delivery", nil)
	}
	cmd, err := p.decodeCommand(commandRaw, credential)
	if err != nil {
		return p.rejectDeliveryV3(ctx, credential.Credential, delivery, "invalid_signed_command", "signed command was rejected", err)
	}
	if cmd.CommandID != delivery.CommandID {
		return p.rejectDeliveryV3(ctx, credential.Credential, delivery, "command_identity_mismatch", "delivery command ID does not match the signed command", nil)
	}
	expectedDeliveryID, err := controlprotocol.ExecutorDeliveryID(cmd.TenantID, cmd.NodeID, cmd.CommandID)
	if err != nil || delivery.DeliveryID != expectedDeliveryID {
		return p.rejectDeliveryV3(ctx, credential.Credential, delivery, "delivery_identity_mismatch", "delivery ID does not match the verified tenant, node, and command", err)
	}
	decision, terminal, err := p.deliveryState.Accept(delivery, cmd.TenantID)
	if err != nil {
		return fmt.Errorf("persist accepted delivery: %w", err)
	}
	switch decision {
	case deliveryStale:
		return nil
	case deliveryReport:
		if terminal == nil {
			return errors.New("terminal delivery has no retained report")
		}
		return p.sendReportV3(ctx, credential.Credential, *terminal)
	case deliveryExecute:
		if err := p.deliveryState.MarkExecuting(delivery.DeliveryID); err != nil {
			return fmt.Errorf("persist executing delivery: %w", err)
		}
		legacyReport := p.dispatcher.execute(ctx, cmd)
		report := makeReportV3(delivery, legacyReport)
		if err := p.deliveryState.MarkTerminal(report); err != nil {
			return fmt.Errorf("persist terminal delivery: %w", err)
		}
		return p.sendReportV3(ctx, credential.Credential, report)
	default:
		return errors.New("delivery store returned an invalid decision")
	}
}

func (p *Poller) processDeliveryV4(ctx context.Context, credential *stewarduplink.Credential, raw []byte) error {
	delivery, err := controlprotocol.DecodeExecutorDeliveryV4(raw)
	if err != nil {
		return fmt.Errorf("decode wrapper: %w", err)
	}
	commandRaw, err := base64.StdEncoding.DecodeString(delivery.CommandDSSEBase64)
	if err != nil || base64.StdEncoding.EncodeToString(commandRaw) != delivery.CommandDSSEBase64 {
		return p.rejectDeliveryV4(
			ctx,
			credential.Credential,
			delivery,
			"invalid_command_encoding",
			"signed command encoding is invalid",
			err,
		)
	}
	if dsse.Digest(commandRaw) != delivery.CommandDigest {
		return p.rejectDeliveryV4(
			ctx,
			credential.Credential,
			delivery,
			"command_digest_mismatch",
			"signed command digest does not match its delivery",
			nil,
		)
	}
	cmd, err := p.decodeCommand(commandRaw, credential)
	if err != nil {
		return p.rejectDeliveryV4(
			ctx,
			credential.Credential,
			delivery,
			"invalid_signed_command",
			"signed command was rejected",
			err,
		)
	}
	if cmd.CommandID != delivery.CommandID {
		return p.rejectDeliveryV4(
			ctx,
			credential.Credential,
			delivery,
			"command_identity_mismatch",
			"delivery command ID does not match the signed command",
			nil,
		)
	}
	expectedDeliveryID, err := controlprotocol.ExecutorDeliveryID(
		cmd.TenantID,
		cmd.NodeID,
		cmd.CommandID,
	)
	if err != nil || delivery.DeliveryID != expectedDeliveryID {
		return p.rejectDeliveryV4(
			ctx,
			credential.Credential,
			delivery,
			"delivery_identity_mismatch",
			"delivery ID does not match the verified tenant, node, and command",
			err,
		)
	}
	if cmd.Kind == "activation-canary" && p.canaryRunner.owns(delivery) {
		return nil
	}
	decision, terminal, err := p.deliveryState.AcceptV4(
		delivery,
		cmd.TenantID,
		cmd.ClaimGeneration,
		cmd.Kind,
	)
	if err != nil {
		return fmt.Errorf("persist accepted delivery: %w", err)
	}
	switch decision {
	case deliveryStale:
		return nil
	case deliveryReport:
		if terminal == nil {
			return errors.New("terminal delivery has no retained report")
		}
		return p.sendReportV4(ctx, credential.Credential, *terminal)
	case deliveryExecute:
		if cmd.Kind == "activation-canary" {
			return p.startActivationCanary(
				ctx,
				credential.Credential,
				delivery,
				cmd,
			)
		}
		if err := p.deliveryState.MarkExecuting(delivery.DeliveryID); err != nil {
			return fmt.Errorf("persist executing delivery: %w", err)
		}
		localReport := p.dispatcher.execute(ctx, cmd)
		report := makeReportV4(delivery, localReport, cmd.Kind)
		if err := p.deliveryState.MarkTerminalV4(report); err != nil {
			return fmt.Errorf("persist terminal delivery: %w", err)
		}
		return p.sendReportV4(ctx, credential.Credential, report)
	default:
		return errors.New("delivery store returned an invalid decision")
	}
}

func (p *Poller) rejectDeliveryV3(
	ctx context.Context,
	credential string,
	delivery controlprotocol.ExecutorDeliveryV3,
	errorCode, detail string,
	cause error,
) error {
	if cause != nil {
		p.logger.Warn("executor uplink rejected signed delivery", "delivery_id", delivery.DeliveryID,
			"error_code", errorCode, "error", cause)
	}
	rejected := controlprotocol.ExecutorReportV3{
		ProtocolVersion: controlprotocol.ExecutorProtocolV3,
		DeliveryID:      delivery.DeliveryID, DeliveryGeneration: delivery.DeliveryGeneration,
		CommandID: delivery.CommandID, CommandDigest: delivery.CommandDigest,
		Status: controlprotocol.ExecutorStatusRejected, ReportedStatus: "failed", ErrorCode: errorCode,
		Result: controlprotocol.ExecutorReportResultV3{Error: detail},
	}
	terminal, err := p.deliveryState.Reject(delivery, rejected)
	if err != nil {
		return fmt.Errorf("persist rejected delivery: %w", err)
	}
	if terminal == nil {
		return nil
	}
	return p.sendReportV3(ctx, credential, *terminal)
}

func (p *Poller) rejectDeliveryV4(
	ctx context.Context,
	credential string,
	delivery controlprotocol.ExecutorDeliveryV4,
	errorCode, detail string,
	cause error,
) error {
	if cause != nil {
		p.logger.Warn(
			"executor uplink rejected signed delivery",
			"delivery_id",
			delivery.DeliveryID,
			"error_code",
			errorCode,
			"error",
			cause,
		)
	}
	rejected := controlprotocol.ExecutorReportV4{
		ProtocolVersion: controlprotocol.ExecutorProtocolV4,
		DeliveryID:      delivery.DeliveryID, DeliveryGeneration: delivery.DeliveryGeneration,
		CommandID: delivery.CommandID, CommandDigest: delivery.CommandDigest,
		Status: controlprotocol.ExecutorStatusRejected, ReportedStatus: "failed",
		ErrorCode: errorCode,
		Result:    controlprotocol.ExecutorReportResultV4{Error: detail},
	}
	terminal, err := p.deliveryState.RejectV4(delivery, rejected)
	if err != nil {
		return fmt.Errorf("persist rejected delivery: %w", err)
	}
	if terminal == nil {
		return nil
	}
	return p.sendReportV4(ctx, credential, *terminal)
}

func makeReportV3(delivery controlprotocol.ExecutorDeliveryV3, legacy report) controlprotocol.ExecutorReportV3 {
	result := controlprotocol.ExecutorReportResultV3{}
	if value, ok := legacy.Result["runtime_ref"].(string); ok {
		result.RuntimeRef = truncateUTF8(value, 1024)
	}
	if value, ok := legacy.Result["error"].(string); ok {
		result.Error = truncateUTF8(value, 4096)
	}
	if value, ok := legacy.Result["replayed"].(bool); ok {
		result.Replayed = value
	}
	if value, ok := legacy.Result["absent"].(bool); ok {
		result.Absent = value
	}
	report := controlprotocol.ExecutorReportV3{
		ProtocolVersion: controlprotocol.ExecutorProtocolV3,
		DeliveryID:      delivery.DeliveryID, DeliveryGeneration: delivery.DeliveryGeneration,
		CommandID: delivery.CommandID, CommandDigest: delivery.CommandDigest,
		Status: legacy.Status, ReportedStatus: boundedReportedStatus(legacy.ReportedStatus),
		ClaimGeneration: legacy.ClaimGeneration, Result: result,
	}
	if legacy.Status == controlprotocol.ExecutorStatusFailed {
		if legacy.effectUncertain {
			report.Status = controlprotocol.ExecutorStatusOutcomeUnknown
			report.ErrorCode = "outcome_unknown"
		} else {
			// A completed pre-handler validation failure is safe to retire. Failed
			// remains reserved for legacy ambiguous reports and is never compacted.
			report.Status = controlprotocol.ExecutorStatusRejected
			report.ErrorCode = "executor_command_rejected"
		}
	}
	return report
}

func makeReportV4(
	delivery controlprotocol.ExecutorDeliveryV4,
	legacy report,
	commandKind string,
) controlprotocol.ExecutorReportV4 {
	result := controlprotocol.ExecutorReportResultV4{}
	if value, ok := legacy.Result["runtime_ref"].(string); ok {
		result.RuntimeRef = truncateUTF8(value, 1024)
	}
	if value, ok := legacy.Result["error"].(string); ok {
		result.Error = truncateUTF8(value, 4096)
	}
	if value, ok := legacy.Result["replayed"].(bool); ok {
		result.Replayed = value
	}
	if value, ok := legacy.Result["absent"].(bool); ok {
		result.Absent = value
	}
	if commandKind == "admit" &&
		legacy.Status == controlprotocol.ExecutorStatusDone &&
		!result.Replayed &&
		!result.Absent &&
		result.Error == "" {
		result.Admission = cloneAdmissionProjection(legacy.admission)
	}
	if commandKind == "activation-canary" &&
		legacy.Status == controlprotocol.ExecutorStatusDone &&
		legacy.ReportedStatus == "running" &&
		!result.Replayed &&
		!result.Absent &&
		result.Error == "" {
		result.ActivationCanary = cloneActivationCanaryResult(
			legacy.activationCanary,
		)
	}
	report := controlprotocol.ExecutorReportV4{
		ProtocolVersion: controlprotocol.ExecutorProtocolV4,
		DeliveryID:      delivery.DeliveryID, DeliveryGeneration: delivery.DeliveryGeneration,
		CommandID: delivery.CommandID, CommandDigest: delivery.CommandDigest,
		Status: legacy.Status, ReportedStatus: boundedReportedStatus(legacy.ReportedStatus),
		ClaimGeneration: legacy.ClaimGeneration, Result: result,
	}
	if commandKind == "activation-canary" &&
		report.Status == controlprotocol.ExecutorStatusDone &&
		report.Result.ActivationCanary == nil {
		report.Status = controlprotocol.ExecutorStatusOutcomeUnknown
		report.ReportedStatus = "failed"
		report.ErrorCode = "outcome_unknown"
		report.Result = controlprotocol.ExecutorReportResultV4{
			Error: "activation canary completed without a qualified result; reconcile the node",
		}
	}
	if legacy.Status == controlprotocol.ExecutorStatusFailed {
		report.Result.Admission = nil
		report.Result.ActivationCanary = nil
		if commandKind == "activation-canary" &&
			legacy.canaryTerminalErrorCode != "" {
			report.Status = controlprotocol.ExecutorStatusFailed
			report.ErrorCode = legacy.canaryTerminalErrorCode
		} else if legacy.effectUncertain {
			report.Status = controlprotocol.ExecutorStatusOutcomeUnknown
			report.ErrorCode = "outcome_unknown"
		} else {
			report.Status = controlprotocol.ExecutorStatusRejected
			report.ErrorCode = "executor_command_rejected"
		}
	}
	if err := report.Validate(); err != nil &&
		(report.Result.Admission != nil ||
			report.Result.ActivationCanary != nil) {
		// Executor has already returned success and its finite effects may be
		// durable, but an invalid or oversized projection must never escape.
		// Persist an explicit ambiguous outcome so an operator reconciles the
		// node instead of trusting a partial admission observation.
		report.Status = controlprotocol.ExecutorStatusOutcomeUnknown
		report.ReportedStatus = "failed"
		report.ErrorCode = "outcome_unknown"
		report.Result = controlprotocol.ExecutorReportResultV4{
			Error: "successful protocol projection was invalid or exceeded its limit; reconcile the node",
		}
	}
	return report
}

func boundedReportedStatus(value string) string {
	value = strings.ToValidUTF8(value, "?")
	value = strings.Map(func(char rune) rune {
		switch char {
		case '\r', '\n', 0:
			return -1
		default:
			return char
		}
	}, value)
	value = strings.TrimSpace(truncateUTF8(strings.TrimSpace(value), 64))
	if value == "" {
		return "failed"
	}
	return value
}

func truncateUTF8(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	value = value[:limit]
	for !utf8.ValidString(value) {
		value = value[:len(value)-1]
	}
	return value
}

func (p *Poller) decodeCommand(raw []byte, credential *stewarduplink.Credential) (command, error) {
	if !credential.NodeScoped() {
		var decoded legacyCommand
		if err := dsse.DecodeStrictInto(raw, maxWireBytes, &decoded); err != nil {
			return command{}, err
		}
		return command{
			CommandID: decoded.CommandID, TenantID: decoded.TenantID, NodeID: decoded.NodeID,
			RuntimeRef: decoded.RuntimeRef, Kind: decoded.Kind, Payload: decoded.Payload,
			ClaimGeneration: decoded.ClaimGeneration, InstanceGeneration: decoded.InstanceGeneration,
			CommandSequence: decoded.CommandSequence,
		}, nil
	}
	envelope, err := dsse.Parse(raw)
	if err != nil {
		return command{}, err
	}
	if envelope.PayloadType != admission.CommandPayloadType {
		return command{}, fmt.Errorf("unexpected signed command payload type %q", envelope.PayloadType)
	}
	untrustedPayload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		return command{}, errors.New("signed command payload is not valid base64")
	}
	var routed admission.CommandStatement
	if err := dsse.DecodeStrictInto(untrustedPayload, dsse.MaxPayloadBytes, &routed); err != nil {
		return command{}, fmt.Errorf("decode signed command statement for key routing: %w", err)
	}
	keys, err := p.commandPolicy.TrustedCommandKeys(routed.TenantID, routed.Kind)
	if err != nil {
		return command{}, err
	}
	verifiedPayload, _, err := dsse.Verify(raw, admission.CommandPayloadType, keys)
	if err != nil {
		return command{}, fmt.Errorf("verify signed command: %w", err)
	}
	var statement admission.CommandStatement
	if err := dsse.DecodeStrictInto(verifiedPayload, dsse.MaxPayloadBytes, &statement); err != nil {
		return command{}, fmt.Errorf("decode verified signed command: %w", err)
	}
	if err := statement.Validate(p.now()); err != nil {
		return command{}, err
	}
	if statement.NodeID != credential.NodeID {
		return command{}, errors.New("signed command is addressed to another node")
	}
	return command{
		CommandID: statement.CommandID, TenantID: statement.TenantID, NodeID: statement.NodeID,
		InstanceID: statement.InstanceID, RuntimeRef: statement.RuntimeRef, Kind: statement.Kind,
		Payload: statement.Payload, ClaimGeneration: statement.ClaimGeneration,
		InstanceGeneration: statement.InstanceGeneration, CommandSequence: statement.CommandSequence,
		signed: true,
	}, nil
}

func (p *Poller) sendReport(ctx context.Context, credential string, report report) error {
	raw, err := json.Marshal(report)
	if err != nil {
		return err
	}
	if len(raw) > maxWireBytes {
		return errors.New("uplink report exceeds wire limit")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.reportURL, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+credential)
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return wireError("report", resp)
	}
	var response reportResponse
	responseBody, err := readBounded(resp.Body, maxWireBytes)
	if err != nil {
		return fmt.Errorf("read report response: %w", err)
	}
	if err := dsse.DecodeStrictInto(responseBody, maxWireBytes, &response); err != nil {
		return fmt.Errorf("decode report response: %w", err)
	}
	if !response.Applied {
		return errors.New("uplink report was not acknowledged as applied")
	}
	return nil
}

func (p *Poller) sendReportV3(ctx context.Context, credential string, report controlprotocol.ExecutorReportV3) error {
	if err := report.Validate(); err != nil {
		return fmt.Errorf("validate executor report v3: %w", err)
	}
	raw, err := json.Marshal(report)
	if err != nil {
		return err
	}
	if len(raw) > maxWireBytes {
		return errors.New("executor uplink report v3 exceeds wire limit")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.reportURL, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+credential)
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return wireError("report", resp)
	}
	responseBody, err := readBounded(resp.Body, maxWireBytes)
	if err != nil {
		return fmt.Errorf("read executor report v3 response: %w", err)
	}
	var response controlprotocol.ExecutorReportResponseV3
	if err := dsse.DecodeStrictInto(responseBody, maxWireBytes, &response); err != nil {
		return fmt.Errorf("decode executor report v3 response: %w", err)
	}
	if response.ProtocolVersion != controlprotocol.ExecutorProtocolV3 {
		return fmt.Errorf("executor report acknowledgement protocol_version is %d, want %d", response.ProtocolVersion, controlprotocol.ExecutorProtocolV3)
	}
	// Both true and false are acknowledgements. False is the control plane's
	// stale-or-duplicate no-op and must never cause command reexecution.
	if err := p.deliveryState.Settle(report.DeliveryID, report.DeliveryGeneration); err != nil {
		return fmt.Errorf("persist executor report acknowledgement: %w", err)
	}
	return nil
}

func (p *Poller) sendReportV4(
	ctx context.Context,
	credential string,
	report controlprotocol.ExecutorReportV4,
) error {
	if err := report.Validate(); err != nil {
		return fmt.Errorf("validate executor report v4: %w", err)
	}
	raw, err := json.Marshal(report)
	if err != nil {
		return err
	}
	if len(raw) > controlprotocol.MaxExecutorReportBytes {
		return errors.New("executor uplink report v4 exceeds wire limit")
	}
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		p.reportURL,
		bytes.NewReader(raw),
	)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+credential)
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return wireError("report", resp)
	}
	responseBody, err := readBounded(resp.Body, controlprotocol.MaxExecutorReportBytes)
	if err != nil {
		return fmt.Errorf("read executor report v4 response: %w", err)
	}
	var response controlprotocol.ExecutorReportResponseV4
	if err := dsse.DecodeStrictInto(
		responseBody,
		controlprotocol.MaxExecutorReportBytes,
		&response,
	); err != nil {
		return fmt.Errorf("decode executor report v4 response: %w", err)
	}
	if response.ProtocolVersion != controlprotocol.ExecutorProtocolV4 {
		return fmt.Errorf(
			"executor report acknowledgement protocol_version is %d, want %d",
			response.ProtocolVersion,
			controlprotocol.ExecutorProtocolV4,
		)
	}
	// Applied false is the same stale-or-duplicate terminal acknowledgement as
	// protocol 3 and must never cause command reexecution.
	if err := p.deliveryState.Settle(report.DeliveryID, report.DeliveryGeneration); err != nil {
		return fmt.Errorf("persist executor report acknowledgement: %w", err)
	}
	return nil
}

func readBounded(reader io.Reader, limit int64) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, fmt.Errorf("response exceeds %d byte limit", limit)
	}
	return raw, nil
}

func wireError(operation string, resp *http.Response) error {
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return fmt.Errorf("uplink %s returned HTTP %d: %s", operation, resp.StatusCode, strings.TrimSpace(string(raw)))
}
