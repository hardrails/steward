package executoruplink

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/evidence"
	stewarduplink "github.com/hardrails/steward/internal/uplink"
)

const (
	minEvidencePublishInterval = time.Second
	maxEvidencePublishInterval = time.Hour
)

// ErrEvidenceDivergence means the controller has retained an authenticated
// rollback or equivocation finding. Publishing remains stopped until an
// operator resolves the node identity or evidence state.
var ErrEvidenceDivergence = errors.New("executor evidence diverges from the retained controller checkpoint")

// EvidencePublisherConfig creates an independent outbound evidence loop. It
// deliberately shares neither backoff nor failure state with command polling.
type EvidencePublisherConfig struct {
	BaseURL              string
	CredentialPath       string
	ControllerInstanceID string
	PollInterval         time.Duration
	HTTPClient           *http.Client
	Logger               *slog.Logger
	Log                  *evidence.Log
	PrivateKey           ed25519.PrivateKey
	SecureExecutor       bool
	SecureNodeID         string
	ProtectedTransport   bool
}

type EvidencePublisher struct {
	pollURL, reportURL   string
	credentialPath       string
	controllerInstanceID string
	expectedVersion      int
	expectedScope        string
	expectedTenantID     string
	expectedNodeID       string
	interval             time.Duration
	client               *http.Client
	logger               *slog.Logger
	log                  *evidence.Log
	private              ed25519.PrivateKey
	public               ed25519.PublicKey
	epoch                uint64
	security             stewarduplink.CredentialSecurity
}

func NewEvidencePublisher(cfg EvidencePublisherConfig) (*EvidencePublisher, error) {
	if cfg.PollInterval < minEvidencePublishInterval || cfg.PollInterval > maxEvidencePublishInterval ||
		cfg.Log == nil || len(cfg.PrivateKey) != ed25519.PrivateKeySize || !cfg.SecureExecutor {
		return nil, errors.New("evidence publisher requires secure Executor evidence, an Ed25519 key, and a 1s-1h interval")
	}
	base, err := url.Parse(cfg.BaseURL)
	if err != nil || base.Host == "" || base.Scheme != "https" || base.User != nil ||
		base.RawQuery != "" || base.Fragment != "" || !cfg.ProtectedTransport {
		return nil, errors.New("evidence publisher requires an absolute protected HTTPS control URL without userinfo, query, or fragment")
	}
	security := stewarduplink.CredentialSecurity{SecureExecutor: true, ProtectedTransport: true}
	credential, err := stewarduplink.LoadCredentialWithSecurity(cfg.CredentialPath, security)
	if err != nil {
		return nil, err
	}
	if !credential.NodeScoped() || cfg.SecureNodeID == "" || credential.NodeID != cfg.SecureNodeID {
		return nil, errors.New("evidence publisher requires a node-scoped credential matching the secure Executor node")
	}
	local, err := cfg.Log.CurrentHead()
	if err != nil {
		return nil, fmt.Errorf("read Executor evidence head: %w", err)
	}
	public := cfg.Log.PublicKey()
	derived, ok := cfg.PrivateKey.Public().(ed25519.PublicKey)
	if !ok || !bytes.Equal(derived, public) || local.NodeID != credential.NodeID || local.NodeID != cfg.SecureNodeID ||
		local.Epoch == 0 || local.KeyID != evidence.KeyID(public) {
		return nil, errors.New("evidence publisher key, log, credential, and secure node identity do not match")
	}
	request := controlprotocol.ExecutorEvidencePollRequestV1{
		ProtocolVersion:      controlprotocol.ExecutorEvidenceProtocolV1,
		ControllerInstanceID: cfg.ControllerInstanceID, ControlNodeID: local.NodeID,
		Stream: controlprotocol.ExecutorEvidenceStreamV1, ReceiptNodeID: local.NodeID,
		ReceiptEpoch: local.Epoch, PublicKeySHA256: controlprotocol.ExecutorEvidencePublicKeySHA256(public),
	}
	if err := request.Validate(); err != nil {
		return nil, fmt.Errorf("validate evidence publisher identity: %w", err)
	}
	client := cfg.HTTPClient
	if client == nil {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.Proxy = nil
		client = &http.Client{Timeout: 30 * time.Second, Transport: transport}
	} else {
		copied := *client
		client = &copied
	}
	if client.Timeout <= 0 || client.Timeout > 2*time.Minute {
		client.Timeout = 30 * time.Second
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return errors.New("evidence publisher redirects are disabled")
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	pollURL, _ := url.JoinPath(cfg.BaseURL, "evidence-uplink", "poll")
	reportURL, _ := url.JoinPath(cfg.BaseURL, "evidence-uplink", "report")
	return &EvidencePublisher{
		pollURL: pollURL, reportURL: reportURL, credentialPath: cfg.CredentialPath,
		controllerInstanceID: cfg.ControllerInstanceID,
		expectedVersion:      credential.Version, expectedScope: credential.Scope,
		expectedTenantID: credential.TenantID, expectedNodeID: credential.NodeID,
		interval: cfg.PollInterval, client: client, logger: logger, log: cfg.Log,
		private: append(ed25519.PrivateKey(nil), cfg.PrivateKey...),
		public:  append(ed25519.PublicKey(nil), public...), epoch: local.Epoch, security: security,
	}, nil
}

// Run publishes independently until ctx is canceled. Controller outages never
// stop local enforcement or the command uplink; they only increase this loop's
// bounded backoff and leave the local receipt log as its durable outbox.
func (publisher *EvidencePublisher) Run(ctx context.Context) {
	failures := 0
	for {
		applied, err := publisher.publishOnce(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			failures++
			publisher.logger.Warn("executor evidence publish failed", "error", err, "failures", failures)
		} else {
			if applied {
				publisher.logger.Info("executor evidence checkpoint advanced")
			}
			failures = 0
		}
		wait := publisher.interval
		for index := 0; index < failures && wait < maxBackoff; index++ {
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

func (publisher *EvidencePublisher) publishOnce(ctx context.Context) (bool, error) {
	credential, err := stewarduplink.LoadCredentialWithSecurity(publisher.credentialPath, publisher.security)
	if err != nil {
		return false, err
	}
	if credential.Version != publisher.expectedVersion || credential.Scope != publisher.expectedScope ||
		credential.TenantID != publisher.expectedTenantID || credential.NodeID != publisher.expectedNodeID {
		return false, errors.New("rotated evidence credential changed version, scope, tenant_id, or node_id")
	}
	poll := controlprotocol.ExecutorEvidencePollRequestV1{
		ProtocolVersion:      controlprotocol.ExecutorEvidenceProtocolV1,
		ControllerInstanceID: publisher.controllerInstanceID, ControlNodeID: publisher.expectedNodeID,
		Stream: controlprotocol.ExecutorEvidenceStreamV1, ReceiptNodeID: publisher.expectedNodeID,
		ReceiptEpoch:    publisher.epoch,
		PublicKeySHA256: controlprotocol.ExecutorEvidencePublicKeySHA256(publisher.public),
	}
	var pollResponse controlprotocol.ExecutorEvidencePollResponseV1
	if err := publisher.exchange(ctx, publisher.pollURL, credential.Credential, poll, func(raw []byte) error {
		decoded, err := controlprotocol.DecodeExecutorEvidencePollResponseV1(raw)
		pollResponse = decoded
		return err
	}); err != nil {
		return false, fmt.Errorf("poll evidence checkpoint: %w", err)
	}
	if err := publisher.validateStatusIdentity(pollResponse.Status); err != nil {
		return false, err
	}
	if pollResponse.Status.Finding != nil {
		return false, ErrEvidenceDivergence
	}
	if pollResponse.Status.Head == nil {
		return false, errors.New("controller has not enrolled this Executor evidence identity")
	}
	controllerCoordinate, err := evidenceCoordinate(*pollResponse.Status.Head)
	if err != nil {
		return false, err
	}
	var reportedHead evidence.Head
	var frames [][]byte
	delta, err := publisher.log.ExportDelta(controllerCoordinate)
	switch {
	case err == nil:
		frames = delta.Frames
		reportedHead = delta.Head
	case errors.Is(err, evidence.ErrDeltaCoordinate):
		// The signed empty report below authenticates the actual local head. It
		// cannot advance controller state but can durably expose rollback/fork.
		frames = nil
		reportedHead, err = publisher.log.CurrentHead()
		if err != nil {
			return false, err
		}
	default:
		return false, fmt.Errorf("export Executor evidence delta: %w", err)
	}
	reported := executorEvidenceProtocolHead(reportedHead, publisher.public)
	claim, err := controlprotocol.NewExecutorEvidenceHeadClaimV1(
		publisher.controllerInstanceID, publisher.expectedNodeID,
		*pollResponse.Status.Head, reported, pollResponse.Challenge, frames, publisher.public,
	)
	if err != nil {
		return false, err
	}
	proof, err := controlprotocol.SignExecutorEvidenceHeadClaimV1(claim, publisher.private)
	if err != nil {
		return false, err
	}
	report := controlprotocol.ExecutorEvidenceReportV1{
		ProtocolVersion: controlprotocol.ExecutorEvidenceProtocolV1, HeadProof: proof,
		SignedFramesBase64: encodeEvidenceFrames(frames),
	}
	var reportResponse controlprotocol.ExecutorEvidenceReportResponseV1
	if err := publisher.exchange(ctx, publisher.reportURL, credential.Credential, report, func(raw []byte) error {
		decoded, err := controlprotocol.DecodeExecutorEvidenceReportResponseV1(raw)
		reportResponse = decoded
		return err
	}); err != nil {
		return false, fmt.Errorf("report evidence checkpoint: %w", err)
	}
	if err := publisher.validateReportResponse(reportResponse, reported, len(frames)); err != nil {
		return false, err
	}
	return reportResponse.Applied, nil
}

func (publisher *EvidencePublisher) exchange(
	ctx context.Context,
	endpoint, credential string,
	input any,
	decode func([]byte) error,
) error {
	raw, err := json.Marshal(input)
	if err != nil {
		return err
	}
	if len(raw) > controlprotocol.MaxExecutorEvidenceJSONBytes {
		return errors.New("evidence request exceeds its JSON bound")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+credential)
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")
	response, err := publisher.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return wireError("evidence", response)
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return errors.New("evidence response Content-Type must be application/json")
	}
	responseRaw, err := readBounded(response.Body, controlprotocol.MaxExecutorEvidenceJSONBytes)
	if err != nil {
		return err
	}
	return decode(responseRaw)
}

func (publisher *EvidencePublisher) validateStatusIdentity(status controlprotocol.ExecutorEvidenceStatusV1) error {
	if status.State == controlprotocol.ExecutorEvidenceStatusUnwitnessed {
		return nil
	}
	if status.Head == nil || status.Head.Stream != controlprotocol.ExecutorEvidenceStreamV1 ||
		status.Head.ReceiptNodeID != publisher.expectedNodeID || status.Head.ReceiptEpoch != publisher.epoch ||
		status.Head.PublicKeySHA256 != controlprotocol.ExecutorEvidencePublicKeySHA256(publisher.public) {
		return errors.New("controller evidence status changed the enrolled receipt identity")
	}
	return nil
}

func (publisher *EvidencePublisher) validateReportResponse(
	response controlprotocol.ExecutorEvidenceReportResponseV1,
	reported controlprotocol.ExecutorEvidenceHeadV1,
	frameCount int,
) error {
	if err := publisher.validateStatusIdentity(response.Status); err != nil {
		return err
	}
	if response.Status.Finding != nil {
		if response.Status.Finding.ObservedHead != reported {
			return errors.New("controller evidence finding does not match the signed report")
		}
		return ErrEvidenceDivergence
	}
	if response.Status.Head == nil || *response.Status.Head != reported {
		return errors.New("controller evidence acknowledgement changed the reported checkpoint")
	}
	if frameCount == 0 && response.Applied {
		return errors.New("controller advanced evidence without signed frames")
	}
	return nil
}

func evidenceCoordinate(head controlprotocol.ExecutorEvidenceHeadV1) (evidence.Coordinate, error) {
	if err := head.Validate(); err != nil {
		return evidence.Coordinate{}, err
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(head.ChainHash, "sha256:"))
	if err != nil || len(raw) != sha256.Size {
		return evidence.Coordinate{}, errors.New("controller evidence head hash is invalid")
	}
	var hash [sha256.Size]byte
	copy(hash[:], raw)
	return evidence.Coordinate{Sequence: head.Sequence, ChainHash: hash}, nil
}

func executorEvidenceProtocolHead(head evidence.Head, public ed25519.PublicKey) controlprotocol.ExecutorEvidenceHeadV1 {
	return controlprotocol.ExecutorEvidenceHeadV1{
		Stream: controlprotocol.ExecutorEvidenceStreamV1, ReceiptNodeID: head.NodeID,
		ReceiptEpoch: head.Epoch, Sequence: head.Sequence, ChainHash: formattedEvidenceHash(head.ChainHash),
		PublicKeySHA256: controlprotocol.ExecutorEvidencePublicKeySHA256(public),
	}
}

func formattedEvidenceHash(hash [sha256.Size]byte) string {
	return "sha256:" + hex.EncodeToString(hash[:])
}

func encodeEvidenceFrames(frames [][]byte) []string {
	if len(frames) == 0 {
		return nil
	}
	encoded := make([]string, len(frames))
	for index, frame := range frames {
		encoded[index] = base64.StdEncoding.EncodeToString(frame)
	}
	return encoded
}
