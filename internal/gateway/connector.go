package gateway

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/hardrails/steward/internal/actionpermit"
	"github.com/hardrails/steward/internal/connectorledger"
	"github.com/hardrails/steward/internal/dsse"
)

var (
	errConnectorCallLimit           = errors.New("connector call budget exhausted")
	errConnectorReplay              = errors.New("connector task was already spent")
	errConnectorInactive            = errors.New("connector grant is not active")
	errConnectorCredentialReflected = errors.New("connector upstream reflected its credential")
)

const connectorCredentialScanBlockBytes = 32 << 10
const actionPermitHeader = "X-Steward-Action-Permit"

func (s *Server) listenConnectorGrantLocked(id string) error {
	if listener := s.connectorListeners[id]; listener != nil {
		return nil
	}
	directory := GrantDirectory(s.config.GrantRoot, id)
	path := connectorSocketPath(s.config.GrantRoot, id)
	listener, err := openGrantListener(directory, path, s.config.RelayGID)
	if err != nil {
		return err
	}
	s.connectorListeners[id] = listener
	server := &http.Server{
		Handler: s.connectorHandler(id), ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout: 30 * time.Second, MaxHeaderBytes: maxHTTPHeaderBytes,
	}
	go func() { _ = server.Serve(listener) }()
	return nil
}

func (s *Server) connectorHandler(grantID string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if !s.allowConnectorAttemptNow(grantID) {
			writeGatewayError(w, http.StatusTooManyRequests, "connector_rate_limited", "connector attempt rate limit reached")
			return
		}
		connectorID, operationID, ok := connectorRequestTarget(request)
		if !ok {
			writeGatewayError(w, http.StatusBadRequest, "invalid_connector_request", "connector request must name one exact connector operation without a query")
			return
		}
		taskID, ok := connectorTaskID(request.Header)
		if !ok {
			writeGatewayError(w, http.StatusBadRequest, "invalid_task_id", "one bounded X-Steward-Task-ID header is required")
			return
		}

		s.mu.Lock()
		grant, granted := s.grants[grantID]
		routePolicyDigest := s.policyDigests[grantID]
		connector, configured := s.connectors[connectorID]
		operation, operationExists := connector.operations[operationID]
		if !granted || !grant.Active {
			s.mu.Unlock()
			writeGatewayError(w, http.StatusServiceUnavailable, "grant_inactive", "connector grant is not active")
			return
		}
		if !configured || !slicesContainsSorted(grant.ConnectorIDs, connectorID) || !operationExists || operation.Method != request.Method {
			s.mu.Unlock()
			writeGatewayError(w, http.StatusForbidden, "connector_denied", "connector operation is not allowed by the active grant")
			return
		}
		semaphore := s.connectorSemaphores[connectorID]
		grantSemaphore := s.connectorGrantSemaphores[grantID]
		if grantSemaphore == nil {
			grantSemaphore = make(chan struct{}, maxConnectorGrantConcurrent)
			s.connectorGrantSemaphores[grantID] = grantSemaphore
		}
		lease := s.grantLeaseLocked(grantID)
		select {
		case s.connectorGlobalSemaphore <- struct{}{}:
		default:
			s.mu.Unlock()
			writeGatewayError(w, http.StatusTooManyRequests, "connector_busy", "Gateway connector concurrency limit reached")
			return
		}
		select {
		case grantSemaphore <- struct{}{}:
		default:
			<-s.connectorGlobalSemaphore
			s.mu.Unlock()
			writeGatewayError(w, http.StatusTooManyRequests, "connector_busy", "connector grant concurrency limit reached")
			return
		}
		select {
		case semaphore <- struct{}{}:
			s.mu.Unlock()
			defer func() {
				<-semaphore
				<-grantSemaphore
				<-s.connectorGlobalSemaphore
			}()
		default:
			<-grantSemaphore
			<-s.connectorGlobalSemaphore
			s.mu.Unlock()
			writeGatewayError(w, http.StatusTooManyRequests, "connector_busy", "connector concurrency limit reached")
			return
		}

		deadline := time.Now().Add(time.Duration(connector.MaxSeconds) * time.Second)
		controller := http.NewResponseController(w)
		_ = controller.SetReadDeadline(deadline)
		_ = controller.SetWriteDeadline(deadline)
		requestContext, cancel := context.WithDeadline(request.Context(), deadline)
		defer cancel()
		stopRevocation := context.AfterFunc(lease, cancel)
		defer stopRevocation()
		request = request.WithContext(requestContext)

		body, err := readConnectorJSONBody(w, request, connector, operation)
		if err != nil {
			var tooLarge *http.MaxBytesError
			if errors.As(err, &tooLarge) {
				writeGatewayError(w, http.StatusRequestEntityTooLarge, "request_too_large", "connector request exceeds its byte limit")
			} else {
				writeGatewayError(w, http.StatusBadRequest, "invalid_json_body", err.Error())
			}
			return
		}

		permit, permitErr := verifyConnectorActionPermit(
			request.Header, connector, s.connectors, grant, routePolicyDigest, connectorID, operationID, taskID, body, s.now().UTC(),
		)
		if permitErr != nil {
			slog.Warn("connector action permit denied", "grant_id", grantID, "connector_id", connectorID,
				"operation_id", operationID, "reason", permitErr.Error())
			if grant.EffectMode == EffectModeAuthorized {
				requestDigest := actionpermit.RequestDigest(body)
				operationDigest, digestErr := ConnectorOperationPolicyDigest(
					connector.BaseURL, connector.CredentialMode, connector.CredentialEpoch, connectorID, operation,
				)
				callDigest := ConnectorCallDigest(grant.TenantID, grant.InstanceID, taskID, connectorID, operationID)
				if digestErr != nil || s.recordActionPermitDenial(connectorDenialEvent(
					grant, routePolicyDigest, connectorID, operationID, operationDigest, callDigest,
					requestDigest, int64(len(body)),
				)) != nil {
					writeGatewayError(w, http.StatusServiceUnavailable, "evidence_unavailable", "connector denial could not be recorded")
					return
				}
			}
			writeGatewayError(w, http.StatusForbidden, "action_permit_denied", "a valid action permit for the exact connector request is required")
			return
		}
		callDigest := ConnectorCallDigest(grant.TenantID, grant.InstanceID, taskID, connectorID, operationID)
		receipt := connectorReceiptEvent(
			grant, routePolicyDigest, connectorID, operationID, callDigest, permit.authorityKeyID,
			permit.authorityKeyIDs, permit.approvalThreshold,
			permit.permitDigest, permit.requestDigest, int64(len(body)),
			permit.operationDigest,
		)
		if err := s.spendConnectorCall(grantID, connectorID, callDigest, receipt); err != nil {
			switch {
			case errors.Is(err, errConnectorReplay):
				writeGatewayError(w, http.StatusConflict, "connector_task_replayed", "connector task was already spent")
			case errors.Is(err, errConnectorCallLimit):
				writeGatewayError(w, http.StatusTooManyRequests, "connector_call_limit", "connector call budget is exhausted")
			case errors.Is(err, errConnectorInactive):
				writeGatewayError(w, http.StatusServiceUnavailable, "grant_inactive", "connector grant is not active")
			case errors.Is(err, connectorledger.ErrTenantQuotaExceeded),
				errors.Is(err, connectorledger.ErrTenantUnbudgeted),
				errors.Is(err, connectorledger.ErrTenantIdentityCapacity):
				writeGatewayError(w, http.StatusServiceUnavailable, "connector_evidence_quota_exhausted", "tenant connector receipt capacity is exhausted")
			default:
				writeGatewayError(w, http.StatusServiceUnavailable, "evidence_unavailable", "connector authorization could not be recorded")
			}
			return
		}
		if !permit.expiresAt.IsZero() && !s.now().UTC().Before(permit.expiresAt) {
			if err := s.finishConnectorReceipt(receipt, 0, 0, "action_permit_expired"); err != nil {
				writeGatewayError(w, http.StatusServiceUnavailable, "evidence_unavailable", "connector result could not be recorded")
				return
			}
			writeGatewayError(w, http.StatusForbidden, "action_permit_denied", "the action permit expired before the connector effect could begin")
			return
		}
		// Spending is durable before DNS because DNS itself is externally visible.
		// Address-denied and resolution-failed attempts therefore consume the same
		// bounded grant budget and cannot be retried without a new task ID.
		host := connector.base.Hostname()
		port := connectorPort(connector.base.Scheme, connector.base.Port())
		ip, err := resolveAllowedIP(request.Context(), host, loadedEgressDestination{prefixes: connector.prefixes})
		if err != nil {
			status, code := classifyAddressFailure(err, lease)
			if receiptErr := s.finishConnectorReceipt(receipt, 0, 0, code); receiptErr != nil {
				writeGatewayError(w, http.StatusServiceUnavailable, "evidence_unavailable", "connector result could not be recorded")
				return
			}
			switch code {
			case "grant_revoked":
				writeGatewayError(w, status, code, "connector grant was revoked during address resolution")
			case "address_denied":
				writeGatewayError(w, status, code, "connector origin resolved only to addresses outside the active policy")
			default:
				writeGatewayError(w, status, code, "connector origin address resolution failed")
			}
			return
		}
		s.proxyConnector(w, request, connector, operation, body, ip, port, receipt)
	})
}

type connectorActionPermit struct {
	authorityKeyID    string
	authorityKeyIDs   []string
	approvalThreshold int
	permitDigest      string
	requestDigest     string
	operationDigest   string
	expiresAt         time.Time
}

func verifyConnectorActionPermit(
	header http.Header,
	connector loadedConnector,
	connectors map[string]loadedConnector,
	grant Grant,
	routePolicyDigest, connectorID, operationID, taskID string,
	body []byte,
	now time.Time,
) (connectorActionPermit, error) {
	values := header.Values(actionPermitHeader)
	if len(connector.authorities) == 0 {
		if len(values) != 0 {
			return connectorActionPermit{}, errors.New("connector does not accept action permits")
		}
		return connectorActionPermit{}, nil
	}
	if len(values) != 1 {
		return connectorActionPermit{}, errors.New("exactly one action permit header is required")
	}
	raw, err := actionpermit.DecodeHeader(values[0])
	if err != nil {
		return connectorActionPermit{}, fmt.Errorf("decode permit header: %w", err)
	}
	trusted := connector.authorities
	if grant.EffectMode == EffectModeAuthorized {
		trusted = grantActionAuthorityKeys(grant, connectorID)
	}
	verified, err := actionpermit.Verify(
		raw, trusted, now, time.Duration(connector.MaxActionPermitSeconds)*time.Second,
	)
	if err != nil {
		return connectorActionPermit{}, err
	}
	if verified.PayloadType == actionpermit.PayloadTypeV4 {
		return verifyConnectorActionBundle(
			verified, connector, connectors, grant, routePolicyDigest, connectorID, operationID, taskID, body,
		)
	}
	statement := verified.Statement
	requestDigest := actionpermit.RequestDigest(body)
	operation, operationExists := connector.operations[operationID]
	if !operationExists {
		return connectorActionPermit{}, errors.New("permit operation is not configured")
	}
	operationDigest, err := ConnectorOperationPolicyDigest(
		connector.BaseURL, connector.CredentialMode, connector.CredentialEpoch, connectorID, operation,
	)
	if err != nil {
		return connectorActionPermit{}, errors.New("connector operation policy is invalid")
	}
	contentType, err := ConnectorOperationContentType(operation.Method)
	if err != nil {
		return connectorActionPermit{}, errors.New("connector operation content type is invalid")
	}
	requiredPayloadType := actionpermit.PayloadTypeV1
	requiredEffectMode := ""
	requiredApprovalThreshold := 0
	if grant.EffectMode == EffectModeAuthorized {
		requiredPayloadType = actionpermit.PayloadTypeV2
		if grant.ActionApprovalThreshold > 1 {
			requiredPayloadType = actionpermit.PayloadTypeV3
			requiredApprovalThreshold = grant.ActionApprovalThreshold
		}
		requiredEffectMode = actionpermit.EffectModeAuthorized
	}
	if verified.PayloadType != requiredPayloadType || statement.EffectMode != requiredEffectMode ||
		statement.ApprovalThreshold != requiredApprovalThreshold ||
		statement.NodeID != connector.permitNodeID || statement.TenantID != grant.TenantID ||
		statement.InstanceID != grant.InstanceID || statement.Generation != grant.Generation ||
		statement.CapsuleDigest != grant.CapsuleDigest || statement.PolicyDigest != grant.PolicyDigest ||
		statement.RoutePolicyDigest != routePolicyDigest || statement.ConnectorID != connectorID ||
		statement.OperationID != operationID || statement.OperationDigest != operationDigest || statement.TaskID != taskID ||
		statement.RequestDigest != requestDigest || statement.RequestBytes != int64(len(body)) ||
		statement.ContentType != contentType {
		return connectorActionPermit{}, errors.New("permit does not match the active tenant, grant, operation, task, and request")
	}
	for _, keyID := range verified.KeyIDs {
		if connector.authorityTenants[keyID] != grant.TenantID {
			return connectorActionPermit{}, errors.New("permit signer does not match the active tenant")
		}
	}
	expiresAt, err := time.Parse(time.RFC3339, statement.ExpiresAt)
	if err != nil {
		return connectorActionPermit{}, errors.New("permit expiry is invalid")
	}
	return connectorActionPermit{
		authorityKeyID: verified.KeyID, authorityKeyIDs: append([]string(nil), verified.KeyIDs...),
		approvalThreshold: statement.ApprovalThreshold, permitDigest: verified.EnvelopeDigest,
		requestDigest: requestDigest, operationDigest: operationDigest, expiresAt: expiresAt,
	}, nil
}

func verifyConnectorActionBundle(
	verified actionpermit.Verified,
	selectedConnector loadedConnector,
	connectors map[string]loadedConnector,
	grant Grant,
	routePolicyDigest, connectorID, operationID, taskID string,
	body []byte,
) (connectorActionPermit, error) {
	bundle := verified.Bundle
	if grant.EffectMode != EffectModeAuthorized || bundle == nil || bundle.ApprovalThreshold != grant.ActionApprovalThreshold ||
		bundle.NodeID != selectedConnector.permitNodeID || bundle.TenantID != grant.TenantID || bundle.InstanceID != grant.InstanceID ||
		bundle.Generation != grant.Generation || bundle.CapsuleDigest != grant.CapsuleDigest ||
		bundle.PolicyDigest != grant.PolicyDigest || bundle.RoutePolicyDigest != routePolicyDigest {
		return connectorActionPermit{}, errors.New("effect bundle does not match the active tenant and grant")
	}
	notBefore, err := time.Parse(time.RFC3339, bundle.NotBefore)
	if err != nil {
		return connectorActionPermit{}, errors.New("effect bundle validity is invalid")
	}
	expiresAt, err := time.Parse(time.RFC3339, bundle.ExpiresAt)
	if err != nil {
		return connectorActionPermit{}, errors.New("effect bundle expiry is invalid")
	}
	requestDigest := actionpermit.RequestDigest(body)
	selected := false
	selectedOperationDigest := ""
	for _, step := range bundle.Steps {
		stepConnector, configured := connectors[step.ConnectorID]
		if !configured || !slicesContainsSorted(grant.ConnectorIDs, step.ConnectorID) ||
			stepConnector.permitNodeID != bundle.NodeID || stepConnector.MaxActionPermitSeconds < 1 ||
			expiresAt.Sub(notBefore) > time.Duration(stepConnector.MaxActionPermitSeconds)*time.Second {
			return connectorActionPermit{}, errors.New("effect bundle contains a connector outside the active grant or its permit lifetime")
		}
		operation, exists := stepConnector.operations[step.OperationID]
		if !exists {
			return connectorActionPermit{}, errors.New("effect bundle operation is not configured")
		}
		operationDigest, digestErr := ConnectorOperationPolicyDigest(
			stepConnector.BaseURL, stepConnector.CredentialMode, stepConnector.CredentialEpoch, step.ConnectorID, operation,
		)
		contentType, contentTypeErr := ConnectorOperationContentType(operation.Method)
		if digestErr != nil || contentTypeErr != nil || step.OperationDigest != operationDigest || step.ContentType != contentType {
			return connectorActionPermit{}, errors.New("effect bundle operation does not match trusted connector policy")
		}
		for _, keyID := range verified.KeyIDs {
			if !grantAuthorityMatchesConnector(grant, stepConnector, keyID, step.ConnectorID) {
				return connectorActionPermit{}, errors.New("effect bundle signer is not authorized for every connector")
			}
		}
		if step.TaskID != taskID {
			continue
		}
		if step.ConnectorID != connectorID || step.OperationID != operationID || step.RequestDigest != requestDigest ||
			step.RequestBytes != int64(len(body)) || step.ContentType != contentType {
			return connectorActionPermit{}, errors.New("effect bundle step does not match the requested connector effect")
		}
		selected = true
		selectedOperationDigest = operationDigest
	}
	if !selected {
		return connectorActionPermit{}, errors.New("effect bundle does not contain the requested task")
	}
	return connectorActionPermit{
		authorityKeyID: verified.KeyID, authorityKeyIDs: append([]string(nil), verified.KeyIDs...),
		approvalThreshold: bundle.ApprovalThreshold, permitDigest: verified.EnvelopeDigest,
		requestDigest: requestDigest, operationDigest: selectedOperationDigest, expiresAt: expiresAt,
	}, nil
}

func grantAuthorityMatchesConnector(grant Grant, connector loadedConnector, keyID, connectorID string) bool {
	configured, ok := connector.authorities[keyID]
	if !ok || connector.authorityTenants[keyID] != grant.TenantID {
		return false
	}
	for _, authority := range grant.ActionAuthorities {
		if authority.KeyID != keyID || !slicesContainsSorted(authority.ConnectorIDs, connectorID) {
			continue
		}
		public, err := base64.StdEncoding.DecodeString(authority.PublicKey)
		return err == nil && len(public) == ed25519.PublicKeySize && bytes.Equal(public, configured)
	}
	return false
}

func grantActionAuthorityKeys(grant Grant, connectorID string) map[string]ed25519.PublicKey {
	keys := make(map[string]ed25519.PublicKey)
	for _, authority := range grant.ActionAuthorities {
		if !slicesContainsSorted(authority.ConnectorIDs, connectorID) {
			continue
		}
		public, err := base64.StdEncoding.DecodeString(authority.PublicKey)
		if err != nil || len(public) != ed25519.PublicKeySize {
			continue
		}
		keys[authority.KeyID] = ed25519.PublicKey(append([]byte(nil), public...))
	}
	return keys
}

func (s *Server) allowConnectorAttemptNow(grantID string) bool {
	return s.allowConnectorAttemptWithClock(grantID, time.Now)
}

func (s *Server) allowConnectorAttemptWithClock(grantID string, clock func() time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Read the clock only after taking the limiter lock. If concurrent callers
	// capture time before locking, the request with the later timestamp can
	// commit first and make the other look like a clock rollback.
	return s.allowConnectorAttemptLocked(grantID, clock())
}

func (s *Server) allowConnectorAttempt(grantID string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.allowConnectorAttemptLocked(grantID, now)
}

func (s *Server) allowConnectorAttemptLocked(grantID string, now time.Time) bool {
	// A request already accepted by the Unix listener can outlive unregister.
	// Do not let that late request recreate limiter state for a deleted grant.
	if _, ok := s.grants[grantID]; !ok {
		return false
	}
	if s.connectorAttempts == nil {
		s.connectorAttempts = make(map[string]connectorAttemptWindow)
	}
	window := s.connectorAttempts[grantID]
	if now.Before(window.started) {
		return false
	}
	if window.started.IsZero() || now.Sub(window.started) >= time.Minute {
		window = connectorAttemptWindow{started: now}
	}
	if window.count >= maxConnectorAttemptsPerMinute {
		return false
	}
	window.count++
	s.connectorAttempts[grantID] = window
	return true
}

func connectorRequestTarget(request *http.Request) (string, string, bool) {
	if request.URL == nil || request.URL.RawQuery != "" || request.URL.ForceQuery || request.URL.RawPath != "" ||
		request.RequestURI != request.URL.Path {
		return "", "", false
	}
	parts := strings.Split(request.URL.Path, "/")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "v1" || parts[2] != "connectors" || parts[4] != "operations" ||
		!routeID(parts[3]) || !routeID(parts[5]) {
		return "", "", false
	}
	return parts[3], parts[5], true
}

func connectorTaskID(header http.Header) (string, bool) {
	values := header.Values("X-Steward-Task-ID")
	returnValue := ""
	if len(values) == 1 {
		returnValue = values[0]
	}
	return returnValue, len(values) == 1 && routeID(returnValue)
}

func readConnectorJSONBody(w http.ResponseWriter, request *http.Request, connector loadedConnector, operation ConnectorOperation) ([]byte, error) {
	request.Body = http.MaxBytesReader(w, request.Body, connector.MaxRequestBytes)
	raw, err := io.ReadAll(request.Body)
	if err != nil {
		return nil, err
	}
	if !connectorMethodHasBody(operation.Method) {
		if len(raw) != 0 {
			return nil, errors.New("connector method does not accept a request body")
		}
		return nil, nil
	}
	mediaType, parameters, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" || len(parameters) > 1 ||
		(len(parameters) == 1 && !strings.EqualFold(parameters["charset"], "utf-8")) {
		return nil, errors.New("connector request body requires application/json")
	}
	if len(raw) == 0 {
		return nil, errors.New("connector request requires a JSON body")
	}
	// Wrap the opaque body so the existing strict decoder can reject duplicate
	// object keys, excessive nesting, trailing values, and malformed JSON while
	// preserving the exact validated bytes sent upstream.
	wrapper := make([]byte, 0, len(raw)+10)
	wrapper = append(wrapper, `{"value":`...)
	wrapper = append(wrapper, raw...)
	wrapper = append(wrapper, '}')
	var decoded struct {
		Value json.RawMessage `json:"value"`
	}
	if err := dsse.DecodeStrictInto(wrapper, int(connector.MaxRequestBytes)+10, &decoded); err != nil {
		return nil, errors.New("connector request body must contain one valid JSON value")
	}
	return raw, nil
}

func connectorPort(scheme, portText string) int {
	if portText != "" {
		port, _ := strconv.Atoi(portText)
		return port
	}
	if scheme == "https" {
		return 443
	}
	return 80
}

// ConnectorCallDigest returns the durable, non-secret replay identity for one
// logical connector effect. It is exported for offline permit-to-receipt audit.
func ConnectorCallDigest(tenantID, instanceID, taskID, connectorID, operationID string) string {
	digest := sha256.New()
	_, _ = digest.Write([]byte("steward-gateway-connector-call-v1\x00"))
	for _, value := range []string{tenantID, instanceID, taskID, connectorID, operationID} {
		_, _ = digest.Write([]byte(value))
		_, _ = digest.Write([]byte{0})
	}
	return "sha256:" + fmt.Sprintf("%x", digest.Sum(nil))
}

// ConnectorOperationPolicyDigest identifies the exact non-secret effect route
// that one logical operation selects. It deliberately excludes credential bytes
// while including their injection mode and the operator-managed credential epoch.
func ConnectorOperationPolicyDigest(
	baseURL string,
	credentialMode CredentialMode,
	credentialEpoch uint64,
	connectorID string,
	operation ConnectorOperation,
) (string, error) {
	base, err := exactConnectorOrigin(baseURL)
	if err != nil || (credentialMode != CredentialModeBearer && credentialMode != CredentialModeXAPIKey) ||
		credentialEpoch == 0 || !routeID(connectorID) || !routeID(operation.ID) ||
		!connectorMethod(operation.Method) || !canonicalConnectorPath(operation.Path) {
		return "", errors.New("connector operation policy is invalid")
	}
	digest := sha256.New()
	_, _ = digest.Write([]byte("steward-connector-operation-policy-v1\x00"))
	for _, value := range []string{
		connectorID, base.String(), string(credentialMode), strconv.FormatUint(credentialEpoch, 10),
		operation.ID, operation.Method, operation.Path,
	} {
		_, _ = digest.Write([]byte(value))
		_, _ = digest.Write([]byte{0})
	}
	return "sha256:" + fmt.Sprintf("%x", digest.Sum(nil)), nil
}

// ConnectorOperationContentType returns the outbound Content-Type fixed by
// Gateway for a validated connector method.
func ConnectorOperationContentType(method string) (string, error) {
	if !connectorMethod(method) {
		return "", errors.New("unsupported connector method")
	}
	if connectorMethodHasBody(method) {
		return "application/json", nil
	}
	return "", nil
}

func (s *Server) spendConnectorCall(grantID, connectorID, digest string, receipt connectorledger.Event) error {
	s.mu.Lock()
	grant, ok := s.grants[grantID]
	connector, connectorOK := s.connectors[connectorID]
	if !ok || !grant.Active || !connectorOK || !slicesContainsSorted(grant.ConnectorIDs, connectorID) {
		s.mu.Unlock()
		return errConnectorInactive
	}
	if _, spent := s.connectorSpends[digest]; spent {
		s.mu.Unlock()
		return errConnectorReplay
	}
	if s.connectorCallCounts[grantID][connectorID] >= connector.MaxCallsPerGrant {
		s.mu.Unlock()
		return errConnectorCallLimit
	}
	ledger := s.connectorLedger
	if ledger == nil {
		s.mu.Unlock()
		return errors.New("connector receipt ledger is unavailable")
	}
	owner := connectorSpendOwner{GrantID: grantID, ConnectorID: connectorID}
	s.connectorSpends[digest] = owner
	if s.connectorCallCounts[grantID] == nil {
		s.connectorCallCounts[grantID] = make(map[string]int)
	}
	s.connectorCallCounts[grantID][connectorID]++
	s.mu.Unlock()

	// The in-memory reservation serializes replay and budget checks, but the
	// signed append may block on storage without blocking unrelated grants or
	// revocation behind the Gateway's global state mutex.
	if _, err := ledger.Begin(receipt); err != nil {
		if !ledger.Failed() {
			s.mu.Lock()
			if current, reserved := s.connectorSpends[digest]; reserved && current == owner {
				delete(s.connectorSpends, digest)
				if s.connectorCallCounts[grantID][connectorID] > 0 {
					s.connectorCallCounts[grantID][connectorID]--
				}
			}
			s.mu.Unlock()
		}
		return err
	}
	return nil
}

func slicesContainsSorted(values []string, value string) bool {
	low, high := 0, len(values)
	for low < high {
		middle := int(uint(low+high) >> 1)
		if values[middle] < value {
			low = middle + 1
		} else {
			high = middle
		}
	}
	return low < len(values) && values[low] == value
}

func (s *Server) proxyConnector(
	w http.ResponseWriter,
	incoming *http.Request,
	connector loadedConnector,
	operation ConnectorOperation,
	body []byte,
	ip netip.Addr,
	port int,
	receipt connectorledger.Event,
) {
	target := *connector.base
	target.Path = operation.Path
	var bodyReader io.Reader
	if connectorMethodHasBody(operation.Method) {
		bodyReader = bytes.NewReader(body)
	}
	request, err := http.NewRequestWithContext(incoming.Context(), operation.Method, target.String(), bodyReader)
	if err != nil {
		if receiptErr := s.finishConnectorReceipt(receipt, 0, 0, "invalid_request"); receiptErr != nil {
			writeGatewayError(w, http.StatusServiceUnavailable, "evidence_unavailable", "connector result could not be recorded")
			return
		}
		writeGatewayError(w, http.StatusBadRequest, "invalid_request", "cannot construct connector request")
		return
	}
	request.Header.Set("Accept", "application/json")
	if bodyReader != nil {
		request.Header.Set("Content-Type", "application/json")
		request.ContentLength = int64(len(body))
	}
	switch connector.CredentialMode {
	case CredentialModeBearer:
		request.Header.Set("Authorization", "Bearer "+connector.credential)
	case CredentialModeXAPIKey:
		request.Header.Set("X-API-Key", connector.credential)
	default:
		if receiptErr := s.finishConnectorReceipt(receipt, 0, 0, "connector_unavailable"); receiptErr != nil {
			writeGatewayError(w, http.StatusServiceUnavailable, "evidence_unavailable", "connector result could not be recorded")
			return
		}
		writeGatewayError(w, http.StatusServiceUnavailable, "connector_unavailable", "connector credential mode is unavailable")
		return
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), strconv.Itoa(port)))
		},
		ResponseHeaderTimeout:  time.Duration(connector.MaxSeconds) * time.Second,
		TLSHandshakeTimeout:    10 * time.Second,
		MaxResponseHeaderBytes: maxHTTPHeaderBytes,
		IdleConnTimeout:        30 * time.Second,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport, Timeout: time.Duration(connector.MaxSeconds) * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	response, err := client.Do(request)
	if err != nil {
		if receiptErr := s.finishConnectorReceipt(receipt, 0, 0, "upstream_unavailable"); receiptErr != nil {
			writeGatewayError(w, http.StatusServiceUnavailable, "evidence_unavailable", "connector result could not be recorded")
			return
		}
		writeGatewayError(w, http.StatusBadGateway, "upstream_unavailable", "configured connector request failed")
		return
	}
	defer response.Body.Close()
	if response.StatusCode >= 300 && response.StatusCode < 400 {
		if receiptErr := s.finishConnectorReceipt(receipt, 0, 0, "redirect_denied"); receiptErr != nil {
			writeGatewayError(w, http.StatusServiceUnavailable, "evidence_unavailable", "connector result could not be recorded")
			return
		}
		writeGatewayError(w, http.StatusBadGateway, "redirect_denied", "configured connector returned a redirect")
		return
	}
	if response.ContentLength > connector.MaxResponseBytes {
		if receiptErr := s.finishConnectorReceipt(receipt, 0, 0, "response_too_large"); receiptErr != nil {
			writeGatewayError(w, http.StatusServiceUnavailable, "evidence_unavailable", "connector result could not be recorded")
			return
		}
		writeGatewayError(w, http.StatusBadGateway, "response_too_large", "configured upstream response exceeds the byte limit")
		return
	}
	if headerContainsCredential(response.Header, connector.credential) {
		if receiptErr := s.finishConnectorReceipt(receipt, response.StatusCode, 0, "credential_reflected"); receiptErr != nil {
			writeGatewayError(w, http.StatusServiceUnavailable, "evidence_unavailable", "connector result could not be recorded")
			return
		}
		writeGatewayError(w, http.StatusBadGateway, "credential_reflected", "configured upstream reflected the connector credential")
		return
	}
	copyHeaders(w.Header(), response.Header)
	for _, name := range []string{
		"Authorization", "Proxy-Authorization", "X-API-Key", "Set-Cookie", "Location",
	} {
		w.Header().Del(name)
	}
	// X-Steward-* is reserved for integrity and enforcement signals produced by
	// this deployment. An upstream must not be able to forge any such header.
	for name := range w.Header() {
		if strings.HasPrefix(strings.ToLower(name), "x-steward-") {
			w.Header().Del(name)
		}
	}
	if connectorResponseHasNoBody(incoming.Method, response.StatusCode) {
		if err := s.finishConnectorReceipt(receipt, response.StatusCode, 0, ""); err != nil {
			writeGatewayError(w, http.StatusServiceUnavailable, "evidence_unavailable", "connector result could not be recorded")
			return
		}
		w.Header().Set(connectorReceiptStatusTrailer, "recorded")
		w.WriteHeader(response.StatusCode)
		return
	}
	// Connector success is complete only when the signed terminal receipt is
	// durable. Force a trailer-framed response so a failed receipt append cannot
	// look like a clean, content-length-delimited success to the agent.
	prepareBoundedHTTPResponse(w, -1)
	w.Header().Add("Trailer", connectorReceiptStatusTrailer)
	w.WriteHeader(response.StatusCode)
	result := copyConnectorResponseBody(w, response.Body, connector.MaxResponseBytes, connector.credential)
	errorCode := ""
	if result.abort {
		errorCode = result.reason
	}
	if err := s.finishConnectorReceipt(receipt, response.StatusCode, result.written, errorCode); err != nil {
		panic(http.ErrAbortHandler)
	}
	w.Header().Set(connectorReceiptStatusTrailer, "recorded")
	if result.abort {
		panic(http.ErrAbortHandler)
	}
}

func connectorResponseHasNoBody(method string, status int) bool {
	return method == http.MethodHead || status == http.StatusNoContent || status == http.StatusNotModified
}

func headerContainsCredential(header http.Header, credential string) bool {
	foldedCredential := strings.ToLower(credential)
	for name, values := range header {
		// net/http canonicalizes field names, so compare their ASCII case-folded
		// form against the visible-ASCII credential before forwarding either the
		// name or its values.
		if strings.Contains(strings.ToLower(name), foldedCredential) {
			return true
		}
		for _, value := range values {
			if strings.Contains(value, credential) {
				return true
			}
		}
	}
	return false
}

// credentialRejectingWriter scans fixed-size blocks while retaining
// len(credential)-1 bytes between scans. The carry detects an exact credential
// split across blocks; coalescing small upstream writes keeps scan work linear
// in the response size. It does not buffer the complete bounded response or try
// to classify transformed data.
type credentialRejectingWriter struct {
	destination io.Writer
	credential  []byte
	pending     []byte
	written     int64
	reflected   bool
}

func (w *credentialRejectingWriter) Write(value []byte) (int, error) {
	if w.reflected {
		return 0, errConnectorCredentialReflected
	}
	w.pending = append(w.pending, value...)
	retain := len(w.credential) - 1
	if len(w.pending) < connectorCredentialScanBlockBytes+retain {
		return len(value), nil
	}
	if err := w.scanAndFlush(len(w.pending) - retain); err != nil {
		return len(value), err
	}
	return len(value), nil
}

func (w *credentialRejectingWriter) finish() error {
	if w.reflected {
		return errConnectorCredentialReflected
	}
	return w.scanAndFlush(len(w.pending))
}

func (w *credentialRejectingWriter) scanAndFlush(safe int) error {
	if index := bytes.Index(w.pending, w.credential); index >= 0 {
		if err := w.flushPrefix(index); err != nil {
			return err
		}
		clear(w.pending)
		w.pending = nil
		w.reflected = true
		return errConnectorCredentialReflected
	}
	return w.flushPrefix(safe)
}

func (w *credentialRejectingWriter) flushPrefix(length int) error {
	data := w.pending[:length]
	for len(data) > 0 {
		count, err := w.destination.Write(data)
		w.written += int64(count)
		if err != nil {
			return err
		}
		if count == 0 {
			return io.ErrShortWrite
		}
		data = data[count:]
	}
	remaining := copy(w.pending, w.pending[length:])
	clear(w.pending[remaining:])
	w.pending = w.pending[:remaining]
	return nil
}

func copyConnectorResponseBody(w http.ResponseWriter, body io.Reader, maximum int64, credential string) boundedHTTPResponseResult {
	destination := flushingResponseWriter{writer: w, controller: http.NewResponseController(w)}
	filter := credentialRejectingWriter{destination: destination, credential: []byte(credential)}
	consumed, copyErr := io.Copy(&filter, io.LimitReader(body, maximum))
	if copyErr == nil {
		copyErr = filter.finish()
	}
	result := boundedHTTPResponseResult{written: filter.written, reason: "completed"}
	switch {
	case errors.Is(copyErr, errConnectorCredentialReflected):
		result.reason, result.abort = "credential_reflected", true
	case copyErr != nil:
		result.reason, result.abort = "stream_failed", true
	case consumed == maximum:
		var probe [1]byte
		count, probeErr := io.ReadFull(body, probe[:])
		switch {
		case count > 0:
			result.reason, result.abort = "response_too_large", true
		case probeErr != nil && !errors.Is(probeErr, io.EOF) && !errors.Is(probeErr, io.ErrUnexpectedEOF):
			result.reason, result.abort = "stream_failed", true
		}
	}
	w.Header().Set(streamStatusTrailer, result.reason)
	return result
}
