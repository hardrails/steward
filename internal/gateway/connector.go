package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/hardrails/steward/internal/connectorledger"
	"github.com/hardrails/steward/internal/dsse"
)

var (
	errConnectorCallLimit = errors.New("connector call budget exhausted")
	errConnectorReplay    = errors.New("connector task was already spent")
	errConnectorInactive  = errors.New("connector grant is not active")
)

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
		if !s.allowConnectorAttempt(grantID, time.Now()) {
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

		callDigest := connectorCallDigest(grant.TenantID, grant.InstanceID, taskID, connectorID, operationID)
		receipt := connectorReceiptEvent(grant, routePolicyDigest, connectorID, operationID, callDigest, int64(len(body)))
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

func (s *Server) allowConnectorAttempt(grantID string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
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

func connectorCallDigest(tenantID, instanceID, taskID, connectorID, operationID string) string {
	digest := sha256.New()
	_, _ = digest.Write([]byte("steward-gateway-connector-call-v1\x00"))
	for _, value := range []string{tenantID, instanceID, taskID, connectorID, operationID} {
		_, _ = digest.Write([]byte(value))
		_, _ = digest.Write([]byte{0})
	}
	return "sha256:" + fmt.Sprintf("%x", digest.Sum(nil))
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
	result := copyHTTPResponseBody(w, response.Body, connector.MaxResponseBytes, true)
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
