package gateway

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

const tlsClientHelloTimeout = 5 * time.Second

var (
	errAddressDenied           = errors.New("resolved address is outside the allowed policy")
	errAddressResolutionFailed = errors.New("address resolution failed")
)

func (s *Server) listenEgressGrantLocked(id string) error {
	if listener := s.egressListeners[id]; listener != nil {
		return nil
	}
	directory := GrantDirectory(s.config.GrantRoot, id)
	path := egressSocketPath(s.config.GrantRoot, id)
	listener, err := openGrantListener(directory, path, s.config.RelayGID)
	if err != nil {
		return err
	}
	s.egressListeners[id] = listener
	server := &http.Server{
		Handler: s.egressHandler(id), ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout: 30 * time.Second, MaxHeaderBytes: maxHTTPHeaderBytes,
	}
	go func() { _ = server.Serve(listener) }()
	return nil
}

func (s *Server) egressHandler(id string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		grant, ok := s.grants[id]
		if !ok || len(grant.EgressRouteIDs) == 0 {
			s.mu.Unlock()
			writeGatewayError(w, http.StatusServiceUnavailable, "grant_inactive", "egress grant is not active")
			return
		}
		if !grant.Active {
			s.mu.Unlock()
			s.rejectEgress(w, grant, "grant_inactive", r.Method, "", 0, http.StatusServiceUnavailable, "egress grant is not active")
			return
		}
		host, port, err := proxyDestination(r)
		if err != nil {
			s.mu.Unlock()
			s.rejectEgress(w, grant, "invalid_destination", r.Method, "", 0, http.StatusBadRequest, err.Error())
			return
		}
		routeID, route, destination, ok := s.selectEgressRoute(grant, host, port)
		var semaphore chan struct{}
		if ok {
			semaphore = s.egressSemaphores[routeID]
		}
		if !ok {
			s.mu.Unlock()
			s.rejectEgress(w, grant, "route_denied", r.Method, host, port, http.StatusForbidden, "destination is not allowed by the active egress grant")
			return
		}
		lease := s.egressLeaseLocked(id)
		select {
		case semaphore <- struct{}{}:
			s.mu.Unlock()
			defer func() { <-semaphore }()
		default:
			s.mu.Unlock()
			s.rejectEgress(w, grant, "route_busy", r.Method, host, port, http.StatusTooManyRequests, "egress route concurrency limit reached")
			return
		}
		deadline := time.Now().Add(time.Duration(route.MaxTunnelSeconds) * time.Second)
		controller := http.NewResponseController(w)
		_ = controller.SetReadDeadline(deadline)
		_ = controller.SetWriteDeadline(deadline)
		requestContext, cancel := context.WithDeadline(r.Context(), deadline)
		defer cancel()
		stopRevocation := context.AfterFunc(lease, cancel)
		defer stopRevocation()
		r = r.WithContext(requestContext)
		ip, err := resolveAllowedIP(r.Context(), host, destination)
		if err != nil {
			status, code := classifyAddressFailure(err, lease)
			switch code {
			case "grant_revoked":
				s.rejectEgress(w, grant, code, r.Method, host, port, status, "egress grant was revoked during address resolution")
			case "address_denied":
				s.rejectEgress(w, grant, code, r.Method, host, port, status, "destination resolved only to addresses outside the active policy")
			default:
				s.rejectEgress(w, grant, code, r.Method, host, port, status, "destination address resolution failed")
			}
			return
		}
		if r.Method == http.MethodConnect {
			s.proxyConnect(w, r, grant, routeID, route, host, port, ip)
			return
		}
		if err := s.recordEgressAllow(grant, routeID, r.Method, host, port); err != nil {
			writeGatewayError(w, http.StatusServiceUnavailable, "audit_unavailable", "egress audit record could not be persisted")
			return
		}
		s.proxyHTTP(w, r, grant, routeID, route, host, port, ip)
	})
}

func (s *Server) recordEgressAllow(grant Grant, routeID, method, host string, port int) error {
	event := egressAuditEvent{Decision: "allow", Reason: "route_allowed", GrantID: grant.GrantID,
		TenantID: grant.TenantID, InstanceID: grant.InstanceID, RouteID: routeID,
		Method: method, Host: host, Port: port}
	if err := s.audit.Append(event); err != nil {
		return err
	}
	s.updateEgressStats(grant.GrantID, event)
	return nil
}

func proxyDestination(request *http.Request) (string, int, error) {
	if request.Method == http.MethodConnect {
		host, portText, err := net.SplitHostPort(request.Host)
		port, parseErr := strconv.Atoi(portText)
		if err != nil || parseErr != nil || host == "" || port < 1 || port > 65535 {
			return "", 0, errors.New("CONNECT requires an explicit hostname and port")
		}
		return strings.ToLower(strings.TrimSuffix(host, ".")), port, nil
	}
	if request.URL == nil || !request.URL.IsAbs() || request.URL.User != nil || request.URL.Fragment != "" ||
		(request.URL.Scheme != "http" && request.URL.Scheme != "https") {
		return "", 0, errors.New("proxy request requires an absolute HTTP(S) URL")
	}
	host := strings.ToLower(strings.TrimSuffix(request.URL.Hostname(), "."))
	port := 80
	if request.URL.Scheme == "https" {
		port = 443
	}
	if request.URL.Port() == "" {
		if invalidExplicitPort(request.URL.Host, host) {
			return "", 0, errors.New("proxy URL has an invalid port")
		}
	} else {
		parsed, err := strconv.Atoi(request.URL.Port())
		if err != nil || parsed < 1 || parsed > 65535 {
			return "", 0, errors.New("proxy URL has an invalid port")
		}
		port = parsed
	}
	if host == "" {
		return "", 0, errors.New("proxy URL requires a hostname")
	}
	return host, port, nil
}

func invalidExplicitPort(rawHost, hostname string) bool {
	if !strings.Contains(rawHost, ":") {
		return false
	}
	if net.ParseIP(hostname) == nil {
		return true
	}
	if !strings.HasPrefix(rawHost, "[") {
		return true
	}
	closing := strings.LastIndexByte(rawHost, ']')
	return closing < 0 || closing != len(rawHost)-1
}

func (s *Server) selectEgressRoute(grant Grant, host string, port int) (string, loadedEgressRoute, loadedEgressDestination, bool) {
	for _, id := range grant.EgressRouteIDs {
		route := s.egressRoutes[id]
		for _, destination := range route.destinations {
			if hostMatches(destination.Host, host) && containsPort(destination.Ports, port) {
				return id, route, destination, true
			}
		}
	}
	return "", loadedEgressRoute{}, loadedEgressDestination{}, false
}

func hostMatches(pattern, host string) bool {
	if !strings.HasPrefix(pattern, "*.") {
		return pattern == host
	}
	suffix := strings.TrimPrefix(pattern, "*")
	return len(host) > len(suffix) && strings.HasSuffix(host, suffix)
}

func containsPort(ports []int, port int) bool {
	for _, allowed := range ports {
		if allowed == port {
			return true
		}
	}
	return false
}

func resolveAllowedIP(ctx context.Context, host string, destination loadedEgressDestination) (netip.Addr, error) {
	var addresses []netip.Addr
	if literal, err := netip.ParseAddr(host); err == nil {
		addresses = []netip.Addr{literal}
	} else {
		resolved, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return netip.Addr{}, fmt.Errorf("%w: %v", errAddressResolutionFailed, err)
		}
		addresses = append(addresses, resolved...)
	}
	if len(addresses) == 0 {
		return netip.Addr{}, errAddressResolutionFailed
	}
	for _, address := range addresses {
		if addressAllowed(address, destination.prefixes) {
			return address.Unmap(), nil
		}
	}
	return netip.Addr{}, errAddressDenied
}

func classifyAddressFailure(err error, lease context.Context) (int, string) {
	if lease != nil && lease.Err() != nil {
		return http.StatusServiceUnavailable, "grant_revoked"
	}
	if errors.Is(err, errAddressDenied) {
		return http.StatusForbidden, "address_denied"
	}
	return http.StatusBadGateway, "resolution_failed"
}

func (s *Server) proxyHTTP(w http.ResponseWriter, incoming *http.Request, grant Grant, routeID string, route loadedEgressRoute, host string, port int, ip netip.Addr) {
	if incoming.ContentLength > route.MaxRequestBytes {
		s.finishEgress(grant, routeID, "request_too_large", incoming.Method, host, port, 0, 0)
		writeGatewayError(w, http.StatusRequestEntityTooLarge, "request_too_large", "egress request exceeds route byte limit")
		return
	}
	incoming.Body = http.MaxBytesReader(w, incoming.Body, route.MaxRequestBytes)
	target := *incoming.URL
	request, err := http.NewRequestWithContext(incoming.Context(), incoming.Method, target.String(), incoming.Body)
	if err != nil {
		writeGatewayError(w, http.StatusBadRequest, "invalid_request", "cannot construct egress request")
		return
	}
	copyHeaders(request.Header, incoming.Header)
	request.Header.Del("Proxy-Authorization")
	request.Host = incoming.URL.Host
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), strconv.Itoa(port)))
	}, ResponseHeaderTimeout: 30 * time.Second, MaxResponseHeaderBytes: maxHTTPHeaderBytes,
		IdleConnTimeout: 30 * time.Second, TLSHandshakeTimeout: 10 * time.Second}
	defer transport.CloseIdleConnections()
	response, err := transport.RoundTrip(request)
	if err != nil {
		s.finishEgress(grant, routeID, "upstream_unavailable", incoming.Method, host, port, incoming.ContentLength, 0)
		writeGatewayError(w, http.StatusBadGateway, "upstream_unavailable", "configured egress destination failed")
		return
	}
	defer response.Body.Close()
	if response.ContentLength > route.MaxResponseBytes {
		s.finishEgress(grant, routeID, "response_too_large", incoming.Method, host, port, incoming.ContentLength, 0)
		writeGatewayError(w, http.StatusBadGateway, "response_too_large", "egress response exceeds route byte limit")
		return
	}
	copyHeaders(w.Header(), response.Header)
	unknownLength := prepareBoundedHTTPResponse(w, response.ContentLength)
	w.WriteHeader(response.StatusCode)
	result := copyHTTPResponseBody(w, response.Body, route.MaxResponseBytes, unknownLength)
	s.finishEgress(grant, routeID, result.reason, incoming.Method, host, port,
		max64(incoming.ContentLength, 0), min64(result.written, route.MaxResponseBytes))
	if result.abort {
		panic(http.ErrAbortHandler)
	}
}

func (s *Server) proxyConnect(w http.ResponseWriter, incoming *http.Request, grant Grant, routeID string, route loadedEgressRoute, host string, port int, ip netip.Addr) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		writeGatewayError(w, http.StatusInternalServerError, "tunnel_unavailable", "egress tunnel is unavailable")
		return
	}
	agent, buffer, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer agent.Close()
	stopAgent := context.AfterFunc(incoming.Context(), func() { _ = agent.Close() })
	defer stopAgent()
	now := time.Now()
	deadline := now.Add(time.Duration(route.MaxTunnelSeconds) * time.Second)
	helloDeadline := boundedTLSClientHelloDeadline(now, deadline)
	// A CONNECT slot receives only a short handshake window until the TLS SNI
	// proves that the encrypted destination matches the signed route.
	_ = agent.SetDeadline(helloDeadline)
	_, _ = buffer.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
	if err := buffer.Flush(); err != nil {
		return
	}
	clientHello, serverName, err := readTLSClientHello(buffer.Reader)
	if err != nil || !tlsServerNameAllowed(host, serverName) {
		s.denyEgress(grant, "tls_server_name_denied", incoming.Method, host, port)
		return
	}
	if int64(len(clientHello)) > route.MaxRequestBytes {
		s.denyEgress(grant, "byte_limit", incoming.Method, host, port)
		return
	}
	_ = agent.SetDeadline(deadline)
	if err := s.recordEgressAllow(grant, routeID, incoming.Method, host, port); err != nil {
		s.updateEgressStats(grant.GrantID, egressAuditEvent{Decision: "deny", Reason: "audit_unavailable", Host: host, Port: port})
		return
	}
	upstream, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(incoming.Context(), "tcp", net.JoinHostPort(ip.String(), strconv.Itoa(port)))
	if err != nil {
		s.finishEgress(grant, routeID, "upstream_unavailable", incoming.Method, host, port, int64(len(clientHello)), 0)
		return
	}
	defer upstream.Close()
	stopUpstream := context.AfterFunc(incoming.Context(), func() { _ = upstream.Close() })
	defer stopUpstream()
	_ = upstream.SetDeadline(deadline)
	if err := writeAllBytes(upstream, clientHello); err != nil {
		s.finishEgress(grant, routeID, "upstream_unavailable", incoming.Method, host, port, int64(len(clientHello)), 0)
		return
	}
	fromAgent := int64(len(clientHello))
	remainingFromAgent, toAgent := bridgeConnect(agent, buffer.Reader, upstream, route.MaxRequestBytes-fromAgent, route.MaxResponseBytes)
	fromAgent += remainingFromAgent
	reason := "completed"
	if fromAgent > route.MaxRequestBytes || toAgent > route.MaxResponseBytes {
		reason = "byte_limit"
	}
	s.finishEgress(grant, routeID, reason, incoming.Method, host, port, min64(fromAgent, route.MaxRequestBytes), min64(toAgent, route.MaxResponseBytes))
}

func boundedTLSClientHelloDeadline(now, tunnelDeadline time.Time) time.Time {
	helloDeadline := now.Add(tlsClientHelloTimeout)
	if tunnelDeadline.Before(helloDeadline) {
		return tunnelDeadline
	}
	return helloDeadline
}

type connectCopyResult struct {
	fromAgent bool
	written   int64
}

// bridgeConnect closes both peers as soon as either copy finishes. Without
// peer cancellation, a half-open or failed tunnel can retain its route slot
// until the full (potentially 24-hour) tunnel deadline.
func bridgeConnect(agent net.Conn, agentReader io.Reader, upstream net.Conn, maxFromAgent, maxToAgent int64) (int64, int64) {
	results := make(chan connectCopyResult, 2)
	go func() {
		written, _ := copyBounded(upstream, agentReader, maxFromAgent)
		results <- connectCopyResult{fromAgent: true, written: written}
	}()
	go func() {
		written, _ := copyBounded(agent, upstream, maxToAgent)
		results <- connectCopyResult{written: written}
	}()

	first := <-results
	_ = agent.Close()
	_ = upstream.Close()
	second := <-results
	var fromAgent, toAgent int64
	for _, result := range []connectCopyResult{first, second} {
		if result.fromAgent {
			fromAgent = result.written
		} else {
			toAgent = result.written
		}
	}
	return fromAgent, toAgent
}

func writeAllBytes(destination io.Writer, value []byte) error {
	for len(value) > 0 {
		written, err := destination.Write(value)
		if err != nil {
			return err
		}
		if written < 1 {
			return io.ErrShortWrite
		}
		value = value[written:]
	}
	return nil
}

func tlsServerNameAllowed(host, serverName string) bool {
	if net.ParseIP(host) != nil {
		return serverName == ""
	}
	return serverName == host
}

func copyBounded(destination io.Writer, source io.Reader, maximum int64) (int64, error) {
	written, err := io.Copy(destination, io.LimitReader(source, maximum))
	if err != nil || written < maximum {
		return written, err
	}
	var probe [1]byte
	count, probeErr := io.ReadFull(source, probe[:])
	if count > 0 {
		return written + int64(count), nil
	}
	if errors.Is(probeErr, io.EOF) || errors.Is(probeErr, io.ErrUnexpectedEOF) {
		return written, nil
	}
	return written, probeErr
}

func (s *Server) rejectEgress(w http.ResponseWriter, grant Grant, reason, method, host string, port, status int, message string) {
	switch s.denyEgress(grant, reason, method, host, port) {
	case egressDenialRateLimited:
		writeGatewayError(w, http.StatusTooManyRequests, "egress_rate_limited", "egress denied-attempt rate limit reached")
		return
	case egressDenialGrantMissing:
		// Preserve the underlying revocation or routing result. A grant deleted
		// during an in-flight request is not a denial-rate-limit event.
		writeGatewayError(w, status, reason, message)
		return
	}
	writeGatewayError(w, status, reason, message)
}

type egressDenialDecision uint8

const (
	egressDenialAllowed egressDenialDecision = iota
	egressDenialRateLimited
	egressDenialGrantMissing
)

// denyEgress reserves denial capacity before touching the shared,
// synchronously-fsynced audit log. Per-grant and fixed per-tenant limits keep
// one tenant from borrowing another tenant's capacity, while the host limit
// bounds total disk work. Callers that can still write an HTTP response
// translate false into a 429 JSON error.
func (s *Server) denyEgress(grant Grant, reason, method, host string, port int) egressDenialDecision {
	decision := s.reserveEgressDeniedAttempt(grant.GrantID, time.Now())
	if decision != egressDenialAllowed {
		return decision
	}
	event := egressAuditEvent{Decision: "deny", Reason: reason, GrantID: grant.GrantID, TenantID: grant.TenantID,
		InstanceID: grant.InstanceID, Method: method, Host: host, Port: port}
	_ = s.audit.Append(event)
	s.updateEgressStats(grant.GrantID, event)
	return egressDenialAllowed
}

func (s *Server) allowEgressDeniedAttempt(grantID string, now time.Time) bool {
	return s.reserveEgressDeniedAttempt(grantID, now) == egressDenialAllowed
}

func (s *Server) reserveEgressDeniedAttempt(grantID string, now time.Time) egressDenialDecision {
	s.mu.Lock()
	defer s.mu.Unlock()
	// An in-flight request can reach a late denial while unregister is revoking
	// the grant. Do not recreate limiter state after unregister has deleted it.
	grant, ok := s.grants[grantID]
	if !ok {
		return egressDenialGrantMissing
	}
	s.pruneExpiredEgressTenantDenialsLocked(now)
	grantWindow, grantAllowed := availableEgressDenialWindow(
		s.egressDeniedAttempts[grantID], now, maxEgressDeniedAttemptsPerGrantMinute,
	)
	tenantWindow, tenantAllowed := availableEgressDenialWindow(
		s.egressTenantDenials[grant.TenantID], now, maxEgressDeniedAttemptsPerTenantMinute,
	)
	hostWindow, hostAllowed := availableEgressDenialWindow(
		s.egressHostDenials, now, maxEgressDeniedAttemptsHostMinute,
	)
	if !grantAllowed || !tenantAllowed || !hostAllowed {
		return egressDenialRateLimited
	}
	grantWindow.count++
	tenantWindow.count++
	hostWindow.count++
	if s.egressDeniedAttempts == nil {
		s.egressDeniedAttempts = make(map[string]egressDeniedAttemptWindow)
	}
	if s.egressTenantDenials == nil {
		s.egressTenantDenials = make(map[string]egressDeniedAttemptWindow)
	}
	s.egressDeniedAttempts[grantID] = grantWindow
	s.egressTenantDenials[grant.TenantID] = tenantWindow
	s.egressHostDenials = hostWindow
	return egressDenialAllowed
}

func (s *Server) pruneExpiredEgressTenantDenialsLocked(now time.Time) {
	for tenantID, window := range s.egressTenantDenials {
		if !window.started.IsZero() && !now.Before(window.started) && now.Sub(window.started) >= time.Minute {
			delete(s.egressTenantDenials, tenantID)
		}
	}
}

func availableEgressDenialWindow(window egressDeniedAttemptWindow, now time.Time, limit int) (egressDeniedAttemptWindow, bool) {
	if !window.started.IsZero() && now.Before(window.started) {
		// A wall-clock rollback must not reopen authority that was already spent.
		return window, false
	}
	if window.started.IsZero() || now.Sub(window.started) >= time.Minute {
		window = egressDeniedAttemptWindow{started: now}
	}
	return window, window.count < limit
}

func (s *Server) finishEgress(grant Grant, routeID, reason, method, host string, port int, fromAgent, toAgent int64) {
	event := egressAuditEvent{Decision: "terminal", Reason: reason, GrantID: grant.GrantID, TenantID: grant.TenantID,
		InstanceID: grant.InstanceID, RouteID: routeID, Method: method, Host: host, Port: port,
		BytesFromAgent: fromAgent, BytesToAgent: toAgent}
	_ = s.audit.Append(event)
	s.updateEgressStats(grant.GrantID, event)
}

func (s *Server) updateEgressStats(id string, event egressAuditEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	stats := s.egressStats[id]
	if event.Decision == "allow" {
		stats.Allowed++
	}
	if event.Decision == "deny" {
		stats.Denied++
	}
	if event.BytesFromAgent > 0 {
		stats.BytesFromAgent += uint64(event.BytesFromAgent)
	}
	if event.BytesToAgent > 0 {
		stats.BytesToAgent += uint64(event.BytesToAgent)
	}
	if event.Host != "" {
		stats.LastDestination = net.JoinHostPort(event.Host, strconv.Itoa(event.Port))
	}
	stats.LastDecision, stats.LastObservedAt = event.Decision+":"+event.Reason, time.Now().UTC().Format(time.RFC3339Nano)
	s.egressStats[id] = stats
}

func (s *Server) getEgressStats(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	s.mu.Lock()
	grant, ok := s.grants[id]
	stats := s.egressStats[id]
	s.mu.Unlock()
	if !ok || len(grant.EgressRouteIDs) == 0 {
		writeGatewayError(w, http.StatusNotFound, "grant_not_found", "egress grant not found")
		return
	}
	writeJSON(w, http.StatusOK, stats)
}

func min64(left, right int64) int64 {
	if left < right {
		return left
	}
	return right
}
func max64(left, right int64) int64 {
	if left > right {
		return left
	}
	return right
}
