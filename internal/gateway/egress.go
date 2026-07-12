package gateway

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
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
		IdleTimeout: 30 * time.Second,
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
			s.denyEgress(grant, "grant_inactive", r.Method, "", 0)
			writeGatewayError(w, http.StatusServiceUnavailable, "grant_inactive", "egress grant is not active")
			return
		}
		host, port, err := proxyDestination(r)
		if err != nil {
			s.mu.Unlock()
			s.denyEgress(grant, "invalid_destination", r.Method, "", 0)
			writeGatewayError(w, http.StatusBadRequest, "invalid_destination", err.Error())
			return
		}
		routeID, route, destination, ok := s.selectEgressRoute(grant, host, port)
		var semaphore chan struct{}
		if ok {
			semaphore = s.egressSemaphores[routeID]
		}
		if !ok {
			s.mu.Unlock()
			s.denyEgress(grant, "route_denied", r.Method, host, port)
			writeGatewayError(w, http.StatusForbidden, "route_denied", "destination is not allowed by the active egress grant")
			return
		}
		select {
		case semaphore <- struct{}{}:
			s.mu.Unlock()
			defer func() { <-semaphore }()
		default:
			s.mu.Unlock()
			s.denyEgress(grant, "route_busy", r.Method, host, port)
			writeGatewayError(w, http.StatusTooManyRequests, "route_busy", "egress route concurrency limit reached")
			return
		}
		deadline := time.Now().Add(time.Duration(route.MaxTunnelSeconds) * time.Second)
		controller := http.NewResponseController(w)
		_ = controller.SetReadDeadline(deadline)
		_ = controller.SetWriteDeadline(deadline)
		requestContext, cancel := context.WithDeadline(r.Context(), deadline)
		defer cancel()
		r = r.WithContext(requestContext)
		ip, err := resolveAllowedIP(r.Context(), host, destination)
		if err != nil {
			s.denyEgress(grant, "address_denied", r.Method, host, port)
			writeGatewayError(w, http.StatusForbidden, "address_denied", "destination did not resolve to an allowed address")
			return
		}
		allowed := egressAuditEvent{Decision: "allow", Reason: "route_allowed", GrantID: grant.GrantID,
			TenantID: grant.TenantID, InstanceID: grant.InstanceID, RouteID: routeID,
			Method: r.Method, Host: host, Port: port}
		if err := s.audit.Append(allowed); err != nil {
			writeGatewayError(w, http.StatusServiceUnavailable, "audit_unavailable", "egress audit record could not be persisted")
			return
		}
		s.updateEgressStats(grant.GrantID, allowed)
		if r.Method == http.MethodConnect {
			s.proxyConnect(w, r, grant, routeID, route, host, port, ip)
			return
		}
		s.proxyHTTP(w, r, grant, routeID, route, host, port, ip)
	})
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
		addresses = []netip.Addr{literal.Unmap()}
	} else {
		resolved, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return netip.Addr{}, err
		}
		for _, address := range resolved {
			addresses = append(addresses, address.Unmap())
		}
	}
	for _, address := range addresses {
		if addressAllowed(address, destination.prefixes) {
			return address, nil
		}
	}
	return netip.Addr{}, errors.New("no allowed address")
}

func addressAllowed(address netip.Addr, prefixes []netip.Prefix) bool {
	if !address.IsValid() || address.IsUnspecified() || address.IsLinkLocalMulticast() || address.IsMulticast() {
		return false
	}
	if len(prefixes) > 0 {
		for _, prefix := range prefixes {
			if prefix.Contains(address) {
				return true
			}
		}
		return false
	}
	return address.IsGlobalUnicast() && !address.IsPrivate() && !address.IsLoopback() && !address.IsLinkLocalUnicast()
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
	}, ResponseHeaderTimeout: 30 * time.Second, IdleConnTimeout: 30 * time.Second, TLSHandshakeTimeout: 10 * time.Second}
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
	w.WriteHeader(response.StatusCode)
	written, copyErr := io.Copy(w, io.LimitReader(response.Body, route.MaxResponseBytes+1))
	reason := "completed"
	if copyErr != nil {
		reason = "stream_failed"
	} else if written > route.MaxResponseBytes {
		reason = "response_too_large"
	}
	s.finishEgress(grant, routeID, reason, incoming.Method, host, port, max64(incoming.ContentLength, 0), min64(written, route.MaxResponseBytes))
}

func (s *Server) proxyConnect(w http.ResponseWriter, incoming *http.Request, grant Grant, routeID string, route loadedEgressRoute, host string, port int, ip netip.Addr) {
	upstream, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(incoming.Context(), "tcp", net.JoinHostPort(ip.String(), strconv.Itoa(port)))
	if err != nil {
		s.finishEgress(grant, routeID, "upstream_unavailable", incoming.Method, host, port, 0, 0)
		writeGatewayError(w, http.StatusBadGateway, "upstream_unavailable", "configured egress destination failed")
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		_ = upstream.Close()
		writeGatewayError(w, http.StatusInternalServerError, "tunnel_unavailable", "egress tunnel is unavailable")
		return
	}
	agent, buffer, err := hijacker.Hijack()
	if err != nil {
		_ = upstream.Close()
		return
	}
	defer agent.Close()
	defer upstream.Close()
	deadline := time.Now().Add(time.Duration(route.MaxTunnelSeconds) * time.Second)
	_ = agent.SetDeadline(deadline)
	_ = upstream.SetDeadline(deadline)
	_, _ = buffer.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
	if err := buffer.Flush(); err != nil {
		return
	}
	var wait sync.WaitGroup
	var fromAgent, toAgent int64
	wait.Add(2)
	go func() { defer wait.Done(); fromAgent, _ = copyBounded(upstream, buffer.Reader, route.MaxRequestBytes) }()
	go func() { defer wait.Done(); toAgent, _ = copyBounded(agent, upstream, route.MaxResponseBytes) }()
	wait.Wait()
	reason := "completed"
	if fromAgent > route.MaxRequestBytes || toAgent > route.MaxResponseBytes {
		reason = "byte_limit"
	}
	s.finishEgress(grant, routeID, reason, incoming.Method, host, port, min64(fromAgent, route.MaxRequestBytes), min64(toAgent, route.MaxResponseBytes))
}

func copyBounded(destination io.Writer, source io.Reader, maximum int64) (int64, error) {
	return io.Copy(destination, io.LimitReader(source, maximum+1))
}

func (s *Server) denyEgress(grant Grant, reason, method, host string, port int) {
	event := egressAuditEvent{Decision: "deny", Reason: reason, GrantID: grant.GrantID, TenantID: grant.TenantID,
		InstanceID: grant.InstanceID, Method: method, Host: host, Port: port}
	_ = s.audit.Append(event)
	s.updateEgressStats(grant.GrantID, event)
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
