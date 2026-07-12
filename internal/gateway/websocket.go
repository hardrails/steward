package gateway

import (
	"bufio"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

func websocketAttempt(request *http.Request) bool {
	return request.Header.Get("Upgrade") != "" || headerHasToken(request.Header.Values("Connection"), "upgrade") ||
		request.Header.Get("Sec-WebSocket-Key") != "" || request.Header.Get("Sec-WebSocket-Version") != ""
}

func websocketUpgrade(request *http.Request) bool {
	if request.Method != http.MethodGet || request.ProtoMajor != 1 || request.ProtoMinor < 1 || request.ContentLength != 0 ||
		len(request.TransferEncoding) != 0 || !strings.EqualFold(strings.TrimSpace(request.Header.Get("Upgrade")), "websocket") ||
		!headerHasToken(request.Header.Values("Connection"), "upgrade") || len(request.Header.Values("Sec-WebSocket-Version")) != 1 ||
		strings.TrimSpace(request.Header.Get("Sec-WebSocket-Version")) != "13" || len(request.Header.Values("Sec-WebSocket-Key")) != 1 {
		return false
	}
	key := strings.TrimSpace(request.Header.Get("Sec-WebSocket-Key"))
	nonce, err := base64.StdEncoding.DecodeString(key)
	return err == nil && len(nonce) == 16 && base64.StdEncoding.EncodeToString(nonce) == key
}

func headerHasToken(values []string, want string) bool {
	for _, value := range values {
		for _, token := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(token), want) {
				return true
			}
		}
	}
	return false
}

func (s *Server) proxyWebSocket(w http.ResponseWriter, incoming *http.Request, base *url.URL, path string, transport http.RoundTripper) {
	target := *base
	target.Path = path
	target.RawQuery = incoming.URL.RawQuery
	request, err := http.NewRequestWithContext(incoming.Context(), http.MethodGet, target.String(), nil)
	if err != nil {
		writeGatewayError(w, http.StatusBadRequest, "invalid_request", "cannot construct upstream WebSocket request")
		return
	}
	copyHeaders(request.Header, incoming.Header)
	request.Header.Del("Authorization")
	request.Header.Del("Proxy-Authorization")
	request.Header.Del("Cookie")
	request.Header.Set("Connection", "Upgrade")
	request.Header.Set("Upgrade", "websocket")

	// Client.Timeout wraps response bodies as read-only streams. RoundTrip keeps
	// net/http's native 101 read-write body, while the grant context supplies the
	// same hard lifetime bound and immediate lifecycle revocation.
	if transport == nil {
		writeGatewayError(w, http.StatusBadGateway, "upstream_unavailable", "configured upstream WebSocket transport is unavailable")
		return
	}
	response, err := transport.RoundTrip(request)
	if err != nil {
		writeGatewayError(w, http.StatusBadGateway, "upstream_unavailable", "configured upstream WebSocket failed")
		return
	}
	if response.StatusCode != http.StatusSwitchingProtocols {
		defer response.Body.Close()
		if response.StatusCode >= 300 && response.StatusCode < 400 {
			writeGatewayError(w, http.StatusBadGateway, "redirect_denied", "configured upstream returned a redirect")
			return
		}
		s.relayHTTPResponse(w, response, true)
		return
	}
	upstream, ok := response.Body.(io.ReadWriteCloser)
	if !ok || !strings.EqualFold(strings.TrimSpace(response.Header.Get("Upgrade")), "websocket") ||
		!headerHasToken(response.Header.Values("Connection"), "upgrade") || len(response.Header.Values("Sec-WebSocket-Accept")) != 1 ||
		strings.TrimSpace(response.Header.Get("Sec-WebSocket-Accept")) != webSocketAccept(request.Header.Get("Sec-WebSocket-Key")) {
		_ = response.Body.Close()
		writeGatewayError(w, http.StatusBadGateway, "upgrade_invalid", "configured upstream returned an invalid WebSocket upgrade")
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		_ = upstream.Close()
		writeGatewayError(w, http.StatusInternalServerError, "upgrade_unavailable", "service WebSocket upgrade is unavailable")
		return
	}
	agent, buffer, err := hijacker.Hijack()
	if err != nil {
		_ = upstream.Close()
		return
	}
	defer agent.Close()
	defer upstream.Close()
	deadline, ok := incoming.Context().Deadline()
	if !ok {
		deadline = time.Now().Add(maxServiceLifetime)
	}
	_ = agent.SetDeadline(deadline)
	if err := writeWebSocketUpgrade(buffer, response.Header); err != nil {
		return
	}
	s.bridgeWebSocket(incoming.Context(), agent, buffer.Reader, upstream)
}

func webSocketAccept(key string) string {
	digest := sha1.Sum([]byte(strings.TrimSpace(key) + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")) // #nosec G505 -- SHA-1 is mandated by RFC 6455 as a handshake checksum, not used for security.
	return base64.StdEncoding.EncodeToString(digest[:])
}

func writeWebSocketUpgrade(buffer *bufio.ReadWriter, upstreamHeaders http.Header) error {
	headers := make(http.Header)
	copyHeaders(headers, upstreamHeaders)
	headers.Del("Set-Cookie")
	headers.Del("Location")
	headers.Del("Content-Length")
	headers.Set("Connection", "Upgrade")
	headers.Set("Upgrade", "websocket")
	headers.Set("X-Steward-Service-Grant", "active")
	if _, err := buffer.WriteString("HTTP/1.1 101 Switching Protocols\r\n"); err != nil {
		return err
	}
	if err := headers.Write(buffer); err != nil {
		return err
	}
	if _, err := buffer.WriteString("\r\n"); err != nil {
		return err
	}
	return buffer.Flush()
}

func (s *Server) bridgeWebSocket(ctx context.Context, agent net.Conn, agentReader io.Reader, upstream io.ReadWriteCloser) {
	var once sync.Once
	closeBoth := func() {
		once.Do(func() {
			_ = agent.Close()
			_ = upstream.Close()
		})
	}
	stop := context.AfterFunc(ctx, closeBoth)
	defer stop()
	var wait sync.WaitGroup
	wait.Add(2)
	go func() {
		defer wait.Done()
		_, _ = copyWebSocketBounded(upstream, agentReader, maxProxyBody)
		closeBoth()
	}()
	go func() {
		defer wait.Done()
		_, _ = copyWebSocketBounded(agent, upstream, maxProxyResponse)
		closeBoth()
	}()
	wait.Wait()
}

func copyWebSocketBounded(destination io.Writer, source io.Reader, maximum int64) (int64, error) {
	return io.Copy(destination, io.LimitReader(source, maximum))
}
