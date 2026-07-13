// Command steward-relay is the trusted, fixed-destination companion used by
// capability-bearing agent workloads.
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/hardrails/steward/internal/buildinfo"
)

const (
	maxHTTPHeaderBytes           = 64 << 10
	maxConnectorRequestBytes     = 4 << 20
	maxConnectorResponseBytes    = 32 << 20
	maxConnectorConcurrent       = 4
	connectorAddress             = "0.0.0.0:8081"
	connectorRequestBodyLifetime = 30 * time.Second
	connectorResponseWriteTime   = 30 * time.Second
	// Gateway accepts connector max_seconds values through one hour. Relay is
	// deliberately a little more patient than that trusted local boundary so a
	// Gateway timeout and its terminal receipt can reach the agent intact.
	connectorGatewayMaximumLifetime = time.Hour
	connectorGatewayRoundTripTime   = connectorGatewayMaximumLifetime + 30*time.Second
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	ctx, stop := context.WithCancel(ctx)
	defer stop()
	flags := flag.NewFlagSet("steward-relay", flag.ContinueOnError)
	flags.SetOutput(stderr)
	version := flags.Bool("version", false, "print the Steward Relay version and exit")
	inferenceAddress := flags.String("inference-addr", ":8080", "private-network inference listener")
	inferenceSocket := flags.String("inference-socket", "", "mounted per-grant gateway Unix socket")
	connectorSocket := flags.String("connector-socket", "", "mounted per-grant gateway connector Unix socket")
	egressAddress := flags.String("egress-addr", ":8082", "private-network HTTP(S) proxy listener")
	egressSocket := flags.String("egress-socket", "", "mounted per-grant gateway egress Unix socket")
	serviceSocket := flags.String("service-socket", "", "mounted per-grant gateway service Unix socket")
	serviceTarget := flags.String("service-target", "", "fixed private agent service origin")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *version {
		fmt.Fprintln(stdout, "steward-relay "+buildinfo.Resolve())
		return 0
	}
	if *inferenceSocket == "" && *connectorSocket == "" && *serviceSocket == "" && *egressSocket == "" {
		fmt.Fprintln(stderr, "steward-relay: at least one gateway or service socket is required")
		return 2
	}
	if (*serviceTarget == "") != (*serviceSocket == "") {
		fmt.Fprintln(stderr, "steward-relay: service target and service socket must be configured together")
		return 2
	}
	var servers []*http.Server
	var egressListener net.Listener
	var serviceListener net.Listener
	var serviceServer *http.Server
	serverListeners := make(map[*http.Server]net.Listener)
	if *inferenceSocket != "" {
		servers = append(servers, newInferenceHTTPServer(*inferenceAddress, *inferenceSocket))
	}
	if *serviceTarget != "" {
		target, err := url.Parse(*serviceTarget)
		if err != nil || target.Scheme != "http" || target.Hostname() != "agent" || target.Port() == "" || target.Path != "" {
			fmt.Fprintln(stderr, "steward-relay: service target must be http://agent:PORT")
			return 2
		}
		proxy := serviceProxy(target)
		serviceListener, err = openServiceListener(*serviceSocket)
		if err != nil {
			fmt.Fprintln(stderr, "steward-relay: service listener:", err)
			return 1
		}
		defer func() {
			_ = serviceListener.Close()
			_ = os.Remove(*serviceSocket)
		}()
		serviceServer = newServiceHTTPServer(proxy)
		servers = append(servers, serviceServer)
		serverListeners[serviceServer] = serviceListener
	}
	if *connectorSocket != "" {
		connectorListener, err := net.Listen("tcp4", connectorAddress)
		if err != nil {
			fmt.Fprintln(stderr, "steward-relay: connector listener:", err)
			return 1
		}
		defer connectorListener.Close()
		connectorServer := newConnectorHTTPServer(ctx, *connectorSocket)
		servers = append(servers, connectorServer)
		serverListeners[connectorServer] = connectorListener
	}
	if *egressSocket != "" {
		var err error
		egressListener, err = net.Listen("tcp", *egressAddress)
		if err != nil {
			fmt.Fprintln(stderr, "steward-relay: egress listener:", err)
			return 1
		}
	}
	var wait sync.WaitGroup
	errorsCh := make(chan error, len(servers)+1)
	for _, server := range servers {
		wait.Add(1)
		go func(server *http.Server) {
			defer wait.Done()
			var err error
			if listener := serverListeners[server]; listener != nil {
				err = server.Serve(listener)
			} else {
				err = server.ListenAndServe()
			}
			if err != nil && err != http.ErrServerClosed && !errors.Is(err, net.ErrClosed) {
				errorsCh <- err
			}
		}(server)
	}
	if egressListener != nil {
		wait.Add(1)
		go func() {
			defer wait.Done()
			if err := serveEgressBridge(ctx, egressListener, *egressSocket); err != nil && ctx.Err() == nil {
				errorsCh <- err
			}
		}()
	}
	failed := false
	select {
	case <-ctx.Done():
	case err := <-errorsCh:
		slog.Error("relay listener", "err", err)
		failed = true
		stop()
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, server := range servers {
		if err := server.Shutdown(shutdown); err != nil {
			// A slow or stuck peer must not retain a relay capability after the
			// bounded graceful shutdown window expires.
			_ = server.Close()
		}
	}
	if egressListener != nil {
		_ = egressListener.Close()
	}
	wait.Wait()
	if failed {
		return 1
	}
	return 0
}

func newInferenceHTTPServer(address, socket string) *http.Server {
	return &http.Server{
		Addr: address, Handler: inferenceProxy(socket),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 2 * time.Minute, WriteTimeout: 2 * time.Minute,
		IdleTimeout: 30 * time.Second, MaxHeaderBytes: maxHTTPHeaderBytes,
	}
}

func newServiceHTTPServer(handler http.Handler) *http.Server {
	return &http.Server{
		Handler: handler,
		// The authenticated host Gateway owns the service stream's 2-minute
		// lifetime and byte ceilings. ReadTimeout/WriteTimeout stay unset here
		// because fixed HTTP deadlines truncate upgraded WebSocket sessions;
		// header and idle limits still bound non-upgraded connections.
		ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: maxHTTPHeaderBytes,
	}
}

func newConnectorHTTPServer(ctx context.Context, socket string) *http.Server {
	return &http.Server{
		Addr: connectorAddress, Handler: connectorProxy(socket),
		// Agent-controlled headers and request bodies retain tight absolute
		// limits. WriteTimeout is phase-managed by connectorProxy: one long
		// fixed server deadline would either truncate a valid one-hour Gateway
		// operation or give a slow response reader that entire hour.
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: connectorRequestBodyLifetime,
		IdleTimeout: 15 * time.Second, MaxHeaderBytes: maxHTTPHeaderBytes,
		BaseContext: func(net.Listener) context.Context { return ctx },
	}
}

func connectorProxy(socket string) http.Handler {
	return connectorProxyWithTimeouts(socket, connectorGatewayRoundTripTime, connectorResponseWriteTime)
}

type connectorDeadlineWriter struct {
	writer     http.ResponseWriter
	controller *http.ResponseController
	timeout    time.Duration
}

func (w connectorDeadlineWriter) Write(payload []byte) (int, error) {
	_ = w.controller.SetWriteDeadline(time.Now().Add(w.timeout))
	return w.writer.Write(payload)
}

func connectorProxyWithTimeouts(socket string, gatewayRoundTripTime, responseWriteTime time.Duration) http.Handler {
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "unix", socket)
		},
		DisableKeepAlives:      true,
		ResponseHeaderTimeout:  gatewayRoundTripTime,
		MaxResponseHeaderBytes: maxHTTPHeaderBytes,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   gatewayRoundTripTime,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	concurrent := make(chan struct{}, maxConnectorConcurrent)
	return http.HandlerFunc(func(w http.ResponseWriter, incoming *http.Request) {
		controller := http.NewResponseController(w)
		_ = controller.SetWriteDeadline(time.Now().Add(responseWriteTime))
		if !validConnectorRequest(incoming) {
			writeConnectorError(w, http.StatusForbidden, "connector_denied", "connector method, path, or query is not allowed")
			return
		}
		select {
		case concurrent <- struct{}{}:
			defer func() { <-concurrent }()
		default:
			writeConnectorError(w, http.StatusTooManyRequests, "connector_busy", "connector relay concurrency limit reached")
			return
		}
		if incoming.ContentLength > maxConnectorRequestBytes {
			writeConnectorError(w, http.StatusRequestEntityTooLarge, "request_too_large", "connector request exceeds the byte limit")
			return
		}
		incoming.Body = http.MaxBytesReader(w, incoming.Body, maxConnectorRequestBytes)
		// A body may consume its entire read budget. Keep a separate response
		// grace so Relay can still return the bounded timeout or size error.
		_ = controller.SetWriteDeadline(time.Now().Add(connectorRequestBodyLifetime + responseWriteTime))
		raw, err := io.ReadAll(incoming.Body)
		_ = controller.SetWriteDeadline(time.Now().Add(responseWriteTime))
		if err != nil {
			var tooLarge *http.MaxBytesError
			if errors.As(err, &tooLarge) {
				writeConnectorError(w, http.StatusRequestEntityTooLarge, "request_too_large", "connector request exceeds the byte limit")
				return
			}
			writeConnectorError(w, http.StatusBadRequest, "invalid_request", "connector request body could not be read")
			return
		}
		target := "http://steward-gateway" + incoming.URL.Path
		request, err := http.NewRequestWithContext(incoming.Context(), incoming.Method, target, bytes.NewReader(raw))
		if err != nil {
			writeConnectorError(w, http.StatusBadRequest, "invalid_request", "connector request could not be constructed")
			return
		}
		copyConnectorHeaders(request.Header, incoming.Header)
		// Gateway is the trusted operation timer. The extra response-write budget
		// lets Relay deliver Gateway's bounded timeout/error instead of racing it.
		_ = controller.SetWriteDeadline(time.Now().Add(gatewayRoundTripTime + responseWriteTime))
		response, err := client.Do(request)
		if err != nil {
			slog.Error("connector gateway request failed", "method", incoming.Method, "path", incoming.URL.Path, "err", err)
			writeConnectorError(w, http.StatusBadGateway, "connector_unavailable", "Steward connector gateway unavailable")
			return
		}
		defer response.Body.Close()
		// Once Gateway has answered, an agent that reads too slowly receives only
		// the short response-write budget, never the one-hour operation budget.
		_ = controller.SetWriteDeadline(time.Now().Add(responseWriteTime))
		if response.ContentLength > maxConnectorResponseBytes {
			writeConnectorError(w, http.StatusBadGateway, "response_too_large", "connector response exceeds the byte limit")
			return
		}
		copyConnectorHeaders(w.Header(), response.Header)
		const streamStatus = "X-Steward-Stream-Status"
		_, hasStreamStatus := response.Trailer[streamStatus]
		if hasStreamStatus {
			w.Header().Add("Trailer", streamStatus)
		}
		if response.ContentLength >= 0 {
			w.Header().Set("Content-Length", strconv.FormatInt(response.ContentLength, 10))
		}
		w.WriteHeader(response.StatusCode)
		// Refresh the short write deadline for every chunk. A trusted Gateway
		// stream may pause for its bounded operation lifetime, but an agent gets
		// only responseWriteTime to consume each available chunk.
		deadlineWriter := connectorDeadlineWriter{writer: w, controller: controller, timeout: responseWriteTime}
		written, err := io.Copy(deadlineWriter, io.LimitReader(response.Body, maxConnectorResponseBytes))
		if err != nil {
			panic(http.ErrAbortHandler)
		}
		if response.ContentLength < 0 && written == maxConnectorResponseBytes {
			var extra [1]byte
			count, readErr := response.Body.Read(extra[:])
			if count != 0 || readErr != io.EOF {
				panic(http.ErrAbortHandler)
			}
		}
		if hasStreamStatus {
			w.Header().Set(streamStatus, response.Trailer.Get(streamStatus))
		}
	})
}

func validConnectorRequest(request *http.Request) bool {
	if request.URL.IsAbs() || request.URL.RawPath != "" || request.URL.RawQuery != "" || request.URL.ForceQuery ||
		strings.ContainsAny(request.URL.Path, "%\\\x00") {
		return false
	}
	switch request.Method {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
	default:
		return false
	}
	const prefix = "/v1/connectors/"
	if !strings.HasPrefix(request.URL.Path, prefix) {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(request.URL.Path, prefix), "/")
	return len(parts) == 3 && parts[1] == "operations" && validConnectorIdentifier(parts[0]) && validConnectorIdentifier(parts[2])
}

func validConnectorIdentifier(id string) bool {
	if id == "" || len(id) > 128 {
		return false
	}
	for index, character := range id {
		if character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' || character >= '0' && character <= '9' ||
			(index > 0 && (character == '.' || character == '_' || character == '-')) {
			continue
		}
		return false
	}
	return true
}

func copyConnectorHeaders(destination, source http.Header) {
	connectionHeaders := make(map[string]struct{})
	for _, value := range source.Values("Connection") {
		for _, name := range strings.Split(value, ",") {
			if name = http.CanonicalHeaderKey(strings.TrimSpace(name)); name != "" {
				connectionHeaders[name] = struct{}{}
			}
		}
	}
	for key, values := range source {
		canonical := http.CanonicalHeaderKey(key)
		if _, nominated := connectionHeaders[canonical]; nominated {
			continue
		}
		switch canonical {
		case "Authorization", "Connection", "Content-Length", "Cookie", "Keep-Alive", "Proxy-Authenticate",
			"Proxy-Authorization", "Proxy-Connection", "Set-Cookie", "Te", "Trailer", "Transfer-Encoding", "Upgrade":
			continue
		}
		for _, value := range values {
			destination.Add(key, value)
		}
	}
}

func writeConnectorError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, `{"error":%q,"message":%q}`+"\n", code, message)
}

func openServiceListener(socket string) (net.Listener, error) {
	if !filepath.IsAbs(socket) || filepath.Clean(socket) != socket || filepath.Base(socket) != "s.sock" || strings.ContainsRune(socket, '\x00') {
		return nil, errors.New("service socket path must be an absolute, clean s.sock path")
	}
	info, err := os.Lstat(filepath.Dir(socket))
	if err != nil || !info.IsDir() {
		return nil, errors.New("service socket directory is unavailable")
	}
	if info, err = os.Lstat(socket); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, errors.New("existing service socket path is not a Unix socket")
		}
		if err := os.Remove(socket); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	listener, err := net.Listen("unix", socket)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(socket, 0o660); err != nil {
		_ = listener.Close()
		_ = os.Remove(socket)
		return nil, err
	}
	return listener, nil
}

func serviceProxy(target *url.URL) *httputil.ReverseProxy {
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.Transport = &http.Transport{
		Proxy: nil, DialContext: (&net.Dialer{Timeout: 3 * time.Second}).DialContext,
		ResponseHeaderTimeout: 30 * time.Second, MaxResponseHeaderBytes: maxHTTPHeaderBytes,
	}
	return proxy
}

func serveEgressBridge(ctx context.Context, listener net.Listener, socket string) error {
	connections := make(chan struct{}, 128)
	go func() { <-ctx.Done(); _ = listener.Close() }()
	for {
		connection, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		select {
		case connections <- struct{}{}:
			go func(agent net.Conn) {
				defer func() { <-connections }()
				bridgeEgress(agent, socket)
			}(connection)
		default:
			_ = connection.Close()
		}
	}
}

func bridgeEgress(agent net.Conn, socket string) {
	defer agent.Close()
	gateway, err := (&net.Dialer{Timeout: 3 * time.Second}).Dial("unix", socket)
	if err != nil {
		return
	}
	defer gateway.Close()
	done := make(chan struct{}, 2)
	copyOneWay := func(destination, source net.Conn) {
		_, _ = io.Copy(destination, source)
		done <- struct{}{}
	}
	go copyOneWay(gateway, agent)
	go copyOneWay(agent, gateway)
	<-done
	// A failed Gateway or agent peer must release the relay's bounded bridge
	// slot immediately instead of leaving the opposite io.Copy blocked.
	_ = agent.Close()
	_ = gateway.Close()
	<-done
}

func inferenceProxy(socket string) http.Handler {
	target, _ := url.Parse("http://steward-gateway")
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.Transport = &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "unix", socket)
		},
		ResponseHeaderTimeout: 30 * time.Second, MaxResponseHeaderBytes: maxHTTPHeaderBytes,
	}
	proxy.ErrorHandler = func(w http.ResponseWriter, request *http.Request, err error) {
		slog.Error("inference gateway request failed", "method", request.Method, "path", request.URL.Path, "err", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(`{"error":"gateway_unavailable","message":"Steward inference gateway unavailable"}` + "\n"))
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 4<<20)
		proxy.ServeHTTP(w, r)
	})
}
