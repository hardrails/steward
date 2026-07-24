package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/hardrails/steward/internal/controlclient"
	"github.com/hardrails/steward/internal/securefile"
)

const (
	maxConsoleProxyRequestBytes = 1 << 20
	consoleProxyShutdownTimeout = 5 * time.Second
)

func consoleCommand(arguments []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("console", flag.ContinueOnError)
	flags.SetOutput(stdout)
	controlURL := flags.String("control-url", "", "Steward Control origin")
	caFile := flags.String("ca-file", "", "private Control CA PEM bundle")
	listenAddress := flags.String("listen", "127.0.0.1:0", "literal loopback listener")
	noContext := flags.Bool("no-context", false, "do not use the selected CLI context")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("console accepts named flags only")
	}
	if *noContext && !hasNamedFlag(arguments, "control-url") {
		return errors.New("console -no-context requires -control-url")
	}
	if !*noContext {
		config, _, err := loadCLIContextConfig()
		if err != nil {
			return err
		}
		selected, err := selectedCLIContext(config)
		if err != nil {
			return err
		}
		if !hasNamedFlag(arguments, "control-url") {
			*controlURL = selected.ControlURL
		}
		if !hasNamedFlag(arguments, "ca-file") {
			*caFile = selected.CAFile
		}
	}
	if *controlURL == "" {
		return errors.New("console requires a Control connection; select a context or pass -no-context -control-url")
	}

	var caPEM []byte
	if *caFile != "" {
		var err error
		caPEM, err = securefile.Read(*caFile, maxConsoleProxyRequestBytes, securefile.TrustFile)
		if err != nil {
			return fmt.Errorf("read Control CA: %w", err)
		}
	}
	target, transport, err := controlclient.NewProxyTarget(*controlURL, caPEM)
	if err != nil {
		return fmt.Errorf("prepare verified Control connection: %w", err)
	}
	listener, err := listenConsoleLoopback(*listenAddress)
	if err != nil {
		return err
	}
	defer listener.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	return serveConsoleProxy(ctx, listener, target.String(), transport, stdout)
}

func listenConsoleLoopback(address string) (net.Listener, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil || port == "" {
		return nil, errors.New("console -listen must be a literal loopback IP and port, for example 127.0.0.1:0")
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip == nil || !ip.IsLoopback() {
		return nil, errors.New("console -listen must use a literal loopback IP; remote exposure is forbidden")
	}
	listener, err := net.Listen("tcp", net.JoinHostPort(ip.String(), port))
	if err != nil {
		return nil, fmt.Errorf("listen for local console: %w", err)
	}
	return listener, nil
}

func serveConsoleProxy(
	ctx context.Context,
	listener net.Listener,
	targetURL string,
	transport http.RoundTripper,
	stdout io.Writer,
) error {
	parsedTarget, parseErr := parseConsoleTarget(targetURL)
	if parseErr != nil {
		return parseErr
	}
	proxy := httputil.NewSingleHostReverseProxy(parsedTarget)
	director := proxy.Director
	proxy.Director = func(request *http.Request) {
		director(request)
		request.Host = parsedTarget.Host
	}
	proxy.Transport = transport
	proxy.ErrorHandler = func(writer http.ResponseWriter, _ *http.Request, proxyErr error) {
		writeConsoleProxyError(writer, http.StatusBadGateway, "control_unavailable",
			"Could not reach Steward Control through the verified connection. Check the Control URL, tunnel, and CA file.")
	}
	expectedHost := listener.Addr().String()
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Host != expectedHost {
			writeConsoleProxyError(writer, http.StatusBadRequest, "invalid_host",
				"Open the exact console URL printed by stewardctl.")
			return
		}
		body, readErr := io.ReadAll(http.MaxBytesReader(writer, request.Body, maxConsoleProxyRequestBytes))
		if readErr != nil {
			writeConsoleProxyError(writer, http.StatusRequestEntityTooLarge, "request_too_large",
				"Console requests are limited to 1 MiB.")
			return
		}
		request.Body = io.NopCloser(bytes.NewReader(body))
		request.ContentLength = int64(len(body))
		proxy.ServeHTTP(writer, request)
	})
	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}

	consoleURL := "http://" + expectedHost + "/console/"
	if _, err := fmt.Fprintf(stdout,
		"Steward console: %s\nControl TLS is verified locally. Keep this command running; press Ctrl-C to stop.\n",
		consoleURL,
	); err != nil {
		return err
	}

	serveResult := make(chan error, 1)
	go func() {
		serveResult <- server.Serve(listener)
	}()
	select {
	case err := <-serveResult:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), consoleProxyShutdownTimeout)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("stop local console: %w", err)
		}
		err := <-serveResult
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	}
}

func parseConsoleTarget(raw string) (*url.URL, error) {
	target, err := url.Parse(raw)
	if err != nil || target.Scheme == "" || target.Host == "" {
		return nil, errors.New("internal console target is invalid")
	}
	return target, nil
}

func writeConsoleProxyError(writer http.ResponseWriter, status int, code, message string) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(map[string]string{"error": code, "message": message})
}
