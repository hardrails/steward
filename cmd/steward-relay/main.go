// Command steward-relay is the trusted, fixed-destination companion used by
// capability-bearing agent workloads.
package main

import (
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
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/hardrails/steward/internal/buildinfo"
)

const maxHTTPHeaderBytes = 64 << 10

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
	if *inferenceSocket == "" && *serviceSocket == "" && *egressSocket == "" {
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
	if *inferenceSocket != "" {
		servers = append(servers, &http.Server{
			Addr: *inferenceAddress, Handler: inferenceProxy(*inferenceSocket),
			ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 2 * time.Minute, WriteTimeout: 2 * time.Minute,
			IdleTimeout: 30 * time.Second, MaxHeaderBytes: maxHTTPHeaderBytes,
		})
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
		serviceServer = &http.Server{
			Handler: proxy,
			// The authenticated host Gateway owns the service stream's 2-minute
			// lifetime and byte ceilings. ReadTimeout/WriteTimeout stay unset here
			// because fixed HTTP deadlines truncate upgraded WebSocket sessions;
			// header and idle limits still bound non-upgraded connections.
			ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: maxHTTPHeaderBytes,
		}
		servers = append(servers, serviceServer)
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
			if server != serviceServer {
				err = server.ListenAndServe()
			} else {
				err = server.Serve(serviceListener)
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
		_ = server.Shutdown(shutdown)
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
