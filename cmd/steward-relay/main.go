// Command steward-relay is the trusted, fixed-destination companion used by
// capability-bearing agent workloads.
package main

import (
	"context"
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
	"sync"
	"syscall"
	"time"

	"github.com/hardrails/steward/internal/buildinfo"
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
	egressAddress := flags.String("egress-addr", ":8082", "private-network HTTP(S) proxy listener")
	egressSocket := flags.String("egress-socket", "", "mounted per-grant gateway egress Unix socket")
	serviceAddress := flags.String("service-addr", ":8081", "loopback-published service relay listener")
	serviceTarget := flags.String("service-target", "", "fixed private agent service origin")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *version {
		fmt.Fprintln(stdout, "steward-relay "+buildinfo.Resolve())
		return 0
	}
	if *inferenceSocket == "" && *serviceTarget == "" && *egressSocket == "" {
		fmt.Fprintln(stderr, "steward-relay: at least one gateway or service socket is required")
		return 2
	}
	var servers []*http.Server
	var egressListener net.Listener
	if *inferenceSocket != "" {
		servers = append(servers, &http.Server{
			Addr: *inferenceAddress, Handler: inferenceProxy(*inferenceSocket),
			ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 2 * time.Minute, WriteTimeout: 2 * time.Minute, IdleTimeout: 30 * time.Second,
		})
	}
	if *serviceTarget != "" {
		target, err := url.Parse(*serviceTarget)
		if err != nil || target.Scheme != "http" || target.Hostname() != "agent" || target.Port() == "" || target.Path != "" {
			fmt.Fprintln(stderr, "steward-relay: service target must be http://agent:PORT")
			return 2
		}
		proxy := httputil.NewSingleHostReverseProxy(target)
		proxy.Transport = &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 3 * time.Second}).DialContext, ResponseHeaderTimeout: 30 * time.Second}
		// The host Gateway reaches this listener through the relay's fixed private
		// IP, so it cannot bind loopback. Isolation comes from the Executor-derived,
		// internal, non-attachable per-instance network: its only peers are this
		// trusted relay and the one agent that already owns the target service.
		servers = append(servers, &http.Server{
			Addr: *serviceAddress, Handler: proxy,
			ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 2 * time.Minute, IdleTimeout: 30 * time.Second,
		})
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
			if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
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
	select {
	case <-ctx.Done():
	case err := <-errorsCh:
		slog.Error("relay listener", "err", err)
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
	return 0
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
	var wait sync.WaitGroup
	wait.Add(2)
	copyOneWay := func(destination, source net.Conn) {
		defer wait.Done()
		_, _ = io.Copy(destination, source)
		if tcp, ok := destination.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
	}
	go copyOneWay(gateway, agent)
	go copyOneWay(agent, gateway)
	wait.Wait()
}

func inferenceProxy(socket string) http.Handler {
	target, _ := url.Parse("http://steward-gateway")
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.Transport = &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "unix", socket)
		},
		ResponseHeaderTimeout: 30 * time.Second,
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
