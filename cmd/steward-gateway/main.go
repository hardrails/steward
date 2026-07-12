// Command steward-gateway brokers narrow local inference and service grants.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/hardrails/steward/internal/buildinfo"
	"github.com/hardrails/steward/internal/gateway"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("steward-gateway", flag.ContinueOnError)
	flags.SetOutput(stderr)
	version := flags.Bool("version", false, "print the Steward Gateway version and exit")
	checkConfig := flags.Bool("check-config", false, "validate configuration and trust files, then exit")
	configPath := flags.String("config", "/etc/steward/gateway.json", "strict gateway configuration")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *version {
		fmt.Fprintln(stdout, "steward-gateway "+buildinfo.Resolve())
		return 0
	}
	config, routes, egressRoutes, token, err := gateway.LoadConfig(*configPath)
	if err != nil {
		fmt.Fprintln(stderr, "steward-gateway: load configuration:", err)
		return 2
	}
	if *checkConfig {
		if _, err := gateway.Validate(config, routes, egressRoutes, token); err != nil {
			fmt.Fprintln(stderr, "steward-gateway: validate:", err)
			return 2
		}
		fmt.Fprintln(stdout, "gateway configuration valid")
		return 0
	}
	server, err := gateway.Open(config, routes, egressRoutes, token)
	if err != nil {
		fmt.Fprintln(stderr, "steward-gateway: open:", err)
		return 2
	}
	reloads := make(chan os.Signal, 1)
	signal.Notify(reloads, syscall.SIGHUP)
	defer signal.Stop(reloads)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-reloads:
				nextConfig, nextRoutes, nextEgressRoutes, nextToken, loadErr := gateway.LoadConfig(*configPath)
				if loadErr == nil {
					loadErr = server.Reload(nextConfig, nextRoutes, nextEgressRoutes, nextToken)
				}
				if loadErr != nil {
					fmt.Fprintln(stderr, "steward-gateway: reload rejected:", loadErr)
				} else {
					fmt.Fprintln(stderr, "steward-gateway: configuration reloaded")
				}
			}
		}
	}()
	if err := server.Start(ctx); err != nil {
		fmt.Fprintln(stderr, "steward-gateway: run:", err)
		return 1
	}
	return 0
}
