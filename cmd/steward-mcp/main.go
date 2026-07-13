// Command steward-mcp exposes optional Steward node, control-plane, and
// Gateway task-lifecycle operations as MCP tools over stdio.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/hardrails/steward/internal/buildinfo"
	"github.com/hardrails/steward/internal/controlclient"
	"github.com/hardrails/steward/internal/gatewayclient"
	"github.com/hardrails/steward/internal/mcpserver"
	"github.com/hardrails/steward/internal/nodeclient"
)

func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("steward-mcp", flag.ContinueOnError)
	flags.SetOutput(stderr)
	version := flags.Bool("version", false, "print the steward-mcp version and exit")
	nodeURL := flags.String("node-url", "http://127.0.0.1:8090", "loopback Steward Executor origin used with -token-file")
	tokenFile := flags.String("token-file", "", "owner-only Executor token file for optional node tools")
	controlURL := flags.String("control-url", "", "Steward control-plane origin for optional fleet tools (HTTPS except literal loopback)")
	controlTokenFile := flags.String("control-token-file", "", "owner-only control-plane operator token file")
	controlCAFile := flags.String("control-ca-file", "", "optional control-plane CA certificate file")
	gatewayURL := flags.String("gateway-url", "", "literal-loopback Steward Gateway origin for optional task tools")
	gatewayTokenFile := flags.String("gateway-token-file", "", "owner-only Gateway token file for optional task tools")
	taskResultDirectory := flags.String("task-result-dir", "", "existing owner-only directory for recovered task results")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *version {
		fmt.Fprintln(stdout, "steward-mcp "+buildinfo.Resolve())
		return 0
	}
	nodeURLExplicit := false
	flags.Visit(func(parsed *flag.Flag) {
		if parsed.Name == "node-url" {
			nodeURLExplicit = true
		}
	})
	nodeConfigured := *tokenFile != "" || nodeURLExplicit
	if nodeConfigured && *tokenFile == "" {
		fmt.Fprintln(stderr, "steward-mcp: -node-url and -token-file must be configured together")
		return 2
	}
	controlConfigured := *controlURL != "" || *controlTokenFile != "" || *controlCAFile != ""
	if controlConfigured && (*controlURL == "" || *controlTokenFile == "") {
		fmt.Fprintln(stderr, "steward-mcp: -control-url and -control-token-file must be configured together; -control-ca-file is optional")
		return 2
	}
	gatewayConfigured := *gatewayURL != "" || *gatewayTokenFile != "" || *taskResultDirectory != ""
	if gatewayConfigured && (*gatewayURL == "" || *gatewayTokenFile == "" || *taskResultDirectory == "") {
		fmt.Fprintln(stderr, "steward-mcp: -gateway-url, -gateway-token-file, and -task-result-dir must be configured together")
		return 2
	}
	if gatewayConfigured && !nodeConfigured {
		fmt.Fprintln(stderr, "steward-mcp: Gateway task tools require -token-file node configuration")
		return 2
	}
	if !nodeConfigured && !controlConfigured {
		fmt.Fprintln(stderr, "steward-mcp: configure node tools with -token-file, control-plane tools with -control-url and -control-token-file, or both")
		return 2
	}

	config := mcpserver.Config{Version: buildinfo.Resolve()}
	if nodeConfigured {
		client, err := nodeclient.NewFromTokenFile(*nodeURL, *tokenFile)
		if err != nil {
			fmt.Fprintln(stderr, "steward-mcp:", err)
			return 2
		}
		config.Node = client
	}
	if controlConfigured {
		client, err := controlclient.NewFromFiles(*controlURL, *controlTokenFile, *controlCAFile)
		if err != nil {
			fmt.Fprintln(stderr, "steward-mcp:", err)
			return 2
		}
		config.Control = client
	}
	if gatewayConfigured {
		gatewayToken, readErr := nodeclient.ReadToken(*gatewayTokenFile)
		if readErr != nil {
			fmt.Fprintln(stderr, "steward-mcp: read Gateway token:", readErr)
			return 2
		}
		taskClient, clientErr := gatewayclient.New(*gatewayURL, gatewayToken)
		if clientErr != nil {
			fmt.Fprintln(stderr, "steward-mcp:", clientErr)
			return 2
		}
		config.Tasks = taskClient
		config.TaskResultDirectory = *taskResultDirectory
	}
	server, err := mcpserver.NewConfigured(config)
	if err != nil {
		fmt.Fprintln(stderr, "steward-mcp:", err)
		return 2
	}
	if err := server.Serve(ctx, stdin, stdout, stderr); err != nil {
		fmt.Fprintln(stderr, "steward-mcp:", err)
		return 1
	}
	return 0
}
