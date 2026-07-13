// Command steward-mcp exposes Steward node operations and optional Gateway
// task-lifecycle operations as MCP tools over stdio.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/hardrails/steward/internal/buildinfo"
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
	nodeURL := flags.String("node-url", "http://127.0.0.1:8090", "loopback Steward Executor origin")
	tokenFile := flags.String("token-file", "", "owner-only Executor token file")
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
	if *tokenFile == "" {
		fmt.Fprintln(stderr, "steward-mcp: -token-file is required")
		return 2
	}
	client, err := nodeclient.NewFromTokenFile(*nodeURL, *tokenFile)
	if err != nil {
		fmt.Fprintln(stderr, "steward-mcp:", err)
		return 2
	}
	var server *mcpserver.Server
	gatewayConfigured := *gatewayURL != "" || *gatewayTokenFile != "" || *taskResultDirectory != ""
	if gatewayConfigured && (*gatewayURL == "" || *gatewayTokenFile == "" || *taskResultDirectory == "") {
		fmt.Fprintln(stderr, "steward-mcp: -gateway-url, -gateway-token-file, and -task-result-dir must be configured together")
		return 2
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
		server, err = mcpserver.NewWithTasks(client, taskClient, *taskResultDirectory, buildinfo.Resolve())
	} else {
		server, err = mcpserver.New(client, buildinfo.Resolve())
	}
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
