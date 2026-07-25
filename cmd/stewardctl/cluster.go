package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"

	"github.com/hardrails/steward/internal/clustersubstrate"
)

func clusterCommand(arguments []string, stdout io.Writer) error {
	if len(arguments) == 0 {
		return errors.New("cluster requires plan, artifact, or baseline")
	}
	switch arguments[0] {
	case "plan":
		return clusterPlan(arguments[1:], stdout)
	case "artifact":
		return clusterArtifact(arguments[1:], stdout)
	case "baseline":
		if len(arguments) != 1 {
			return errors.New("cluster baseline accepts no options")
		}
		_, err := io.WriteString(stdout, clustersubstrate.BaselineManifest)
		return err
	default:
		return errors.New("cluster requires plan, artifact, or baseline")
	}
}

func clusterPlan(arguments []string, stdout io.Writer) error {
	if len(arguments) == 0 {
		return errors.New("cluster plan requires init, join-server, or join-worker")
	}
	operation := arguments[0]
	flags := flag.NewFlagSet("cluster plan "+operation, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	clusterName := flags.String("cluster", "steward", "lowercase cluster name")
	nodeName := flags.String("node", defaultClusterNodeName(), "lowercase node name")
	server := flags.String("server", "", "RKE2 registration origin for a joining node")
	tokenFile := flags.String("token-file", "/run/steward-cluster/join-token", "owner-only bootstrap token file")
	arch := flags.String("arch", runtime.GOARCH, "target architecture: amd64 or arm64")
	airGap := flags.Bool("air-gap", false, "require the pinned RKE2 image archive")
	noStart := flags.Bool("no-start", false, "stage without starting the RKE2 service")
	output := flags.String("output", "human", "human, json, or config")
	if err := flags.Parse(arguments[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("cluster plan accepts no positional arguments after the operation")
	}
	request := clustersubstrate.PlanRequest{
		Operation: operation, ClusterName: *clusterName, NodeName: *nodeName,
		Arch: *arch, AirGap: *airGap, Start: !*noStart,
	}
	if operation != clustersubstrate.OperationInit {
		request.ServerURL = *server
		request.TokenFile = *tokenFile
	}
	plan, err := clustersubstrate.BuildPlan(request)
	if err != nil {
		return err
	}
	switch *output {
	case "human":
		return writeClusterPlanHuman(stdout, plan)
	case "json":
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(plan)
	case "config":
		_, err := io.WriteString(stdout, plan.Config)
		return err
	default:
		return errors.New("cluster plan output must be human, json, or config")
	}
}

func defaultClusterNodeName() string {
	host, err := os.Hostname()
	if err != nil || host == "" {
		return "steward-node"
	}
	return strings.ToLower(strings.TrimSuffix(host, "."))
}

func writeClusterPlanHuman(writer io.Writer, plan clustersubstrate.Plan) error {
	fmt.Fprintf(writer, "Steward cluster plan\n\n")
	fmt.Fprintf(writer, "Operation:     %s\n", plan.Operation)
	fmt.Fprintf(writer, "Node:          %s\n", plan.NodeName)
	fmt.Fprintf(writer, "Cluster:       %s\n", plan.ClusterName)
	fmt.Fprintf(writer, "Service:       %s\n", plan.Service)
	fmt.Fprintf(writer, "Substrate:     RKE2 %s (%s)\n", plan.Version, plan.Architecture)
	fmt.Fprintf(writer, "Source:        %s\n", map[bool]string{true: "offline bundle", false: "pinned HTTPS"}[plan.AirGap])
	fmt.Fprintf(writer, "Start service: %t\n", plan.Start)
	if plan.ServerURL != "" {
		fmt.Fprintf(writer, "Join endpoint: %s\n", plan.ServerURL)
	}
	fmt.Fprintln(writer, "\nSecurity boundary:")
	for _, boundary := range plan.Trust {
		fmt.Fprintf(writer, "- %s\n", boundary)
	}
	fmt.Fprintln(writer, "\nImportant:")
	for _, warning := range plan.Warnings {
		fmt.Fprintf(writer, "- %s\n", warning)
	}
	fmt.Fprintln(writer, "\nNo host changes were made.")
	return nil
}

func clusterArtifact(arguments []string, stdout io.Writer) error {
	if len(arguments) == 0 {
		return errors.New("cluster artifact requires bundle, images, or checksums")
	}
	kind := arguments[0]
	flags := flag.NewFlagSet("cluster artifact "+kind, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	arch := flags.String("arch", runtime.GOARCH, "target architecture: amd64 or arm64")
	output := flags.String("output", "tsv", "tsv or json")
	if err := flags.Parse(arguments[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("cluster artifact accepts no positional arguments after the artifact kind")
	}
	lock, err := clustersubstrate.CurrentLock()
	if err != nil {
		return err
	}
	artifact, err := lock.Artifact(*arch, kind)
	if err != nil {
		return err
	}
	switch *output {
	case "tsv":
		_, err := fmt.Fprintf(stdout, "%s\t%s\t%d\t%s\n", artifact.Name, artifact.URL, artifact.Size, artifact.SHA256)
		return err
	case "json":
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(artifact)
	default:
		return errors.New("cluster artifact output must be tsv or json")
	}
}
