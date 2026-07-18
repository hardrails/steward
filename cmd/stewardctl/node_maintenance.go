package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/hardrails/steward/internal/nodeclient"
)

type nodeDrainResult struct {
	SchemaVersion string                       `json:"schema_version"`
	Applied       bool                         `json:"applied"`
	Destroyed     []string                     `json:"destroyed_runtime_refs"`
	Maintenance   nodeclient.MaintenanceStatus `json:"maintenance"`
}

func nodeMaintenanceCommand(arguments []string, stdout io.Writer) error {
	if len(arguments) == 0 {
		return errors.New("node maintenance requires status, enter, drain, or exit")
	}
	action := arguments[0]
	flags := flag.NewFlagSet("node maintenance "+action, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	nodeURL := flags.String("node-url", "http://127.0.0.1:8090", "loopback Executor origin")
	tokenFile := flags.String("token-file", "", "owner-only Executor token")
	reason := flags.String("reason", "", "bounded reason retained until maintenance exits")
	apply := flags.Bool("apply", false, "enter maintenance and destroy every active runtime")
	if err := flags.Parse(arguments[1:]); err != nil {
		return err
	}
	if *tokenFile == "" || flags.NArg() != 0 {
		return errors.New("node maintenance requires -token-file and no positional arguments")
	}
	if action != "enter" && action != "drain" && *reason != "" {
		return fmt.Errorf("node maintenance %s does not accept -reason", action)
	}
	if action != "drain" && *apply {
		return fmt.Errorf("node maintenance %s does not accept -apply", action)
	}
	if (action == "enter" || (action == "drain" && *apply)) && *reason == "" {
		return fmt.Errorf("node maintenance %s requires -reason", action)
	}
	client, err := nodeclient.NewFromTokenFile(*nodeURL, *tokenFile)
	if err != nil {
		return err
	}
	timeout := 30 * time.Second
	if action == "drain" && *apply {
		timeout = 10 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	var result any
	switch action {
	case "status":
		result, err = client.MaintenanceStatus(ctx)
	case "enter":
		result, err = client.EnterMaintenance(ctx, *reason)
	case "exit":
		result, err = client.ExitMaintenance(ctx)
	case "drain":
		status, statusErr := client.MaintenanceStatus(ctx)
		if statusErr != nil {
			return statusErr
		}
		if !*apply {
			result = nodeDrainResult{
				SchemaVersion: "steward.node-drain.v1", Applied: false,
				Destroyed: []string{}, Maintenance: status,
			}
			break
		}
		status, err = client.EnterMaintenance(ctx, *reason)
		if err != nil {
			return err
		}
		destroyed := make([]string, 0, len(status.ActiveRuntimeRefs))
		for _, runtimeRef := range status.ActiveRuntimeRefs {
			if err := client.Destroy(ctx, runtimeRef); err != nil {
				return fmt.Errorf("drain stopped after %d runtimes; maintenance remains enabled: destroy %s: %w", len(destroyed), runtimeRef, err)
			}
			destroyed = append(destroyed, runtimeRef)
		}
		status, err = client.MaintenanceStatus(ctx)
		if err != nil {
			return fmt.Errorf("drain completed but final maintenance status is unavailable: %w", err)
		}
		result = nodeDrainResult{
			SchemaVersion: "steward.node-drain.v1", Applied: true,
			Destroyed: destroyed, Maintenance: status,
		}
	default:
		return errors.New("node maintenance requires status, enter, drain, or exit")
	}
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(result)
}
