package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"time"

	"github.com/hardrails/steward/internal/controlstore"
)

func controlSnapshotQuarantineStatus(arguments []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("control snapshot status", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	common := addControlFlags(flags, true)
	tenantID := flags.String("tenant-id", "", "tenant identity")
	nodeID := flags.String("node-id", "", "source node identity")
	snapshotID := flags.String("snapshot-id", "", "snapshot identity")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || !validRequiredControlIdentifier(*tenantID, 128) ||
		!validRequiredControlIdentifier(*nodeID, 128) || !validRequiredControlIdentifier(*snapshotID, 128) {
		return errors.New("control snapshot status requires bounded tenant, node, and snapshot identities")
	}
	client, err := common.client(true)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	status, err := client.GetSnapshotQuarantine(ctx, *tenantID, *nodeID, *snapshotID)
	if err != nil {
		return err
	}
	return writeControlJSON(stdout, status)
}

func controlSnapshotQuarantineChange(
	arguments []string,
	stdout io.Writer,
	action controlstore.SnapshotQuarantineAction,
) error {
	command := "control snapshot quarantine"
	if action == controlstore.SnapshotQuarantineActionClear {
		command = "control snapshot unquarantine"
	}
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	common := addControlFlags(flags, true)
	tenantID := flags.String("tenant-id", "", "tenant identity")
	nodeID := flags.String("node-id", "", "source node identity")
	snapshotID := flags.String("snapshot-id", "", "snapshot identity")
	reason := flags.String("reason", "", "short incident reason required when quarantining")
	revision := flags.Uint64("revision", 0, "optional exact retained revision; default discovers it")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || !validRequiredControlIdentifier(*tenantID, 128) ||
		!validRequiredControlIdentifier(*nodeID, 128) || !validRequiredControlIdentifier(*snapshotID, 128) ||
		action == controlstore.SnapshotQuarantineActionSet && (*reason == "" || len(*reason) > 256) ||
		action == controlstore.SnapshotQuarantineActionClear && *reason != "" {
		return errors.New(command + " requires bounded tenant, node, and snapshot identities and a reason only when quarantining")
	}
	client, err := common.client(true)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	expected := *revision
	if expected == 0 {
		status, inspectErr := client.GetSnapshotQuarantine(ctx, *tenantID, *nodeID, *snapshotID)
		if inspectErr != nil {
			return inspectErr
		}
		if status.Record != nil {
			expected = status.Record.Revision
		}
	}
	change, err := client.ChangeSnapshotQuarantine(
		ctx, *tenantID, *nodeID, *snapshotID, action, expected, *reason,
	)
	if err != nil {
		return err
	}
	return writeControlJSON(stdout, change)
}
