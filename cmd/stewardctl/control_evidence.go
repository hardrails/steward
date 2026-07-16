package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/controlwitness"
	"github.com/hardrails/steward/internal/securefile"
)

type controlEvidenceVerification struct {
	Verified               bool    `json:"verified"`
	ControllerInstanceID   string  `json:"controller_instance_id"`
	ControlNodeID          string  `json:"control_node_id"`
	State                  string  `json:"state"`
	Sequence               *uint64 `json:"sequence,omitempty"`
	Finding                string  `json:"finding,omitempty"`
	ExportedAt             string  `json:"exported_at"`
	WitnessPublicKeySHA256 string  `json:"witness_public_key_sha256"`
}

func controlEvidenceStatus(arguments []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("control evidence status", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	common := addControlFlags(flags, true)
	nodeID := flags.String("node-id", "", "node identity")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *nodeID == "" || flags.NArg() != 0 {
		return errors.New("control evidence status requires -node-id and a site-admin token")
	}
	client, err := common.client(true)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	inspection, err := client.InspectExecutorEvidence(ctx, *nodeID)
	if err != nil {
		return err
	}
	return writeControlJSON(stdout, inspection)
}

func controlEvidenceExport(arguments []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("control evidence export", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	common := addControlFlags(flags, true)
	nodeID := flags.String("node-id", "", "node identity")
	output := flags.String("out", "", "new owner-only signed evidence export")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *nodeID == "" || *output == "" || flags.NArg() != 0 {
		return errors.New("control evidence export requires -node-id, -out, and a site-admin token")
	}
	if _, err := os.Lstat(*output); err == nil {
		return fmt.Errorf("control evidence export output already exists: %s", *output)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect control evidence export output: %w", err)
	}
	client, err := common.client(true)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	export, err := client.ExportExecutorEvidence(ctx, *nodeID)
	if err != nil {
		return err
	}
	raw, err := json.MarshalIndent(export, "", "  ")
	if err != nil {
		return err
	}
	if err := writeNewFile(*output, append(raw, '\n'), 0o600); err != nil {
		return fmt.Errorf("write control evidence export: %w", err)
	}
	_, err = fmt.Fprintln(stdout, *output)
	return err
}

func controlEvidenceVerify(arguments []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("control evidence verify", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	input := flags.String("in", "", "signed evidence export")
	witnessPublicKey := flags.String("witness-public-key", "", "pinned controller witness public key PEM")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *input == "" || *witnessPublicKey == "" || flags.NArg() != 0 {
		return errors.New("control evidence verify requires -in and -witness-public-key")
	}
	raw, err := securefile.Read(*input, controlprotocol.MaxExecutorEvidenceJSONBytes, securefile.Regular)
	if err != nil {
		return fmt.Errorf("read control evidence export: %w", err)
	}
	export, err := controlprotocol.DecodeExecutorEvidenceExportV1(raw)
	if err != nil {
		return fmt.Errorf("decode control evidence export: %w", err)
	}
	public, err := controlwitness.LoadPublic(*witnessPublicKey)
	if err != nil {
		return err
	}
	if err := controlprotocol.VerifyExecutorEvidenceExportV1(export, public); err != nil {
		return fmt.Errorf("verify control evidence export: %w", err)
	}
	var sequence *uint64
	if export.Statement.Status.Head != nil {
		value := export.Statement.Status.Head.Sequence
		sequence = &value
	}
	finding := ""
	if export.Statement.Status.Finding != nil {
		finding = export.Statement.Status.Finding.Kind
	}
	return writeControlJSON(stdout, controlEvidenceVerification{
		Verified: true, ControllerInstanceID: export.Statement.ControllerInstanceID,
		ControlNodeID: export.Statement.ControlNodeID, State: export.Statement.Status.State,
		Sequence: sequence, Finding: finding, ExportedAt: export.Statement.ExportedAt,
		WitnessPublicKeySHA256: export.WitnessPublicKeySHA256,
	})
}
