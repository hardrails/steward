package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hardrails/steward/internal/controlcapture"
	"github.com/hardrails/steward/internal/controlclient"
	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/controlstore"
	"github.com/hardrails/steward/internal/controlwitness"
	"github.com/hardrails/steward/internal/securefile"
)

type controlEvidenceCaptureDeleteOutput struct {
	NodeID    string `json:"node_id"`
	CaptureID string `json:"capture_id"`
	Deleted   bool   `json:"deleted"`
}

type controlEvidenceCaptureExportOutput struct {
	NodeID                     string `json:"node_id"`
	CaptureID                  string `json:"capture_id"`
	Output                     string `json:"output"`
	FrameCount                 uint32 `json:"frame_count"`
	FramesDigest               string `json:"frames_digest"`
	WitnessPublicKeySHA256     string `json:"witness_public_key_sha256"`
	ActivationBeginDigest      string `json:"activation_begin_digest"`
	ActivationCheckpointDigest string `json:"activation_checkpoint_digest"`
}

type controlEvidenceCaptureVerificationOutput struct {
	Verified                       bool   `json:"verified"`
	CaptureID                      string `json:"capture_id"`
	NodeID                         string `json:"node_id"`
	ActivationID                   string `json:"activation_id"`
	FinalSequence                  uint64 `json:"final_sequence"`
	FinalChainHash                 string `json:"final_chain_hash"`
	ActivationBeginSequence        uint64 `json:"activation_begin_sequence"`
	ActivationBeginDigest          string `json:"activation_begin_digest"`
	ActivationCheckpointSequence   uint64 `json:"activation_checkpoint_sequence"`
	ActivationCheckpointDigest     string `json:"activation_checkpoint_digest"`
	WitnessPublicKeySHA256         string `json:"witness_public_key_sha256"`
	ExecutorReceiptPublicKeySHA256 string `json:"executor_receipt_public_key_sha256"`
}

func controlEvidenceCaptureArm(arguments []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("control evidence-capture arm", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	common := addControlFlags(flags, true)
	nodeID := flags.String("node-id", "", "node identity")
	captureID := flags.String("capture-id", "", "stable capture identity")
	requestID := flags.String("request-id", "", "idempotency identity")
	tenantID := flags.String("tenant-id", "", "activation tenant")
	runtimeRef := flags.String("runtime-ref", "", "exact Executor runtime reference")
	generation := flags.Uint64("generation", 0, "exact instance generation")
	activationID := flags.String("activation-id", "", "exact activation identity")
	activationBeginDigest := flags.String("activation-begin-digest", "", "exact activation begin SHA-256 digest")
	ttl := flags.Duration("ttl", 0, "capture lifetime from 1s through 1h, in whole seconds")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if !validRequiredControlIdentifier(*nodeID, 128) ||
		!validRequiredControlIdentifier(*captureID, 128) ||
		!validRequiredControlIdentifier(*requestID, 128) ||
		!validRequiredControlIdentifier(*tenantID, 128) ||
		!validExecutorRuntimeRef(*runtimeRef) ||
		*generation == 0 ||
		!validRequiredControlIdentifier(*activationID, 128) ||
		!controlprotocol.ValidSHA256Digest(*activationBeginDigest) ||
		*ttl < controlstore.MinEvidenceCaptureTTL ||
		*ttl > controlstore.MaxEvidenceCaptureTTL ||
		*ttl%time.Second != 0 ||
		flags.NArg() != 0 {
		return errors.New("control evidence-capture arm requires bounded node, capture, request, tenant, runtime, non-zero generation, activation, activation-begin SHA-256 digest, and a whole-second TTL from 1s through 1h")
	}
	client, err := common.client(true)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	capture, err := client.ArmExecutorEvidenceCapture(ctx, *nodeID, controlclient.EvidenceCaptureArmInput{
		CaptureID: *captureID, RequestID: *requestID, TenantID: *tenantID,
		RuntimeRef: *runtimeRef, Generation: *generation, ActivationID: *activationID,
		ActivationBeginDigest: *activationBeginDigest,
		TTL:                   *ttl,
	})
	if err != nil {
		return err
	}
	return writeControlJSON(stdout, capture)
}

func validExecutorRuntimeRef(value string) bool {
	const prefix = "executor-"
	if !strings.HasPrefix(value, prefix) || len(value) != len(prefix)+64 {
		return false
	}
	for _, character := range strings.TrimPrefix(value, prefix) {
		if character < '0' || (character > '9' && character < 'a') || character > 'f' {
			return false
		}
	}
	return true
}

func controlEvidenceCaptureStatus(arguments []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("control evidence-capture status", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	common := addControlFlags(flags, true)
	nodeID := flags.String("node-id", "", "node identity")
	captureID := flags.String("capture-id", "", "capture identity")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if err := validateControlEvidenceCaptureCoordinates(*nodeID, *captureID, flags.NArg()); err != nil {
		return fmt.Errorf("control evidence-capture status: %w", err)
	}
	client, err := common.client(true)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	capture, err := client.GetExecutorEvidenceCapture(ctx, *nodeID, *captureID)
	if err != nil {
		return err
	}
	return writeControlJSON(stdout, capture)
}

func controlEvidenceCaptureSeal(arguments []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("control evidence-capture seal", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	common := addControlFlags(flags, true)
	nodeID := flags.String("node-id", "", "node identity")
	captureID := flags.String("capture-id", "", "capture identity")
	canaryCommandID := flags.String("canary-command-id", "", "successful activation-canary command identity")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if err := validateControlEvidenceCaptureCoordinates(*nodeID, *captureID, flags.NArg()); err != nil ||
		!validRequiredControlIdentifier(*canaryCommandID, 256) {
		return errors.New("control evidence-capture seal requires bounded node, capture, and canary command identities")
	}
	client, err := common.client(true)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	capture, err := client.SealExecutorEvidenceCapture(ctx, *nodeID, *captureID, *canaryCommandID)
	if err != nil {
		return err
	}
	return writeControlJSON(stdout, capture)
}

func controlEvidenceCaptureExport(arguments []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("control evidence-capture export", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	common := addControlFlags(flags, true)
	nodeID := flags.String("node-id", "", "node identity")
	captureID := flags.String("capture-id", "", "sealed capture identity")
	output := flags.String("out", "", "new owner-only signed evidence capture")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if err := validateControlEvidenceCaptureCoordinates(*nodeID, *captureID, flags.NArg()); err != nil ||
		!validNewControlEvidenceCaptureOutput(*output) {
		return errors.New("control evidence-capture export requires bounded node and capture identities and a safe new output path")
	}
	if _, err := os.Lstat(*output); err == nil {
		return fmt.Errorf("control evidence-capture export output already exists: %s", *output)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect control evidence-capture export output: %w", err)
	}
	client, err := common.client(true)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	export, err := client.ExportExecutorEvidenceCapture(ctx, *nodeID, *captureID)
	if err != nil {
		return err
	}
	canonical, err := json.Marshal(export)
	if err != nil {
		return fmt.Errorf("encode control evidence capture export: %w", err)
	}
	if len(canonical) > controlprotocol.MaxControllerEvidenceCaptureJSONBytes {
		return errors.New("control evidence capture export exceeds its canonical JSON limit")
	}
	if err := writeNewFile(*output, append(canonical, '\n'), 0o600); err != nil {
		return fmt.Errorf("write control evidence capture export: %w", err)
	}
	return writeControlJSON(stdout, controlEvidenceCaptureExportOutput{
		NodeID: *nodeID, CaptureID: *captureID, Output: *output,
		FrameCount: export.Statement.FrameCount, FramesDigest: export.Statement.FramesDigest,
		WitnessPublicKeySHA256:     export.WitnessPublicKeySHA256,
		ActivationBeginDigest:      export.Statement.ActivationBeginDigest,
		ActivationCheckpointDigest: export.Statement.ActivationCheckpointDigest,
	})
}

func controlEvidenceCaptureVerify(arguments []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("control evidence-capture verify", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	input := flags.String("in", "", "owner-only signed evidence capture")
	witnessPublicKey := flags.String("witness-public-key", "", "pinned controller witness public key PEM")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *input == "" || *witnessPublicKey == "" || flags.NArg() != 0 {
		return errors.New("control evidence-capture verify requires -in and -witness-public-key")
	}
	raw, err := securefile.Read(
		*input,
		controlprotocol.MaxControllerEvidenceCaptureJSONBytes,
		securefile.OwnerOnly,
	)
	if err != nil {
		return fmt.Errorf("read control evidence capture export: %w", err)
	}
	capture, err := controlprotocol.DecodeControllerEvidenceCaptureV1(raw)
	if err != nil {
		return fmt.Errorf("decode control evidence capture export: %w", err)
	}
	public, err := controlwitness.LoadPublic(*witnessPublicKey)
	if err != nil {
		return err
	}
	result, err := controlcapture.VerifyV1(capture, public)
	if err != nil {
		return fmt.Errorf("verify control evidence capture export: %w", err)
	}
	return writeControlJSON(stdout, controlEvidenceCaptureVerificationOutput{
		Verified: true, CaptureID: result.Statement.CaptureID, NodeID: result.Statement.NodeID,
		ActivationID:                   result.Statement.ActivationID,
		FinalSequence:                  result.Statement.FinalHead.Sequence,
		FinalChainHash:                 result.Statement.FinalHead.ChainHash,
		ActivationBeginSequence:        result.Begin.Receipt.Sequence,
		ActivationBeginDigest:          result.Statement.ActivationBeginDigest,
		ActivationCheckpointSequence:   result.Checkpoint.Receipt.Sequence,
		ActivationCheckpointDigest:     result.Statement.ActivationCheckpointDigest,
		WitnessPublicKeySHA256:         capture.WitnessPublicKeySHA256,
		ExecutorReceiptPublicKeySHA256: result.Statement.FinalHead.PublicKeySHA256,
	})
}

func controlEvidenceCaptureDelete(arguments []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("control evidence-capture delete", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	common := addControlFlags(flags, true)
	nodeID := flags.String("node-id", "", "node identity")
	captureID := flags.String("capture-id", "", "capture identity")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if err := validateControlEvidenceCaptureCoordinates(*nodeID, *captureID, flags.NArg()); err != nil {
		return fmt.Errorf("control evidence-capture delete: %w", err)
	}
	client, err := common.client(true)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := client.DeleteExecutorEvidenceCapture(ctx, *nodeID, *captureID); err != nil {
		return err
	}
	return writeControlJSON(stdout, controlEvidenceCaptureDeleteOutput{
		NodeID: *nodeID, CaptureID: *captureID, Deleted: true,
	})
}

func validateControlEvidenceCaptureCoordinates(nodeID, captureID string, positional int) error {
	if !validRequiredControlIdentifier(nodeID, 128) ||
		!validRequiredControlIdentifier(captureID, 128) || positional != 0 {
		return errors.New("bounded node and capture identities are required")
	}
	return nil
}

func validRequiredControlIdentifier(value string, maximum int) bool {
	return value != "" && validOptionalControlIdentifier(value, maximum)
}

func validNewControlEvidenceCaptureOutput(path string) bool {
	return path != "" && (filepath.IsAbs(path) || !strings.Contains(path, ".."))
}
