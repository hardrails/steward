package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"

	"github.com/hardrails/steward/internal/activation"
	"github.com/hardrails/steward/internal/activationstore"
	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/securefile"
	"github.com/hardrails/steward/internal/taskpermit"
)

const (
	activationAttachmentCanaryTask   = "canary-task"
	activationAttachmentFinalWitness = "final-witness"
)

func attachActivationArtifact(arguments []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("activation attach", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	directoryFlag := flags.String("dir", "", "owner-only activation workspace")
	kindFlag := flags.String("kind", "", "attachment kind: canary-task or final-witness")
	inputFlag := flags.String("in", "", "owner-only attachment file")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *directoryFlag == "" || *inputFlag == "" || flags.NArg() != 0 {
		return errors.New("activation attach requires -dir, -kind canary-task|final-witness, -in, and no positional arguments")
	}
	if *kindFlag != activationAttachmentCanaryTask &&
		*kindFlag != activationAttachmentFinalWitness {
		return errors.New("activation attach -kind must be canary-task or final-witness")
	}
	directory, err := filepath.Abs(*directoryFlag)
	if err != nil {
		return fmt.Errorf("resolve activation workspace path: %w", err)
	}
	store, err := activationstore.Open(directory)
	if err != nil {
		return err
	}
	defer store.Close()
	inputs, chain, err := loadUnverifiedActivationStateChain(store)
	if err != nil {
		return err
	}

	var name string
	var raw []byte
	switch *kindFlag {
	case activationAttachmentCanaryTask:
		if chain.latest().Phase != activation.PhaseCanaryChallengeReady {
			return fmt.Errorf(
				"canary task may be attached only while activation is in %s",
				activation.PhaseCanaryChallengeReady,
			)
		}
		name = activationstore.CanaryTaskFileName
		raw, err = readAttachedCanaryTask(*inputFlag)
	case activationAttachmentFinalWitness:
		if chain.latest().Phase != activation.PhaseAgentReportedTerminal {
			return fmt.Errorf(
				"final witness may be attached only while activation is in %s",
				activation.PhaseAgentReportedTerminal,
			)
		}
		checkpointRaw, present, checkpointErr := readOptionalActivationArtifact(
			store,
			activationstore.ExecutorCheckpointFileName,
			activation.MaxExecutorCheckpointBytes,
		)
		if checkpointErr != nil {
			return fmt.Errorf("inspect activation checkpoint: %w", checkpointErr)
		}
		if !present {
			return errors.New("activation run must record the Executor checkpoint before a final witness can be attached")
		}
		if _, checkpointErr := activation.ParseExecutorCheckpointV1(
			checkpointRaw,
		); checkpointErr != nil {
			return fmt.Errorf(
				"validate retained activation checkpoint: %w",
				checkpointErr,
			)
		}
		name = activationstore.ExecutorFinalWitnessFileName
		raw, err = securefile.Read(
			*inputFlag,
			controlprotocol.MaxExecutorEvidenceJSONBytes,
			securefile.OwnerOnly,
		)
		if err == nil {
			_, err = controlprotocol.DecodeExecutorEvidenceExportV1(raw)
		}
	}
	if err != nil {
		return fmt.Errorf("validate activation %s attachment: %w", *kindFlag, err)
	}
	if err := store.WriteOnce(name, raw); err != nil {
		return fmt.Errorf("store activation %s attachment: %w", *kindFlag, err)
	}
	return writeUnverifiedActivationStatus(stdout, store, inputs, chain)
}

func readAttachedCanaryTask(path string) ([]byte, error) {
	raw, wire, trusted, err := readTaskBundleWithEmbeddedTrust(path)
	if err != nil {
		return nil, err
	}
	permitRaw, err := decodeCanonicalBase64(
		wire.Permit,
		taskpermit.MaxEnvelopeBytes,
		"task permit",
	)
	if err != nil {
		return nil, err
	}
	payload, keyID, err := dsse.Verify(permitRaw, taskpermit.PayloadType, trusted)
	if err != nil {
		return nil, err
	}
	if keyID != wire.Authority.KeyID {
		return nil, errors.New("task permit key does not match the embedded authority")
	}
	var statement taskpermit.Statement
	if err := dsse.DecodeStrictInto(payload, taskpermit.MaxEnvelopeBytes, &statement); err != nil {
		return nil, fmt.Errorf("decode signed task permit: %w", err)
	}
	notBefore, err := parsePermitTime(statement.NotBefore)
	if err != nil {
		return nil, fmt.Errorf("task permit not_before: %w", err)
	}
	verified, err := decodeTaskBundleRaw(raw, trusted, notBefore, taskpermit.MaxValidity)
	if err != nil {
		return nil, fmt.Errorf("validate historical task bundle: %w", err)
	}
	if _, err := requireLifecycleTaskBundle(verified); err != nil {
		return nil, err
	}
	return raw, nil
}
