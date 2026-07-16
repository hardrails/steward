package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/hardrails/steward/internal/activation"
	"github.com/hardrails/steward/internal/activationstore"
	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/agentrelease"
	"github.com/hardrails/steward/internal/connectorledger"
	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/evidence"
	"github.com/hardrails/steward/internal/executor"
	"github.com/hardrails/steward/internal/gateway"
	"github.com/hardrails/steward/internal/gatewayclient"
	"github.com/hardrails/steward/internal/imageimport"
	"github.com/hardrails/steward/internal/nodeclient"
	"github.com/hardrails/steward/internal/ocibundle"
	"github.com/hardrails/steward/internal/taskpermit"
)

const (
	defaultActivationNodeURL          = "http://127.0.0.1:8090"
	defaultActivationNodeToken        = "/etc/steward/executor-token"
	defaultActivationGatewayConfig    = "/etc/steward/gateway.json"
	defaultActivationDockerSocket     = "/var/run/docker.sock"
	defaultActivationExecutorEvidence = "/var/lib/steward-executor/evidence.bin"

	activationSubmitSchemaV1     = "steward.activation-submit.v1"
	activationTaskStatusSchemaV1 = "steward.task-status.v1"

	activationTaskReceiptRecovered gatewayclient.TaskReceipt = "recovered"
)

type activationGatewayLocal struct {
	config        gateway.Config
	serviceTrust  []byte
	client        *gatewayclient.Client
	receiptPublic ed25519.PublicKey
}

type activationSubmitRecord struct {
	SchemaVersion          string                    `json:"schema_version"`
	TaskDigest             string                    `json:"task_digest"`
	PermitDigest           string                    `json:"permit_digest"`
	RunID                  string                    `json:"run_id"`
	Receipt                gatewayclient.TaskReceipt `json:"receipt"`
	ReceiptNodeID          string                    `json:"receipt_node_id"`
	ReceiptEpoch           uint64                    `json:"receipt_epoch"`
	ReceiptPublicKeyBase64 string                    `json:"receipt_public_key_base64"`
}

func runActivation(arguments []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("activation run", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	directoryFlag := flags.String("dir", "", "owner-only activation workspace")
	publisherPublicPath := flags.String("publisher-public-key", "", "pinned publisher public key")
	publisherKeyID := flags.String("publisher-key-id", "", "publisher DSSE key ID")
	siteRootPublicPath := flags.String("site-root-public-key", "", "pinned site-root public key")
	siteRootKeyID := flags.String("site-root-key-id", "", "site-root DSSE key ID")
	witnessPublicPath := flags.String("witness-public-key", "", "pinned controller witness public key")
	nodeURL := flags.String("node-url", defaultActivationNodeURL, "Executor loopback origin")
	nodeTokenPath := flags.String("node-token-file", defaultActivationNodeToken, "owner-only Executor bearer token")
	gatewayConfigPath := flags.String("gateway-config", defaultActivationGatewayConfig, "trusted local Gateway configuration")
	dockerSocket := flags.String("docker-socket", defaultActivationDockerSocket, "Docker Engine Unix socket")
	executorEvidencePath := flags.String("executor-evidence-log", defaultActivationExecutorEvidence, "local Executor signed evidence log")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *directoryFlag == "" || *nodeURL == "" || *nodeTokenPath == "" ||
		*gatewayConfigPath == "" || *dockerSocket == "" || *executorEvidencePath == "" ||
		flags.NArg() != 0 {
		return errors.New("activation run requires -dir, trust keys, bounded local runtime paths, and no positional arguments")
	}
	directory, err := filepath.Abs(*directoryFlag)
	if err != nil {
		return fmt.Errorf("resolve activation workspace path: %w", err)
	}
	trust, err := loadActivationTrust(
		*publisherKeyID, *publisherPublicPath,
		*siteRootKeyID, *siteRootPublicPath,
		*witnessPublicPath, true,
	)
	if err != nil {
		return err
	}
	store, err := activationstore.Open(directory)
	if err != nil {
		return err
	}
	defer store.Close()

	now := timeNow().UTC()
	_, preliminaryChain, err := loadUnverifiedActivationStateChain(store)
	if err != nil {
		return err
	}
	inputVerificationTime, err := activationInputVerificationTime(
		preliminaryChain, now,
	)
	if err != nil {
		return err
	}
	inputs, err := loadVerifiedActivationInputs(
		store, trust, inputVerificationTime,
	)
	if err != nil {
		return err
	}
	baselineRaw, err := store.Read(
		activationstore.ExecutorBaselineWitnessFileName,
		controlprotocol.MaxExecutorEvidenceJSONBytes,
	)
	if err != nil {
		return fmt.Errorf("read activation baseline witness: %w", err)
	}
	baseline, err := validateBaselineWitness(baselineRaw, trust.witness, inputs.intent.NodeID)
	if err != nil {
		return err
	}
	receiptPublic, err := controlprotocol.VerifyExecutorEvidenceIdentityProofV1(
		baseline.Statement.IdentityProof,
	)
	if err != nil {
		return fmt.Errorf("verify activation Executor receipt identity: %w", err)
	}
	executorEvidenceKeyID := evidence.KeyID(receiptPublic)
	chain, err := loadActivationStateChain(store, inputs)
	if err != nil {
		return err
	}
	if !activationStateChainsEqual(preliminaryChain, chain) {
		return errors.New("activation state changed between bootstrap and verified loading")
	}

	var localGateway *activationGatewayLocal
	loadLiveGateway := func() (activationGatewayLocal, error) {
		if localGateway != nil {
			return *localGateway, nil
		}
		loaded, loadErr := loadActivationGateway(*gatewayConfigPath, inputs)
		if loadErr != nil {
			return activationGatewayLocal{}, fmt.Errorf("preflight Gateway: %w", loadErr)
		}
		if existing, present, readErr := readOptionalActivationArtifact(
			store, activationstore.ServiceTrustFileName, maxServiceTrustBytes,
		); readErr != nil {
			return activationGatewayLocal{}, readErr
		} else if present && !bytes.Equal(existing, loaded.serviceTrust) {
			return activationGatewayLocal{},
				errors.New("current Gateway service policy differs from the activation's retained service trust")
		}
		localGateway = &loaded
		return loaded, nil
	}
	if activationPhaseNeedsGatewayPreflight(chain.latest().Phase) {
		if _, err := loadLiveGateway(); err != nil {
			return err
		}
	}

	for {
		switch chain.latest().Phase {
		case activation.PhaseNew:
			if err := appendActivationStateAt(
				store, &chain, activation.PhaseReleaseVerified, "", "",
				inputVerificationTime,
			); err != nil {
				return err
			}

		case activation.PhaseReleaseVerified:
			ctx, cancel := context.WithTimeout(
				context.Background(),
				time.Duration(inputs.plan.Timeouts.PreflightSeconds)*time.Second,
			)
			preflightErr := preflightActivationArchive(ctx, inputs)
			cancel()
			if preflightErr != nil {
				return preflightErr
			}
			if err := appendActivationState(
				store, &chain, activation.PhasePreflightPassed, "", "",
			); err != nil {
				return err
			}

		case activation.PhasePreflightPassed:
			timeout := time.Duration(inputs.plan.Timeouts.ImageImportSeconds) * time.Second
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			_, importErr := imageimport.Execute(ctx, imageimport.Request{
				ArchivePath:     inputs.archivePath,
				Archive:         inputs.plan.Archive,
				CapsuleEnvelope: inputs.release.CapsuleEnvelope,
				PolicyEnvelope:  inputs.policyRaw,
				SiteRoots: map[string]ed25519.PublicKey{
					trust.siteRootKeyID: trust.siteRoot,
				},
				Now:          timeNow().UTC(),
				DockerSocket: *dockerSocket,
				Timeout:      timeout,
			})
			cancel()
			if importErr != nil {
				return importErr
			}
			if err := appendActivationState(
				store, &chain, activation.PhaseImageImported, "", "",
			); err != nil {
				return err
			}

		case activation.PhaseImageImported:
			admitted, _, err := ensureActivationAdmission(
				store, inputs, chain.latest().Binding,
				*nodeURL, *nodeTokenPath, executorEvidenceKeyID,
			)
			if err != nil {
				return err
			}
			if err := appendActivationState(
				store, &chain, activation.PhaseAdmitted, admitted.RuntimeRef, "",
			); err != nil {
				return err
			}

		case activation.PhaseAdmitted:
			admitted, _, err := readActivationAdmission(
				store, inputs, executorEvidenceKeyID,
			)
			if err != nil {
				return err
			}
			client, err := nodeclient.NewFromTokenFile(*nodeURL, *nodeTokenPath)
			if err != nil {
				return err
			}
			timeout := time.Duration(inputs.plan.Timeouts.StartupSeconds) * time.Second
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			started, startErr := client.Start(ctx, admitted.RuntimeRef)
			cancel()
			if startErr != nil {
				if prerequisite := activationNodePrerequisiteError(startErr); prerequisite != nil {
					return prerequisite
				}
				return startErr
			}
			startedAdmission := permitAdmissionFromNodeState(started)
			if err := validateActivationAdmission(
				startedAdmission, inputs, executorEvidenceKeyID, true,
			); err != nil {
				return fmt.Errorf("validate started activation runtime: %w", err)
			}
			if startedAdmission.RuntimeRef != admitted.RuntimeRef {
				return errors.New("Executor changed the activation runtime reference during start")
			}
			if err := appendActivationState(
				store, &chain, activation.PhaseRunning, admitted.RuntimeRef, "",
			); err != nil {
				return err
			}

		case activation.PhaseRunning:
			admitted, admissionRaw, err := readActivationAdmission(
				store, inputs, executorEvidenceKeyID,
			)
			if err != nil {
				return err
			}
			gatewayLocal, err := loadLiveGateway()
			if err != nil {
				return err
			}
			if _, _, _, err := ensureActivationHandoff(
				store, inputs, admitted, admissionRaw, gatewayLocal.serviceTrust,
			); err != nil {
				return err
			}
			if err := appendActivationState(
				store, &chain, activation.PhaseCanaryChallengeReady,
				admitted.RuntimeRef, "",
			); err != nil {
				return err
			}

		case activation.PhaseCanaryChallengeReady:
			admitted, _, err := readActivationAdmission(
				store, inputs, executorEvidenceKeyID,
			)
			if err != nil {
				return err
			}
			challengeRaw, err := store.Read(
				activationstore.CanaryChallengeFileName, activation.MaxChallengeBytes,
			)
			if err != nil {
				return err
			}
			challenge, err := activation.ParseChallengeV1(challengeRaw)
			if err != nil {
				return err
			}
			taskRaw, present, err := readOptionalActivationArtifact(
				store, activationstore.CanaryTaskFileName, maxTaskBundleBytes,
			)
			if err != nil {
				return err
			}
			if !present {
				return writeActivationStatus(
					stdout, inputs, chain, true, "canary_task",
					activationAttachCanaryTaskCommand, "",
				)
			}
			serviceTrustRaw, err := store.Read(
				activationstore.ServiceTrustFileName, maxServiceTrustBytes,
			)
			if err != nil {
				return err
			}
			requestRaw, err := store.Read(
				activationstore.CanaryRequestFileName, agentrelease.MaxCanaryRequestBytes,
			)
			if err != nil {
				return err
			}
			if _, err := verifyActivationTask(
				taskRaw, challenge, admitted, inputs, serviceTrustRaw, requestRaw,
			); err != nil {
				return markActivationActionRequired(
					store, &chain, stdout, inputs,
					"canary_authorization_invalid", err,
				)
			}
			if err := appendActivationState(
				store, &chain, activation.PhaseCanaryAuthorized,
				admitted.RuntimeRef, "",
			); err != nil {
				return err
			}

		case activation.PhaseCanaryAuthorized:
			admitted, task, err := loadVerifiedActivationTask(
				store, inputs, executorEvidenceKeyID,
			)
			if err != nil {
				return markActivationActionRequired(
					store, &chain, stdout, inputs,
					"canary_authorization_invalid", err,
				)
			}
			gatewayLocal, err := loadLiveGateway()
			if err != nil {
				return err
			}
			canaryDeadline, err := activationCanaryDeadline(
				chain,
				time.Duration(inputs.plan.Timeouts.CanarySeconds)*time.Second,
			)
			if err != nil {
				return err
			}
			if _, err := ensureActivationSubmit(
				store, task, gatewayLocal, canaryDeadline,
				func(at time.Time) error {
					if err := verifyActivationInputsAt(
						store, trust, inputs, at,
					); err != nil {
						return err
					}
					return verifyActivationTaskAt(
						task, at.UTC().Format(time.RFC3339Nano),
					)
				},
			); err != nil {
				var invalid *activationCanaryAuthorizationInvalidError
				if errors.As(err, &invalid) {
					return markActivationActionRequired(
						store, &chain, stdout, inputs,
						"canary_authorization_invalid", err,
					)
				}
				var timeout *activationCanaryTimeoutError
				if errors.As(err, &timeout) {
					return markActivationActionRequired(
						store, &chain, stdout, inputs,
						"canary_timeout", err,
					)
				}
				if activationCanaryFailureIsSticky(err) {
					return markActivationActionRequired(
						store, &chain, stdout, inputs,
						"canary_terminal_failure", err,
					)
				}
				return err
			}
			if err := appendActivationState(
				store, &chain, activation.PhaseCanaryDispatched,
				admitted.RuntimeRef, "",
			); err != nil {
				return err
			}

		case activation.PhaseCanaryDispatched:
			admitted, task, err := loadVerifiedActivationTask(
				store, inputs, executorEvidenceKeyID,
			)
			if err != nil {
				return markActivationActionRequired(
					store, &chain, stdout, inputs,
					"canary_authorization_invalid", err,
				)
			}
			submit, err := readActivationSubmit(store, task)
			if err != nil {
				return err
			}
			_, _, stored, err := readStoredActivationCanaryResult(
				store, inputs, task, submit,
			)
			if err != nil {
				return markActivationActionRequired(
					store, &chain, stdout, inputs,
					"canary_terminal_failure", err,
				)
			}
			if !stored {
				gatewayLocal, loadErr := loadLiveGateway()
				if loadErr != nil {
					return loadErr
				}
				canaryDeadline, deadlineErr := activationCanaryDeadline(
					chain,
					time.Duration(inputs.plan.Timeouts.CanarySeconds)*time.Second,
				)
				if deadlineErr != nil {
					return deadlineErr
				}
				_, _, err = ensureActivationCanaryResult(
					store, inputs, task, submit, gatewayLocal.client,
					canaryDeadline,
				)
			}
			if err != nil {
				var timeout *activationCanaryTimeoutError
				if errors.As(err, &timeout) {
					return markActivationActionRequired(
						store, &chain, stdout, inputs,
						"canary_timeout", err,
					)
				}
				if activationCanaryFailureIsSticky(err) {
					return markActivationActionRequired(
						store, &chain, stdout, inputs,
						"canary_terminal_failure", err,
					)
				}
				return err
			}
			if err := appendActivationState(
				store, &chain, activation.PhaseAgentReportedTerminal,
				admitted.RuntimeRef, "",
			); err != nil {
				return err
			}

		case activation.PhaseAgentReportedTerminal:
			admitted, task, err := loadVerifiedActivationTask(
				store, inputs, executorEvidenceKeyID,
			)
			if err != nil {
				return markActivationActionRequired(
					store, &chain, stdout, inputs,
					"canary_authorization_invalid", err,
				)
			}
			submit, err := readActivationSubmit(store, task)
			if err != nil {
				return err
			}
			resultRaw, _, stored, err := readStoredActivationCanaryResult(
				store, inputs, task, submit,
			)
			if err != nil || !stored {
				if err == nil {
					err = errors.New("activation terminal phase has no retained canary result and status")
				}
				return markActivationActionRequired(
					store, &chain, stdout, inputs,
					"canary_terminal_failure", err,
				)
			}
			ctx, cancel := context.WithTimeout(
				context.Background(),
				time.Duration(inputs.plan.Timeouts.EvidenceSeconds)*time.Second,
			)
			gatewayResult, gatewayPresent, err :=
				readStoredActivationGatewayEvidence(
					ctx, store, task, submit, resultRaw,
				)
			if err == nil && !gatewayPresent {
				gatewayLocal, loadErr := loadLiveGateway()
				if loadErr != nil {
					err = loadErr
				} else {
					gatewayResult, err = collectActivationGatewayEvidence(
						ctx, store, task, submit, resultRaw, gatewayLocal,
					)
				}
			}
			if err == nil {
				err = verifyActivationTaskAt(task, gatewayResult.AuthorizedAt)
			}
			if err == nil {
				err = verifyActivationInputsAtSignedTime(
					store, trust, inputs, gatewayResult.AuthorizedAt,
				)
			}
			var checkpointRaw []byte
			var beginDigest string
			var checkpointDigest string
			if err == nil {
				beginDigest, err = verifyStoredActivationExecutorBegin(
					store, inputs, chain.latest().Binding, admitted,
				)
			}
			if err == nil {
				checkpointRaw, checkpointDigest, err =
					ensureActivationExecutorCheckpoint(
						ctx, store, inputs, chain.latest().Binding,
						admitted, gatewayResult, *nodeURL, *nodeTokenPath,
					)
			}
			if err == nil {
				finalWitnessRaw, present, readErr := readOptionalActivationArtifact(
					store,
					activationstore.ExecutorFinalWitnessFileName,
					controlprotocol.MaxExecutorEvidenceJSONBytes,
				)
				if readErr != nil {
					err = readErr
				} else if !present {
					cancel()
					return writeActivationStatus(
						stdout, inputs, chain, true, "final_witness",
						activationAttachWitnessCommand, "",
					)
				} else {
					var executorResult activation.ExecutorEvidenceResultV1
					executorResult, err = ensureActivationExecutorEvidence(
						ctx, store, inputs, chain.latest().Binding, admitted,
						baselineRaw, finalWitnessRaw, checkpointRaw,
						beginDigest, checkpointDigest,
						trust.witness, *executorEvidencePath,
					)
					if err == nil &&
						(executorResult.Coordinate.Sequence == 0 ||
							gatewayResult.Coordinate.Sequence == 0) {
						err = errors.New("activation evidence collection returned an empty coordinate")
					}
				}
			}
			cancel()
			if err != nil {
				var invalid *activationRetainedEvidenceInvalidError
				var conflict *activationArtifactConflictError
				if errors.As(err, &invalid) || errors.As(err, &conflict) {
					return markActivationActionRequired(
						store, &chain, stdout, inputs,
						"evidence_invalid", err,
					)
				}
				return err
			}
			if err := appendActivationState(
				store, &chain, activation.PhaseEvidenceCollected,
				admitted.RuntimeRef, "",
			); err != nil {
				return err
			}

		case activation.PhaseEvidenceCollected:
			admitted, task, err := loadVerifiedActivationTask(
				store, inputs, executorEvidenceKeyID,
			)
			if err != nil {
				return err
			}
			submit, err := readActivationSubmit(store, task)
			if err != nil {
				return err
			}
			resultRaw, err := store.Read(
				activationstore.CanaryResultFileName, activation.MaxCanaryResultBytes,
			)
			if err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(
				context.Background(),
				time.Duration(inputs.plan.Timeouts.EvidenceSeconds)*time.Second,
			)
			gatewayResult, err := verifyStoredActivationGatewayEvidence(
				ctx, store, task, submit, resultRaw,
			)
			if err == nil {
				err = verifyActivationTaskAt(task, gatewayResult.AuthorizedAt)
			}
			if err == nil {
				err = verifyActivationInputsAtSignedTime(
					store, trust, inputs, gatewayResult.AuthorizedAt,
				)
			}
			var checkpointDigest string
			var beginDigest string
			if err == nil {
				beginDigest, err = verifyStoredActivationExecutorBegin(
					store, inputs, chain.latest().Binding, admitted,
				)
			}
			if err == nil {
				checkpointDigest, err = verifyStoredActivationExecutorCheckpoint(
					store, inputs, chain.latest().Binding, admitted, gatewayResult,
				)
			}
			var executorResult activation.ExecutorEvidenceResultV1
			if err == nil {
				executorResult, err = verifyStoredActivationExecutorEvidence(
					ctx, store, inputs, chain.latest().Binding, admitted,
					beginDigest, checkpointDigest, trust.witness,
				)
			}
			cancel()
			if err != nil {
				var invalid *activationRetainedEvidenceInvalidError
				if errors.As(err, &invalid) {
					return markActivationActionRequired(
						store, &chain, stdout, inputs,
						"evidence_invalid", err,
					)
				}
				return err
			}
			proofRaw, err := finalizeActivationProof(
				store, &chain, inputs, beginDigest, checkpointDigest,
				executorResult, gatewayResult,
			)
			if err != nil {
				var invalid *activationRetainedEvidenceInvalidError
				var conflict *activationArtifactConflictError
				if errors.As(err, &invalid) || errors.As(err, &conflict) {
					return markActivationActionRequired(
						store, &chain, stdout, inputs,
						"evidence_invalid", err,
					)
				}
				return err
			}
			proofDigest, err := activation.ProofDigestV1(proofRaw)
			if err != nil {
				return err
			}
			return writeActivationStatus(
				stdout, inputs, chain, true, "", "", proofDigest,
			)

		case activation.PhasePassed:
			proofRaw, err := store.Read(
				activationstore.ProofFileName, activation.MaxProofBytes,
			)
			if err != nil {
				return err
			}
			if _, err := activation.CorrelateProofV1(
				inputs.planRaw, chain.latestRaw(), proofRaw,
			); err != nil {
				return err
			}
			proofDigest, err := activation.ProofDigestV1(proofRaw)
			if err != nil {
				return err
			}
			return writeActivationStatus(
				stdout, inputs, chain, false, "", "", proofDigest,
			)

		case activation.PhaseActionRequired:
			return writeActivationStatus(
				stdout, inputs, chain, false, "operator",
				activationReplaceFailedCommand(chain.latest().Binding.Generation), "",
			)

		default:
			return fmt.Errorf("unsupported activation phase %q", chain.latest().Phase)
		}
	}
}

func preflightActivationArchive(
	ctx context.Context,
	inputs verifiedActivationInputs,
) error {
	expected := ocibundle.Identity{
		ManifestDigest: inputs.release.Release.Archive.Image.ManifestDigest,
		ConfigDigest:   inputs.release.Release.Archive.Image.ConfigDigest,
		Platform: ocibundle.Platform{
			OS:           inputs.release.Release.Archive.Image.Platform.OS,
			Architecture: inputs.release.Release.Archive.Image.Platform.Architecture,
			Variant:      inputs.release.Release.Archive.Image.Platform.Variant,
		},
	}
	prepared, err := ocibundle.PrepareBoundContext(
		ctx, inputs.archivePath, expected, inputs.plan.Archive,
		ocibundle.DefaultLimits(),
	)
	if err != nil {
		return fmt.Errorf("preflight activation archive: %w", err)
	}
	if err := prepared.Close(); err != nil {
		return fmt.Errorf("close preflight activation archive: %w", err)
	}
	return nil
}

func loadActivationGateway(
	configPath string,
	inputs verifiedActivationInputs,
) (activationGatewayLocal, error) {
	config, _, _, token, err := gateway.LoadConfig(configPath)
	if err != nil {
		return activationGatewayLocal{}, err
	}
	var trust bytes.Buffer
	if err := writeServiceTrustInventory(
		&trust, config, inputs.intent.NodeID, inputs.intent.TenantID,
	); err != nil {
		return activationGatewayLocal{}, err
	}
	operation, err := decodeServiceTrust(
		trust.Bytes(), inputs.intent, agentrelease.HermesOperationID,
	)
	if err != nil {
		return activationGatewayLocal{}, err
	}
	if operation.ServiceID != agentrelease.HermesServiceID ||
		operation.TaskProtocol != connectorledger.TaskProtocolLifecycleV1 ||
		int64(agentrelease.MaxCanaryRequestBytes) > operation.MaxRequestBytes {
		return activationGatewayLocal{}, errors.New("Gateway does not expose the bounded Hermes lifecycle canary operation")
	}
	client, err := gatewayclient.New("http://"+config.ServiceAddress, token)
	if err != nil {
		return activationGatewayLocal{}, err
	}
	private, err := connectorledger.ReadPrivateKey(config.ConnectorReceiptKeyFile)
	if err != nil {
		return activationGatewayLocal{}, fmt.Errorf("read Gateway receipt key: %w", err)
	}
	public, ok := private.Public().(ed25519.PublicKey)
	if !ok {
		return activationGatewayLocal{}, errors.New("Gateway receipt key has no Ed25519 public key")
	}
	return activationGatewayLocal{
		config: config, serviceTrust: append([]byte(nil), trust.Bytes()...),
		client:        client,
		receiptPublic: append(ed25519.PublicKey(nil), public...),
	}, nil
}

func activationPhaseNeedsGatewayPreflight(phase string) bool {
	switch phase {
	case activation.PhaseNew,
		activation.PhaseReleaseVerified,
		activation.PhasePreflightPassed,
		activation.PhaseImageImported,
		activation.PhaseAdmitted,
		activation.PhaseRunning:
		return true
	default:
		return false
	}
}

func ensureActivationAdmission(
	store *activationstore.Store,
	inputs verifiedActivationInputs,
	binding activation.BindingV1,
	nodeURL, tokenPath, expectedEvidenceKeyID string,
) (permitAdmission, []byte, error) {
	if existing, present, err := readOptionalActivationArtifact(
		store, activationstore.AdmissionFileName, maxArtifactBytes,
	); err != nil {
		return permitAdmission{}, nil, err
	} else if present {
		admitted, err := parseActivationAdmission(
			existing, inputs, expectedEvidenceKeyID, false,
		)
		return admitted, existing, err
	}
	client, err := nodeclient.NewFromTokenFile(nodeURL, tokenPath)
	if err != nil {
		return permitAdmission{}, nil, err
	}
	beginRaw, err := activation.MarshalExecutorBeginV1(
		binding,
		executor.RuntimeRef(inputs.intent.TenantID, inputs.intent.InstanceID),
		executor.StateVolumeName(inputs.intent.TenantID, inputs.intent.LineageID),
		inputs.release.CapsuleEnvelopeDigest,
	)
	if err != nil {
		return permitAdmission{}, nil, err
	}
	beginDigest, err := activation.ExecutorBeginDigestV1(beginRaw)
	if err != nil {
		return permitAdmission{}, nil, err
	}
	if err := writeActivationArtifact(
		store, activationstore.ExecutorBeginFileName, beginRaw, false,
	); err != nil {
		return permitAdmission{}, nil, err
	}
	timeout := time.Duration(inputs.plan.Timeouts.AdmissionSeconds) * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	runtimeReference := executor.RuntimeRef(
		inputs.intent.TenantID, inputs.intent.InstanceID,
	)
	state, recovered, err := recoverActivationAdmissionState(
		ctx, client, runtimeReference,
		inputs.plan.ActivationID, beginDigest,
	)
	if err != nil {
		return permitAdmission{}, nil, err
	}
	if !recovered {
		var admitErr error
		state, admitErr = client.AdmitActivation(
			ctx, inputs.release.CapsuleEnvelope, inputs.intent,
			inputs.plan.ActivationID, beginDigest,
		)
		if admitErr != nil {
			if prerequisite := activationNodePrerequisiteError(admitErr); prerequisite != nil {
				return permitAdmission{}, nil, prerequisite
			}
			if !activationAdmissionRecoveryAllowed(ctx, admitErr) {
				return permitAdmission{}, nil, admitErr
			}
			state, recovered, err = recoverActivationAdmissionState(
				ctx, client, runtimeReference,
				inputs.plan.ActivationID, beginDigest,
			)
			if err != nil || !recovered {
				return permitAdmission{}, nil, admitErr
			}
		}
	}
	admitted := permitAdmissionFromNodeState(state)
	if err := validateActivationAdmission(
		admitted, inputs, expectedEvidenceKeyID, false,
	); err != nil {
		return permitAdmission{}, nil, fmt.Errorf("validate activation admission: %w", err)
	}
	raw, err := json.Marshal(admitted)
	if err != nil {
		return permitAdmission{}, nil, err
	}
	if err := writeActivationArtifact(
		store, activationstore.AdmissionFileName, raw, false,
	); err != nil {
		return permitAdmission{}, nil, err
	}
	return admitted, raw, nil
}

func recoverActivationAdmissionState(
	ctx context.Context,
	client *nodeclient.Client,
	runtimeReference, activationID, beginDigest string,
) (nodeclient.State, bool, error) {
	state, err := client.Status(ctx, runtimeReference)
	if err != nil {
		var apiErr *nodeclient.APIError
		if errors.As(err, &apiErr) && apiErr.Status == http.StatusNotFound {
			return nodeclient.State{}, false, nil
		}
		return nodeclient.State{}, false, err
	}
	if err := validateActivationNodeIdentity(
		state, activationID, beginDigest,
	); err != nil {
		return nodeclient.State{}, true, err
	}
	return state, true, nil
}

func activationAdmissionRecoveryAllowed(
	ctx context.Context,
	admitErr error,
) bool {
	var apiErr *nodeclient.APIError
	return admitErr != nil && !errors.As(admitErr, &apiErr) && ctx.Err() == nil
}

func activationNodePrerequisiteError(cause error) error {
	var apiErr *nodeclient.APIError
	if !errors.As(cause, &apiErr) {
		return nil
	}
	switch {
	case apiErr.Code == "tenant_identity_required" ||
		apiErr.Code == "signed_lifecycle_required":
		return fmt.Errorf(
			"node-local activation requires Executor -admission-allow-host-admin-intent on its one-tenant dedicated host: %w",
			cause,
		)
	case apiErr.Code == "capability_unavailable" &&
		strings.Contains(apiErr.Message, "persistent state"):
		return fmt.Errorf(
			"Hermes activation requires Executor -allow-unquotaed-state-on-dedicated-host; do not enable it on a shared host: %w",
			cause,
		)
	default:
		return nil
	}
}

func validateActivationNodeIdentity(
	state nodeclient.State,
	activationID, beginDigest string,
) error {
	if state.ActivationID != activationID ||
		state.ActivationBeginDigest != beginDigest {
		return errors.New("Executor runtime does not match the exact activation admission identity")
	}
	return nil
}

func readActivationAdmission(
	store *activationstore.Store,
	inputs verifiedActivationInputs,
	expectedEvidenceKeyID string,
) (permitAdmission, []byte, error) {
	raw, err := store.Read(activationstore.AdmissionFileName, maxArtifactBytes)
	if err != nil {
		return permitAdmission{}, nil, err
	}
	admitted, err := parseActivationAdmission(
		raw, inputs, expectedEvidenceKeyID, false,
	)
	return admitted, raw, err
}

func parseActivationAdmission(
	raw []byte,
	inputs verifiedActivationInputs,
	expectedEvidenceKeyID string,
	requireRunning bool,
) (permitAdmission, error) {
	var admitted permitAdmission
	if err := dsse.DecodeStrictInto(raw, maxArtifactBytes, &admitted); err != nil {
		return permitAdmission{}, fmt.Errorf("decode activation admission: %w", err)
	}
	if err := validateActivationAdmission(
		admitted, inputs, expectedEvidenceKeyID, requireRunning,
	); err != nil {
		return permitAdmission{}, err
	}
	return admitted, nil
}

func permitAdmissionFromNodeState(state nodeclient.State) permitAdmission {
	authorities := make([]gateway.TaskAuthority, len(state.TaskAuthorities))
	for index, authority := range state.TaskAuthorities {
		authorities[index] = gateway.TaskAuthority{
			KeyID: authority.KeyID, PublicKey: authority.PublicKey,
		}
	}
	return permitAdmission{
		RuntimeRef: state.RuntimeRef, Status: state.Status,
		CapsuleDigest: state.CapsuleDigest, PolicyDigest: state.PolicyDigest,
		Generation: state.Generation, EvidenceKeyID: state.EvidenceKeyID,
		GrantID: state.GrantID, ServicePath: state.ServicePath,
		ServiceID: state.ServiceID, TaskAuthorities: authorities,
		EgressProxy:       state.EgressProxy,
		EgressRouteIDs:    append([]string(nil), state.EgressRouteIDs...),
		ConnectorURL:      state.ConnectorURL,
		ConnectorIDs:      append([]string(nil), state.ConnectorIDs...),
		RoutePolicyDigest: state.RoutePolicyDigest,
	}
}

func validateActivationAdmission(
	admitted permitAdmission,
	inputs verifiedActivationInputs,
	expectedEvidenceKeyID string,
	requireRunning bool,
) error {
	statusOK := admitted.Status == "created" || admitted.Status == "running"
	if requireRunning {
		statusOK = admitted.Status == "running"
	}
	if !statusOK || !activationRuntimeRef(admitted.RuntimeRef) ||
		admitted.CapsuleDigest != inputs.effective.CapsuleDigest ||
		admitted.PolicyDigest != inputs.effective.PolicyDigest ||
		admitted.Generation != inputs.intent.Generation ||
		admitted.EvidenceKeyID != expectedEvidenceKeyID ||
		admitted.GrantID != gateway.GrantID(
			inputs.intent.TenantID, inputs.intent.InstanceID, inputs.intent.Generation,
		) ||
		admitted.ServicePath != "/v1/services/"+admitted.GrantID+"/" ||
		admitted.ServiceID != agentrelease.HermesServiceID ||
		!canonicalActivationRunDigest(admitted.RoutePolicyDigest) {
		return errors.New("Executor admission does not match the exact activation identity and service grant")
	}
	trusted, err := inputs.effective.SitePolicy.TrustedTaskKeys(
		inputs.intent.TenantID, inputs.intent.ServiceID,
	)
	if err != nil {
		return err
	}
	keyIDs := make([]string, 0, len(trusted))
	for keyID := range trusted {
		keyIDs = append(keyIDs, keyID)
	}
	sort.Strings(keyIDs)
	expectedAuthorities := make([]gateway.TaskAuthority, 0, len(keyIDs))
	for _, keyID := range keyIDs {
		expectedAuthorities = append(expectedAuthorities, gateway.TaskAuthority{
			KeyID:     keyID,
			PublicKey: base64.StdEncoding.EncodeToString(trusted[keyID]),
		})
	}
	if len(expectedAuthorities) == 0 ||
		!slices.Equal(admitted.TaskAuthorities, expectedAuthorities) {
		return errors.New("Executor admission changed the signed tenant task-authority set")
	}
	if inputs.intent.Capabilities.Egress {
		if admitted.EgressProxy != "http://steward-relay:8082" ||
			!slices.Equal(
				admitted.EgressRouteIDs,
				admission.CanonicalRouteIDs(inputs.effective.Intent.EgressRouteIDs),
			) {
			return errors.New("Executor admission changed the requested egress grant")
		}
	} else if admitted.EgressProxy != "" || len(admitted.EgressRouteIDs) != 0 {
		return errors.New("Executor admission returned unrequested egress authority")
	}
	if inputs.intent.Capabilities.Connector {
		if admitted.ConnectorURL != "http://steward-relay:8081" ||
			!slices.Equal(
				admitted.ConnectorIDs,
				admission.CanonicalConnectorIDs(inputs.effective.Intent.ConnectorIDs),
			) {
			return errors.New("Executor admission changed the requested connector grant")
		}
	} else if admitted.ConnectorURL != "" || len(admitted.ConnectorIDs) != 0 {
		return errors.New("Executor admission returned unrequested connector authority")
	}
	return nil
}

func activationRuntimeRef(value string) bool {
	const prefix = "executor-"
	return strings.HasPrefix(value, prefix) &&
		len(value) == len(prefix)+64 &&
		canonicalActivationRunHex(strings.TrimPrefix(value, prefix))
}

func canonicalActivationRunDigest(value string) bool {
	const prefix = "sha256:"
	return strings.HasPrefix(value, prefix) &&
		len(value) == len(prefix)+64 &&
		canonicalActivationRunHex(strings.TrimPrefix(value, prefix))
}

func canonicalActivationRunHex(value string) bool {
	for index := range value {
		if value[index] < '0' ||
			value[index] > '9' && value[index] < 'a' ||
			value[index] > 'f' {
			return false
		}
	}
	return value != ""
}

func ensureActivationHandoff(
	store *activationstore.Store,
	inputs verifiedActivationInputs,
	admitted permitAdmission,
	admissionRaw, serviceTrustRaw []byte,
) ([]byte, []byte, activation.CanaryChallengeV1, error) {
	if err := writeActivationArtifact(
		store, activationstore.ServiceTrustFileName, serviceTrustRaw, true,
	); err != nil {
		return nil, nil, activation.CanaryChallengeV1{}, err
	}
	requestRaw, err := agentrelease.BuildCanaryRequest(
		inputs.release.Release.Canary.Request, inputs.plan.ActivationID,
	)
	if err != nil {
		return nil, nil, activation.CanaryChallengeV1{}, err
	}
	if err := writeActivationArtifact(
		store, activationstore.CanaryRequestFileName, requestRaw, false,
	); err != nil {
		return nil, nil, activation.CanaryChallengeV1{}, err
	}
	authorities, err := activationTaskAuthorities(admitted)
	if err != nil {
		return nil, nil, activation.CanaryChallengeV1{}, err
	}
	challenge := activation.CanaryChallengeV1{
		SchemaVersion:      activation.ChallengeSchemaV1,
		ActivationID:       inputs.plan.ActivationID,
		PlanDigest:         dsse.Digest(inputs.planRaw),
		ReleaseDigest:      inputs.release.EnvelopeDigest,
		AdmissionDigest:    dsse.Digest(admissionRaw),
		IntentDigest:       dsse.Digest(inputs.intentRaw),
		ServiceTrustDigest: dsse.Digest(serviceTrustRaw),
		RequestDigest:      taskpermit.RequestDigest(requestRaw),
		TenantID:           inputs.intent.TenantID, NodeID: inputs.intent.NodeID,
		InstanceID: inputs.intent.InstanceID, RuntimeRef: admitted.RuntimeRef,
		Generation: inputs.intent.Generation, GrantID: admitted.GrantID,
		ServiceID:       agentrelease.HermesServiceID,
		OperationID:     agentrelease.HermesOperationID,
		TaskAuthorities: authorities,
	}
	existing, present, err := readOptionalActivationArtifact(
		store, activationstore.CanaryChallengeFileName, activation.MaxChallengeBytes,
	)
	if err != nil {
		return nil, nil, activation.CanaryChallengeV1{}, err
	}
	if present {
		parsed, err := activation.ParseChallengeV1(existing)
		if err != nil {
			return nil, nil, activation.CanaryChallengeV1{}, err
		}
		challenge.CreatedAt = parsed.CreatedAt
		expected, err := activation.MarshalChallengeV1(challenge)
		if err != nil {
			return nil, nil, activation.CanaryChallengeV1{}, err
		}
		if !bytes.Equal(existing, expected) {
			return nil, nil, activation.CanaryChallengeV1{},
				errors.New("retained activation challenge does not match the exact admitted canary")
		}
		return requestRaw, existing, parsed, nil
	}
	challenge.CreatedAt = timeNow().UTC().Format(time.RFC3339Nano)
	challengeRaw, err := activation.MarshalChallengeV1(challenge)
	if err != nil {
		return nil, nil, activation.CanaryChallengeV1{}, err
	}
	if err := writeActivationArtifact(
		store, activationstore.CanaryChallengeFileName, challengeRaw, false,
	); err != nil {
		return nil, nil, activation.CanaryChallengeV1{}, err
	}
	return requestRaw, challengeRaw, challenge, nil
}

func loadVerifiedActivationTask(
	store *activationstore.Store,
	inputs verifiedActivationInputs,
	expectedEvidenceKeyID string,
) (permitAdmission, verifiedTaskBundle, error) {
	admitted, _, err := readActivationAdmission(
		store, inputs, expectedEvidenceKeyID,
	)
	if err != nil {
		return permitAdmission{}, verifiedTaskBundle{}, err
	}
	challengeRaw, err := store.Read(
		activationstore.CanaryChallengeFileName, activation.MaxChallengeBytes,
	)
	if err != nil {
		return permitAdmission{}, verifiedTaskBundle{}, err
	}
	challenge, err := activation.ParseChallengeV1(challengeRaw)
	if err != nil {
		return permitAdmission{}, verifiedTaskBundle{}, err
	}
	taskRaw, err := store.Read(
		activationstore.CanaryTaskFileName, maxTaskBundleBytes,
	)
	if err != nil {
		return permitAdmission{}, verifiedTaskBundle{}, err
	}
	serviceTrustRaw, err := store.Read(
		activationstore.ServiceTrustFileName, maxServiceTrustBytes,
	)
	if err != nil {
		return permitAdmission{}, verifiedTaskBundle{}, err
	}
	requestRaw, err := store.Read(
		activationstore.CanaryRequestFileName, agentrelease.MaxCanaryRequestBytes,
	)
	if err != nil {
		return permitAdmission{}, verifiedTaskBundle{}, err
	}
	task, err := verifyActivationTask(
		taskRaw, challenge, admitted, inputs, serviceTrustRaw, requestRaw,
	)
	return admitted, task, err
}

func ensureActivationSubmit(
	store *activationstore.Store,
	task verifiedTaskBundle,
	local activationGatewayLocal,
	deadline time.Time,
	validateAuthorization func(time.Time) error,
) (activationSubmitRecord, error) {
	retainedStatus, statusPresent, err := readRetainedActivationTerminalStatus(
		store, task,
	)
	if err != nil {
		return activationSubmitRecord{},
			&activationCanaryRetainedInvalidError{cause: err}
	}
	raw, submitPresent, err := readOptionalActivationArtifact(
		store, activationstore.CanarySubmitFileName, maxArtifactBytes,
	)
	if err != nil {
		return activationSubmitRecord{}, err
	}
	if statusPresent && retainedStatus.State !=
		string(gatewayclient.AgentReportedCompleted) {
		return activationSubmitRecord{}, &activationCanaryTerminalError{
			state: retainedStatus.State,
			code:  retainedStatus.ErrorCode,
		}
	}
	if submitPresent {
		record, err := parseActivationSubmit(raw, task)
		if err != nil {
			return activationSubmitRecord{},
				&activationCanaryRetainedInvalidError{cause: err}
		}
		if err := activationGatewayMatchesSubmit(local, record, task); err != nil {
			return activationSubmitRecord{},
				&activationCanaryRetainedInvalidError{cause: err}
		}
		if statusPresent && retainedStatus.RunID != record.RunID {
			return activationSubmitRecord{},
				&activationCanaryRetainedInvalidError{
					cause: errors.New("retained activation terminal status and submit record have different run IDs"),
				}
		}
		return record, nil
	}
	if statusPresent {
		return storeRecoveredActivationSubmit(
			store, task, local, retainedStatus.RunID,
		)
	}
	ctx, cancel, err := activationCanaryContext(deadline)
	if err != nil {
		return activationSubmitRecord{}, err
	}
	defer cancel()
	if validateAuthorization == nil {
		return activationSubmitRecord{},
			&activationCanaryAuthorizationInvalidError{
				cause: errors.New("current canary authorization validator is unavailable"),
			}
	}
	authorizationTime := timeNow().UTC()
	if err := validateAuthorization(authorizationTime); err != nil {
		return activationSubmitRecord{},
			&activationCanaryAuthorizationInvalidError{cause: err}
	}
	result, err := local.client.Submit(ctx, gatewayclient.TaskSubmission{
		ServicePath:   task.Bundle.ServicePath,
		OperationPath: task.Bundle.Operation.Path,
		ContentType:   task.Bundle.Operation.ContentType,
		Request:       task.Request, Permit: task.Permit,
	})
	if err != nil {
		statement := task.Verified.Statement
		taskDigest := taskpermit.TaskDigest(
			statement.TenantID, statement.InstanceID, statement.TaskID,
		)
		status, statusErr := local.client.Status(
			ctx, taskDigest, task.Verified.EnvelopeDigest,
		)
		if statusErr == nil {
			switch {
			case status.Phase == gatewayclient.PhaseDispatch:
				return storeRecoveredActivationSubmit(
					store, task, local, status.RunID,
				)
			case status.Phase == gatewayclient.PhaseTerminal &&
				status.State == string(gatewayclient.AgentReportedCompleted):
				if err := storeActivationTerminalStatus(store, status); err != nil {
					return activationSubmitRecord{}, err
				}
				return storeRecoveredActivationSubmit(
					store, task, local, status.RunID,
				)
			case status.Phase == gatewayclient.PhaseTerminal:
				return activationSubmitRecord{}, activationTerminalStatusError(
					store, status, "",
				)
			}
		}
		var apiError *gatewayclient.APIError
		if errors.As(err, &apiError) &&
			terminalActivationSubmitCode(apiError.Code) {
			return activationSubmitRecord{}, &activationCanaryTerminalError{
				state: "submit_rejected",
				code:  apiError.Code,
			}
		}
		if errors.Is(err, context.DeadlineExceeded) ||
			errors.Is(statusErr, context.DeadlineExceeded) ||
			errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return activationSubmitRecord{},
				&activationCanaryTimeoutError{deadline: deadline}
		}
		return activationSubmitRecord{}, err
	}
	record := newActivationSubmitRecord(
		task, local, result.RunID, result.Receipt,
	)
	return storeActivationSubmit(store, record)
}

func storeRecoveredActivationSubmit(
	store *activationstore.Store,
	task verifiedTaskBundle,
	local activationGatewayLocal,
	runID string,
) (activationSubmitRecord, error) {
	record := newActivationSubmitRecord(
		task, local, runID, activationTaskReceiptRecovered,
	)
	return storeActivationSubmit(store, record)
}

func newActivationSubmitRecord(
	task verifiedTaskBundle,
	local activationGatewayLocal,
	runID string,
	receipt gatewayclient.TaskReceipt,
) activationSubmitRecord {
	statement := task.Verified.Statement
	return activationSubmitRecord{
		SchemaVersion: activationSubmitSchemaV1,
		TaskDigest: taskpermit.TaskDigest(
			statement.TenantID, statement.InstanceID, statement.TaskID,
		),
		PermitDigest: task.Verified.EnvelopeDigest,
		RunID:        runID,
		Receipt:      receipt,
		ReceiptNodeID: gateway.ServiceTaskReceiptNodeID(
			statement.NodeID,
		),
		ReceiptEpoch: local.config.ConnectorReceiptEpoch,
		ReceiptPublicKeyBase64: base64.StdEncoding.EncodeToString(
			local.receiptPublic,
		),
	}
}

func storeActivationSubmit(
	store *activationstore.Store,
	record activationSubmitRecord,
) (activationSubmitRecord, error) {
	raw, err := json.Marshal(record)
	if err != nil {
		return activationSubmitRecord{}, err
	}
	if err := writeActivationArtifact(
		store, activationstore.CanarySubmitFileName, raw, false,
	); err != nil {
		return activationSubmitRecord{}, err
	}
	return record, nil
}

func readActivationSubmit(
	store *activationstore.Store,
	task verifiedTaskBundle,
) (activationSubmitRecord, error) {
	raw, err := store.Read(activationstore.CanarySubmitFileName, maxArtifactBytes)
	if err != nil {
		return activationSubmitRecord{}, err
	}
	return parseActivationSubmit(raw, task)
}

func parseActivationSubmit(
	raw []byte,
	task verifiedTaskBundle,
) (activationSubmitRecord, error) {
	var record activationSubmitRecord
	if err := dsse.DecodeStrictInto(raw, maxArtifactBytes, &record); err != nil {
		return activationSubmitRecord{}, err
	}
	statement := task.Verified.Statement
	if record.SchemaVersion != activationSubmitSchemaV1 ||
		record.TaskDigest != taskpermit.TaskDigest(
			statement.TenantID, statement.InstanceID, statement.TaskID,
		) ||
		record.PermitDigest != task.Verified.EnvelopeDigest ||
		!taskIdentifier(record.RunID) ||
		record.Receipt != gatewayclient.TaskReceiptRecorded &&
			record.Receipt != gatewayclient.TaskReceiptReplayed &&
			record.Receipt != activationTaskReceiptRecovered ||
		record.ReceiptNodeID != gateway.ServiceTaskReceiptNodeID(statement.NodeID) ||
		record.ReceiptEpoch == 0 {
		return activationSubmitRecord{}, errors.New("activation submit record does not match the verified task")
	}
	if _, err := activationSubmitReceiptPublicKey(record); err != nil {
		return activationSubmitRecord{}, err
	}
	canonical, err := json.Marshal(record)
	if err != nil || !bytes.Equal(canonical, raw) {
		return activationSubmitRecord{}, errors.New("activation submit record is not canonical JSON")
	}
	return record, nil
}

func activationSubmitReceiptPublicKey(
	record activationSubmitRecord,
) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(record.ReceiptPublicKeyBase64)
	if err != nil || len(raw) != ed25519.PublicKeySize ||
		base64.StdEncoding.EncodeToString(raw) != record.ReceiptPublicKeyBase64 {
		return nil, errors.New("activation submit record has an invalid Gateway receipt public key")
	}
	return append(ed25519.PublicKey(nil), raw...), nil
}

func activationGatewayMatchesSubmit(
	local activationGatewayLocal,
	record activationSubmitRecord,
	task verifiedTaskBundle,
) error {
	public, err := activationSubmitReceiptPublicKey(record)
	if err != nil {
		return err
	}
	if record.ReceiptNodeID !=
		gateway.ServiceTaskReceiptNodeID(task.Verified.Statement.NodeID) ||
		record.ReceiptEpoch != local.config.ConnectorReceiptEpoch ||
		!bytes.Equal(public, local.receiptPublic) {
		return errors.New("current Gateway receipt identity differs from the dispatched activation")
	}
	return nil
}

type activationCanaryTerminalError struct {
	state string
	code  string
}

func (err *activationCanaryTerminalError) Error() string {
	if err.code != "" {
		return "Hermes canary ended in terminal state " + err.state +
			" (" + err.code + ")"
	}
	return "Hermes canary ended in terminal state " + err.state
}

type activationCanaryRetainedInvalidError struct {
	cause error
}

func (err *activationCanaryRetainedInvalidError) Error() string {
	return "retained canary state is invalid: " + err.cause.Error()
}

func (err *activationCanaryRetainedInvalidError) Unwrap() error {
	return err.cause
}

type activationCanaryAuthorizationInvalidError struct {
	cause error
}

func (err *activationCanaryAuthorizationInvalidError) Error() string {
	return "canary authorization is not currently valid: " + err.cause.Error()
}

func (err *activationCanaryAuthorizationInvalidError) Unwrap() error {
	return err.cause
}

type activationCanaryTimeoutError struct {
	deadline time.Time
}

func (err *activationCanaryTimeoutError) Error() string {
	return "Hermes canary exceeded its activation-wide deadline " +
		err.deadline.UTC().Format(time.RFC3339Nano)
}

func activationCanaryFailureIsSticky(err error) bool {
	var terminal *activationCanaryTerminalError
	var retained *activationCanaryRetainedInvalidError
	var conflict *activationArtifactConflictError
	return errors.As(err, &terminal) ||
		errors.As(err, &retained) ||
		errors.As(err, &conflict)
}

func activationCanaryDeadline(
	chain activationStateChain,
	timeout time.Duration,
) (time.Time, error) {
	if timeout <= 0 {
		return time.Time{}, errors.New("activation canary timeout must be positive")
	}
	authorizedAtRaw, err := chain.phaseTime(activation.PhaseCanaryAuthorized)
	if err != nil {
		return time.Time{}, err
	}
	authorizedAt, err := canonicalActivationTime(authorizedAtRaw)
	if err != nil {
		return time.Time{}, fmt.Errorf(
			"parse canary authorization checkpoint time: %w", err,
		)
	}
	deadline := authorizedAt.Add(timeout)
	if !deadline.After(authorizedAt) {
		return time.Time{}, errors.New("activation canary deadline overflowed")
	}
	return deadline, nil
}

func activationCanaryContext(
	deadline time.Time,
) (context.Context, context.CancelFunc, error) {
	if deadline.IsZero() {
		return nil, nil, errors.New("activation canary deadline is unavailable")
	}
	ctx, cancel := context.WithDeadline(context.Background(), deadline.UTC())
	if err := ctx.Err(); err != nil {
		cancel()
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, nil, &activationCanaryTimeoutError{
				deadline: deadline,
			}
		}
		return nil, nil, err
	}
	return ctx, cancel, nil
}

func terminalActivationSubmitCode(code string) bool {
	switch code {
	case "task_permit_denied", "permit_expired", "grant_revoked",
		"task_already_spent", "task_id_conflict", "run_id_conflict",
		"outcome_unknown", "service_task_rejected", "redirect_denied":
		return true
	default:
		return false
	}
}

func activationTerminalStatusError(
	store *activationstore.Store,
	status gatewayclient.TaskLifecycleStatus,
	code string,
) error {
	if code == "" {
		code = status.ErrorCode
	}
	terminal := &activationCanaryTerminalError{
		state: status.State,
		code:  code,
	}
	if status.Phase != gatewayclient.PhaseTerminal {
		return terminal
	}
	if err := storeActivationTerminalStatus(store, status); err != nil {
		return errors.Join(terminal, err)
	}
	return terminal
}

func ensureActivationCanaryResult(
	store *activationstore.Store,
	inputs verifiedActivationInputs,
	task verifiedTaskBundle,
	submit activationSubmitRecord,
	client *gatewayclient.Client,
	deadline time.Time,
) ([]byte, gatewayclient.TaskLifecycleStatus, error) {
	resultRaw, resultPresent, err := readOptionalActivationArtifact(
		store, activationstore.CanaryResultFileName, activation.MaxCanaryResultBytes,
	)
	if err != nil {
		return nil, gatewayclient.TaskLifecycleStatus{}, err
	}
	if resultPresent {
		hermes, err := activation.VerifyHermesWorkspaceAuditResultV1(
			resultRaw,
			agentrelease.HermesSessionIDPrefix+"-"+inputs.plan.ActivationID,
		)
		if err != nil || hermes.RunID != submit.RunID {
			return nil, gatewayclient.TaskLifecycleStatus{},
				&activationCanaryTerminalError{
					state: "retained_result_invalid",
					code:  "closed_canary_invalid",
				}
		}
	}

	ctx, cancel, err := activationCanaryContext(deadline)
	if err != nil {
		return nil, gatewayclient.TaskLifecycleStatus{}, err
	}
	defer cancel()
	poll := time.Duration(task.Bundle.Operation.PollIntervalSeconds) * time.Second
	terminalCompletionConfirmed := false
	for {
		if !terminalCompletionConfirmed {
			status, err := client.Status(
				ctx, submit.TaskDigest, submit.PermitDigest,
			)
			if err != nil {
				if errors.Is(err, context.DeadlineExceeded) ||
					errors.Is(ctx.Err(), context.DeadlineExceeded) {
					return nil, gatewayclient.TaskLifecycleStatus{},
						&activationCanaryTimeoutError{deadline: deadline}
				}
				return nil, gatewayclient.TaskLifecycleStatus{}, err
			}
			if status.Phase == gatewayclient.PhaseTerminal {
				if status.State != string(gatewayclient.AgentReportedCompleted) {
					return nil, status, activationTerminalStatusError(
						store, status, "",
					)
				}
				terminalCompletionConfirmed = true
				if resultPresent {
					if status.RunID != submit.RunID ||
						status.ResultDigest != dsse.Digest(resultRaw) ||
						status.ResponseBytes != int64(len(resultRaw)) {
						return nil, status, activationTerminalStatusError(
							store, status, "retained_result_mismatch",
						)
					}
					if err := storeActivationTerminalStatus(
						store, status,
					); err != nil {
						return nil, status, err
					}
					return resultRaw, status, nil
				}
			}
		}

		observed, observeErr := client.Observe(
			ctx, submit.TaskDigest, submit.PermitDigest,
		)
		if observeErr != nil {
			if errors.Is(observeErr, context.DeadlineExceeded) ||
				errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return nil, gatewayclient.TaskLifecycleStatus{},
					&activationCanaryTimeoutError{deadline: deadline}
			}
			var apiError *gatewayclient.APIError
			if errors.As(observeErr, &apiError) &&
				apiError.Status == http.StatusTooManyRequests {
				delay := apiError.RetryAfter
				if delay <= 0 {
					delay = poll
				}
				if err := waitTaskPoll(ctx, delay); err != nil {
					if errors.Is(err, context.DeadlineExceeded) {
						return nil, gatewayclient.TaskLifecycleStatus{},
							&activationCanaryTimeoutError{deadline: deadline}
					}
					return nil, gatewayclient.TaskLifecycleStatus{}, err
				}
				continue
			}
			return nil, gatewayclient.TaskLifecycleStatus{}, observeErr
		}
		if observed.Phase != gatewayclient.PhaseTerminal {
			if err := waitTaskPoll(ctx, poll); err != nil {
				if errors.Is(err, context.DeadlineExceeded) {
					return nil, gatewayclient.TaskLifecycleStatus{},
						&activationCanaryTimeoutError{deadline: deadline}
				}
				return nil, gatewayclient.TaskLifecycleStatus{}, err
			}
			continue
		}
		if observed.State != string(gatewayclient.AgentReportedCompleted) {
			return nil, observed, activationTerminalStatusError(
				store, observed, "",
			)
		}
		raw, err := decodeActivationObservation(observed)
		if err != nil {
			return nil, observed, activationTerminalStatusError(
				store, observed, "terminal_observation_invalid",
			)
		}
		hermes, err := activation.VerifyHermesWorkspaceAuditResultV1(
			raw,
			agentrelease.HermesSessionIDPrefix+"-"+inputs.plan.ActivationID,
		)
		if err != nil || hermes.RunID != submit.RunID {
			return nil, observed, activationTerminalStatusError(
				store, observed, "closed_canary_invalid",
			)
		}
		if err := writeActivationArtifact(
			store, activationstore.CanaryResultFileName, raw, false,
		); err != nil {
			return nil, observed, err
		}
		if err := storeActivationTerminalStatus(store, observed); err != nil {
			return nil, observed, err
		}
		return raw, observed, nil
	}
}

func readStoredActivationCanaryResult(
	store *activationstore.Store,
	inputs verifiedActivationInputs,
	task verifiedTaskBundle,
	submit activationSubmitRecord,
) ([]byte, gatewayclient.TaskLifecycleStatus, bool, error) {
	resultRaw, resultPresent, err := readOptionalActivationArtifact(
		store, activationstore.CanaryResultFileName, activation.MaxCanaryResultBytes,
	)
	if err != nil {
		return nil, gatewayclient.TaskLifecycleStatus{}, false, err
	}
	if resultPresent {
		hermes, verifyErr := activation.VerifyHermesWorkspaceAuditResultV1(
			resultRaw,
			agentrelease.HermesSessionIDPrefix+"-"+inputs.plan.ActivationID,
		)
		if verifyErr != nil || hermes.RunID != submit.RunID {
			return nil, gatewayclient.TaskLifecycleStatus{}, false,
				&activationCanaryTerminalError{
					state: "retained_result_invalid",
					code:  "closed_canary_invalid",
				}
		}
	}
	status, statusPresent, err := readRetainedActivationTerminalStatus(
		store, task,
	)
	if err != nil {
		return nil, gatewayclient.TaskLifecycleStatus{}, false,
			&activationCanaryRetainedInvalidError{cause: err}
	}
	if statusPresent {
		if status.State != string(gatewayclient.AgentReportedCompleted) ||
			status.RunID != submit.RunID {
			return nil, gatewayclient.TaskLifecycleStatus{}, false,
				&activationCanaryRetainedInvalidError{
					cause: errors.New("retained activation terminal status does not prove one completed canary"),
				}
		}
		if resultPresent &&
			(status.ResultDigest != dsse.Digest(resultRaw) ||
				status.ResponseBytes != int64(len(resultRaw))) {
			return nil, gatewayclient.TaskLifecycleStatus{}, false,
				&activationCanaryRetainedInvalidError{
					cause: errors.New("retained activation terminal status does not match the canary result"),
				}
		}
	}
	if !resultPresent || !statusPresent {
		return resultRaw, status, false, nil
	}
	return resultRaw, status, true, nil
}

func readRetainedActivationTerminalStatus(
	store *activationstore.Store,
	task verifiedTaskBundle,
) (gatewayclient.TaskLifecycleStatus, bool, error) {
	raw, present, err := readOptionalActivationArtifact(
		store, activationstore.CanaryStatusFileName, maxArtifactBytes,
	)
	if err != nil || !present {
		return gatewayclient.TaskLifecycleStatus{}, present, err
	}
	var status gatewayclient.TaskLifecycleStatus
	if err := dsse.DecodeStrictInto(raw, maxArtifactBytes, &status); err != nil {
		return gatewayclient.TaskLifecycleStatus{}, true,
			fmt.Errorf("decode retained activation terminal status: %w", err)
	}
	canonical, err := json.Marshal(status)
	if err != nil || !bytes.Equal(canonical, raw) {
		return gatewayclient.TaskLifecycleStatus{}, true,
			errors.New("retained activation terminal status is not canonical JSON")
	}
	statement := task.Verified.Statement
	if status.SchemaVersion != activationTaskStatusSchemaV1 ||
		status.TaskDigest != taskpermit.TaskDigest(
			statement.TenantID, statement.InstanceID, statement.TaskID,
		) ||
		status.PermitDigest != task.Verified.EnvelopeDigest ||
		status.Phase != gatewayclient.PhaseTerminal ||
		status.ObservedStatus != "" || status.ObservationBase64 != "" {
		return gatewayclient.TaskLifecycleStatus{}, true,
			errors.New("retained activation terminal status does not match the verified task")
	}
	switch status.State {
	case string(gatewayclient.AgentReportedCompleted),
		string(gatewayclient.AgentReportedFailed),
		string(gatewayclient.AgentReportedCancelled):
		if !taskIdentifier(status.RunID) ||
			string(status.TaskStatus) != status.State ||
			!activationStatusDigest(status.ResultDigest) ||
			status.ResponseBytes < 1 ||
			status.ErrorCode != "" || status.RetrySafety != "" {
			return gatewayclient.TaskLifecycleStatus{}, true,
				errors.New("retained agent-reported terminal status has inconsistent fields")
		}
	case gatewayclient.StateFailedWithoutDispatchEvidence:
		if status.RunID != "" || status.TaskStatus != "" ||
			status.ResultDigest != "" || status.ResponseBytes != 0 ||
			!taskIdentifier(status.ErrorCode) ||
			status.RetrySafety != gatewayclient.RetryReplacementSafeAfterNewAuthority &&
				status.RetrySafety != gatewayclient.RetryReplacementUnsafe {
			return gatewayclient.TaskLifecycleStatus{}, true,
				errors.New("retained pre-dispatch terminal status has inconsistent fields")
		}
	case gatewayclient.StateObservationFailed:
		if !taskIdentifier(status.RunID) || status.TaskStatus != "" ||
			status.ResultDigest != "" || status.ResponseBytes != 0 ||
			!taskIdentifier(status.ErrorCode) ||
			status.RetrySafety != gatewayclient.RetryReplacementUnsafe {
			return gatewayclient.TaskLifecycleStatus{}, true,
				errors.New("retained observation-failure status has inconsistent fields")
		}
	default:
		return gatewayclient.TaskLifecycleStatus{}, true,
			errors.New("retained activation terminal status has an unknown state")
	}
	return status, true, nil
}

func activationStatusDigest(value string) bool {
	if len(value) != len("sha256:")+64 ||
		!strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, character := range value[len("sha256:"):] {
		if character < '0' || character > '9' &&
			(character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func decodeActivationObservation(
	status gatewayclient.TaskLifecycleStatus,
) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(status.ObservationBase64)
	if err != nil || len(raw) == 0 ||
		base64.StdEncoding.EncodeToString(raw) != status.ObservationBase64 ||
		int64(len(raw)) != status.ResponseBytes ||
		dsse.Digest(raw) != status.ResultDigest {
		return nil, errors.New("Gateway activation observation has invalid exact bytes")
	}
	return raw, nil
}

func storeActivationTerminalStatus(
	store *activationstore.Store,
	status gatewayclient.TaskLifecycleStatus,
) error {
	status.ObservationBase64 = ""
	status.ObservedStatus = ""
	raw, err := json.Marshal(status)
	if err != nil {
		return err
	}
	return writeActivationArtifact(
		store, activationstore.CanaryStatusFileName, raw, false,
	)
}

func activationGatewayEvidenceRequest(
	task verifiedTaskBundle,
	submit activationSubmitRecord,
	resultRaw []byte,
) (activation.GatewayEvidenceRequestV1, error) {
	receiptPublic, err := activationSubmitReceiptPublicKey(submit)
	if err != nil {
		return activation.GatewayEvidenceRequestV1{}, err
	}
	return activation.GatewayEvidenceRequestV1{
		Task:             task.Verified,
		TaskProtocol:     task.Bundle.Operation.TaskProtocol,
		RunID:            submit.RunID,
		Result:           resultRaw,
		ReceiptPublicKey: receiptPublic,
		ReceiptEpoch:     submit.ReceiptEpoch,
	}, nil
}

func collectActivationGatewayEvidence(
	ctx context.Context,
	store *activationstore.Store,
	task verifiedTaskBundle,
	submit activationSubmitRecord,
	resultRaw []byte,
	localGateway activationGatewayLocal,
) (activation.GatewayEvidenceResultV1, error) {
	if err := activationGatewayMatchesSubmit(localGateway, submit, task); err != nil {
		return activation.GatewayEvidenceResultV1{}, err
	}
	request, err := activationGatewayEvidenceRequest(task, submit, resultRaw)
	if err != nil {
		return activation.GatewayEvidenceResultV1{}, err
	}
	gatewayResult, err := activation.CollectGatewayEvidenceV1Context(
		ctx, request, localGateway.config.ConnectorReceiptFile,
	)
	if err != nil {
		if errors.Is(err, activation.ErrEvidenceInvalid) {
			return activation.GatewayEvidenceResultV1{},
				&activationRetainedEvidenceInvalidError{cause: err}
		}
		return activation.GatewayEvidenceResultV1{}, err
	}
	if err := writeActivationArtifact(
		store, activationstore.GatewayTaskReceiptsFileName,
		gatewayResult.Receipts, false,
	); err != nil {
		return activation.GatewayEvidenceResultV1{}, err
	}
	return gatewayResult, nil
}

func readStoredActivationGatewayEvidence(
	ctx context.Context,
	store *activationstore.Store,
	task verifiedTaskBundle,
	submit activationSubmitRecord,
	resultRaw []byte,
) (activation.GatewayEvidenceResultV1, bool, error) {
	_, gatewayPresent, err := readOptionalActivationArtifact(
		store,
		activationstore.GatewayTaskReceiptsFileName,
		connectorledger.MaxPortableTaskEvidenceBytes,
	)
	if err != nil {
		return activation.GatewayEvidenceResultV1{}, false, err
	}
	if !gatewayPresent {
		return activation.GatewayEvidenceResultV1{}, false, nil
	}
	result, err := verifyStoredActivationGatewayEvidence(
		ctx, store, task, submit, resultRaw,
	)
	return result, true, err
}

func verifyStoredActivationGatewayEvidence(
	ctx context.Context,
	store *activationstore.Store,
	task verifiedTaskBundle,
	submit activationSubmitRecord,
	resultRaw []byte,
) (activation.GatewayEvidenceResultV1, error) {
	request, err := activationGatewayEvidenceRequest(task, submit, resultRaw)
	if err != nil {
		return activation.GatewayEvidenceResultV1{}, err
	}
	receipts, err := store.Read(
		activationstore.GatewayTaskReceiptsFileName,
		connectorledger.MaxPortableTaskEvidenceBytes,
	)
	if err != nil {
		return activation.GatewayEvidenceResultV1{}, err
	}
	gatewayResult, err := activation.VerifyGatewayEvidenceV1Context(
		ctx, request, receipts,
	)
	if err != nil {
		if errors.Is(err, context.Canceled) ||
			errors.Is(err, context.DeadlineExceeded) {
			return activation.GatewayEvidenceResultV1{}, err
		}
		return activation.GatewayEvidenceResultV1{},
			&activationRetainedEvidenceInvalidError{cause: err}
	}
	return gatewayResult, nil
}

func ensureActivationExecutorCheckpoint(
	ctx context.Context,
	store *activationstore.Store,
	inputs verifiedActivationInputs,
	binding activation.BindingV1,
	admitted permitAdmission,
	gatewayResult activation.GatewayEvidenceResultV1,
	nodeURL, tokenPath string,
) ([]byte, string, error) {
	raw, err := activation.MarshalExecutorCheckpointV1(
		binding, admitted.RuntimeRef, admitted.CapsuleDigest,
		admitted.RoutePolicyDigest, admitted.GrantID, gatewayResult,
	)
	if err != nil {
		return nil, "", err
	}
	digest, err := activation.ExecutorCheckpointDigestV1(raw)
	if err != nil {
		return nil, "", err
	}
	if existing, present, readErr := readOptionalActivationArtifact(
		store, activationstore.ExecutorCheckpointFileName,
		activation.MaxExecutorCheckpointBytes,
	); readErr != nil {
		return nil, "", readErr
	} else if present {
		if !bytes.Equal(existing, raw) {
			return nil, "", &activationArtifactConflictError{
				name: activationstore.ExecutorCheckpointFileName,
			}
		}
		return existing, digest, nil
	}
	client, err := nodeclient.NewFromTokenFile(nodeURL, tokenPath)
	if err != nil {
		return nil, "", err
	}
	if err := client.ActivationCheckpoint(
		ctx, admitted.RuntimeRef, inputs.plan.ActivationID, digest,
	); err != nil {
		if prerequisite := activationNodePrerequisiteError(err); prerequisite != nil {
			return nil, "", prerequisite
		}
		return nil, "", err
	}
	if err := writeActivationArtifact(
		store, activationstore.ExecutorCheckpointFileName, raw, false,
	); err != nil {
		return nil, "", err
	}
	return raw, digest, nil
}

func verifyStoredActivationExecutorBegin(
	store *activationstore.Store,
	inputs verifiedActivationInputs,
	binding activation.BindingV1,
	admitted permitAdmission,
) (string, error) {
	expected, err := activation.MarshalExecutorBeginV1(
		binding,
		executor.RuntimeRef(inputs.intent.TenantID, inputs.intent.InstanceID),
		executor.StateVolumeName(inputs.intent.TenantID, inputs.intent.LineageID),
		admitted.CapsuleDigest,
	)
	if err != nil {
		return "", err
	}
	raw, err := store.Read(
		activationstore.ExecutorBeginFileName,
		activation.MaxExecutorCheckpointBytes,
	)
	if err != nil {
		return "", err
	}
	if !bytes.Equal(raw, expected) {
		return "", &activationRetainedEvidenceInvalidError{
			cause: errors.New("Executor activation begin marker does not match the immutable activation binding"),
		}
	}
	begin, err := activation.ParseExecutorBeginV1(raw)
	if err != nil || begin.Binding.ActivationID != inputs.plan.ActivationID {
		if err == nil {
			err = errors.New("Executor activation begin marker has another activation identity")
		}
		return "", &activationRetainedEvidenceInvalidError{cause: err}
	}
	return activation.ExecutorBeginDigestV1(raw)
}

func verifyStoredActivationExecutorCheckpoint(
	store *activationstore.Store,
	inputs verifiedActivationInputs,
	binding activation.BindingV1,
	admitted permitAdmission,
	gatewayResult activation.GatewayEvidenceResultV1,
) (string, error) {
	expected, err := activation.MarshalExecutorCheckpointV1(
		binding, admitted.RuntimeRef, admitted.CapsuleDigest,
		admitted.RoutePolicyDigest, admitted.GrantID, gatewayResult,
	)
	if err != nil {
		return "", err
	}
	raw, err := store.Read(
		activationstore.ExecutorCheckpointFileName,
		activation.MaxExecutorCheckpointBytes,
	)
	if err != nil {
		return "", err
	}
	if !bytes.Equal(raw, expected) {
		return "", &activationRetainedEvidenceInvalidError{
			cause: errors.New("Executor activation checkpoint does not match the verified Gateway evidence and activation binding"),
		}
	}
	checkpoint, err := activation.ParseExecutorCheckpointV1(raw)
	if err != nil || checkpoint.Binding.ActivationID != inputs.plan.ActivationID {
		if err == nil {
			err = errors.New("Executor activation checkpoint has another activation identity")
		}
		return "", &activationRetainedEvidenceInvalidError{cause: err}
	}
	return activation.ExecutorCheckpointDigestV1(raw)
}

func activationExecutorEvidenceRequest(
	inputs verifiedActivationInputs,
	binding activation.BindingV1,
	admitted permitAdmission,
	baselineRaw, finalWitnessRaw []byte,
	beginDigest string,
	checkpointDigest string,
	witnessPublic ed25519.PublicKey,
) activation.ExecutorEvidenceRequestV1 {
	return activation.ExecutorEvidenceRequestV1{
		Binding:    binding,
		RuntimeRef: admitted.RuntimeRef,
		StateRuntimeRef: executor.StateVolumeName(
			inputs.intent.TenantID, inputs.intent.LineageID,
		),
		CapsuleDigest:              admitted.CapsuleDigest,
		RoutePolicyDigest:          admitted.RoutePolicyDigest,
		GrantID:                    admitted.GrantID,
		ActivationBeginDigest:      beginDigest,
		ActivationCheckpointDigest: checkpointDigest,
		BaselineWitness:            baselineRaw,
		FinalWitness:               finalWitnessRaw,
		WitnessPublicKey:           witnessPublic,
	}
}

func ensureActivationExecutorEvidence(
	ctx context.Context,
	store *activationstore.Store,
	inputs verifiedActivationInputs,
	binding activation.BindingV1,
	admitted permitAdmission,
	baselineRaw, finalWitnessRaw, checkpointRaw []byte,
	beginDigest string,
	checkpointDigest string,
	witnessPublic ed25519.PublicKey,
	executorEvidencePath string,
) (activation.ExecutorEvidenceResultV1, error) {
	verifiedDigest, err := activation.ExecutorCheckpointDigestV1(checkpointRaw)
	if err != nil || verifiedDigest != checkpointDigest {
		if err == nil {
			err = errors.New("Executor activation checkpoint digest changed")
		}
		return activation.ExecutorEvidenceResultV1{},
			&activationRetainedEvidenceInvalidError{cause: err}
	}
	request := activationExecutorEvidenceRequest(
		inputs, binding, admitted, baselineRaw, finalWitnessRaw,
		beginDigest, checkpointDigest, witnessPublic,
	)
	if delta, present, readErr := readOptionalActivationArtifact(
		store, activationstore.ExecutorDeltaFileName,
		activation.MaxExecutorDeltaBytes,
	); readErr != nil {
		return activation.ExecutorEvidenceResultV1{}, readErr
	} else if present {
		result, verifyErr := activation.VerifyExecutorEvidenceDeltaV1Context(
			ctx, request, delta,
		)
		if verifyErr != nil {
			if errors.Is(verifyErr, context.Canceled) ||
				errors.Is(verifyErr, context.DeadlineExceeded) {
				return activation.ExecutorEvidenceResultV1{}, verifyErr
			}
			return activation.ExecutorEvidenceResultV1{},
				&activationRetainedEvidenceInvalidError{cause: verifyErr}
		}
		return result, nil
	}
	if err := activation.VerifyExecutorWitnessPairV1(request); err != nil {
		return activation.ExecutorEvidenceResultV1{},
			&activationRetainedEvidenceInvalidError{cause: err}
	}
	result, err := activation.CollectExecutorEvidenceV1Context(
		ctx, request, executorEvidencePath,
	)
	if err != nil {
		if errors.Is(err, activation.ErrEvidenceInvalid) {
			return activation.ExecutorEvidenceResultV1{},
				&activationRetainedEvidenceInvalidError{cause: err}
		}
		return activation.ExecutorEvidenceResultV1{}, err
	}
	if err := writeActivationArtifact(
		store, activationstore.ExecutorDeltaFileName, result.Delta, false,
	); err != nil {
		return activation.ExecutorEvidenceResultV1{}, err
	}
	return result, nil
}

func verifyStoredActivationExecutorEvidence(
	ctx context.Context,
	store *activationstore.Store,
	inputs verifiedActivationInputs,
	binding activation.BindingV1,
	admitted permitAdmission,
	beginDigest string,
	checkpointDigest string,
	witnessPublic ed25519.PublicKey,
) (activation.ExecutorEvidenceResultV1, error) {
	baselineRaw, err := store.Read(
		activationstore.ExecutorBaselineWitnessFileName,
		controlprotocol.MaxExecutorEvidenceJSONBytes,
	)
	if err != nil {
		return activation.ExecutorEvidenceResultV1{}, err
	}
	finalRaw, err := store.Read(
		activationstore.ExecutorFinalWitnessFileName,
		controlprotocol.MaxExecutorEvidenceJSONBytes,
	)
	if err != nil {
		return activation.ExecutorEvidenceResultV1{}, err
	}
	delta, err := store.Read(
		activationstore.ExecutorDeltaFileName, activation.MaxExecutorDeltaBytes,
	)
	if err != nil {
		return activation.ExecutorEvidenceResultV1{}, err
	}
	result, err := activation.VerifyExecutorEvidenceDeltaV1Context(
		ctx,
		activationExecutorEvidenceRequest(
			inputs, binding, admitted, baselineRaw, finalRaw,
			beginDigest, checkpointDigest, witnessPublic,
		),
		delta,
	)
	if err != nil {
		if errors.Is(err, context.Canceled) ||
			errors.Is(err, context.DeadlineExceeded) {
			return activation.ExecutorEvidenceResultV1{}, err
		}
		return activation.ExecutorEvidenceResultV1{},
			&activationRetainedEvidenceInvalidError{cause: err}
	}
	return result, nil
}

type activationRetainedEvidenceInvalidError struct {
	cause error
}

func (err *activationRetainedEvidenceInvalidError) Error() string {
	return "retained activation evidence is invalid: " + err.cause.Error()
}

func (err *activationRetainedEvidenceInvalidError) Unwrap() error {
	return err.cause
}

func finalizeActivationProof(
	store *activationstore.Store,
	chain *activationStateChain,
	inputs verifiedActivationInputs,
	beginDigest string,
	checkpointDigest string,
	executorResult activation.ExecutorEvidenceResultV1,
	gatewayResult activation.GatewayEvidenceResultV1,
) ([]byte, error) {
	current := chain.latest()
	if current.Phase != activation.PhaseEvidenceCollected {
		return nil, errors.New("activation proof can be finalized only after evidence collection")
	}
	if existing, present, err := readOptionalActivationArtifact(
		store, activationstore.ProofFileName, activation.MaxProofBytes,
	); err != nil {
		return nil, err
	} else if present {
		proof, err := activation.ParseProofV1(existing)
		if err != nil {
			return nil, &activationRetainedEvidenceInvalidError{cause: err}
		}
		next := current
		next.Phase = activation.PhasePassed
		next.UpdatedAt = proof.CompletedAt
		nextRaw, err := activation.MarshalStateV1(next)
		if err != nil {
			return nil, &activationRetainedEvidenceInvalidError{cause: err}
		}
		if dsse.Digest(nextRaw) != proof.StateDigest ||
			proof.Binding != current.Binding ||
			proof.RuntimeRef != current.RuntimeRef ||
			proof.ExecutorBeginDigest != beginDigest ||
			proof.ExecutorCheckpointDigest != checkpointDigest ||
			proof.ExecutorEvidence != executorResult.Coordinate ||
			proof.GatewayEvidence != gatewayResult.Coordinate ||
			proof.Witness != executorResult.Witness ||
			proof.Canary != gatewayResult.Canary {
			return nil, &activationRetainedEvidenceInvalidError{
				cause: errors.New(
					"retained activation proof does not match the verified evidence",
				),
			}
		}
		if err := activation.ValidateStateTransitionV1(current, next); err != nil {
			return nil, &activationRetainedEvidenceInvalidError{cause: err}
		}
		name, err := store.AppendState(uint64(len(chain.states)), nextRaw)
		if err != nil {
			return nil, err
		}
		chain.names = append(chain.names, name)
		chain.raw = append(chain.raw, nextRaw)
		chain.states = append(chain.states, next)
		if _, err := activation.CorrelateProofV1(
			inputs.planRaw, nextRaw, existing,
		); err != nil {
			return nil, &activationRetainedEvidenceInvalidError{cause: err}
		}
		return existing, nil
	}

	completed := timeNow().UTC()
	currentTime, _ := time.Parse(time.RFC3339Nano, current.UpdatedAt)
	witnessed, _ := time.Parse(
		time.RFC3339Nano, executorResult.Witness.WitnessedAt,
	)
	if !completed.After(currentTime) {
		completed = currentTime.Add(time.Nanosecond)
	}
	if completed.Before(witnessed) {
		completed = witnessed
		if !completed.After(currentTime) {
			completed = currentTime.Add(time.Nanosecond)
		}
	}
	next := current
	next.Phase = activation.PhasePassed
	next.UpdatedAt = completed.Format(time.RFC3339Nano)
	nextRaw, err := activation.MarshalStateV1(next)
	if err != nil {
		return nil, err
	}
	if err := activation.ValidateStateTransitionV1(current, next); err != nil {
		return nil, err
	}
	proof := activation.ProofV1{
		SchemaVersion:            activation.ProofSchemaV1,
		Binding:                  current.Binding,
		StateDigest:              dsse.Digest(nextRaw),
		RuntimeRef:               current.RuntimeRef,
		Canary:                   gatewayResult.Canary,
		ExecutorBeginDigest:      beginDigest,
		ExecutorCheckpointDigest: checkpointDigest,
		ExecutorEvidence:         executorResult.Coordinate,
		GatewayEvidence:          gatewayResult.Coordinate,
		Witness:                  executorResult.Witness,
		CompletedAt:              next.UpdatedAt,
	}
	proofRaw, err := activation.MarshalProofV1(proof)
	if err != nil {
		return nil, err
	}
	if err := writeActivationArtifact(
		store, activationstore.ProofFileName, proofRaw, false,
	); err != nil {
		return nil, err
	}
	name, err := store.AppendState(uint64(len(chain.states)), nextRaw)
	if err != nil {
		return nil, err
	}
	chain.names = append(chain.names, name)
	chain.raw = append(chain.raw, nextRaw)
	chain.states = append(chain.states, next)
	if _, err := activation.CorrelateProofV1(
		inputs.planRaw, nextRaw, proofRaw,
	); err != nil {
		return nil, err
	}
	return proofRaw, nil
}

func markActivationActionRequired(
	store *activationstore.Store,
	chain *activationStateChain,
	stdout io.Writer,
	inputs verifiedActivationInputs,
	reason string,
	cause error,
) error {
	if chain.latest().Phase != activation.PhaseActionRequired {
		if err := appendActivationState(
			store, chain, activation.PhaseActionRequired,
			chain.latest().RuntimeRef, reason,
		); err != nil {
			return errors.Join(cause, err)
		}
	}
	statusErr := writeActivationStatus(
		stdout, inputs, *chain, true, "operator",
		activationReplaceFailedCommand(chain.latest().Binding.Generation), "",
	)
	return errors.Join(cause, statusErr)
}
