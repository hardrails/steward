package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/hardrails/steward/internal/activation"
	"github.com/hardrails/steward/internal/activationcanary"
	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/controlcapture"
	"github.com/hardrails/steward/internal/controlclient"
	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/controlstore"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/gateway"
	"github.com/hardrails/steward/internal/rollout"
	"github.com/hardrails/steward/internal/rolloutdriver"
	"github.com/hardrails/steward/internal/rolloutstore"
)

const (
	reasonRolloutDeadlineExpired = "rollout_deadline_expired"
	reasonNodePreflightFailed    = "node_preflight_failed"
	reasonCaptureArmConflict     = "evidence_capture_arm_conflict"
	reasonAdmitConflict          = "admit_command_conflict"
	reasonAdmitTerminal          = "admit_terminal_failure"
	reasonAdmissionInvalid       = "admission_projection_invalid"
	reasonStartConflict          = "start_command_conflict"
	reasonStartTerminal          = "start_terminal_failure"
	reasonCanaryConflict         = "canary_command_conflict"
	reasonCanaryTerminal         = "canary_terminal_failure"
	reasonCanaryInvalid          = "canary_result_invalid"
	reasonEvidenceInvalid        = "evidence_capture_invalid"
	reasonPhaseTimeout           = "phase_deadline_expired"
)

type rolloutStickyError struct {
	reason string
	cause  error
}

func (err *rolloutStickyError) Error() string {
	if err == nil || err.cause == nil {
		return "rollout requires operator action"
	}
	return err.cause.Error()
}

func (err *rolloutStickyError) Unwrap() error { return err.cause }

func executeRolloutStateMachine(
	store *rolloutstore.Store,
	run *verifiedRolloutRun,
	keys rolloutRunKeys,
	client *controlclient.Client,
	stdout io.Writer,
	jsonOutput bool,
) error {
	if store == nil || run == nil || client == nil {
		return errors.New("rollout runner is unavailable")
	}
	for _, state := range run.states {
		if state.Phase == rollout.PhaseActionRequired {
			return writeExistingRolloutActionRequired(stdout, *run, jsonOutput)
		}
	}
	pending, err := rolloutCurrentBatchTargets(run.plan, run.states)
	if err != nil {
		return err
	}
	if len(pending) == 0 {
		return ensureRolloutProofManifest(store, run, true)
	}
	for _, index := range pending {
		if err := executeRolloutTarget(
			store, run, uint16(index), keys, client, stdout, jsonOutput,
		); err != nil {
			return err
		}
	}
	allPassed := true
	for _, state := range run.states {
		allPassed = allPassed && state.Phase == rollout.PhasePassed
	}
	if allPassed {
		return ensureRolloutProofManifest(store, run, true)
	}
	return nil
}

func rolloutCurrentBatchTargets(
	plan rollout.PlanV1,
	states []rollout.TargetStateV1,
) ([]int, error) {
	if len(states) != len(plan.Targets) {
		return nil, errors.New("rollout state count differs from the plan")
	}
	current := -1
	for index, state := range states {
		if state.Phase != rollout.PhasePassed {
			current = index
			break
		}
	}
	if current == -1 {
		return nil, nil
	}
	active, err := rolloutBatchContaining(plan, current)
	if err != nil {
		return nil, err
	}
	pending := make([]int, 0, active.End-active.Start)
	for index := active.Start; index < active.End; index++ {
		if states[index].Phase != rollout.PhasePassed {
			pending = append(pending, index)
		}
	}
	return pending, nil
}

func rolloutBatchContaining(plan rollout.PlanV1, target int) (rollout.BatchV1, error) {
	batches, err := plan.Batches()
	if err != nil {
		return rollout.BatchV1{}, err
	}
	for _, batch := range batches {
		if target >= batch.Start && target < batch.End {
			return batch, nil
		}
	}
	return rollout.BatchV1{}, errors.New("current rollout target is outside deterministic batches")
}

func executeRolloutTarget(
	store *rolloutstore.Store,
	run *verifiedRolloutRun,
	index uint16,
	keys rolloutRunKeys,
	client *controlclient.Client,
	stdout io.Writer,
	jsonOutput bool,
) error {
	target := &run.targets[index]
	for {
		state := run.states[index]
		if state.Phase != rollout.PhaseActionRequired {
			deadline, _ := time.Parse(time.RFC3339Nano, run.plan.Deadline)
			if !deadline.After(timeNow().UTC()) {
				return markRolloutActionRequired(
					store, run, index, stdout, jsonOutput,
					reasonRolloutDeadlineExpired,
					errors.New("rollout deadline expired before target completion"),
				)
			}
		}
		switch state.Phase {
		case rollout.PhasePlanned:
			phaseDeadline, err := rolloutPhaseDeadlineFromNow(
				run.plan, target.timeouts.PreflightSeconds,
			)
			if err != nil {
				return markPhaseDeadline(store, run, index, stdout, jsonOutput, err)
			}
			ctx, cancel, err := rolloutControlContext(phaseDeadline)
			if err != nil {
				return markPhaseDeadline(store, run, index, stdout, jsonOutput, err)
			}
			node, callErr := client.GetNode(ctx, run.plan.TenantID, target.prepared.Target().NodeID)
			cancel()
			if callErr != nil {
				if rolloutPermanentControlError(callErr) {
					return markRolloutActionRequired(
						store, run, index, stdout, jsonOutput,
						reasonNodePreflightFailed, callErr,
					)
				}
				return fmt.Errorf("preflight rollout node: %w", callErr)
			}
			contextLockedEffects := false
			if target.prepared.Intent().EffectMode == admission.EffectModeAuthorized {
				contextLockedEffects, err = run.verified.SitePolicy.AuthorizedActionContextRequired(run.plan.TenantID)
				if err != nil {
					return markRolloutActionRequired(store, run, index, stdout, jsonOutput, reasonNodePreflightFailed, err)
				}
			}
			if node.NodeID != target.prepared.Target().NodeID ||
				!nodeSupportsRollout(
					node,
					run.plan.TenantID,
					target.prepared.Intent().EffectMode == admission.EffectModeAuthorized,
					contextLockedEffects,
				) {
				return markRolloutActionRequired(
					store, run, index, stdout, jsonOutput,
					reasonNodePreflightFailed,
					errors.New("node is not active, tenant-authorized, and protocol-4 canary capable"),
				)
			}
			if err := appendRolloutTargetPhase(
				store, run, index, rollout.PhasePreflightPassed, nil,
			); err != nil {
				return err
			}

		case rollout.PhasePreflightPassed:
			ttl, err := rolloutEvidenceCaptureTTL(target.timeouts)
			if err != nil {
				return err
			}
			phaseDeadline, err := rolloutTargetPhaseDeadline(
				run.plan, state, target.timeouts.AdmissionSeconds,
			)
			if err != nil {
				return markPhaseDeadline(store, run, index, stdout, jsonOutput, err)
			}
			ctx, cancel, err := rolloutControlContext(phaseDeadline)
			if err != nil {
				return markPhaseDeadline(store, run, index, stdout, jsonOutput, err)
			}
			armed, callErr := client.ArmExecutorEvidenceCapture(
				ctx,
				target.prepared.Target().NodeID,
				controlclient.EvidenceCaptureArmInput{
					CaptureID:             rolloutCaptureID(run.plan, index),
					RequestID:             rolloutCaptureRequestID(run.plan, index),
					TenantID:              run.plan.TenantID,
					RuntimeRef:            target.prepared.RuntimeRef(),
					Generation:            target.prepared.Target().InstanceGeneration,
					ActivationID:          target.prepared.Target().ActivationID,
					ActivationBeginDigest: target.prepared.ExecutorBeginDigest(),
					TTL:                   ttl,
				},
			)
			cancel()
			if callErr != nil {
				if rolloutPermanentControlError(callErr) {
					return markRolloutActionRequired(
						store, run, index, stdout, jsonOutput,
						reasonCaptureArmConflict, callErr,
					)
				}
				return fmt.Errorf("arm rollout evidence capture: %w", callErr)
			}
			if err := validateRolloutArmedCapture(
				armed, run.plan, target.prepared, index, ttl,
			); err != nil {
				return markRolloutActionRequired(
					store, run, index, stdout, jsonOutput, reasonCaptureArmConflict, err,
				)
			}
			if len(target.admitCommandRaw) == 0 {
				window, err := newRolloutSigningWindow(keys, phaseDeadline)
				if err != nil {
					return markPhaseDeadline(store, run, index, stdout, jsonOutput, err)
				}
				command, err := rolloutdriver.SignAdmissionCommandV1(target.prepared, window)
				if err != nil {
					return err
				}
				if err := writeRolloutTargetArtifact(
					store, index, rolloutstore.TargetAdmitCommandKind, command.Raw(),
				); err != nil {
					return err
				}
				target.admitCommandRaw = command.Raw()
			}
			if err := appendRolloutTargetPhase(
				store, run, index, rollout.PhaseEvidenceCaptureArmed, nil,
			); err != nil {
				return err
			}

		case rollout.PhaseEvidenceCaptureArmed:
			phaseDeadline, err := rolloutStoredCommandDeadline(target.admitCommandRaw, false)
			if err != nil {
				return markPhaseDeadline(store, run, index, stdout, jsonOutput, err)
			}
			if err := submitExactRolloutCommand(
				client, run.plan, target.prepared, target.admitCommandRaw,
				"admit", phaseDeadline,
			); err != nil {
				if sticky, ok := err.(*rolloutStickyError); ok {
					return markRolloutActionRequired(
						store, run, index, stdout, jsonOutput, sticky.reason, sticky.cause,
					)
				}
				return err
			}
			if err := appendRolloutTargetPhase(
				store, run, index, rollout.PhaseAdmitSubmitted, nil,
			); err != nil {
				return err
			}

		case rollout.PhaseAdmitSubmitted:
			phaseDeadline, err := rolloutStoredCommandDeadline(target.admitCommandRaw, false)
			if err != nil {
				return markPhaseDeadline(store, run, index, stdout, jsonOutput, err)
			}
			command, err := waitRolloutCommand(
				client, run.plan, target.prepared, target.admitCommandRaw,
				"admit", phaseDeadline,
			)
			if err != nil {
				if sticky, ok := err.(*rolloutStickyError); ok {
					return markRolloutActionRequired(
						store, run, index, stdout, jsonOutput, sticky.reason, sticky.cause,
					)
				}
				return err
			}
			if command.TerminalStatus != controlprotocol.ExecutorStatusDone ||
				command.DeliveryProtocol != controlprotocol.ExecutorProtocolV4 ||
				command.AdmissionProjectionState != "present" ||
				command.Result == nil || command.Result.Admission == nil {
				return markRolloutActionRequired(
					store, run, index, stdout, jsonOutput, reasonAdmitTerminal,
					errors.New("admit did not finish with one protocol-4 admission projection"),
				)
			}
			admissionProjection := *command.Result.Admission
			if err := rolloutdriver.VerifyAdmissionV1(target.prepared, admissionProjection); err != nil {
				return markRolloutActionRequired(
					store, run, index, stdout, jsonOutput, reasonAdmissionInvalid, err,
				)
			}
			admissionRaw, err := json.Marshal(admissionProjection)
			if err != nil {
				return err
			}
			if len(target.admissionRaw) != 0 {
				if !bytes.Equal(target.admissionRaw, admissionRaw) {
					return markRolloutActionRequired(
						store, run, index, stdout, jsonOutput,
						reasonAdmissionInvalid,
						errors.New("live admission differs from retained admission"),
					)
				}
			} else if err := writeRolloutTargetArtifact(
				store, index, rolloutstore.TargetAdmissionKind, admissionRaw,
			); err != nil {
				return err
			}
			target.admissionRaw = admissionRaw
			target.admission = &admissionProjection
			if err := appendRolloutTargetPhase(
				store, run, index, rollout.PhaseAdmitted,
				func(next *rollout.TargetStateV1) {
					next.RuntimeRef = admissionProjection.RuntimeRef
					next.AdmissionDigest = dsse.Digest(admissionRaw)
				},
			); err != nil {
				return err
			}

		case rollout.PhaseAdmitted:
			phaseDeadline, err := rolloutTargetPhaseDeadline(
				run.plan, state, target.timeouts.StartupSeconds,
			)
			if err != nil {
				return markPhaseDeadline(store, run, index, stdout, jsonOutput, err)
			}
			if len(target.startCommandRaw) == 0 {
				window, err := newRolloutSigningWindow(keys, phaseDeadline)
				if err != nil {
					return markPhaseDeadline(store, run, index, stdout, jsonOutput, err)
				}
				command, err := rolloutdriver.SignStartCommandV1(target.prepared, window)
				if err != nil {
					return err
				}
				if err := writeRolloutTargetArtifact(
					store, index, rolloutstore.TargetStartCommandKind, command.Raw(),
				); err != nil {
					return err
				}
				target.startCommandRaw = command.Raw()
			}
			phaseDeadline, err = rolloutStoredCommandDeadline(target.startCommandRaw, false)
			if err != nil {
				return markPhaseDeadline(store, run, index, stdout, jsonOutput, err)
			}
			if err := submitExactRolloutCommand(
				client, run.plan, target.prepared, target.startCommandRaw,
				"start", phaseDeadline,
			); err != nil {
				if sticky, ok := err.(*rolloutStickyError); ok {
					return markRolloutActionRequired(
						store, run, index, stdout, jsonOutput, sticky.reason, sticky.cause,
					)
				}
				return err
			}
			if err := appendRolloutTargetPhase(
				store, run, index, rollout.PhaseStartSubmitted, nil,
			); err != nil {
				return err
			}

		case rollout.PhaseStartSubmitted:
			phaseDeadline, err := rolloutStoredCommandDeadline(target.startCommandRaw, false)
			if err != nil {
				return markPhaseDeadline(store, run, index, stdout, jsonOutput, err)
			}
			command, err := waitRolloutCommand(
				client, run.plan, target.prepared, target.startCommandRaw,
				"start", phaseDeadline,
			)
			if err != nil {
				if sticky, ok := err.(*rolloutStickyError); ok {
					return markRolloutActionRequired(
						store, run, index, stdout, jsonOutput, sticky.reason, sticky.cause,
					)
				}
				return err
			}
			if command.TerminalStatus != controlprotocol.ExecutorStatusDone ||
				command.DeliveryProtocol != controlprotocol.ExecutorProtocolV4 ||
				command.ReportedStatus != "running" || command.Result == nil ||
				command.Result.RuntimeRef != target.prepared.RuntimeRef() {
				return markRolloutActionRequired(
					store, run, index, stdout, jsonOutput, reasonStartTerminal,
					errors.New("start did not finish running on protocol 4"),
				)
			}
			if err := appendRolloutTargetPhase(
				store, run, index, rollout.PhaseRunning, nil,
			); err != nil {
				return err
			}

		case rollout.PhaseRunning:
			if target.admission == nil {
				return errors.New("running rollout target has no authenticated admission")
			}
			phaseDeadline, err := rolloutTargetPhaseDeadline(
				run.plan, state, target.timeouts.CanarySeconds,
			)
			if err != nil {
				return markPhaseDeadline(store, run, index, stdout, jsonOutput, err)
			}
			if len(target.canaryCommandRaw) == 0 {
				window, err := newRolloutSigningWindow(keys, phaseDeadline)
				if err != nil {
					return markPhaseDeadline(store, run, index, stdout, jsonOutput, err)
				}
				canaryDeadline := window.IssuedAt.Add(window.ValidFor).Truncate(time.Second)
				if !canaryDeadline.After(window.IssuedAt) {
					return markPhaseDeadline(
						store, run, index, stdout, jsonOutput,
						errors.New("canary authorization window has less than one whole second remaining"),
					)
				}
				artifacts, err := rolloutdriver.BuildCanaryCommandV1(
					rolloutdriver.CanaryInputV1{
						Prepared: target.prepared, Admission: *target.admission,
						TaskKeyID: keys.taskID, TaskPrivateKey: keys.taskPrivate,
						TaskPublicKey:         keys.taskPublic,
						OperationPolicyDigest: target.prepared.Target().OperationPolicyDigest,
						ReceiptAuthority: activationcanary.ReceiptAuthorityV1{
							NodeID:          gateway.ServiceTaskReceiptNodeID(target.prepared.Target().NodeID),
							Epoch:           target.prepared.Target().GatewayReceiptEpoch,
							PublicKeySHA256: target.prepared.Target().GatewayReceiptPublicKeySHA256,
						},
						Deadline: canaryDeadline, CommandWindow: window,
					},
				)
				if err != nil {
					return err
				}
				outerRaw := artifacts.OuterCommand().Raw()
				if err := writeRolloutTargetArtifact(
					store, index, rolloutstore.TargetCanaryCommandKind, outerRaw,
				); err != nil {
					return err
				}
				target.canaryCommandRaw = outerRaw
			}
			if err := appendRolloutTargetPhase(
				store, run, index, rollout.PhaseCanaryAuthorized, nil,
			); err != nil {
				return err
			}

		case rollout.PhaseCanaryAuthorized:
			phaseDeadline, err := rolloutStoredCommandDeadline(target.canaryCommandRaw, true)
			if err != nil {
				return markPhaseDeadline(store, run, index, stdout, jsonOutput, err)
			}
			if err := submitExactRolloutCommand(
				client, run.plan, target.prepared, target.canaryCommandRaw,
				"activation-canary", phaseDeadline,
			); err != nil {
				if sticky, ok := err.(*rolloutStickyError); ok {
					return markRolloutActionRequired(
						store, run, index, stdout, jsonOutput, sticky.reason, sticky.cause,
					)
				}
				return err
			}
			if err := appendRolloutTargetPhase(
				store, run, index, rollout.PhaseCanarySubmitted, nil,
			); err != nil {
				return err
			}

		case rollout.PhaseCanarySubmitted:
			phaseDeadline, err := rolloutStoredCommandDeadline(target.canaryCommandRaw, true)
			if err != nil {
				return markPhaseDeadline(store, run, index, stdout, jsonOutput, err)
			}
			command, err := waitRolloutCommand(
				client, run.plan, target.prepared, target.canaryCommandRaw,
				"activation-canary", phaseDeadline,
			)
			if err != nil {
				if sticky, ok := err.(*rolloutStickyError); ok {
					return markRolloutActionRequired(
						store, run, index, stdout, jsonOutput, sticky.reason, sticky.cause,
					)
				}
				return err
			}
			if command.TerminalStatus != controlprotocol.ExecutorStatusDone ||
				command.DeliveryProtocol != controlprotocol.ExecutorProtocolV4 ||
				command.ActivationCanaryProjectionState != "present" ||
				command.Result == nil || command.Result.ActivationCanary == nil {
				return markRolloutActionRequired(
					store, run, index, stdout, jsonOutput, reasonCanaryTerminal,
					errors.New("closed canary did not finish with one protocol-4 result projection"),
				)
			}
			resultRaw, err := json.Marshal(command.Result.ActivationCanary)
			if err != nil {
				return err
			}
			canaryRaw, err := canaryOuterPayload(target.canaryCommandRaw, keys)
			if err != nil {
				return markRolloutActionRequired(
					store, run, index, stdout, jsonOutput, reasonCanaryInvalid, err,
				)
			}
			verifiedCanary, err := rolloutdriver.VerifyCanaryV1(
				rolloutdriver.VerifyCanaryInputV1{
					Prepared: target.prepared, Admission: *target.admission,
					CommandRaw: canaryRaw, ResultRaw: resultRaw,
					ReceiptPublicKey: target.gatewayPublic,
				},
			)
			if err != nil {
				return markRolloutActionRequired(
					store, run, index, stdout, jsonOutput, reasonCanaryInvalid, err,
				)
			}
			if len(target.canaryResultRaw) != 0 {
				if !bytes.Equal(target.canaryResultRaw, resultRaw) {
					return markRolloutActionRequired(
						store, run, index, stdout, jsonOutput,
						reasonCanaryInvalid,
						errors.New("live canary result differs from retained result"),
					)
				}
			} else if err := writeRolloutTargetArtifact(
				store, index, rolloutstore.TargetCanaryResultKind, resultRaw,
			); err != nil {
				return err
			}
			target.canaryResultRaw = resultRaw
			target.verifiedCanary = &verifiedCanary
			if err := appendRolloutTargetPhase(
				store, run, index, rollout.PhaseAgentReportedTerminal,
				func(next *rollout.TargetStateV1) {
					verifiedResult := verifiedCanary.Result()
					next.CanaryResultDigest = verifiedResult.TerminalResultDigest
					next.CanaryResultBytes = verifiedResult.TerminalResultBytes
				},
			); err != nil {
				return err
			}

		case rollout.PhaseAgentReportedTerminal:
			phaseDeadline, err := rolloutTargetPhaseDeadline(
				run.plan, state, target.timeouts.EvidenceSeconds,
			)
			if err != nil {
				return markPhaseDeadline(store, run, index, stdout, jsonOutput, err)
			}
			if len(target.captureRaw) == 0 {
				captureState, waitErr := waitRolloutEvidenceCapture(
					client, run.plan, target.prepared, phaseDeadline,
				)
				if waitErr != nil {
					if sticky, ok := waitErr.(*rolloutStickyError); ok {
						return markRolloutActionRequired(
							store, run, index, stdout, jsonOutput,
							sticky.reason, sticky.cause,
						)
					}
					return waitErr
				}
				ctx, cancel, err := rolloutControlContext(phaseDeadline)
				if err != nil {
					return markPhaseDeadline(store, run, index, stdout, jsonOutput, err)
				}
				var sealErr error
				if captureState.State != controlstore.EvidenceCaptureSealed {
					_, sealErr = client.SealExecutorEvidenceCapture(
						ctx, target.prepared.Target().NodeID,
						rolloutCaptureID(run.plan, index),
						target.prepared.Target().CanaryCommandID,
					)
				} else if captureState.CanaryCommandID != target.prepared.Target().CanaryCommandID {
					sealErr = errors.New("sealed evidence capture names another canary command")
				}
				cancel()
				if sealErr != nil {
					if rolloutPermanentControlError(sealErr) {
						return markRolloutActionRequired(
							store, run, index, stdout, jsonOutput,
							reasonEvidenceInvalid, sealErr,
						)
					}
					return fmt.Errorf("seal rollout evidence capture: %w", sealErr)
				}
				ctx, cancel, err = rolloutControlContext(phaseDeadline)
				if err != nil {
					return markPhaseDeadline(store, run, index, stdout, jsonOutput, err)
				}
				exported, exportErr := client.ExportExecutorEvidenceCapture(
					ctx, target.prepared.Target().NodeID,
					rolloutCaptureID(run.plan, index),
				)
				cancel()
				if exportErr != nil {
					if rolloutPermanentControlError(exportErr) {
						return markRolloutActionRequired(
							store, run, index, stdout, jsonOutput,
							reasonEvidenceInvalid, exportErr,
						)
					}
					return fmt.Errorf("export rollout evidence capture: %w", exportErr)
				}
				captureRaw, err := json.Marshal(exported)
				if err != nil {
					return err
				}
				capture, err := controlcapture.VerifyJSONV1(captureRaw, run.witnessPublic)
				if err != nil {
					return markRolloutActionRequired(
						store, run, index, stdout, jsonOutput, reasonEvidenceInvalid, err,
					)
				}
				if err := correlateRolloutCapture(target, capture); err != nil {
					return markRolloutActionRequired(
						store, run, index, stdout, jsonOutput, reasonEvidenceInvalid, err,
					)
				}
				if err := writeRolloutTargetArtifact(
					store, index, rolloutstore.TargetCaptureExportKind, captureRaw,
				); err != nil {
					return err
				}
				target.captureRaw = captureRaw
			}
			if err := appendRolloutTargetPhase(
				store, run, index, rollout.PhaseEvidenceCollected, nil,
			); err != nil {
				return err
			}

		case rollout.PhaseEvidenceCollected:
			if err := ensureRolloutActivationProof(store, run, index); err != nil {
				return markRolloutActionRequired(
					store, run, index, stdout, jsonOutput, reasonEvidenceInvalid, err,
				)
			}
			if err := appendRolloutTargetPhase(
				store, run, index, rollout.PhasePassed,
				func(next *rollout.TargetStateV1) {
					proof, parseErr := activation.ParseProofV1(target.activationProof)
					if parseErr != nil {
						return
					}
					completed, _ := time.Parse(time.RFC3339Nano, proof.CompletedAt)
					updated, _ := time.Parse(time.RFC3339Nano, next.UpdatedAt)
					if !updated.After(completed) {
						next.UpdatedAt = completed.Add(time.Nanosecond).Format(time.RFC3339Nano)
					}
				},
			); err != nil {
				return err
			}

		case rollout.PhasePassed:
			return nil
		case rollout.PhaseActionRequired:
			return writeExistingRolloutActionRequired(stdout, *run, jsonOutput)
		default:
			return fmt.Errorf("unsupported rollout phase %q", state.Phase)
		}
	}
}

func submitExactRolloutCommand(
	client *controlclient.Client,
	plan rollout.PlanV1,
	prepared rolloutdriver.PreparedTargetV1,
	raw []byte,
	kind string,
	deadline time.Time,
) error {
	if err := ensureRolloutCommandUnexpired(raw); err != nil {
		return &rolloutStickyError{reason: reasonPhaseTimeout, cause: err}
	}
	ctx, cancel, err := rolloutControlContext(deadline)
	if err != nil {
		return &rolloutStickyError{reason: reasonPhaseTimeout, cause: err}
	}
	command, callErr := client.SubmitCommand(
		ctx, plan.TenantID, prepared.Target().NodeID, raw,
	)
	cancel()
	if callErr != nil {
		if rolloutPermanentControlError(callErr) {
			return &rolloutStickyError{reason: rolloutCommandConflictReason(kind), cause: callErr}
		}
		return fmt.Errorf("submit exact %s rollout command: %w", kind, callErr)
	}
	if err := validateRolloutControlCommand(command, plan, prepared, raw, kind); err != nil {
		return &rolloutStickyError{reason: rolloutCommandConflictReason(kind), cause: err}
	}
	return nil
}

func waitRolloutCommand(
	client *controlclient.Client,
	plan rollout.PlanV1,
	prepared rolloutdriver.PreparedTargetV1,
	raw []byte,
	kind string,
	deadline time.Time,
) (controlclient.Command, error) {
	delay := 100 * time.Millisecond
	for {
		if !deadline.After(timeNow().UTC()) {
			return controlclient.Command{}, &rolloutStickyError{
				reason: reasonPhaseTimeout,
				cause:  fmt.Errorf("%s command phase deadline expired", kind),
			}
		}
		ctx, cancel, err := rolloutControlContext(deadline)
		if err != nil {
			return controlclient.Command{}, &rolloutStickyError{reason: reasonPhaseTimeout, cause: err}
		}
		command, callErr := client.GetCommand(
			ctx, plan.TenantID, prepared.Target().NodeID,
			preparedCommandID(prepared, kind),
		)
		cancel()
		if callErr != nil {
			if rolloutPermanentControlError(callErr) {
				return controlclient.Command{}, &rolloutStickyError{
					reason: rolloutCommandConflictReason(kind), cause: callErr,
				}
			}
			return controlclient.Command{}, fmt.Errorf("observe %s rollout command: %w", kind, callErr)
		}
		if err := validateRolloutControlCommand(command, plan, prepared, raw, kind); err != nil {
			return controlclient.Command{}, &rolloutStickyError{
				reason: rolloutCommandConflictReason(kind), cause: err,
			}
		}
		if command.State == string(controlstore.CommandTerminal) {
			if command.TerminalStatus != controlprotocol.ExecutorStatusDone {
				reason := reasonCanaryTerminal
				switch kind {
				case "admit":
					reason = reasonAdmitTerminal
				case "start":
					reason = reasonStartTerminal
				}
				return controlclient.Command{}, &rolloutStickyError{
					reason: reason,
					cause:  fmt.Errorf("%s command ended with %s", kind, command.TerminalStatus),
				}
			}
			return command, nil
		}
		if command.State != string(controlstore.CommandPending) &&
			command.State != string(controlstore.CommandLeased) {
			return controlclient.Command{}, &rolloutStickyError{
				reason: rolloutCommandConflictReason(kind),
				cause:  fmt.Errorf("%s command has unknown controller state %q", kind, command.State),
			}
		}
		remaining := deadline.Sub(timeNow().UTC())
		if remaining <= 0 {
			return controlclient.Command{}, &rolloutStickyError{
				reason: reasonPhaseTimeout, cause: errors.New("command phase deadline expired"),
			}
		}
		if delay > remaining {
			delay = remaining
		}
		ctx, cancel = context.WithTimeout(context.Background(), remaining)
		err = rolloutPollSleep(ctx, delay)
		cancel()
		if err != nil {
			return controlclient.Command{}, &rolloutStickyError{reason: reasonPhaseTimeout, cause: err}
		}
		if delay < 2*time.Second {
			delay *= 2
			if delay > 2*time.Second {
				delay = 2 * time.Second
			}
		}
	}
}

func waitRolloutEvidenceCapture(
	client *controlclient.Client,
	plan rollout.PlanV1,
	prepared rolloutdriver.PreparedTargetV1,
	deadline time.Time,
) (controlstore.EvidenceCapture, error) {
	delay := 100 * time.Millisecond
	captureID := rolloutCaptureID(plan, prepared.TargetIndex())
	for {
		if !deadline.After(timeNow().UTC()) {
			return controlstore.EvidenceCapture{}, &rolloutStickyError{
				reason: reasonPhaseTimeout,
				cause:  errors.New("evidence publication deadline expired"),
			}
		}
		ctx, cancel, err := rolloutControlContext(deadline)
		if err != nil {
			return controlstore.EvidenceCapture{}, &rolloutStickyError{
				reason: reasonPhaseTimeout, cause: err,
			}
		}
		capture, callErr := client.GetExecutorEvidenceCapture(
			ctx, prepared.Target().NodeID, captureID,
		)
		cancel()
		if callErr != nil {
			if rolloutPermanentControlError(callErr) {
				return controlstore.EvidenceCapture{}, &rolloutStickyError{
					reason: reasonEvidenceInvalid, cause: callErr,
				}
			}
			return controlstore.EvidenceCapture{},
				fmt.Errorf("observe rollout evidence capture: %w", callErr)
		}
		if capture.RequestID != rolloutCaptureRequestID(plan, prepared.TargetIndex()) ||
			capture.TenantID != plan.TenantID ||
			capture.RuntimeRef != prepared.RuntimeRef() ||
			capture.Generation != prepared.Target().InstanceGeneration ||
			capture.ActivationID != prepared.Target().ActivationID ||
			capture.ActivationBeginDigest != prepared.ExecutorBeginDigest() {
			return controlstore.EvidenceCapture{}, &rolloutStickyError{
				reason: reasonEvidenceInvalid,
				cause:  errors.New("controller evidence capture changed its prepared target binding"),
			}
		}
		switch capture.State {
		case controlstore.EvidenceCaptureObserved, controlstore.EvidenceCaptureSealed:
			return capture, nil
		case controlstore.EvidenceCaptureFailed, controlstore.EvidenceCaptureExpired:
			return controlstore.EvidenceCapture{}, &rolloutStickyError{
				reason: reasonEvidenceInvalid,
				cause:  fmt.Errorf("evidence capture ended in %s (%s)", capture.State, capture.Failure),
			}
		case controlstore.EvidenceCaptureArmed:
			// A successful canary report and its signed Executor checkpoint are
			// published through independent durable paths. Armed is expected here
			// until the controller observes the evidence delta.
		default:
			return controlstore.EvidenceCapture{}, &rolloutStickyError{
				reason: reasonEvidenceInvalid,
				cause:  fmt.Errorf("evidence capture has unknown state %q", capture.State),
			}
		}
		remaining := deadline.Sub(timeNow().UTC())
		if remaining <= 0 {
			continue
		}
		if delay > remaining {
			delay = remaining
		}
		ctx, cancel = context.WithTimeout(context.Background(), remaining)
		err = rolloutPollSleep(ctx, delay)
		cancel()
		if err != nil {
			return controlstore.EvidenceCapture{}, &rolloutStickyError{
				reason: reasonPhaseTimeout, cause: err,
			}
		}
		if delay < 2*time.Second {
			delay *= 2
			if delay > 2*time.Second {
				delay = 2 * time.Second
			}
		}
	}
}

func validateRolloutArmedCapture(
	capture controlstore.EvidenceCapture,
	plan rollout.PlanV1,
	prepared rolloutdriver.PreparedTargetV1,
	index uint16,
	ttl time.Duration,
) error {
	target := prepared.Target()
	if capture.CaptureID != rolloutCaptureID(plan, index) ||
		capture.RequestID != rolloutCaptureRequestID(plan, index) ||
		capture.NodeID != target.NodeID || capture.TenantID != plan.TenantID ||
		capture.RuntimeRef != prepared.RuntimeRef() ||
		capture.Generation != target.InstanceGeneration ||
		capture.ActivationID != target.ActivationID ||
		capture.ActivationBeginDigest != prepared.ExecutorBeginDigest() {
		return errors.New("controller evidence capture arm changed its deterministic target binding")
	}
	armedAt, armedErr := time.Parse(time.RFC3339Nano, capture.ArmedAt)
	expiresAt, expiryErr := time.Parse(time.RFC3339Nano, capture.ExpiresAt)
	if capture.State != controlstore.EvidenceCaptureArmed ||
		armedErr != nil || expiryErr != nil || expiresAt.Sub(armedAt) != ttl ||
		!expiresAt.After(timeNow().UTC()) {
		return errors.New("controller evidence capture replay is not armed with its fixed unexpired expiry")
	}
	return nil
}

func validateRolloutControlCommand(
	command controlclient.Command,
	plan rollout.PlanV1,
	prepared rolloutdriver.PreparedTargetV1,
	raw []byte,
	kind string,
) error {
	target := prepared.Target()
	if command.CommandID != preparedCommandID(prepared, kind) ||
		command.TenantID != plan.TenantID || command.NodeID != target.NodeID ||
		command.CommandDigest != dsse.Digest(raw) || command.CommandKind != kind ||
		command.SignedRuntimeRef != prepared.OuterRuntimeRef() ||
		command.SignedClaimGeneration != target.ClaimGeneration ||
		command.SignedInstanceGeneration != target.InstanceGeneration {
		return errors.New("controller command projection differs from exact signed rollout command")
	}
	if command.DeliveryProtocol != 0 && command.DeliveryProtocol != controlprotocol.ExecutorProtocolV4 {
		return errors.New("rollout command was delivered through a non-protocol-4 node")
	}
	return nil
}

func preparedCommandID(prepared rolloutdriver.PreparedTargetV1, kind string) string {
	switch kind {
	case "admit":
		return prepared.Target().AdmitCommandID
	case "start":
		return prepared.Target().StartCommandID
	case "activation-canary":
		return prepared.Target().CanaryCommandID
	default:
		return ""
	}
}

func ensureRolloutCommandUnexpired(raw []byte) error {
	_, err := rolloutStoredCommandDeadline(raw, false)
	return err
}

func rolloutStoredCommandDeadline(raw []byte, canary bool) (time.Time, error) {
	if len(raw) == 0 {
		return time.Time{}, errors.New("stored rollout command is unavailable")
	}
	envelope, err := dsse.Parse(raw)
	if err != nil {
		return time.Time{}, err
	}
	var statement admission.CommandStatement
	payload, err := envelopePayload(envelope)
	if err != nil {
		return time.Time{}, err
	}
	if err := dsse.DecodeStrictInto(payload, dsse.MaxPayloadBytes, &statement); err != nil {
		return time.Time{}, err
	}
	deadline, err := time.Parse(time.RFC3339Nano, statement.ExpiresAt)
	if err != nil {
		return time.Time{}, errors.New("stored rollout command has an invalid expiry")
	}
	if canary {
		closed, err := activationcanary.ParseCommandV1(statement.Payload)
		if err != nil {
			return time.Time{}, fmt.Errorf("parse stored closed canary deadline: %w", err)
		}
		inner, err := time.Parse(time.RFC3339Nano, closed.Deadline)
		if err != nil {
			return time.Time{}, errors.New("stored closed canary has an invalid deadline")
		}
		if inner.Before(deadline) {
			deadline = inner
		}
	}
	if !deadline.After(timeNow().UTC()) {
		return deadline, errors.New("stored rollout command authority expired")
	}
	return deadline, nil
}

func newRolloutSigningWindow(
	keys rolloutRunKeys,
	phaseDeadline time.Time,
) (rolloutdriver.SigningWindowV1, error) {
	now := timeNow().UTC()
	if keys.authorizationContextTime.IsZero() || now.Before(keys.authorizationContextTime) {
		return rolloutdriver.SigningWindowV1{}, errors.New("coordinator clock precedes the active rollout authorization")
	}
	expires := now.Add(rolloutCommandMaximumValidity)
	if phaseDeadline.Before(expires) {
		expires = phaseDeadline
	}
	if !expires.After(now) {
		return rolloutdriver.SigningWindowV1{}, errors.New("rollout command phase has no validity remaining")
	}
	return rolloutdriver.SigningWindowV1{
		KeyID: keys.commandID, PrivateKey: keys.commandPrivate,
		PublicKey:                  keys.commandPublic,
		AuthorizationContextDigest: keys.authorizationContextDigest,
		IssuedAt:                   now,
		ValidFor:                   expires.Sub(now),
	}, nil
}

func rolloutTargetPhaseDeadline(
	plan rollout.PlanV1,
	state rollout.TargetStateV1,
	seconds uint32,
) (time.Time, error) {
	started, err := time.Parse(time.RFC3339Nano, state.UpdatedAt)
	if err != nil {
		return time.Time{}, errors.New("rollout phase has no valid fixed deadline")
	}
	if seconds == 0 {
		return time.Time{}, errors.New("rollout phase has no timeout")
	}
	deadline := started.Add(time.Duration(seconds) * time.Second)
	global, _ := time.Parse(time.RFC3339Nano, plan.Deadline)
	if global.Before(deadline) {
		deadline = global
	}
	if !deadline.After(timeNow().UTC()) {
		return deadline, errors.New("rollout phase deadline expired")
	}
	return deadline, nil
}

func rolloutPhaseDeadlineFromNow(
	plan rollout.PlanV1,
	seconds uint32,
) (time.Time, error) {
	if seconds == 0 {
		return time.Time{}, errors.New("rollout phase has no timeout")
	}
	now := timeNow().UTC()
	deadline := now.Add(time.Duration(seconds) * time.Second)
	global, _ := time.Parse(time.RFC3339Nano, plan.Deadline)
	if global.Before(deadline) {
		deadline = global
	}
	if !deadline.After(now) {
		return deadline, errors.New("rollout phase deadline expired")
	}
	return deadline, nil
}

func rolloutControlContext(deadline time.Time) (context.Context, context.CancelFunc, error) {
	now := timeNow().UTC()
	if !deadline.After(now) {
		return nil, nil, errors.New("rollout control-call deadline expired")
	}
	callDeadline := now.Add(30 * time.Second)
	if deadline.Before(callDeadline) {
		callDeadline = deadline
	}
	ctx, cancel := context.WithTimeout(context.Background(), callDeadline.Sub(now))
	return ctx, cancel, nil
}

func rolloutPermanentControlError(err error) bool {
	var api *controlclient.APIError
	if !errors.As(err, &api) {
		return false
	}
	switch api.Status {
	case http.StatusNotFound, http.StatusConflict, http.StatusGone,
		http.StatusUnprocessableEntity:
		return true
	default:
		// Authentication, authorization, throttling, timeout, and server errors
		// are operator/transport conditions. They do not prove a target failure
		// and therefore must not consume the sticky rollout state.
		return false
	}
}

func rolloutCommandConflictReason(kind string) string {
	switch kind {
	case "admit":
		return reasonAdmitConflict
	case "start":
		return reasonStartConflict
	default:
		return reasonCanaryConflict
	}
}

func rolloutCaptureID(plan rollout.PlanV1, index uint16) string {
	return derivedRolloutIdentifier(
		"capture", plan.RolloutID, int(index), plan.Targets[index].NodeID,
	)
}

func rolloutCaptureRequestID(plan rollout.PlanV1, index uint16) string {
	return derivedRolloutIdentifier(
		"capture-request", plan.RolloutID, int(index), plan.Targets[index].NodeID,
	)
}

func appendRolloutTargetPhase(
	store *rolloutstore.Store,
	run *verifiedRolloutRun,
	index uint16,
	phase string,
	mutate func(*rollout.TargetStateV1),
) error {
	current := run.states[index]
	next := current
	next.Phase = phase
	next.ActionRequiredReason = ""
	next.UpdatedAt = nextRolloutStateTime(current.UpdatedAt).Format(time.RFC3339Nano)
	if mutate != nil {
		mutate(&next)
	}
	deadline, _ := time.Parse(time.RFC3339Nano, run.plan.Deadline)
	nextTime, _ := time.Parse(time.RFC3339Nano, next.UpdatedAt)
	if phase != rollout.PhaseActionRequired && nextTime.After(deadline) {
		return errors.New("rollout target progress would exceed the global deadline")
	}
	if err := rollout.ValidateTargetTransitionV1(current, next); err != nil {
		return err
	}
	if err := rollout.CorrelateTargetStateV1(run.planRaw, next); err != nil {
		return err
	}
	raw, err := rollout.MarshalTargetStateV1(next)
	if err != nil {
		return err
	}
	if _, err := store.AppendTargetState(index, run.stateCounts[index], raw); err != nil {
		return err
	}
	run.stateCounts[index]++
	run.states[index] = next
	return nil
}

func nextRolloutStateTime(previous string) time.Time {
	now := timeNow().UTC()
	prior, err := time.Parse(time.RFC3339Nano, previous)
	if err == nil && !now.After(prior) {
		now = prior.Add(time.Nanosecond)
	}
	return now
}

func markRolloutActionRequired(
	store *rolloutstore.Store,
	run *verifiedRolloutRun,
	index uint16,
	stdout io.Writer,
	jsonOutput bool,
	reason string,
	cause error,
) error {
	if run.states[index].Phase != rollout.PhaseActionRequired {
		if err := appendRolloutTargetPhase(
			store, run, index, rollout.PhaseActionRequired,
			func(next *rollout.TargetStateV1) { next.ActionRequiredReason = reason },
		); err != nil {
			return errors.Join(cause, err)
		}
	}
	return errors.Join(cause, writeVerifiedRolloutRunStatus(stdout, *run, jsonOutput))
}

func markPhaseDeadline(
	store *rolloutstore.Store,
	run *verifiedRolloutRun,
	index uint16,
	stdout io.Writer,
	jsonOutput bool,
	cause error,
) error {
	return markRolloutActionRequired(
		store, run, index, stdout, jsonOutput, reasonPhaseTimeout, cause,
	)
}

func writeExistingRolloutActionRequired(
	stdout io.Writer,
	run verifiedRolloutRun,
	jsonOutput bool,
) error {
	return errors.Join(
		errors.New("rollout is in sticky action_required state"),
		writeVerifiedRolloutRunStatus(stdout, run, jsonOutput),
	)
}

func writeRolloutTargetArtifact(
	store *rolloutstore.Store,
	index uint16,
	kind string,
	raw []byte,
) error {
	name, err := rolloutstore.TargetArtifactName(index, kind)
	if err != nil {
		return err
	}
	if err := store.WriteOnce(name, raw); err != nil {
		return fmt.Errorf("write rollout artifact %q: %w", name, err)
	}
	return nil
}

func ensureRolloutActivationProof(
	store *rolloutstore.Store,
	run *verifiedRolloutRun,
	index uint16,
) error {
	target := &run.targets[index]
	if target.verifiedCanary == nil || len(target.captureRaw) == 0 {
		return errors.New("activation proof companions are incomplete")
	}
	if len(target.activationProof) != 0 {
		if len(target.activationState) == 0 {
			return errors.New("activation proof has no exact state companion")
		}
		return verifyRetainedRolloutActivationProof(
			target, target.activationState, target.activationProof,
		)
	}
	portable, err := controlprotocol.DecodeControllerEvidenceCaptureV1(target.captureRaw)
	if err != nil {
		return err
	}
	verifiedGateway, err := gatewayResultFromVerifiedCanary(target)
	if err != nil {
		return err
	}
	var activationState activation.StateV1
	activationStateRaw := target.activationState
	if len(activationStateRaw) != 0 {
		activationState, err = activation.ParseStateV1(activationStateRaw)
		if err != nil || activationState.Phase != activation.PhasePassed ||
			activationState.Binding != target.prepared.Binding() ||
			activationState.RuntimeRef != target.prepared.RuntimeRef() {
			return errors.New("partial activation state differs from verified rollout target")
		}
	} else {
		completed := nextRolloutStateTime(run.states[index].UpdatedAt)
		exportedAt, err := time.Parse(time.RFC3339Nano, portable.Statement.ExportedAt)
		if err != nil {
			return err
		}
		if completed.Before(exportedAt) {
			completed = exportedAt
		}
		deadline, _ := time.Parse(time.RFC3339Nano, run.plan.Deadline)
		if completed.After(deadline) {
			return errors.New("verified evidence completed after the rollout deadline")
		}
		activationState = activation.StateV1{
			SchemaVersion: activation.StateSchemaV1,
			Binding:       target.prepared.Binding(),
			Phase:         activation.PhasePassed,
			RuntimeRef:    target.prepared.RuntimeRef(),
			UpdatedAt:     completed.Format(time.RFC3339Nano),
		}
		activationStateRaw, err = activation.MarshalStateV1(activationState)
		if err != nil {
			return err
		}
		if err := writeRolloutTargetArtifact(
			store, index, rolloutstore.TargetActivationStateKind, activationStateRaw,
		); err != nil {
			return err
		}
		target.activationState = activationStateRaw
	}
	statement := portable.Statement
	proof := activation.ProofV1{
		SchemaVersion:            activation.ProofSchemaV1,
		Binding:                  activationState.Binding,
		StateDigest:              dsse.Digest(activationStateRaw),
		RuntimeRef:               activationState.RuntimeRef,
		Canary:                   verifiedGateway.Canary,
		ExecutorBeginDigest:      target.prepared.ExecutorBeginDigest(),
		ExecutorCheckpointDigest: dsse.Digest(target.verifiedCanary.CheckpointRaw()),
		ExecutorEvidence: activation.ReceiptCoordinateV1{
			ReceiptNodeID:   statement.FinalHead.ReceiptNodeID,
			ReceiptEpoch:    statement.FinalHead.ReceiptEpoch,
			Sequence:        statement.FinalHead.Sequence,
			ChainHash:       statement.FinalHead.ChainHash,
			PublicKeySHA256: statement.FinalHead.PublicKeySHA256,
		},
		GatewayEvidence: verifiedGateway.Coordinate,
		Witness: activation.WitnessCoordinateV1{
			ControllerInstanceID:   statement.ControllerInstanceID,
			ControlNodeID:          statement.NodeID,
			ReceiptNodeID:          statement.FinalHead.ReceiptNodeID,
			ReceiptEpoch:           statement.FinalHead.ReceiptEpoch,
			Sequence:               statement.FinalHead.Sequence,
			ChainHash:              statement.FinalHead.ChainHash,
			ReceiptPublicKeySHA256: statement.FinalHead.PublicKeySHA256,
			WitnessPublicKeySHA256: portable.WitnessPublicKeySHA256,
			WitnessExportDigest:    dsse.Digest(target.captureRaw),
			WitnessedAt:            statement.ExportedAt,
		},
		CompletedAt: activationState.UpdatedAt,
	}
	activationProofRaw, err := activation.MarshalProofV1(proof)
	if err != nil {
		return err
	}
	if _, err := activation.CorrelateProofV1(
		target.prepared.ActivationPlanRaw(), activationStateRaw, activationProofRaw,
	); err != nil {
		return err
	}
	if err := writeRolloutTargetArtifact(
		store, index, rolloutstore.TargetActivationProofKind, activationProofRaw,
	); err != nil {
		return err
	}
	target.activationProof = activationProofRaw
	return verifyRetainedRolloutActivationProof(target, activationStateRaw, activationProofRaw)
}

func ensureRolloutProofManifest(
	store *rolloutstore.Store,
	run *verifiedRolloutRun,
	allowWrite bool,
) error {
	planDigest := dsse.Digest(run.planRaw)
	planAuthorizationRaw, err := store.Read(
		rolloutstore.PlanAuthorizationFileName,
		rollout.MaxPlanAuthorizationEnvelopeBytes,
	)
	if err != nil {
		return fmt.Errorf("read proof plan authorization: %w", err)
	}
	batches, err := run.plan.Batches()
	if err != nil {
		return err
	}
	promotionNames, err := store.ListBatchPromotions()
	if err != nil {
		return err
	}
	if len(promotionNames) != len(batches)-1 {
		return errors.New("aggregate rollout proof requires every signed batch promotion")
	}
	batchPromotionRaws := make([][]byte, len(promotionNames))
	batchPromotionDigests := make([]string, len(promotionNames))
	for index, name := range promotionNames {
		expected, nameErr := rolloutstore.BatchPromotionName(uint16(index + 1))
		if nameErr != nil || name != expected {
			return errors.New("aggregate rollout proof promotion inventory is not contiguous")
		}
		batchPromotionRaws[index], err = store.Read(
			name, rollout.MaxBatchPromotionEnvelopeBytes,
		)
		if err != nil {
			return err
		}
		batchPromotionDigests[index] = dsse.Digest(batchPromotionRaws[index])
	}
	latestStateRaws := make([][]byte, len(run.targets))
	admitCommandRaws := make([][]byte, len(run.targets))
	startCommandRaws := make([][]byte, len(run.targets))
	canaryCommandRaws := make([][]byte, len(run.targets))
	activationPlanRaws := make([][]byte, len(run.targets))
	activationStateRaws := make([][]byte, len(run.targets))
	activationProofRaws := make([][]byte, len(run.targets))
	entries := make([]rollout.TargetProofV1, len(run.targets))
	completed := timeNow().UTC()
	for index := range run.targets {
		if run.states[index].Phase != rollout.PhasePassed {
			return errors.New("aggregate rollout proof requires every target to pass")
		}
		name, err := rolloutstore.TargetStateName(uint16(index), run.stateCounts[index]-1)
		if err != nil {
			return err
		}
		latestStateRaws[index], err = store.Read(name, rollout.MaxTargetStateBytes)
		if err != nil {
			return err
		}
		activationPlanRaws[index] = run.targets[index].prepared.ActivationPlanRaw()
		admitCommandRaws[index] = run.targets[index].admitCommandRaw
		startCommandRaws[index] = run.targets[index].startCommandRaw
		canaryCommandRaws[index] = run.targets[index].canaryCommandRaw
		activationStateRaws[index] = run.targets[index].activationState
		activationProofRaws[index] = run.targets[index].activationProof
		if len(admitCommandRaws[index]) == 0 ||
			len(startCommandRaws[index]) == 0 ||
			len(canaryCommandRaws[index]) == 0 ||
			len(activationStateRaws[index]) == 0 || len(activationProofRaws[index]) == 0 {
			return errors.New("passed rollout target is missing command or activation proof companions")
		}
		stateTime, _ := time.Parse(time.RFC3339Nano, run.states[index].UpdatedAt)
		proof, _ := activation.ParseProofV1(activationProofRaws[index])
		proofTime, _ := time.Parse(time.RFC3339Nano, proof.CompletedAt)
		if completed.Before(stateTime) {
			completed = stateTime
		}
		if completed.Before(proofTime) {
			completed = proofTime
		}
		entries[index] = rollout.TargetProofV1{
			TargetIndex: uint16(index), NodeID: run.plan.Targets[index].NodeID,
			ActivationID:          run.plan.Targets[index].ActivationID,
			ActivationPlanDigest:  run.plan.Targets[index].ActivationPlanDigest,
			AdmitCommandDigest:    dsse.Digest(admitCommandRaws[index]),
			StartCommandDigest:    dsse.Digest(startCommandRaws[index]),
			CanaryCommandDigest:   dsse.Digest(canaryCommandRaws[index]),
			TargetStateDigest:     dsse.Digest(latestStateRaws[index]),
			ActivationProofDigest: dsse.Digest(activationProofRaws[index]),
		}
	}
	manifest := rollout.ProofManifestV1{
		SchemaVersion:           rollout.ProofManifestSchemaV1,
		RolloutID:               run.plan.RolloutID,
		PlanDigest:              planDigest,
		PlanAuthorizationDigest: dsse.Digest(planAuthorizationRaw),
		BatchPromotionDigests:   batchPromotionDigests,
		Targets:                 entries,
		CompletedAt:             completed.Format(time.RFC3339Nano),
	}
	manifestRaw, err := rollout.MarshalProofManifestV1(manifest)
	if err != nil {
		return err
	}
	existing, present, err := optionalRolloutFixedArtifact(
		store, rolloutstore.ProofFileName, rollout.MaxProofManifestBytes,
	)
	if err != nil {
		return err
	}
	if present {
		manifestRaw = existing
	}
	if _, err := rollout.CorrelateProofManifestV1(
		run.planRaw, planAuthorizationRaw, batchPromotionRaws,
		admitCommandRaws, startCommandRaws, canaryCommandRaws,
		latestStateRaws, activationPlanRaws,
		activationStateRaws, activationProofRaws, manifestRaw,
	); err != nil {
		return err
	}
	if present {
		return nil
	}
	if !allowWrite {
		return errors.New("aggregate rollout proof is missing during read-only recovery verification")
	}
	verifiedChain, err := verifyCompletedRolloutAuthorization(store, *run)
	if err != nil {
		return fmt.Errorf("authenticate complete rollout authorization before publishing proof: %w", err)
	}
	verifiedPromotions := orderedRolloutPromotionRaws(verifiedChain)
	if !bytes.Equal(verifiedChain.planRawRecord, planAuthorizationRaw) ||
		len(verifiedPromotions) != len(batchPromotionRaws) {
		return errors.New("verified rollout authorization differs from proof companions")
	}
	for index := range verifiedPromotions {
		if !bytes.Equal(verifiedPromotions[index], batchPromotionRaws[index]) {
			return errors.New("verified rollout promotion differs from proof companion")
		}
	}
	run.authorization = &verifiedChain
	if err := store.WriteOnce(rolloutstore.ProofFileName, manifestRaw); err != nil {
		return err
	}
	return nil
}

func optionalRolloutFixedArtifact(
	store *rolloutstore.Store,
	name string,
	limit int64,
) ([]byte, bool, error) {
	raw, err := store.Read(name, limit)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return raw, true, nil
}

func envelopePayload(envelope dsse.Envelope) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil || base64.StdEncoding.EncodeToString(decoded) != envelope.Payload {
		return nil, errors.New("DSSE payload is not canonical base64")
	}
	if len(decoded) == 0 {
		return nil, errors.New("DSSE payload is empty")
	}
	return decoded, nil
}
