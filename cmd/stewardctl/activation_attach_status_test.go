package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/activation"
	"github.com/hardrails/steward/internal/activationstore"
	"github.com/hardrails/steward/internal/dsse"
)

type activationStatusFixture struct {
	directory string
	planRaw   []byte
	plan      activation.PlanV1
	states    []activation.StateV1
	rawStates [][]byte
}

func TestActivationStatusReportsUnverifiedWaitingActionsAndPassedProof(t *testing.T) {
	for _, phase := range []string{
		activation.PhaseNew,
		activation.PhaseReleaseVerified,
		activation.PhasePreflightPassed,
		activation.PhaseImageImported,
		activation.PhaseAdmitted,
		activation.PhaseRunning,
		activation.PhaseCanaryAuthorized,
		activation.PhaseCanaryDispatched,
		activation.PhaseEvidenceCollected,
	} {
		t.Run("resume "+phase, func(t *testing.T) {
			fixture := newActivationStatusFixture(t, phase, "node-a")
			status := runActivationStatus(t, fixture.directory)
			if status.Phase != phase ||
				status.WaitingFor != activationWaitingRun ||
				status.NextCommand != activationResumeRunCommand ||
				status.ProofDigest != "" || status.Verified {
				t.Fatalf("status=%#v", status)
			}
		})
	}

	t.Run("canary task", func(t *testing.T) {
		fixture := newActivationStatusFixture(t, activation.PhaseCanaryChallengeReady, "node-a")
		status := runActivationStatus(t, fixture.directory)
		if status.ActivationID != fixture.plan.ActivationID ||
			status.Phase != activation.PhaseCanaryChallengeReady ||
			status.StateSequence != uint64(len(fixture.states)-1) ||
			status.RuntimeRef != fixture.states[len(fixture.states)-1].RuntimeRef ||
			status.WaitingFor != activationWaitingCanaryTask ||
			status.NextCommand != activationAttachCanaryTaskCommand ||
			status.ProofDigest != "" || status.Verified {
			t.Fatalf("status=%#v", status)
		}
	})

	t.Run("final witness", func(t *testing.T) {
		fixture := newActivationStatusFixture(t, activation.PhaseAgentReportedTerminal, "node-a")
		writeActivationCheckpointFixture(t, fixture)
		status := runActivationStatus(t, fixture.directory)
		if status.Phase != activation.PhaseAgentReportedTerminal ||
			status.WaitingFor != activationWaitingFinalWitness ||
			status.NextCommand != activationAttachWitnessCommand ||
			status.ProofDigest != "" || status.Verified {
			t.Fatalf("status=%#v", status)
		}
	})

	t.Run("checkpoint recovery", func(t *testing.T) {
		fixture := newActivationStatusFixture(t, activation.PhaseAgentReportedTerminal, "node-a")
		status := runActivationStatus(t, fixture.directory)
		if status.Phase != activation.PhaseAgentReportedTerminal ||
			status.WaitingFor != activationWaitingCheckpoint ||
			status.NextCommand != activationResumeRunCommand ||
			status.ProofDigest != "" || status.Verified {
			t.Fatalf("status=%#v", status)
		}
	})

	t.Run("passed proof", func(t *testing.T) {
		fixture := newActivationStatusFixture(t, activation.PhasePassed, "node-a")
		proofRaw := writeActivationProofFixture(t, fixture)
		status := runActivationStatus(t, fixture.directory)
		if status.Phase != activation.PhasePassed ||
			status.WaitingFor != "" || status.NextCommand != "" ||
			status.ProofDigest != dsse.Digest(proofRaw) || status.Verified {
			t.Fatalf("status=%#v", status)
		}
	})

	t.Run("passed without proof", func(t *testing.T) {
		fixture := newActivationStatusFixture(t, activation.PhasePassed, "node-a")
		err := run(
			[]string{"activation", "status", "-dir", fixture.directory},
			&bytes.Buffer{},
			&bytes.Buffer{},
		)
		if err == nil || !strings.Contains(err.Error(), "read activation proof") {
			t.Fatalf("missing proof error=%v", err)
		}
	})

	t.Run("action required advances generation", func(t *testing.T) {
		fixture := newActivationStatusFixture(
			t, activation.PhaseCanaryChallengeReady, "node-a",
		)
		store, err := activationstore.Open(fixture.directory)
		if err != nil {
			t.Fatal(err)
		}
		failed := fixture.states[len(fixture.states)-1]
		failed.Phase = activation.PhaseActionRequired
		failed.UpdatedAt = "2026-07-16T01:01:00Z"
		failed.ActionRequiredReason = "canary_timeout"
		raw, err := activation.MarshalStateV1(failed)
		if err != nil {
			_ = store.Close()
			t.Fatal(err)
		}
		if _, err := store.AppendState(uint64(len(fixture.states)), raw); err != nil {
			_ = store.Close()
			t.Fatal(err)
		}
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
		status := runActivationStatus(t, fixture.directory)
		if status.Phase != activation.PhaseActionRequired ||
			status.WaitingFor != "operator" ||
			status.NextCommand != activationReplaceFailedCommand(
				failed.Binding.Generation,
			) ||
			!strings.Contains(status.NextCommand, "new activation ID") ||
			!strings.Contains(status.NextCommand, "generation greater than 1") ||
			status.Verified {
			t.Fatalf("status=%#v", status)
		}
	})
}

func TestActivationStatusRejectsGapInvalidTransitionAndMismatchedPlan(t *testing.T) {
	t.Run("gap", func(t *testing.T) {
		fixture := newActivationStatusFixture(t, activation.PhaseReleaseVerified, "node-a")
		first, err := activationstore.StateCheckpointName(1)
		if err != nil {
			t.Fatal(err)
		}
		second, err := activationstore.StateCheckpointName(2)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(
			filepath.Join(fixture.directory, first),
			filepath.Join(fixture.directory, second),
		); err != nil {
			t.Fatal(err)
		}
		err = run(
			[]string{"activation", "status", "-dir", fixture.directory},
			&bytes.Buffer{},
			&bytes.Buffer{},
		)
		if err == nil {
			t.Fatal("state checkpoint gap was accepted")
		}
		if !strings.Contains(err.Error(), "not contiguous") &&
			!errors.Is(err, activationstore.ErrStateOrder) {
			t.Fatalf("gap error=%v", err)
		}
	})

	t.Run("transition", func(t *testing.T) {
		fixture := newActivationStatusFixture(t, activation.PhaseNew, "node-a")
		store, err := activationstore.Open(fixture.directory)
		if err != nil {
			t.Fatal(err)
		}
		next := fixture.states[0]
		next.Phase = activation.PhaseImageImported
		next.UpdatedAt = "2026-07-16T01:00:01Z"
		raw, err := activation.MarshalStateV1(next)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.AppendState(1, raw); err != nil {
			t.Fatal(err)
		}
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
		err = run(
			[]string{"activation", "status", "-dir", fixture.directory},
			&bytes.Buffer{},
			&bytes.Buffer{},
		)
		if err == nil || !strings.Contains(err.Error(), "phase must advance exactly one step") {
			t.Fatalf("transition error=%v", err)
		}
	})

	t.Run("plan binding", func(t *testing.T) {
		fixture := newActivationStatusFixture(t, activation.PhaseNew, "node-a")
		statePath := filepath.Join(fixture.directory, "state-000000000000.json")
		changed := fixture.states[0]
		changed.Binding.ReleaseDigest = activationTestDigest("f")
		raw, err := activation.MarshalStateV1(changed)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(statePath, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		err = run(
			[]string{"activation", "status", "-dir", fixture.directory},
			&bytes.Buffer{},
			&bytes.Buffer{},
		)
		if err == nil || !strings.Contains(err.Error(), "does not match") {
			t.Fatalf("binding error=%v", err)
		}
	})
}

func TestActivationAttachStoresOneStrictOwnerOnlyCanaryTask(t *testing.T) {
	activationFixture := newActivationStatusFixture(t, activation.PhaseCanaryChallengeReady, "node-a")
	taskFixture := newTaskCLIFixture(t)
	taskFixture.issue(t)
	taskRaw, err := os.ReadFile(taskFixture.bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	arguments := []string{
		"activation", "attach",
		"-dir", activationFixture.directory,
		"-kind", activationAttachmentCanaryTask,
		"-in", taskFixture.bundlePath,
	}
	if err := run(arguments, &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	status := decodeActivationStatus(t, output.Bytes())
	if status.Phase != activation.PhaseCanaryChallengeReady ||
		status.WaitingFor != activationWaitingRun ||
		status.NextCommand != activationResumeRunCommand ||
		status.Verified {
		t.Fatalf("status=%#v", status)
	}
	stored := readActivationFixtureArtifact(
		t,
		activationFixture.directory,
		activationstore.CanaryTaskFileName,
		maxTaskBundleBytes,
	)
	if !bytes.Equal(stored, taskRaw) {
		t.Fatal("stored canary task differs from the stable source snapshot")
	}
	if err := run(arguments, &bytes.Buffer{}, &bytes.Buffer{}); !errors.Is(err, activationstore.ErrAlreadyExists) {
		t.Fatalf("second attachment error=%v", err)
	}
	if after := readActivationFixtureArtifact(
		t,
		activationFixture.directory,
		activationstore.CanaryTaskFileName,
		maxTaskBundleBytes,
	); !bytes.Equal(after, taskRaw) {
		t.Fatal("failed second attachment changed the stored canary task")
	}
}

func TestActivationAttachRejectsMalformedOrLooselyProtectedCanaryTask(t *testing.T) {
	t.Run("strict JSON", func(t *testing.T) {
		fixture := newActivationStatusFixture(t, activation.PhaseCanaryChallengeReady, "node-a")
		input := filepath.Join(t.TempDir(), "task.json")
		if err := os.WriteFile(
			input,
			[]byte(`{"schema_version":"steward.task-bundle.v2","schema_version":"steward.task-bundle.v2"}`),
			0o600,
		); err != nil {
			t.Fatal(err)
		}
		err := run([]string{
			"activation", "attach", "-dir", fixture.directory,
			"-kind", activationAttachmentCanaryTask, "-in", input,
		}, &bytes.Buffer{}, &bytes.Buffer{})
		if err == nil || !strings.Contains(err.Error(), "duplicate") {
			t.Fatalf("strict JSON error=%v", err)
		}
		assertActivationArtifactMissing(t, fixture.directory, activationstore.CanaryTaskFileName)
	})

	t.Run("owner only", func(t *testing.T) {
		fixture := newActivationStatusFixture(t, activation.PhaseCanaryChallengeReady, "node-a")
		taskFixture := newTaskCLIFixture(t)
		taskFixture.issue(t)
		if err := os.Chmod(taskFixture.bundlePath, 0o644); err != nil {
			t.Fatal(err)
		}
		err := run([]string{
			"activation", "attach", "-dir", fixture.directory,
			"-kind", activationAttachmentCanaryTask, "-in", taskFixture.bundlePath,
		}, &bytes.Buffer{}, &bytes.Buffer{})
		if err == nil || !strings.Contains(err.Error(), "permission policy") {
			t.Fatalf("owner-only error=%v", err)
		}
		assertActivationArtifactMissing(t, fixture.directory, activationstore.CanaryTaskFileName)
	})
}

func TestActivationAttachStoresStrictFinalWitnessOnlyAtTerminalPhase(t *testing.T) {
	fixture := newActivationStatusFixture(t, activation.PhaseAgentReportedTerminal, "node-1")
	writeActivationCheckpointFixture(t, fixture)
	_, export, _ := stewardctlEvidenceFixtures(t)
	raw, err := json.Marshal(export)
	if err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(t.TempDir(), "final-witness.json")
	if err := os.WriteFile(input, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := run([]string{
		"activation", "attach", "-dir", fixture.directory,
		"-kind", activationAttachmentFinalWitness, "-in", input,
	}, &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	status := decodeActivationStatus(t, output.Bytes())
	if status.WaitingFor != activationWaitingRun ||
		status.NextCommand != activationResumeRunCommand ||
		status.Phase != activation.PhaseAgentReportedTerminal ||
		status.Verified {
		t.Fatalf("status=%#v", status)
	}
	stored := readActivationFixtureArtifact(
		t,
		fixture.directory,
		activationstore.ExecutorFinalWitnessFileName,
		int64(len(raw)),
	)
	if !bytes.Equal(stored, raw) {
		t.Fatal("stored final witness differs from the stable source snapshot")
	}

	wrongPhase := newActivationStatusFixture(t, activation.PhaseCanaryChallengeReady, "node-1")
	err = run([]string{
		"activation", "attach", "-dir", wrongPhase.directory,
		"-kind", activationAttachmentFinalWitness, "-in", input,
	}, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "only while activation is in") {
		t.Fatalf("phase error=%v", err)
	}
	assertActivationArtifactMissing(
		t,
		wrongPhase.directory,
		activationstore.ExecutorFinalWitnessFileName,
	)
}

func TestActivationAttachRejectsInvalidFinalWitnessWithoutWriting(t *testing.T) {
	t.Run("strict JSON", func(t *testing.T) {
		fixture := newActivationStatusFixture(t, activation.PhaseAgentReportedTerminal, "node-1")
		writeActivationCheckpointFixture(t, fixture)
		input := filepath.Join(t.TempDir(), "final-witness.json")
		if err := os.WriteFile(input, []byte(`{"payload_type":"wrong","unexpected":true}`), 0o600); err != nil {
			t.Fatal(err)
		}
		err := run([]string{
			"activation", "attach", "-dir", fixture.directory,
			"-kind", activationAttachmentFinalWitness, "-in", input,
		}, &bytes.Buffer{}, &bytes.Buffer{})
		if err == nil {
			t.Fatal("invalid final witness was accepted")
		}
		assertActivationArtifactMissing(
			t,
			fixture.directory,
			activationstore.ExecutorFinalWitnessFileName,
		)
	})

	t.Run("owner only", func(t *testing.T) {
		fixture := newActivationStatusFixture(t, activation.PhaseAgentReportedTerminal, "node-1")
		writeActivationCheckpointFixture(t, fixture)
		_, export, _ := stewardctlEvidenceFixtures(t)
		raw, err := json.Marshal(export)
		if err != nil {
			t.Fatal(err)
		}
		input := filepath.Join(t.TempDir(), "final-witness.json")
		if err := os.WriteFile(input, raw, 0o644); err != nil {
			t.Fatal(err)
		}
		err = run([]string{
			"activation", "attach", "-dir", fixture.directory,
			"-kind", activationAttachmentFinalWitness, "-in", input,
		}, &bytes.Buffer{}, &bytes.Buffer{})
		if err == nil || !strings.Contains(err.Error(), "permission policy") {
			t.Fatalf("owner-only error=%v", err)
		}
		assertActivationArtifactMissing(
			t,
			fixture.directory,
			activationstore.ExecutorFinalWitnessFileName,
		)
	})

	t.Run("checkpoint not recorded", func(t *testing.T) {
		fixture := newActivationStatusFixture(t, activation.PhaseAgentReportedTerminal, "node-1")
		_, export, _ := stewardctlEvidenceFixtures(t)
		raw, err := json.Marshal(export)
		if err != nil {
			t.Fatal(err)
		}
		input := filepath.Join(t.TempDir(), "final-witness.json")
		if err := os.WriteFile(input, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		err = run([]string{
			"activation", "attach", "-dir", fixture.directory,
			"-kind", activationAttachmentFinalWitness, "-in", input,
		}, &bytes.Buffer{}, &bytes.Buffer{})
		if err == nil || !strings.Contains(err.Error(), "must record the Executor checkpoint") {
			t.Fatalf("missing checkpoint error=%v", err)
		}
		assertActivationArtifactMissing(
			t,
			fixture.directory,
			activationstore.ExecutorFinalWitnessFileName,
		)
	})
}

func TestActivationAttachAndStatusRequireExactFlags(t *testing.T) {
	for _, arguments := range [][]string{
		{"activation", "attach"},
		{"activation", "attach", "-dir", "/tmp/example", "-kind", "other", "-in", "input"},
		{"activation", "status"},
		{"activation", "status", "-dir", "/tmp/example", "extra"},
	} {
		if err := run(arguments, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
			t.Fatalf("incomplete command accepted: %#v", arguments)
		}
	}
}

func newActivationStatusFixture(
	t *testing.T,
	terminalPhase string,
	nodeID string,
) activationStatusFixture {
	t.Helper()
	parent := t.TempDir()
	directory := filepath.Join(parent, "activation")
	store, err := activationstore.Create(directory)
	if err != nil {
		t.Fatal(err)
	}
	plan := activation.PlanV1{
		SchemaVersion: activation.PlanSchemaV1,
		ActivationID:  "activation-test",
		ReleaseDigest: activationTestDigest("a"),
		PolicyDigest:  activationTestDigest("b"),
		IntentDigest:  activationTestDigest("c"),
		Archive: activation.ArchiveV1{
			Digest: activationTestDigest("d"),
			Bytes:  1,
		},
		Transport: activation.TransportNodeLocal,
		Canary: activation.CanaryV1{
			Kind: activation.CanaryHermesWorkspaceAuditV1,
		},
		Timeouts: activation.TimeoutsV1{
			PreflightSeconds: 1, ImageImportSeconds: 1,
			AdmissionSeconds: 1, StartupSeconds: 1,
			CanarySeconds: 1, EvidenceSeconds: 1,
		},
	}
	planRaw, err := activation.MarshalPlanV1(plan)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.WriteOnce(activationstore.PlanFileName, planRaw); err != nil {
		t.Fatal(err)
	}
	initial := activation.StateV1{
		SchemaVersion: activation.StateSchemaV1,
		Binding: activation.BindingV1{
			ActivationID:  plan.ActivationID,
			PlanDigest:    dsse.Digest(planRaw),
			ReleaseDigest: plan.ReleaseDigest,
			PolicyDigest:  plan.PolicyDigest,
			IntentDigest:  plan.IntentDigest,
			Archive:       plan.Archive,
			TenantID:      "tenant-a",
			NodeID:        nodeID,
			InstanceID:    "agent-a",
			Generation:    1,
		},
		Phase:     activation.PhaseNew,
		UpdatedAt: "2026-07-16T01:00:00Z",
	}
	phases := []string{
		activation.PhaseNew,
		activation.PhaseReleaseVerified,
		activation.PhasePreflightPassed,
		activation.PhaseImageImported,
		activation.PhaseAdmitted,
		activation.PhaseRunning,
		activation.PhaseCanaryChallengeReady,
		activation.PhaseCanaryAuthorized,
		activation.PhaseCanaryDispatched,
		activation.PhaseAgentReportedTerminal,
		activation.PhaseEvidenceCollected,
		activation.PhasePassed,
	}
	fixture := activationStatusFixture{
		directory: directory,
		planRaw:   planRaw,
		plan:      plan,
	}
	current := initial
	for index, phase := range phases {
		if index > 0 {
			current.Phase = phase
			current.UpdatedAt = time.Date(
				2026, 7, 16, 1, 0, index, 0, time.UTC,
			).Format(time.RFC3339Nano)
			if phase == activation.PhaseAdmitted {
				current.RuntimeRef = "executor-" + strings.Repeat("e", 64)
			}
		}
		raw, marshalErr := activation.MarshalStateV1(current)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		if _, appendErr := store.AppendState(uint64(index), raw); appendErr != nil {
			t.Fatal(appendErr)
		}
		fixture.states = append(fixture.states, current)
		fixture.rawStates = append(fixture.rawStates, raw)
		if phase == terminalPhase {
			break
		}
	}
	if fixture.states[len(fixture.states)-1].Phase != terminalPhase {
		t.Fatalf("unknown terminal phase %q", terminalPhase)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func writeActivationProofFixture(
	t *testing.T,
	fixture activationStatusFixture,
) []byte {
	t.Helper()
	state := fixture.states[len(fixture.states)-1]
	stateRaw := fixture.rawStates[len(fixture.rawStates)-1]
	executor := activation.ReceiptCoordinateV1{
		ReceiptNodeID:   state.Binding.NodeID,
		ReceiptEpoch:    1,
		Sequence:        7,
		ChainHash:       activationTestDigest("1"),
		PublicKeySHA256: activationTestDigest("2"),
	}
	proof := activation.ProofV1{
		SchemaVersion: activation.ProofSchemaV1,
		Binding:       state.Binding,
		StateDigest:   dsse.Digest(stateRaw),
		RuntimeRef:    state.RuntimeRef,
		Canary: activation.CanaryProofV1{
			Kind:         fixture.plan.Canary.Kind,
			TaskDigest:   activationTestDigest("3"),
			PermitDigest: activationTestDigest("4"),
			ResultDigest: activationTestDigest("5"),
			ResultBytes:  1,
		},
		ExecutorBeginDigest:      activationTestDigest("a"),
		ExecutorCheckpointDigest: activationTestDigest("b"),
		ExecutorEvidence:         executor,
		GatewayEvidence: activation.ReceiptCoordinateV1{
			ReceiptNodeID:   state.Binding.NodeID + "/gateway",
			ReceiptEpoch:    1,
			Sequence:        9,
			ChainHash:       activationTestDigest("6"),
			PublicKeySHA256: activationTestDigest("7"),
		},
		Witness: activation.WitnessCoordinateV1{
			ControllerInstanceID:   "controller-a",
			ControlNodeID:          state.Binding.NodeID,
			ReceiptNodeID:          executor.ReceiptNodeID,
			ReceiptEpoch:           executor.ReceiptEpoch,
			Sequence:               executor.Sequence,
			ChainHash:              executor.ChainHash,
			ReceiptPublicKeySHA256: executor.PublicKeySHA256,
			WitnessPublicKeySHA256: activationTestDigest("8"),
			WitnessExportDigest:    activationTestDigest("9"),
			WitnessedAt:            "2026-07-16T01:00:10Z",
		},
		CompletedAt: state.UpdatedAt,
	}
	raw, err := activation.MarshalProofV1(proof)
	if err != nil {
		t.Fatal(err)
	}
	store, err := activationstore.Open(fixture.directory)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.WriteOnce(activationstore.ProofFileName, raw); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	return raw
}

func writeActivationCheckpointFixture(
	t *testing.T,
	fixture activationStatusFixture,
) []byte {
	t.Helper()
	state := fixture.states[len(fixture.states)-1]
	raw, err := activation.MarshalExecutorCheckpointV1(
		state.Binding,
		state.RuntimeRef,
		activationTestDigest("a"),
		activationTestDigest("b"),
		"grant-"+strings.Repeat("c", 64),
		activation.GatewayEvidenceResultV1{
			Receipts: []byte("portable gateway receipts"),
			Coordinate: activation.ReceiptCoordinateV1{
				ReceiptNodeID:   state.Binding.NodeID + "/gateway",
				ReceiptEpoch:    1,
				Sequence:        3,
				ChainHash:       activationTestDigest("d"),
				PublicKeySHA256: activationTestDigest("e"),
			},
			Canary: activation.CanaryProofV1{
				Kind:         activation.CanaryHermesWorkspaceAuditV1,
				TaskDigest:   activationTestDigest("f"),
				PermitDigest: activationTestDigest("1"),
				ResultDigest: activationTestDigest("2"),
				ResultBytes:  1,
			},
			AuthorizedAt: "2026-07-16T01:00:08Z",
			TerminalAt:   "2026-07-16T01:00:09Z",
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	store, err := activationstore.Open(fixture.directory)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.WriteOnce(
		activationstore.ExecutorCheckpointFileName,
		raw,
	); err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	return raw
}

func runActivationStatus(t *testing.T, directory string) activationStatusOutput {
	t.Helper()
	var output bytes.Buffer
	if err := run(
		[]string{"activation", "status", "-dir", directory},
		&output,
		&bytes.Buffer{},
	); err != nil {
		t.Fatal(err)
	}
	return decodeActivationStatus(t, output.Bytes())
}

func decodeActivationStatus(t *testing.T, raw []byte) activationStatusOutput {
	t.Helper()
	var status activationStatusOutput
	if err := json.Unmarshal(raw, &status); err != nil {
		t.Fatal(err)
	}
	return status
}

func readActivationFixtureArtifact(
	t *testing.T,
	directory string,
	name string,
	limit int64,
) []byte {
	t.Helper()
	store, err := activationstore.Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := store.Read(name, limit)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	return raw
}

func assertActivationArtifactMissing(t *testing.T, directory, name string) {
	t.Helper()
	store, err := activationstore.Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.Read(name, activationstore.MaxSmallArtifactBytes)
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("artifact %q exists or returned unexpected error: %v", name, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
}

func activationTestDigest(character string) string {
	return "sha256:" + strings.Repeat(character, 64)
}
