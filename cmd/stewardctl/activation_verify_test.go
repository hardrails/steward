package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
	"github.com/hardrails/steward/internal/taskpermit"
)

type offlineActivationFixture struct {
	directory            string
	now                  time.Time
	publisherPublicPath  string
	siteRootPublicPath   string
	witnessPublicPath    string
	gatewayPublicPath    string
	proofDigest          string
	verificationArgument []string
}

func TestActivationCreateSnapshotsAndVerifiesCopiedArchive(t *testing.T) {
	fixture := newOfflineActivationFixture(t)
	target := filepath.Join(t.TempDir(), "created-activation")
	var output bytes.Buffer
	if err := createActivation([]string{
		"-dir", target,
		"-activation-id", "activation-create-test",
		"-release", filepath.Join(fixture.directory, activationstore.ReleaseFileName),
		"-policy", filepath.Join(fixture.directory, activationstore.PolicyFileName),
		"-intent", filepath.Join(fixture.directory, activationstore.IntentFileName),
		"-archive", filepath.Join(fixture.directory, activationstore.ImageArchiveFileName),
		"-publisher-public-key", fixture.publisherPublicPath,
		"-publisher-key-id", "publisher-a",
		"-site-root-public-key", fixture.siteRootPublicPath,
		"-site-root-key-id", "site-root",
		"-baseline-witness", filepath.Join(
			fixture.directory, activationstore.ExecutorBaselineWitnessFileName,
		),
		"-witness-public-key", fixture.witnessPublicPath,
	}, &output); err != nil {
		t.Fatal(err)
	}
	status := decodeActivationStatus(t, output.Bytes())
	if status.ActivationID != "activation-create-test" ||
		status.Phase != activation.PhaseNew ||
		status.WaitingFor != activationWaitingRun ||
		status.NextCommand != activationResumeRunCommand ||
		!status.Verified {
		t.Fatalf("create status=%#v", status)
	}
	source := offlineRead(
		t, filepath.Join(fixture.directory, activationstore.ImageArchiveFileName),
	)
	copied := offlineRead(
		t, filepath.Join(target, activationstore.ImageArchiveFileName),
	)
	if !bytes.Equal(copied, source) {
		t.Fatal("activation archive snapshot does not match the verified source bytes")
	}
	if _, err := os.Stat(filepath.Join(target, activationstore.PlanFileName)); err != nil {
		t.Fatalf("activation plan was not published after archive verification: %v", err)
	}
}

func TestActivationVerifyAuthenticatesCompleteWorkspaceOffline(t *testing.T) {
	fixture := newOfflineActivationFixture(t)
	var output bytes.Buffer
	if err := verifyActivation(fixture.verificationArgument, &output); err != nil {
		t.Fatal(err)
	}
	var verified activationVerificationOutput
	if err := json.Unmarshal(output.Bytes(), &verified); err != nil {
		t.Fatal(err)
	}
	if verified.SchemaVersion != activationVerificationSchemaV1 ||
		!verified.Valid || !verified.Verified ||
		verified.ProofDigest != fixture.proofDigest {
		t.Fatalf("activation verification output = %#v", verified)
	}
}

func TestActivationVerifyRejectsChangedResultCompanion(t *testing.T) {
	fixture := newOfflineActivationFixture(t)
	path := filepath.Join(fixture.directory, activationstore.CanaryResultFileName)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(raw, ' '), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyActivation(fixture.verificationArgument, &bytes.Buffer{}); err == nil {
		t.Fatal("changed canary result accepted")
	}
}

func TestActivationVerifyRejectsIncompleteArguments(t *testing.T) {
	for _, arguments := range [][]string{
		nil,
		{"-dir", "/tmp/activation"},
		{"-dir", "/tmp/activation", "extra"},
	} {
		if err := verifyActivation(arguments, &bytes.Buffer{}); err == nil {
			t.Fatalf("incomplete activation verification accepted: %#v", arguments)
		}
	}
}

func TestRunActivationResumesTerminalPhasesWithoutCurrentGateway(t *testing.T) {
	tests := []struct {
		name         string
		removeStates []uint64
		removeProof  bool
		wantVerified bool
	}{
		{
			name:         "passed",
			wantVerified: false,
		},
		{
			name:         "evidence collected",
			removeStates: []uint64{11},
			removeProof:  true,
			wantVerified: true,
		},
		{
			name:         "agent terminal with retained evidence",
			removeStates: []uint64{11, 10},
			removeProof:  true,
			wantVerified: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newOfflineActivationFixture(t)
			for _, sequence := range test.removeStates {
				name, err := activationstore.StateCheckpointName(sequence)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(filepath.Join(fixture.directory, name)); err != nil {
					t.Fatal(err)
				}
			}
			if test.removeProof {
				if err := os.Remove(filepath.Join(
					fixture.directory, activationstore.ProofFileName,
				)); err != nil {
					t.Fatal(err)
				}
			}
			previousNow := timeNow
			timeNow = func() time.Time {
				return fixture.now.Add(30 * time.Minute)
			}
			t.Cleanup(func() { timeNow = previousNow })

			var output bytes.Buffer
			if err := runActivation(
				fixture.runArgumentsWithoutLiveServices(), &output,
			); err != nil {
				t.Fatal(err)
			}
			status := decodeActivationStatus(t, output.Bytes())
			if status.Phase != activation.PhasePassed ||
				status.Verified != test.wantVerified ||
				status.ProofDigest == "" {
				t.Fatalf("status=%#v", status)
			}
		})
	}
}

func TestRunActivationMakesInvalidRetainedEvidenceSticky(t *testing.T) {
	tests := []struct {
		name         string
		removeStates []uint64
	}{
		{
			name:         "agent terminal",
			removeStates: []uint64{11, 10},
		},
		{
			name:         "evidence collected",
			removeStates: []uint64{11},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newOfflineActivationFixture(t)
			for _, sequence := range test.removeStates {
				name, err := activationstore.StateCheckpointName(sequence)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(filepath.Join(fixture.directory, name)); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Remove(filepath.Join(
				fixture.directory, activationstore.ProofFileName,
			)); err != nil {
				t.Fatal(err)
			}
			deltaPath := filepath.Join(
				fixture.directory, activationstore.ExecutorDeltaFileName,
			)
			delta := offlineRead(t, deltaPath)
			delta[len(delta)-1] ^= 0xff
			if err := os.WriteFile(deltaPath, delta, 0o600); err != nil {
				t.Fatal(err)
			}
			previousNow := timeNow
			timeNow = func() time.Time {
				return fixture.now.Add(30 * time.Minute)
			}
			t.Cleanup(func() { timeNow = previousNow })

			var output bytes.Buffer
			err := runActivation(
				fixture.runArgumentsWithoutLiveServices(), &output,
			)
			if err == nil {
				t.Fatal("invalid retained evidence was accepted")
			}
			status := decodeActivationStatus(t, output.Bytes())
			if status.Phase != activation.PhaseActionRequired ||
				!status.Verified {
				t.Fatalf("status=%#v err=%v", status, err)
			}
			store, openErr := activationstore.Open(fixture.directory)
			if openErr != nil {
				t.Fatal(openErr)
			}
			_, chain, loadErr := loadUnverifiedActivationStateChain(store)
			closeErr := store.Close()
			if loadErr != nil {
				t.Fatal(loadErr)
			}
			if closeErr != nil {
				t.Fatal(closeErr)
			}
			if chain.latest().ActionRequiredReason != "evidence_invalid" {
				t.Fatalf("latest state=%#v", chain.latest())
			}
		})
	}
}

func TestRunActivationMakesInvalidRetainedProofSticky(t *testing.T) {
	fixture := newOfflineActivationFixture(t)
	passedState, err := activationstore.StateCheckpointName(11)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(fixture.directory, passedState)); err != nil {
		t.Fatal(err)
	}
	proofPath := filepath.Join(
		fixture.directory, activationstore.ProofFileName,
	)
	proof := offlineRead(t, proofPath)
	proof[len(proof)-1] ^= 0xff
	if err := os.WriteFile(proofPath, proof, 0o600); err != nil {
		t.Fatal(err)
	}
	previousNow := timeNow
	timeNow = func() time.Time {
		return fixture.now.Add(30 * time.Minute)
	}
	t.Cleanup(func() { timeNow = previousNow })

	var output bytes.Buffer
	err = runActivation(
		fixture.runArgumentsWithoutLiveServices(), &output,
	)
	if err == nil {
		t.Fatal("invalid retained proof was accepted")
	}
	status := decodeActivationStatus(t, output.Bytes())
	if status.Phase != activation.PhaseActionRequired || !status.Verified {
		t.Fatalf("status=%#v err=%v", status, err)
	}
	store, openErr := activationstore.Open(fixture.directory)
	if openErr != nil {
		t.Fatal(openErr)
	}
	_, chain, loadErr := loadUnverifiedActivationStateChain(store)
	closeErr := store.Close()
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if closeErr != nil {
		t.Fatal(closeErr)
	}
	if chain.latest().ActionRequiredReason != "evidence_invalid" {
		t.Fatalf("latest state=%#v", chain.latest())
	}
}

func newOfflineActivationFixture(t *testing.T) offlineActivationFixture {
	t.Helper()
	fixtureNow := time.Now().UTC().Truncate(time.Second)
	releaseFixture := newAgentReleaseCLIFixture(t)
	releaseFixture.now = fixtureNow
	timeNow = func() time.Time { return fixtureNow }
	releasePrivate, err := readPrivateKey(releaseFixture.privateKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	writeSignedJSON(
		t, releaseFixture.capsulePath, admission.CapsulePayloadType,
		releaseFixture.capsule(t), "publisher-a", releasePrivate,
	)
	if err := run(
		releaseFixture.issueArguments(), &bytes.Buffer{}, &bytes.Buffer{},
	); err != nil {
		t.Fatal(err)
	}
	releaseRaw := offlineRead(t, releaseFixture.outputPath)
	publisherPublic, err := readPublicKey(releaseFixture.publicKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	release, err := agentrelease.Verify(
		releaseRaw,
		map[string]ed25519.PublicKey{"publisher-a": publisherPublic},
		releaseFixture.now,
	)
	if err != nil {
		t.Fatal(err)
	}

	sitePrivatePath, sitePublicPath := generateTestKeyPair(
		t, releaseFixture.directory, "activation-site-root",
	)
	sitePrivate, err := readPrivateKey(sitePrivatePath)
	if err != nil {
		t.Fatal(err)
	}
	taskPrivatePath, _ := generateTestKeyPair(
		t, releaseFixture.directory, "activation-task",
	)
	taskPrivate, err := readPrivateKey(taskPrivatePath)
	if err != nil {
		t.Fatal(err)
	}
	taskPublic := taskPrivate.Public().(ed25519.PublicKey)
	capsule := release.Capsule
	ceiling := admission.ResourceLimits{
		MemoryBytes: 1 << 30, CPUMillis: 2000, PIDs: 256,
	}
	policy := admission.SitePolicy{
		SchemaVersion: admission.SchemaV1,
		PolicyID:      "activation-site",
		PolicyEpoch:   1,
		Publishers: []admission.PublisherRule{{
			KeyID:               "publisher-a",
			PublicKey:           base64.StdEncoding.EncodeToString(publisherPublic),
			AllowedProfiles:     []admission.ProfileRef{capsule.Profile},
			AllowedRepositories: []string{capsule.Image.Repository},
			AllowedManifestDigests: []string{
				capsule.Image.ManifestDigest,
			},
			AllowedArtifacts: capsule.Artifacts,
			ResourceCeiling:  ceiling,
		}},
		Tenants: []admission.TenantRule{{
			TenantID:         "tenant-a",
			PublisherKeyIDs:  []string{"publisher-a"},
			ResourceCeiling:  ceiling,
			AllowedArtifacts: capsule.Artifacts,
			ServiceIDs:       []string{agentrelease.HermesServiceID},
			TaskKeys: []admission.TaskKey{{
				KeyID:      "tenant-task",
				PublicKey:  base64.StdEncoding.EncodeToString(taskPublic),
				ServiceIDs: []string{agentrelease.HermesServiceID},
			}},
		}},
	}
	policyPath := filepath.Join(releaseFixture.directory, "activation-policy.dsse.json")
	writeSignedJSON(
		t, policyPath, admission.PolicyPayloadType, policy,
		"site-root", sitePrivate,
	)
	policyRaw := offlineRead(t, policyPath)
	intent := admission.InstanceIntent{
		TenantID:      "tenant-a",
		NodeID:        "node-a",
		InstanceID:    "hermes-a",
		LineageID:     "hermes-lineage-a",
		Generation:    7,
		CapsuleDigest: release.CapsuleEnvelopeDigest,
		Resources:     capsule.Resources,
		Capabilities: admission.Capabilities{
			State: true, Service: true,
		},
		StateDisposition: "new",
		ServiceID:        agentrelease.HermesServiceID,
	}
	intentRaw, err := json.Marshal(intent)
	if err != nil {
		t.Fatal(err)
	}
	archiveRaw := offlineRead(t, releaseFixture.archivePath)
	plan := activation.PlanV1{
		SchemaVersion: activation.PlanSchemaV1,
		ActivationID:  "activation-offline-test",
		ReleaseDigest: release.EnvelopeDigest,
		PolicyDigest:  dsse.Digest(policyRaw),
		IntentDigest:  dsse.Digest(intentRaw),
		Archive: activation.ArchiveV1{
			Digest: dsse.Digest(archiveRaw), Bytes: int64(len(archiveRaw)),
		},
		Transport: activation.TransportNodeLocal,
		Canary: activation.CanaryV1{
			Kind: activation.CanaryHermesWorkspaceAuditV1,
		},
		Timeouts: activation.TimeoutsV1{
			PreflightSeconds: 30, ImageImportSeconds: 1800,
			AdmissionSeconds: 60, StartupSeconds: 120,
			CanarySeconds: 300, EvidenceSeconds: 60,
		},
	}
	planRaw, err := activation.MarshalPlanV1(plan)
	if err != nil {
		t.Fatal(err)
	}
	binding := activation.BindingV1{
		ActivationID:  plan.ActivationID,
		PlanDigest:    dsse.Digest(planRaw),
		ReleaseDigest: plan.ReleaseDigest,
		PolicyDigest:  plan.PolicyDigest,
		IntentDigest:  plan.IntentDigest,
		Archive:       plan.Archive,
		TenantID:      intent.TenantID,
		NodeID:        intent.NodeID,
		InstanceID:    intent.InstanceID,
		Generation:    intent.Generation,
	}
	runtimeRef := executor.RuntimeRef(intent.TenantID, intent.InstanceID)
	grantID := gateway.GrantID(
		intent.TenantID, intent.InstanceID, intent.Generation,
	)
	routePolicyDigest := digest('9')
	executorReceiptPublic, executorReceiptPrivate, err := ed25519.GenerateKey(
		rand.Reader,
	)
	if err != nil {
		t.Fatal(err)
	}
	witnessPublic, witnessPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	admitted := permitAdmission{
		RuntimeRef:    runtimeRef,
		Status:        "created",
		CapsuleDigest: release.CapsuleEnvelopeDigest,
		PolicyDigest:  plan.PolicyDigest,
		Generation:    intent.Generation,
		EvidenceKeyID: evidence.KeyID(executorReceiptPublic),
		GrantID:       grantID,
		ServicePath:   "/v1/services/" + grantID + "/",
		ServiceID:     agentrelease.HermesServiceID,
		TaskAuthorities: []gateway.TaskAuthority{{
			KeyID:     "tenant-task",
			PublicKey: base64.StdEncoding.EncodeToString(taskPublic),
		}},
		RoutePolicyDigest: routePolicyDigest,
	}
	admissionRaw, err := json.Marshal(admitted)
	if err != nil {
		t.Fatal(err)
	}
	operation := serviceTrustOperation{
		ServiceID:           agentrelease.HermesServiceID,
		ID:                  agentrelease.HermesOperationID,
		Method:              "POST",
		Path:                "/v1/runs",
		ContentType:         "application/json",
		MaxRequestBytes:     64 << 10,
		MaxResponseBytes:    1 << 20,
		MaxSeconds:          30,
		MaxPermitSeconds:    600,
		TaskProtocol:        connectorledger.TaskProtocolLifecycleV1,
		StatusPathPrefix:    "/v1/runs/",
		StatusMaxSeconds:    15,
		PollIntervalSeconds: 2,
	}
	operation.PolicyDigest = gateway.ServiceOperationDigest(
		operation.gatewayOperation(),
	)
	serviceTrustRaw, err := json.Marshal(serviceTrustInventory{
		SchemaVersion: serviceTrustSchemaV2,
		NodeID:        intent.NodeID,
		TenantID:      intent.TenantID,
		Services: []serviceTrustService{{
			ServiceID:  agentrelease.HermesServiceID,
			Operations: []serviceTrustOperation{operation},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	requestRaw, err := agentrelease.BuildCanaryRequest(
		release.Release.Canary.Request, plan.ActivationID,
	)
	if err != nil {
		t.Fatal(err)
	}
	pins, err := activationTaskAuthorities(admitted)
	if err != nil {
		t.Fatal(err)
	}
	challenge := activation.CanaryChallengeV1{
		SchemaVersion:      activation.ChallengeSchemaV1,
		ActivationID:       plan.ActivationID,
		PlanDigest:         dsse.Digest(planRaw),
		ReleaseDigest:      release.EnvelopeDigest,
		AdmissionDigest:    dsse.Digest(admissionRaw),
		IntentDigest:       dsse.Digest(intentRaw),
		ServiceTrustDigest: dsse.Digest(serviceTrustRaw),
		RequestDigest:      dsse.Digest(requestRaw),
		TenantID:           intent.TenantID,
		NodeID:             intent.NodeID,
		InstanceID:         intent.InstanceID,
		RuntimeRef:         runtimeRef,
		Generation:         intent.Generation,
		GrantID:            grantID,
		ServiceID:          agentrelease.HermesServiceID,
		OperationID:        agentrelease.HermesOperationID,
		TaskAuthorities:    pins,
		CreatedAt:          fixtureNow.Add(5 * time.Second).Format(time.RFC3339Nano),
	}
	challengeRaw, err := activation.MarshalChallengeV1(challenge)
	if err != nil {
		t.Fatal(err)
	}
	taskRaw, task := offlineActivationTask(
		t, taskPrivate, admitted, intent, operation, requestRaw, fixtureNow,
	)
	resultRaw := offlineHermesResult(t, plan.ActivationID)
	gatewayEvidence := offlineGatewayEvidence(
		t, releaseFixture.directory, task, operation.TaskProtocol, resultRaw,
	)
	gatewayPublicPath := offlineWritePublicKey(
		t, releaseFixture.directory, "gateway-receipt.public",
		gatewayEvidence.public,
	)
	stateRuntimeRef := executor.StateVolumeName(
		intent.TenantID, intent.LineageID,
	)
	beginRaw, err := activation.MarshalExecutorBeginV1(
		binding, runtimeRef, stateRuntimeRef, admitted.CapsuleDigest,
	)
	if err != nil {
		t.Fatal(err)
	}
	beginDigest, err := activation.ExecutorBeginDigestV1(beginRaw)
	if err != nil {
		t.Fatal(err)
	}
	checkpointRaw, err := activation.MarshalExecutorCheckpointV1(
		binding, runtimeRef, admitted.CapsuleDigest,
		routePolicyDigest, grantID, gatewayEvidence.result,
	)
	if err != nil {
		t.Fatal(err)
	}
	checkpointDigest, err := activation.ExecutorCheckpointDigestV1(
		checkpointRaw,
	)
	if err != nil {
		t.Fatal(err)
	}
	gatewayTerminalAt, err := time.Parse(
		time.RFC3339Nano, gatewayEvidence.result.TerminalAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	baselineWitnessAt := fixtureNow.Add(-2 * time.Minute)
	finalWitnessAt := gatewayTerminalAt.Add(2 * time.Minute)
	executorEvidence := offlineExecutorEvidence(
		t, releaseFixture.directory, binding, runtimeRef, stateRuntimeRef,
		release.CapsuleEnvelopeDigest, routePolicyDigest, grantID,
		beginDigest, checkpointDigest,
		executorReceiptPublic, executorReceiptPrivate,
		witnessPublic, witnessPrivate,
		baselineWitnessAt, finalWitnessAt,
	)
	witnessPublicPath := offlineWritePublicKey(
		t, releaseFixture.directory, "controller-witness.public",
		executorEvidence.witnessPublic,
	)
	submitRaw, err := json.Marshal(activationSubmitRecord{
		SchemaVersion: activationSubmitSchemaV1,
		TaskDigest:    gatewayEvidence.result.Canary.TaskDigest,
		PermitDigest:  gatewayEvidence.result.Canary.PermitDigest,
		RunID:         "run_0123456789abcdef0123456789abcdef",
		Receipt:       gatewayclient.TaskReceiptRecorded,
		ReceiptNodeID: gateway.ServiceTaskReceiptNodeID(
			intent.NodeID,
		),
		ReceiptEpoch: gatewayEvidence.result.Coordinate.ReceiptEpoch,
		ReceiptPublicKeyBase64: base64.StdEncoding.EncodeToString(
			gatewayEvidence.public,
		),
	})
	if err != nil {
		t.Fatal(err)
	}
	canaryStatusRaw, err := json.Marshal(gatewayclient.TaskLifecycleStatus{
		SchemaVersion: activationTaskStatusSchemaV1,
		TaskDigest:    gatewayEvidence.result.Canary.TaskDigest,
		PermitDigest:  gatewayEvidence.result.Canary.PermitDigest,
		Phase:         gatewayclient.PhaseTerminal,
		State:         string(gatewayclient.AgentReportedCompleted),
		RunID:         "run_0123456789abcdef0123456789abcdef",
		TaskStatus:    gatewayclient.AgentReportedCompleted,
		ResultDigest:  dsse.Digest(resultRaw),
		ResponseBytes: int64(len(resultRaw)),
	})
	if err != nil {
		t.Fatal(err)
	}

	stateRaws, finalState := offlineActivationStates(
		t, binding, runtimeRef, finalWitnessAt,
	)
	completedAt := finalWitnessAt.Add(time.Second)
	proof := activation.ProofV1{
		SchemaVersion:            activation.ProofSchemaV1,
		Binding:                  binding,
		StateDigest:              dsse.Digest(stateRaws[len(stateRaws)-1]),
		RuntimeRef:               runtimeRef,
		Canary:                   gatewayEvidence.result.Canary,
		ExecutorBeginDigest:      beginDigest,
		ExecutorCheckpointDigest: checkpointDigest,
		ExecutorEvidence:         executorEvidence.result.Coordinate,
		GatewayEvidence:          gatewayEvidence.result.Coordinate,
		Witness:                  executorEvidence.result.Witness,
		CompletedAt:              completedAt.Format(time.RFC3339Nano),
	}
	if finalState.UpdatedAt != finalWitnessAt.Format(time.RFC3339Nano) {
		t.Fatalf("final state time = %q", finalState.UpdatedAt)
	}
	proofRaw, err := activation.MarshalProofV1(proof)
	if err != nil {
		t.Fatal(err)
	}
	proofDigest := dsse.Digest(proofRaw)

	workspaceParent := t.TempDir()
	workspace := filepath.Join(workspaceParent, "activation")
	store, err := activationstore.Create(workspace)
	if err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string][]byte{
		activationstore.ReleaseFileName:      releaseRaw,
		activationstore.PolicyFileName:       policyRaw,
		activationstore.IntentFileName:       intentRaw,
		activationstore.ServiceTrustFileName: serviceTrustRaw,
	} {
		if err := store.Import(name, raw); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.ImportArchive(releaseFixture.archivePath, plan.Archive); err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string][]byte{
		activationstore.PlanFileName:                    planRaw,
		activationstore.AdmissionFileName:               admissionRaw,
		activationstore.CanaryRequestFileName:           requestRaw,
		activationstore.CanaryChallengeFileName:         challengeRaw,
		activationstore.CanaryTaskFileName:              taskRaw,
		activationstore.CanarySubmitFileName:            submitRaw,
		activationstore.CanaryStatusFileName:            canaryStatusRaw,
		activationstore.CanaryResultFileName:            resultRaw,
		activationstore.ExecutorBaselineWitnessFileName: executorEvidence.baseline,
		activationstore.ExecutorBeginFileName:           beginRaw,
		activationstore.ExecutorCheckpointFileName:      checkpointRaw,
		activationstore.ExecutorDeltaFileName:           executorEvidence.result.Delta,
		activationstore.ExecutorFinalWitnessFileName:    executorEvidence.final,
		activationstore.GatewayTaskReceiptsFileName:     gatewayEvidence.result.Receipts,
		activationstore.ProofFileName:                   proofRaw,
	} {
		if err := store.WriteOnce(name, raw); err != nil {
			t.Fatal(err)
		}
	}
	for sequence, raw := range stateRaws {
		if _, err := store.AppendState(uint64(sequence), raw); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	return offlineActivationFixture{
		directory:           workspace,
		now:                 fixtureNow,
		publisherPublicPath: releaseFixture.publicKeyPath,
		siteRootPublicPath:  sitePublicPath,
		witnessPublicPath:   witnessPublicPath,
		gatewayPublicPath:   gatewayPublicPath,
		proofDigest:         proofDigest,
		verificationArgument: []string{
			"-dir", workspace,
			"-publisher-public-key", releaseFixture.publicKeyPath,
			"-publisher-key-id", "publisher-a",
			"-site-root-public-key", sitePublicPath,
			"-site-root-key-id", "site-root",
			"-witness-public-key", witnessPublicPath,
			"-gateway-receipt-public-key", gatewayPublicPath,
		},
	}
}

func (fixture offlineActivationFixture) runArgumentsWithoutLiveServices() []string {
	return []string{
		"-dir", fixture.directory,
		"-publisher-public-key", fixture.publisherPublicPath,
		"-publisher-key-id", "publisher-a",
		"-site-root-public-key", fixture.siteRootPublicPath,
		"-site-root-key-id", "site-root",
		"-witness-public-key", fixture.witnessPublicPath,
		"-node-url", "http://127.0.0.1:1",
		"-node-token-file", filepath.Join(fixture.directory, "missing-node-token"),
		"-gateway-config", filepath.Join(fixture.directory, "missing-gateway.json"),
		"-docker-socket", filepath.Join(fixture.directory, "missing-docker.sock"),
		"-executor-evidence-log", filepath.Join(fixture.directory, "missing-executor-evidence.bin"),
	}
}

type offlineExecutorEvidenceResult struct {
	baseline      []byte
	final         []byte
	receiptPublic ed25519.PublicKey
	witnessPublic ed25519.PublicKey
	result        activation.ExecutorEvidenceResultV1
}

func offlineExecutorEvidence(
	t *testing.T,
	directory string,
	binding activation.BindingV1,
	runtimeRef, stateRuntimeRef, capsuleDigest, routePolicyDigest, grantID string,
	beginDigest, checkpointDigest string,
	receiptPublic ed25519.PublicKey,
	receiptPrivate ed25519.PrivateKey,
	witnessPublic ed25519.PublicKey,
	witnessPrivate ed25519.PrivateKey,
	baselineWitnessAt time.Time,
	finalWitnessAt time.Time,
) offlineExecutorEvidenceResult {
	t.Helper()
	path := filepath.Join(directory, "activation-executor-evidence.bin")
	log, err := evidence.Open(path, receiptPrivate, binding.NodeID, 1)
	if err != nil {
		t.Fatal(err)
	}
	unrelated := evidence.Event{
		Type: evidence.PolicyReload, TenantID: binding.TenantID,
		RuntimeRef:    "executor-" + strings.Repeat("e", 64),
		CapsuleDigest: capsuleDigest, PolicyDigest: binding.PolicyDigest,
		Generation: binding.Generation, GrantID: "workload",
		Outcome: evidence.Committed,
	}
	if _, err := log.Append(unrelated); err != nil {
		t.Fatal(err)
	}
	baselineHead, err := log.CurrentHead()
	if err != nil {
		t.Fatal(err)
	}
	event := evidence.Event{
		Type:     evidence.ActivationBegin,
		TenantID: binding.TenantID, RuntimeRef: runtimeRef,
		CapsuleDigest: capsuleDigest, PolicyDigest: binding.PolicyDigest,
		Generation: binding.Generation, GrantID: binding.ActivationID,
		Outcome: evidence.Allowed, MetadataHash: beginDigest,
	}
	if _, err := log.AppendActivationBegin(event); err != nil {
		t.Fatal(err)
	}
	event = evidence.Event{
		TenantID: binding.TenantID, RuntimeRef: runtimeRef,
		CapsuleDigest: capsuleDigest, PolicyDigest: binding.PolicyDigest,
		Generation: binding.Generation,
	}
	event.Type, event.GrantID, event.Outcome =
		evidence.AdmissionAllow, grantID, evidence.Allowed
	if _, err := log.Append(event); err != nil {
		t.Fatal(err)
	}
	event.Type, event.GrantID, event.Outcome =
		evidence.JournalPrepare, "workload", evidence.Allowed
	event.ErrorCode = ""
	event.MetadataHash = ""
	if _, err := log.Append(event); err != nil {
		t.Fatal(err)
	}
	event.Type, event.GrantID, event.Outcome =
		evidence.JournalCommit, "workload", evidence.Committed
	event.MetadataHash = routePolicyDigest
	if _, err := log.Append(event); err != nil {
		t.Fatal(err)
	}
	event.Type, event.Outcome = evidence.JournalPrepare, evidence.Allowed
	event.ErrorCode = "start"
	event.MetadataHash = ""
	if _, err := log.Append(event); err != nil {
		t.Fatal(err)
	}
	event.Type = evidence.LifecycleStart
	event.Outcome = evidence.Committed
	event.ErrorCode = ""
	event.MetadataHash = routePolicyDigest
	if _, err := log.Append(event); err != nil {
		t.Fatal(err)
	}
	event.Type = evidence.ActivationCheckpoint
	event.GrantID = binding.ActivationID
	event.Outcome = evidence.Committed
	event.ErrorCode = ""
	event.MetadataHash = checkpointDigest
	if _, err := log.AppendActivationCheckpoint(event); err != nil {
		t.Fatal(err)
	}
	finalHead, err := log.CurrentHead()
	if err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	claim, err := controlprotocol.NewExecutorEvidenceIdentityClaimV1(
		"controller-a", "enrollment-a", binding.NodeID,
		binding.NodeID, 1, receiptPublic,
	)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := controlprotocol.SignExecutorEvidenceIdentityClaimV1(
		claim, receiptPrivate,
	)
	if err != nil {
		t.Fatal(err)
	}
	baseline := offlineSignExecutorWitness(
		t, identity, witnessPrivate, baselineHead,
		baselineWitnessAt,
	)
	final := offlineSignExecutorWitness(
		t, identity, witnessPrivate, finalHead,
		finalWitnessAt,
	)
	request := activation.ExecutorEvidenceRequestV1{
		Binding: binding, RuntimeRef: runtimeRef,
		StateRuntimeRef: stateRuntimeRef,
		CapsuleDigest:   capsuleDigest, RoutePolicyDigest: routePolicyDigest,
		GrantID: grantID, BaselineWitness: baseline, FinalWitness: final,
		ActivationBeginDigest:      beginDigest,
		ActivationCheckpointDigest: checkpointDigest,
		WitnessPublicKey:           witnessPublic,
	}
	result, err := activation.CollectExecutorEvidenceV1(request, path)
	if err != nil {
		t.Fatal(err)
	}
	return offlineExecutorEvidenceResult{
		baseline: baseline, final: final,
		receiptPublic: receiptPublic, witnessPublic: witnessPublic,
		result: result,
	}
}

func offlineSignExecutorWitness(
	t *testing.T,
	identity controlprotocol.ExecutorEvidenceIdentityProofV1,
	private ed25519.PrivateKey,
	head evidence.Head,
	at time.Time,
) []byte {
	t.Helper()
	public, err := controlprotocol.VerifyExecutorEvidenceIdentityProofV1(identity)
	if err != nil {
		t.Fatal(err)
	}
	timestamp := at.UTC().Format(time.RFC3339Nano)
	export, err := controlprotocol.SignExecutorEvidenceExportV1(
		controlprotocol.ExecutorEvidenceExportStatementV1{
			ProtocolVersion:      controlprotocol.ExecutorEvidenceProtocolV1,
			ControllerInstanceID: "controller-a",
			ControlNodeID:        "node-a",
			IdentityProof:        identity,
			Status: controlprotocol.ExecutorEvidenceStatusV1{
				State: controlprotocol.ExecutorEvidenceStatusCurrent,
				Head: &controlprotocol.ExecutorEvidenceHeadV1{
					Stream:          controlprotocol.ExecutorEvidenceStreamV1,
					ReceiptNodeID:   head.NodeID,
					ReceiptEpoch:    head.Epoch,
					Sequence:        head.Sequence,
					ChainHash:       offlineEvidenceHash(head.ChainHash),
					PublicKeySHA256: controlprotocol.ExecutorEvidencePublicKeySHA256(public),
				},
				WitnessedAt: timestamp,
			},
			ExportedAt: timestamp,
		},
		private,
	)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(export)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func offlineEvidenceHash(hash [32]byte) string {
	return "sha256:" + hex.EncodeToString(hash[:])
}

func offlineActivationTask(
	t *testing.T,
	private ed25519.PrivateKey,
	admitted permitAdmission,
	intent admission.InstanceIntent,
	operation serviceTrustOperation,
	request []byte,
	now time.Time,
) ([]byte, verifiedTaskBundle) {
	t.Helper()
	statement := taskpermit.Statement{
		SchemaVersion: taskpermit.SchemaV1,
		NodeID:        intent.NodeID, TenantID: intent.TenantID,
		InstanceID: intent.InstanceID, RuntimeRef: admitted.RuntimeRef,
		GrantID: admitted.GrantID, Generation: intent.Generation,
		CapsuleDigest:     admitted.CapsuleDigest,
		PolicyDigest:      admitted.PolicyDigest,
		RoutePolicyDigest: admitted.RoutePolicyDigest,
		ServiceID:         intent.ServiceID, OperationID: operation.ID,
		OperationPolicyDigest: operation.PolicyDigest,
		TaskID:                "activation-task",
		RequestDigest:         taskpermit.RequestDigest(request),
		RequestBytes:          int64(len(request)), ContentType: operation.ContentType,
		NotBefore: now.Add(-30 * time.Second).Format(time.RFC3339),
		ExpiresAt: now.Add(9 * time.Minute).Format(time.RFC3339),
	}
	payload, err := json.Marshal(statement)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := dsse.Sign(
		taskpermit.PayloadType, payload, "tenant-task", private,
	)
	if err != nil {
		t.Fatal(err)
	}
	permitRaw, err := dsse.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	public := private.Public().(ed25519.PublicKey)
	raw, err := json.Marshal(taskBundle{
		SchemaVersion: taskBundleSchemaV2,
		ServicePath:   admitted.ServicePath,
		Operation:     operation,
		Request:       base64.StdEncoding.EncodeToString(request),
		Permit:        base64.StdEncoding.EncodeToString(permitRaw),
		Authority: taskBundleAuthority{
			KeyID:     "tenant-task",
			PublicKey: base64.StdEncoding.EncodeToString(public),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	verified, err := decodeTaskBundle(
		raw, map[string]ed25519.PublicKey{"tenant-task": public},
		now,
		taskpermit.MaxValidity,
	)
	if err != nil {
		t.Fatal(err)
	}
	return raw, verified
}

type offlineGatewayEvidenceResult struct {
	public ed25519.PublicKey
	result activation.GatewayEvidenceResultV1
}

func offlineGatewayEvidence(
	t *testing.T,
	directory string,
	task verifiedTaskBundle,
	taskProtocol string,
	resultRaw []byte,
) offlineGatewayEvidenceResult {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "activation-gateway-receipts.ndjson")
	log, err := connectorledger.Open(path, private, "node-a/gateway", 1)
	if err != nil {
		t.Fatal(err)
	}
	statement := task.Verified.Statement
	event := connectorledger.Event{
		Phase: connectorledger.Authorize, Outcome: connectorledger.Allowed,
		Kind:     connectorledger.ServiceTask,
		TenantID: statement.TenantID, RuntimeRef: statement.RuntimeRef,
		CapsuleDigest:     statement.CapsuleDigest,
		PolicyDigest:      statement.PolicyDigest,
		RoutePolicyDigest: statement.RoutePolicyDigest,
		Generation:        statement.Generation, GrantID: statement.GrantID,
		ServiceID: statement.ServiceID, OperationID: statement.OperationID,
		OperationPolicyDigest: statement.OperationPolicyDigest,
		TaskDigest: taskpermit.TaskDigest(
			statement.TenantID, statement.InstanceID, statement.TaskID,
		),
		AuthorityKeyID: task.Verified.KeyID,
		PermitDigest:   task.Verified.EnvelopeDigest,
		RequestDigest:  statement.RequestDigest,
		RequestBytes:   statement.RequestBytes,
		TaskProtocol:   taskProtocol,
	}
	if _, err := log.Begin(event); err != nil {
		t.Fatal(err)
	}
	runID := "run_0123456789abcdef0123456789abcdef"
	event.Phase, event.Outcome = connectorledger.Dispatch, connectorledger.Responded
	event.HTTPStatus, event.ResponseBytes, event.RunID = 202, 128, runID
	if _, err := log.Dispatch(event); err != nil {
		t.Fatal(err)
	}
	event.Phase, event.HTTPStatus = connectorledger.Terminal, 200
	event.ResponseBytes = int64(len(resultRaw))
	event.TaskStatus = connectorledger.TaskStatusAgentReportedCompleted
	event.ResultDigest = dsse.Digest(resultRaw)
	if _, err := log.Finish(event); err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	collected, err := activation.CollectGatewayEvidenceV1(
		activation.GatewayEvidenceRequestV1{
			Task: task.Verified, TaskProtocol: taskProtocol,
			RunID: runID, Result: resultRaw,
			ReceiptPublicKey: public, ReceiptEpoch: 1,
		},
		path,
	)
	if err != nil {
		t.Fatal(err)
	}
	return offlineGatewayEvidenceResult{public: public, result: collected}
}

func offlineHermesResult(t *testing.T, activationID string) []byte {
	t.Helper()
	workspace, err := json.Marshal(struct {
		Entries        []any  `json:"entries"`
		FileCount      int    `json:"file_count"`
		ManifestDigest string `json:"manifest_digest"`
		Root           string `json:"root"`
		SchemaVersion  string `json:"schema_version"`
		TotalBytes     int64  `json:"total_bytes"`
	}{
		Entries: []any{}, FileCount: 0,
		ManifestDigest: agentrelease.HermesWorkspaceAuditEmptyManifestDigest,
		Root:           "workspace", SchemaVersion: "steward.workspace-audit.result.v1",
		TotalBytes: 0,
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(struct {
		Object    string         `json:"object"`
		RunID     string         `json:"run_id"`
		Status    string         `json:"status"`
		UpdatedAt float64        `json:"updated_at"`
		CreatedAt float64        `json:"created_at"`
		SessionID string         `json:"session_id"`
		Model     string         `json:"model"`
		Output    string         `json:"output"`
		Usage     map[string]int `json:"usage"`
		LastEvent string         `json:"last_event"`
	}{
		Object: "hermes.run",
		RunID:  "run_0123456789abcdef0123456789abcdef",
		Status: "completed", UpdatedAt: 2, CreatedAt: 1,
		SessionID: agentrelease.HermesSessionIDPrefix + "-" + activationID,
		Model:     "local-model", Output: string(workspace),
		Usage: map[string]int{
			"input_tokens": 1, "output_tokens": 2, "total_tokens": 3,
		},
		LastEvent: "run.completed",
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func offlineActivationStates(
	t *testing.T,
	binding activation.BindingV1,
	runtimeRef string,
	finalAt time.Time,
) ([][]byte, activation.StateV1) {
	t.Helper()
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
	base := finalAt.Add(-time.Duration(len(phases)-1) * time.Second)
	var raws [][]byte
	var previous activation.StateV1
	for index, phase := range phases {
		state := activation.StateV1{
			SchemaVersion: activation.StateSchemaV1,
			Binding:       binding,
			Phase:         phase,
			UpdatedAt:     base.Add(time.Duration(index) * time.Second).Format(time.RFC3339Nano),
		}
		if index >= 4 {
			state.RuntimeRef = runtimeRef
		}
		raw, err := activation.MarshalStateV1(state)
		if err != nil {
			t.Fatal(err)
		}
		if index > 0 {
			if err := activation.ValidateStateTransitionV1(previous, state); err != nil {
				t.Fatal(err)
			}
		}
		raws = append(raws, raw)
		previous = state
	}
	return raws, previous
}

func offlineWritePublicKey(
	t *testing.T,
	directory, name string,
	public ed25519.PublicKey,
) string {
	t.Helper()
	path := filepath.Join(directory, name)
	raw := []byte(base64.StdEncoding.EncodeToString(public) + "\n")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func offlineRead(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
