package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/activation"
	"github.com/hardrails/steward/internal/activationstore"
	"github.com/hardrails/steward/internal/controlwitness"
	"github.com/hardrails/steward/internal/dsse"
)

type storedProofTailFixture struct {
	store            *activationstore.Store
	inputs           verifiedActivationInputs
	chain            activationStateChain
	binding          activation.BindingV1
	admitted         permitAdmission
	task             verifiedTaskBundle
	submit           activationSubmitRecord
	resultRaw        []byte
	gatewayResult    activation.GatewayEvidenceResultV1
	executorResult   activation.ExecutorEvidenceResultV1
	baselineRaw      []byte
	finalRaw         []byte
	checkpointRaw    []byte
	beginDigest      string
	checkpointDigest string
	witnessPublic    []byte
}

func TestStoredActivationProofTailArtifactsRoundTrip(t *testing.T) {
	fixture := newStoredProofTailFixture(t)
	gatewayResult, present, err := readStoredActivationGatewayEvidence(
		context.Background(), fixture.store, fixture.task,
		fixture.submit, fixture.resultRaw,
	)
	if err != nil || !present ||
		gatewayResult.Coordinate != fixture.gatewayResult.Coordinate {
		t.Fatalf("gateway present=%v result=%#v err=%v", present, gatewayResult, err)
	}

	raw, digestValue, err := ensureActivationExecutorCheckpoint(
		context.Background(), fixture.store, fixture.inputs, fixture.binding,
		fixture.admitted, fixture.gatewayResult, "", "",
	)
	if err != nil || !bytes.Equal(raw, fixture.checkpointRaw) ||
		digestValue != fixture.checkpointDigest {
		t.Fatalf("checkpoint digest=%q err=%v", digestValue, err)
	}
	result, err := ensureActivationExecutorEvidence(
		context.Background(), fixture.store, fixture.inputs, fixture.binding,
		fixture.admitted, fixture.baselineRaw, fixture.finalRaw,
		fixture.checkpointRaw, fixture.beginDigest, fixture.checkpointDigest,
		fixture.witnessPublic, filepath.Join(t.TempDir(), "unused"),
	)
	if err != nil || result.Coordinate != fixture.executorResult.Coordinate {
		t.Fatalf("executor result=%#v err=%v", result, err)
	}
	if _, err := finalizeActivationProof(
		fixture.store, &fixture.chain, fixture.inputs,
		fixture.beginDigest, fixture.checkpointDigest,
		fixture.executorResult, fixture.gatewayResult,
	); err == nil || !strings.Contains(err.Error(), "only after evidence collection") {
		t.Fatalf("passed-state finalize err=%v", err)
	}
}

func TestActivationProofTailRejectsRetainedConflictsAndCancellation(t *testing.T) {
	fixture := newStoredProofTailFixture(t)
	changedGateway := fixture.gatewayResult
	changedGateway.Canary.ResultBytes++
	if _, _, err := ensureActivationExecutorCheckpoint(
		context.Background(), fixture.store, fixture.inputs, fixture.binding,
		fixture.admitted, changedGateway, "", "",
	); err == nil {
		t.Fatal("changed retained Executor checkpoint accepted")
	}

	beginStore := newActivationRunStore(t)
	if err := beginStore.WriteOnce(
		activationstore.ExecutorBeginFileName, fixture.checkpointRaw,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyStoredActivationExecutorBegin(
		beginStore, fixture.inputs, fixture.binding, fixture.admitted,
	); err == nil {
		t.Fatal("changed retained Executor begin accepted")
	}
	checkpointStore := newActivationRunStore(t)
	if err := checkpointStore.WriteOnce(
		activationstore.ExecutorCheckpointFileName, fixture.baselineRaw,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyStoredActivationExecutorCheckpoint(
		checkpointStore, fixture.inputs, fixture.binding, fixture.admitted,
		fixture.gatewayResult,
	); err == nil {
		t.Fatal("changed retained Executor checkpoint accepted")
	}

	badCheckpointStore := newActivationRunStore(t)
	if _, err := ensureActivationExecutorEvidence(
		context.Background(), badCheckpointStore, fixture.inputs, fixture.binding,
		fixture.admitted, fixture.baselineRaw, fixture.finalRaw,
		[]byte("not a checkpoint"), fixture.beginDigest,
		fixture.checkpointDigest, fixture.witnessPublic, "unused",
	); err == nil {
		t.Fatal("malformed checkpoint accepted before Executor evidence collection")
	}

	invalidDeltaStore := newActivationRunStore(t)
	if err := invalidDeltaStore.WriteOnce(
		activationstore.ExecutorDeltaFileName, []byte("bad delta"),
	); err != nil {
		t.Fatal(err)
	}
	if _, err := ensureActivationExecutorEvidence(
		context.Background(), invalidDeltaStore, fixture.inputs, fixture.binding,
		fixture.admitted, fixture.baselineRaw, fixture.finalRaw,
		fixture.checkpointRaw, fixture.beginDigest, fixture.checkpointDigest,
		fixture.witnessPublic, "unused",
	); err == nil {
		t.Fatal("invalid retained Executor delta accepted")
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ensureActivationExecutorEvidence(
		canceled, fixture.store, fixture.inputs, fixture.binding,
		fixture.admitted, fixture.baselineRaw, fixture.finalRaw,
		fixture.checkpointRaw, fixture.beginDigest, fixture.checkpointDigest,
		fixture.witnessPublic, "unused",
	); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled retained delta verification err=%v", err)
	}

	missingDeltaStore := newActivationRunStore(t)
	if _, err := ensureActivationExecutorEvidence(
		context.Background(), missingDeltaStore, fixture.inputs, fixture.binding,
		fixture.admitted, []byte("{"), fixture.finalRaw,
		fixture.checkpointRaw, fixture.beginDigest, fixture.checkpointDigest,
		fixture.witnessPublic, "unused",
	); err == nil {
		t.Fatal("invalid witness pair reached local Executor log")
	}
	if _, err := ensureActivationExecutorEvidence(
		context.Background(), missingDeltaStore, fixture.inputs, fixture.binding,
		fixture.admitted, fixture.baselineRaw, fixture.finalRaw,
		fixture.checkpointRaw, fixture.beginDigest, fixture.checkpointDigest,
		fixture.witnessPublic, filepath.Join(t.TempDir(), "missing"),
	); err == nil || !strings.Contains(err.Error(), "evidence log") {
		t.Fatalf("missing Executor evidence log err=%v", err)
	}
}

func TestEnsureActivationExecutorCheckpointLiveAndErrorPaths(t *testing.T) {
	fixture := newStoredProofTailFixture(t)
	tokenPath := filepath.Join(t.TempDir(), "executor.token")
	if err := os.WriteFile(tokenPath, []byte("test-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		if request.Header.Get("Authorization") != "Bearer test-token" {
			t.Error("missing Executor bearer token")
		}
		var body map[string]any
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{"schema_version":"steward.executor-activation-checkpoint.v1","activation_id":`+
			jsonString(t, fixture.inputs.plan.ActivationID)+
			`,"checkpoint_digest":`+jsonString(t, body["checkpoint_digest"].(string))+`}`)
	}))
	defer server.Close()
	store := newActivationRunStore(t)
	raw, checkpointDigest, err := ensureActivationExecutorCheckpoint(
		context.Background(), store, fixture.inputs, fixture.binding,
		fixture.admitted, fixture.gatewayResult, server.URL, tokenPath,
	)
	if err != nil || len(raw) == 0 || checkpointDigest == "" {
		t.Fatalf("live checkpoint digest=%q err=%v", checkpointDigest, err)
	}
	if retained, err := store.Read(
		activationstore.ExecutorCheckpointFileName,
		activation.MaxExecutorCheckpointBytes,
	); err != nil || !bytes.Equal(retained, raw) {
		t.Fatalf("retained checkpoint err=%v", err)
	}

	invalidBinding := fixture.binding
	invalidBinding.NodeID = ""
	if _, _, err := ensureActivationExecutorCheckpoint(
		context.Background(), newActivationRunStore(t), fixture.inputs,
		invalidBinding, fixture.admitted, fixture.gatewayResult, "", "",
	); err == nil {
		t.Fatal("invalid checkpoint binding accepted")
	}
	if _, _, err := ensureActivationExecutorCheckpoint(
		context.Background(), newActivationRunStore(t), fixture.inputs,
		fixture.binding, fixture.admitted, fixture.gatewayResult,
		server.URL, filepath.Join(t.TempDir(), "missing-token"),
	); err == nil {
		t.Fatal("missing Executor token accepted")
	}
}

func TestFinalizeActivationProofNewAndRetainedMismatchPaths(t *testing.T) {
	previousNow := timeNow
	t.Cleanup(func() { timeNow = previousNow })

	fixture := newActivationStatusFixture(
		t, activation.PhaseEvidenceCollected, "node-a",
	)
	store, err := activationstore.Open(fixture.directory)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	inputs, chain, err := loadUnverifiedActivationStateChain(store)
	if err != nil {
		t.Fatal(err)
	}
	currentTime, _ := time.Parse(time.RFC3339Nano, chain.latest().UpdatedAt)
	executorResult, gatewayResult := activationProofEvidenceResults(
		chain.latest().Binding,
		currentTime.Add(2*time.Second).Format(time.RFC3339Nano),
	)
	timeNow = func() time.Time { return currentTime.Add(-time.Second) }
	proofRaw, err := finalizeActivationProof(
		store, &chain, inputs, digest('6'), digest('7'),
		executorResult, gatewayResult,
	)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := activation.ParseProofV1(proofRaw)
	if err != nil {
		t.Fatal(err)
	}
	if proof.CompletedAt != executorResult.Witness.WitnessedAt ||
		chain.latest().Phase != activation.PhasePassed {
		t.Fatalf("proof=%#v latest=%#v", proof, chain.latest())
	}

	mismatchFixture := newActivationStatusFixture(
		t, activation.PhaseEvidenceCollected, "node-a",
	)
	mismatchStore, err := activationstore.Open(mismatchFixture.directory)
	if err != nil {
		t.Fatal(err)
	}
	defer mismatchStore.Close()
	mismatchInputs, mismatchChain, err :=
		loadUnverifiedActivationStateChain(mismatchStore)
	if err != nil {
		t.Fatal(err)
	}
	executorResult, gatewayResult = activationProofEvidenceResults(
		mismatchChain.latest().Binding, mismatchChain.latest().UpdatedAt,
	)
	writeRecoverableProofTail(
		t, mismatchStore, mismatchChain, executorResult, gatewayResult,
	)
	gatewayResult.Canary.ResultBytes++
	if _, err := finalizeActivationProof(
		mismatchStore, &mismatchChain, mismatchInputs,
		digest('6'), digest('7'), executorResult, gatewayResult,
	); err == nil {
		t.Fatal("retained proof accepted changed verified evidence")
	}
}

func newStoredProofTailFixture(t *testing.T) storedProofTailFixture {
	t.Helper()
	previousNow := timeNow
	t.Cleanup(func() { timeNow = previousNow })
	offline := newOfflineActivationFixture(t)
	store, err := activationstore.Open(offline.directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	publisher, err := readPublicKey(offline.publisherPublicPath)
	if err != nil {
		t.Fatal(err)
	}
	siteRoot, err := readPublicKey(offline.siteRootPublicPath)
	if err != nil {
		t.Fatal(err)
	}
	witness, err := controlwitness.LoadPublic(offline.witnessPublicPath)
	if err != nil {
		t.Fatal(err)
	}
	inputs, err := loadVerifiedActivationInputs(store, activationTrust{
		publisherKeyID: "publisher-a", publisher: publisher,
		siteRootKeyID: "site-root", siteRoot: siteRoot, witness: witness,
	}, offline.now)
	if err != nil {
		t.Fatal(err)
	}
	chain, err := loadActivationStateChain(store, inputs)
	if err != nil {
		t.Fatal(err)
	}
	admissionRaw, err := store.Read(
		activationstore.AdmissionFileName, maxArtifactBytes,
	)
	if err != nil {
		t.Fatal(err)
	}
	var admitted permitAdmission
	if err := json.Unmarshal(admissionRaw, &admitted); err != nil {
		t.Fatal(err)
	}
	_, task, err := loadVerifiedActivationTask(
		store, inputs, admitted.EvidenceKeyID,
	)
	if err != nil {
		t.Fatal(err)
	}
	submit, err := readActivationSubmit(store, task)
	if err != nil {
		t.Fatal(err)
	}
	resultRaw, err := store.Read(
		activationstore.CanaryResultFileName, maxArtifactBytes,
	)
	if err != nil {
		t.Fatal(err)
	}
	gatewayResult, err := verifyStoredActivationGatewayEvidence(
		context.Background(), store, task, submit, resultRaw,
	)
	if err != nil {
		t.Fatal(err)
	}
	binding := chain.latest().Binding
	beginDigest, err := verifyStoredActivationExecutorBegin(
		store, inputs, binding, admitted,
	)
	if err != nil {
		t.Fatal(err)
	}
	checkpointDigest, err := verifyStoredActivationExecutorCheckpoint(
		store, inputs, binding, admitted, gatewayResult,
	)
	if err != nil {
		t.Fatal(err)
	}
	executorResult, err := verifyStoredActivationExecutorEvidence(
		context.Background(), store, inputs, binding, admitted,
		beginDigest, checkpointDigest, witness,
	)
	if err != nil {
		t.Fatal(err)
	}
	read := func(name string, limit int64) []byte {
		raw, readErr := store.Read(name, limit)
		if readErr != nil {
			t.Fatal(readErr)
		}
		return raw
	}
	return storedProofTailFixture{
		store: store, inputs: inputs, chain: chain, binding: binding,
		admitted: admitted, task: task, submit: submit, resultRaw: resultRaw,
		gatewayResult: gatewayResult, executorResult: executorResult,
		baselineRaw: read(
			activationstore.ExecutorBaselineWitnessFileName, maxArtifactBytes,
		),
		finalRaw: read(
			activationstore.ExecutorFinalWitnessFileName, maxArtifactBytes,
		),
		checkpointRaw: read(
			activationstore.ExecutorCheckpointFileName, maxArtifactBytes,
		),
		beginDigest: beginDigest, checkpointDigest: checkpointDigest,
		witnessPublic: witness,
	}
}

func writeRecoverableProofTail(
	t *testing.T,
	store *activationstore.Store,
	chain activationStateChain,
	executorResult activation.ExecutorEvidenceResultV1,
	gatewayResult activation.GatewayEvidenceResultV1,
) {
	t.Helper()
	next := chain.latest()
	next.Phase = activation.PhasePassed
	next.UpdatedAt = "2026-07-16T01:00:11Z"
	nextRaw, err := activation.MarshalStateV1(next)
	if err != nil {
		t.Fatal(err)
	}
	proofRaw, err := activation.MarshalProofV1(activation.ProofV1{
		SchemaVersion: activation.ProofSchemaV1,
		Binding:       chain.latest().Binding, StateDigest: dsse.Digest(nextRaw),
		RuntimeRef:               chain.latest().RuntimeRef,
		Canary:                   gatewayResult.Canary,
		ExecutorBeginDigest:      digest('6'),
		ExecutorCheckpointDigest: digest('7'),
		ExecutorEvidence:         executorResult.Coordinate,
		GatewayEvidence:          gatewayResult.Coordinate,
		Witness:                  executorResult.Witness, CompletedAt: next.UpdatedAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.WriteOnce(activationstore.ProofFileName, proofRaw); err != nil {
		t.Fatal(err)
	}
}

func jsonString(t *testing.T, value string) string {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}
