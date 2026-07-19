package controlstore

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/activationcanary"
	"github.com/hardrails/steward/internal/controlauth"
	"github.com/hardrails/steward/internal/controlcapture"
	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/evidence"
)

func TestEvidenceCaptureObservesSealsExportsRecoversAndDeletes(t *testing.T) {
	fixture := newExecutorEvidenceFixture(t, "tenant-a")
	runtimeRef := "executor-" + strings.Repeat("a", 64)
	armAt := fixture.now.Add(2 * time.Minute)
	request := evidenceCaptureRequest(
		fixture.identity.NodeID,
		runtimeRef,
		30*time.Minute,
	)
	statement := baseV4CommandStatement(
		"capture-canary", "tenant-a", fixture.identity.NodeID,
		"activation-canary", 7, request.Generation,
	)
	projection := controlStoreCanaryFixture(t, &statement, fixture.now)
	canaryCommand, err := activationcanary.ParseCommandV1(statement.Payload)
	if err != nil {
		t.Fatal(err)
	}
	request.ActivationBeginDigest = canaryCommand.Admission.ActivationBeginDigest
	armed, created, err := fixture.store.ArmEvidenceCapture(fixture.admin, request, armAt)
	if err != nil || !created || armed.State != EvidenceCaptureArmed || armed.FrameCount != 0 {
		t.Fatalf("arm evidence capture = (%+v, %v, %v)", armed, created, err)
	}
	if err := armed.Validate(); err != nil {
		t.Fatalf("armed public projection: %v", err)
	}
	retry, created, err := fixture.store.ArmEvidenceCapture(
		fixture.admin, request, armAt.Add(time.Second),
	)
	if err != nil || created || retry.CaptureID != armed.CaptureID {
		t.Fatalf("exact arm retry = (%+v, %v, %v)", retry, created, err)
	}
	conflict := request
	conflict.ActivationID = "activation-conflict"
	if _, _, err := fixture.store.ArmEvidenceCapture(
		fixture.admin, conflict, armAt.Add(time.Second),
	); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflicting capture reuse error = %v", err)
	}

	capsuleDigest := dsse.Digest([]byte("capsule"))
	policyDigest := dsse.Digest([]byte("policy"))
	checkpointDigest := "sha256:" + strings.Repeat("5", 64)
	appendCaptureActivation(
		t, fixture, runtimeRef, request.Generation, request.ActivationID,
		capsuleDigest, policyDigest, request.ActivationBeginDigest, checkpointDigest,
	)
	if _, err := fixture.log.Append(evidence.Event{
		Type: evidence.AdmissionAllow, TenantID: "tenant-a", RuntimeRef: runtimeRef,
		CapsuleDigest: capsuleDigest, PolicyDigest: policyDigest,
		Generation: request.Generation, GrantID: "suffix", Outcome: evidence.Allowed,
	}); err != nil {
		t.Fatal(err)
	}
	poll := fixture.poll(t, armAt.Add(time.Minute))
	report, delta := fixture.reportFrom(t, evidence.Coordinate{}, poll.Challenge)
	response, err := fixture.store.ApplyExecutorEvidenceReport(
		fixture.auth, fixture.identity, report, armAt.Add(2*time.Minute),
	)
	if err != nil || !response.Applied || response.Status.Head == nil ||
		response.Status.Head.Sequence != 3 {
		t.Fatalf("capture evidence report = (%+v, %v)", response, err)
	}
	observed, found, err := fixture.store.GetEvidenceCapture(
		fixture.admin, request.CaptureID, armAt.Add(3*time.Minute),
	)
	if err != nil || !found || observed.State != EvidenceCaptureObserved ||
		observed.FrameCount != len(delta.Frames) || observed.CapturedBytes == 0 ||
		observed.FinalHead.Sequence != 3 ||
		observed.ActivationCheckpointDigest != checkpointDigest ||
		observed.CapsuleDigest != capsuleDigest || observed.PolicyDigest != policyDigest {
		t.Fatalf("observed capture = (%+v, %v, %v)", observed, found, err)
	}
	if err := observed.Validate(); err != nil {
		t.Fatalf("observed public projection: %v", err)
	}

	delivery := submitAndPollActivationCanaryV4(
		t, fixture.recordsFixture, fixture.identity, statement,
	)
	if applied, err := fixture.store.ApplyReportV4(
		fixture.identity,
		activationCanaryReportV4(delivery, statement, projection),
		armAt.Add(4*time.Minute),
	); err != nil || !applied {
		t.Fatalf("apply canary result = (%v, %v)", applied, err)
	}
	sealed, changed, err := fixture.store.SealEvidenceCapture(
		fixture.admin, request.NodeID, request.CaptureID, statement.CommandID, armAt.Add(5*time.Minute),
	)
	if err != nil || !changed || sealed.State != EvidenceCaptureSealed ||
		sealed.CanaryCommandID != statement.CommandID {
		t.Fatalf("seal evidence capture = (%+v, %v, %v)", sealed, changed, err)
	}
	if retry, changed, err := fixture.store.SealEvidenceCapture(
		fixture.admin, request.NodeID, request.CaptureID, statement.CommandID, armAt.Add(6*time.Minute),
	); err != nil || changed || retry.State != EvidenceCaptureSealed {
		t.Fatalf("exact seal retry = (%+v, %v, %v)", retry, changed, err)
	}

	snapshot, found, err := fixture.store.SnapshotEvidenceCaptureExport(
		fixture.admin, request.CaptureID, armAt.Add(7*time.Minute),
	)
	if err != nil || !found || len(snapshot.Frames) != len(delta.Frames) {
		t.Fatalf("capture export snapshot = (%+v, %v, %v)", snapshot.Capture, found, err)
	}
	exportStatement, err := snapshot.Statement(
		fixture.auth.InstanceID(), armAt.Add(7*time.Minute),
	)
	if err != nil || exportStatement.FramesDigest !=
		controlprotocol.ControllerEvidenceCaptureFramesDigestV1(delta.Frames) {
		t.Fatalf("capture export statement = (%+v, %v)", exportStatement, err)
	}
	witnessPublic, witnessPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	portable, err := controlprotocol.SignControllerEvidenceCaptureV1(
		exportStatement, snapshot.Frames, witnessPrivate,
	)
	if err != nil {
		t.Fatalf("sign controller evidence capture: %v", err)
	}
	verified, err := controlcapture.VerifyV1(portable, witnessPublic)
	if err != nil || verified.FinalHead.Sequence != observed.FinalHead.Sequence ||
		verified.Checkpoint.Receipt.MetadataHash != checkpointDigest {
		t.Fatalf("offline verify controller capture = (%+v, %v)", verified, err)
	}
	current, err := fixture.store.EvidenceCaptureSnapshotCurrent(
		fixture.admin, snapshot, armAt.Add(7*time.Minute),
	)
	if err != nil || !current {
		t.Fatalf("capture snapshot current = (%v, %v)", current, err)
	}
	snapshot.Frames[0][4] ^= 1
	retainedSnapshot, found, err := fixture.store.SnapshotEvidenceCaptureExport(
		fixture.admin, request.CaptureID, armAt.Add(7*time.Minute),
	)
	if err != nil || !found || retainedSnapshot.Frames[0][4] == snapshot.Frames[0][4] {
		t.Fatal("export snapshot frames alias durable state")
	}

	if err := fixture.store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(fixture.dir, fixture.limits)
	if err != nil {
		t.Fatalf("reopen capture store: %v", err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	fixture.store = reopened
	recovered, found, err := reopened.GetEvidenceCapture(
		fixture.admin, request.CaptureID, armAt.Add(8*time.Minute),
	)
	if err != nil || !found || recovered.State != EvidenceCaptureSealed ||
		recovered.FrameCount != len(delta.Frames) {
		t.Fatalf("recovered capture = (%+v, %v, %v)", recovered, found, err)
	}
	if deleted, err := reopened.DeleteEvidenceCapture(
		fixture.admin, request.NodeID, request.CaptureID, armAt.Add(9*time.Minute),
	); err != nil || !deleted {
		t.Fatalf("delete capture = (%v, %v)", deleted, err)
	}
	if current, err := reopened.EvidenceCaptureSnapshotCurrent(
		fixture.admin, retainedSnapshot, armAt.Add(10*time.Minute),
	); err != nil || current {
		t.Fatalf("deleted capture snapshot current = (%v, %v)", current, err)
	}
}

func TestEvidenceCaptureOverflowFailsWithoutBlockingWitness(t *testing.T) {
	fixture := newExecutorEvidenceFixture(t, "tenant-a")
	runtimeRef := "executor-" + strings.Repeat("a", 64)
	armAt := fixture.now.Add(2 * time.Minute)
	request := evidenceCaptureRequest(
		fixture.identity.NodeID, runtimeRef, time.Hour,
	)
	if _, created, err := fixture.store.ArmEvidenceCapture(
		fixture.admin, request, armAt,
	); err != nil || !created {
		t.Fatalf("arm capture = (%v, %v)", created, err)
	}
	for index := 0; index < MaxEvidenceCaptureFrames+1; index++ {
		if _, err := fixture.log.Append(evidence.Event{
			Type: evidence.AdmissionAllow, TenantID: "tenant-a", RuntimeRef: runtimeRef,
			CapsuleDigest: dsse.Digest([]byte("capsule")),
			PolicyDigest:  dsse.Digest([]byte("policy")),
			Generation:    uint64(index + 1), GrantID: "ordinary", Outcome: evidence.Allowed,
		}); err != nil {
			t.Fatal(err)
		}
	}
	firstPoll := fixture.poll(t, armAt.Add(time.Minute))
	firstReport, firstDelta := fixture.reportFrom(t, evidence.Coordinate{}, firstPoll.Challenge)
	if len(firstDelta.Frames) != MaxEvidenceCaptureFrames || !firstDelta.More {
		t.Fatalf("first evidence delta = %d frames, more=%v", len(firstDelta.Frames), firstDelta.More)
	}
	if response, err := fixture.store.ApplyExecutorEvidenceReport(
		fixture.auth, fixture.identity, firstReport, armAt.Add(2*time.Minute),
	); err != nil || !response.Applied {
		t.Fatalf("apply first evidence delta = (%+v, %v)", response, err)
	}
	coordinate := evidence.Coordinate{
		Sequence: firstDelta.Head.Sequence, ChainHash: firstDelta.Head.ChainHash,
	}
	secondPoll := fixture.poll(t, armAt.Add(3*time.Minute))
	secondReport, secondDelta := fixture.reportFrom(t, coordinate, secondPoll.Challenge)
	if len(secondDelta.Frames) != 1 {
		t.Fatalf("second evidence delta frames = %d", len(secondDelta.Frames))
	}
	response, err := fixture.store.ApplyExecutorEvidenceReport(
		fixture.auth, fixture.identity, secondReport, armAt.Add(4*time.Minute),
	)
	if err != nil || !response.Applied || response.Status.Head == nil ||
		response.Status.Head.Sequence != uint64(MaxEvidenceCaptureFrames+1) {
		t.Fatalf("overflow evidence advance = (%+v, %v)", response, err)
	}
	capture, found, err := fixture.store.GetEvidenceCapture(
		fixture.admin, request.CaptureID, armAt.Add(5*time.Minute),
	)
	if err != nil || !found || capture.State != EvidenceCaptureFailed ||
		capture.Failure != EvidenceCaptureFailureOverflow ||
		capture.FrameCount != MaxEvidenceCaptureFrames {
		t.Fatalf("overflow capture = (%+v, %v, %v)", capture, found, err)
	}
}

func TestEvidenceCaptureTargetContradictionFailsWithoutBlockingWitness(t *testing.T) {
	fixture := newExecutorEvidenceFixture(t, "tenant-a")
	runtimeRef := "executor-" + strings.Repeat("a", 64)
	armAt := fixture.now.Add(2 * time.Minute)
	request := evidenceCaptureRequest(
		fixture.identity.NodeID, runtimeRef, time.Hour,
	)
	if _, created, err := fixture.store.ArmEvidenceCapture(
		fixture.admin, request, armAt,
	); err != nil || !created {
		t.Fatalf("arm capture = (%v, %v)", created, err)
	}
	appendCaptureActivation(
		t, fixture, runtimeRef, request.Generation, "activation-other",
		dsse.Digest([]byte("capsule")), dsse.Digest([]byte("policy")),
		request.ActivationBeginDigest,
		dsse.Digest([]byte("checkpoint")),
	)
	poll := fixture.poll(t, armAt.Add(time.Minute))
	report, _ := fixture.reportFrom(t, evidence.Coordinate{}, poll.Challenge)
	response, err := fixture.store.ApplyExecutorEvidenceReport(
		fixture.auth, fixture.identity, report, armAt.Add(2*time.Minute),
	)
	if err != nil || !response.Applied || response.Status.Head == nil ||
		response.Status.Head.Sequence != 2 {
		t.Fatalf("contradictory target witness advance = (%+v, %v)", response, err)
	}
	capture, found, err := fixture.store.GetEvidenceCapture(
		fixture.admin, request.CaptureID, armAt.Add(3*time.Minute),
	)
	if err != nil || !found || capture.State != EvidenceCaptureFailed ||
		capture.Failure != EvidenceCaptureFailureContradiction || capture.FrameCount != 0 {
		t.Fatalf("contradictory target capture = (%+v, %v, %v)", capture, found, err)
	}
}

func TestEvidenceCaptureRejectsCheckpointWhoseBeginWasAlreadyWitnessedBeforeArm(t *testing.T) {
	fixture := newExecutorEvidenceFixture(t, "tenant-a")
	runtimeRef := "executor-" + strings.Repeat("a", 64)
	request := evidenceCaptureRequest(fixture.identity.NodeID, runtimeRef, time.Hour)
	capsuleDigest := dsse.Digest([]byte("capsule"))
	policyDigest := dsse.Digest([]byte("policy"))
	begin := evidence.Event{
		Type: evidence.ActivationBegin, TenantID: "tenant-a", RuntimeRef: runtimeRef,
		CapsuleDigest: capsuleDigest, PolicyDigest: policyDigest,
		Generation: request.Generation, GrantID: request.ActivationID,
		Outcome: evidence.Allowed, MetadataHash: request.ActivationBeginDigest,
	}
	if _, err := fixture.log.AppendActivationBegin(begin); err != nil {
		t.Fatal(err)
	}
	firstPoll := fixture.poll(t, fixture.now.Add(2*time.Minute))
	firstReport, firstDelta := fixture.reportFrom(t, evidence.Coordinate{}, firstPoll.Challenge)
	if response, err := fixture.store.ApplyExecutorEvidenceReport(
		fixture.auth, fixture.identity, firstReport, fixture.now.Add(2*time.Minute+time.Second),
	); err != nil || !response.Applied || response.Status.Head == nil || response.Status.Head.Sequence != 1 {
		t.Fatalf("witness pre-arm begin = (%+v, %v)", response, err)
	}

	armAt := fixture.now.Add(3 * time.Minute)
	if _, created, err := fixture.store.ArmEvidenceCapture(fixture.admin, request, armAt); err != nil || !created {
		t.Fatalf("arm after witnessed begin = (%v, %v)", created, err)
	}
	checkpoint := begin
	checkpoint.Type = evidence.ActivationCheckpoint
	checkpoint.Outcome = evidence.Committed
	checkpoint.MetadataHash = dsse.Digest([]byte("checkpoint"))
	if _, err := fixture.log.AppendActivationCheckpoint(checkpoint); err != nil {
		t.Fatal(err)
	}
	secondPoll := fixture.poll(t, fixture.now.Add(4*time.Minute))
	secondReport, _ := fixture.reportFrom(
		t,
		evidence.Coordinate{Sequence: firstDelta.Head.Sequence, ChainHash: firstDelta.Head.ChainHash},
		secondPoll.Challenge,
	)
	response, err := fixture.store.ApplyExecutorEvidenceReport(
		fixture.auth, fixture.identity, secondReport, fixture.now.Add(4*time.Minute+time.Second),
	)
	if err != nil || !response.Applied || response.Status.Head == nil || response.Status.Head.Sequence != 2 {
		t.Fatalf("witness checkpoint-only suffix = (%+v, %v)", response, err)
	}
	capture, found, err := fixture.store.GetEvidenceCapture(
		fixture.admin, request.CaptureID, fixture.now.Add(5*time.Minute),
	)
	if err != nil || !found || capture.State != EvidenceCaptureFailed ||
		capture.Failure != EvidenceCaptureFailureContradiction {
		t.Fatalf("checkpoint-only capture = (%+v, %v, %v)", capture, found, err)
	}
	if _, _, err := fixture.store.SealEvidenceCapture(
		fixture.admin, request.NodeID, request.CaptureID, "canary-command", fixture.now.Add(6*time.Minute),
	); !errors.Is(err, ErrConflict) {
		t.Fatalf("seal checkpoint-only capture error = %v", err)
	}
}

func TestEvidenceCaptureRejectsWrongActivationBeginDigestWithoutBlockingWitness(t *testing.T) {
	fixture := newExecutorEvidenceFixture(t, "tenant-a")
	runtimeRef := "executor-" + strings.Repeat("a", 64)
	request := evidenceCaptureRequest(fixture.identity.NodeID, runtimeRef, time.Hour)
	armAt := fixture.now.Add(2 * time.Minute)
	if _, created, err := fixture.store.ArmEvidenceCapture(fixture.admin, request, armAt); err != nil || !created {
		t.Fatalf("arm capture = (%v, %v)", created, err)
	}
	begin := evidence.Event{
		Type: evidence.ActivationBegin, TenantID: "tenant-a", RuntimeRef: runtimeRef,
		CapsuleDigest: dsse.Digest([]byte("capsule")), PolicyDigest: dsse.Digest([]byte("policy")),
		Generation: request.Generation, GrantID: request.ActivationID,
		Outcome: evidence.Allowed, MetadataHash: dsse.Digest([]byte("wrong-begin")),
	}
	if _, err := fixture.log.AppendActivationBegin(begin); err != nil {
		t.Fatal(err)
	}
	poll := fixture.poll(t, armAt.Add(time.Minute))
	report, _ := fixture.reportFrom(t, evidence.Coordinate{}, poll.Challenge)
	response, err := fixture.store.ApplyExecutorEvidenceReport(
		fixture.auth, fixture.identity, report, armAt.Add(2*time.Minute),
	)
	if err != nil || !response.Applied || response.Status.Head == nil || response.Status.Head.Sequence != 1 {
		t.Fatalf("witness wrong begin = (%+v, %v)", response, err)
	}
	capture, found, err := fixture.store.GetEvidenceCapture(
		fixture.admin, request.CaptureID, armAt.Add(3*time.Minute),
	)
	if err != nil || !found || capture.State != EvidenceCaptureFailed ||
		capture.Failure != EvidenceCaptureFailureContradiction {
		t.Fatalf("wrong-begin capture = (%+v, %v, %v)", capture, found, err)
	}
}

func TestEvidenceCaptureClockRollbackCannotBlockOrdinaryWitnessAdvance(t *testing.T) {
	fixture := newExecutorEvidenceFixture(t, "tenant-a")
	runtimeRef := "executor-" + strings.Repeat("a", 64)
	request := evidenceCaptureRequest(fixture.identity.NodeID, runtimeRef, time.Hour)
	if _, err := fixture.log.Append(evidence.Event{
		Type: evidence.InferenceAuthorize, TenantID: "tenant-a", RuntimeRef: "runtime-unrelated",
		CapsuleDigest: dsse.Digest([]byte("other-capsule")),
		PolicyDigest:  dsse.Digest([]byte("other-policy")), Generation: 1,
		GrantID: "ordinary", Outcome: evidence.Allowed,
	}); err != nil {
		t.Fatal(err)
	}
	armAt := fixture.now.Add(3 * time.Minute)
	poll := fixture.poll(t, armAt.Add(-2*time.Second))
	report, _ := fixture.reportFrom(t, evidence.Coordinate{}, poll.Challenge)
	if _, created, err := fixture.store.ArmEvidenceCapture(fixture.admin, request, armAt); err != nil || !created {
		t.Fatalf("arm capture = (%v, %v)", created, err)
	}
	response, err := fixture.store.ApplyExecutorEvidenceReport(
		fixture.auth, fixture.identity, report, armAt.Add(-time.Second),
	)
	if err != nil || !response.Applied || response.Status.Head == nil || response.Status.Head.Sequence != 1 {
		t.Fatalf("clock-rollback witness advance = (%+v, %v)", response, err)
	}
	capture, found, err := fixture.store.GetEvidenceCapture(
		fixture.admin, request.CaptureID, armAt.Add(time.Second),
	)
	if err != nil || !found || capture.State != EvidenceCaptureArmed ||
		capture.FrameCount != 1 || capture.FinalHead.Sequence != 1 {
		t.Fatalf("clock-rollback capture = (%+v, %v, %v)", capture, found, err)
	}
	if err := capture.Validate(); err != nil {
		t.Fatalf("clock-rollback capture validation = %v", err)
	}
}

func TestEvidenceCaptureRecordCapacityDropsCaptureButAdvancesWitness(t *testing.T) {
	fixture := newExecutorEvidenceFixture(t, "tenant-a")
	runtimeRef := "executor-" + strings.Repeat("a", 64)
	request := evidenceCaptureRequest(fixture.identity.NodeID, runtimeRef, time.Hour)
	armAt := fixture.now.Add(2 * time.Minute)
	if _, created, err := fixture.store.ArmEvidenceCapture(fixture.admin, request, armAt); err != nil || !created {
		t.Fatalf("arm capture = (%v, %v)", created, err)
	}
	if _, err := fixture.log.Append(evidence.Event{
		Type: evidence.InferenceAuthorize, TenantID: "tenant-a", RuntimeRef: "runtime-unrelated",
		CapsuleDigest: dsse.Digest([]byte("capsule")), PolicyDigest: dsse.Digest([]byte("policy")),
		Generation: 1, GrantID: "ordinary", Outcome: evidence.Allowed,
	}); err != nil {
		t.Fatal(err)
	}
	poll := fixture.poll(t, armAt.Add(time.Minute))
	report, _ := fixture.reportFrom(t, evidence.Coordinate{}, poll.Challenge)
	now := armAt.Add(2 * time.Minute)
	snapshot, err := fixture.store.executorEvidenceSnapshot(fixture.identity)
	if err != nil {
		t.Fatal(err)
	}
	frames, err := report.DecodeFrames()
	if err != nil {
		t.Fatal(err)
	}
	verified, err := verifyExecutorEvidenceReport(
		fixture.auth, fixture.identity, report.HeadProof, frames, snapshot, now,
	)
	if err != nil || verified.action != executorEvidenceAdvance {
		t.Fatalf("preverify evidence report = (%+v, %v)", verified, err)
	}
	node := cloneNode(fixture.store.current.nodes[fixture.identity.NodeID])
	witness := cloneEvidenceWitness(node.Evidence)
	witness.Sequence = verified.head.Sequence
	witness.ChainHash = verified.head.ChainHash
	witness.AdvancedAt = canonicalTimestamp(now)
	witness.RecordsAccepted = verified.head.Sequence
	witness.LastBatchStart = verified.batchStart
	witness.LastBatchEnd = verified.batchEnd
	witness.LastBatchDigest = verified.batchDigest
	node.Evidence = witness
	base := []mutation{{Kind: mutationNode, Node: &node}}
	basePayload, err := encodeTransaction(base...)
	if err != nil {
		t.Fatal(err)
	}
	captureMutation := fixture.store.evidenceCaptureMutationForReportLocked(
		fixture.identity.NodeID, verified, frames, now,
	)
	if captureMutation == nil {
		t.Fatal("capture mutation was not derived")
	}
	combinedPayload, err := encodeTransaction(append(base, *captureMutation)...)
	if err != nil {
		t.Fatal(err)
	}
	baseRecordLimit := walFrameFixedBytes + len(basePayload)
	if walFrameFixedBytes+len(combinedPayload) <= baseRecordLimit {
		t.Fatal("capture mutation did not enlarge the evidence WAL record")
	}
	fixture.store.limits.MaxRecordBytes = baseRecordLimit

	response, err := fixture.store.ApplyExecutorEvidenceReport(
		fixture.auth, fixture.identity, report, now,
	)
	if err != nil || !response.Applied || response.Status.Head == nil || response.Status.Head.Sequence != 1 {
		t.Fatalf("capacity-isolated evidence advance = (%+v, %v)", response, err)
	}
	if _, found, err := fixture.store.GetEvidenceCapture(
		fixture.admin, request.CaptureID, now.Add(time.Second),
	); err != nil || found {
		t.Fatalf("capacity-dropped capture = (%v, %v)", found, err)
	}
}

func TestEvidenceCaptureCoordinateAndFindingBecomeCaptureFailures(t *testing.T) {
	for name, build := range map[string]func(EvidenceCapture) verifiedExecutorEvidenceReport{
		"coordinate": func(capture EvidenceCapture) verifiedExecutorEvidenceReport {
			return verifiedExecutorEvidenceReport{
				action: executorEvidenceAdvance, baseSequence: capture.FinalHead.Sequence + 1,
				baseChainHash: capture.FinalHead.ChainHash,
			}
		},
		"finding": func(capture EvidenceCapture) verifiedExecutorEvidenceReport {
			return verifiedExecutorEvidenceReport{
				action: executorEvidenceFinding, baseSequence: capture.FinalHead.Sequence,
				baseChainHash: capture.FinalHead.ChainHash,
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newExecutorEvidenceFixture(t, "tenant-a")
			armAt := fixture.now.Add(2 * time.Minute)
			request := evidenceCaptureRequest(
				fixture.identity.NodeID,
				"executor-"+strings.Repeat("a", 64),
				time.Hour,
			)
			view, created, err := fixture.store.ArmEvidenceCapture(fixture.admin, request, armAt)
			if err != nil || !created {
				t.Fatal(err)
			}
			fixture.store.mu.Lock()
			change := fixture.store.evidenceCaptureMutationForReportLocked(
				fixture.identity.NodeID, build(view), nil, armAt.Add(time.Minute),
			)
			if change == nil {
				fixture.store.mu.Unlock()
				t.Fatal("capture report failure produced no durable mutation")
			}
			err = fixture.store.applyMutationsLocked(*change)
			fixture.store.mu.Unlock()
			if err != nil {
				t.Fatal(err)
			}
			failed, found, err := fixture.store.GetEvidenceCapture(
				fixture.admin, request.CaptureID, armAt.Add(2*time.Minute),
			)
			if err != nil || !found || failed.State != EvidenceCaptureFailed {
				t.Fatalf("failed capture = (%+v, %v, %v)", failed, found, err)
			}
			want := EvidenceCaptureFailureFinding
			if name == "coordinate" {
				want = EvidenceCaptureFailureCoordinate
			}
			if failed.Failure != want {
				t.Fatalf("failure = %q, want %q", failed.Failure, want)
			}
		})
	}
}

func TestEvidenceCaptureExpiresAndRequiresSiteAdministrator(t *testing.T) {
	fixture := newExecutorEvidenceFixture(t, "tenant-a")
	runtimeRef := "executor-" + strings.Repeat("a", 64)
	armAt := fixture.now.Add(2 * time.Minute)
	request := evidenceCaptureRequest(
		fixture.identity.NodeID, runtimeRef, 2*MinEvidenceCaptureTTL,
	)
	tenantRaw, _, _, err := fixture.store.IssueOperator(
		fixture.admin, fixture.auth, "tenant-operator", controlauth.RoleTenantOperator,
		"tenant-a", armAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	tenantActor, err := fixture.store.AuthenticateOperator(fixture.auth, tenantRaw)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := fixture.store.ArmEvidenceCapture(
		tenantActor, request, armAt,
	); !errors.Is(err, ErrForbidden) {
		t.Fatalf("tenant operator arm error = %v", err)
	}
	if _, created, err := fixture.store.ArmEvidenceCapture(
		fixture.admin, request, armAt,
	); err != nil || !created {
		t.Fatalf("site administrator arm = (%v, %v)", created, err)
	}
	concurrent := request
	concurrent.CaptureID = "capture-2"
	concurrent.RequestID = "capture-request-2"
	if _, _, err := fixture.store.ArmEvidenceCapture(
		fixture.admin, concurrent, armAt.Add(500*time.Millisecond),
	); !errors.Is(err, ErrConflict) {
		t.Fatalf("second active node capture error = %v", err)
	}
	expiresAt := armAt.Add(request.TTL)
	expired, found, err := fixture.store.GetEvidenceCapture(
		fixture.admin, request.CaptureID, expiresAt,
	)
	if err != nil || !found || expired.State != EvidenceCaptureExpired || expired.ExpiredAt == "" {
		t.Fatalf("expired capture = (%+v, %v, %v)", expired, found, err)
	}
	concurrent.TTL = request.TTL + time.Minute
	if _, created, err := fixture.store.ArmEvidenceCapture(
		fixture.admin, concurrent, expiresAt,
	); err != nil || !created {
		t.Fatalf("arm after prior capture expiry = (%v, %v)", created, err)
	}
}

func TestEvidenceCaptureMutationsAtomicallyFenceReplacementNode(t *testing.T) {
	fixture := newExecutorEvidenceFixture(t, "tenant-a")
	runtimeRef := "executor-" + strings.Repeat("a", 64)
	request := evidenceCaptureRequest(fixture.identity.NodeID, runtimeRef, time.Hour)
	armAt := fixture.now.Add(2 * time.Minute)
	if _, created, err := fixture.store.ArmEvidenceCapture(fixture.admin, request, armAt); err != nil || !created {
		t.Fatalf("arm original capture = (%v, %v)", created, err)
	}
	if deleted, err := fixture.store.DeleteEvidenceCapture(
		fixture.admin, request.NodeID, request.CaptureID, armAt.Add(time.Second),
	); err != nil || !deleted {
		t.Fatalf("delete original capture = (%v, %v)", deleted, err)
	}

	raw, enrollment, _, err := fixture.store.CreateEnrollment(
		fixture.admin, fixture.auth, "node-replacement", []string{"tenant-a"},
		armAt.Add(time.Hour), armAt.Add(2*time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}
	private := newEvidencePrivateKey(t)
	proof := evidenceIdentityProof(t, fixture.auth, enrollment, private)
	credential, err := fixture.store.ExchangeEnrollment(
		fixture.auth, raw, "replacement-exchange", proof, armAt.Add(3*time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}
	replacementIdentity, err := fixture.store.AuthenticateNode(fixture.auth, credential.Credential)
	if err != nil {
		t.Fatal(err)
	}
	replacement := request
	replacement.NodeID = replacementIdentity.NodeID
	replacement.RequestID = "capture-request-replacement"
	if _, created, err := fixture.store.ArmEvidenceCapture(
		fixture.admin, replacement, armAt.Add(4*time.Second),
	); err != nil || !created {
		t.Fatalf("arm replacement capture = (%v, %v)", created, err)
	}

	if deleted, err := fixture.store.DeleteEvidenceCapture(
		fixture.admin, request.NodeID, request.CaptureID, armAt.Add(5*time.Second),
	); err != nil || deleted {
		t.Fatalf("stale-node delete = (%v, %v)", deleted, err)
	}
	if _, _, err := fixture.store.SealEvidenceCapture(
		fixture.admin, request.NodeID, request.CaptureID, "canary-command", armAt.Add(6*time.Second),
	); !errors.Is(err, ErrNotFound) {
		t.Fatalf("stale-node seal error = %v", err)
	}
	retained, found, err := fixture.store.GetEvidenceCapture(
		fixture.admin, replacement.CaptureID, armAt.Add(7*time.Second),
	)
	if err != nil || !found || retained.NodeID != replacement.NodeID ||
		retained.RequestID != replacement.RequestID {
		t.Fatalf("replacement capture = (%+v, %v, %v)", retained, found, err)
	}
}

func TestEvidenceCaptureFormatFourStrictlyMigratesLegacyState(t *testing.T) {
	fixture := newExecutorEvidenceFixture(t, "tenant-a")
	armAt := fixture.now.Add(2 * time.Minute)
	request := evidenceCaptureRequest(
		fixture.identity.NodeID,
		"executor-"+strings.Repeat("a", 64),
		time.Minute,
	)
	if _, created, err := fixture.store.ArmEvidenceCapture(
		fixture.admin, request, armAt,
	); err != nil || !created {
		t.Fatalf("arm format fixture = (%v, %v)", created, err)
	}
	fixture.store.mu.Lock()
	current := fixture.store.current.clone()
	fixture.store.mu.Unlock()
	raw, err := encodeState(current, fixture.limits.MaxStateBytes)
	if err != nil {
		t.Fatal(err)
	}
	var snapshot snapshotState
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		t.Fatal(err)
	}
	if snapshot.Version != stateFormatWriteVersion || len(snapshot.Captures) != 1 ||
		snapshot.Captures[0].FramesBase64 == nil {
		t.Fatalf("current snapshot = version %d captures %+v", snapshot.Version, snapshot.Captures)
	}
	decoded, err := decodeState(raw, fixture.limits.MaxStateBytes)
	if err != nil || len(decoded.captures) != 1 {
		t.Fatalf("decode format-4 capture = (%d, %v)", len(decoded.captures), err)
	}

	var legacyObject map[string]json.RawMessage
	if err := json.Unmarshal(raw, &legacyObject); err != nil {
		t.Fatal(err)
	}
	legacyVersion, _ := json.Marshal(stateFormatExecutorV4Version)
	legacyObject["version"] = legacyVersion
	delete(legacyObject, "captures")
	delete(legacyObject, "deployments")
	legacyRaw, err := json.Marshal(legacyObject)
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := decodeState(legacyRaw, fixture.limits.MaxStateBytes)
	if err != nil || legacy.captures == nil || len(legacy.captures) != 0 {
		t.Fatalf("strict legacy migration = (%+v, %v)", legacy.captures, err)
	}

	snapshot.Version = stateFormatExecutorV4Version
	snapshot.Deployments = nil
	legacyWithCapture, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeState(legacyWithCapture, fixture.limits.MaxStateBytes); err == nil {
		t.Fatal("format-3 snapshot smuggled capture state")
	}
	change := captureMutation(snapshot.Captures[0])
	if _, err := applyTransaction(
		legacy,
		transaction{Version: transactionExecutorV4Version, Mutations: []mutation{change}},
	); err == nil {
		t.Fatal("format-3 transaction smuggled capture state")
	}
	encoded, err := encodeTransaction(change)
	if err != nil {
		t.Fatal(err)
	}
	var written transaction
	if err := json.Unmarshal(encoded, &written); err != nil {
		t.Fatal(err)
	}
	if written.Version != transactionFormatWriteVersion {
		t.Fatalf("capture transaction write version = %d", written.Version)
	}
}

func TestEvidenceCapturePublicProjectionRejectsSemanticMutation(t *testing.T) {
	fixture := newExecutorEvidenceFixture(t, "tenant-a")
	armAt := fixture.now.Add(2 * time.Minute)
	request := evidenceCaptureRequest(
		fixture.identity.NodeID,
		"executor-"+strings.Repeat("a", 64),
		time.Minute,
	)
	valid, created, err := fixture.store.ArmEvidenceCapture(fixture.admin, request, armAt)
	if err != nil || !created {
		t.Fatal(err)
	}
	tests := map[string]func(*EvidenceCapture){
		"runtime": func(value *EvidenceCapture) { value.RuntimeRef = "runtime" },
		"head identity": func(value *EvidenceCapture) {
			value.FinalHead.ReceiptEpoch++
		},
		"frame count": func(value *EvidenceCapture) { value.FrameCount = 1 },
		"state":       func(value *EvidenceCapture) { value.State = "unknown" },
		"terminal leakage": func(value *EvidenceCapture) {
			value.CapsuleDigest = dsse.Digest([]byte("capsule"))
		},
		"lifetime": func(value *EvidenceCapture) {
			value.ExpiresAt = canonicalTimestamp(armAt.Add(MaxEvidenceCaptureTTL + time.Second))
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			mutate(&candidate)
			if err := candidate.Validate(); err == nil {
				t.Fatal("semantically invalid public capture was accepted")
			}
		})
	}
}

func TestEvidenceCaptureCapacityAccountingReservesEveryArmedCapture(t *testing.T) {
	armed := make(map[string]storedEvidenceCapture)
	for index := 0; index < MaxEvidenceCapturesActive; index++ {
		id := fmt.Sprintf("capture-%d", index)
		armed[id] = storedEvidenceCapture{State: EvidenceCaptureArmed}
	}
	active, reserved := evidenceCaptureUsage(armed)
	if active != MaxEvidenceCapturesActive ||
		reserved != MaxEvidenceCapturesActive*MaxEvidenceCaptureDecodedBytes {
		t.Fatalf("armed usage = (%d, %d)", active, reserved)
	}
	armed["capture-overflow"] = storedEvidenceCapture{State: EvidenceCaptureArmed}
	active, _ = evidenceCaptureUsage(armed)
	if active <= MaxEvidenceCapturesActive {
		t.Fatal("active capture accounting did not cross the hard cap")
	}

	retained := make(map[string]storedEvidenceCapture)
	for index := 0; index < MaxEvidenceCaptureAggregateBytes/MaxEvidenceCaptureDecodedBytes; index++ {
		id := fmt.Sprintf("retained-%d", index)
		retained[id] = storedEvidenceCapture{
			State: EvidenceCaptureFailed, CapturedBytes: MaxEvidenceCaptureDecodedBytes,
		}
	}
	_, reserved = evidenceCaptureUsage(retained)
	if reserved != MaxEvidenceCaptureAggregateBytes {
		t.Fatalf("exact aggregate usage = %d", reserved)
	}
	retained["retained-overflow"] = storedEvidenceCapture{
		State: EvidenceCaptureFailed, CapturedBytes: 1,
	}
	_, reserved = evidenceCaptureUsage(retained)
	if reserved <= MaxEvidenceCaptureAggregateBytes {
		t.Fatal("aggregate capture accounting did not cross the hard cap")
	}

	tooMany := emptyState()
	for index := 0; index <= MaxEvidenceCapturesRetained; index++ {
		id := fmt.Sprintf("capture-%d", index)
		tooMany.captures[id] = storedEvidenceCapture{}
	}
	if err := validateState(tooMany, DefaultLimits()); !errors.Is(err, ErrCapacityExceeded) {
		t.Fatalf("retained capture cap error = %v", err)
	}
}

func evidenceCaptureRequest(
	nodeID string,
	runtimeRef string,
	ttl time.Duration,
) EvidenceCaptureArmRequest {
	return EvidenceCaptureArmRequest{
		CaptureID: "capture-1", RequestID: "capture-request-1",
		NodeID: nodeID, TenantID: "tenant-a", RuntimeRef: runtimeRef,
		Generation: 11, ActivationID: "activation-1",
		ActivationBeginDigest: dsse.Digest([]byte("activation-begin")), TTL: ttl,
	}
}

func appendCaptureActivation(
	t *testing.T,
	fixture executorEvidenceFixture,
	runtimeRef string,
	generation uint64,
	activationID string,
	capsuleDigest string,
	policyDigest string,
	beginDigest string,
	checkpointDigest string,
) {
	t.Helper()
	base := evidence.Event{
		TenantID: "tenant-a", RuntimeRef: runtimeRef, Generation: generation,
		GrantID: activationID, CapsuleDigest: capsuleDigest, PolicyDigest: policyDigest,
	}
	begin := base
	begin.Type = evidence.ActivationBegin
	begin.Outcome = evidence.Allowed
	begin.MetadataHash = beginDigest
	if _, err := fixture.log.AppendActivationBegin(begin); err != nil {
		t.Fatal(err)
	}
	checkpoint := base
	checkpoint.Type = evidence.ActivationCheckpoint
	checkpoint.Outcome = evidence.Committed
	checkpoint.MetadataHash = checkpointDigest
	if _, err := fixture.log.AppendActivationCheckpoint(checkpoint); err != nil {
		t.Fatal(err)
	}
}
