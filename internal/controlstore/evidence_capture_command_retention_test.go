package controlstore

import (
	"testing"
	"time"

	"github.com/hardrails/steward/internal/activationcanary"
	"github.com/hardrails/steward/internal/controlauth"
	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/evidence"
)

func TestEvidenceCaptureRetainsOneSealableCanaryThroughPruningAndRecovery(t *testing.T) {
	fixture := newExecutorEvidenceFixture(t, "tenant-a")
	limits := fixture.limits
	limits.MaxCommands = 2
	limits.MaxCommandsPerTenant = 2
	limits.MaxCommandsPerNode = 2
	limits.TerminalRetention = time.Second
	fixture.limits = limits
	fixture.store.limits = limits

	runtimeRef := "executor-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	armAt := fixture.now.Add(2 * time.Minute)
	request := evidenceCaptureRequest(fixture.identity.NodeID, runtimeRef, 30*time.Minute)

	firstStatement := baseV4CommandStatement(
		"capture-canary-first", "tenant-a", fixture.identity.NodeID,
		"activation-canary", 7, request.Generation,
	)
	firstProjection := controlStoreCanaryFixture(t, &firstStatement, fixture.now)
	firstCanary, err := activationcanary.ParseCommandV1(firstStatement.Payload)
	if err != nil {
		t.Fatal(err)
	}
	request.ActivationBeginDigest = firstCanary.Admission.ActivationBeginDigest
	if _, created, err := fixture.store.ArmEvidenceCapture(
		fixture.admin, request, armAt,
	); err != nil || !created {
		t.Fatalf("arm evidence capture = (%v, %v)", created, err)
	}

	firstDelivery := submitAndPollActivationCanaryV4(
		t, fixture.recordsFixture, fixture.identity, firstStatement,
	)
	if applied, err := fixture.store.ApplyReportV4(
		fixture.identity,
		activationCanaryReportV4(firstDelivery, firstStatement, firstProjection),
		fixture.now.Add(4*time.Minute),
	); err != nil || !applied {
		t.Fatalf("apply first canary = (%v, %v)", applied, err)
	}

	// A second fully matching success proves that one capture cannot pin every
	// matching command. The earliest completion remains the stable selection.
	secondStatement := baseV4CommandStatement(
		"capture-canary-second", "tenant-a", fixture.identity.NodeID,
		"activation-canary", 7, request.Generation,
	)
	secondProjection := controlStoreCanaryFixture(t, &secondStatement, fixture.now)
	secondDelivery := submitAndPollActivationCanaryV4(
		t, fixture.recordsFixture, fixture.identity, secondStatement,
	)
	if applied, err := fixture.store.ApplyReportV4(
		fixture.identity,
		activationCanaryReportV4(secondDelivery, secondStatement, secondProjection),
		fixture.now.Add(5*time.Minute),
	); err != nil || !applied {
		t.Fatalf("apply second canary = (%v, %v)", applied, err)
	}

	fixture.store.mu.Lock()
	protected := evidenceCapturePruningCanaries(
		fixture.store.current.captures,
		fixture.store.current.commands,
		fixture.now.Add(10*time.Minute),
	)
	firstKey := commandKey("tenant-a", fixture.identity.NodeID, firstStatement.CommandID)
	firstCommand := cloneCommand(fixture.store.current.commands[firstKey])
	retainedCapture := cloneStoredEvidenceCapture(fixture.store.current.captures[request.CaptureID])
	fixture.store.mu.Unlock()
	if len(protected) != 1 {
		t.Fatalf("protected matching canaries = %d, want one", len(protected))
	}
	if _, ok := protected[firstKey]; !ok {
		t.Fatalf("earliest matching canary was not selected: %v", protected)
	}

	partial := cloneCommand(firstCommand)
	partial.Terminal.ActivationCanary = nil
	if got := evidenceCapturePruningCanaries(
		map[string]storedEvidenceCapture{retainedCapture.CaptureID: retainedCapture},
		map[string]Command{firstKey: partial},
		fixture.now.Add(10*time.Minute),
	); len(got) != 0 {
		t.Fatalf("partial canary received capture protection: %v", got)
	}
	conflicting := cloneCommand(firstCommand)
	conflicting.Terminal.ActivationCanary.ActivationID = "activation-other"
	if got := evidenceCapturePruningCanaries(
		map[string]storedEvidenceCapture{retainedCapture.CaptureID: retainedCapture},
		map[string]Command{firstKey: conflicting},
		fixture.now.Add(10*time.Minute),
	); len(got) != 0 {
		t.Fatalf("conflicting canary received capture protection: %v", got)
	}
	if got := evidenceCapturePruningCanaries(
		map[string]storedEvidenceCapture{retainedCapture.CaptureID: retainedCapture},
		map[string]Command{firstKey: firstCommand},
		fixture.now.Add(33*time.Minute),
	); len(got) != 0 {
		t.Fatalf("expired armed capture retained a canary: %v", got)
	}

	completeCaptureRetentionRead(
		t, fixture.store, fixture.admin, fixture.identity,
		"capacity-read-1", fixture.now.Add(10*time.Minute),
	)
	if _, found, err := fixture.store.GetCommand(
		fixture.admin, "tenant-a", fixture.identity.NodeID, secondStatement.CommandID,
	); err != nil || found {
		t.Fatalf("non-selected matching canary was retained: found=%v err=%v", found, err)
	}
	completeCaptureRetentionRead(
		t, fixture.store, fixture.admin, fixture.identity,
		"capacity-read-2", fixture.now.Add(15*time.Minute),
	)
	assertCaptureRetentionCommand(t, fixture, firstStatement.CommandID, true)

	if err := fixture.store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(fixture.dir, fixture.limits)
	if err != nil {
		t.Fatalf("reopen store with armed capture: %v", err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	fixture.store = reopened
	fixture.recordsFixture.store = reopened
	assertCaptureRetentionCommand(t, fixture, firstStatement.CommandID, true)

	capsuleDigest := firstCanary.Admission.CapsuleDigest
	policyDigest := firstCanary.Admission.PolicyDigest
	checkpointDigest := firstProjection.ActivationCheckpointDigest
	appendCaptureActivation(
		t, fixture, runtimeRef, request.Generation, request.ActivationID,
		capsuleDigest, policyDigest, request.ActivationBeginDigest, checkpointDigest,
	)
	poll := fixture.poll(t, fixture.now.Add(20*time.Minute))
	report, _ := fixture.reportFrom(t, evidence.Coordinate{}, poll.Challenge)
	if response, err := fixture.store.ApplyExecutorEvidenceReport(
		fixture.auth, fixture.identity, report, fixture.now.Add(20*time.Minute+time.Second),
	); err != nil || !response.Applied {
		t.Fatalf("observe capture after recovery = (%+v, %v)", response, err)
	}
	if err := fixture.store.Close(); err != nil {
		t.Fatal(err)
	}
	reopenedObserved, err := Open(fixture.dir, fixture.limits)
	if err != nil {
		t.Fatalf("reopen store with observed capture: %v", err)
	}
	t.Cleanup(func() { _ = reopenedObserved.Close() })
	fixture.store = reopenedObserved
	fixture.recordsFixture.store = reopenedObserved
	assertCaptureRetentionCommand(t, fixture, firstStatement.CommandID, true)

	completeCaptureRetentionRead(
		t, fixture.store, fixture.admin, fixture.identity,
		"capacity-read-3", fixture.now.Add(25*time.Minute),
	)
	assertCaptureRetentionCommand(t, fixture, firstStatement.CommandID, true)
	sealed, changed, err := fixture.store.SealEvidenceCapture(
		fixture.admin, fixture.identity.NodeID, request.CaptureID, firstStatement.CommandID,
		fixture.now.Add(26*time.Minute),
	)
	if err != nil || !changed || sealed.State != EvidenceCaptureSealed {
		t.Fatalf("seal retained capture = (%+v, %v, %v)", sealed, changed, err)
	}

	// Once sealed, the command no longer receives capture protection and can
	// be reclaimed normally on the next old-terminal capacity boundary.
	completeCaptureRetentionRead(
		t, fixture.store, fixture.admin, fixture.identity,
		"capacity-read-4", fixture.now.Add(28*time.Minute),
	)
	assertCaptureRetentionCommand(t, fixture, firstStatement.CommandID, false)
}

func completeCaptureRetentionRead(
	t *testing.T,
	store *Store,
	admin controlauth.Identity,
	node controlauth.NodeIdentity,
	commandID string,
	submittedAt time.Time,
) {
	t.Helper()
	statement := baseV4CommandStatement(
		commandID, "tenant-a", node.NodeID, "read", 7, 11,
	)
	if _, created, err := store.SubmitCommand(
		admin,
		statement.TenantID,
		statement.NodeID,
		signV4CommandStatement(t, statement),
		submittedAt,
	); err != nil || !created {
		t.Fatalf("submit %s = (%v, %v)", commandID, created, err)
	}
	deliveries, err := store.PollV4(
		node,
		[]string{controlprotocol.ExecutorCapabilityAdmissionProjectionV1},
		submittedAt.Add(time.Second),
		time.Minute,
		1,
	)
	if err != nil || len(deliveries) != 1 || deliveries[0].CommandID != commandID {
		t.Fatalf("poll %s = (%+v, %v)", commandID, deliveries, err)
	}
	report := controlprotocol.ExecutorReportV4{
		ProtocolVersion:    controlprotocol.ExecutorProtocolV4,
		DeliveryID:         deliveries[0].DeliveryID,
		DeliveryGeneration: deliveries[0].DeliveryGeneration,
		CommandID:          deliveries[0].CommandID,
		CommandDigest:      deliveries[0].CommandDigest,
		Status:             controlprotocol.ExecutorStatusDone,
		ReportedStatus:     "completed",
		ClaimGeneration:    statement.ClaimGeneration,
		Result: controlprotocol.ExecutorReportResultV4{
			RuntimeRef: statement.RuntimeRef,
		},
	}
	if applied, err := store.ApplyReportV4(
		node, report, submittedAt.Add(2*time.Second),
	); err != nil || !applied {
		t.Fatalf("apply %s = (%v, %v)", commandID, applied, err)
	}
}

func assertCaptureRetentionCommand(
	t *testing.T,
	fixture executorEvidenceFixture,
	commandID string,
	want bool,
) {
	t.Helper()
	_, found, err := fixture.store.GetCommand(
		fixture.admin, "tenant-a", fixture.identity.NodeID, commandID,
	)
	if err != nil || found != want {
		t.Fatalf("retained canary %s = (found=%v, err=%v), want found=%v", commandID, found, err, want)
	}
}
