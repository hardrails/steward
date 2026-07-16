package controlstore

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/controlauth"
	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/evidence"
)

type executorEvidenceFixture struct {
	recordsFixture
	identity controlauth.NodeIdentity
	private  ed25519.PrivateKey
	public   ed25519.PublicKey
	log      *evidence.Log
	logPath  string
	request  controlprotocol.ExecutorEvidencePollRequestV1
}

func newExecutorEvidenceFixture(t *testing.T, tenantIDs ...string) executorEvidenceFixture {
	t.Helper()
	base := newRecordsFixture(t, DefaultLimits())
	for _, tenantID := range tenantIDs {
		base.createTenant(t, tenantID)
	}
	raw, enrollment, _, err := base.store.CreateEnrollment(
		base.admin, base.auth, "node-evidence", tenantIDs, base.now.Add(time.Hour), base.now,
	)
	if err != nil {
		t.Fatal(err)
	}
	private := newEvidencePrivateKey(t)
	public := private.Public().(ed25519.PublicKey)
	proof := evidenceIdentityProof(t, base.auth, enrollment, private)
	credential, err := base.store.ExchangeEnrollment(
		base.auth, raw, "evidence-exchange", proof, base.now.Add(time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := base.store.AuthenticateNode(base.auth, credential.Credential)
	if err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(t.TempDir(), "executor-evidence.log")
	log, err := evidence.Open(logPath, private, identity.NodeID, 1)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	return executorEvidenceFixture{
		recordsFixture: base, identity: identity, private: private, public: public, log: log, logPath: logPath,
		request: controlprotocol.ExecutorEvidencePollRequestV1{
			ProtocolVersion:      controlprotocol.ExecutorEvidenceProtocolV1,
			ControllerInstanceID: base.auth.InstanceID(), ControlNodeID: identity.NodeID,
			Stream: controlprotocol.ExecutorEvidenceStreamV1, ReceiptNodeID: identity.NodeID,
			ReceiptEpoch: 1, PublicKeySHA256: controlprotocol.ExecutorEvidencePublicKeySHA256(public),
		},
	}
}

func TestExecutorEvidencePollAdvanceRetryEqualityAndRecovery(t *testing.T) {
	fixture := newExecutorEvidenceFixture(t, "tenant-a")
	pollAt := fixture.now.Add(2 * time.Minute)
	poll := fixture.poll(t, pollAt)
	if poll.Status.State != controlprotocol.ExecutorEvidenceStatusCurrent ||
		poll.Status.Head == nil || poll.Status.Head.Sequence != 0 ||
		poll.Status.Head.ChainHash != zeroEvidenceHash() || poll.Status.WitnessedAt == "" {
		t.Fatalf("initial poll status=%#v", poll.Status)
	}
	if err := fixture.auth.VerifyEvidenceChallenge(
		poll.Challenge, fixture.identity.CredentialID, fixture.identity.NodeID, pollAt.Add(time.Second),
	); err != nil {
		t.Fatalf("poll challenge is not credential-bound: %v", err)
	}
	wrongRequest := fixture.request
	wrongRequest.PublicKeySHA256 = digestBytes([]byte("wrong key"))
	if _, err := fixture.store.PollExecutorEvidence(
		fixture.auth, fixture.identity, wrongRequest, pollAt, pollAt.Add(5*time.Minute),
	); !errors.Is(err, ErrConflict) {
		t.Fatalf("substituted poll identity error=%v", err)
	}

	fixture.appendReceipt(t, "tenant-a")
	fixture.appendReceipt(t, "tenant-a")
	report, delta := fixture.reportFrom(t, evidence.Coordinate{}, poll.Challenge)
	appliedAt := pollAt.Add(time.Second)
	response, err := fixture.store.ApplyExecutorEvidenceReport(fixture.auth, fixture.identity, report, appliedAt)
	if err != nil || !response.Applied || response.Status.State != controlprotocol.ExecutorEvidenceStatusCurrent ||
		response.Status.Head == nil || response.Status.Head.Sequence != 2 {
		t.Fatalf("advance response=%#v err=%v", response, err)
	}
	retained := retainedExecutorEvidence(t, fixture.store, fixture.identity.NodeID)
	if retained.Sequence != 2 || retained.ChainHash != encodeExecutorEvidenceHash(delta.Head.ChainHash) ||
		retained.RecordsAccepted != 2 || retained.LastBatchStart != 1 || retained.LastBatchEnd != 2 ||
		retained.LastBatchDigest != controlprotocol.ExecutorEvidenceFramesDigestV1(delta.Frames) {
		t.Fatalf("retained advancement=%#v", retained)
	}

	sequenceAfterAdvance := fixture.store.sequence
	retry, err := fixture.store.ApplyExecutorEvidenceReport(
		fixture.auth, fixture.identity, report, appliedAt.Add(time.Second),
	)
	if err != nil || retry.Applied || fixture.store.sequence != sequenceAfterAdvance {
		t.Fatalf("exact retry response=%#v sequence=%d err=%v", retry, fixture.store.sequence, err)
	}

	refreshPoll := fixture.poll(t, appliedAt.Add(2*time.Second))
	currentHead, err := fixture.log.CurrentHead()
	if err != nil {
		t.Fatal(err)
	}
	refreshReport := fixture.signedReport(
		t, evidence.Coordinate{Sequence: currentHead.Sequence, ChainHash: currentHead.ChainHash},
		currentHead.Sequence, encodeExecutorEvidenceHash(currentHead.ChainHash), refreshPoll.Challenge, nil,
	)
	refreshedAt := appliedAt.Add(3 * time.Second)
	sequenceBeforeEquality := fixture.store.sequence
	refreshed, err := fixture.store.ApplyExecutorEvidenceReport(
		fixture.auth, fixture.identity, refreshReport, refreshedAt,
	)
	if err != nil || refreshed.Applied || fixture.store.sequence != sequenceBeforeEquality {
		t.Fatalf("equality response=%#v sequence=%d err=%v", refreshed, fixture.store.sequence, err)
	}
	afterRefresh := retainedExecutorEvidence(t, fixture.store, fixture.identity.NodeID)
	if afterRefresh.AdvancedAt != retained.AdvancedAt ||
		afterRefresh.LastBatchDigest != retained.LastBatchDigest {
		t.Fatalf("equality changed retained batch or timestamp=%#v", afterRefresh)
	}

	if err := fixture.store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(fixture.dir, fixture.limits)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	recovered := retainedExecutorEvidence(t, reopened, fixture.identity.NodeID)
	if !evidenceWitnessEqual(recovered, afterRefresh) {
		t.Fatalf("recovered witness=%#v want %#v", recovered, afterRefresh)
	}
}

func TestExecutorEvidenceFindingsAreStickyAndFenceAdvancement(t *testing.T) {
	fixture := newExecutorEvidenceFixture(t, "tenant-a")
	fixture.appendReceipt(t, "tenant-a")
	fixture.appendReceipt(t, "tenant-a")
	var records []evidence.VerifiedReceipt
	if _, err := evidence.VerifyRecords(
		fixture.logPath, fixture.public, fixture.identity.NodeID, 1,
		func(record evidence.VerifiedReceipt) error {
			records = append(records, record)
			return nil
		},
	); err != nil {
		t.Fatal(err)
	}
	poll := fixture.poll(t, fixture.now.Add(2*time.Minute))
	report, _ := fixture.reportFrom(t, evidence.Coordinate{}, poll.Challenge)
	if _, err := fixture.store.ApplyExecutorEvidenceReport(
		fixture.auth, fixture.identity, report, fixture.now.Add(2*time.Minute+time.Second),
	); err != nil {
		t.Fatal(err)
	}

	rollbackPoll := fixture.poll(t, fixture.now.Add(3*time.Minute))
	retainedBeforeFinding := retainedExecutorEvidence(t, fixture.store, fixture.identity.NodeID)
	retainedHash, err := decodeExecutorEvidenceHash(retainedBeforeFinding.ChainHash)
	if err != nil {
		t.Fatal(err)
	}
	retainedCoordinate := evidence.Coordinate{Sequence: retainedBeforeFinding.Sequence, ChainHash: retainedHash}
	rollback := fixture.signedReport(
		t, retainedCoordinate, 1, encodeExecutorEvidenceHash(records[0].ChainHash), rollbackPoll.Challenge, nil,
	)
	response, err := fixture.store.ApplyExecutorEvidenceReport(
		fixture.auth, fixture.identity, rollback, fixture.now.Add(3*time.Minute+time.Second),
	)
	if err != nil || !response.Applied || response.Status.State != controlprotocol.ExecutorEvidenceStatusRollbackDetected {
		t.Fatalf("rollback response=%#v err=%v", response, err)
	}
	finding := retainedExecutorEvidence(t, fixture.store, fixture.identity.NodeID).Finding
	if finding == nil || finding.FirstReason != EvidenceRollback || finding.Count != 1 {
		t.Fatalf("rollback finding=%#v", finding)
	}
	duplicatePoll := fixture.poll(t, fixture.now.Add(3*time.Minute+10*time.Second))
	duplicate := fixture.signedReport(
		t, retainedCoordinate, 1, encodeExecutorEvidenceHash(records[0].ChainHash), duplicatePoll.Challenge, nil,
	)
	sequenceBeforeDuplicate := fixture.store.sequence
	duplicateResponse, err := fixture.store.ApplyExecutorEvidenceReport(
		fixture.auth, fixture.identity, duplicate, fixture.now.Add(3*time.Minute+11*time.Second),
	)
	if err != nil || duplicateResponse.Applied || fixture.store.sequence != sequenceBeforeDuplicate {
		t.Fatalf("coalesced finding response=%#v sequence=%d err=%v",
			duplicateResponse, fixture.store.sequence, err)
	}
	if duplicateFinding := retainedExecutorEvidence(t, fixture.store, fixture.identity.NodeID).Finding; duplicateFinding == nil || duplicateFinding.Count != 1 {
		t.Fatalf("duplicate finding was persisted=%#v", duplicateFinding)
	}

	forkHash := digestBytes([]byte("authenticated fork head"))
	forkPoll := fixture.poll(t, fixture.now.Add(4*time.Minute))
	fork := fixture.signedReport(t, retainedCoordinate, 2, forkHash, forkPoll.Challenge, nil)
	beforeAlternate := retainedExecutorEvidence(t, fixture.store, fixture.identity.NodeID)
	sequenceBeforeAlternate := fixture.store.sequence
	response, err = fixture.store.ApplyExecutorEvidenceReport(
		fixture.auth, fixture.identity, fork, fixture.now.Add(4*time.Minute+time.Second),
	)
	if err != nil || response.Applied ||
		response.Status.State != controlprotocol.ExecutorEvidenceStatusRollbackDetected ||
		fixture.store.sequence != sequenceBeforeAlternate {
		t.Fatalf("fork response=%#v err=%v", response, err)
	}
	retained := retainedExecutorEvidence(t, fixture.store, fixture.identity.NodeID)
	if !evidenceWitnessEqual(beforeAlternate, retained) ||
		retained.Finding == nil || retained.Finding.FirstReason != EvidenceRollback ||
		retained.Finding.LastReason != EvidenceRollback || retained.Finding.Count != 1 {
		t.Fatalf("sticky finding=%#v", retained.Finding)
	}
	beforeInvalidSignature := retained
	invalidPoll := fixture.poll(t, fixture.now.Add(4*time.Minute+10*time.Second))
	invalidSignature := fixture.signedReport(
		t, retainedCoordinate, 1, encodeExecutorEvidenceHash(records[0].ChainHash), invalidPoll.Challenge, nil,
	)
	invalidSignature.HeadProof.SignatureBase64 = base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	if _, err := fixture.store.ApplyExecutorEvidenceReport(
		fixture.auth, fixture.identity, invalidSignature, fixture.now.Add(4*time.Minute+11*time.Second),
	); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid finding signature error=%v", err)
	}
	if after := retainedExecutorEvidence(t, fixture.store, fixture.identity.NodeID); !evidenceWitnessEqual(beforeInvalidSignature, after) {
		t.Fatal("invalid signature mutated an existing finding")
	}
	beforeRegressedTime := retained
	regressedNow := fixture.now.Add(3*time.Minute + 500*time.Millisecond)
	regressedPoll := fixture.poll(t, regressedNow)
	regressed := fixture.signedReport(
		t, retainedCoordinate, 1, encodeExecutorEvidenceHash(records[0].ChainHash), regressedPoll.Challenge, nil,
	)
	if _, err := fixture.store.ApplyExecutorEvidenceReport(
		fixture.auth, fixture.identity, regressed, regressedNow,
	); !errors.Is(err, ErrInvalid) {
		t.Fatalf("finding timestamp regression error=%v", err)
	}
	if after := retainedExecutorEvidence(t, fixture.store, fixture.identity.NodeID); !evidenceWitnessEqual(beforeRegressedTime, after) {
		t.Fatal("finding timestamp regression mutated the retained finding")
	}

	fixture.appendReceipt(t, "tenant-a")
	checkpoint, err := decodeExecutorEvidenceHash(retained.ChainHash)
	if err != nil {
		t.Fatal(err)
	}
	advancePoll := fixture.poll(t, fixture.now.Add(6*time.Minute))
	advance, _ := fixture.reportFrom(
		t, evidence.Coordinate{Sequence: retained.Sequence, ChainHash: checkpoint}, advancePoll.Challenge,
	)
	before := retainedExecutorEvidence(t, fixture.store, fixture.identity.NodeID)
	blocked, err := fixture.store.ApplyExecutorEvidenceReport(
		fixture.auth, fixture.identity, advance, fixture.now.Add(6*time.Minute+time.Second),
	)
	if !errors.Is(err, ErrConflict) || blocked.Status.State != controlprotocol.ExecutorEvidenceStatusRollbackDetected &&
		blocked.Status.State != controlprotocol.ExecutorEvidenceStatusEquivocationDetected {
		t.Fatalf("blocked advancement response=%#v err=%v", blocked, err)
	}
	after := retainedExecutorEvidence(t, fixture.store, fixture.identity.NodeID)
	if !evidenceWitnessEqual(before, after) {
		t.Fatal("a finding was cleared or checkpoint advanced automatically")
	}
	if err := fixture.store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(fixture.dir, fixture.limits)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	recovered := retainedExecutorEvidence(t, reopened, fixture.identity.NodeID)
	if !evidenceWitnessEqual(after, recovered) {
		t.Fatalf("recovered sticky finding=%#v want %#v", recovered, after)
	}
}

func TestStaleExecutorEvidenceChallengeCannotCreateFinding(t *testing.T) {
	fixture := newExecutorEvidenceFixture(t, "tenant-a")
	stalePoll := fixture.poll(t, fixture.now.Add(2*time.Minute))
	staleEquality := fixture.signedReport(
		t, evidence.Coordinate{}, 0, zeroEvidenceHash(), stalePoll.Challenge, nil,
	)

	fixture.appendReceipt(t, "tenant-a")
	advancePoll := fixture.poll(t, fixture.now.Add(2*time.Minute+time.Second))
	advance, _ := fixture.reportFrom(t, evidence.Coordinate{}, advancePoll.Challenge)
	if _, err := fixture.store.ApplyExecutorEvidenceReport(
		fixture.auth, fixture.identity, advance, fixture.now.Add(2*time.Minute+2*time.Second),
	); err != nil {
		t.Fatal(err)
	}
	before := retainedExecutorEvidence(t, fixture.store, fixture.identity.NodeID)
	sequence := fixture.store.sequence
	if _, err := fixture.store.ApplyExecutorEvidenceReport(
		fixture.auth, fixture.identity, staleEquality, fixture.now.Add(2*time.Minute+3*time.Second),
	); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale equality error=%v", err)
	}
	after := retainedExecutorEvidence(t, fixture.store, fixture.identity.NodeID)
	if !evidenceWitnessEqual(before, after) || after.Finding != nil || fixture.store.sequence != sequence {
		t.Fatal("stale equality created a rollback finding")
	}

	stripped := advance
	stripped.SignedFramesBase64 = nil
	if _, err := fixture.store.ApplyExecutorEvidenceReport(
		fixture.auth, fixture.identity, stripped, fixture.now.Add(2*time.Minute+4*time.Second),
	); !errors.Is(err, ErrInvalid) {
		t.Fatalf("frame-stripped stale advancement error=%v", err)
	}
	after = retainedExecutorEvidence(t, fixture.store, fixture.identity.NodeID)
	if !evidenceWitnessEqual(before, after) || after.Finding != nil || fixture.store.sequence != sequence {
		t.Fatal("frame-stripped stale advancement created a finding")
	}

	forkLog, err := evidence.Open(
		filepath.Join(t.TempDir(), "delayed-fork-evidence.log"), fixture.private, fixture.identity.NodeID, 1,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer forkLog.Close()
	if _, err := forkLog.Append(evidence.Event{
		Type: evidence.AdmissionAllow, TenantID: "tenant-a", RuntimeRef: "runtime-delayed-fork",
		CapsuleDigest: "sha256:capsule", PolicyDigest: "sha256:policy", Generation: 1,
		GrantID: "grant-a", Outcome: evidence.Allowed,
	}); err != nil {
		t.Fatal(err)
	}
	forkDelta, err := forkLog.ExportDelta(evidence.Coordinate{})
	if err != nil {
		t.Fatal(err)
	}
	delayedFork := fixture.signedReport(
		t, evidence.Coordinate{}, forkDelta.Head.Sequence, encodeExecutorEvidenceHash(forkDelta.Head.ChainHash),
		stalePoll.Challenge, encodeExecutorEvidenceTestFrames(forkDelta.Frames),
	)
	if _, err := fixture.store.ApplyExecutorEvidenceReport(
		fixture.auth, fixture.identity, delayedFork, fixture.now.Add(2*time.Minute+5*time.Second),
	); !errors.Is(err, ErrConflict) {
		t.Fatalf("valid delayed stale branch error=%v", err)
	}
	after = retainedExecutorEvidence(t, fixture.store, fixture.identity.NodeID)
	if !evidenceWitnessEqual(before, after) || after.Finding != nil || fixture.store.sequence != sequence {
		t.Fatal("valid delayed stale branch created an equivocation finding")
	}
}

func TestExecutorEvidenceAheadHeadWithoutExtensionRecordsEquivocation(t *testing.T) {
	fixture := newExecutorEvidenceFixture(t, "tenant-a")
	fixture.appendReceipt(t, "tenant-a")
	advancePoll := fixture.poll(t, fixture.now.Add(2*time.Minute))
	advance, _ := fixture.reportFrom(t, evidence.Coordinate{}, advancePoll.Challenge)
	if _, err := fixture.store.ApplyExecutorEvidenceReport(
		fixture.auth, fixture.identity, advance, fixture.now.Add(2*time.Minute+time.Second),
	); err != nil {
		t.Fatal(err)
	}
	retained := retainedExecutorEvidence(t, fixture.store, fixture.identity.NodeID)
	retainedHash, err := decodeExecutorEvidenceHash(retained.ChainHash)
	if err != nil {
		t.Fatal(err)
	}
	poll := fixture.poll(t, fixture.now.Add(3*time.Minute))
	ahead := fixture.signedReport(
		t, evidence.Coordinate{Sequence: retained.Sequence, ChainHash: retainedHash},
		retained.Sequence+1, digestBytes([]byte("ahead fork head")), poll.Challenge, nil,
	)
	response, err := fixture.store.ApplyExecutorEvidenceReport(
		fixture.auth, fixture.identity, ahead, fixture.now.Add(3*time.Minute+time.Second),
	)
	if err != nil || !response.Applied ||
		response.Status.State != controlprotocol.ExecutorEvidenceStatusEquivocationDetected ||
		response.Status.Finding == nil ||
		response.Status.Finding.ObservedHead.Sequence != retained.Sequence+1 {
		t.Fatalf("ahead equivocation response=%#v err=%v", response, err)
	}
	after := retainedExecutorEvidence(t, fixture.store, fixture.identity.NodeID)
	if after.Sequence != retained.Sequence || after.ChainHash != retained.ChainHash ||
		after.Finding == nil || after.Finding.FirstReason != EvidenceFork ||
		after.Finding.FirstSequence != retained.Sequence+1 {
		t.Fatalf("ahead equivocation witness=%#v", after)
	}
}

func TestExecutorEvidenceFindingCASRejectsRegressedObservationTime(t *testing.T) {
	fixture := newExecutorEvidenceFixture(t, "tenant-a")
	fixture.appendReceipt(t, "tenant-a")
	advancePoll := fixture.poll(t, fixture.now.Add(2*time.Minute))
	advance, _ := fixture.reportFrom(t, evidence.Coordinate{}, advancePoll.Challenge)
	if _, err := fixture.store.ApplyExecutorEvidenceReport(
		fixture.auth, fixture.identity, advance, fixture.now.Add(2*time.Minute+time.Second),
	); err != nil {
		t.Fatal(err)
	}
	retained := retainedExecutorEvidence(t, fixture.store, fixture.identity.NodeID)
	retainedHash, err := decodeExecutorEvidenceHash(retained.ChainHash)
	if err != nil {
		t.Fatal(err)
	}
	poll := fixture.poll(t, fixture.now.Add(3*time.Minute))
	rollback := fixture.signedReport(
		t, evidence.Coordinate{Sequence: retained.Sequence, ChainHash: retainedHash},
		0, zeroEvidenceHash(), poll.Challenge, nil,
	)
	type applyResult struct {
		response controlprotocol.ExecutorEvidenceReportResponseV1
		err      error
	}
	readyLater, readyEarlier := make(chan struct{}), make(chan struct{})
	releaseLater, releaseEarlier := make(chan struct{}), make(chan struct{})
	laterResult, earlierResult := make(chan applyResult, 1), make(chan applyResult, 1)
	go func() {
		response, err := fixture.store.applyExecutorEvidenceReport(
			fixture.auth, fixture.identity, rollback, fixture.now.Add(4*time.Minute),
			func() {
				close(readyLater)
				<-releaseLater
			},
		)
		laterResult <- applyResult{response: response, err: err}
	}()
	go func() {
		response, err := fixture.store.applyExecutorEvidenceReport(
			fixture.auth, fixture.identity, rollback, fixture.now.Add(3*time.Minute+30*time.Second),
			func() {
				close(readyEarlier)
				<-releaseEarlier
			},
		)
		earlierResult <- applyResult{response: response, err: err}
	}()
	<-readyLater
	<-readyEarlier
	close(releaseLater)
	later := <-laterResult
	if later.err != nil || !later.response.Applied {
		t.Fatalf("later finding response=%#v err=%v", later.response, later.err)
	}
	close(releaseEarlier)
	earlier := <-earlierResult
	if earlier.err != nil || earlier.response.Applied ||
		earlier.response.Status.State != controlprotocol.ExecutorEvidenceStatusRollbackDetected {
		t.Fatalf("regressed concurrent finding response=%#v err=%v", earlier.response, earlier.err)
	}
	finding := retainedExecutorEvidence(t, fixture.store, fixture.identity.NodeID).Finding
	if finding == nil || finding.Count != 1 ||
		finding.FirstObservedAt != canonicalTimestamp(fixture.now.Add(4*time.Minute)) ||
		finding.LastObservedAt != finding.FirstObservedAt {
		t.Fatalf("concurrent finding chronology=%#v", finding)
	}
}

func TestConcurrentDivergentExecutorEvidenceAdvancesRecordFork(t *testing.T) {
	fixture := newExecutorEvidenceFixture(t, "tenant-a")
	fixture.appendReceipt(t, "tenant-a")
	firstDelta, err := fixture.log.ExportDelta(evidence.Coordinate{})
	if err != nil {
		t.Fatal(err)
	}

	forkLog, err := evidence.Open(
		filepath.Join(t.TempDir(), "fork-evidence.log"), fixture.private, fixture.identity.NodeID, 1,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = forkLog.Close() })
	if _, err := forkLog.Append(evidence.Event{
		Type: evidence.AdmissionAllow, TenantID: "tenant-a", RuntimeRef: "runtime-fork",
		CapsuleDigest: "sha256:capsule", PolicyDigest: "sha256:policy", Generation: 1,
		GrantID: "grant-a", Outcome: evidence.Allowed,
	}); err != nil {
		t.Fatal(err)
	}
	secondDelta, err := forkLog.ExportDelta(evidence.Coordinate{})
	if err != nil {
		t.Fatal(err)
	}
	if firstDelta.Head.Sequence != secondDelta.Head.Sequence || firstDelta.Head.ChainHash == secondDelta.Head.ChainHash {
		t.Fatal("test did not construct equal-sequence divergent chains")
	}

	poll := fixture.poll(t, fixture.now.Add(2*time.Minute))
	firstReport := fixture.signedReport(
		t, evidence.Coordinate{}, firstDelta.Head.Sequence, encodeExecutorEvidenceHash(firstDelta.Head.ChainHash),
		poll.Challenge, encodeExecutorEvidenceTestFrames(firstDelta.Frames),
	)
	secondReport := fixture.signedReport(
		t, evidence.Coordinate{}, secondDelta.Head.Sequence, encodeExecutorEvidenceHash(secondDelta.Head.ChainHash),
		poll.Challenge, encodeExecutorEvidenceTestFrames(secondDelta.Frames),
	)
	type applyResult struct {
		response controlprotocol.ExecutorEvidenceReportResponseV1
		err      error
	}
	readyFirst, readySecond := make(chan struct{}), make(chan struct{})
	releaseFirst, releaseSecond := make(chan struct{}), make(chan struct{})
	resultFirst, resultSecond := make(chan applyResult, 1), make(chan applyResult, 1)
	reportAt := fixture.now.Add(2*time.Minute + time.Second)
	go func() {
		response, err := fixture.store.applyExecutorEvidenceReport(
			fixture.auth, fixture.identity, firstReport, reportAt,
			func() {
				close(readyFirst)
				<-releaseFirst
			},
		)
		resultFirst <- applyResult{response: response, err: err}
	}()
	go func() {
		response, err := fixture.store.applyExecutorEvidenceReport(
			fixture.auth, fixture.identity, secondReport, reportAt,
			func() {
				close(readySecond)
				<-releaseSecond
			},
		)
		resultSecond <- applyResult{response: response, err: err}
	}()
	<-readyFirst
	<-readySecond
	close(releaseFirst)
	first := <-resultFirst
	if first.err != nil || !first.response.Applied {
		t.Fatalf("first concurrent advancement=%#v err=%v", first.response, first.err)
	}
	close(releaseSecond)
	second := <-resultSecond
	if second.err != nil || !second.response.Applied ||
		second.response.Status.State != controlprotocol.ExecutorEvidenceStatusEquivocationDetected {
		t.Fatalf("second concurrent advancement=%#v err=%v", second.response, second.err)
	}
	retained := retainedExecutorEvidence(t, fixture.store, fixture.identity.NodeID)
	if retained.Sequence != firstDelta.Head.Sequence ||
		retained.ChainHash != encodeExecutorEvidenceHash(firstDelta.Head.ChainHash) ||
		retained.Finding == nil || retained.Finding.LastReason != EvidenceFork ||
		retained.Finding.LastChainHash != encodeExecutorEvidenceHash(secondDelta.Head.ChainHash) {
		t.Fatalf("concurrent fork witness=%#v", retained)
	}
	replayed, err := fixture.store.ApplyExecutorEvidenceReport(
		fixture.auth, fixture.identity, firstReport, reportAt.Add(time.Second),
	)
	if err != nil || replayed.Applied ||
		replayed.Status.State != controlprotocol.ExecutorEvidenceStatusEquivocationDetected ||
		replayed.Status.Finding == nil {
		t.Fatalf("replayed primary after fork response=%#v err=%v", replayed, err)
	}
}

func TestExecutorEvidenceAcceptsBoundedPrefixHead(t *testing.T) {
	fixture := newExecutorEvidenceFixture(t, "tenant-a")
	for index := 0; index < evidence.MaxDeltaRecords+1; index++ {
		fixture.appendReceipt(t, "tenant-a")
	}
	localHead, err := fixture.log.CurrentHead()
	if err != nil {
		t.Fatal(err)
	}
	if localHead.Sequence != evidence.MaxDeltaRecords+1 {
		t.Fatalf("local evidence head=%d", localHead.Sequence)
	}
	firstPoll := fixture.poll(t, fixture.now.Add(2*time.Minute))
	firstReport, firstDelta := fixture.reportFrom(t, evidence.Coordinate{}, firstPoll.Challenge)
	if firstDelta.Head.Sequence != evidence.MaxDeltaRecords ||
		firstReport.HeadProof.Claim.Sequence != firstDelta.Head.Sequence {
		t.Fatalf("first bounded report head=%d delta=%d",
			firstReport.HeadProof.Claim.Sequence, firstDelta.Head.Sequence)
	}
	first, err := fixture.store.ApplyExecutorEvidenceReport(
		fixture.auth, fixture.identity, firstReport, fixture.now.Add(2*time.Minute+time.Second),
	)
	if err != nil || first.Status.Head == nil || first.Status.Head.Sequence != evidence.MaxDeltaRecords {
		t.Fatalf("first bounded response=%#v err=%v", first, err)
	}

	checkpoint := evidence.Coordinate{Sequence: firstDelta.Head.Sequence, ChainHash: firstDelta.Head.ChainHash}
	secondPoll := fixture.poll(t, fixture.now.Add(3*time.Minute))
	secondReport, secondDelta := fixture.reportFrom(t, checkpoint, secondPoll.Challenge)
	if len(secondDelta.Frames) != 1 || secondDelta.Head.Sequence != localHead.Sequence {
		t.Fatalf("second bounded delta frames=%d head=%d", len(secondDelta.Frames), secondDelta.Head.Sequence)
	}
	second, err := fixture.store.ApplyExecutorEvidenceReport(
		fixture.auth, fixture.identity, secondReport, fixture.now.Add(3*time.Minute+time.Second),
	)
	if err != nil || second.Status.Head == nil || second.Status.Head.Sequence != localHead.Sequence {
		t.Fatalf("second bounded response=%#v err=%v", second, err)
	}
}

func TestExecutorEvidenceInvalidProofDeltaAndTenantDoNotMutate(t *testing.T) {
	tests := []struct {
		name   string
		tenant string
		mutate func(*executorEvidenceFixture, *controlprotocol.ExecutorEvidenceReportV1)
	}{
		{
			name: "head signature", tenant: "tenant-a",
			mutate: func(_ *executorEvidenceFixture, report *controlprotocol.ExecutorEvidenceReportV1) {
				report.HeadProof.SignatureBase64 = base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
			},
		},
		{
			name: "frame signature", tenant: "tenant-a",
			mutate: func(_ *executorEvidenceFixture, report *controlprotocol.ExecutorEvidenceReportV1) {
				frame, _ := base64.StdEncoding.DecodeString(report.SignedFramesBase64[0])
				frame[len(frame)-1] ^= 1
				report.SignedFramesBase64[0] = base64.StdEncoding.EncodeToString(frame)
			},
		},
		{
			name: "tenant scope", tenant: "tenant-b",
			mutate: func(_ *executorEvidenceFixture, _ *controlprotocol.ExecutorEvidenceReportV1) {},
		},
		{
			name: "derived head mismatch", tenant: "tenant-a",
			mutate: func(fixture *executorEvidenceFixture, report *controlprotocol.ExecutorEvidenceReportV1) {
				replacement := fixture.signedReport(
					t, executorEvidenceClaimBase(t, report.HeadProof.Claim),
					report.HeadProof.Claim.Sequence, digestBytes([]byte("unrelated head")),
					report.HeadProof.Claim.Challenge, report.SignedFramesBase64,
				)
				*report = replacement
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newExecutorEvidenceFixture(t, "tenant-a")
			fixture.appendReceipt(t, test.tenant)
			poll := fixture.poll(t, fixture.now.Add(2*time.Minute))
			report, _ := fixture.reportFrom(t, evidence.Coordinate{}, poll.Challenge)
			test.mutate(&fixture, &report)
			before := retainedExecutorEvidence(t, fixture.store, fixture.identity.NodeID)
			sequence := fixture.store.sequence
			if _, err := fixture.store.ApplyExecutorEvidenceReport(
				fixture.auth, fixture.identity, report, fixture.now.Add(2*time.Minute+time.Second),
			); !errors.Is(err, ErrInvalid) {
				t.Fatalf("invalid report error=%v", err)
			}
			after := retainedExecutorEvidence(t, fixture.store, fixture.identity.NodeID)
			if !evidenceWitnessEqual(before, after) || fixture.store.sequence != sequence {
				t.Fatalf("invalid report mutated witness before=%#v after=%#v", before, after)
			}
		})
	}

	fixture := newExecutorEvidenceFixture(t, "tenant-a")
	poll := fixture.poll(t, fixture.now.Add(2*time.Minute))
	head, err := fixture.log.CurrentHead()
	if err != nil {
		t.Fatal(err)
	}
	malformed := fixture.signedReport(
		t, evidence.Coordinate{Sequence: head.Sequence, ChainHash: head.ChainHash},
		head.Sequence, encodeExecutorEvidenceHash(head.ChainHash), poll.Challenge, nil,
	)
	malformed.SignedFramesBase64 = []string{"AA=="}
	if _, err := fixture.store.ApplyExecutorEvidenceReport(
		fixture.auth, fixture.identity, malformed, fixture.now.Add(2*time.Minute+time.Second),
	); !errors.Is(err, ErrInvalid) {
		t.Fatalf("malformed delta error=%v", err)
	}
}

func TestExecutorEvidenceUsesCredentialTenantScopeNotNodeUnion(t *testing.T) {
	fixture := newExecutorEvidenceFixture(t, "tenant-a")
	fixture.createTenant(t, "tenant-b")
	if _, _, _, err := fixture.store.CreateEnrollment(
		fixture.admin, fixture.auth, fixture.identity.NodeID, []string{"tenant-b"},
		fixture.now.Add(2*time.Hour), fixture.now.Add(2*time.Minute),
	); err != nil {
		t.Fatal(err)
	}
	node := retainedExecutorEvidenceNode(t, fixture.store, fixture.identity.NodeID)
	if !tenantMember(node.TenantIDs, "tenant-b") || tenantMember(fixture.identity.TenantIDs, "tenant-b") {
		t.Fatalf("test did not establish node-union/credential-scope split: node=%v credential=%v",
			node.TenantIDs, fixture.identity.TenantIDs)
	}
	fixture.appendReceipt(t, "tenant-b")
	poll := fixture.poll(t, fixture.now.Add(3*time.Minute))
	report, _ := fixture.reportFrom(t, evidence.Coordinate{}, poll.Challenge)
	before := retainedExecutorEvidence(t, fixture.store, fixture.identity.NodeID)
	if _, err := fixture.store.ApplyExecutorEvidenceReport(
		fixture.auth, fixture.identity, report, fixture.now.Add(3*time.Minute+time.Second),
	); !errors.Is(err, ErrInvalid) {
		t.Fatalf("cross-credential tenant evidence error=%v", err)
	}
	after := retainedExecutorEvidence(t, fixture.store, fixture.identity.NodeID)
	if !evidenceWitnessEqual(before, after) {
		t.Fatal("credential-out-of-scope evidence mutated the witness")
	}
}

func TestExecutorEvidenceReportFencesCredentialRevocationBetweenVerificationPhases(t *testing.T) {
	fixture := newExecutorEvidenceFixture(t, "tenant-a")
	fixture.appendReceipt(t, "tenant-a")
	poll := fixture.poll(t, fixture.now.Add(2*time.Minute))
	report, _ := fixture.reportFrom(t, evidence.Coordinate{}, poll.Challenge)

	snapshotTaken := make(chan struct{})
	continueVerification := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		_, err := fixture.store.applyExecutorEvidenceReport(
			fixture.auth, fixture.identity, report, fixture.now.Add(3*time.Minute),
			func() {
				close(snapshotTaken)
				<-continueVerification
			},
		)
		result <- err
	}()
	<-snapshotTaken
	if _, revoked, err := fixture.store.RevokeNodeCredential(
		fixture.admin, fixture.identity.CredentialID, fixture.now.Add(2*time.Minute+30*time.Second),
	); err != nil || !revoked {
		t.Fatal(err)
	}
	close(continueVerification)
	if err := <-result; !errors.Is(err, controlauth.ErrUnauthorized) {
		t.Fatalf("report crossing revocation error=%v", err)
	}
	retained := retainedExecutorEvidence(t, fixture.store, fixture.identity.NodeID)
	if retained.Sequence != 0 || retained.Finding != nil {
		t.Fatalf("revoked report mutated witness=%#v", retained)
	}
}

func TestConcurrentExecutorEvidenceReportAppliesOnce(t *testing.T) {
	fixture := newExecutorEvidenceFixture(t, "tenant-a")
	fixture.appendReceipt(t, "tenant-a")
	poll := fixture.poll(t, fixture.now.Add(2*time.Minute))
	report, _ := fixture.reportFrom(t, evidence.Coordinate{}, poll.Challenge)

	const workers = 16
	start := make(chan struct{})
	results := make(chan controlprotocol.ExecutorEvidenceReportResponseV1, workers)
	errorsSeen := make(chan error, workers)
	var group sync.WaitGroup
	for index := 0; index < workers; index++ {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			response, err := fixture.store.ApplyExecutorEvidenceReport(
				fixture.auth, fixture.identity, report, fixture.now.Add(2*time.Minute+time.Second),
			)
			results <- response
			errorsSeen <- err
		}()
	}
	close(start)
	group.Wait()
	close(results)
	close(errorsSeen)

	applied := 0
	for err := range errorsSeen {
		if err != nil && !errors.Is(err, ErrConflict) {
			t.Fatalf("concurrent report error=%v", err)
		}
	}
	for response := range results {
		if response.Applied {
			applied++
		}
	}
	if applied != 1 {
		t.Fatalf("concurrent reports applied=%d want 1", applied)
	}
	retained := retainedExecutorEvidence(t, fixture.store, fixture.identity.NodeID)
	if retained.Sequence != 1 || retained.RecordsAccepted != 1 {
		t.Fatalf("concurrent retained witness=%#v", retained)
	}
}

func TestExecutorEvidenceWALFailureDoesNotPublish(t *testing.T) {
	fixture := newExecutorEvidenceFixture(t, "tenant-a")
	fixture.appendReceipt(t, "tenant-a")
	poll := fixture.poll(t, fixture.now.Add(2*time.Minute))
	report, _ := fixture.reportFrom(t, evidence.Coordinate{}, poll.Challenge)
	before := retainedExecutorEvidence(t, fixture.store, fixture.identity.NodeID)
	sequence := fixture.store.sequence
	fixture.store.syncFile = func(*os.File) error { return errors.New("injected evidence sync failure") }
	if _, err := fixture.store.ApplyExecutorEvidenceReport(
		fixture.auth, fixture.identity, report, fixture.now.Add(2*time.Minute+time.Second),
	); err == nil {
		t.Fatal("evidence advancement succeeded despite WAL sync failure")
	}
	after := retainedExecutorEvidence(t, fixture.store, fixture.identity.NodeID)
	if !evidenceWitnessEqual(before, after) || fixture.store.sequence != sequence {
		t.Fatalf("unsynced evidence mutation published before=%#v after=%#v", before, after)
	}
	if _, err := fixture.store.PollExecutorEvidence(
		fixture.auth, fixture.identity, fixture.request, fixture.now.Add(3*time.Minute), fixture.now.Add(8*time.Minute),
	); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("poisoned evidence store poll error=%v", err)
	}
}

func TestExecutorEvidenceFindingWALFailureDoesNotPublish(t *testing.T) {
	fixture := newExecutorEvidenceFixture(t, "tenant-a")
	fixture.appendReceipt(t, "tenant-a")
	advancePoll := fixture.poll(t, fixture.now.Add(2*time.Minute))
	advance, _ := fixture.reportFrom(t, evidence.Coordinate{}, advancePoll.Challenge)
	if _, err := fixture.store.ApplyExecutorEvidenceReport(
		fixture.auth, fixture.identity, advance, fixture.now.Add(2*time.Minute+time.Second),
	); err != nil {
		t.Fatal(err)
	}

	rollbackPoll := fixture.poll(t, fixture.now.Add(3*time.Minute))
	before := retainedExecutorEvidence(t, fixture.store, fixture.identity.NodeID)
	beforeHash, err := decodeExecutorEvidenceHash(before.ChainHash)
	if err != nil {
		t.Fatal(err)
	}
	rollback := fixture.signedReport(
		t, evidence.Coordinate{Sequence: before.Sequence, ChainHash: beforeHash},
		0, zeroEvidenceHash(), rollbackPoll.Challenge, nil,
	)
	sequence := fixture.store.sequence
	fixture.store.syncFile = func(*os.File) error { return errors.New("injected finding sync failure") }
	if _, err := fixture.store.ApplyExecutorEvidenceReport(
		fixture.auth, fixture.identity, rollback, fixture.now.Add(3*time.Minute+time.Second),
	); err == nil {
		t.Fatal("evidence finding succeeded despite WAL sync failure")
	}
	after := retainedExecutorEvidence(t, fixture.store, fixture.identity.NodeID)
	if !evidenceWitnessEqual(before, after) || after.Finding != nil || fixture.store.sequence != sequence {
		t.Fatalf("unsynced evidence finding published before=%#v after=%#v", before, after)
	}
}

func (fixture executorEvidenceFixture) poll(t *testing.T, now time.Time) controlprotocol.ExecutorEvidencePollResponseV1 {
	t.Helper()
	response, err := fixture.store.PollExecutorEvidence(
		fixture.auth, fixture.identity, fixture.request, now, now.Add(5*time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := response.Validate(); err != nil {
		t.Fatalf("invalid poll response: %v", err)
	}
	return response
}

func (fixture executorEvidenceFixture) appendReceipt(t *testing.T, tenantID string) {
	t.Helper()
	next := fixture.log.NextSequence()
	_, err := fixture.log.Append(evidence.Event{
		Type: evidence.AdmissionAllow, TenantID: tenantID, RuntimeRef: "runtime-a",
		CapsuleDigest: "sha256:capsule", PolicyDigest: "sha256:policy", Generation: next,
		GrantID: "grant-a", Outcome: evidence.Allowed,
	})
	if err != nil {
		t.Fatal(err)
	}
}

func (fixture executorEvidenceFixture) reportFrom(t *testing.T, coordinate evidence.Coordinate, challenge string) (controlprotocol.ExecutorEvidenceReportV1, evidence.Delta) {
	t.Helper()
	delta, err := fixture.log.ExportDelta(coordinate)
	if err != nil {
		t.Fatal(err)
	}
	return fixture.signedReport(
		t, coordinate, delta.Head.Sequence, encodeExecutorEvidenceHash(delta.Head.ChainHash), challenge,
		encodeExecutorEvidenceTestFrames(delta.Frames),
	), delta
}

func (fixture executorEvidenceFixture) signedReport(
	t *testing.T,
	base evidence.Coordinate,
	sequence uint64,
	chainHash, challenge string,
	frames []string,
) controlprotocol.ExecutorEvidenceReportV1 {
	t.Helper()
	publicKeyDigest := controlprotocol.ExecutorEvidencePublicKeySHA256(fixture.public)
	baseHead := controlprotocol.ExecutorEvidenceHeadV1{
		Stream: controlprotocol.ExecutorEvidenceStreamV1, ReceiptNodeID: fixture.identity.NodeID,
		ReceiptEpoch: 1, Sequence: base.Sequence, ChainHash: encodeExecutorEvidenceHash(base.ChainHash),
		PublicKeySHA256: publicKeyDigest,
	}
	reportedHead := controlprotocol.ExecutorEvidenceHeadV1{
		Stream: controlprotocol.ExecutorEvidenceStreamV1, ReceiptNodeID: fixture.identity.NodeID,
		ReceiptEpoch: 1, Sequence: sequence, ChainHash: chainHash, PublicKeySHA256: publicKeyDigest,
	}
	decodedFrames := make([][]byte, len(frames))
	for index, encoded := range frames {
		frame, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			t.Fatal(err)
		}
		decodedFrames[index] = frame
	}
	claim, err := controlprotocol.NewExecutorEvidenceHeadClaimV1(
		fixture.auth.InstanceID(), fixture.identity.NodeID,
		baseHead, reportedHead, challenge, decodedFrames, fixture.public,
	)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := controlprotocol.SignExecutorEvidenceHeadClaimV1(claim, fixture.private)
	if err != nil {
		t.Fatal(err)
	}
	return controlprotocol.ExecutorEvidenceReportV1{
		ProtocolVersion: controlprotocol.ExecutorEvidenceProtocolV1,
		HeadProof:       proof, SignedFramesBase64: append([]string(nil), frames...),
	}
}

func executorEvidenceClaimBase(t *testing.T, claim controlprotocol.ExecutorEvidenceHeadClaimV1) evidence.Coordinate {
	t.Helper()
	hash, err := decodeExecutorEvidenceHash(claim.BaseChainHash)
	if err != nil {
		t.Fatal(err)
	}
	return evidence.Coordinate{Sequence: claim.BaseSequence, ChainHash: hash}
}

func retainedExecutorEvidence(t *testing.T, store *Store, nodeID string) EvidenceWitness {
	t.Helper()
	store.mu.Lock()
	defer store.mu.Unlock()
	node, ok := store.current.nodes[nodeID]
	if !ok || node.Evidence == nil {
		t.Fatalf("node %q has no retained evidence witness", nodeID)
	}
	return *cloneEvidenceWitness(node.Evidence)
}

func retainedExecutorEvidenceNode(t *testing.T, store *Store, nodeID string) Node {
	t.Helper()
	store.mu.Lock()
	defer store.mu.Unlock()
	node, ok := store.current.nodes[nodeID]
	if !ok || node.Evidence == nil {
		t.Fatalf("node %q has no retained evidence witness", nodeID)
	}
	return cloneNode(node)
}

func encodeExecutorEvidenceTestFrames(frames [][]byte) []string {
	encoded := make([]string, len(frames))
	for index, frame := range frames {
		encoded[index] = base64.StdEncoding.EncodeToString(frame)
	}
	return encoded
}
