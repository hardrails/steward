package controlstore

import (
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/controlprotocol"
)

func TestExecutorEvidenceReportGateRejectsConcurrentReplayWithoutWaiting(t *testing.T) {
	store := &Store{limits: DefaultLimits()}
	now := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	expiresAt := now.Add(5 * time.Minute)
	const credentialID = "credential-a"
	const challenge = "challenge-a"
	if err := store.rememberExecutorEvidenceChallenge(credentialID, challenge, expiresAt, now); err != nil {
		t.Fatal(err)
	}

	reportDigest := sha256.Sum256([]byte("exact signed report"))
	attempt, _, err, leader := store.beginExecutorEvidenceReport(
		credentialID, challenge, reportDigest, expiresAt, now,
	)
	if err != nil || !leader || attempt == nil {
		t.Fatalf("initial gate admission=(%#v, %v, %t)", attempt, err, leader)
	}

	for range 16 {
		otherAttempt, _, otherErr, otherLeader := store.beginExecutorEvidenceReport(
			credentialID, challenge, reportDigest, expiresAt, now,
		)
		if otherAttempt != nil || !errors.Is(otherErr, ErrConflict) || otherLeader {
			t.Fatalf("active replay admission=(%#v, %v, %t)", otherAttempt, otherErr, otherLeader)
		}
	}
	response := controlprotocol.ExecutorEvidenceReportResponseV1{
		ProtocolVersion: controlprotocol.ExecutorEvidenceProtocolV1,
		Applied:         true,
		Status: controlprotocol.ExecutorEvidenceStatusV1{
			State: controlprotocol.ExecutorEvidenceStatusCurrent,
		},
	}
	store.finishExecutorEvidenceReport(credentialID, attempt, response, nil)
	_, replay, err, leader := store.beginExecutorEvidenceReport(
		credentialID, challenge, reportDigest, expiresAt, now,
	)
	if err != nil || leader || replay.Applied ||
		replay.ProtocolVersion != controlprotocol.ExecutorEvidenceProtocolV1 {
		t.Fatalf("completed replay result=(%#v, %v, %t)", replay, err, leader)
	}
}

func TestExecutorEvidenceReportGateBoundsChallengeVariants(t *testing.T) {
	store := &Store{limits: DefaultLimits()}
	now := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	expiresAt := now.Add(5 * time.Minute)
	const credentialID = "credential-a"
	const challenge = "challenge-a"
	if err := store.rememberExecutorEvidenceChallenge(credentialID, challenge, expiresAt, now); err != nil {
		t.Fatal(err)
	}

	for _, value := range []string{"primary", "equivocation-variant"} {
		digest := sha256.Sum256([]byte(value))
		attempt, _, err, leader := store.beginExecutorEvidenceReport(
			credentialID, challenge, digest, expiresAt, now,
		)
		if err != nil || !leader || attempt == nil {
			t.Fatalf("variant %q admission=(%#v, %v, %t)", value, attempt, err, leader)
		}
		store.finishExecutorEvidenceReport(
			credentialID, attempt, controlprotocol.ExecutorEvidenceReportResponseV1{}, nil,
		)
	}

	thirdDigest := sha256.Sum256([]byte("third variant"))
	if attempt, _, err, leader := store.beginExecutorEvidenceReport(
		credentialID, challenge, thirdDigest, expiresAt, now,
	); attempt != nil || !errors.Is(err, ErrConflict) || leader {
		t.Fatalf("third variant admission=(%#v, %v, %t)", attempt, err, leader)
	}

	const nextChallenge = "challenge-b"
	nextExpiresAt := now.Add(6 * time.Minute)
	if err := store.rememberExecutorEvidenceChallenge(
		credentialID, nextChallenge, nextExpiresAt, now,
	); err != nil {
		t.Fatal(err)
	}
	attempt, _, err, leader := store.beginExecutorEvidenceReport(
		credentialID, nextChallenge, thirdDigest, nextExpiresAt, now,
	)
	if err != nil || !leader || attempt == nil {
		t.Fatalf("new challenge admission=(%#v, %v, %t)", attempt, err, leader)
	}
	store.finishExecutorEvidenceReport(
		credentialID, attempt, controlprotocol.ExecutorEvidenceReportResponseV1{}, nil,
	)
}

func TestExecutorEvidenceReportGatePrunesExpiredCredentials(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxCredentials = 1
	store := &Store{limits: limits}
	now := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	if err := store.rememberExecutorEvidenceChallenge(
		"credential-a", "challenge-a", now.Add(time.Minute), now,
	); err != nil {
		t.Fatal(err)
	}
	if err := store.rememberExecutorEvidenceChallenge(
		"credential-b", "challenge-b", now.Add(time.Minute), now,
	); !errors.Is(err, ErrCapacityExceeded) {
		t.Fatalf("capacity error=%v", err)
	}
	later := now.Add(2 * time.Minute)
	if err := store.rememberExecutorEvidenceChallenge(
		"credential-b", "challenge-b", later.Add(time.Minute), later,
	); err != nil {
		t.Fatalf("reuse expired capacity: %v", err)
	}
}

func TestExecutorEvidenceReportGateDoesNotResurrectSupersededChallenge(t *testing.T) {
	store := &Store{limits: DefaultLimits()}
	now := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	const credentialID = "credential-a"
	oldExpiresAt := now.Add(5 * time.Minute)
	if err := store.rememberExecutorEvidenceChallenge(
		credentialID, "old-challenge", oldExpiresAt, now,
	); err != nil {
		t.Fatal(err)
	}
	if err := store.rememberExecutorEvidenceChallenge(
		credentialID, "new-challenge", now.Add(time.Minute), now,
	); err != nil {
		t.Fatal(err)
	}

	later := now.Add(2 * time.Minute)
	digest := sha256.Sum256([]byte("old report"))
	if attempt, _, err, leader := store.beginExecutorEvidenceReport(
		credentialID, "old-challenge", digest, oldExpiresAt, later,
	); attempt != nil || !errors.Is(err, ErrConflict) || leader {
		t.Fatalf("superseded challenge admission=(%#v, %v, %t)", attempt, err, leader)
	}
}

func TestExecutorEvidenceReportGateAllowsOneRestartFallbackChallenge(t *testing.T) {
	store := &Store{limits: DefaultLimits()}
	now := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	expiresAt := now.Add(5 * time.Minute)
	digest := sha256.Sum256([]byte("report"))
	attempt, _, err, leader := store.beginExecutorEvidenceReport(
		"credential-a", "pre-restart-challenge", digest, expiresAt, now,
	)
	if err != nil || !leader || attempt == nil {
		t.Fatalf("restart fallback admission=(%#v, %v, %t)", attempt, err, leader)
	}
	store.finishExecutorEvidenceReport(
		"credential-a", attempt, controlprotocol.ExecutorEvidenceReportResponseV1{}, nil,
	)
	otherDigest := sha256.Sum256([]byte("different pre-restart report"))
	otherExpiresAt := now.Add(9 * time.Minute)
	if attempt, _, err, leader := store.beginExecutorEvidenceReport(
		"credential-a", "other-pre-restart-challenge", otherDigest, otherExpiresAt, now,
	); attempt != nil || !errors.Is(err, ErrConflict) || leader {
		t.Fatalf("second restart fallback admission=(%#v, %v, %t)", attempt, err, leader)
	}
	later := expiresAt.Add(time.Second)
	if attempt, _, err, leader := store.beginExecutorEvidenceReport(
		"credential-a", "other-pre-restart-challenge", otherDigest, otherExpiresAt, later,
	); attempt != nil || !errors.Is(err, ErrConflict) || leader {
		t.Fatalf("staggered restart fallback admission=(%#v, %v, %t)", attempt, err, leader)
	}
}

func TestExecutorEvidenceReportGateRejectsInvalidAndCapacityBoundAdmissions(t *testing.T) {
	now := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	for name, test := range map[string]struct {
		store        *Store
		credentialID string
		challenge    string
		expiresAt    time.Time
		now          time.Time
	}{
		"nil store":        {credentialID: "credential-a", challenge: "challenge-a", expiresAt: now.Add(time.Minute), now: now},
		"empty credential": {store: &Store{limits: DefaultLimits()}, challenge: "challenge-a", expiresAt: now.Add(time.Minute), now: now},
		"empty challenge":  {store: &Store{limits: DefaultLimits()}, credentialID: "credential-a", expiresAt: now.Add(time.Minute), now: now},
		"zero now":         {store: &Store{limits: DefaultLimits()}, credentialID: "credential-a", challenge: "challenge-a", expiresAt: now.Add(time.Minute)},
		"expired":          {store: &Store{limits: DefaultLimits()}, credentialID: "credential-a", challenge: "challenge-a", expiresAt: now, now: now},
	} {
		t.Run(name, func(t *testing.T) {
			if err := test.store.rememberExecutorEvidenceChallenge(
				test.credentialID, test.challenge, test.expiresAt, test.now,
			); !errors.Is(err, ErrInvalid) {
				t.Fatalf("invalid gate input error=%v", err)
			}
		})
	}

	limits := DefaultLimits()
	limits.MaxCredentials = 1
	store := &Store{limits: limits}
	if err := store.rememberExecutorEvidenceChallenge(
		"credential-a", "challenge-a", now.Add(time.Minute), now,
	); err != nil {
		t.Fatal(err)
	}
	if attempt, _, err, leader := store.beginExecutorEvidenceReport(
		"credential-b", "challenge-b", sha256.Sum256([]byte("report")),
		now.Add(time.Minute), now,
	); attempt != nil || !errors.Is(err, ErrCapacityExceeded) || leader {
		t.Fatalf("capacity-bound admission=(%#v, %v, %t)", attempt, err, leader)
	}
}

func TestExecutorEvidenceReportGateBindsPendingChallengeAndIgnoresForeignCompletion(t *testing.T) {
	store := &Store{limits: DefaultLimits()}
	now := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	expiresAt := now.Add(5 * time.Minute)
	const credentialID = "credential-a"
	const challenge = "challenge-a"
	if err := store.rememberExecutorEvidenceChallenge(credentialID, challenge, expiresAt, now); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("report"))
	for name, candidate := range map[string]struct {
		challenge string
		expiresAt time.Time
	}{
		"challenge": {"substituted", expiresAt},
		"expiry":    {challenge, expiresAt.Add(time.Second)},
	} {
		t.Run(name, func(t *testing.T) {
			if attempt, _, err, leader := store.beginExecutorEvidenceReport(
				credentialID, candidate.challenge, digest, candidate.expiresAt, now,
			); attempt != nil || !errors.Is(err, ErrConflict) || leader {
				t.Fatalf("substituted pending claim=(%#v, %v, %t)", attempt, err, leader)
			}
		})
	}

	attempt, _, err, leader := store.beginExecutorEvidenceReport(
		credentialID, challenge, digest, expiresAt, now,
	)
	if err != nil || !leader || attempt == nil {
		t.Fatalf("valid admission=(%#v, %v, %t)", attempt, err, leader)
	}
	store.finishExecutorEvidenceReport(
		credentialID, &executorEvidenceReportAttempt{}, controlprotocol.ExecutorEvidenceReportResponseV1{}, nil,
	)
	if other, _, err, leader := store.beginExecutorEvidenceReport(
		credentialID, challenge, digest, expiresAt, now,
	); other != nil || !errors.Is(err, ErrConflict) || leader {
		t.Fatalf("foreign completion cleared active attempt=(%#v, %v, %t)", other, err, leader)
	}
	store.finishExecutorEvidenceReport(
		credentialID, attempt, controlprotocol.ExecutorEvidenceReportResponseV1{}, nil,
	)

	laterExpiry := expiresAt.Add(time.Minute)
	secondDigest := sha256.Sum256([]byte("equivocation variant"))
	second, _, err, leader := store.beginExecutorEvidenceReport(
		credentialID, challenge, secondDigest, laterExpiry, now,
	)
	if err != nil || !leader || second == nil {
		t.Fatalf("secondary admission=(%#v, %v, %t)", second, err, leader)
	}
	store.finishExecutorEvidenceReport(
		credentialID, second, controlprotocol.ExecutorEvidenceReportResponseV1{}, nil,
	)
	if got := store.evidenceReports[credentialID].issuedUntil; !got.Equal(laterExpiry) {
		t.Fatalf("secondary report expiry tombstone=%v want=%v", got, laterExpiry)
	}
}

func TestExecutorEvidenceReportFingerprintRejectsMalformedClaim(t *testing.T) {
	if _, err := executorEvidenceReportFingerprint(controlprotocol.ExecutorEvidenceReportV1{}); err == nil {
		t.Fatal("malformed evidence report produced a replay fingerprint")
	}
}
