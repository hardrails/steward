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
