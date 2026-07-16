package controlstore

import (
	"crypto/sha256"
	"encoding/binary"
	"hash"
	"time"

	"github.com/hardrails/steward/internal/controlauth"
	"github.com/hardrails/steward/internal/controlprotocol"
)

const maxExecutorEvidenceChallengeVariants = 2

type executorEvidenceReportAttempt struct {
	challenge [sha256.Size]byte
	report    [sha256.Size]byte
	expiresAt time.Time
	response  controlprotocol.ExecutorEvidenceReportResponseV1
	err       error
}

type executorEvidenceReportGate struct {
	pendingChallenge [sha256.Size]byte
	pendingExpiresAt time.Time
	hasPending       bool
	// issuedUntil is the latest expiry of every challenge issued or accepted
	// through this process. It keeps an empty gate as a bounded tombstone until
	// every superseded challenge is cryptographically expired.
	issuedUntil time.Time
	active      *executorEvidenceReportAttempt
	completed   []*executorEvidenceReportAttempt
}

// rememberExecutorEvidenceChallenge retains only the latest challenge issued
// to one credential. The map is bounded by the durable credential capacity and
// is deliberately ephemeral: after restart, a still-valid authenticated token
// can be consumed once and is then covered by the same gate.
func (store *Store) rememberExecutorEvidenceChallenge(credentialID, challenge string, expiresAt, now time.Time) error {
	if store == nil || credentialID == "" || challenge == "" || now.IsZero() || !expiresAt.After(now) {
		return invalid("executor evidence challenge gate input is invalid")
	}
	store.evidenceReportMu.Lock()
	defer store.evidenceReportMu.Unlock()
	gate, err := store.executorEvidenceReportGateLocked(credentialID, now)
	if err != nil {
		return err
	}
	gate.pendingChallenge = sha256.Sum256([]byte(challenge))
	gate.pendingExpiresAt = expiresAt.UTC()
	gate.hasPending = true
	if expiresAt.UTC().After(gate.issuedUntil) {
		gate.issuedUntil = expiresAt.UTC()
	}
	gate.completed = nil
	return nil
}

// beginExecutorEvidenceReport admits at most one expensive verification for an
// exact report at a time. One challenge can verify a primary report and at most
// one distinct variant so Steward can still retain direct equivocation evidence;
// further variants are rejected without repeating receipt-signature work.
func (store *Store) beginExecutorEvidenceReport(
	credentialID, challenge string,
	reportDigest [sha256.Size]byte,
	expiresAt, now time.Time,
) (*executorEvidenceReportAttempt, controlprotocol.ExecutorEvidenceReportResponseV1, error, bool) {
	challengeDigest := sha256.Sum256([]byte(challenge))
	store.evidenceReportMu.Lock()
	gate, err := store.executorEvidenceReportGateLocked(credentialID, now)
	if err != nil {
		store.evidenceReportMu.Unlock()
		return nil, controlprotocol.ExecutorEvidenceReportResponseV1{}, err, false
	}
	gate.pruneExpired(now)
	if gate.active != nil {
		store.evidenceReportMu.Unlock()
		return nil, controlprotocol.ExecutorEvidenceReportResponseV1{}, ErrConflict, false
	}

	secondary := false
	restartFallback := false
	if gate.hasPending {
		if gate.pendingChallenge != challengeDigest || !gate.pendingExpiresAt.Equal(expiresAt.UTC()) {
			store.evidenceReportMu.Unlock()
			return nil, controlprotocol.ExecutorEvidenceReportResponseV1{}, ErrConflict, false
		}
		gate.hasPending = false
		gate.completed = nil
	} else if len(gate.completed) > 0 {
		if gate.completed[0].challenge != challengeDigest {
			store.evidenceReportMu.Unlock()
			return nil, controlprotocol.ExecutorEvidenceReportResponseV1{}, ErrConflict, false
		}
		for _, completed := range gate.completed {
			if completed.report == reportDigest {
				store.evidenceReportMu.Unlock()
				return nil, executorEvidenceReplayResponse(completed.response, completed.err), completed.err, false
			}
		}
		if len(gate.completed) >= maxExecutorEvidenceChallengeVariants {
			store.evidenceReportMu.Unlock()
			return nil, controlprotocol.ExecutorEvidenceReportResponseV1{}, ErrConflict, false
		}
		secondary = true
	} else if gate.issuedUntil.After(now.UTC()) {
		store.evidenceReportMu.Unlock()
		return nil, controlprotocol.ExecutorEvidenceReportResponseV1{}, ErrConflict, false
	} else {
		restartFallback = true
	}

	attempt := &executorEvidenceReportAttempt{
		challenge: challengeDigest,
		report:    reportDigest,
		expiresAt: expiresAt.UTC(),
	}
	if restartFallback {
		gate.issuedUntil = now.UTC().Add(controlauth.MaxEvidenceChallengeLifetime)
	} else if expiresAt.UTC().After(gate.issuedUntil) {
		gate.issuedUntil = expiresAt.UTC()
	}
	gate.active = attempt
	if !secondary {
		gate.completed = nil
	}
	store.evidenceReportMu.Unlock()
	return attempt, controlprotocol.ExecutorEvidenceReportResponseV1{}, nil, true
}

func (store *Store) finishExecutorEvidenceReport(
	credentialID string,
	attempt *executorEvidenceReportAttempt,
	response controlprotocol.ExecutorEvidenceReportResponseV1,
	err error,
) {
	store.evidenceReportMu.Lock()
	defer store.evidenceReportMu.Unlock()
	gate := store.evidenceReports[credentialID]
	if gate == nil || attempt == nil || gate.active != attempt {
		return
	}
	attempt.response = response
	attempt.err = err
	gate.active = nil
	if !gate.hasPending {
		gate.completed = append(gate.completed, attempt)
		if len(gate.completed) > maxExecutorEvidenceChallengeVariants {
			gate.completed = gate.completed[len(gate.completed)-maxExecutorEvidenceChallengeVariants:]
		}
	}
}

func (store *Store) executorEvidenceReportGateLocked(credentialID string, now time.Time) (*executorEvidenceReportGate, error) {
	if store.evidenceReports == nil {
		store.evidenceReports = make(map[string]*executorEvidenceReportGate)
	}
	if gate := store.evidenceReports[credentialID]; gate != nil {
		return gate, nil
	}
	for id, candidate := range store.evidenceReports {
		candidate.pruneExpired(now)
		if candidate.active == nil && !candidate.hasPending && len(candidate.completed) == 0 &&
			!candidate.issuedUntil.After(now.UTC()) {
			delete(store.evidenceReports, id)
		}
	}
	if len(store.evidenceReports) >= store.limits.MaxCredentials {
		return nil, ErrCapacityExceeded
	}
	gate := &executorEvidenceReportGate{}
	store.evidenceReports[credentialID] = gate
	return gate, nil
}

func (gate *executorEvidenceReportGate) pruneExpired(now time.Time) {
	if gate.hasPending && !gate.pendingExpiresAt.After(now.UTC()) {
		gate.hasPending = false
	}
	kept := gate.completed[:0]
	for _, completed := range gate.completed {
		if completed.expiresAt.After(now.UTC()) {
			kept = append(kept, completed)
		}
	}
	gate.completed = kept
}

func executorEvidenceReplayResponse(
	response controlprotocol.ExecutorEvidenceReportResponseV1,
	err error,
) controlprotocol.ExecutorEvidenceReportResponseV1 {
	if err == nil {
		response.Applied = false
	}
	return response
}

func executorEvidenceReportFingerprint(report controlprotocol.ExecutorEvidenceReportV1) ([sha256.Size]byte, error) {
	statement, err := controlprotocol.ExecutorEvidenceHeadProofStatementV1(report.HeadProof.Claim)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	digest := sha256.New()
	_, _ = digest.Write([]byte("steward-control-evidence-report-replay-v1\x00"))
	writeExecutorEvidenceDigestField(digest, statement)
	writeExecutorEvidenceDigestField(digest, []byte(report.HeadProof.SignatureBase64))
	var count [8]byte
	binary.BigEndian.PutUint64(count[:], uint64(len(report.SignedFramesBase64)))
	_, _ = digest.Write(count[:])
	for _, frame := range report.SignedFramesBase64 {
		writeExecutorEvidenceDigestField(digest, []byte(frame))
	}
	var result [sha256.Size]byte
	copy(result[:], digest.Sum(nil))
	return result, nil
}

func writeExecutorEvidenceDigestField(digest hash.Hash, value []byte) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	_, _ = digest.Write(length[:])
	_, _ = digest.Write(value)
}
