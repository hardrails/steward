package rollout

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
)

// DerivedIdentifierV1 returns a purpose-separated, deterministic rollout
// identifier. Length framing prevents two different field sequences from
// producing the same hash input.
func DerivedIdentifierV1(
	prefix string,
	rolloutID string,
	targetIndex int,
	nodeID string,
) string {
	hash := sha256.New()
	for _, value := range []string{
		"steward-rollout-identifier-v1",
		prefix,
		rolloutID,
		strconv.Itoa(targetIndex),
		nodeID,
	} {
		_, _ = hash.Write([]byte{byte(len(value) >> 8), byte(len(value))})
		_, _ = hash.Write([]byte(value))
	}
	return prefix + "-" + hex.EncodeToString(hash.Sum(nil)[:16])
}

// TargetCommandIDsV1 derives the only command identities accepted for one
// indexed rollout target.
func TargetCommandIDsV1(rolloutID string, targetIndex int, nodeID string) (
	admit string,
	start string,
	canary string,
) {
	prefix := DerivedIdentifierV1("rollout-command", rolloutID, targetIndex, nodeID)
	return prefix + "-admit", prefix + "-start", prefix + "-canary"
}

// PlanAuthorizationCommandIDV1 derives the signed plan authorization identity.
func PlanAuthorizationCommandIDV1(rolloutID, planDigest string) string {
	return DerivedIdentifierV1("rollout-plan-authorization", rolloutID, 0, planDigest)
}

// BatchPromotionCommandIDV1 derives the signed authorization identity for the
// transition into nextBatch. The plan digest prevents cross-plan replay.
func BatchPromotionCommandIDV1(rolloutID, planDigest string, nextBatch uint16) string {
	return DerivedIdentifierV1(
		"rollout-batch-promotion",
		rolloutID,
		int(nextBatch),
		planDigest,
	)
}
