package rolloutstore

import (
	"fmt"
	"sort"
	"strings"
)

const (
	PlanAuthorizationFileName = "plan-authorization.dsse.json"

	batchPromotionPrefix = "batch-promotion-"
	batchPromotionDigits = 3
	batchPromotionSuffix = ".dsse.json"

	maxPlanAuthorizationBytes = int64(16 << 10)
	maxBatchPromotionBytes    = int64(128 << 10)
)

// BatchPromotionName returns the only accepted artifact name for the signed
// authorization to enter one nonzero batch.
func BatchPromotionName(nextBatch uint16) (string, error) {
	if nextBatch == 0 || nextBatch >= MaxTargets {
		return "", fmt.Errorf("%w: batch promotion index is outside its bound", ErrInvalidName)
	}
	return fmt.Sprintf(
		"%s%0*d%s",
		batchPromotionPrefix,
		batchPromotionDigits,
		nextBatch,
		batchPromotionSuffix,
	), nil
}

// ListBatchPromotions returns every retained promotion name in batch order.
func (store *Store) ListBatchPromotions() ([]string, error) {
	if store == nil {
		return nil, ErrClosed
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.usableLocked(); err != nil {
		return nil, err
	}
	snapshot, err := store.auditLocked()
	if err != nil {
		return nil, err
	}
	names := make([]string, 0)
	for name := range snapshot.info {
		if _, ok := parseBatchPromotionName(name); ok {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names, nil
}

func authorizationArtifactByteLimit(name string) (int64, bool) {
	if name == PlanAuthorizationFileName {
		return maxPlanAuthorizationBytes, true
	}
	if _, ok := parseBatchPromotionName(name); ok {
		return maxBatchPromotionBytes, true
	}
	return 0, false
}

func isAuthorizationArtifactName(name string) bool {
	_, ok := authorizationArtifactByteLimit(name)
	return ok
}

func parseBatchPromotionName(name string) (uint16, bool) {
	expectedLength := len(batchPromotionPrefix) + batchPromotionDigits + len(batchPromotionSuffix)
	if len(name) != expectedLength || !strings.HasPrefix(name, batchPromotionPrefix) ||
		!strings.HasSuffix(name, batchPromotionSuffix) {
		return 0, false
	}
	start := len(batchPromotionPrefix)
	value, ok := parseFixedDecimal(name[start : start+batchPromotionDigits])
	if !ok || value == 0 || value >= MaxTargets {
		return 0, false
	}
	return uint16(value), true
}
