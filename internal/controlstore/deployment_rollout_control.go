package controlstore

import (
	"math"
	"time"

	"github.com/hardrails/steward/internal/controlauth"
)

// SetDeploymentRolloutPaused controls whether reconciliation may spend a new
// disruption-budget slot. Commands and per-instance transitions already in
// flight continue to their safe boundary so a pause cannot strand a runtime
// between source destruction and target admission.
func (store *Store) SetDeploymentRolloutPaused(
	actor controlauth.Identity,
	tenantID, deploymentID string,
	expectedRevision uint64,
	paused bool,
	now time.Time,
) (Deployment, bool, error) {
	if store == nil {
		return Deployment{}, false, ErrUnavailable
	}
	if !controlauth.AuthorizedTenant(actor, tenantID) {
		return Deployment{}, false, ErrNotFound
	}
	if now.IsZero() || expectedRevision == 0 || !validRecordID(tenantID, 128) ||
		!validRecordID(deploymentID, 128) {
		return Deployment{}, false, invalid("deployment rollout control input is invalid")
	}

	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.availableLocked(); err != nil {
		return Deployment{}, false, err
	}
	if err := store.revalidateOperatorLocked(actor); err != nil {
		return Deployment{}, false, err
	}
	deployment, found := store.current.deployments[deploymentKey(tenantID, deploymentID)]
	if !found {
		return Deployment{}, false, ErrNotFound
	}
	if deployment.Revision != expectedRevision || deployment.DesiredState != DeploymentRunning ||
		deployment.Rollout == nil {
		return Deployment{}, false, ErrConflict
	}
	isPaused := deployment.Rollout.PausedAt != ""
	if isPaused == paused {
		return cloneDeployment(deployment), false, nil
	}
	if deployment.Revision == math.MaxUint64 {
		return Deployment{}, false, ErrCapacityExceeded
	}
	deployment.Rollout = cloneDeployment(deployment).Rollout
	if paused {
		deployment.Rollout.PausedAt = canonicalTimestamp(now)
	} else {
		deployment.Rollout.PausedAt = ""
	}
	deployment.Revision++
	deployment.UpdatedAt = canonicalTimestamp(now)
	if err := store.applyMutationsLocked(deploymentMutation(deployment)); err != nil {
		return Deployment{}, false, err
	}
	return cloneDeployment(deployment), true, nil
}
