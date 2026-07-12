package executor

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/gateway"
)

// secureMutationBlockedLocked reports whether a signed mutation may widen
// authority or make durable state harder to recover. Callers hold provisionMu,
// which serializes this decision with reconciliation and every host mutation.
func (s *Server) secureMutationBlockedLocked() bool {
	if s.secure == nil {
		return false
	}
	if len(s.secure.journal.Pending()) != 0 {
		return true
	}
	s.reconcileMu.RLock()
	degraded := s.reconcileAttempted && !s.reconcileReport.Ready
	s.reconcileMu.RUnlock()
	return degraded
}

// containSecureWorkload is the only signed mutation allowed while Executor is
// degraded. It does not prepare, commit, compensate, recreate, adopt, remove,
// or update any durable authority record. It can only deactivate the grant
// derived from the retained fence and stop objects whose exact retained
// identity is independently proven. A failed response is followed by exact
// reinspection; an unproven result remains a 503 and readiness stays degraded.
func (s *Server) containSecureWorkload(w http.ResponseWriter, r *http.Request, name string) {
	record, ok := s.containmentFenceRecord(name)
	if !ok {
		writeError(w, http.StatusNotFound, "not_found", "unknown signed workload")
		return
	}
	if !s.principalAuthorizesRecord(r.Context(), record) {
		writeError(w, http.StatusForbidden, "signed_lifecycle_required", "workload is not bound to the authenticated signed admission")
		return
	}

	observed, err := s.docker.Inspect(r.Context(), name)
	if err != nil {
		// The retained fence is sufficient to narrow the deterministic grant
		// even when Docker cannot return the agent. Relay identity cannot be
		// proven without the admitted workload definition, so report incomplete.
		_ = s.containDeterministicGrant(r, record)
		writeError(w, http.StatusServiceUnavailable, "reconciliation_required", "the deterministic grant was contained when possible, but the signed agent and relay identities could not be inspected")
		return
	}
	identityMatches := s.containmentIdentityMatches(name, observed, record)
	if !identityMatches {
		_ = s.containDeterministicGrant(r, record)
		writeError(w, http.StatusConflict, "workload_drift", "workload identity is insufficient for degraded containment")
		return
	}

	final, complete := s.containObservedSecureWorkload(r, name, record, observed)
	if !complete {
		writeError(w, http.StatusServiceUnavailable, "reconciliation_required", "local containment was attempted, but every authority boundary could not be verified inactive and stopped")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"runtime_ref": name, "status": final.Status})
}

// containObservedSecureWorkload performs the shared monotonic containment used
// by degraded stop and by a start request that discovers an already-running
// topology breach. It changes no journal, evidence, fence, or desired-state
// record. Every backend is reinspected before containment is reported complete.
func (s *Server) containObservedSecureWorkload(
	r *http.Request, name string, record admission.FenceRecord, observed ObservedWorkload,
) (ObservedWorkload, bool) {
	if !s.containmentIdentityMatches(name, observed, record) {
		return ObservedWorkload{}, false
	}
	complete := true
	if observed.Workload.Runtime != nil {
		complete = s.containDeterministicGrant(r, record) && complete
	}
	complete = s.containExactAgent(r, name, record, observed) && complete
	if observed.Workload.Runtime != nil {
		complete = s.containExactRelay(r, record, observed.Workload) && complete
	}
	final, err := s.docker.Inspect(r.Context(), name)
	if err != nil || !s.containmentIdentityMatches(name, final, record) ||
		classifyDockerLifecycle(final.Status) != dockerLifecycleStopped {
		return ObservedWorkload{}, false
	}
	return final, complete
}

func (s *Server) containmentFenceRecord(name string) (admission.FenceRecord, bool) {
	for _, record := range s.secure.fences.Records() {
		if record.Present && RuntimeRef(record.TenantID, record.InstanceID) == name {
			return record, true
		}
	}
	return admission.FenceRecord{}, false
}

func (s *Server) containmentIdentityMatches(name string, observed ObservedWorkload, record admission.FenceRecord) bool {
	if !observed.Managed {
		return false
	}
	if !record.Present || RuntimeRef(record.TenantID, record.InstanceID) != name ||
		observed.Workload.TenantID != record.TenantID || observed.Workload.InstanceID != record.InstanceID {
		return false
	}
	wantFingerprint := strings.TrimPrefix(record.WorkloadDigest, "sha256:")
	if wantFingerprint == "" || observed.Fingerprint != wantFingerprint ||
		workloadFingerprint(observed.Workload) != wantFingerprint ||
		observed.ImageID != record.ImageConfigDigest || observed.Workload.ImageConfigDigest != record.ImageConfigDigest {
		return false
	}
	return true
}

func (s *Server) containDeterministicGrant(r *http.Request, record admission.FenceRecord) bool {
	if s.secure.gateway == nil {
		return false
	}
	grantID := gateway.GrantID(record.TenantID, record.InstanceID, record.Generation)
	inspection, inspectErr := s.secure.gateway.InspectWithPolicy(r.Context(), grantID)
	if gatewayGrantNotFound(inspectErr) {
		return true
	}
	if inspectErr != nil || inspection.Grant.Active {
		// Inspection failure cannot prove the grant inactive. Deactivation is
		// idempotent and only narrows the deterministic retained authority.
		_ = s.secure.gateway.Deactivate(r.Context(), grantID)
	}
	inspection, inspectErr = s.secure.gateway.InspectWithPolicy(r.Context(), grantID)
	return gatewayGrantNotFound(inspectErr) || inspectErr == nil && !inspection.Grant.Active
}

func (s *Server) containExactAgent(r *http.Request, name string, record admission.FenceRecord, observed ObservedWorkload) bool {
	if classifyDockerLifecycle(observed.Status) != dockerLifecycleStopped {
		_ = boundedDockerStop(r.Context(), s.docker, name)
	}
	final, err := s.docker.Inspect(r.Context(), name)
	if err != nil {
		return false
	}
	return s.containmentIdentityMatches(name, final, record) && classifyDockerLifecycle(final.Status) == dockerLifecycleStopped
}

func (s *Server) containExactRelay(r *http.Request, record admission.FenceRecord, workload Workload) bool {
	if s.secure.topology == nil || !runtimeIdentityMatchesRecord(workload, record) {
		return false
	}
	want := s.desiredRelay(workload)
	relay, err := s.secure.topology.InspectRelay(r.Context(), want.Name)
	if errors.Is(err, ErrNotFound) {
		return true
	}
	if err != nil || !relayContainmentIdentity(relay, want) {
		// A drifted relay is not adopted as Steward-owned cleanup authority.
		return false
	}
	if classifyDockerLifecycle(relay.Status) != dockerLifecycleStopped {
		_ = s.stopRelayForContainmentAndConfirm(r.Context(), want.Name, want)
	}
	final, err := s.secure.topology.InspectRelay(r.Context(), want.Name)
	return err == nil && relayContainmentIdentity(final, want) && classifyDockerLifecycle(final.Status) == dockerLifecycleStopped
}

// relayContainmentIdentity deliberately omits the Hardened observation. A
// hardened-field drift must prevent start or adoption, but it cannot make an
// otherwise exact Steward relay impossible to stop. The deterministic full
// spec and its fingerprint remain required before any mutation.
func relayContainmentIdentity(observed ObservedRelay, want RelaySpec) bool {
	return observed.Managed && observed.Spec == want && observed.Fingerprint == relayFingerprint(want)
}

func (s *Server) stopRelayForContainmentAndConfirm(ctx context.Context, relayName string, want RelaySpec) error {
	stopErr := boundedDockerStop(ctx, s.docker, relayName)
	observed, inspectErr := s.secure.topology.InspectRelay(ctx, relayName)
	if inspectErr != nil {
		if stopErr != nil {
			return fmt.Errorf("stop trusted relay: %v; inspect stopped trusted relay: %w", stopErr, inspectErr)
		}
		return fmt.Errorf("inspect stopped trusted relay: %w", inspectErr)
	}
	if !relayContainmentIdentity(observed, want) {
		return errors.New("trusted relay identity changed during containment")
	}
	if classifyDockerLifecycle(observed.Status) == dockerLifecycleStopped {
		return nil
	}
	if stopErr != nil {
		return fmt.Errorf("stop trusted relay: %v; Docker status remains %q", stopErr, observed.Status)
	}
	return fmt.Errorf("trusted relay did not reach an exact stopped state; Docker status is %q", observed.Status)
}

func runtimeIdentityMatchesRecord(workload Workload, record admission.FenceRecord) bool {
	runtime := workload.Runtime
	if runtime == nil || runtime.Generation != record.Generation ||
		runtime.NetworkName != NetworkName(record.TenantID, record.InstanceID, record.Generation) ||
		runtime.GrantID != gateway.GrantID(record.TenantID, record.InstanceID, record.Generation) {
		return false
	}
	return runtimeAllocationMatches(
		NetworkSpecFor(record.TenantID, record.InstanceID, record.Generation),
		runtime.Subnet, runtime.Gateway, runtime.RelayIP, runtime.AgentIP,
	)
}
