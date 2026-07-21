package executor

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/evidence"
	"github.com/hardrails/steward/internal/gateway"
)

// recoverMissingWorkload handles the one degraded state where ordinary destroy
// is both safe and necessary: reconciliation has proven that the signed agent
// container is already absent. It returns false unless every precondition for
// this narrow recovery is present, leaving the normal degraded gate in force.
func (s *Server) recoverMissingWorkload(w http.ResponseWriter, r *http.Request, runtimeRef string) bool {
	if len(s.secure.journal.Pending()) != 0 {
		return false
	}
	s.reconcileMu.RLock()
	report := cloneReconcileReport(s.reconcileReport)
	attempted := s.reconcileAttempted
	s.reconcileMu.RUnlock()
	if !attempted || len(report.Failures) != 1 || report.DroppedFailures != 0 ||
		report.Failures[0].RuntimeRef != runtimeRef || report.Failures[0].Code != "workload_missing" {
		return false
	}
	record, ok := s.missingRecoveryRecord(r, runtimeRef)
	if !ok {
		return false
	}
	if _, err := s.docker.Inspect(r.Context(), runtimeRef); !errors.Is(err, ErrNotFound) {
		writeError(w, http.StatusConflict, "recovery_precondition_changed", "the workload is no longer proven absent; run reconciliation again")
		return true
	}
	if err := s.applyMissingWorkloadRecovery(r, record, runtimeRef); err != nil {
		writeError(w, http.StatusServiceUnavailable, "reconciliation_required", err.Error())
		return true
	}
	w.WriteHeader(http.StatusNoContent)
	return true
}

func (s *Server) missingRecoveryRecord(r *http.Request, runtimeRef string) (admission.FenceRecord, bool) {
	for _, record := range s.secure.fences.Records() {
		if record.Present && RuntimeRef(record.TenantID, record.InstanceID) == runtimeRef &&
			s.principalAuthorizesRecord(r.Context(), record) {
			return record, true
		}
	}
	return admission.FenceRecord{}, false
}

func (s *Server) applyMissingWorkloadRecovery(r *http.Request, record admission.FenceRecord, runtimeRef string) error {
	opID, err := newOperationID("recover-missing-"+runtimeRef, record.Generation)
	if err != nil {
		return fmt.Errorf("create missing-workload recovery identity: %w", err)
	}
	if _, err := s.secure.journal.Prepare(opID, "recover-missing:"+runtimeRef, record.Generation); err != nil {
		return fmt.Errorf("prepare missing-workload recovery: %w", err)
	}
	prepared := evidence.Event{
		Type: evidence.JournalPrepare, TenantID: record.TenantID, RuntimeRef: runtimeRef,
		CapsuleDigest: record.CapsuleDigest, PolicyDigest: record.PolicyDigest,
		Generation: record.Generation, GrantID: "workload", Outcome: evidence.Allowed,
		ErrorCode: "recover_missing_workload",
	}
	if _, err := s.secure.evidence.Append(prepared); err != nil {
		_ = s.secure.journal.Compensate(opID)
		return fmt.Errorf("record missing-workload recovery authorization: %w", err)
	}

	ctx := r.Context()
	grantID := gateway.GrantID(record.TenantID, record.InstanceID, record.Generation)
	if record.RoutePolicyDigest != "" {
		if s.secure.gateway == nil || s.secure.topology == nil {
			return errors.New("missing-workload recovery requires the configured Gateway and topology inspector")
		}
		inspection, grantErr := s.secure.gateway.InspectWithPolicy(ctx, grantID)
		if grantErr == nil {
			grant := inspection.Grant
			if grant.GrantID != grantID || grant.TenantID != record.TenantID || grant.InstanceID != record.InstanceID ||
				grant.Generation != record.Generation || grant.RuntimeRef != runtimeRef {
				return errors.New("missing-workload recovery stopped: deterministic Gateway grant identity does not match the signed fence")
			}
			if grant.Active {
				if err := s.secure.gateway.Deactivate(ctx, grantID); err != nil {
					return fmt.Errorf("missing-workload recovery could not prove Gateway grant deactivation: %w", err)
				}
			}
			if err := s.secure.gateway.Unregister(ctx, grantID); err != nil {
				return fmt.Errorf("missing-workload recovery could not remove Gateway grant: %w", err)
			}
		} else if !gatewayGrantNotFound(grantErr) {
			return fmt.Errorf("missing-workload recovery could not inspect Gateway grant: %w", grantErr)
		}

		relayName := RelayName(record.TenantID, record.InstanceID, record.Generation)
		relay, relayErr := s.secure.topology.InspectRelay(ctx, relayName)
		if relayErr == nil {
			if !relay.Managed || relay.Spec.Name != relayName || relay.Spec.TenantID != record.TenantID ||
				relay.Spec.InstanceID != record.InstanceID || relay.Spec.Generation != record.Generation || relay.Spec.GrantID != grantID {
				return errors.New("missing-workload recovery stopped: deterministic relay identity does not match the signed fence")
			}
			if !stoppedStatus(relay.Status) {
				if err := boundedDockerStop(ctx, s.docker, relayName); err != nil {
					return fmt.Errorf("missing-workload recovery could not stop the trusted relay: %w", err)
				}
			}
			if err := s.docker.Remove(ctx, relayName); err != nil && !errors.Is(err, ErrNotFound) {
				return fmt.Errorf("missing-workload recovery could not remove the trusted relay: %w", err)
			}
			if _, err := s.secure.topology.InspectRelay(ctx, relayName); !errors.Is(err, ErrNotFound) {
				return errors.New("missing-workload recovery could not prove trusted relay removal")
			}
		} else if !errors.Is(relayErr, ErrNotFound) {
			return fmt.Errorf("missing-workload recovery could not inspect the trusted relay: %w", relayErr)
		}

		networkName := NetworkName(record.TenantID, record.InstanceID, record.Generation)
		network, networkErr := s.secure.topology.InspectNetwork(ctx, networkName)
		if networkErr == nil {
			if !network.Managed || network.Name != networkName || network.TenantID != record.TenantID ||
				network.InstanceID != record.InstanceID || network.Generation != record.Generation {
				return errors.New("missing-workload recovery stopped: deterministic network identity does not match the signed fence")
			}
			if err := s.secure.topology.RemoveNetwork(ctx, networkName); err != nil && !errors.Is(err, ErrNotFound) {
				return fmt.Errorf("missing-workload recovery could not remove the isolated network: %w", err)
			}
			if _, err := s.secure.topology.InspectNetwork(ctx, networkName); !errors.Is(err, ErrNotFound) {
				return errors.New("missing-workload recovery could not prove isolated network removal")
			}
		} else if !errors.Is(networkErr, ErrNotFound) {
			return fmt.Errorf("missing-workload recovery could not inspect the isolated network: %w", networkErr)
		}
	}
	if _, err := s.docker.Inspect(ctx, runtimeRef); !errors.Is(err, ErrNotFound) {
		return errors.New("missing-workload recovery lost proof that the agent container is absent")
	}

	committed := prepared
	committed.Type, committed.Outcome, committed.ErrorCode = evidence.LifecycleDestroy, evidence.Committed, ""
	if _, err := s.secure.evidence.Append(committed); err != nil {
		return fmt.Errorf("missing workload was contained but its recovery receipt could not be persisted: %w", err)
	}
	record.Present = false
	policyEpoch := s.secure.fences.Fences(record.TenantID, record.InstanceID).PolicyEpoch
	if err := s.secure.fences.Commit(record, policyEpoch); err != nil {
		return fmt.Errorf("missing workload was contained but its tombstone could not be persisted: %w", err)
	}
	if err := s.secure.journal.Commit(opID); err != nil {
		return fmt.Errorf("missing workload was contained but recovery completion could not be persisted: %w", err)
	}
	s.reconcileMu.Lock()
	s.reconcileReport = ReconcileReport{Ready: true, Checked: reportCheckedAfterTombstone(s.reconcileReport.Checked)}
	s.reconcileMu.Unlock()
	return nil
}

func reportCheckedAfterTombstone(checked int) int {
	if checked > 0 {
		return checked - 1
	}
	return 0
}
