package executor

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/evidence"
	"github.com/hardrails/steward/internal/gateway"
)

const (
	maxReconcileRecords  = 4096
	maxReconcileFailures = 64
	maxReconcileMessage  = 256
	minReconcileInterval = time.Second
	maxReconcileInterval = 24 * time.Hour
)

// ErrReconciliationIncomplete means at least one signed runtime could not be
// proven to match its fail-closed desired state. The bounded report identifies
// the affected runtime without expanding an untrusted backend error into an
// unbounded process or API response.
var ErrReconciliationIncomplete = errors.New("executor reconciliation is incomplete")

// ReconcileFailure is one bounded, non-secret readiness failure.
type ReconcileFailure struct {
	RuntimeRef string `json:"runtime_ref,omitempty"`
	Code       string `json:"code"`
	Message    string `json:"message"`
}

// ReconcileReport is the bounded result of one complete signed-runtime scan.
// Revoked counts present records whose policy is no longer current, whether or
// not they already satisfied the stopped state. Changed counts records for
// which this scan durably committed an actual lifecycle/control mutation.
type ReconcileReport struct {
	Ready           bool               `json:"ready"`
	Checked         int                `json:"checked"`
	Changed         int                `json:"changed"`
	Revoked         int                `json:"revoked"`
	Failures        []ReconcileFailure `json:"failures,omitempty"`
	DroppedFailures int                `json:"dropped_failures,omitempty"`
}

type reconcilePlan struct {
	record            admission.FenceRecord
	runtimeRef        string
	workload          Workload
	revoked           bool
	wantRunning       bool
	relayName         string
	grantID           string
	wantGrant         gateway.Grant
	routePolicyDigest string
	degraded          error
	containment       bool

	startRelay   bool
	stopRelay    bool
	stopAgent    bool
	register     bool
	activate     bool
	deactivate   bool
	actualChange bool
}

type reconcileError struct {
	code string
	err  error
}

func (e *reconcileError) Error() string { return e.err.Error() }
func (e *reconcileError) Unwrap() error { return e.err }

func reconciliationError(code, format string, args ...any) error {
	return &reconcileError{code: code, err: fmt.Errorf(format, args...)}
}

// Reconcile proves every present signed fence against exact Docker, state,
// network, relay and gateway observations. It serializes with all other host
// mutations. Missing or drifted runtime objects are reported, never adopted or
// recreated. A pending journal blocks the scan because its external result is
// already ambiguous and must be resolved by an operator-specific recovery.
func (s *Server) Reconcile(ctx context.Context) (ReconcileReport, error) {
	report := ReconcileReport{}
	s.provisionMu.Lock()
	defer s.provisionMu.Unlock()
	// Publish the result before releasing provisionMu. A mutation waiting behind
	// this scan must never observe the previous ready result after this scan has
	// already found ambiguity.
	defer func() {
		s.reconcileMu.Lock()
		s.reconcileAttempted = true
		s.reconcileAt = time.Now().UTC()
		s.reconcileReport = cloneReconcileReport(report)
		s.reconcileMu.Unlock()
	}()
	if ctx == nil {
		report.addFailure("", "invalid_context", "reconciliation requires a context")
		return report, ErrReconciliationIncomplete
	}
	if s.secure == nil {
		report.addFailure("", "secure_admission_unavailable", "signed admission is not configured")
		return report, ErrReconciliationIncomplete
	}

	if len(s.secure.journal.Pending()) != 0 {
		report.addFailure("", "journal_pending", "a prior host mutation requires explicit recovery")
		return report, ErrReconciliationIncomplete
	}

	records := s.secure.fences.Records()
	present := records[:0]
	for _, record := range records {
		if record.Present {
			present = append(present, record)
		}
	}
	sort.Slice(present, func(i, j int) bool {
		if present[i].TenantID != present[j].TenantID {
			return present[i].TenantID < present[j].TenantID
		}
		if present[i].InstanceID != present[j].InstanceID {
			return present[i].InstanceID < present[j].InstanceID
		}
		return present[i].Generation < present[j].Generation
	})
	if len(present) > maxReconcileRecords {
		report.addFailure("", "record_limit", "present admission records exceed the bounded reconciliation limit")
		return report, ErrReconciliationIncomplete
	}
	report.Checked = len(present)

	plans := make([]reconcilePlan, 0, len(present))
	scanDegraded := false
	for _, record := range present {
		if err := ctx.Err(); err != nil {
			report.addFailure(RuntimeRef(record.TenantID, record.InstanceID), "context_done", err.Error())
			scanDegraded = true
			break
		}
		plan, err := s.planReconciliation(ctx, record)
		if err != nil {
			report.addError(RuntimeRef(record.TenantID, record.InstanceID), err)
			scanDegraded = true
			continue
		}
		if plan.revoked {
			report.Revoked++
		}
		if plan.degraded != nil {
			scanDegraded = true
		}
		plans = append(plans, plan)
	}

	for _, plan := range plans {
		// A scan that found any ambiguity may only narrow authority. Repairs
		// that start a relay, register a grant, or activate a grant wait until a
		// later complete scan proves the whole signed host state coherent.
		if scanDegraded && !plan.containment && !plan.revoked {
			continue
		}
		if !plan.actualChange {
			if plan.degraded != nil {
				report.addError(plan.runtimeRef, plan.degraded)
			}
			continue
		}
		if err := s.applyReconciliation(ctx, plan); err != nil {
			report.addError(plan.runtimeRef, err)
			// Any error after a prepared external mutation intentionally leaves
			// the journal pending. Further changes must not cross that ambiguity.
			if len(s.secure.journal.Pending()) != 0 {
				break
			}
			continue
		}
		report.Changed++
		if plan.degraded != nil {
			report.addError(plan.runtimeRef, plan.degraded)
		}
	}

	report.Ready = len(report.Failures) == 0 && report.DroppedFailures == 0 && len(s.secure.journal.Pending()) == 0
	if !report.Ready {
		return report, ErrReconciliationIncomplete
	}
	return report, nil
}

func cloneReconcileReport(report ReconcileReport) ReconcileReport {
	report.Failures = append([]ReconcileFailure(nil), report.Failures...)
	return report
}

// RunReconciler periodically reconciles until ctx is cancelled. Individual
// failed scans are logged and retried; an invalid interval is a startup error.
// The executable calls Reconcile once before opening its listener or uplink so
// the first served request sees either ready state or the degraded mutation gate.
func (s *Server) RunReconciler(ctx context.Context, interval time.Duration) error {
	if ctx == nil {
		return errors.New("reconciler requires a context")
	}
	if interval < minReconcileInterval || interval > maxReconcileInterval {
		return fmt.Errorf("reconcile interval must be between %s and %s", minReconcileInterval, maxReconcileInterval)
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			report, err := s.Reconcile(ctx)
			if err != nil {
				s.logger.Error("executor reconciliation incomplete",
					"checked", report.Checked, "changed", report.Changed,
					"revoked", report.Revoked, "failures", len(report.Failures)+report.DroppedFailures)
				continue
			}
			s.logger.Debug("executor reconciliation complete", "checked", report.Checked, "changed", report.Changed, "revoked", report.Revoked)
		}
	}
}

func (s *Server) planReconciliation(ctx context.Context, record admission.FenceRecord) (reconcilePlan, error) {
	plan := reconcilePlan{
		record: record, runtimeRef: RuntimeRef(record.TenantID, record.InstanceID),
		grantID:           gateway.GrantID(record.TenantID, record.InstanceID, record.Generation),
		routePolicyDigest: record.RoutePolicyDigest,
	}
	observed, err := s.docker.Inspect(ctx, plan.runtimeRef)
	if errors.Is(err, ErrNotFound) {
		return plan, reconciliationError("workload_missing", "present signed workload is missing")
	}
	if err != nil {
		return plan, reconciliationError("workload_inspect", "inspect signed workload: %v", err)
	}
	if !observed.Managed || !observed.Hardened {
		return plan, reconciliationError("workload_drift", "signed workload is not exactly managed and hardened")
	}
	if observed.Workload.TenantID != record.TenantID || observed.Workload.InstanceID != record.InstanceID ||
		observed.Fingerprint != strings.TrimPrefix(record.WorkloadDigest, "sha256:") ||
		observed.Fingerprint != workloadFingerprint(observed.Workload) ||
		observed.ImageID != record.ImageConfigDigest || observed.Workload.ImageConfigDigest != record.ImageConfigDigest {
		return plan, reconciliationError("workload_identity_drift", "signed workload tuple, fingerprint, or image config does not match its fence")
	}
	plan.workload = observed.Workload
	plan.revoked = record.PolicyDigest != dsse.Digest(s.secure.policyEnvelope)
	if plan.revoked {
		plan.stopAgent = !stoppedStatus(observed.Status)
	} else {
		var ok bool
		plan.wantRunning, ok = desiredStatus(observed.Status)
		if !ok {
			return s.containReconciliation(ctx, plan, observed, "workload_state_ambiguous", "signed workload has an ambiguous Docker lifecycle state")
		}
	}

	if observed.Workload.State != nil {
		stateDocker, ok := s.docker.(StateDocker)
		if !ok {
			return s.containReconciliation(ctx, plan, observed, "state_unavailable", "persistent state inspection is unavailable")
		}
		want := StateVolumeSpec{
			Name: StateVolumeName(record.TenantID, record.LineageID), TenantID: record.TenantID, LineageID: record.LineageID,
		}
		if observed.Workload.State.VolumeName != want.Name {
			return s.containReconciliation(ctx, plan, observed, "state_drift", "workload state mount does not match its signed lineage")
		}
		state, err := stateDocker.InspectStateVolume(ctx, want.Name)
		if err != nil || !stateVolumeEqual(state, want) {
			return s.containReconciliation(ctx, plan, observed, "state_drift", "persistent state volume is missing or drifted")
		}
	}

	if observed.Workload.Runtime == nil {
		plan.actualChange = plan.stopAgent
		return plan, nil
	}
	if s.secure.topology == nil || s.secure.gateway == nil {
		return s.containReconciliation(ctx, plan, observed, "topology_unavailable", "signed runtime topology inspection is unavailable")
	}
	runtime := observed.Workload.Runtime
	wantNetwork := NetworkSpecFor(record.TenantID, record.InstanceID, record.Generation)
	if runtime.Generation != record.Generation || runtime.NetworkName != wantNetwork.Name ||
		runtime.GrantID != plan.grantID ||
		!runtimeAllocationMatches(wantNetwork, runtime.Subnet, runtime.Gateway, runtime.RelayIP, runtime.AgentIP) {
		return s.containReconciliation(ctx, plan, observed, "topology_identity_drift", "runtime topology is not derived from the signed tenant, instance, and generation")
	}
	network, err := s.secure.topology.InspectNetwork(ctx, wantNetwork.Name)
	if err != nil || !networkEqual(network, wantNetwork) || network.Subnet != runtime.Subnet || network.Gateway != runtime.Gateway ||
		network.RelayIP != runtime.RelayIP || network.AgentIP != runtime.AgentIP {
		return s.containReconciliation(ctx, plan, observed, "network_drift", "isolated runtime network is missing or drifted")
	}
	plan.relayName = RelayName(record.TenantID, record.InstanceID, record.Generation)
	relay, err := s.secure.topology.InspectRelay(ctx, plan.relayName)
	if err != nil || !relayEqual(relay, s.desiredRelay(observed.Workload)) {
		return s.containReconciliation(ctx, plan, observed, "relay_drift", "trusted relay is missing or drifted")
	}

	inspection, grantErr := s.secure.gateway.InspectWithPolicy(ctx, runtime.GrantID)
	grant := inspection.Grant
	policyBearingGrant := runtime.Inference || len(runtime.EgressRouteIDs) != 0
	if !plan.revoked && policyBearingGrant && !imageConfigDigest.MatchString(record.RoutePolicyDigest) {
		return s.containReconciliation(ctx, plan, observed, "gateway_drift", "committed admission fence has no valid gateway route policy binding")
	}
	if !plan.revoked && !policyBearingGrant && record.RoutePolicyDigest != "" {
		return s.containReconciliation(ctx, plan, observed, "gateway_drift", "committed admission fence has an unexpected gateway route policy binding")
	}
	if !plan.revoked && grantErr == nil && policyBearingGrant && inspection.RoutePolicyDigest != record.RoutePolicyDigest {
		return s.containReconciliation(ctx, plan, observed, "gateway_drift", "gateway route policy does not match the committed admission fence")
	}
	grantMissing := gatewayGrantNotFound(grantErr)
	if grantErr != nil && !grantMissing {
		if !plan.revoked {
			return s.containReconciliation(ctx, plan, observed, "gateway_inspect", fmt.Sprintf("inspect gateway grant: %v", grantErr))
		}
		// Policy revocation is best-effort fail closed even while gateway
		// inspection is unavailable. Journal an explicit deactivation attempt,
		// then stop the local agent and relay regardless of its result. The
		// operation remains pending until gateway state can be proven.
		plan.deactivate = true
	}
	serviceURL := ""
	if runtime.ServicePort > 0 && (plan.wantRunning || grantErr == nil && grant.ServiceURL != "") {
		serviceURL = gateway.ServiceSocketURL(s.secure.grantRoot, runtime.GrantID)
	}
	plan.wantGrant = s.desiredGatewayGrant(observed.Workload, serviceURL)
	if grantErr == nil && !plan.revoked {
		want := plan.wantGrant
		want.Active = grant.Active
		if !gateway.GrantsEqual(grant, want) {
			return s.containReconciliation(ctx, plan, observed, "gateway_drift", "gateway grant identity or capability policy has drifted")
		}
	}

	if plan.revoked {
		plan.deactivate = plan.deactivate || grantErr == nil && grant.Active
		plan.stopRelay = !stoppedStatus(relay.Status)
		plan.actualChange = plan.deactivate || plan.stopAgent || plan.stopRelay
		return plan, nil
	}

	relayRunning, relayStateKnown := desiredStatus(relay.Status)
	if !relayStateKnown {
		// The relay identity was proven exact above, so a bounded stop is an
		// authorized fail-closed containment action. Never treat an unknown
		// Docker status as already stopped.
		plan.stopRelay = true
		return s.containReconciliation(ctx, plan, observed, "relay_state_ambiguous", "trusted relay has an ambiguous Docker lifecycle state")
	}
	if plan.wantRunning {
		plan.startRelay = !relayRunning
		plan.register = grantMissing
		plan.activate = grantMissing || !grant.Active
	} else {
		plan.deactivate = !grantMissing && grant.Active
		plan.stopRelay = relayRunning
		plan.register = grantMissing
	}
	plan.actualChange = plan.startRelay || plan.stopRelay || plan.register || plan.activate || plan.deactivate
	return plan, nil
}

// containReconciliation turns proven isolation drift into a narrow fail-closed
// mutation. The agent container was already proven to be the exact signed,
// hardened object before this helper is called, so stopping it is safe. Drifted
// networks, volumes, and relays are never adopted, recreated, or removed. The
// deterministic gateway grant is deactivated when it is active (or when its
// state cannot be observed), preventing a compromised relay from retaining
// inference, service, or egress authority.
func (s *Server) containReconciliation(ctx context.Context, plan reconcilePlan, observed ObservedWorkload, code, message string) (reconcilePlan, error) {
	plan.containment = true
	plan.degraded = reconciliationError(code, "%s", message)
	plan.stopAgent = !stoppedStatus(observed.Status)
	if observed.Workload.Runtime != nil && s.secure.gateway != nil {
		inspection, err := s.secure.gateway.InspectWithPolicy(ctx, plan.grantID)
		if err == nil {
			plan.deactivate = inspection.Grant.Active
		} else if !gatewayGrantNotFound(err) {
			// An unavailable or malformed control response cannot prove the
			// grant inactive. Attempt deactivation and leave the journal pending
			// if its outcome remains ambiguous.
			plan.deactivate = true
		}
	}
	if observed.Workload.Runtime != nil && s.secure.topology != nil && runtimeIdentityMatchesRecord(observed.Workload, plan.record) {
		plan.relayName = RelayName(plan.record.TenantID, plan.record.InstanceID, plan.record.Generation)
		relay, err := s.secure.topology.InspectRelay(ctx, plan.relayName)
		if err == nil && relayContainmentIdentity(relay, s.desiredRelay(observed.Workload)) {
			plan.stopRelay = !stoppedStatus(relay.Status)
		}
	}
	plan.actualChange = plan.deactivate || plan.stopAgent || plan.stopRelay
	return plan, nil
}

func (s *Server) applyReconciliation(ctx context.Context, plan reconcilePlan) error {
	action := "control_repair"
	if plan.containment {
		action = "isolation_containment"
	}
	if plan.revoked {
		action = "policy_revocation"
	}
	opID, err := newOperationID("reconcile-"+plan.runtimeRef, plan.record.Generation)
	if err != nil {
		return reconciliationError("operation_identity", "create reconciliation operation identity: %v", err)
	}
	if _, err := s.secure.journal.Prepare(opID, action+":"+plan.runtimeRef, plan.record.Generation); err != nil {
		return reconciliationError("journal_unavailable", "prepare reconciliation journal: %v", err)
	}
	prepared := evidence.Event{
		Type: evidence.JournalPrepare, TenantID: plan.record.TenantID, RuntimeRef: plan.runtimeRef,
		CapsuleDigest: plan.record.CapsuleDigest, PolicyDigest: plan.record.PolicyDigest,
		Generation: plan.record.Generation, GrantID: "workload", Outcome: evidence.Allowed, ErrorCode: action,
	}
	if _, err := s.secure.evidence.Append(prepared); err != nil {
		_ = s.secure.journal.Compensate(opID)
		return reconciliationError("evidence_unavailable", "append reconciliation prepare receipt: %v", err)
	}

	// Every call below may have committed despite a lost response. Any error
	// therefore leaves the prepared journal entry intact for explicit recovery.
	if plan.revoked || plan.containment {
		var mutationErrors []error
		if plan.deactivate {
			if err := s.secure.gateway.Deactivate(ctx, plan.grantID); err != nil {
				mutationErrors = append(mutationErrors, fmt.Errorf("deactivate revoked gateway grant: %w", err))
			}
		}
		if plan.stopAgent {
			if err := s.stopWorkloadAndConfirm(ctx, plan.runtimeRef, plan.workload); err != nil {
				mutationErrors = append(mutationErrors, fmt.Errorf("stop revoked workload: %w", err))
			}
		}
		if plan.stopRelay {
			stopRelay := s.stopRelayAndConfirm
			if plan.containment {
				stopRelay = s.stopRelayForContainmentAndConfirm
			}
			if err := stopRelay(ctx, plan.relayName, s.desiredRelay(plan.workload)); err != nil {
				mutationErrors = append(mutationErrors, fmt.Errorf("stop revoked trusted relay: %w", err))
			}
		}
		if err := errors.Join(mutationErrors...); err != nil {
			code, operation := "revocation_ambiguous", "revoke runtime"
			if plan.containment && !plan.revoked {
				code, operation = "containment_ambiguous", "contain runtime"
			}
			return reconciliationError(code, "%s: %v", operation, err)
		}
	} else if plan.wantRunning {
		if plan.startRelay {
			if err := s.docker.Start(ctx, plan.relayName); err != nil {
				return reconciliationError("repair_ambiguous", "start trusted relay: %v", err)
			}
		}
		if plan.register {
			if err := s.secure.gateway.Register(ctx, plan.wantGrant); err != nil {
				return reconciliationError("repair_ambiguous", "restore gateway grant: %v", err)
			}
			if !s.gatewayRoutePolicyMatches(ctx, plan.workload, plan.record.RoutePolicyDigest) {
				_ = s.secure.gateway.Unregister(ctx, plan.workload.Runtime.GrantID)
				return reconciliationError("repair_ambiguous", "restored gateway grant does not match the committed route policy")
			}
		}
		if plan.activate {
			if err := s.secure.gateway.Activate(ctx, plan.workload.Runtime.GrantID); err != nil {
				return reconciliationError("repair_ambiguous", "activate gateway grant: %v", err)
			}
		}
	} else {
		if plan.deactivate {
			if err := s.secure.gateway.Deactivate(ctx, plan.workload.Runtime.GrantID); err != nil {
				return reconciliationError("repair_ambiguous", "deactivate gateway grant: %v", err)
			}
		}
		if plan.stopRelay {
			if err := s.stopRelayAndConfirm(ctx, plan.relayName, s.desiredRelay(plan.workload)); err != nil {
				return reconciliationError("repair_ambiguous", "stop trusted relay: %v", err)
			}
		}
		if plan.register {
			if err := s.secure.gateway.Register(ctx, plan.wantGrant); err != nil {
				return reconciliationError("repair_ambiguous", "restore inactive gateway grant: %v", err)
			}
			if !s.gatewayRoutePolicyMatches(ctx, plan.workload, plan.record.RoutePolicyDigest) {
				_ = s.secure.gateway.Unregister(ctx, plan.workload.Runtime.GrantID)
				return reconciliationError("repair_ambiguous", "restored gateway grant does not match the committed route policy")
			}
		}
	}

	settledRoutePolicyDigest := ""
	if plan.containment {
		if err := s.verifyReconciliationContainment(ctx, plan); err != nil {
			return reconciliationError("verification_ambiguous", "verify contained runtime: %v", err)
		}
		settledRoutePolicyDigest = plan.routePolicyDigest
	} else {
		settled, err := s.planReconciliation(ctx, plan.record)
		if err != nil || settled.actualChange {
			if err == nil {
				err = errors.New("reconciled runtime still requires mutation")
			}
			return reconciliationError("verification_ambiguous", "verify reconciled runtime: %v", err)
		}
		settledRoutePolicyDigest = settled.routePolicyDigest
	}
	committed := prepared
	committed.ErrorCode = ""
	committed.Outcome = evidence.Committed
	if plan.revoked {
		committed.Type = evidence.Revocation
	} else {
		committed.Type = evidence.Drift
	}
	committed.MetadataHash = settledRoutePolicyDigest
	if _, err := s.secure.evidence.Append(committed); err != nil {
		return reconciliationError("evidence_ambiguous", "append reconciliation commit receipt: %v", err)
	}
	if err := s.secure.journal.Commit(opID); err != nil {
		return reconciliationError("journal_ambiguous", "commit reconciliation journal: %v", err)
	}
	return nil
}

func (s *Server) verifyReconciliationContainment(ctx context.Context, plan reconcilePlan) error {
	observed, err := s.docker.Inspect(ctx, plan.runtimeRef)
	if err != nil {
		return fmt.Errorf("inspect contained workload: %w", err)
	}
	if !observed.Managed || !observed.Hardened || observed.Workload.TenantID != plan.record.TenantID ||
		observed.Workload.InstanceID != plan.record.InstanceID || observed.Fingerprint != strings.TrimPrefix(plan.record.WorkloadDigest, "sha256:") ||
		observed.Fingerprint != workloadFingerprint(observed.Workload) || observed.ImageID != plan.record.ImageConfigDigest ||
		observed.Workload.ImageConfigDigest != plan.record.ImageConfigDigest || !stoppedStatus(observed.Status) {
		return errors.New("contained workload identity or stopped state is not exact")
	}
	if plan.stopRelay {
		relay, err := s.secure.topology.InspectRelay(ctx, plan.relayName)
		if err != nil {
			return fmt.Errorf("inspect contained trusted relay: %w", err)
		}
		if !relayContainmentIdentity(relay, s.desiredRelay(plan.workload)) || !stoppedStatus(relay.Status) {
			return errors.New("contained trusted relay identity or stopped state is not exact")
		}
	}
	if plan.deactivate && observed.Workload.Runtime != nil && s.secure.gateway != nil {
		inspection, err := s.secure.gateway.InspectWithPolicy(ctx, plan.grantID)
		if gatewayGrantNotFound(err) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("inspect contained gateway grant: %w", err)
		}
		if inspection.Grant.Active {
			return errors.New("contained gateway grant remains active")
		}
	}
	return nil
}

func desiredStatus(status string) (running bool, known bool) {
	switch classifyDockerLifecycle(status) {
	case dockerLifecycleRunning:
		return true, true
	case dockerLifecycleStopped:
		return false, true
	default:
		return false, false
	}
}

func stoppedStatus(status string) bool {
	running, known := desiredStatus(status)
	return known && !running
}

// ControlClient currently exposes the gateway's closed JSON error code through
// its error text. Match the exact code prefix, never a generic "not found", so
// transport and decode failures cannot be mistaken for safe absence.
func gatewayGrantNotFound(err error) bool {
	return err != nil && strings.HasPrefix(err.Error(), "gateway grant_not_found:")
}

func (r *ReconcileReport) addError(runtimeRef string, err error) {
	var reconcileErr *reconcileError
	if errors.As(err, &reconcileErr) {
		r.addFailure(runtimeRef, reconcileErr.code, reconcileErr.Error())
		return
	}
	r.addFailure(runtimeRef, "reconciliation_failed", err.Error())
}

func (r *ReconcileReport) addFailure(runtimeRef, code, message string) {
	if len(r.Failures) >= maxReconcileFailures {
		r.DroppedFailures++
		return
	}
	if len(message) > maxReconcileMessage {
		message = message[:maxReconcileMessage]
		for !utf8.ValidString(message) {
			message = message[:len(message)-1]
		}
	}
	message = strings.Map(func(char rune) rune {
		if char < ' ' || char == '\u007f' {
			return ' '
		}
		return char
	}, message)
	r.Failures = append(r.Failures, ReconcileFailure{RuntimeRef: runtimeRef, Code: code, Message: message})
}
