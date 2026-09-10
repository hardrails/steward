package controlstore

import (
	"strings"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/controlprotocol"
)

func TestRejectedRenewalCleanupChecksRetainedIdentityAndOutcome(t *testing.T) {
	for _, name := range []string{
		"valid", "running", "start failure", "destroy requested", "missing cursor", "missing admission",
		"empty runtime", "wrong target", "admission generation", "missing command", "wrong operation",
		"pending", "missing terminal", "failed", "unknown", "done", "wrong runtime", "wrong generation", "wrong claim",
		"inconsistent physical projection", "malformed signed reference",
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newRecordsFixture(t, DefaultLimits())
			runtimeRef := "executor-" + strings.Repeat("a", 64)
			deployment := Deployment{TenantID: "tenant-a", DesiredState: DeploymentAbsent}
			instance := DeploymentInstance{
				NodeID: "node-1", InstanceID: "instance-a", Generation: 2,
				CommandID: "renew-a", CommandOperation: "renew", Phase: DeploymentInstanceFailed,
				Admission: &controlprotocol.ExecutorAdmissionProjectionV1{RuntimeRef: runtimeRef, Generation: 2},
			}
			statement := admission.CommandStatement{Kind: "stop", RuntimeRef: runtimeRef, ClaimGeneration: 3}
			command := Command{
				CommandKind: "renew", State: CommandTerminal, SignedRuntimeRef: runtimeRef,
				SignedInstanceGeneration: 2, SignedClaimGeneration: 3,
			}
			command.Terminal = &TerminalReport{}
			command.Terminal.Report.Status = controlprotocol.ExecutorStatusRejected
			switch name {
			case "running":
				deployment.DesiredState = DeploymentRunning
			case "start failure":
				instance.CommandOperation = "start"
			case "destroy requested":
				statement.Kind = "destroy"
			case "missing cursor":
				instance.CommandID = ""
			case "missing admission":
				instance.Admission = nil
			case "empty runtime":
				instance.Admission.RuntimeRef = ""
			case "wrong target":
				statement.RuntimeRef = "runtime-b"
			case "admission generation":
				instance.Admission.Generation++
			case "wrong operation":
				command.CommandKind = "destroy"
			case "pending":
				command.State = CommandPending
			case "missing terminal":
				command.Terminal = nil
			case "failed":
				command.Terminal.Report.Status = controlprotocol.ExecutorStatusFailed
			case "unknown":
				command.Terminal.Report.Status = controlprotocol.ExecutorStatusOutcomeUnknown
			case "done":
				command.Terminal.Report.Status = controlprotocol.ExecutorStatusDone
			case "wrong runtime":
				command.SignedRuntimeRef = "runtime-b"
			case "wrong generation":
				command.SignedInstanceGeneration++
			case "wrong claim":
				command.SignedClaimGeneration++
			case "inconsistent physical projection":
				instance.Admission.RuntimeRef = "executor-" + strings.Repeat("b", 64)
			case "malformed signed reference":
				command.SignedRuntimeRef, statement.RuntimeRef = "uplink:invalid", "uplink:invalid"
			}
			fixture.store.mu.Lock()
			if name != "missing command" {
				fixture.store.current.commands[commandKey("tenant-a", "node-1", "renew-a")] = command
			}
			allowed := fixture.store.rejectedRenewalCleanupAllowedLocked(deployment, instance, statement)
			fixture.store.mu.Unlock()
			if allowed != (name == "valid") {
				t.Fatalf("cleanup allowed = %v", allowed)
			}
		})
	}
}

func TestRejectedRenewalPruningProtectionEndsOnlyWhenCleanupCursorAdvances(t *testing.T) {
	fixture := newRecordsFixture(t, DefaultLimits())
	instance := DeploymentInstance{
		InstanceID: "instance-a", NodeID: "node-1", Phase: DeploymentInstanceFailed,
		CommandID: "renew-rejected", CommandOperation: "renew", CommandSequence: 1,
	}
	deployment := Deployment{
		TenantID: "tenant-a", ID: "deployment-a", DesiredState: DeploymentRunning,
		Instances: []DeploymentInstance{instance},
	}
	command := Command{
		TenantID: "tenant-a", NodeID: "node-1", ID: instance.CommandID,
		CommandKind: "renew", State: CommandTerminal,
		Terminal: &TerminalReport{
			Report:      controlprotocol.ExecutorReportV3{Status: controlprotocol.ExecutorStatusRejected},
			CompletedAt: canonicalTimestamp(fixture.now.Add(-48 * time.Hour)),
		},
	}
	fixture.store.mu.Lock()
	defer fixture.store.mu.Unlock()
	key := deploymentKey(deployment.TenantID, deployment.ID)
	fixture.store.current.commands[commandKey(command.TenantID, command.NodeID, command.ID)] = command
	for _, desired := range []DeploymentDesiredState{DeploymentRunning, DeploymentAbsent} {
		deployment.DesiredState = desired
		fixture.store.current.deployments[key] = deployment
		if prunable := fixture.store.prunableCommandsLocked("tenant-a", "node-1", fixture.now); len(prunable) != 0 {
			t.Fatalf("aged failed-renewal cursor was reclaimed before cleanup (%s): %+v", desired, prunable)
		}
	}
	// A new stop replaces the active cursor without permanently pinning the
	// rejected renewal. Normal settled-command retention can reclaim it then.
	deployment.Instances[0].CommandID = "cleanup-stop"
	deployment.Instances[0].CommandOperation = "stop"
	deployment.Instances[0].Phase = DeploymentInstanceStopping
	deployment.Instances[0].CommandSequence++
	fixture.store.current.deployments[key] = deployment
	prunable := fixture.store.prunableCommandsLocked("tenant-a", "node-1", fixture.now)
	if len(prunable) != 1 || prunable[0].ID != command.ID {
		t.Fatalf("advanced cleanup cursor retained stale renewal indefinitely: %+v", prunable)
	}
}
