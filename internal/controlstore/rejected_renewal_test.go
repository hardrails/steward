package controlstore

import (
	"testing"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/controlprotocol"
)

func TestRejectedRenewalCleanupChecksRetainedIdentityAndOutcome(t *testing.T) {
	for _, name := range []string{
		"valid", "running", "start failure", "destroy requested", "missing cursor", "missing admission",
		"empty runtime", "wrong target", "admission generation", "missing command", "wrong operation",
		"pending", "missing terminal", "failed", "unknown", "done", "wrong runtime", "wrong generation", "wrong claim",
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newRecordsFixture(t, DefaultLimits())
			deployment := Deployment{TenantID: "tenant-a", DesiredState: DeploymentAbsent}
			instance := DeploymentInstance{
				NodeID: "node-1", InstanceID: "instance-a", Generation: 2,
				CommandID: "renew-a", CommandOperation: "renew", Phase: DeploymentInstanceFailed,
				Admission: &controlprotocol.ExecutorAdmissionProjectionV1{RuntimeRef: "runtime-a", Generation: 2},
			}
			statement := admission.CommandStatement{Kind: "stop", RuntimeRef: "runtime-a", ClaimGeneration: 3}
			command := Command{
				CommandKind: "renew", State: CommandTerminal, SignedRuntimeRef: "runtime-a",
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
