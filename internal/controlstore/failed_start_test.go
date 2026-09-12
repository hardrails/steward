package controlstore

import (
	"strings"
	"testing"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/controlprotocol"
)

func TestFailedStartCleanupChecksExactRetainedIdentity(t *testing.T) {
	for _, name := range []string{"unknown", "failed", "rejected", "done", "running intent", "renew", "stop", "destroy successor", "start successor", "missing cursor", "missing admission", "empty runtime", "admission generation", "missing command", "pending", "missing terminal", "wrong operation", "wrong runtime", "wrong physical runtime", "wrong generation", "wrong claim", "wrong tenant", "wrong node"} {
		t.Run(name, func(t *testing.T) {
			fixture := newRecordsFixture(t, DefaultLimits())
			ref := "executor-" + strings.Repeat("a", 64)
			deployment := Deployment{TenantID: "tenant-a", DesiredState: DeploymentAbsent}
			instance := DeploymentInstance{NodeID: "node-1", InstanceID: "instance-a", Generation: 2,
				CommandID: "start-a", CommandOperation: "start", Phase: DeploymentInstanceFailed,
				Admission: &controlprotocol.ExecutorAdmissionProjectionV1{RuntimeRef: ref, Generation: 2}}
			statement := admission.CommandStatement{Kind: "stop", RuntimeRef: ref, ClaimGeneration: 3}
			command := Command{CommandKind: "start", State: CommandTerminal, SignedRuntimeRef: ref,
				SignedInstanceGeneration: 2, SignedClaimGeneration: 3,
				Terminal: &TerminalReport{Report: controlprotocol.ExecutorReportV3{Status: controlprotocol.ExecutorStatusOutcomeUnknown}}}
			switch name {
			case "failed", "rejected", "done":
				command.Terminal.Report.Status = name
			case "running intent":
				deployment.DesiredState = DeploymentRunning
			case "renew", "stop":
				instance.CommandOperation, command.CommandKind = name, name
			case "destroy successor":
				statement.Kind = "destroy"
			case "start successor":
				statement.Kind = "start"
			case "missing cursor":
				instance.CommandID = ""
			case "missing admission":
				instance.Admission = nil
			case "empty runtime":
				instance.Admission.RuntimeRef = ""
			case "admission generation":
				instance.Admission.Generation++
			case "pending":
				command.State = CommandPending
			case "missing terminal":
				command.Terminal = nil
			case "wrong operation":
				command.CommandKind = "destroy"
			case "wrong runtime":
				statement.RuntimeRef = "executor-" + strings.Repeat("b", 64)
			case "wrong physical runtime":
				instance.Admission.RuntimeRef = "executor-" + strings.Repeat("b", 64)
			case "wrong generation":
				command.SignedInstanceGeneration++
			case "wrong claim":
				command.SignedClaimGeneration++
			case "wrong tenant":
				deployment.TenantID = "tenant-b"
			case "wrong node":
				instance.NodeID = "node-b"
			}
			fixture.store.mu.Lock()
			defer fixture.store.mu.Unlock()
			if name != "missing command" {
				fixture.store.current.commands[commandKey("tenant-a", "node-1", "start-a")] = command
			}
			allowed := fixture.store.failedStartCleanupAllowedLocked(deployment, instance, statement)
			if allowed != (name == "unknown" || name == "failed" || name == "rejected") {
				t.Fatalf("cleanup allowed = %v", allowed)
			}
			if replaced := fixture.store.cleanupPredecessorToReplaceLocked(deployment, instance, statement); replaced != nil {
				t.Fatalf("failed start evidence was reclaimed to make room: %+v", replaced)
			}
		})
	}
}
