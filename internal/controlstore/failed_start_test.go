package controlstore

import (
	"strings"
	"testing"
	"time"

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

func TestAgedFailedStartRetentionFollowsOutcomeAndCleanupCursor(t *testing.T) {
	for _, status := range []string{controlprotocol.ExecutorStatusRejected, controlprotocol.ExecutorStatusFailed, controlprotocol.ExecutorStatusOutcomeUnknown} {
		t.Run(status, func(t *testing.T) {
			fixture := newRecordsFixture(t, DefaultLimits())
			instance := DeploymentInstance{InstanceID: "instance-a", NodeID: "node-1",
				Phase: DeploymentInstanceFailed, CommandID: "start-a", CommandOperation: "start", CommandSequence: 1}
			deployment := Deployment{TenantID: "tenant-a", ID: "deployment-a", Instances: []DeploymentInstance{instance}}
			command := Command{TenantID: "tenant-a", NodeID: "node-1", ID: instance.CommandID,
				CommandKind: "start", State: CommandTerminal,
				Terminal: &TerminalReport{Report: controlprotocol.ExecutorReportV3{Status: status},
					CompletedAt: canonicalTimestamp(fixture.now.Add(-48 * time.Hour))}}
			fixture.store.mu.Lock()
			defer fixture.store.mu.Unlock()
			fixture.store.current.commands[commandKey(command.TenantID, command.NodeID, command.ID)] = command
			key := deploymentKey(deployment.TenantID, deployment.ID)
			for _, desired := range []DeploymentDesiredState{DeploymentRunning, DeploymentAbsent} {
				deployment.DesiredState = desired
				fixture.store.current.deployments[key] = deployment
				if prunable := fixture.store.prunableCommandsLocked("tenant-a", "node-1", fixture.now); len(prunable) != 0 {
					t.Fatalf("aged start lost before cleanup cursor advanced (%s): %+v", desired, prunable)
				}
			}
			deployment.Instances[0].CommandID = "cleanup-stop"
			deployment.Instances[0].CommandOperation = "stop"
			deployment.Instances[0].CommandSequence++
			deployment.Instances[0].Phase = DeploymentInstanceStopping
			fixture.store.current.deployments[key] = deployment
			prunable := fixture.store.prunableCommandsLocked("tenant-a", "node-1", fixture.now)
			if status == controlprotocol.ExecutorStatusRejected {
				if len(prunable) != 1 || prunable[0].ID != command.ID {
					t.Fatal("settled rejection did not return to ordinary retention after cursor advance")
				}
			} else if len(prunable) != 0 {
				t.Fatal("cleanup made an uncertain outcome prunable")
			}
		})
	}
}
