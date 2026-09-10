package controlreconcile

import (
	"context"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/controlstore"
)

func TestRejectedRenewalCleanupRequiresRemovalAndConfirmedLifecycle(t *testing.T) {
	for _, test := range []struct {
		name, status          string
		expired, stopRejected bool
	}{
		{name: "confirmed cleanup", status: controlprotocol.ExecutorStatusRejected},
		{name: "uncertain renewal", status: controlprotocol.ExecutorStatusOutcomeUnknown},
		{name: "expired authority", status: controlprotocol.ExecutorStatusRejected, expired: true},
		{name: "rejected stop", status: controlprotocol.ExecutorStatusRejected, stopRejected: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newControlReconcileFixture(t)
			applyControlDeployment(t, fixture, 1)
			reconciler := fixture.reconciler(t)
			assertReconcileCount(t, reconciler, "enqueue admit", 0, 1)
			completeDeploymentCommand(t, fixture, "admit", controlprotocol.ExecutorStatusDone)
			assertReconcileCount(t, reconciler, "observe admit", 1, 0)
			assertReconcileCount(t, reconciler, "enqueue initial renewal", 0, 1)
			completeDeploymentCommand(t, fixture, "renew", controlprotocol.ExecutorStatusDone)
			assertReconcileCount(t, reconciler, "observe initial renewal", 1, 0)
			assertReconcileCount(t, reconciler, "enqueue start", 0, 1)
			completeDeploymentCommand(t, fixture, "start", controlprotocol.ExecutorStatusDone)
			assertReconcileCount(t, reconciler, "observe start", 1, 0)
			fixture.now = fixture.now.Add(4 * time.Minute)
			heartbeatControlNode(t, fixture)
			assertReconcileCount(t, reconciler, "enqueue renewal", 0, 1)
			completeDeploymentCommand(t, fixture, "renew", test.status)
			assertReconcileCount(t, reconciler, "observe renewal", 1, 0)
			failed := getControlDeployment(t, fixture)
			if failed.Instances[0].Phase != controlstore.DeploymentInstanceFailed {
				t.Fatalf("renewal did not fail: %+v", failed)
			}
			// A rejected renewal must not become permission to restart or retry.
			assertReconcileCount(t, reconciler, "running intent remains failed", 0, 0)
			if _, _, err := fixture.store.SetDeploymentDesiredState(
				fixture.admin, failed.TenantID, failed.ID, failed.Revision,
				controlstore.DeploymentAbsent, fixture.now,
			); err != nil {
				t.Fatal(err)
			}
			if test.expired {
				fixture.now = fixture.now.Add(24 * time.Hour)
				heartbeatControlNode(t, fixture)
			}
			if test.status != controlprotocol.ExecutorStatusRejected || test.expired {
				report, err := reconciler.Reconcile(context.Background())
				if err != nil || report.Enqueued != 0 || report.Removed != 0 {
					t.Fatalf("uncertain renewal must remain fenced: %+v, %v", report, err)
				}
				return
			}
			assertReconcileCount(t, reconciler, "enqueue stop", 0, 1)
			stopping := getControlDeployment(t, fixture)
			if stopping.Instances[0].CommandSequence <= failed.Instances[0].CommandSequence ||
				stopping.Instances[0].Generation != failed.Instances[0].Generation ||
				stopping.Instances[0].LineageID != failed.Instances[0].LineageID ||
				stopping.Instances[0].Admission.RuntimeRef != failed.Instances[0].Admission.RuntimeRef {
				t.Fatalf("cleanup changed identity or failed to advance sequence: %+v", stopping)
			}
			// Reopen the durable store with the stop pending: no duplicate command.
			if err := fixture.store.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := controlstore.Open(fixture.dir, fixture.limits)
			if err != nil {
				t.Fatal(err)
			}
			fixture.store = reopened
			t.Cleanup(func() { _ = reopened.Close() })
			reconciler = fixture.reconciler(t)
			assertReconcileCount(t, reconciler, "pending stop after restart", 0, 0)
			if test.stopRejected {
				completeDeploymentCommand(t, fixture, "stop", controlprotocol.ExecutorStatusRejected)
				assertReconcileCount(t, reconciler, "observe rejected stop", 1, 0)
				assertReconcileCount(t, reconciler, "never retry rejected stop", 0, 0)
				return
			}
			completeDeploymentCommand(t, fixture, "stop", controlprotocol.ExecutorStatusDone)
			assertReconcileCount(t, reconciler, "observe stop", 1, 0)
			assertReconcileCount(t, reconciler, "enqueue destroy", 0, 1)
			assertReconcileCount(t, reconciler, "unconfirmed destroy", 0, 0)
			completeDeploymentCommand(t, fixture, "destroy", controlprotocol.ExecutorStatusDone)
			assertReconcileCount(t, reconciler, "observe absence", 1, 0)
			removed := getControlDeployment(t, fixture)
			if removed.Phase != controlstore.DeploymentRemoved {
				t.Fatalf("confirmed cleanup did not finish: %+v", removed)
			}
			oldCommand, found, err := fixture.store.GetCommand(fixture.admin, failed.TenantID,
				failed.Instances[0].NodeID, failed.Instances[0].CommandID)
			if err != nil || !found || oldCommand.Terminal == nil ||
				oldCommand.Terminal.Report.Status != controlprotocol.ExecutorStatusRejected {
				t.Fatalf("cleanup lost the rejected command history: %+v, %v", oldCommand, err)
			}
		})
	}
}

func TestFencedRenewalDoesNotStarveSiblingRemoval(t *testing.T) {
	for _, expired := range []bool{false, true} {
		name := "uncertain renewal"
		status := controlprotocol.ExecutorStatusOutcomeUnknown
		if expired {
			name, status = "expired authority", controlprotocol.ExecutorStatusRejected
		}
		t.Run(name, func(t *testing.T) {
			fixture := newControlReconcileFixture(t)
			fixture.additionalInstances = []admission.CommandDelegationInstance{{
				InstanceID: "research-1", LineageID: "research-lineage-1",
				MinInstanceGeneration: 1, MaxInstanceGeneration: 5,
			}}
			applyControlDeployment(t, fixture, 1)
			reconciler := fixture.reconciler(t)
			assertReconcileCount(t, reconciler, "enqueue first admit", 0, 1)
			completeDeploymentCommand(t, fixture, "admit", controlprotocol.ExecutorStatusDone)
			assertReconcileCount(t, reconciler, "observe first admit", 1, 0)
			assertReconcileCount(t, reconciler, "enqueue first renewal", 0, 1)
			completeDeploymentCommand(t, fixture, "renew", status)
			assertReconcileCount(t, reconciler, "observe failed renewal", 1, 0)
			failed := getControlDeployment(t, fixture)
			if _, _, err := fixture.store.SetDeploymentDesiredState(
				fixture.admin, failed.TenantID, failed.ID, failed.Revision,
				controlstore.DeploymentAbsent, fixture.now,
			); err != nil {
				t.Fatal(err)
			}
			if expired {
				fixture.now = fixture.now.Add(24 * time.Hour)
				heartbeatControlNode(t, fixture)
			}
			report, err := reconciler.Reconcile(context.Background())
			if err != nil || report.Enqueued != 0 || report.Removed != 1 || report.Conflicts != 0 {
				t.Fatalf("fenced instance starved its sibling: %+v, %v", report, err)
			}
			after := getControlDeployment(t, fixture)
			if after.Instances[0].Phase != controlstore.DeploymentInstanceFailed ||
				after.Instances[0].CommandID != failed.Instances[0].CommandID ||
				after.Instances[0].LastError != failed.Instances[0].LastError ||
				after.Instances[1].Phase != controlstore.DeploymentInstanceRemoved {
				t.Fatalf("sibling cleanup altered the failed instance: %+v", after)
			}
		})
	}
}
