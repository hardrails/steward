package controlreconcile

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/controlstore"
)

func TestFailedStartRemovalRequiresConfirmedStopAndDestroy(t *testing.T) {
	for _, outcome := range []string{controlprotocol.ExecutorStatusFailed, controlprotocol.ExecutorStatusOutcomeUnknown, controlprotocol.ExecutorStatusRejected} {
		t.Run(outcome, func(t *testing.T) {
			fixture := newControlReconcileFixture(t)
			applyControlDeployment(t, fixture, 1)
			reconciler := fixture.reconciler(t)
			for _, operation := range []string{"admit", "renew"} {
				assertReconcileCount(t, reconciler, "enqueue "+operation, 0, 1)
				completeDeploymentCommand(t, fixture, operation, controlprotocol.ExecutorStatusDone)
				assertReconcileCount(t, reconciler, "observe "+operation, 1, 0)
			}
			assertReconcileCount(t, reconciler, "enqueue start", 0, 1)
			completeDeploymentCommand(t, fixture, "start", outcome)
			assertReconcileCount(t, reconciler, "observe failed start", 1, 0)
			failed := getControlDeployment(t, fixture)
			assertReconcileCount(t, reconciler, "never retry start", 0, 0)
			if _, _, err := fixture.store.SetDeploymentDesiredState(fixture.admin, failed.TenantID,
				failed.ID, failed.Revision, controlstore.DeploymentAbsent, fixture.now); err != nil {
				t.Fatal(err)
			}
			assertReconcileCount(t, reconciler, "enqueue cleanup stop", 0, 1)
			stopping := getControlDeployment(t, fixture)
			before, after := failed.Instances[0], stopping.Instances[0]
			if after.Generation != before.Generation || after.LineageID != before.LineageID ||
				after.Admission.RuntimeRef != before.Admission.RuntimeRef || after.CommandSequence <= before.CommandSequence {
				t.Fatal("cleanup changed identity or did not advance the signed sequence")
			}
			for _, operation := range []string{"stop", "destroy"} {
				assertReconcileCount(t, reconciler, "unconfirmed "+operation, 0, 0)
				completeDeploymentCommand(t, fixture, operation, controlprotocol.ExecutorStatusDone)
				assertReconcileCount(t, reconciler, "observe "+operation, 1, 0)
				if operation == "stop" {
					assertReconcileCount(t, reconciler, "enqueue destroy", 0, 1)
				}
			}
			if getControlDeployment(t, fixture).Phase != controlstore.DeploymentRemoved {
				t.Fatal("confirmed cleanup did not finish")
			}
			retained, found, err := fixture.store.GetCommand(fixture.admin, failed.TenantID, before.NodeID, before.CommandID)
			if err != nil || !found || retained.Terminal == nil || retained.Terminal.Report.Status != outcome {
				t.Fatal("cleanup lost or rewrote the failed start outcome")
			}
		})
	}
}

func TestFailedStartCleanupRemainsFencedWithoutAuthorityOrConfirmedStop(t *testing.T) {
	for _, boundary := range []string{"expired authority", "full capacity", "failed stop", "unknown stop"} {
		t.Run(boundary, func(t *testing.T) {
			fixture := newControlReconcileFixture(t)
			applyControlDeployment(t, fixture, 1)
			reconciler := fixture.reconciler(t)
			for _, operation := range []string{"admit", "renew", "start"} {
				assertReconcileCount(t, reconciler, "enqueue "+operation, 0, 1)
				status := controlprotocol.ExecutorStatusDone
				if operation == "start" {
					status = controlprotocol.ExecutorStatusOutcomeUnknown
				}
				completeDeploymentCommand(t, fixture, operation, status)
				assertReconcileCount(t, reconciler, "observe "+operation, 1, 0)
			}
			failed := getControlDeployment(t, fixture)
			if _, _, err := fixture.store.SetDeploymentDesiredState(fixture.admin, failed.TenantID,
				failed.ID, failed.Revision, controlstore.DeploymentAbsent, fixture.now); err != nil {
				t.Fatal(err)
			}
			if boundary == "expired authority" {
				fixture.now = fixture.now.Add(24 * time.Hour)
				heartbeatControlNode(t, fixture)
				assertReconcileCount(t, reconciler, "expired authority cannot stop", 0, 0)
				return
			}
			if boundary == "full capacity" {
				status, err := fixture.store.Status()
				if err != nil {
					t.Fatal(err)
				}
				fixture.limits.MaxCommands = status.Commands
				fixture.limits.MaxCommandsPerTenant = status.Commands
				fixture.limits.MaxCommandsPerNode = status.Commands
				if err := fixture.store.Close(); err != nil {
					t.Fatal(err)
				}
				reopened, err := controlstore.Open(fixture.dir, fixture.limits)
				if err != nil {
					t.Fatal(err)
				}
				fixture.store = reopened
				t.Cleanup(func() { _ = reopened.Close() })
				report, err := fixture.reconciler(t).Reconcile(context.Background())
				if !errors.Is(err, controlstore.ErrCapacityExceeded) || report.Enqueued != 0 {
					t.Fatalf("uncertain start must not be evicted to create space: %+v, %v", report, err)
				}
				if getControlDeployment(t, fixture).Instances[0].CommandID != failed.Instances[0].CommandID {
					t.Fatal("failed capacity transaction advanced the cursor")
				}
				return
			}
			assertReconcileCount(t, reconciler, "enqueue stop", 0, 1)
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
			assertReconcileCount(t, reconciler, "restart does not duplicate stop", 0, 0)
			status := controlprotocol.ExecutorStatusFailed
			if boundary == "unknown stop" {
				status = controlprotocol.ExecutorStatusOutcomeUnknown
			}
			completeDeploymentCommand(t, fixture, "stop", status)
			assertReconcileCount(t, reconciler, "observe unsuccessful stop", 1, 0)
			assertReconcileCount(t, reconciler, "cannot skip or retry stop", 0, 0)
		})
	}
}
