package controlreconcile

import (
	"testing"
	"time"

	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/controlstore"
)

func TestAutomaticRenewalsReclaimSettledHistoryWithinCommandBounds(t *testing.T) {
	for _, bound := range []string{"global", "tenant", "node"} {
		t.Run(bound, func(t *testing.T) {
			fixture := newControlReconcileFixture(t)
			applyControlDeployment(t, fixture, 1)
			reconciler := fixture.reconciler(t)
			retained := make(map[string]string)
			for _, operation := range []string{"admit", "renew", "start"} {
				assertReconcileCount(t, reconciler, "enqueue "+operation, 0, 1)
				retained[operation] = getControlDeployment(t, fixture).Instances[0].CommandID
				completeDeploymentCommand(t, fixture, operation, controlprotocol.ExecutorStatusDone)
				assertReconcileCount(t, reconciler, "observe "+operation, 1, 0)
			}
			// Keep admission/start history for the normal 24-hour window. Only
			// renewals older than the lease plus clock-skew horizon can make room.
			switch bound {
			case "global":
				fixture.limits.MaxCommands = 5
				fixture.limits.MaxCommandsPerTenant = 5
				fixture.limits.MaxCommandsPerNode = 5
			case "tenant":
				fixture.limits.MaxCommandsPerTenant = 5
			case "node":
				fixture.limits.MaxCommandsPerNode = 5
			}
			reopen := func() {
				t.Helper()
				if err := fixture.store.Close(); err != nil {
					t.Fatal(err)
				}
				store, err := controlstore.Open(fixture.dir, fixture.limits)
				if err != nil {
					t.Fatal(err)
				}
				fixture.store = store
				t.Cleanup(func() { _ = store.Close() })
				reconciler = fixture.reconciler(t)
			}
			reopen()
			for cycle := 0; cycle < 24; cycle++ {
				fixture.now = fixture.now.Add(2 * time.Minute)
				heartbeatControlNode(t, fixture)
				before := getControlDeployment(t, fixture)
				assertReconcileCount(t, reconciler, "automatic renewal", 0, 1)
				pending := getControlDeployment(t, fixture)
				if pending.Revision != before.Revision+1 ||
					pending.Instances[0].CommandSequence != before.Instances[0].CommandSequence+1 ||
					pending.Instances[0].LeaseExpiresAt <= before.Instances[0].LeaseExpiresAt {
					t.Fatal("renewal did not advance exact cursor and lease")
				}
				if cycle == 12 {
					reopen()
				}
				assertReconcileCount(t, reconciler, "pending renewal stays pending", 0, 0)
				completeDeploymentCommand(t, fixture, "renew", controlprotocol.ExecutorStatusDone)
				assertReconcileCount(t, reconciler, "observe renewal", 1, 0)
				if status, err := fixture.store.Status(); err != nil || status.Commands != min(cycle+4, 5) {
					t.Fatalf("command inventory escaped bound: %+v, %v", status, err)
				}
				if deployment := getControlDeployment(t, fixture); deployment.Phase != controlstore.DeploymentReady {
					t.Fatalf("renewal lost ready deployment: %s", deployment.Phase)
				}
			}
			reopen()
			for operation, id := range retained {
				_, found, err := fixture.store.GetCommand(fixture.admin, "tenant-a", "node-1", id)
				if err != nil || found != (operation != "renew") {
					t.Fatalf("wrong retained %s history after restart: found=%v, %v", operation, found, err)
				}
			}
		})
	}
}
