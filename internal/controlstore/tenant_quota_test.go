package controlstore

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/controlprotocol"
)

func TestTenantResourceQuotaTransitionsAreScopedOptimisticAndDurable(t *testing.T) {
	fixture := newRecordsFixture(t, DefaultLimits())
	fixture.createTenant(t, "tenant-a")
	fixture.createTenant(t, "tenant-b")
	tenantA := operationalFreezeTenantOperator(t, fixture, "tenant-a", "quota-operator-a")
	tenantB := operationalFreezeTenantOperator(t, fixture, "tenant-b", "quota-operator-b")
	resources := quotaResources(4<<30, 4000, 1024, 8)

	status, err := fixture.store.InspectTenantResourceQuota(tenantA, "tenant-a")
	if err != nil || status.TenantID != "tenant-a" || status.Quota != nil || status.OverQuota {
		t.Fatalf("initial quota status = (%+v, %v)", status, err)
	}
	if _, err := fixture.store.InspectTenantResourceQuota(tenantB, "tenant-a"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant quota inspection error = %v", err)
	}
	if _, _, err := fixture.store.ChangeTenantResourceQuota(
		tenantA, "tenant-a", TenantQuotaActionSet, 0, resources, fixture.now.Add(time.Minute),
	); !errors.Is(err, ErrForbidden) {
		t.Fatalf("tenant operator quota change error = %v", err)
	}

	status, changed, err := fixture.store.ChangeTenantResourceQuota(
		fixture.admin, "tenant-a", TenantQuotaActionSet, 0, resources, fixture.now.Add(2*time.Minute),
	)
	if err != nil || !changed || status.Quota == nil || !status.Quota.Enabled ||
		status.Quota.Revision != 1 || status.Quota.Resources != resources {
		t.Fatalf("set quota = (%+v, %v, %v)", status, changed, err)
	}
	status, changed, err = fixture.store.ChangeTenantResourceQuota(
		fixture.admin, "tenant-a", TenantQuotaActionSet, 1, resources, fixture.now.Add(3*time.Minute),
	)
	if err != nil || changed || status.Quota == nil || status.Quota.Revision != 1 {
		t.Fatalf("idempotent quota set = (%+v, %v, %v)", status, changed, err)
	}
	if _, _, err := fixture.store.ChangeTenantResourceQuota(
		fixture.admin, "tenant-a", TenantQuotaActionClear, 0,
		controlprotocol.ExecutorSchedulingResourcesV1{}, fixture.now.Add(4*time.Minute),
	); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale quota clear error = %v", err)
	}
	status, changed, err = fixture.store.ChangeTenantResourceQuota(
		fixture.admin, "tenant-a", TenantQuotaActionClear, 1,
		controlprotocol.ExecutorSchedulingResourcesV1{}, fixture.now.Add(5*time.Minute),
	)
	if err != nil || !changed || status.Quota == nil || status.Quota.Enabled || status.Quota.Revision != 2 ||
		status.Quota.Resources != (controlprotocol.ExecutorSchedulingResourcesV1{}) {
		t.Fatalf("clear quota = (%+v, %v, %v)", status, changed, err)
	}

	if err := fixture.store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(fixture.dir, fixture.limits)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	status, err = reopened.InspectTenantResourceQuota(fixture.admin, "tenant-a")
	if err != nil || status.Quota == nil || status.Quota.Enabled || status.Quota.Revision != 2 {
		t.Fatalf("reopened quota status = (%+v, %v)", status, err)
	}
}

func TestTenantResourceQuotaCountsConservativelyAndExcludesReplacement(t *testing.T) {
	intent := func(memory, cpu, pids int64) *admission.InstanceIntent {
		return &admission.InstanceIntent{Resources: admission.ResourceLimits{
			MemoryBytes: memory, CPUMillis: cpu, PIDs: pids,
		}}
	}
	deployments := map[string]Deployment{
		deploymentKey("tenant-a", "deployment-a"): {
			ID: "deployment-a", TenantID: "tenant-a",
			Instances: []DeploymentInstance{
				{InstanceID: "replace-me", Intent: intent(100, 100, 10), Phase: DeploymentInstanceRunning},
				{InstanceID: "ambiguous", Intent: intent(200, 200, 20), Phase: DeploymentInstanceFailed},
				{InstanceID: "waiting", Intent: intent(700, 700, 70), Phase: DeploymentInstancePending},
				{InstanceID: "removed", Intent: intent(900, 900, 90), Phase: DeploymentInstanceRemoved},
			},
		},
		deploymentKey("tenant-b", "deployment-b"): {
			ID: "deployment-b", TenantID: "tenant-b",
			Instances: []DeploymentInstance{{
				InstanceID: "other", Intent: intent(800, 800, 80), Phase: DeploymentInstanceRunning,
			}},
		},
	}
	usage, err := tenantRequestedResourceUsage(deployments, "tenant-a", "", "")
	if err != nil || usage != quotaResources(300, 300, 30, 2) {
		t.Fatalf("tenant quota usage = (%+v, %v)", usage, err)
	}
	tenant := Tenant{ID: "tenant-a", Quota: &TenantResourceQuota{
		Enabled: true, Revision: 1, ChangedAt: "2026-07-20T12:00:00Z",
		Resources: quotaResources(350, 350, 35, 2),
	}}
	if err := checkTenantResourceQuota(
		tenant, deployments, "deployment-a", "replace-me", *intent(150, 150, 15),
	); err != nil {
		t.Fatalf("replacement quota error = %v", err)
	}
	if err := checkTenantResourceQuota(
		tenant, deployments, "deployment-new", "new", *intent(51, 51, 6),
	); !errors.Is(err, ErrTenantQuotaExceeded) {
		t.Fatalf("new workload quota error = %v", err)
	}
}

func TestTenantResourceQuotaFormatRejectsLegacySmuggling(t *testing.T) {
	current, limits := populatedControlState(t)
	var tenantID string
	for key, tenant := range current.tenants {
		tenantID = key
		tenant.Quota = &TenantResourceQuota{
			Enabled: true, Revision: 1, ChangedAt: tenant.CreatedAt,
			Resources: quotaResources(4<<30, 4000, 1024, 8),
		}
		current.tenants[key] = tenant
		break
	}
	raw, err := encodeState(current, limits.MaxStateBytes)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeState(raw, limits.MaxStateBytes)
	if err != nil || decoded.tenants[tenantID].Quota == nil {
		t.Fatalf("quota round trip = (%+v, %v)", decoded.tenants[tenantID].Quota, err)
	}
	var snapshot snapshotState
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		t.Fatal(err)
	}
	snapshot.Version = stateFormatOperationalFreezeVersion
	snapshot.Quarantines = nil
	smuggled, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeState(smuggled, limits.MaxStateBytes); err == nil {
		t.Fatal("legacy snapshot accepted tenant quota state")
	}
	for index := range snapshot.Tenants {
		snapshot.Tenants[index].Quota = nil
	}
	legacy, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeState(legacy, limits.MaxStateBytes); err != nil {
		t.Fatalf("legacy quota migration error = %v", err)
	}
	tenant := current.tenants[tenantID]
	if _, err := applyTransaction(current, transaction{
		Version:   transactionOperationalFreezeVersion,
		Mutations: []mutation{{Kind: mutationTenant, Tenant: &tenant}},
	}); err == nil {
		t.Fatal("legacy transaction accepted tenant quota state")
	}
}

func quotaResources(memory, cpu, pids, workloads int64) controlprotocol.ExecutorSchedulingResourcesV1 {
	return controlprotocol.ExecutorSchedulingResourcesV1{
		MemoryBytes: memory, CPUMillis: cpu, PIDs: pids, Workloads: workloads,
	}
}
