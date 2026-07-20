package controlstore

import (
	"errors"
	"math"
	"time"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/controlauth"
	"github.com/hardrails/steward/internal/controlprotocol"
)

var ErrTenantQuotaExceeded = errors.New("tenant resource quota exceeded")

type TenantResourceQuotaStatus struct {
	TenantID  string                                        `json:"tenant_id"`
	Quota     *TenantResourceQuota                          `json:"quota,omitempty"`
	Usage     controlprotocol.ExecutorSchedulingResourcesV1 `json:"usage"`
	OverQuota bool                                          `json:"over_quota"`
}

// InspectTenantResourceQuota returns the site-defined limit and conservative
// requested-resource usage. Tenant operators can read only their own status;
// only a site administrator may change the limit.
func (store *Store) InspectTenantResourceQuota(
	actor controlauth.Identity,
	tenantID string,
) (TenantResourceQuotaStatus, error) {
	if store == nil {
		return TenantResourceQuotaStatus{}, ErrUnavailable
	}
	if !validRecordID(tenantID, 128) || !controlauth.AuthorizedTenant(actor, tenantID) {
		return TenantResourceQuotaStatus{}, ErrNotFound
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.availableLocked(); err != nil {
		return TenantResourceQuotaStatus{}, err
	}
	if err := store.revalidateOperatorLocked(actor); err != nil {
		return TenantResourceQuotaStatus{}, err
	}
	tenant, ok := store.current.tenants[tenantID]
	if !ok || !tenant.Active {
		return TenantResourceQuotaStatus{}, ErrNotFound
	}
	return tenantResourceQuotaStatusLocked(store.current, tenant), nil
}

// ChangeTenantResourceQuota applies an optimistic site policy transition. A
// lower quota does not evict existing work: status becomes over_quota and new
// admissions remain blocked until usage falls within the retained ceiling.
func (store *Store) ChangeTenantResourceQuota(
	actor controlauth.Identity,
	tenantID string,
	action TenantQuotaAction,
	expectedRevision uint64,
	resources controlprotocol.ExecutorSchedulingResourcesV1,
	now time.Time,
) (TenantResourceQuotaStatus, bool, error) {
	if store == nil {
		return TenantResourceQuotaStatus{}, false, ErrUnavailable
	}
	if !controlauth.IsSiteAdmin(actor) {
		return TenantResourceQuotaStatus{}, false, ErrForbidden
	}
	if !validRecordID(tenantID, 128) || !validTenantQuotaChange(action, resources) || now.IsZero() {
		return TenantResourceQuotaStatus{}, false, invalid("tenant resource quota transition is invalid")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.availableLocked(); err != nil {
		return TenantResourceQuotaStatus{}, false, err
	}
	if err := store.revalidateOperatorLocked(actor); err != nil {
		return TenantResourceQuotaStatus{}, false, err
	}
	tenant, ok := store.current.tenants[tenantID]
	if !ok || !tenant.Active {
		return TenantResourceQuotaStatus{}, false, ErrNotFound
	}
	current := tenant.Quota
	if current == nil {
		if expectedRevision != 0 {
			return TenantResourceQuotaStatus{}, false, ErrConflict
		}
		if action == TenantQuotaActionClear {
			return tenantResourceQuotaStatusLocked(store.current, tenant), false, nil
		}
	} else {
		if current.Revision != expectedRevision {
			return TenantResourceQuotaStatus{}, false, ErrConflict
		}
		changedAt, _ := parseTimestamp(current.ChangedAt)
		if now.Before(changedAt) {
			return TenantResourceQuotaStatus{}, false, invalid("tenant resource quota transition predates retained state")
		}
		wantEnabled := action == TenantQuotaActionSet
		if current.Enabled == wantEnabled && (!wantEnabled || current.Resources == resources) {
			return tenantResourceQuotaStatusLocked(store.current, tenant), false, nil
		}
		if current.Revision == math.MaxUint64 {
			return TenantResourceQuotaStatus{}, false, ErrCapacityExceeded
		}
	}
	revision := uint64(1)
	if current != nil {
		revision = current.Revision + 1
	}
	quota := &TenantResourceQuota{
		Enabled: action == TenantQuotaActionSet, Revision: revision,
		Resources: resources, ChangedAt: canonicalTimestamp(now),
	}
	if !quota.Enabled {
		quota.Resources = controlprotocol.ExecutorSchedulingResourcesV1{}
	}
	updated := cloneTenant(tenant)
	updated.Quota = quota
	if err := store.applyMutationsLocked(mutation{Kind: mutationTenant, Tenant: &updated}); err != nil {
		return TenantResourceQuotaStatus{}, false, err
	}
	return tenantResourceQuotaStatusLocked(store.current, updated), true, nil
}

func tenantResourceQuotaStatusLocked(current state, tenant Tenant) TenantResourceQuotaStatus {
	usage, usageErr := tenantRequestedResourceUsage(current.deployments, tenant.ID, "", "")
	status := TenantResourceQuotaStatus{
		TenantID: tenant.ID,
		Quota:    cloneTenantResourceQuota(tenant.Quota),
		Usage:    usage,
	}
	if usageErr != nil {
		status.OverQuota = true
		return status
	}
	if tenant.Quota != nil && tenant.Quota.Enabled {
		status.OverQuota = exceedsSchedulingCapacity(
			usage, controlprotocol.ExecutorSchedulingResourcesV1{}, tenant.Quota.Resources,
		)
	}
	return status
}

func checkTenantResourceQuota(
	tenant Tenant,
	deployments map[string]Deployment,
	deploymentID, instanceID string,
	intent admission.InstanceIntent,
) error {
	if tenant.Quota == nil || !tenant.Quota.Enabled {
		return nil
	}
	usage, err := tenantRequestedResourceUsage(deployments, tenant.ID, deploymentID, instanceID)
	if err != nil {
		return ErrTenantQuotaExceeded
	}
	requested := controlprotocol.ExecutorSchedulingResourcesV1{
		MemoryBytes: intent.Resources.MemoryBytes,
		CPUMillis:   intent.Resources.CPUMillis,
		PIDs:        intent.Resources.PIDs,
		Workloads:   1,
	}
	if exceedsSchedulingCapacity(usage, requested, tenant.Quota.Resources) {
		return ErrTenantQuotaExceeded
	}
	return nil
}

func tenantRequestedResourceUsage(
	deployments map[string]Deployment,
	tenantID, excludeDeploymentID, excludeInstanceID string,
) (controlprotocol.ExecutorSchedulingResourcesV1, error) {
	var usage controlprotocol.ExecutorSchedulingResourcesV1
	for _, deployment := range deployments {
		if deployment.TenantID != tenantID {
			continue
		}
		for _, instance := range deployment.Instances {
			if instance.Phase == DeploymentInstanceRemoved || instance.Intent == nil ||
				deployment.ID == excludeDeploymentID && instance.InstanceID == excludeInstanceID {
				continue
			}
			requested := controlprotocol.ExecutorSchedulingResourcesV1{
				MemoryBytes: instance.Intent.Resources.MemoryBytes,
				CPUMillis:   instance.Intent.Resources.CPUMillis,
				PIDs:        instance.Intent.Resources.PIDs,
				Workloads:   1,
			}
			if err := addSchedulingResources(&usage, requested); err != nil {
				return usage, err
			}
		}
	}
	return usage, nil
}

func validTenantQuotaChange(
	action TenantQuotaAction,
	resources controlprotocol.ExecutorSchedulingResourcesV1,
) bool {
	switch action {
	case TenantQuotaActionSet:
		return validTenantQuotaResources(resources)
	case TenantQuotaActionClear:
		return resources == (controlprotocol.ExecutorSchedulingResourcesV1{})
	default:
		return false
	}
}

func validTenantResourceQuota(quota TenantResourceQuota) bool {
	if quota.Revision == 0 || !validTimestamp(quota.ChangedAt) {
		return false
	}
	if !quota.Enabled {
		return quota.Resources == (controlprotocol.ExecutorSchedulingResourcesV1{})
	}
	return validTenantQuotaResources(quota.Resources)
}

func validTenantQuotaResources(resources controlprotocol.ExecutorSchedulingResourcesV1) bool {
	return resources.MemoryBytes > 0 && resources.CPUMillis > 0 &&
		resources.CPUMillis <= math.MaxInt64/1_000_000 && resources.PIDs > 0 && resources.Workloads > 0
}

func cloneTenant(tenant Tenant) Tenant {
	tenant.Quota = cloneTenantResourceQuota(tenant.Quota)
	return tenant
}

func cloneTenantResourceQuota(quota *TenantResourceQuota) *TenantResourceQuota {
	if quota == nil {
		return nil
	}
	cloned := *quota
	return &cloned
}
