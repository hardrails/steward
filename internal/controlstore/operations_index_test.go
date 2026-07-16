package controlstore

import (
	"fmt"
	"slices"
	"testing"

	"github.com/hardrails/steward/internal/controlauth"
)

func TestSiteAttentionIndexMatchesTenantProjection(t *testing.T) {
	fixture := newRecordsFixture(t, DefaultLimits())
	fixture.createTenant(t, "tenant-a")
	fixture.createTenant(t, "tenant-b")
	_, _ = fixture.createNode(t, "tenant-a", "tenant-b")
	_ = operationsTenantOperator(t, fixture, "tenant-a", "operator-a")
	_ = operationsTenantOperator(t, fixture, "tenant-b", "operator-b")
	for index, tenantID := range []string{"tenant-a", "tenant-b"} {
		commandID := "command-a"
		if index == 1 {
			commandID = "command-b"
		}
		if _, created, err := fixture.store.SubmitCommand(
			fixture.admin, tenantID, "node-1",
			signedCommand(t, commandID, tenantID, "node-1", index),
			fixture.now,
		); err != nil || !created {
			t.Fatalf("submit %s = (%v, %v)", commandID, created, err)
		}
	}

	fixture.store.mu.Lock()
	defer fixture.store.mu.Unlock()
	index := fixture.store.buildSiteAttentionIndexLocked()
	if !slices.Equal(index.tenantIDs, []string{"tenant-a", "tenant-b"}) {
		t.Fatalf("tenant index order = %v", index.tenantIDs)
	}
	for _, tenantID := range index.tenantIDs {
		want := fixture.store.capacityUsageLocked(operationsScope{tenantID: tenantID}, 80)
		got := tenantCapacityUsage(index.capacity[tenantID], fixture.store.limits, 80)
		if !slices.Equal(got, want) {
			t.Fatalf("%s capacity index = %+v, want %+v", tenantID, got, want)
		}
		if !slices.Equal(index.nodeIDs[tenantID], []string{"node-1"}) {
			t.Fatalf("%s node index = %v", tenantID, index.nodeIDs[tenantID])
		}
		if len(index.commandKeys[tenantID]) != 1 {
			t.Fatalf("%s command index = %v", tenantID, index.commandKeys[tenantID])
		}
	}
}

var benchmarkSiteAttentionIndex siteAttentionIndex

func BenchmarkBuildSiteAttentionIndexAtDefaultLimits(b *testing.B) {
	limits := DefaultLimits()
	current := emptyState()
	tenantID := func(index int) string {
		return fmt.Sprintf("tenant-%03d", index%limits.MaxTenants)
	}
	for index := 0; index < limits.MaxTenants; index++ {
		id := tenantID(index)
		current.tenants[id] = Tenant{ID: id, Active: true}
	}
	for index := 0; index < limits.MaxNodes; index++ {
		id := fmt.Sprintf("node-%05d", index)
		tenants := make([]string, 0, 8)
		for offset := 0; offset < 8; offset++ {
			tenants = append(tenants, tenantID(index+offset))
		}
		current.nodes[id] = Node{ID: id, TenantIDs: tenants, Active: true}
	}
	for index := 0; index < limits.MaxCredentials; index++ {
		id := fmt.Sprintf("credential-%05d", index)
		if index < limits.MaxTenants {
			current.credentials[id] = controlauth.Credential{
				ID: id, Kind: controlauth.KindOperator, Role: controlauth.RoleTenantOperator,
				TenantID: tenantID(index),
			}
			continue
		}
		current.credentials[id] = controlauth.Credential{
			ID: id, Kind: controlauth.KindNode, NodeID: fmt.Sprintf("node-%05d", index%limits.MaxNodes),
			TenantIDs: []string{tenantID(index)},
		}
	}
	for index := 0; index < limits.MaxEnrollments; index++ {
		id := fmt.Sprintf("enrollment-%05d", index)
		current.enrollments[id] = controlauth.Enrollment{
			ID: id, NodeID: fmt.Sprintf("node-%05d", index), TenantIDs: []string{tenantID(index)},
		}
	}
	for index := 0; index < limits.MaxCommands; index++ {
		id := fmt.Sprintf("command-%05d", index)
		tenant := tenantID(index)
		node := fmt.Sprintf("node-%05d", index%limits.MaxNodes)
		current.commands[commandKey(tenant, node, id)] = Command{
			TenantID: tenant, NodeID: node, ID: id,
		}
	}
	store := &Store{limits: limits, current: current}

	b.ResetTimer()
	for iteration := 0; iteration < b.N; iteration++ {
		benchmarkSiteAttentionIndex = store.buildSiteAttentionIndexLocked()
	}
}
