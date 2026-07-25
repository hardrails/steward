import assert from "node:assert/strict";
import test from "node:test";

import {
  deriveWorkspaceProjection,
  workspaceLifecycle,
  workspaceMatches,
} from "./workspace-model.js";

test("workspace lifecycle is derived without creating a second desired-state model", () => {
  assert.equal(workspaceLifecycle({instances: [{}]}), "managed");
  assert.equal(workspaceLifecycle({instances: [{}, {}]}), "fleet");
  assert.equal(workspaceLifecycle({fork: {snapshot_id: "snap"}, instances: [{}]}), "resumable");
  assert.equal(workspaceLifecycle({
    fork: {snapshot_id: "snap", expires_at: "2026-08-01T00:00:00Z"},
    instances: [{}],
  }), "temporary");
});

test("workspace projection joins only exact tenant and instance observations", () => {
  const deployments = {
    deployments: [{
      tenant_id: "tenant-a",
      deployment_id: "research",
      agent_name: "hermes",
      generation: 2,
      revision: 3,
      phase: "ready",
      desired_state: "present",
      fork: {
        snapshot_id: "baseline",
        source_node_id: "node-a",
        source_lineage_id: "lineage-a",
        expires_at: "2026-08-01T00:00:00Z",
      },
      instances: [{instance_id: "worker-a", phase: "running"}],
    }],
  };
  const agents = {
    agents: [
      {
        tenant_id: "tenant-a",
        instance_id: "worker-a",
        instance_generation: 2,
        node_id: "node-a",
        observed_status: "running",
        runtime_ref: "executor-worker-a",
        connector_ids: ["web-search", "web-search"],
        egress_route_ids: ["browser"],
        service_id: "hermes",
        updated_at: "2026-07-25T12:00:00Z",
      },
      {
        tenant_id: "tenant-b",
        instance_id: "worker-a",
        instance_generation: 99,
        node_id: "node-b",
        observed_status: "running",
      },
      {
        tenant_id: "tenant-a",
        instance_id: "direct-a",
        instance_generation: 1,
        node_id: "node-a",
        observed_status: "stopped",
      },
    ],
  };

  const projection = deriveWorkspaceProjection(deployments, agents);
  assert.equal(projection.workspaces.length, 1);
  assert.equal(projection.workspaces[0].lifecycle, "temporary");
  assert.deepEqual(projection.workspaces[0].node_ids, ["node-a"]);
  assert.deepEqual(projection.workspaces[0].connector_ids, ["web-search"]);
  assert.equal(projection.workspaces[0].members[0].runtime_ref, "executor-worker-a");
  assert.deepEqual(
    projection.directInstances.map((agent) => `${agent.tenant_id}/${agent.instance_id}`),
    ["tenant-b/worker-a", "tenant-a/direct-a"],
  );
});

test("workspace search covers identity, placement, and delegated capabilities", () => {
  const workspace = {
    lifecycle: "managed",
    id: "analyst",
    tenant_id: "research",
    agent_name: "hermes",
    phase: "ready",
    node_ids: ["node-west"],
    connector_ids: ["primary-sources"],
    egress_route_ids: ["browser"],
    service_ids: [],
    members: [{instance_id: "analyst-1"}],
  };
  assert.equal(workspaceMatches(workspace, "primary-source", "all"), true);
  assert.equal(workspaceMatches(workspace, "node-west", "managed"), true);
  assert.equal(workspaceMatches(workspace, "node-west", "temporary"), false);
  assert.equal(workspaceMatches(workspace, "missing", "all"), false);
});
