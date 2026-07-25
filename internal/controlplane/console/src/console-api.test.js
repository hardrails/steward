import assert from "node:assert/strict";
import test from "node:test";

import {
  canonicalID,
  consoleMutationAllowed,
  consoleReadAllowed,
  deploymentReplicaCount,
  splitIDs,
} from "./console-api.js";

test("console API allowlist admits only explicit control mutations", () => {
  const allowed = [
    ["POST", "/v1/tenants"],
    ["POST", "/v1/enrollments"],
    ["PUT", "/v1/tenants/tenant-a/quota"],
    ["PUT", "/v1/node-pools/pool-a"],
    ["PUT", "/v1/tenants/tenant-a/deployments/research"],
    ["DELETE", "/v1/nodes/node-a/drain"],
    ["POST", "/v1/tenants/tenant-a/interactions/question-a/response"],
    ["POST", "/v1/nodes/node-a/evidence/captures"],
    ["POST", "/v1/nodes/node-a/evidence/captures/capture-a/seal"],
    ["DELETE", "/v1/nodes/node-a/evidence/captures/capture-a"],
    ["PUT", "/v1/tenants/tenant-a/nodes/node-a/snapshots/snapshot-a/quarantine"],
  ];
  for (const [method, path] of allowed) {
    assert.equal(consoleMutationAllowed(method, path), true, `${method} ${path}`);
  }
  for (const [method, path] of [
    ["PATCH", "/v1/tenants/tenant-a"],
    ["POST", "/executor-uplink/poll"],
    ["DELETE", "/v1/tenants"],
    ["PUT", "/v1/tenants/a/deployments/b/extra"],
    ["POST", "/v1/enroll"],
    ["POST", "/v1/nodes/node-a/evidence/export"],
    ["POST", "/v1/nodes/node-a/evidence/captures/capture-a/export"],
  ]) {
    assert.equal(consoleMutationAllowed(method, path), false, `${method} ${path}`);
  }
  assert.equal(consoleReadAllowed("/v1/readiness"), true);
  assert.equal(consoleReadAllowed("/executor-uplink/poll"), false);
});

test("console form helpers canonicalize bounded identifiers", () => {
  assert.equal(canonicalID("node-a"), "node-a");
  assert.deepEqual(splitIDs("tenant-b, tenant-a,tenant-b"), ["tenant-a", "tenant-b"]);
  assert.throws(() => canonicalID("bad id"), /must start/u);
  assert.throws(() => splitIDs(""), /at least one/u);
  assert.equal(deploymentReplicaCount({instances: [{}, {}, {}]}), 3);
  assert.equal(deploymentReplicaCount({}), 0);
});
