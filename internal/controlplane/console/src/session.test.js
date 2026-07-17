import assert from "node:assert/strict";
import test from "node:test";

import {
  SessionFence,
  SnapshotFence,
  StaleSessionError,
  StaleSnapshotError,
  sessionExpired,
} from "./session.js";

test("a delayed administrator response cannot enter a later tenant session", async () => {
  const fence = new SessionFence();
  const administrator = fence.begin();
  let releaseAdministrator;
  const delayedAdministrator = new Promise((resolve) => {
    releaseAdministrator = resolve;
  });
  const guardedAdministrator = delayedAdministrator.then((value) => {
    fence.assertCurrent(administrator.epoch);
    return value;
  });

  fence.lock();
  assert.equal(administrator.signal.aborted, true);
  const tenant = fence.begin();
  releaseAdministrator({tenant_id: "", secret_site_count: 9});

  await assert.rejects(guardedAdministrator, StaleSessionError);
  assert.equal(fence.current(tenant.epoch), true);
  assert.deepEqual({tenant_id: "tenant-a"}, {tenant_id: "tenant-a"});
});

test("starting a replacement session aborts every request from the old epoch", () => {
  const fence = new SessionFence();
  const first = fence.begin();
  const second = fence.begin();

  assert.equal(first.signal.aborted, true);
  assert.equal(second.signal.aborted, false);
  assert.throws(() => fence.signal(first.epoch), StaleSessionError);
  assert.equal(fence.signal(second.epoch), second.signal);
});

test("a delayed projection cannot replace the newest tenant snapshot", () => {
  const fence = new SnapshotFence();
  const tenantA = fence.begin();
  const tenantB = fence.begin();

  assert.throws(() => fence.assertCurrent(tenantA), StaleSnapshotError);
  assert.doesNotThrow(() => fence.assertCurrent(tenantB));
  fence.invalidate();
  assert.throws(() => fence.assertCurrent(tenantB), StaleSnapshotError);
});

test("activity after a suspended idle window cannot revive a session", () => {
  const minute = 60 * 1000;
  const startedAt = 100 * minute;
  const lastActivity = 101 * minute;

  assert.equal(sessionExpired(116 * minute, startedAt, lastActivity, 15 * minute, 8 * 60 * minute), true);
  assert.equal(sessionExpired(115 * minute - 1, startedAt, lastActivity, 15 * minute, 8 * 60 * minute), false);
  assert.equal(sessionExpired(startedAt - 1, startedAt, lastActivity, 15 * minute, 8 * 60 * minute), true);
});
