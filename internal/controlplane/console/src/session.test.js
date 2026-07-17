import assert from "node:assert/strict";
import test from "node:test";

import {
  SessionFence,
  SnapshotFence,
  StaleSessionError,
  StaleSnapshotError,
  armDeadline,
  displayStringList,
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

test("authentication deadline expires once or can be cancelled", () => {
  let scheduled;
  let cleared = 0;
  let expired = 0;
  const setTimer = (callback, milliseconds) => {
    scheduled = {callback, milliseconds, id: 41};
    return scheduled.id;
  };
  const clearTimer = (id) => {
    assert.equal(id, 41);
    cleared += 1;
  };

  const cancel = armDeadline(120_000, () => { expired += 1; }, setTimer, clearTimer);
  assert.equal(scheduled.milliseconds, 120_000);
  scheduled.callback();
  scheduled.callback();
  cancel();
  assert.equal(expired, 1);
  assert.equal(cleared, 0);

  const cancelBeforeExpiry = armDeadline(1, () => { expired += 1; }, setTimer, clearTimer);
  cancelBeforeExpiry();
  scheduled.callback();
  assert.equal(expired, 1);
  assert.equal(cleared, 1);
});

test("nullable or malformed display collections cannot crash a view", () => {
  assert.deepEqual(displayStringList(null), []);
  assert.deepEqual(displayStringList(undefined), []);
  assert.deepEqual(displayStringList(["authorized-effects-v1", null, {value: "unsafe"}, "delivery-leases-v3"]), [
    "authorized-effects-v1",
    "delivery-leases-v3",
  ]);
});
