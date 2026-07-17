export class StaleSessionError extends Error {
  constructor() {
    super("The operator session changed while the request was in flight.");
    this.name = "StaleSessionError";
  }
}

export class StaleSnapshotError extends Error {
  constructor() {
    super("A newer fleet projection replaced this response.");
    this.name = "StaleSnapshotError";
  }
}

export function sessionExpired(now, startedAt, lastActivity, idleTimeout, absoluteTimeout) {
  if (!Number.isFinite(now) || !Number.isFinite(startedAt) || !Number.isFinite(lastActivity) ||
      startedAt <= 0 || lastActivity <= 0 || now < startedAt || now < lastActivity) {
    return true;
  }
  return now - lastActivity >= idleTimeout || now - startedAt >= absoluteTimeout;
}

// SnapshotFence is independent from the credential epoch. An administrator
// can switch tenant projections while an auto-refresh is still in flight; only
// the newest request may enter React state.
export class SnapshotFence {
  #generation = 0;

  begin() {
    this.#generation += 1;
    return this.#generation;
  }

  invalidate() {
    this.#generation += 1;
  }

  current(generation) {
    return generation === this.#generation;
  }

  assertCurrent(generation) {
    if (!this.current(generation)) {
      throw new StaleSnapshotError();
    }
  }
}

// SessionFence gives every credential activation a monotonically increasing
// epoch and one shared AbortSignal. Locking or starting another session aborts
// every request from the prior credential before its response can reach React.
export class SessionFence {
  #epoch = 0;
  #controller = null;

  begin() {
    this.#controller?.abort();
    this.#epoch += 1;
    this.#controller = new AbortController();
    return {epoch: this.#epoch, signal: this.#controller.signal};
  }

  lock() {
    this.#controller?.abort();
    this.#controller = null;
    this.#epoch += 1;
  }

  current(epoch) {
    return this.#controller !== null &&
      !this.#controller.signal.aborted &&
      epoch === this.#epoch;
  }

  signal(epoch) {
    if (!this.current(epoch)) {
      throw new StaleSessionError();
    }
    return this.#controller.signal;
  }

  assertCurrent(epoch) {
    if (!this.current(epoch)) {
      throw new StaleSessionError();
    }
  }
}
