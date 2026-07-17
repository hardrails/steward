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

// armDeadline uses the platform timer but keeps cancellation and the one-shot
// property explicit and testable. Authentication is not yet a session, so its
// credential lifetime needs an independent hard bound.
export function armDeadline(
  milliseconds,
  onExpire,
  setTimer = (callback, delay) => globalThis.setTimeout(callback, delay),
  clearTimer = (timer) => globalThis.clearTimeout(timer),
) {
  if (!Number.isFinite(milliseconds) || milliseconds <= 0 ||
      typeof onExpire !== "function" || typeof setTimer !== "function" || typeof clearTimer !== "function") {
    throw new TypeError("A deadline requires a positive duration, callback, and timer functions.");
  }
  let active = true;
  const timer = setTimer(() => {
    if (!active) {
      return;
    }
    active = false;
    onExpire();
  }, milliseconds);
  return () => {
    if (!active) {
      return;
    }
    active = false;
    clearTimer(timer);
  };
}

// displayStringList prevents one nullable collection in an otherwise valid API
// response from taking down the entire control room. React still escapes every
// retained string when it renders the returned values.
export function displayStringList(value) {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.filter((item) => typeof item === "string");
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
