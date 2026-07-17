import React, {useCallback, useEffect, useRef, useState} from "react";

import {
  SessionFence,
  SnapshotFence,
  StaleSessionError,
  StaleSnapshotError,
  armDeadline,
  displayStringList,
  sessionExpired,
} from "./session.js";

const idleTimeoutMilliseconds = 15 * 60 * 1000;
const absoluteTimeoutMilliseconds = 8 * 60 * 60 * 1000;
const authenticationTimeoutMilliseconds = 2 * 60 * 1000;
const refreshMilliseconds = 30 * 1000;

class ControlError extends Error {
  constructor(status, code, message) {
    super(message);
    this.name = "ControlError";
    this.status = status;
    this.code = code;
  }
}

function formatTime(value) {
  if (!value) {
    return "—";
  }
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return String(value);
  }
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "medium",
    timeZone: "UTC",
  }).format(parsed) + " UTC";
}

function humanize(value) {
  return String(value || "unknown").replaceAll("_", " ");
}

function projectedPath(base, tenantID, extra = {}) {
  const url = new URL(base, window.location.origin);
  if (tenantID) {
    url.searchParams.set("tenant_id", tenantID);
  }
  for (const [key, value] of Object.entries(extra)) {
    if (value !== "" && value !== undefined && value !== null) {
      url.searchParams.set(key, String(value));
    }
  }
  return url.pathname + url.search;
}

function useClock() {
  const [clock, setClock] = useState(() => new Date());
  useEffect(() => {
    const timer = window.setInterval(() => setClock(new Date()), 1000);
    return () => window.clearInterval(timer);
  }, []);
  return clock.toISOString().slice(11, 19) + " UTC";
}

function useControlHealth() {
  const [health, setHealth] = useState({state: "pending", label: "CHECKING CONTROL PLANE"});
  useEffect(() => {
    const controller = new AbortController();
    fetch("/v1/healthz", {
      cache: "no-store",
      credentials: "omit",
      redirect: "error",
      referrerPolicy: "no-referrer",
      signal: controller.signal,
    }).then((response) => {
      if (!response.ok) {
        throw new Error("unhealthy");
      }
      setHealth({state: "ok", label: "CONTROL PLANE ONLINE"});
    }).catch((error) => {
      if (error?.name !== "AbortError") {
        setHealth({state: "error", label: "CONTROL PLANE UNREACHABLE"});
      }
    });
    return () => controller.abort();
  }, []);
  return health;
}

export default function App() {
  const health = useControlHealth();
  const clock = useClock();
  const fenceRef = useRef(new SessionFence());
  const snapshotFenceRef = useRef(new SnapshotFence());
  const credentialRef = useRef("");
  const startedAtRef = useRef(0);
  const lastActivityRef = useRef(0);
  const [session, setSession] = useState(null);
  const [snapshot, setSnapshot] = useState(null);
  const [tenants, setTenants] = useState([]);
  const [selectedTenant, setSelectedTenant] = useState("");
  const [view, setView] = useState("overview");
  const [authenticating, setAuthenticating] = useState(false);
  const [loginError, setLoginError] = useState("");
  const [refreshing, setRefreshing] = useState(false);
  const [refreshError, setRefreshError] = useState("");
  const [lastRefresh, setLastRefresh] = useState("");

  const clearAuthority = useCallback(() => {
    fenceRef.current.lock();
    snapshotFenceRef.current.invalidate();
    credentialRef.current = "";
    startedAtRef.current = 0;
    lastActivityRef.current = 0;
  }, []);

  const lock = useCallback((message = "") => {
    clearAuthority();
    setSession(null);
    setSnapshot(null);
    setTenants([]);
    setSelectedTenant("");
    setView("overview");
    setRefreshing(false);
    setRefreshError("");
    setLastRefresh("");
    setAuthenticating(false);
    setLoginError(message);
  }, [clearAuthority]);

  useEffect(() => {
    const onPageHide = () => lock("");
    window.addEventListener("pagehide", onPageHide);
    return () => {
      window.removeEventListener("pagehide", onPageHide);
      clearAuthority();
    };
  }, [clearAuthority, lock]);

  const api = useCallback(async (path, epoch) => {
    const fence = fenceRef.current;
    const signal = fence.signal(epoch);
    const url = new URL(path, window.location.origin);
    if (url.origin !== window.location.origin || !url.pathname.startsWith("/v1/")) {
      throw new Error("Console API path escaped the local control origin.");
    }
    const headers = new Headers();
    headers.set("Authorization", "Bearer " + credentialRef.current);
    const response = await fetch(url, {
      method: "GET",
      headers,
      cache: "no-store",
      credentials: "omit",
      redirect: "error",
      referrerPolicy: "no-referrer",
      signal,
    });
    const raw = await response.text();
    fence.assertCurrent(epoch);
    let payload = null;
    if (raw) {
      try {
        payload = JSON.parse(raw);
      } catch {
        throw new ControlError(response.status, "invalid_response", "The control plane returned invalid JSON.");
      }
    }
    if (!response.ok) {
      const code = payload && typeof payload.error === "string" ? payload.error : "request_failed";
      const message = payload && typeof payload.message === "string"
        ? payload.message
        : "The control plane rejected the request.";
      throw new ControlError(response.status, code, message);
    }
    return payload;
  }, []);

  const loadSnapshot = useCallback(async (epoch, tenantID, prefetchedSummary = null) => {
    const requests = [
      prefetchedSummary || api(projectedPath("/v1/operations/summary", tenantID), epoch),
      api(projectedPath("/v1/operations/attention", tenantID, {limit: 100}), epoch),
      api(projectedPath("/v1/operations/commands", tenantID, {limit: 100}), epoch),
      api(projectedPath("/v1/operations/credentials", tenantID, {limit: 100}), epoch),
      tenantID
        ? api("/v1/tenants/" + encodeURIComponent(tenantID) + "/nodes?limit=500", epoch)
        : Promise.resolve({nodes: []}),
    ];
    const [summary, attention, commands, credentials, nodes] = await Promise.all(requests);
    fenceRef.current.assertCurrent(epoch);
    return {summary, attention, commands, credentials, nodes};
  }, [api]);

  const authenticate = useCallback(async (rawCredential) => {
    setLoginError("");
    if (!rawCredential || rawCredential.trim() !== rawCredential) {
      setLoginError("Enter one credential without leading or trailing whitespace.");
      return;
    }
    const activation = fenceRef.current.begin();
    const cancelAuthenticationDeadline = armDeadline(authenticationTimeoutMilliseconds, () => {
      if (fenceRef.current.current(activation.epoch)) {
        lock("Authentication took too long, so the operator credential was cleared.");
      }
    });
    credentialRef.current = rawCredential;
    setAuthenticating(true);
    try {
      const initialSummary = await api("/v1/operations/summary", activation.epoch);
      const siteAdmin = !initialSummary.tenant_id;
      const tenantPage = await api("/v1/tenants?limit=500", activation.epoch);
      const tenantOperatorScope = initialSummary.tenant_id || "";
      const projection = siteAdmin ? "" : tenantOperatorScope;
      const initialSnapshot = await loadSnapshot(
        activation.epoch,
        projection,
        initialSummary,
      );
      fenceRef.current.assertCurrent(activation.epoch);

      const now = Date.now();
      startedAtRef.current = now;
      lastActivityRef.current = now;
      setTenants(tenantPage.tenants);
      setSelectedTenant(projection);
      setSnapshot(initialSnapshot);
      setLastRefresh(new Date().toISOString());
      setSession({
        epoch: activation.epoch,
        siteAdmin,
        tenantOperatorScope,
      });
      setAuthenticating(false);
    } catch (error) {
      if (error instanceof StaleSessionError || error?.name === "AbortError") {
        return;
      }
      lock(error instanceof Error ? error.message : "Authentication failed.");
    } finally {
      cancelAuthenticationDeadline();
    }
  }, [api, loadSnapshot, lock]);

  const refresh = useCallback(async (projection = selectedTenant, quiet = false) => {
    if (!session || refreshing) {
      return;
    }
    const epoch = session.epoch;
    const snapshotGeneration = snapshotFenceRef.current.begin();
    if (!quiet) {
      setRefreshing(true);
    }
    setRefreshError("");
    try {
      const next = await loadSnapshot(epoch, projection);
      fenceRef.current.assertCurrent(epoch);
      snapshotFenceRef.current.assertCurrent(snapshotGeneration);
      setSnapshot(next);
      setLastRefresh(new Date().toISOString());
    } catch (error) {
      if (error instanceof StaleSessionError || error instanceof StaleSnapshotError ||
          error?.name === "AbortError") {
        return;
      }
      if (error instanceof ControlError && error.status === 401) {
        lock("The operator credential was rejected, expired, or revoked.");
        return;
      }
      setRefreshError(error instanceof Error ? error.message : "Refresh failed.");
    } finally {
      if (fenceRef.current.current(epoch) &&
          snapshotFenceRef.current.current(snapshotGeneration)) {
        setRefreshing(false);
      }
    }
  }, [loadSnapshot, lock, refreshing, selectedTenant, session]);

  useEffect(() => {
    if (!session) {
      return undefined;
    }
    const expired = (now) => sessionExpired(
      now,
      startedAtRef.current,
      lastActivityRef.current,
      idleTimeoutMilliseconds,
      absoluteTimeoutMilliseconds,
    );
    const securityTimeout = () => lock("The operator session was locked after its security timeout.");
    const onActivity = (event) => {
      if (event.isTrusted) {
        const now = Date.now();
        if (expired(now)) {
          securityTimeout();
          return;
        }
        lastActivityRef.current = now;
      }
    };
    const onResume = () => {
      if (expired(Date.now())) {
        securityTimeout();
      }
    };
    window.addEventListener("pointerdown", onActivity, {passive: true});
    window.addEventListener("keydown", onActivity);
    window.addEventListener("focus", onResume);
    document.addEventListener("visibilitychange", onResume);
    const timeout = window.setInterval(() => {
      if (expired(Date.now())) {
        securityTimeout();
      }
    }, 10000);
    return () => {
      window.removeEventListener("pointerdown", onActivity);
      window.removeEventListener("keydown", onActivity);
      window.removeEventListener("focus", onResume);
      document.removeEventListener("visibilitychange", onResume);
      window.clearInterval(timeout);
    };
  }, [lock, session]);

  useEffect(() => {
    if (!session) {
      return undefined;
    }
    const timer = window.setInterval(() => {
      if (!document.hidden) {
        refresh(selectedTenant, true);
      }
    }, refreshMilliseconds);
    return () => window.clearInterval(timer);
  }, [refresh, selectedTenant, session]);

  const changeProjection = useCallback((tenantID) => {
    setSelectedTenant(tenantID);
    setSnapshot(null);
    refresh(tenantID);
  }, [refresh]);

  return (
    <>
      <a className="skip-link" href="#main-content">Skip to control room</a>
      <div className="shell">
        <Masthead health={health} clock={clock} />
        <main id="main-content">
          {!session ? (
            <Airlock
              authenticating={authenticating}
              error={loginError}
              onUnlock={authenticate}
            />
          ) : (
            <ControlRoom
              session={session}
              snapshot={snapshot}
              tenants={tenants}
              selectedTenant={selectedTenant}
              view={view}
              refreshing={refreshing}
              refreshError={refreshError}
              lastRefresh={lastRefresh}
              onView={setView}
              onProjection={changeProjection}
              onRefresh={() => refresh()}
              onLock={() => lock("")}
            />
          )}
        </main>
      </div>
    </>
  );
}

function Masthead({health, clock}) {
  return (
    <header className="masthead">
      <a className="brand" href="/console/" aria-label="Steward control room">
        <span className="brand-mark" aria-hidden="true"><span>S</span></span>
        <span>
          <strong>STEWARD</strong>
          <small>CONTROL ROOM</small>
        </span>
      </a>
      <div className="masthead-status" aria-live="polite">
        <span className={"signal signal-" + health.state} aria-hidden="true" />
        <span id="health-label">{health.label}</span>
        <time>{clock}</time>
      </div>
    </header>
  );
}

function Airlock({authenticating, error, onUnlock}) {
  const inputRef = useRef(null);
  const submit = () => {
    const value = inputRef.current?.value || "";
    if (inputRef.current) {
      inputRef.current.value = "";
    }
    onUnlock(value);
  };
  return (
    <section className="airlock" aria-labelledby="airlock-title">
      <div className="airlock-copy">
        <p className="eyebrow">LOCAL OPERATOR ACCESS</p>
        <h1 id="airlock-title">Your fleet stops here.</h1>
        <p className="lede">
          Inspect the control plane without sending fleet data, credentials,
          or telemetry to another service.
        </p>
        <dl className="boundary-list">
          <div><dt>Assets</dt><dd>Embedded. No CDN.</dd></div>
          <div><dt>Credential</dt><dd>Memory only. Never browser storage.</dd></div>
          <div><dt>Authority</dt><dd>Exactly your existing operator scope.</dd></div>
        </dl>
      </div>
      <div className="airlock-panel">
        <div className="panel-index" aria-hidden="true">01 / AUTHORITY</div>
        <label htmlFor="operator-token">Operator bearer credential</label>
        <div className="credential-entry">
          <input
            ref={inputRef}
            id="operator-token"
            name="operator-token"
            type="password"
            maxLength="4096"
            autoComplete="off"
            autoCapitalize="off"
            spellCheck="false"
            aria-describedby="credential-note login-error"
            placeholder="steward_cp_v1…"
            onKeyDown={(event) => {
              if (event.key === "Enter") {
                event.preventDefault();
                submit();
              }
            }}
          />
          <button className="button button-primary" type="button" disabled={authenticating} onClick={submit}>
            {authenticating ? "Authenticating…" : "Enter control room"}
          </button>
        </div>
        <p id="credential-note" className="microcopy">
          The credential is held only in this tab's JavaScript memory. Locking,
          navigating away, 15 minutes of inactivity, or eight hours of use clears
          it. Browser extensions may still read page content; use a hardened
          operator profile.
        </p>
        <p id="login-error" className="error-message" role="alert">{error}</p>
      </div>
    </section>
  );
}

const views = [
  ["overview", "01", "Overview"],
  ["attention", "02", "Attention"],
  ["nodes", "03", "Nodes"],
  ["commands", "04", "Commands"],
  ["credentials", "05", "Credentials"],
];

function ControlRoom(props) {
  const {session, snapshot, tenants, selectedTenant, view, refreshing, refreshError, lastRefresh} = props;
  const attentionCount = snapshot?.summary.attention.total || 0;
  return (
    <section className="control-room">
      <aside className="navigation" aria-label="Control room navigation">
        <div className="authority-card">
          <span className="authority-label">ACTIVE AUTHORITY</span>
          <strong>{session.siteAdmin ? "SITE ADMINISTRATOR" : "TENANT OPERATOR"}</strong>
          <span>
            {session.siteAdmin
              ? "Site-wide projection available"
              : "Tenant " + session.tenantOperatorScope}
          </span>
        </div>
        <nav>
          {views.map(([id, index, label]) => (
            <button
              key={id}
              className={"nav-item" + (view === id ? " is-active" : "")}
              type="button"
              aria-current={view === id ? "page" : undefined}
              onClick={() => props.onView(id)}
            >
              <span>{index}</span> {label}
              {id === "attention" ? <b>{attentionCount}</b> : null}
            </button>
          ))}
        </nav>
        <div className="trust-rail">
          <span>NO CLOUD CALLS</span>
          <span>NO TELEMETRY</span>
          <span>NO TOKEN STORAGE</span>
          <a href="/console/THIRD_PARTY_NOTICES.txt">THIRD-PARTY NOTICES</a>
        </div>
      </aside>
      <div className="workbench">
        <div className="toolbar">
          <div>
            <label htmlFor="tenant-filter">Tenant projection</label>
            <select
              id="tenant-filter"
              value={selectedTenant}
              disabled={!session.siteAdmin || refreshing}
              onChange={(event) => props.onProjection(event.target.value)}
            >
              {session.siteAdmin ? <option value="">Site-wide</option> : null}
              {tenants.map((tenant) => (
                <option key={tenant.tenant_id} value={tenant.tenant_id}>{tenant.tenant_id}</option>
              ))}
            </select>
          </div>
          <div className="toolbar-actions">
            <span className="refresh-time">
              {lastRefresh ? "SYNCED " + lastRefresh.slice(11, 19) + " UTC" : "SYNCING"}
            </span>
            <button className="button button-quiet" type="button" disabled={refreshing} onClick={props.onRefresh}>
              {refreshing ? "Syncing…" : "Refresh"}
            </button>
            <button className="button button-danger" type="button" onClick={props.onLock}>Lock</button>
          </div>
        </div>
        <div className="read-only-boundary">
          <strong>OBSERVE HERE. AUTHORIZE ELSEWHERE.</strong>
          <span>Mutations and private signing material remain in stewardctl and offline operator workflows.</span>
        </div>
        {refreshError ? <div className="flash-message is-error" role="alert">{refreshError}</div> : null}
        {!snapshot ? (
          <div className="loading-state" aria-live="polite">
            <span className="signal signal-pending" />
            Loading the scoped fleet projection…
          </div>
        ) : (
          <>
            {view === "overview" ? <Overview snapshot={snapshot} onAttention={() => props.onView("attention")} /> : null}
            {view === "attention" ? <AttentionView page={snapshot.attention} /> : null}
            {view === "nodes" ? <NodesView page={snapshot.nodes} tenantID={selectedTenant} /> : null}
            {view === "commands" ? <CommandsView page={snapshot.commands} /> : null}
            {view === "credentials" ? <CredentialsView page={snapshot.credentials} /> : null}
          </>
        )}
      </div>
    </section>
  );
}

function Overview({snapshot, onAttention}) {
  const {summary, attention} = snapshot;
  const failures = summary.commands.failed + summary.commands.rejected + summary.commands.outcome_unknown;
  const capacityWarning = summary.capacity.some((item) => item.warning);
  return (
    <section className="view" aria-labelledby="overview-title">
      <ViewHeading eyebrow="LIVE FLEET POSTURE" title="What needs your judgment?">
        Generated {formatTime(summary.generated_at)}
      </ViewHeading>
      <div className="metric-grid">
        <Metric label="Attention" value={summary.attention.total}>
          {summary.attention.critical} critical · {summary.attention.warnings} warnings
        </Metric>
        <Metric label="Active nodes" value={summary.evidence.active_nodes}>
          {summary.evidence.nodes} retained evidence identities
        </Metric>
        <Metric label="Evidence current" value={summary.evidence.current}>
          {summary.evidence.witnessed} witnessed · {summary.evidence.stale} stale
        </Metric>
        <Metric label="Command failures" value={failures}>
          {summary.commands.failed} failed · {summary.commands.outcome_unknown} unknown
        </Metric>
      </div>
      <div className="overview-grid">
        <article className="panel">
          <PanelHeading index="02 / RETAINED STATE" title="Capacity">
            <span className={"status-chip " + (capacityWarning ? "is-warning" : "is-ok")}>
              {capacityWarning ? "REQUIRES ATTENTION" : "WITHIN LIMITS"}
            </span>
          </PanelHeading>
          <div className="capacity-list">
            {summary.capacity.map((capacity) => (
              <div key={capacity.resource} className={"capacity-row" + (capacity.warning ? " is-warning" : "")}>
                <label>{humanize(capacity.resource)}</label>
                <progress
                  max={capacity.limit}
                  value={capacity.used}
                  aria-label={`${humanize(capacity.resource)}: ${capacity.used} of ${capacity.limit}`}
                />
                <span>{capacity.used} / {capacity.limit}</span>
              </div>
            ))}
          </div>
        </article>
        <article className="panel">
          <PanelHeading index="03 / TRUST SIGNALS" title="Evidence posture" />
          <dl className="evidence-list">
            <EvidenceValue label="Witnessed" value={summary.evidence.witnessed} />
            <EvidenceValue label="Unwitnessed" value={summary.evidence.unwitnessed} />
            <EvidenceValue label="Rollback findings" value={summary.evidence.rollback_detected} />
            <EvidenceValue label="Equivocation findings" value={summary.evidence.equivocation_detected} />
          </dl>
        </article>
      </div>
      <article className="panel recent-attention-panel">
        <PanelHeading index="04 / FIRST RESPONSE" title="Highest-priority attention">
          <button className="text-button" type="button" onClick={onAttention}>See all findings →</button>
        </PanelHeading>
        <AttentionList items={attention.items.slice(0, 4)} />
      </article>
    </section>
  );
}

function Metric({label, value, children}) {
  return (
    <article className={"metric" + (label === "Attention" ? " metric-attention" : "")}>
      <span>{label}</span><strong>{value}</strong><small>{children}</small>
    </article>
  );
}

function EvidenceValue({label, value}) {
  return <div><dt>{label}</dt><dd>{value}</dd></div>;
}

function ViewHeading({eyebrow, title, children}) {
  return (
    <div className="view-heading">
      <div><p className="eyebrow">{eyebrow}</p><h2>{title}</h2></div>
      <p>{children}</p>
    </div>
  );
}

function PanelHeading({index, title, children}) {
  return (
    <div className="panel-heading">
      <div><span className="panel-index">{index}</span><h3>{title}</h3></div>
      {children}
    </div>
  );
}

function attentionResource(item) {
  const parts = [item.resource, item.tenant_id, item.node_id, item.command_id, item.capacity_resource].filter(Boolean);
  if (item.used !== undefined && item.limit !== undefined) {
    parts.push(item.used + " / " + item.limit);
  }
  return parts.join(" · ");
}

function AttentionList({items}) {
  if (!items.length) {
    return <p className="empty-state">No attention findings in this projection.</p>;
  }
  return (
    <div className="attention-list">
      {items.map((item) => (
        <article key={item.id} className={"attention-item" + (item.severity === "critical" ? " is-critical" : "")}>
          <span className="attention-marker" />
          <strong className="attention-reason">{humanize(item.reason)}</strong>
          <span className="attention-resource">{attentionResource(item)}</span>
          <time className="attention-since">
            {item.since ? formatTime(item.since) : humanize(item.status || item.state)}
          </time>
        </article>
      ))}
    </div>
  );
}

function AttentionView({page}) {
  return (
    <section className="view" aria-labelledby="attention-title">
      <ViewHeading eyebrow="DERIVED, NOT MUTABLE" title="Operator attention">
        Stable findings calculated from durable state.
      </ViewHeading>
      <AttentionList items={page.items} />
      {page.next_cursor ? <p className="truncation-note">More findings exist. Narrow the tenant projection or use the API cursor.</p> : null}
    </section>
  );
}

function Badge({children, kind = ""}) {
  return <span className={"badge" + (kind ? " " + kind : "")}>{children}</span>;
}

function NodesView({page, tenantID}) {
  return (
    <section className="view" aria-labelledby="nodes-title">
      <ViewHeading eyebrow="ENROLLED EXECUTORS" title="Nodes">
        {tenantID ? "Tenant " + tenantID : "Select one tenant to inspect its nodes."}
      </ViewHeading>
      <TableFrame empty={!tenantID ? "Select one tenant to load nodes." : "No nodes in this tenant."} hasRows={page.nodes.length > 0}>
        <table>
          <thead><tr><th>Node</th><th>State</th><th>Last seen</th><th>Capabilities</th></tr></thead>
          <tbody>
            {page.nodes.map((node) => (
              <tr key={node.node_id}>
                <td><strong>{node.node_id}</strong><small>{node.tenant_ids.join(", ")}</small></td>
                <td><Badge kind={node.state === "active" ? "is-ok" : "is-danger"}>{node.state}</Badge></td>
                <td>{formatTime(node.last_seen_at || node.created_at)}</td>
                <td>
                  <div className="badge-row">
                    {displayStringList(node.capabilities).map((capability) => (
                      <Badge key={capability} kind={capability === "authorized-effects-v1" ? "is-ok" : ""}>
                        {capability}
                      </Badge>
                    ))}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </TableFrame>
    </section>
  );
}

function CommandsView({page}) {
  return (
    <section className="view" aria-labelledby="commands-title">
      <ViewHeading eyebrow="METADATA ONLY" title="Command inventory">
        Signed command bytes and terminal result text stay out of this view.
      </ViewHeading>
      <TableFrame empty="No commands in this projection." hasRows={page.commands.length > 0}>
        <table>
          <thead><tr><th>Command</th><th>Tenant / Node</th><th>State</th><th>Created</th></tr></thead>
          <tbody>
            {page.commands.map((command) => {
              const status = command.terminal_status || command.state;
              const kind = ["failed", "rejected", "outcome_unknown"].includes(status)
                ? "is-danger"
                : status === "done" ? "is-ok" : "is-warning";
              return (
                <tr key={command.id}>
                  <td><strong>{command.id}</strong><small>{command.digest}</small></td>
                  <td><strong>{command.tenant_id}</strong><small>{command.node_id}</small></td>
                  <td><Badge kind={kind}>{status}</Badge></td>
                  <td>{formatTime(command.created_at)}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </TableFrame>
      {page.next_cursor ? <p className="truncation-note">More commands exist. Use the API cursor for the next page.</p> : null}
    </section>
  );
}

function CredentialsView({page}) {
  return (
    <section className="view" aria-labelledby="credentials-title">
      <ViewHeading eyebrow="NON-SECRET RECORDS" title="Credential inventory">
        Bearer values and token message-authentication codes are never returned.
      </ViewHeading>
      <TableFrame empty="No credentials in this projection." hasRows={page.credentials.length > 0}>
        <table>
          <thead><tr><th>Credential</th><th>Kind / Role</th><th>Scope</th><th>State</th></tr></thead>
          <tbody>
            {page.credentials.map((credential) => {
              const scope = credential.tenant_id ||
                (Array.isArray(credential.tenant_ids) ? credential.tenant_ids.join(", ") : "site");
              return (
                <tr key={credential.id}>
                  <td><strong>{credential.id}</strong><small>{formatTime(credential.created_at)}</small></td>
                  <td><strong>{credential.kind}</strong><small>{credential.role || credential.node_id || "—"}</small></td>
                  <td>{scope}</td>
                  <td><Badge kind={credential.revoked ? "is-danger" : "is-ok"}>{credential.revoked ? "revoked" : "active"}</Badge></td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </TableFrame>
      {page.next_cursor ? <p className="truncation-note">More credentials exist. Use the API cursor for the next page.</p> : null}
    </section>
  );
}

function TableFrame({empty, hasRows, children}) {
  return (
    <div className="table-frame">
      {children}
      {!hasRows ? <p className="empty-state">{empty}</p> : null}
    </div>
  );
}
