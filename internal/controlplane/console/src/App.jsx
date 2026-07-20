import React, {useCallback, useEffect, useRef, useState} from "react";

import {
  commandConfirmation,
  commandReviewCurrent,
  decodeSignedCommand,
} from "./command-courier.js";
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
  const [tenantCursor, setTenantCursor] = useState("");
  const [loadingTenants, setLoadingTenants] = useState(false);
  const [tenantError, setTenantError] = useState("");
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
    setTenantCursor("");
    setLoadingTenants(false);
    setTenantError("");
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

  const api = useCallback(async (path, epoch, options = {}) => {
    const fence = fenceRef.current;
    const signal = fence.signal(epoch);
    const url = new URL(path, window.location.origin);
    if (url.origin !== window.location.origin || !url.pathname.startsWith("/v1/")) {
      throw new Error("Console API path escaped the local control origin.");
    }
    const method = options.method || "GET";
    const commandSubmission = method === "POST" && url.search === "" &&
      /^\/v1\/tenants\/[^/]+\/nodes\/[^/]+\/commands$/u.test(url.pathname);
    if (method !== "GET" && !commandSubmission) {
      throw new Error("The console attempted an unsupported mutation.");
    }
    const headers = new Headers();
    headers.set("Authorization", "Bearer " + (options.credential || credentialRef.current));
    if (commandSubmission) {
      headers.set("Content-Type", "application/json");
    }
    const response = await fetch(url, {
      method,
      headers,
      body: commandSubmission ? options.body : undefined,
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
      api(projectedPath("/v1/operations/agents", tenantID, {limit: 100}), epoch),
      api(projectedPath("/v1/operations/commands", tenantID, {limit: 100}), epoch),
      api(projectedPath("/v1/operations/credentials", tenantID, {limit: 100}), epoch),
      tenantID
        ? api("/v1/tenants/" + encodeURIComponent(tenantID) + "/nodes?limit=500", epoch)
        : Promise.resolve({nodes: []}),
    ];
    const [summary, attention, agents, commands, credentials, nodes] = await Promise.all(requests);
    fenceRef.current.assertCurrent(epoch);
    return {summary, attention, agents, commands, credentials, nodes};
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
      setTenantCursor(tenantPage.next_after || "");
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

  const loadMoreTenants = useCallback(async () => {
    if (!session?.siteAdmin || !tenantCursor || loadingTenants) {
      return;
    }
    const epoch = session.epoch;
    setLoadingTenants(true);
    setTenantError("");
    try {
      const tenantPage = await api(projectedPath("/v1/tenants", "", {
        after: tenantCursor,
        limit: 500,
      }), epoch);
      fenceRef.current.assertCurrent(epoch);
      setTenants((current) => {
        const known = new Set(current.map((tenant) => tenant.tenant_id));
        return current.concat(tenantPage.tenants.filter((tenant) => !known.has(tenant.tenant_id)));
      });
      setTenantCursor(tenantPage.next_after || "");
    } catch (error) {
      if (error instanceof StaleSessionError || error?.name === "AbortError") {
        return;
      }
      if (error instanceof ControlError && error.status === 401) {
        lock("The operator credential was rejected, expired, or revoked.");
        return;
      }
      setTenantError(error instanceof Error ? error.message : "The next tenant page could not be loaded.");
    } finally {
      if (fenceRef.current.current(epoch)) {
        setLoadingTenants(false);
      }
    }
  }, [api, loadingTenants, lock, session, tenantCursor]);

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

  const submitSignedCommand = useCallback(async (preview, reenteredCredential) => {
    if (!session || !selectedTenant) {
      throw new Error("Select one tenant before submitting a signed command.");
    }
    if (preview.statement.tenant_id !== selectedTenant) {
      throw new Error("The signed tenant does not match the active tenant projection.");
    }
    if (!reenteredCredential || reenteredCredential !== credentialRef.current) {
      throw new Error("The re-entered operator credential does not match this session.");
    }
    if (!commandReviewCurrent(preview)) {
      throw new Error("The signed command or its five-minute review window has expired. Load it again.");
    }
    const path = "/v1/tenants/" + encodeURIComponent(preview.statement.tenant_id) +
      "/nodes/" + encodeURIComponent(preview.statement.node_id) + "/commands";
    const command = await api(path, session.epoch, {
      method: "POST",
      credential: reenteredCredential,
      body: JSON.stringify({command_dsse_base64: preview.envelopeBase64}),
    });
    await refresh(selectedTenant);
    return command;
  }, [api, refresh, selectedTenant, session]);

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
              tenantCursor={tenantCursor}
              loadingTenants={loadingTenants}
              tenantError={tenantError}
              selectedTenant={selectedTenant}
              view={view}
              refreshing={refreshing}
              refreshError={refreshError}
              lastRefresh={lastRefresh}
              onView={setView}
              onProjection={changeProjection}
              onLoadMoreTenants={loadMoreTenants}
              onRefresh={() => refresh()}
              onSubmitSignedCommand={submitSignedCommand}
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
          <small>AGENT AUTHORITY</small>
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
        <h1 id="airlock-title">See what your agents can actually do.</h1>
        <p className="lede">
          Inspect nodes, external-action authority, failures, and signed evidence
          without sending fleet data, credentials, or telemetry to another service.
        </p>
        <dl className="boundary-list">
          <div><dt>Assets</dt><dd>Embedded. No CDN.</dd></div>
          <div><dt>Credential</dt><dd>Memory only. Never browser storage.</dd></div>
          <div><dt>Access</dt><dd>Limited to your existing operator scope.</dd></div>
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
  ["overview", "01", "Fleet health"],
  ["attention", "02", "Needs review"],
  ["nodes", "03", "Agent nodes"],
  ["commands", "04", "Signed activity"],
  ["credentials", "05", "Access records"],
  ["agents", "06", "Agents"],
];

function ControlRoom(props) {
  const {
    session,
    snapshot,
    tenants,
    tenantCursor,
    loadingTenants,
    tenantError,
    selectedTenant,
    view,
    refreshing,
    refreshError,
    lastRefresh,
  } = props;
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
            {session.siteAdmin && tenantCursor ? (
              <button
                className="button button-quiet tenant-page-button"
                type="button"
                disabled={loadingTenants}
                onClick={props.onLoadMoreTenants}
              >
                {loadingTenants ? "Loading…" : "Load 500 more"}
              </button>
            ) : null}
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
          <strong>OBSERVE HERE. AUTHORIZE WITH YOUR KEYS.</strong>
          <span>This console can transfer an exact command signed elsewhere. Private keys, reusable service credentials, and general mutations stay outside the browser.</span>
        </div>
        {tenantError ? <div className="flash-message is-error" role="alert">{tenantError}</div> : null}
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
            {view === "commands" ? (
              <CommandsView
                page={snapshot.commands}
                tenantID={selectedTenant}
                onSubmit={props.onSubmitSignedCommand}
              />
            ) : null}
            {view === "credentials" ? <CredentialsView page={snapshot.credentials} /> : null}
            {view === "agents" ? <AgentApplicationsView page={snapshot.agents} tenantID={selectedTenant} /> : null}
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
      <ViewHeading eyebrow="LIVE FLEET POSTURE" title="What needs your attention?">
        Generated {formatTime(summary.generated_at)}
      </ViewHeading>
      <div className="metric-grid">
        <Metric label="Needs review" value={summary.attention.total}>
          {summary.attention.critical} critical · {summary.attention.warnings} warnings
        </Metric>
        <Metric label="Active nodes" value={summary.evidence.active_nodes}>
          {summary.evidence.nodes} retained evidence identities
        </Metric>
        <Metric label="Current evidence" value={summary.evidence.current}>
          {summary.evidence.witnessed} witnessed · {summary.evidence.stale} stale
        </Metric>
        <Metric label="Failed actions" value={failures}>
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
          <PanelHeading index="03 / TRUST SIGNALS" title="Evidence health" />
          <dl className="evidence-list">
            <EvidenceValue label="Witnessed" value={summary.evidence.witnessed} />
            <EvidenceValue label="Unwitnessed" value={summary.evidence.unwitnessed} />
            <EvidenceValue label="Rollback findings" value={summary.evidence.rollback_detected} />
            <EvidenceValue label="Equivocation findings" value={summary.evidence.equivocation_detected} />
          </dl>
        </article>
      </div>
      <article className="panel recent-attention-panel">
        <PanelHeading index="04 / FIRST RESPONSE" title="Review first">
          <button className="text-button" type="button" onClick={onAttention}>See all findings →</button>
        </PanelHeading>
        <AttentionList items={attention.items.slice(0, 4)} />
      </article>
    </section>
  );
}

function Metric({label, value, children}) {
  return (
    <article className={"metric" + (label === "Needs review" ? " metric-attention" : "")}>
      <span>{label}</span><strong>{value}</strong><small>{children}</small>
    </article>
  );
}

function EvidenceValue({label, value}) {
  return <div><dt>{label}</dt><dd>{value}</dd></div>;
}

function agentStatusKind(agent) {
  if (["failed", "rejected", "outcome_unknown"].includes(agent.latest_terminal_status)) {
    return "is-danger";
  }
  if (["pending", "leased"].includes(agent.latest_command_state) || agent.observed_status === "unknown") {
    return "is-warning";
  }
  return agent.observed_status === "running" ? "is-ok" : "";
}

function AgentApplicationsView({page, tenantID}) {
  const tenant = tenantID || "site-wide";
  const running = page.agents.filter((agent) => agent.observed_status === "running").length;
  const inFlight = page.agents.filter((agent) => ["pending", "leased"].includes(agent.latest_command_state)).length;
  const degraded = page.agents.filter((agent) => ["failed", "rejected", "outcome_unknown"].includes(agent.latest_terminal_status)).length;
  return (
    <section className="view" aria-labelledby="agent-applications-title">
      <ViewHeading eyebrow="SIGNED RUNTIME OBSERVATIONS" title="Your agent fleet, without guesswork.">
        Last successful workload state and latest signed operation for the {tenant} projection. This is observed state, not desired state.
      </ViewHeading>
      <div className="agent-tally" aria-label="Agent fleet summary">
        <div><strong>{page.agents.length}</strong><span>observed runtimes</span></div>
        <div><strong>{running}</strong><span>running</span></div>
        <div><strong>{inFlight}</strong><span>operations in flight</span></div>
        <div className={degraded ? "is-degraded" : ""}><strong>{degraded}</strong><span>latest operations failed</span></div>
      </div>
      {page.agents.length ? (
        <div className="agent-board">
          {page.agents.map((agent) => (
            <article className="agent-card" key={`${agent.tenant_id}/${agent.node_id}/${agent.runtime_ref}/${agent.instance_generation}`}>
              <div className="agent-card-head">
                <div>
                  <span className="panel-index">{agent.service_id || "AGENT RUNTIME"}</span>
                  <h3>{agent.latest_command_kind || "observed"}</h3>
                </div>
                <Badge kind={agentStatusKind(agent)}>{agent.observed_status}</Badge>
              </div>
              <dl className="agent-facts">
                <div><dt>Tenant / node</dt><dd>{agent.tenant_id} / {agent.node_id}</dd></div>
                <div><dt>Generation</dt><dd>{agent.instance_generation}</dd></div>
                <div className="agent-runtime"><dt>Runtime</dt><dd>{agent.runtime_ref}</dd></div>
                <div><dt>Latest signed operation</dt><dd>{agent.latest_command_kind} · {agent.latest_terminal_status || agent.latest_command_state}</dd></div>
                <div><dt>Last activity</dt><dd>{formatTime(agent.updated_at)}</dd></div>
              </dl>
              <div className="agent-capabilities">
                {displayStringList(agent.egress_route_ids).map((route) => <Badge key={`egress-${route}`}>egress:{route}</Badge>)}
                {displayStringList(agent.connector_ids).map((connector) => <Badge key={`connector-${connector}`}>connector:{connector}</Badge>)}
                {!agent.egress_route_ids?.length && !agent.connector_ids?.length ? <span>No delegated routes observed</span> : null}
              </div>
              {["failed", "rejected", "outcome_unknown"].includes(agent.latest_terminal_status) ? (
                <p className="agent-warning">The latest {agent.latest_command_kind} operation {humanize(agent.latest_terminal_status)}. The status above is the last successful workload observation.</p>
              ) : null}
            </article>
          ))}
        </div>
      ) : (
        <article className="agent-empty">
          <span className="panel-index">NO SIGNED RUNTIMES OBSERVED</span>
          <h3>Deploy the first agent from a trusted terminal.</h3>
          <p>Steward will show it here after Executor verifies signed admission and reports a bounded runtime observation.</p>
        </article>
      )}
      {page.next_cursor ? <p className="truncation-note">More agents exist. Narrow the tenant projection or use the API continuation cursor.</p> : null}
      <div className="overview-grid">
        <article className="panel">
          <PanelHeading index="01 / DEFINE" title="Create an agent" />
          <p>Choose the reasoning runtime while Steward fixes the image, skills, model route, resources, state, lifetime, and isolation requirements.</p>
          <pre><code>{`stewardctl agent init -runtime hermes -name my-agent my-agent
stewardctl agent build -file my-agent/Stewardfile.cue`}</code></pre>
        </article>
        <article className="panel">
          <PanelHeading index="02 / PLACE" title="Explain placement" />
          <p>The scheduler rejects ineligible nodes first, then scores image and snapshot locality, preferred labels, and current load. The selected tenant projection is <strong>{tenant}</strong>.</p>
          <pre><code>{`stewardctl agent plan -bundle agent.bundle.json \\
  -nodes nodes.json -tenant ${tenant}`}</code></pre>
        </article>
      </div>
      <article className="panel recent-attention-panel">
        <PanelHeading index="03 / AUTHORITY" title="Placement is not permission" />
        <p>A bundle and placement decision cannot start a workload. Tenant-signed commands and Executor admission still verify the exact node, image, generation, policy, and capability boundary. Private keys and reusable credentials never enter this console.</p>
      </article>
    </section>
  );
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
      <ViewHeading eyebrow="DERIVED, NOT MUTABLE" title="Needs review">
        Findings computed from retained records and current node observations. This view does not change fleet state.
      </ViewHeading>
      <AttentionList items={page.items} />
      {page.next_cursor ? <p className="truncation-note">More findings exist. Narrow the tenant projection or use the API cursor.</p> : null}
    </section>
  );
}

function Badge({children, kind = ""}) {
  return <span className={"badge" + (kind ? " " + kind : "")}>{children}</span>;
}

function NodeScheduling({scheduling}) {
  if (!scheduling?.observation?.policy?.host) {
    return <div><Badge kind="is-warning">not reported</Badge><small>New placement pauses.</small></div>;
  }
  const observation = scheduling.observation;
  const host = observation.policy.host;
  const tenant = observation.policy.tenant;
  return (
    <div>
      <Badge kind="is-ok">reported</Badge>
      <small>{observation.isolation} · {observation.architecture}</small>
      <small>{host.workloads} host slots · {tenant.workloads}/tenant</small>
      <small>Observed {formatTime(scheduling.observed_at)}</small>
    </div>
  );
}

function NodePlacement({placement, drain}) {
  const mode = placement?.mode || "schedulable";
  const kind = mode === "quarantined" ? "is-danger" : mode === "cordoned" ? "is-warning" : "is-ok";
  return (
    <div>
      <Badge kind={kind}>{mode}</Badge>
	  {drain ? <Badge kind={drain.state === "active" ? "is-warning" : ""}>drain {drain.state}</Badge> : null}
      {placement?.reason ? <small>{placement.reason}</small> : <small>Accepting eligible work.</small>}
	  {drain ? <small>{drain.reason} · request {drain.request_id}</small> : null}
      {placement?.changed_at ? <small>In state since {formatTime(placement.changed_at)}</small> : null}
    </div>
  );
}

function NodesView({page, tenantID}) {
  return (
    <section className="view" aria-labelledby="nodes-title">
      <ViewHeading eyebrow="ENROLLED EXECUTORS" title="Agent nodes">
        {tenantID ? "Tenant " + tenantID : "Select one tenant to inspect its nodes."}
      </ViewHeading>
      <TableFrame empty={!tenantID ? "Select one tenant to load nodes." : "No nodes in this tenant."} hasRows={page.nodes.length > 0}>
        <table>
          <thead><tr><th>Node</th><th>State</th><th>Placement</th><th>Last seen</th><th>Capacity</th><th>Capabilities</th></tr></thead>
          <tbody>
            {page.nodes.map((node) => (
              <tr key={node.node_id}>
                <td><strong>{node.node_id}</strong><small>{node.tenant_ids.join(", ")}</small></td>
                <td><Badge kind={node.state === "active" ? "is-ok" : "is-danger"}>{node.state}</Badge></td>
                <td><NodePlacement placement={node.placement} drain={node.drain} /></td>
                <td>{formatTime(node.last_seen_at || node.created_at)}</td>
                <td><NodeScheduling scheduling={node.scheduling} /></td>
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
      {page.next_after ? <p className="truncation-note">More nodes exist. Use the API continuation cursor for the next page.</p> : null}
    </section>
  );
}

function CommandsView({page, tenantID, onSubmit}) {
  const fileInputRef = useRef(null);
  const credentialInputRef = useRef(null);
  const reviewGenerationRef = useRef(0);
  const [preview, setPreview] = useState(null);
  const [fileName, setFileName] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [error, setError] = useState("");
  const [result, setResult] = useState("");
  const [submitting, setSubmitting] = useState(false);

  const clearReview = useCallback(() => {
    reviewGenerationRef.current += 1;
    setPreview(null);
    setFileName("");
    setConfirmation("");
    setError("");
    if (fileInputRef.current) {
      fileInputRef.current.value = "";
    }
    if (credentialInputRef.current) {
      credentialInputRef.current.value = "";
    }
  }, []);

  useEffect(() => {
    clearReview();
    setResult("");
  }, [clearReview, tenantID]);

  const loadFile = async (event) => {
    const file = event.target.files?.[0];
    const generation = reviewGenerationRef.current + 1;
    reviewGenerationRef.current = generation;
    setPreview(null);
    setFileName("");
    setConfirmation("");
    setError("");
    setResult("");
    if (!file) {
      return;
    }
    try {
      const loaded = await decodeSignedCommand(await file.arrayBuffer());
      if (reviewGenerationRef.current !== generation) {
        return;
      }
      if (!tenantID) {
        throw new Error("Select one tenant before reviewing a signed command.");
      }
      if (loaded.statement.tenant_id !== tenantID) {
        throw new Error("The signed tenant does not match the active tenant projection.");
      }
      setPreview(loaded);
      setFileName(file.name);
    } catch (loadError) {
      if (reviewGenerationRef.current !== generation) {
        return;
      }
      setError(loadError instanceof Error ? loadError.message : "The signed command could not be read.");
      if (fileInputRef.current) {
        fileInputRef.current.value = "";
      }
    }
  };

  const submit = async () => {
    setError("");
    setResult("");
    if (!preview || !commandReviewCurrent(preview)) {
      setError("The signed command or its five-minute review window has expired. Load it again.");
      return;
    }
    if (confirmation !== commandConfirmation(preview.statement.command_id)) {
      setError("Type the exact confirmation phrase before submission.");
      return;
    }
    const credential = credentialInputRef.current?.value || "";
    if (credentialInputRef.current) {
      credentialInputRef.current.value = "";
    }
    setSubmitting(true);
    try {
      const accepted = await onSubmit(preview, credential);
      setResult("Controller queued " + accepted.id + " in state " + accepted.state + ". Executor verification is still pending.");
      clearReview();
    } catch (submitError) {
      setError(submitError instanceof Error ? submitError.message : "The command submission failed closed.");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <section className="view" aria-labelledby="commands-title">
      <ViewHeading eyebrow="OFFLINE-SIGNED COMMAND" title="Transfer a signed action">
        Load a command signed outside this browser, compare its exact digest with the signing station, and submit the unchanged file.
      </ViewHeading>
      <div className="command-courier">
        <div className="courier-intake">
          <span className="panel-index">01 / LOAD</span>
          <label htmlFor="signed-command-file">Signed Executor command</label>
          <input
            ref={fileInputRef}
            id="signed-command-file"
            type="file"
            accept=".json,application/json"
            disabled={!tenantID || submitting}
            onChange={loadFile}
          />
          <p className="microcopy">
            One signed command JSON file, at most 750 KiB. This preview does not verify the signature.
            The controller checks scope and route; Executor verifies signature authority.
          </p>
          {!tenantID ? <p className="error-message">Select one tenant to enable command transfer.</p> : null}
        </div>
        {preview ? (
          <div className="courier-review">
            <div className="courier-verification">
              <span>UNVERIFIED LOCAL PREVIEW</span>
              <strong>Compare this digest with the offline signing station.</strong>
            </div>
            <dl className="courier-facts">
              <div className="courier-digest"><dt>Exact file SHA-256</dt><dd>{preview.digest}</dd></div>
              <div><dt>File</dt><dd>{fileName} · {preview.byteLength.toLocaleString()} bytes</dd></div>
              <div><dt>Command</dt><dd>{preview.statement.command_id}</dd></div>
              <div><dt>Operation</dt><dd>{preview.statement.kind}</dd></div>
              <div><dt>Tenant / node</dt><dd>{preview.statement.tenant_id} / {preview.statement.node_id}</dd></div>
              <div><dt>Instance</dt><dd>{preview.statement.instance_id}</dd></div>
              <div><dt>Runtime</dt><dd>{preview.statement.runtime_ref}</dd></div>
              <div><dt>Replay protections</dt><dd>claim generation {preview.statement.claim_generation} · instance generation {preview.statement.instance_generation} · command sequence {preview.statement.command_sequence}</dd></div>
              <div><dt>Issued</dt><dd>{formatTime(preview.statement.issued_at)}</dd></div>
              <div><dt>Expires</dt><dd>{formatTime(preview.statement.expires_at)}</dd></div>
              <div><dt>Signature key IDs</dt><dd>{preview.keyIDs.join(", ")}</dd></div>
            </dl>
            <div className="courier-confirmation">
              <span className="panel-index">02 / REAUTHENTICATE</span>
              <label htmlFor="command-confirmation">
                Type <code>{commandConfirmation(preview.statement.command_id)}</code>
              </label>
              <input
                id="command-confirmation"
                value={confirmation}
                maxLength={preview.statement.command_id.length + 7}
                autoComplete="off"
                spellCheck="false"
                disabled={submitting}
                onChange={(event) => setConfirmation(event.target.value)}
              />
              <label htmlFor="command-credential">Re-enter the current operator bearer</label>
              <input
                ref={credentialInputRef}
                id="command-credential"
                type="password"
                maxLength="4096"
                autoComplete="off"
                autoCapitalize="off"
                spellCheck="false"
                disabled={submitting}
              />
              <div className="courier-actions">
                <button className="button button-primary" type="button" disabled={submitting} onClick={submit}>
                  {submitting ? "Submitting exact bytes…" : "Submit signed command"}
                </button>
                <button className="button button-quiet" type="button" disabled={submitting} onClick={clearReview}>Clear</button>
              </div>
            </div>
          </div>
        ) : null}
        {error ? <p className="flash-message is-error" role="alert">{error}</p> : null}
        {result ? <p className="flash-message is-success" role="status">{result}</p> : null}
      </div>
      <ViewHeading eyebrow="RETAINED METADATA" title="Signed activity">
        Signed command bytes and terminal result text are not returned by this view.
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
      <ViewHeading eyebrow="NON-SECRET RECORDS" title="Access records">
        Review who can call Steward. Bearer values and token message-authentication codes are never returned.
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
