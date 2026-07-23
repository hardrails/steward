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
import {attentionCommand, attentionGuidance} from "./operator-guidance.js";
import {interactionResponseCommand} from "./interaction-guidance.js";

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

function formatResourceValue(resource, value) {
  if (!Number.isFinite(value) || value < 0) {
    return "unknown";
  }
  if (resource === "memory_bytes") {
    const gibibytes = value / (1024 ** 3);
    if (gibibytes >= 1) {
      return new Intl.NumberFormat(undefined, {maximumFractionDigits: 2}).format(gibibytes) + " GiB";
    }
    return new Intl.NumberFormat(undefined, {maximumFractionDigits: 0}).format(value / (1024 ** 2)) + " MiB";
  }
  if (resource === "cpu_millis") {
    return new Intl.NumberFormat(undefined, {maximumFractionDigits: 2}).format(value / 1000) + " CPU";
  }
  return new Intl.NumberFormat().format(value);
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

  const loadSnapshot = useCallback(async (epoch, tenantID, prefetchedSummary = null, includeSiteResources = false) => {
    const requests = [
      prefetchedSummary || api(projectedPath("/v1/operations/summary", tenantID), epoch),
      api(projectedPath("/v1/operations/attention", tenantID, {limit: 100}), epoch),
      api(projectedPath("/v1/operations/timeline", tenantID, {limit: 100}), epoch),
      api(projectedPath("/v1/operations/agents", tenantID, {limit: 100}), epoch),
      api(projectedPath("/v1/operations/commands", tenantID, {limit: 100}), epoch),
      api(projectedPath("/v1/operations/credentials", tenantID, {limit: 100}), epoch),
      tenantID
        ? api("/v1/tenants/" + encodeURIComponent(tenantID) + "/freeze", epoch)
        : api("/v1/operations/freeze", epoch),
      tenantID
        ? api("/v1/tenants/" + encodeURIComponent(tenantID) + "/nodes?limit=500", epoch)
        : Promise.resolve({nodes: []}),
      tenantID
        ? api("/v1/tenants/" + encodeURIComponent(tenantID) + "/quota", epoch)
        : Promise.resolve(null),
      tenantID
        ? api("/v1/tenants/" + encodeURIComponent(tenantID) + "/instance-events?limit=100", epoch)
        : Promise.resolve({events: []}),
      tenantID
        ? api("/v1/tenants/" + encodeURIComponent(tenantID) + "/tasks?limit=100", epoch)
        : Promise.resolve({tasks: []}),
      tenantID
        ? api("/v1/tenants/" + encodeURIComponent(tenantID) + "/projects?limit=128", epoch)
        : Promise.resolve({projects: []}),
      tenantID
        ? api("/v1/tenants/" + encodeURIComponent(tenantID) + "/interactions?limit=100", epoch)
        : Promise.resolve({interactions: []}),
      tenantID
        ? api("/v1/tenants/" + encodeURIComponent(tenantID) + "/schedules?limit=100", epoch)
        : Promise.resolve({schedules: []}),
      includeSiteResources
        ? api("/v1/node-pools?limit=500", epoch)
        : Promise.resolve({node_pools: []}),
    ];
    const [summary, attention, timeline, agents, commands, credentials, freeze, nodes, quota, events, tasks, projects, interactions, schedules, nodePools] = await Promise.all(requests);
    fenceRef.current.assertCurrent(epoch);
    return {summary, attention, timeline, agents, commands, credentials, freeze, nodes, quota, events, tasks, projects, interactions, schedules, nodePools};
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
        siteAdmin,
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
      const next = await loadSnapshot(epoch, projection, null, session.siteAdmin);
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
  ["inbox", "02", "Agent inbox"],
  ["workrooms", "03", "Workrooms"],
  ["schedules", "04", "Schedules"],
  ["attention", "05", "Needs review"],
  ["incident", "06", "Incident view"],
  ["nodes", "07", "Agent nodes"],
  ["pools", "08", "Node pools"],
  ["commands", "09", "Signed activity"],
  ["credentials", "10", "Access records"],
  ["agents", "11", "Agents"],
  ["tasks", "12", "Fleet tasks"],
  ["events", "13", "Agent signals"],
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
          {views.filter(([id]) => id !== "pools" || session.siteAdmin).map(([id, index, label]) => (
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
          <span>This console can transfer an exact command signed elsewhere. Incident freeze changes, private keys, reusable service credentials, and general mutations stay outside the browser.</span>
        </div>
        {snapshot ? <OperationalFreezeBanner status={snapshot.freeze} tenantID={selectedTenant} /> : null}
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
            {view === "inbox" ? (
              <AgentInboxView page={snapshot.interactions} tenantID={selectedTenant} />
            ) : null}
            {view === "workrooms" ? (
              <WorkroomsView
                page={snapshot.projects}
                tasks={snapshot.tasks}
                interactions={snapshot.interactions}
                schedules={snapshot.schedules}
                tenantID={selectedTenant}
              />
            ) : null}
            {view === "schedules" ? <SchedulesView page={snapshot.schedules} tenantID={selectedTenant} /> : null}
            {view === "attention" ? <AttentionView page={snapshot.attention} /> : null}
            {view === "incident" ? <IncidentTimelineView page={snapshot.timeline} /> : null}
            {view === "nodes" ? <NodesView page={snapshot.nodes} tenantID={selectedTenant} /> : null}
            {view === "pools" ? <NodePoolsView page={snapshot.nodePools} /> : null}
            {view === "commands" ? (
              <CommandsView
                page={snapshot.commands}
                tenantID={selectedTenant}
                onSubmit={props.onSubmitSignedCommand}
              />
            ) : null}
            {view === "credentials" ? <CredentialsView page={snapshot.credentials} /> : null}
            {view === "agents" ? <AgentApplicationsView page={snapshot.agents} tenantID={selectedTenant} /> : null}
            {view === "tasks" ? <TaskProjectionsView page={snapshot.tasks} tenantID={selectedTenant} /> : null}
            {view === "events" ? <InstanceEventsView page={snapshot.events} tenantID={selectedTenant} /> : null}
          </>
        )}
      </div>
    </section>
  );
}

function AgentInboxView({page, tenantID}) {
  const interactions = Array.isArray(page?.interactions) ? page.interactions : [];
  const open = interactions.filter((interaction) => interaction.state === "open").length;
  const waiting = interactions.filter((interaction) => interaction.state === "response_queued").length;
  const resolved = interactions.filter((interaction) => interaction.state === "resolved").length;
  return (
    <section className="view agent-inbox-view" aria-labelledby="agent-inbox-title">
      <ViewHeading id="agent-inbox-title" eyebrow="SIGNED HUMAN-IN-THE-LOOP" title="Questions that can safely wait">
        Running agents can pause for a bounded answer without gaining your key or turning Control into an authority.
      </ViewHeading>
      <aside className="interaction-boundary">
        <strong>THE PROMPT IS UNTRUSTED. YOUR RESPONSE IS EXACTLY BOUND.</strong>
        <span>Read the request as agent-authored content. Steward signs only your selected answer, the request digest, and the exact workload identity. The answer cannot be replayed for another agent or question.</span>
      </aside>
      {!tenantID ? (
        <article className="incident-empty">
          <span className="panel-index">TENANT PROJECTION REQUIRED</span>
          <h3>Select one tenant to open its agent inbox.</h3>
          <p>Questions and decisions remain inside the tenant boundary that admitted the requesting workload.</p>
        </article>
      ) : (
        <>
          <dl className="interaction-totals" aria-label="Agent inbox totals">
            <div className={open ? "is-open" : ""}><dt>Needs answer</dt><dd>{open}</dd></div>
            <div><dt>In delivery</dt><dd>{waiting}</dd></div>
            <div><dt>Resolved</dt><dd>{resolved}</dd></div>
            <div><dt>Retained</dt><dd>{interactions.length}</dd></div>
          </dl>
          {interactions.length ? (
            <ol className="interaction-list">
              {interactions.map((interaction) => (
                <li key={interaction.interaction_id}>
                  <InteractionCard interaction={interaction} />
                </li>
              ))}
            </ol>
          ) : (
            <article className="incident-empty">
              <span className="panel-index">INBOX CLEAR</span>
              <h3>No agent is waiting for a human response.</h3>
              <p>Hermes receives the interaction URL only when its signed capsule includes both controller events and task authorities.</p>
            </article>
          )}
        </>
      )}
      {page?.next_after ? <p className="truncation-note">More questions are retained. Continue with stewardctl or the MCP interaction cursor.</p> : null}
    </section>
  );
}

function InteractionCard({interaction}) {
  const options = Array.isArray(interaction.options) ? interaction.options : [];
  const [choice, setChoice] = useState("");
  const [text, setText] = useState("");
  const [copyState, setCopyState] = useState("idle");
  const [commandError, setCommandError] = useState("");
  const open = interaction.state === "open" &&
    Date.parse(interaction.expires_at) > Date.now();
  const copyCommand = async () => {
    setCommandError("");
    try {
      const command = interactionResponseCommand(interaction, choice, text);
      await navigator.clipboard.writeText(command);
      setCopyState("copied");
      window.setTimeout(() => setCopyState("idle"), 2000);
    } catch (error) {
      if (error instanceof Error && error.name !== "NotAllowedError") {
        setCommandError(error.message);
      } else {
        setCopyState("failed");
      }
    }
  };
  return (
    <article className={"interaction-card is-" + interaction.state}>
      <header>
        <div>
          <span className="interaction-origin">AGENT REQUEST · {humanize(interaction.kind)}</span>
          <h3>{interaction.title}</h3>
        </div>
        <Badge kind={open ? "is-warning" : interaction.state === "resolved" ? "is-ok" : ""}>
          {open ? "needs answer" : humanize(interaction.state)}
        </Badge>
      </header>
      <div className="untrusted-prompt">
        <span>UNTRUSTED AGENT CONTENT</span>
        <p>{interaction.prompt}</p>
      </div>
      <dl className="interaction-binding">
        <div><dt>Agent</dt><dd>{interaction.instance_id} · gen {interaction.generation}</dd></div>
        <div><dt>Node</dt><dd>{interaction.node_id}</dd></div>
        {interaction.task_id ? <div><dt>Task</dt><dd>{interaction.task_id}</dd></div> : null}
        {interaction.project_id ? <div><dt>Workroom</dt><dd>{interaction.project_id}</dd></div> : null}
        <div><dt>Expires</dt><dd>{formatTime(interaction.expires_at)}</dd></div>
        <div><dt>Request</dt><dd><code>{interaction.request_digest.slice(0, 22)}…</code></dd></div>
      </dl>
      {open ? (
        <div className="interaction-response">
          {options.length ? (
            <fieldset>
              <legend>Choose an offered response</legend>
              <div className="interaction-options">
                {options.map((option) => (
                  <label key={option}>
                    <input
                      type="radio"
                      name={"choice-" + interaction.interaction_id}
                      value={option}
                      checked={choice === option}
                      onChange={(event) => setChoice(event.target.value)}
                    />
                    <span>{option}</span>
                  </label>
                ))}
              </div>
            </fieldset>
          ) : null}
          {interaction.allow_text ? (
            <label className="interaction-text">
              <span>{options.length ? "Optional note" : "Your response"}</span>
              <input
                type="text"
                value={text}
                maxLength="2048"
                autoComplete="off"
                spellCheck="true"
                placeholder="One bounded line; never paste a secret"
                onChange={(event) => setText(event.target.value)}
              />
            </label>
          ) : null}
          <div className="interaction-signing-step">
            <div>
              <strong>SIGN OUTSIDE THE BROWSER</strong>
              <span>The command includes only this answer and public workload bindings. Replace the two key placeholders in a trusted terminal.</span>
            </div>
            <button
              className="button button-primary"
              type="button"
              disabled={!choice && !text}
              onClick={copyCommand}
            >
              {copyState === "copied" ? "Command copied" : copyState === "failed" ? "Copy failed" : "Copy signed-response command"}
            </button>
          </div>
          {commandError ? <p className="error-message" role="alert">{commandError}</p> : null}
        </div>
      ) : (
        <div className="interaction-terminal">
          <strong>{interaction.state === "resolved" ? "DELIVERED AND ACKNOWLEDGED BY THE NODE" : humanize(interaction.state).toUpperCase()}</strong>
          <span>{interaction.response_key_id ? "Signed by " + interaction.response_key_id + "." : "No answer content is stored in this operator view."}</span>
        </div>
      )}
    </article>
  );
}

function WorkroomsView({page, tasks, interactions, schedules, tenantID}) {
  const projects = Array.isArray(page?.projects) ? page.projects : [];
  const taskByID = new Map((tasks?.tasks || []).map((task) => [task.task_id, task]));
  const interactionItems = Array.isArray(interactions?.interactions) ? interactions.interactions : [];
  const scheduleItems = Array.isArray(schedules?.schedules) ? schedules.schedules : [];
  const sessionCount = projects.reduce((total, project) => total + project.sessions.length, 0);
  const artifactCount = projects.reduce((total, project) => total + project.artifacts.length, 0);
  const openQuestions = interactionItems.filter((item) => item.state === "open").length;
  const activeSchedules = scheduleItems.filter((item) => item.state === "active").length;
  const activeTasks = projects.reduce((total, project) => (
    total + project.sessions.reduce((sessionTotal, session) => (
      sessionTotal + session.task_ids.filter((taskID) => {
        const state = taskByID.get(taskID)?.state;
        return state && state !== "completed" && state !== "failed" && state !== "rejected";
      }).length
    ), 0)
  ), 0);

  return (
    <section className="view workrooms-view" aria-labelledby="workrooms-title">
      <ViewHeading id="workrooms-title" eyebrow="DURABLE AGENT WORK" title="Research that survives the chat">
        Workrooms join sessions, signed tasks, agent questions, finite schedules, external artifacts, and memory you selected on purpose.
      </ViewHeading>
      <aside className="workroom-principle">
        <span className="workroom-principle-mark" aria-hidden="true">W</span>
        <div>
          <strong>THE PROJECT REMEMBERS. THE AGENT DOES NOT GAIN AUTHORITY.</strong>
          <p>Artifacts stay in storage you control. Steward retains their digest and location, while every consequential task still needs authority signed outside this browser.</p>
        </div>
      </aside>
      <dl className="workroom-totals" aria-label="Workroom totals">
        <div><dt>Projects</dt><dd>{projects.length}</dd></div>
        <div><dt>Sessions</dt><dd>{sessionCount}</dd></div>
        <div><dt>Indexed artifacts</dt><dd>{artifactCount}</dd></div>
        <div className={activeTasks ? "is-live" : ""}><dt>Active tasks</dt><dd>{activeTasks}</dd></div>
        <div className={openQuestions ? "is-live" : ""}><dt>Open questions</dt><dd>{openQuestions}</dd></div>
        <div className={activeSchedules ? "is-live" : ""}><dt>Active schedules</dt><dd>{activeSchedules}</dd></div>
      </dl>
      {!tenantID ? (
        <article className="workroom-empty">
          <span className="panel-index">TENANT PROJECT SPACE</span>
          <h3>Select one tenant to enter its Workrooms.</h3>
          <p>Site-wide authority can inspect fleet posture, but project evidence is always projected through one tenant boundary.</p>
        </article>
      ) : projects.length ? (
        <div className="workroom-board">
          {projects.map((project, projectIndex) => {
            const projectInteractions = interactionItems.filter((item) => item.project_id === project.id);
            const projectSchedules = scheduleItems.filter((item) => item.schedule?.project_id === project.id);
            const activity = [
              ...projectInteractions.map((item) => ({
                id: "interaction-" + item.interaction_id,
                at: item.received_at,
                kind: "AGENT QUESTION · UNTRUSTED TEXT",
                title: item.title,
                state: item.state,
              })),
              ...projectSchedules.flatMap((schedule) => (schedule.runs || []).map((run) => ({
                id: "schedule-" + schedule.schedule.schedule_id + "-" + run.ordinal,
                at: run.created_at,
                kind: "SCHEDULE RUN " + run.ordinal,
                title: run.task_id,
                state: run.state,
              }))),
            ].sort((left, right) => String(right.at).localeCompare(String(left.at))).slice(0, 5);
            return (
            <article className="workroom-card" key={project.id}>
              <header>
                <div>
                  <span className="panel-index">PROJECT {String(projectIndex + 1).padStart(2, "0")} / REV {project.revision}</span>
                  <h3>{project.name}</h3>
                  <code>{project.id}</code>
                </div>
                <Badge kind={project.sessions.some((item) => item.state === "active") ? "is-ok" : ""}>
                  {project.sessions.some((item) => item.state === "active") ? "active" : "archived"}
                </Badge>
              </header>
              <p className="workroom-description">{project.description || "No project description has been retained."}</p>
              <div className="workroom-agent-line">
                <span>DEFAULT AGENT</span>
                <strong>{project.agent_ref || "choose when dispatching"}</strong>
                <span>SKILLS</span>
                <strong>{displayStringList(project.skills).length ? displayStringList(project.skills).join(" · ") : "task-defined"}</strong>
              </div>
              <div className="workroom-session-grid">
                <section aria-label={`${project.name} sessions`}>
                  <h4>Sessions</h4>
                  {project.sessions.length ? (
                    <ol>
                      {project.sessions.map((session) => (
                        <li key={session.id}>
                          <div>
                            <strong>{session.title}</strong>
                            <code>{session.id}</code>
                          </div>
                          <span>{session.task_ids.length} task{session.task_ids.length === 1 ? "" : "s"}</span>
                          <Badge kind={session.state === "active" ? "is-ok" : ""}>{session.state}</Badge>
                        </li>
                      ))}
                    </ol>
                  ) : <p className="workroom-muted">No sessions yet.</p>}
                </section>
                <section aria-label={`${project.name} retained evidence`}>
                  <h4>Evidence index</h4>
                  <dl className="workroom-evidence">
                    <div><dt>Artifacts</dt><dd>{project.artifacts.length}</dd></div>
                    <div><dt>Selected memory</dt><dd>{project.memory_refs.length}</dd></div>
                    <div><dt>Updated</dt><dd>{formatTime(project.updated_at)}</dd></div>
                  </dl>
                </section>
              </div>
              {project.artifacts.length ? (
                <div className="workroom-artifacts">
                  {project.artifacts.slice(-3).reverse().map((artifact) => (
                    <div key={artifact.id}>
                      <span>{artifact.media_type}</span>
                      <strong>{artifact.name}</strong>
                      <code>{artifact.sha256.slice(0, 20)}…</code>
                    </div>
                  ))}
                  {project.artifacts.length > 3 ? <small>+ {project.artifacts.length - 3} more indexed artifacts</small> : null}
                </div>
              ) : null}
              <section className="workroom-activity" aria-label={`${project.name} recent activity`}>
                <h4>Recent activity</h4>
                {activity.length ? (
                  <ol>
                    {activity.map((item) => (
                      <li key={item.id}>
                        <div><span>{item.kind}</span><strong>{item.title}</strong></div>
                        <Badge kind={item.state === "completed" || item.state === "resolved" ? "is-ok" : ""}>{item.state}</Badge>
                        <time>{formatTime(item.at)}</time>
                      </li>
                    ))}
                  </ol>
                ) : <p className="workroom-muted">No retained task questions or schedule runs yet.</p>}
              </section>
              <footer>
                <span>CREATE THE NEXT SESSION</span>
                <code>stewardctl workroom session create {project.id} -tenant-id {tenantID} -id SESSION -title &quot;Research question&quot;</code>
              </footer>
            </article>
            );
          })}
        </div>
      ) : (
        <article className="workroom-empty">
          <span className="panel-index">FIRST PROJECT / TENANT {tenantID}</span>
          <h3>Give long-running work a place to land.</h3>
          <p>Create one project, open a session, then attach signed research tasks. The browser never receives a task-signing key.</p>
          <pre><code>stewardctl workroom create research -tenant-id {tenantID} -description &quot;Evidence-backed market research&quot;</code></pre>
        </article>
      )}
      {page?.next_after ? <p className="truncation-note">More projects exist. Continue with the API or stewardctl workroom cursor.</p> : null}
    </section>
  );
}

function SchedulesView({page, tenantID}) {
  const schedules = Array.isArray(page?.schedules) ? page.schedules : [];
  const active = schedules.filter((schedule) => schedule.state === "active").length;
  const queued = schedules.reduce((total, schedule) => (
    total + (schedule.runs || []).filter((run) => ["queued", "leased", "dispatched", "running"].includes(run.state)).length
  ), 0);
  return (
    <section className="view schedules-view" aria-labelledby="schedules-title">
      <ViewHeading id="schedules-title" eyebrow="FINITE SIGNED AUTOMATION" title="Repeat work without handing over a signing key">
        Every schedule fixes one workload, operation, request, interval, run count, dispatch window, and concurrency ceiling. Control can materialize due runs, but it cannot widen those signed bounds.
      </ViewHeading>
      <aside className="schedule-boundary">
        <strong>CONTROL HOLDS A FINITE ENVELOPE, NOT YOUR TASK KEY.</strong>
        <span>Gateway verifies the tenant signature and exact due run before an agent receives the request. Cancelling a schedule only narrows future authority.</span>
      </aside>
      <dl className="workroom-totals" aria-label="Schedule totals">
        <div><dt>Retained</dt><dd>{schedules.length}</dd></div>
        <div className={active ? "is-live" : ""}><dt>Active</dt><dd>{active}</dd></div>
        <div className={queued ? "is-live" : ""}><dt>Runs in flight</dt><dd>{queued}</dd></div>
      </dl>
      {!tenantID ? (
        <article className="workroom-empty">
          <span className="panel-index">TENANT-SCOPED AUTHORITY</span>
          <h3>Select one tenant to inspect its finite schedules.</h3>
        </article>
      ) : schedules.length ? (
        <div className="schedule-board">
          {schedules.map((item) => {
            const schedule = item.schedule;
            const recentRuns = (item.runs || []).slice(-4).reverse();
            return (
              <article className="schedule-card" key={schedule.schedule_id}>
                <header>
                  <div>
                    <span className="panel-index">NEXT RUN {item.next_ordinal} / {schedule.run_count}</span>
                    <h3>{schedule.schedule_id}</h3>
                    <code>{schedule.service_id} · {schedule.operation_id}</code>
                  </div>
                  <Badge kind={item.state === "active" ? "is-ok" : ""}>{item.state}</Badge>
                </header>
                <dl>
                  <div><dt>First due</dt><dd>{formatTime(schedule.starts_at)}</dd></div>
                  <div><dt>Interval</dt><dd>{schedule.interval_seconds ? formatDurationSeconds(schedule.interval_seconds) : "one time"}</dd></div>
                  <div><dt>Dispatch window</dt><dd>{formatDurationSeconds(schedule.window_seconds)}</dd></div>
                  <div><dt>Concurrency</dt><dd>{schedule.max_concurrency} · {schedule.overlap_policy}</dd></div>
                  <div><dt>Runs</dt><dd>{item.enqueued_runs} queued · {item.skipped_runs} skipped</dd></div>
                  <div><dt>Agent</dt><dd>{schedule.instance_id}</dd></div>
                </dl>
                <section className="schedule-runs">
                  <h4>Recent runs</h4>
                  {recentRuns.length ? recentRuns.map((run) => (
                    <div key={run.ordinal}>
                      <span>#{run.ordinal}</span>
                      <strong>{run.task_id}</strong>
                      <Badge kind={run.state === "completed" ? "is-ok" : ""}>{run.state}</Badge>
                      <time>{formatTime(run.due_at)}</time>
                    </div>
                  )) : <p className="workroom-muted">Waiting for the first signed due time.</p>}
                </section>
                {item.state === "active" ? (
                  <footer>
                    <span>STOP FUTURE RUNS</span>
                    <code>stewardctl task schedule cancel {schedule.schedule_id} -tenant-id {tenantID}</code>
                  </footer>
                ) : null}
              </article>
            );
          })}
        </div>
      ) : (
        <article className="workroom-empty">
          <span className="panel-index">FIRST FINITE SCHEDULE / TENANT {tenantID}</span>
          <h3>Turn a proven prompt into bounded recurring work.</h3>
          <p>The current CLI context supplies Control, trust, and signing paths. You choose the deployment, frequency, and finite run count.</p>
          <pre><code>stewardctl task schedule researcher -every 1h -runs 24 &quot;Check primary sources and report material changes&quot;</code></pre>
        </article>
      )}
      {page?.next_after ? <p className="truncation-note">More schedules exist. Continue with stewardctl task schedule list -after.</p> : null}
    </section>
  );
}

function formatDurationSeconds(value) {
  const seconds = Number(value) || 0;
  if (seconds % 86400 === 0) return `${seconds / 86400}d`;
  if (seconds % 3600 === 0) return `${seconds / 3600}h`;
  if (seconds % 60 === 0) return `${seconds / 60}m`;
  return `${seconds}s`;
}

function OperationalFreezeBanner({status, tenantID}) {
  const effective = status?.effective;
  if (!effective) {
    return (
      <aside className="freeze-banner is-open" aria-label="Command delivery status">
        <div>
          <span className="freeze-kicker">DELIVERY GATE / OPEN</span>
          <strong>New signed commands can be delivered.</strong>
        </div>
        <p>{tenantID ? "No freeze is active for tenant " + tenantID + "." : "No site freeze is active."}</p>
      </aside>
    );
  }
  const scope = effective.scope === "site" ? "THE ENTIRE SITE" : "TENANT " + effective.tenant_id;
  return (
    <aside className="freeze-banner is-frozen" role="status" aria-live="polite">
      <div>
        <span className="freeze-kicker">INCIDENT CONTROL / {effective.scope.toUpperCase()}</span>
        <strong>New command delivery is frozen for {scope}.</strong>
      </div>
      <dl>
        <div><dt>Reason</dt><dd>{effective.reason}</dd></div>
        <div><dt>Since</dt><dd>{formatTime(effective.changed_at)}</dd></div>
        <div><dt>Revision</dt><dd>{effective.revision}</dd></div>
      </dl>
      <p>Heartbeats, terminal reports, and evidence continue. A command already accepted by a node is not instantly revoked; its signed authority and workload lease remain the execution fence.</p>
    </aside>
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
        <Metric label="Active schedules" value={summary.workflows.schedules_active}>
          {summary.workflows.runs_running} running · {summary.workflows.runs_failed} failed
        </Metric>
        <Metric label="Agent questions" value={summary.workflows.interactions_open}>
          {summary.workflows.interactions_queued} awaiting delivery · {summary.workflows.interactions_expired} expired
        </Metric>
      </div>
      {snapshot.quota ? <TenantQuotaPanel status={snapshot.quota} /> : null}
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

const tenantQuotaResources = [
  ["memory_bytes", "Memory"],
  ["cpu_millis", "CPU"],
  ["pids", "Processes"],
  ["workloads", "Agents"],
];

function TenantQuotaPanel({status}) {
  const quota = status.quota;
  const enabled = Boolean(quota?.enabled);
  return (
    <article className={"quota-panel" + (status.over_quota ? " is-over" : "")}>
      <PanelHeading index="01 / TENANT BOUNDARY" title="Fleet-wide resource quota">
        <span className={"status-chip " + (status.over_quota ? "is-danger" : enabled ? "is-ok" : "is-warning")}>
          {status.over_quota ? "OVER QUOTA" : enabled ? "ENFORCED" : "NOT SET"}
        </span>
      </PanelHeading>
      {enabled ? (
        <>
          <p className="quota-explainer">
            Tenant <strong>{status.tenant_id}</strong> cannot win new admission above these combined signed requests across the fleet. Existing work is not evicted when a limit is lowered.
          </p>
          <div className="quota-resource-grid">
            {tenantQuotaResources.map(([resource, label]) => {
              const used = status.usage[resource];
              const limit = quota.resources[resource];
              const exceeded = used > limit;
              return (
                <div key={resource} className={exceeded ? "is-exceeded" : ""}>
                  <span>{label}</span>
                  <strong>{formatResourceValue(resource, used)}</strong>
                  <small>of {formatResourceValue(resource, limit)}</small>
                  <progress max={limit} value={Math.min(used, limit)} aria-label={`${label}: ${used} of ${limit}`} />
                </div>
              );
            })}
          </div>
          <p className="quota-footnote">Revision {quota.revision} · changed {formatTime(quota.changed_at)} · node-local runtime overhead remains separately enforced by Executor.</p>
        </>
      ) : (
        <div className="quota-unset">
          <strong>No tenant-wide ceiling is active.</strong>
          <p>Executor still enforces each node's workload and tenant limits, but this tenant can consume capacity across multiple nodes until a site administrator sets a fleet-wide quota.</p>
          <code>stewardctl control quota set -tenant-id {status.tenant_id} …</code>
        </div>
      )}
    </article>
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
          <p>The scheduler rejects ineligible nodes first, then considers topology spread, tenant-signed label preferences, exact image locality, and current load. A fork stays on the node that owns its snapshot. The selected tenant projection is <strong>{tenant}</strong>.</p>
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

function ViewHeading({id, eyebrow, title, children}) {
  return (
    <div className="view-heading">
      <div><p className="eyebrow">{eyebrow}</p><h2 id={id}>{title}</h2></div>
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
  const parts = [item.resource, item.tenant_id, item.node_id, item.command_id, item.capacity_resource, item.quota_resource].filter(Boolean);
  if (item.used !== undefined && item.limit !== undefined) {
    parts.push(item.used + " / " + item.limit);
  }
  if (item.used_value !== undefined && item.limit_value !== undefined) {
    parts.push(formatResourceValue(item.quota_resource, item.used_value) + " / " + formatResourceValue(item.quota_resource, item.limit_value));
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
        <AttentionCard key={item.id} item={item} />
      ))}
    </div>
  );
}

function AttentionCard({item}) {
  const [copyState, setCopyState] = useState("idle");
  const guidance = attentionGuidance(item);
  const command = attentionCommand(item);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(command);
      setCopyState("copied");
      window.setTimeout(() => setCopyState("idle"), 2000);
    } catch {
      setCopyState("failed");
    }
  };
  return (
    <article className={"attention-item" + (item.severity === "critical" ? " is-critical" : "")}>
      <div className="attention-card-head">
        <span className="attention-marker" aria-hidden="true" />
        <div>
          <span className="attention-code">{item.severity} / {humanize(item.reason)}</span>
          <h3>{guidance.title}</h3>
        </div>
        <time className="attention-since">
          {item.since ? formatTime(item.since) : humanize(item.status || item.state)}
        </time>
      </div>
      <div className="attention-resource">{attentionResource(item)}</div>
      <dl className="attention-guidance">
        <div><dt>What happened</dt><dd>{guidance.explanation}</dd></div>
        <div><dt>What it affects</dt><dd>{guidance.impact}</dd></div>
        <div><dt>Safest next step</dt><dd>{guidance.nextStep}</dd></div>
      </dl>
      <div className="attention-command">
        <code>{command}</code>
        <button className="button button-quiet" type="button" onClick={copy}>
          {copyState === "copied" ? "Copied" : copyState === "failed" ? "Copy failed" : "Copy diagnostic command"}
        </button>
      </div>
    </article>
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

const incidentKindLabels = {
  containment: "Containment",
  evidence: "Evidence",
  access: "Access",
  workload: "Workload",
};

function IncidentTimelineView({page}) {
  const counts = page.events.reduce((result, event) => {
    result[event.kind] = (result[event.kind] || 0) + 1;
    return result;
  }, {});
  return (
    <section className="view incident-view" aria-labelledby="incident-title">
      <ViewHeading eyebrow="CURRENT RETAINED FACTS" title="What changed the risk posture?">
        One chronology for current containment, evidence, access, and failed-workload facts. Metadata only; no prompts, secrets, bodies, or results.
      </ViewHeading>
      <div className="incident-summary" aria-label="Incident fact summary">
        {Object.entries(incidentKindLabels).map(([kind, label]) => (
          <div key={kind}>
            <span>{label}</span>
            <strong>{counts[kind] || 0}</strong>
          </div>
        ))}
      </div>
      <aside className="incident-boundary">
        <strong>THIS IS A CURRENT VIEW, NOT A COMPLETE AUDIT LOG.</strong>
        <span>Later transitions replace earlier retained state. Preserve signed evidence and export historical events to your own SIEM when reconstruction matters.</span>
      </aside>
      {page.events.length ? (
        <ol className="incident-timeline">
          {page.events.map((event) => (
            <li key={event.id} className={`incident-event is-${event.severity}`}>
              <div className="incident-time">
                <time dateTime={event.occurred_at}>{formatTime(event.occurred_at)}</time>
                <span>{event.scope === "site" ? "SITE-WIDE" : event.tenant_id}</span>
              </div>
              <span className="incident-node" aria-hidden="true" />
              <article>
                <div className="incident-event-head">
                  <div>
                    <Badge kind={event.severity === "critical" ? "is-danger" : event.severity === "warning" ? "is-warning" : "is-ok"}>
                      {event.severity}
                    </Badge>
                    <span className="incident-kind">{incidentKindLabels[event.kind] || humanize(event.kind)}</span>
                  </div>
                  <code>{event.id.slice(-10)}</code>
                </div>
                <h3>{humanize(event.action)}</h3>
                {event.reason ? <p>{event.reason}</p> : null}
                <dl>
                  {event.node_id ? <div><dt>Node</dt><dd>{event.node_id}</dd></div> : null}
                  {event.resource_id ? <div><dt>Resource</dt><dd>{event.resource_id}</dd></div> : null}
                  {event.status ? <div><dt>Status</dt><dd>{humanize(event.status)}</dd></div> : null}
                  {event.count ? <div><dt>Observed</dt><dd>{event.count} times</dd></div> : null}
                </dl>
              </article>
            </li>
          ))}
        </ol>
      ) : (
        <article className="incident-empty">
          <span className="panel-index">NO CURRENT INCIDENT FACTS</span>
          <h3>No retained containment or failure state is visible.</h3>
          <p>This does not prove that no incident occurred. It means the current Control projection contains none of the facts represented by this view.</p>
        </article>
      )}
      {page.next_cursor ? <p className="truncation-note">More incident facts exist. Narrow the tenant projection or use the API continuation cursor.</p> : null}
    </section>
  );
}

function InstanceEventsView({page, tenantID}) {
  const events = Array.isArray(page?.events) ? page.events : [];
  return (
    <section className="view agent-signal-view" aria-labelledby="agent-signals-title">
      <ViewHeading id="agent-signals-title" eyebrow="AGENT-REPORTED · IDENTITY-STAMPED" title="Signals from inside the sandbox">
        Status updates and research findings emitted by running agents. Steward binds each signal to its node, runtime, policy, and capsule before it leaves the host.
      </ViewHeading>
      <aside className="signal-boundary">
        <strong>READ AS A CLAIM, NOT AS PROOF.</strong>
        <span>The agent wrote the summary and attributes. These records cannot authorize work, change desired state, or replace Steward's signed evidence chain.</span>
      </aside>
      {!tenantID ? (
        <article className="incident-empty">
          <span className="panel-index">TENANT PROJECTION REQUIRED</span>
          <h3>Select one tenant to read its agent signals.</h3>
          <p>Agent-authored content never crosses tenant projections in the console.</p>
        </article>
      ) : events.length ? (
        <ol className="agent-signal-stream">
          {events.map((retained) => {
            const event = retained.event;
            const attributes = Object.entries(event.attributes || {});
            return (
              <li key={event.event_id} className={`agent-signal is-${event.severity}`}>
                <div className="agent-signal-rail">
                  <span>{event.kind === "finding" ? "FINDING" : "STATUS"}</span>
                  <time dateTime={event.accepted_at}>{formatTime(event.accepted_at)}</time>
                </div>
                <article>
                  <header>
                    <div>
                      <Badge kind={event.severity === "critical" ? "is-danger" : event.severity === "warning" ? "is-warning" : "is-ok"}>
                        {event.severity}
                      </Badge>
                      <code>{event.code}</code>
                    </div>
                    <span>{event.instance_id} · gen {event.generation}</span>
                  </header>
                  <h3>{event.summary}</h3>
                  <dl className="agent-signal-binding">
                    <div><dt>Node</dt><dd>{event.node_id}</dd></div>
                    <div><dt>Runtime</dt><dd><code>{event.runtime_ref.slice(0, 22)}…</code></dd></div>
                    {event.task_id ? <div><dt>Task</dt><dd>{event.task_id}</dd></div> : null}
                    {event.run_id ? <div><dt>Run</dt><dd>{event.run_id}</dd></div> : null}
                  </dl>
                  {attributes.length ? (
                    <dl className="agent-signal-attributes">
                      {attributes.map(([key, value]) => <div key={key}><dt>{humanize(key)}</dt><dd>{value}</dd></div>)}
                    </dl>
                  ) : null}
                </article>
              </li>
            );
          })}
        </ol>
      ) : (
        <article className="incident-empty">
          <span className="panel-index">NO AGENT SIGNALS</span>
          <h3>No running instance has reported a status or finding.</h3>
          <p>Enable the controller-events capability for an agent that needs to publish progress or research results.</p>
        </article>
      )}
      {page?.next_after ? <p className="truncation-note">More signals are retained. Continue with the HTTP API, MCP tool, or stewardctl event cursor.</p> : null}
    </section>
  );
}

const terminalTaskStates = new Set([
  "agent_reported_completed",
  "agent_reported_failed",
  "agent_reported_cancelled",
]);

function TaskProjectionsView({page, tenantID}) {
  const tasks = Array.isArray(page?.tasks) ? page.tasks : [];
  const running = tasks.filter((task) => task.state === "agent_reported_running").length;
  const terminal = tasks.filter((task) => terminalTaskStates.has(task.state)).length;
  const conflicts = tasks.filter((task) => Array.isArray(task.conditions) && task.conditions.length).length;
  return (
    <section className="view fleet-task-view" aria-labelledby="fleet-tasks-title">
      <ViewHeading id="fleet-tasks-title" eyebrow="BOUNDED TASK PROJECTION" title="Work reported across the fleet">
        Follow task-correlated progress and findings without turning agent output into authority.
      </ViewHeading>
      <aside className="signal-boundary">
        <strong>REPORTED STATE · NOT VERIFIED OUTCOME</strong>
        <span>Steward binds every projection to one workload lineage and preserves conflicts. The agent still authored the lifecycle claims and summary.</span>
      </aside>
      {!tenantID ? (
        <article className="incident-empty">
          <span className="panel-index">TENANT PROJECTION REQUIRED</span>
          <h3>Select one tenant to inspect fleet tasks.</h3>
          <p>Task-correlated agent output never crosses tenant projections in this console.</p>
        </article>
      ) : tasks.length ? (
        <>
          <dl className="task-totals" aria-label="Retained task projection totals">
            <div><dt>Retained</dt><dd>{tasks.length}</dd></div>
            <div><dt>Reported running</dt><dd>{running}</dd></div>
            <div><dt>Reported terminal</dt><dd>{terminal}</dd></div>
            <div className={conflicts ? "has-conflict" : ""}><dt>With conflicts</dt><dd>{conflicts}</dd></div>
          </dl>
          <ol className="fleet-task-list">
            {tasks.map((task) => {
              const conditions = Array.isArray(task.conditions) ? task.conditions : [];
              const failed = task.state === "agent_reported_failed";
              const completed = task.state === "agent_reported_completed";
              return (
                <li key={task.projection_id}>
                  <article className={"fleet-task-card" + (conditions.length ? " has-conflict" : "")}>
                    <div className="fleet-task-state">
                      <span>AGENT REPORTED</span>
                      <strong>{humanize(task.state.replace("agent_reported_", ""))}</strong>
                      <div className="task-state-track" aria-hidden="true">
                        <i className={failed ? "is-failed" : completed ? "is-complete" : "is-active"} />
                      </div>
                      <time dateTime={task.last_observed_at}>{formatTime(task.last_observed_at)}</time>
                    </div>
                    <div className="fleet-task-body">
                      <header>
                        <div>
                          <Badge kind={task.highest_severity === "critical" ? "is-danger" : task.highest_severity === "warning" ? "is-warning" : "is-ok"}>
                            peak {task.highest_severity}
                          </Badge>
                          <code>{task.latest_code}</code>
                        </div>
                        <span>{task.instance_id} · gen {task.generation}</span>
                      </header>
                      <p className="fleet-task-id">{task.task_id}</p>
                      <h3>{task.latest_summary}</h3>
                      {conditions.length ? (
                        <aside className="task-conflicts">
                          <strong>CONFLICT PRESERVED</strong>
                          <span>{conditions.map(humanize).join(" · ")}</span>
                        </aside>
                      ) : null}
                      <dl className="fleet-task-facts">
                        <div><dt>Events</dt><dd>{task.event_count}</dd></div>
                        <div><dt>Findings</dt><dd>{task.finding_count}</dd></div>
                        <div><dt>Node</dt><dd>{task.node_id}</dd></div>
                        <div><dt>Run</dt><dd>{task.run_id || "not reported"}</dd></div>
                        <div><dt>Runtime</dt><dd><code>{task.runtime_ref.slice(0, 22)}…</code></dd></div>
                        <div><dt>First seen</dt><dd>{formatTime(task.first_observed_at)}</dd></div>
                      </dl>
                    </div>
                  </article>
                </li>
              );
            })}
          </ol>
        </>
      ) : (
        <article className="incident-empty">
          <span className="panel-index">NO TASK-CORRELATED SIGNALS</span>
          <h3>No retained event includes a task ID.</h3>
          <p>Agents can report bounded progress and findings through the controller-events capability.</p>
        </article>
      )}
      {page?.next_after ? <p className="truncation-note">More task projections are retained. Continue with the HTTP API, MCP tool, or stewardctl task cursor.</p> : null}
    </section>
  );
}

function nodePoolConditionKind(condition) {
  if (condition === "capacity_shortfall") {
    return "is-danger";
  }
  if (condition === "nodes_not_ready" || condition === "membership_unverified" || condition === "scale_in_available") {
    return "is-warning";
  }
  return "";
}

function NodePoolsView({page}) {
  const pools = Array.isArray(page?.node_pools) ? page.node_pools : [];
  const registered = pools.reduce((total, status) => total + status.registered_nodes, 0);
  const eligible = pools.reduce((total, status) => total + status.eligible_nodes, 0);
  const ready = pools.reduce((total, status) => total + status.ready_nodes, 0);
  const scaleOut = pools.reduce((total, status) => total + status.scale_out_needed, 0);
  const scaleIn = pools.reduce((total, status) => total + (status.scale_in_candidates?.length || 0), 0);
  return (
    <section className="view node-pool-view" aria-labelledby="node-pools-title">
      <ViewHeading id="node-pools-title" eyebrow="PROVIDER-NEUTRAL CAPACITY" title="Elastic capacity without ambient authority">
        Reconcile machines through an external driver while Steward preserves exact-node workload authorization and safe drain boundaries.
      </ViewHeading>
      <aside className="signal-boundary">
        <strong>CAPACITY IS NOT PERMISSION.</strong>
        <span>A pool label is only discovery metadata. A configured pool counts a node only after it binds a short-lived statement from the independent membership authority.</span>
      </aside>
      <dl className="task-totals" aria-label="Node pool capacity totals">
        <div><dt>Pools</dt><dd>{pools.length}</dd></div>
        <div><dt>Registered nodes</dt><dd>{registered}</dd></div>
        <div><dt>Eligible / ready</dt><dd>{eligible} / {ready}</dd></div>
        <div className={scaleOut ? "has-conflict" : ""}><dt>Scale out needed</dt><dd>{scaleOut}</dd></div>
      </dl>
      {pools.length ? (
        <div className="pool-board">
          {pools.map((status) => {
            const pool = status.pool;
            const conditions = Array.isArray(status.conditions) ? status.conditions : [];
            const candidates = Array.isArray(status.scale_in_candidates) ? status.scale_in_candidates : [];
            return (
              <article className="pool-card" key={pool.id}>
                <header>
                  <div>
                    <span className="panel-index">NODE POOL / REV {pool.revision} · MEMBERSHIP GEN {pool.membership_generation}</span>
                    <h3>{pool.id}</h3>
                  </div>
                  <Badge kind={conditions.length ? "is-warning" : "is-ok"}>
                    {conditions.length ? "attention" : "at target"}
                  </Badge>
                </header>
                <div className="pool-capacity">
                  <div><span>Eligible</span><strong>{status.eligible_nodes}</strong></div>
                  <div><span>Registered</span><strong>{status.registered_nodes}</strong></div>
                  <div><span>Desired</span><strong>{pool.desired_nodes}</strong></div>
                  <div><span>Maximum</span><strong>{pool.max_nodes}</strong></div>
                </div>
                <progress
                  max={pool.max_nodes}
                  value={Math.min(status.eligible_nodes, pool.max_nodes)}
                  aria-label={`${pool.id}: ${status.eligible_nodes} eligible of ${pool.max_nodes} maximum nodes`}
                />
                <dl className="pool-facts">
                  <div><dt>Tenant scopes</dt><dd>{displayStringList(pool.tenant_ids).join(", ")}</dd></div>
                  <div><dt>Architecture</dt><dd>{pool.architecture || "any reported architecture"}</dd></div>
                  <div><dt>Membership</dt><dd>{pool.membership_key_id || "not required (label accounting)"}</dd></div>
                  <div><dt>Capacity range</dt><dd>{pool.min_nodes} minimum · {pool.desired_nodes} desired · {pool.max_nodes} maximum</dd></div>
                  <div><dt>Observed</dt><dd>{formatTime(status.observed_at)}</dd></div>
                </dl>
                <div className="pool-conditions">
                  {conditions.map((condition) => <Badge key={condition} kind={nodePoolConditionKind(condition)}>{humanize(condition)}</Badge>)}
                  {!conditions.length ? <Badge kind="is-ok">capacity healthy</Badge> : null}
                </div>
                {status.scale_out_needed ? (
                  <p className="pool-action"><strong>CREATE {status.scale_out_needed}</strong> The provider driver may create exactly this many machines, then complete finite enrollment and bind independent membership.</p>
                ) : null}
                {candidates.length ? (
                  <div className="pool-candidates">
                    <strong>{candidates.length} POST-DRAIN SCALE-IN CANDIDATE{candidates.length === 1 ? "" : "S"}</strong>
                    {candidates.map((nodeID) => <code key={nodeID}>{nodeID}</code>)}
                  </div>
                ) : null}
              </article>
            );
          })}
        </div>
      ) : (
        <article className="incident-empty">
          <span className="panel-index">NO CAPACITY INTENT RETAINED</span>
          <h3>Define a provider-neutral node pool from a trusted terminal.</h3>
          <p>Control will report creation deficits and only post-drain, empty-node scale-in candidates. It will not receive cloud credentials.</p>
          <pre><code>stewardctl control node-pool apply -pool-id agents -tenant-ids TENANT -min-nodes 1 -desired-nodes 2 -max-nodes 10</code></pre>
        </article>
      )}
      {page?.next_after ? <p className="truncation-note">More node pools exist. Continue with the HTTP API or stewardctl node-pool cursor.</p> : null}
      {scaleIn ? <p className="truncation-note">{scaleIn} drained, empty node{scaleIn === 1 ? " is" : "s are"} eligible for exact provider removal.</p> : null}
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
  const cachedImages = observation.cached_image_config_digests;
  return (
    <div>
      <Badge kind="is-ok">reported</Badge>
      <small>{observation.isolation} · {observation.architecture}</small>
      <small>{host.workloads} host slots · {tenant.workloads}/tenant</small>
      <small>{Array.isArray(cachedImages) ? `${cachedImages.length} cached image${cachedImages.length === 1 ? "" : "s"} reported` : "Image locality not reported"}</small>
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
      {drain ? <Badge kind={drain.state === "failed" ? "is-danger" : drain.state === "active" ? "is-warning" : ""}>drain {drain.state}</Badge> : null}
      {placement?.reason ? <small>{placement.reason}</small> : <small>Accepting eligible work.</small>}
      {drain ? <small>{drain.reason} · request {drain.request_id}</small> : null}
      {drain?.failed_instance_id ? <small>Stopped at instance {drain.failed_instance_id}; inspect the degraded deployment.</small> : null}
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
