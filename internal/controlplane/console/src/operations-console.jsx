import React, {useEffect, useRef, useState} from "react";

import {
  canonicalID,
  deploymentReplicaCount,
  fileBase64,
  requestID,
  splitIDs,
} from "./console-api.js";

function asInteger(value, label, minimum = 0, maximum = Number.MAX_SAFE_INTEGER) {
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number < minimum || number > maximum) {
    throw new Error(`${label} must be a whole number from ${minimum.toLocaleString()} to ${maximum.toLocaleString()}.`);
  }
  return number;
}

function ActionFeedback({state}) {
  if (!state?.message) {
    return null;
  }
  return (
    <p className={"action-feedback " + (state.kind === "error" ? "is-error" : "is-success")} role={state.kind === "error" ? "alert" : "status"}>
      {state.message}
    </p>
  );
}

function OperatorAction({title, description, danger = false, children, onSubmit, submitLabel = "Apply change"}) {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [feedback, setFeedback] = useState(null);
  const submit = async (event) => {
    event.preventDefault();
    setBusy(true);
    setFeedback(null);
    try {
      const message = await onSubmit(new FormData(event.currentTarget));
      setFeedback({kind: "success", message: message || "The change was accepted."});
      setOpen(false);
    } catch (error) {
      setFeedback({kind: "error", message: error instanceof Error ? error.message : "The change failed closed."});
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className={"operator-action" + (danger ? " is-danger" : "")}>
      <button className={"button " + (danger ? "button-danger" : "button-quiet")} type="button" aria-expanded={open} onClick={() => setOpen((current) => !current)}>
        {open ? "Close" : title}
      </button>
      {open ? (
        <form className="action-form" onSubmit={submit}>
          <strong>{title}</strong>
          <p>{description}</p>
          {children}
          <div className="action-form-buttons">
            <button className={"button " + (danger ? "button-danger" : "button-primary")} type="submit" disabled={busy}>
              {busy ? "Applying…" : submitLabel}
            </button>
            <button className="button button-quiet" type="button" disabled={busy} onClick={() => setOpen(false)}>Cancel</button>
          </div>
        </form>
      ) : null}
      <ActionFeedback state={feedback} />
    </div>
  );
}

function OneTimeSecret({result, onClear}) {
  if (!result) {
    return null;
  }
  const secret = result.token || result.credential || result.enrollment_token || "";
  return (
    <aside className="one-time-secret" aria-live="polite">
      <span>ONE-TIME OUTPUT</span>
      <strong>Save this value now. Steward will not show it again.</strong>
      <textarea value={secret} readOnly rows="4" spellCheck="false" aria-label="One-time credential" />
      <dl>
        {result.credential_id ? <div><dt>Credential</dt><dd>{result.credential_id}</dd></div> : null}
        {result.enrollment_id ? <div><dt>Enrollment</dt><dd>{result.enrollment_id}</dd></div> : null}
        {result.expires_at ? <div><dt>Expires</dt><dd>{result.expires_at}</dd></div> : null}
      </dl>
      <button className="button button-quiet" type="button" onClick={onClear}>Clear from page</button>
    </aside>
  );
}

function downloadJSON(value, filename) {
  const blob = new Blob([JSON.stringify(value, null, 2) + "\n"], {type: "application/json"});
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

export function AdministrationView({siteAdmin, tenantID, tenants, freeze, quota, onMutation}) {
  const [oneTime, setOneTime] = useState(null);
  const scopedFreeze = tenantID ? freeze?.tenant : freeze?.site;
  const freezeRevision = scopedFreeze?.revision || 0;
  const quotaRevision = quota?.quota?.revision || 0;
  const quotaResources = quota?.quota?.resources || {};
  return (
    <section className="view administration-view" aria-labelledby="administration-title">
      <header className="view-heading">
        <p className="eyebrow">CONTROL-PLANE OPERATIONS</p>
        <h1 id="administration-title">Administration</h1>
        <p>Manage tenants, operator access, node enrollment, incident containment, and tenant resource ceilings from one scoped surface.</p>
      </header>
      {!siteAdmin ? (
        <aside className="signal-boundary">
          <strong>TENANT OPERATOR SCOPE</strong>
          <span>You can contain {tenantID}, enroll its nodes, and manage its agent work. Site-wide identity, shared capacity, and quota changes require a site administrator.</span>
        </aside>
      ) : null}
      <div className="administration-grid">
        <article className="management-card">
          <span className="panel-index">01 / TENANCY</span>
          <h2>Tenants</h2>
          <p>{tenants.length} tenant{tenants.length === 1 ? "" : "s"} currently loaded.</p>
          {siteAdmin ? (
            <OperatorAction
              title="Create tenant"
              description="Creates an isolated tenant identity. This does not grant an operator or enroll a node."
              onSubmit={async (form) => {
                const id = canonicalID(form.get("tenant_id"), "Tenant ID");
                await onMutation("/v1/tenants", {method: "POST", body: {tenant_id: id}});
                return `Tenant ${id} is ready.`;
              }}
            >
              <label>Tenant ID<input name="tenant_id" required maxLength="128" placeholder="research-team" /></label>
            </OperatorAction>
          ) : null}
        </article>

        <article className="management-card">
          <span className="panel-index">02 / ACCESS</span>
          <h2>Operator access</h2>
          <p>Issue a least-privilege bearer. Its plaintext appears once and remains only in this page until cleared.</p>
          {siteAdmin ? (
            <OperatorAction
              title="Issue operator"
              description="Choose tenant operator for routine work. Site administrator can change every tenant and node."
              submitLabel="Issue one-time bearer"
              onSubmit={async (form) => {
                const role = form.get("role");
                const scopedTenant = role === "tenant_operator" ? canonicalID(form.get("tenant_id"), "Tenant ID") : "";
                const result = await onMutation("/v1/operators", {
                  method: "POST",
                  body: {request_id: requestID("console-operator"), role, ...(scopedTenant ? {tenant_id: scopedTenant} : {})},
                });
                setOneTime(result);
                return "The operator bearer was issued.";
              }}
            >
              <label>Role<select name="role" defaultValue="tenant_operator">
                <option value="tenant_operator">Tenant operator</option>
                <option value="site_admin">Site administrator</option>
              </select></label>
              <label>Tenant ID<input name="tenant_id" maxLength="128" defaultValue={tenantID} placeholder="research-team" /></label>
            </OperatorAction>
          ) : null}
        </article>

        <article className="management-card">
          <span className="panel-index">03 / ENROLLMENT</span>
          <h2>Bring in a node</h2>
          <p>Create a short-lived, single-use enrollment token. The node still proves its local evidence identity during exchange.</p>
          <OperatorAction
            title="Create enrollment"
            description="The token expires even if it is never used. Prefer ten minutes or less."
            submitLabel="Create one-time token"
            onSubmit={async (form) => {
              const nodeID = canonicalID(form.get("node_id"), "Node ID");
              const tenantIDs = splitIDs(form.get("tenant_ids"), "Tenant IDs");
              const ttlSeconds = asInteger(form.get("ttl_seconds"), "Lifetime", 60, 86400);
              const result = await onMutation("/v1/enrollments", {
                method: "POST",
                body: {request_id: requestID("console-enrollment"), node_id: nodeID, tenant_ids: tenantIDs, ttl_seconds: ttlSeconds},
              });
              setOneTime(result);
              return `Enrollment for ${nodeID} was created.`;
            }}
          >
            <label>Node ID<input name="node_id" required maxLength="128" placeholder="agent-node-03" /></label>
            <label>Tenant IDs<input name="tenant_ids" required readOnly={!siteAdmin} maxLength="512" defaultValue={tenantID} placeholder="research-team, review-team" /></label>
            <label>Lifetime<select name="ttl_seconds" defaultValue="600">
              <option value="300">5 minutes</option>
              <option value="600">10 minutes</option>
              <option value="3600">1 hour</option>
              <option value="86400">24 hours</option>
            </select></label>
          </OperatorAction>
        </article>

        <article className="management-card">
          <span className="panel-index">04 / CONTAINMENT</span>
          <h2>{tenantID ? "Tenant freeze" : "Site freeze"}</h2>
          <p>{freeze?.effective ? "New command delivery is frozen." : "New command delivery is enabled."} Existing accepted work is not revoked.</p>
          <OperatorAction
            title={scopedFreeze?.frozen ? "Unfreeze delivery" : "Freeze delivery"}
            danger={!scopedFreeze?.frozen}
            description={scopedFreeze?.frozen
              ? "Restores new command delivery for this exact scope. A broader site freeze can still apply."
              : "Stops Control from delivering new commands in this exact scope while reports and evidence continue."}
            onSubmit={async (form) => {
              const frozen = Boolean(scopedFreeze?.frozen);
              const path = tenantID ? `/v1/tenants/${encodeURIComponent(tenantID)}/freeze` : "/v1/operations/freeze";
              await onMutation(path, {
                method: "PUT",
                body: {
                  action: frozen ? "unfreeze" : "freeze",
                  expected_revision: freezeRevision,
                  ...(frozen ? {} : {reason: String(form.get("reason") || "").trim()}),
                },
              });
              return frozen ? "New command delivery is enabled for this scope." : "New command delivery is frozen for this scope.";
            }}
          >
            {!scopedFreeze?.frozen ? <label>Incident reason<input name="reason" required maxLength="256" placeholder="Credential exposure investigation" /></label> : null}
          </OperatorAction>
        </article>

        {siteAdmin && tenantID ? (
          <article className="management-card management-card-wide">
            <span className="panel-index">05 / RESOURCE POLICY</span>
            <h2>Tenant resource ceiling</h2>
            <p>Limits the sum of signed requests for non-removed instances. Lowering a limit does not evict existing work.</p>
            <dl className="resource-usage">
              {["workloads", "cpu_millis", "memory_bytes", "pids"].map((resource) => (
                <div key={resource}><dt>{resource.replaceAll("_", " ")}</dt><dd>{quota?.usage?.[resource] ?? 0} used · {quotaResources[resource] ?? "no active limit"}</dd></div>
              ))}
            </dl>
            <div className="management-actions-row">
              <OperatorAction
                title="Set quota"
                description="All four ceilings are enforced together. Use values that include expected replica growth."
                onSubmit={async (form) => {
                  await onMutation(`/v1/tenants/${encodeURIComponent(tenantID)}/quota`, {
                    method: "PUT",
                    body: {
                      action: "set",
                      expected_revision: quotaRevision,
                      resources: {
                        workloads: asInteger(form.get("workloads"), "Workloads", 1),
                        cpu_millis: asInteger(form.get("cpu_millis"), "CPU millicores", 1),
                        memory_bytes: asInteger(form.get("memory_bytes"), "Memory bytes", 1),
                        pids: asInteger(form.get("pids"), "PIDs", 1),
                      },
                    },
                  });
                  return `Quota for ${tenantID} was updated.`;
                }}
              >
                <div className="form-grid">
                  <label>Workloads<input name="workloads" type="number" min="1" required defaultValue={quotaResources.workloads || 10} /></label>
                  <label>CPU millicores<input name="cpu_millis" type="number" min="1" required defaultValue={quotaResources.cpu_millis || 10000} /></label>
                  <label>Memory bytes<input name="memory_bytes" type="number" min="1" required defaultValue={quotaResources.memory_bytes || 17179869184} /></label>
                  <label>PIDs<input name="pids" type="number" min="1" required defaultValue={quotaResources.pids || 4096} /></label>
                </div>
              </OperatorAction>
              {quota?.quota?.enabled ? (
                <OperatorAction
                  title="Clear quota"
                  danger
                  description="Removes the site-wide tenant ceiling. Executor node-local limits continue to apply."
                  onSubmit={async () => {
                    await onMutation(`/v1/tenants/${encodeURIComponent(tenantID)}/quota`, {
                      method: "PUT",
                      body: {action: "clear", expected_revision: quotaRevision, resources: {memory_bytes: 0, cpu_millis: 0, pids: 0, workloads: 0}},
                    });
                    return `Quota for ${tenantID} was cleared.`;
                  }}
                />
              ) : null}
            </div>
          </article>
        ) : null}
      </div>
      <OneTimeSecret result={oneTime} onClear={() => setOneTime(null)} />
    </section>
  );
}

function DeploymentApply({tenantID, deployment, onMutation}) {
  const capsuleRef = useRef(null);
  const delegationRef = useRef(null);
  return (
    <OperatorAction
      title={deployment ? "Roll out signed generation" : "Create deployment"}
      description="Upload public signed authority envelopes. Private signing keys never enter the browser. Replica count comes from the signed delegation."
      submitLabel={deployment ? "Start controlled rollout" : "Create deployment"}
      onSubmit={async (form) => {
        const deploymentID = canonicalID(deployment?.deployment_id || form.get("deployment_id"), "Deployment ID");
        const generation = asInteger(form.get("generation"), "Generation", 1);
        const capsule = await fileBase64(capsuleRef.current?.files?.[0], 320 * 1024, "the signed capsule");
        const delegation = await fileBase64(delegationRef.current?.files?.[0], 320 * 1024, "the signed delegation");
        const result = await onMutation(`/v1/tenants/${encodeURIComponent(tenantID)}/deployments/${encodeURIComponent(deploymentID)}`, {
          method: "PUT",
          body: {
            generation,
            expected_revision: deployment?.revision || 0,
            agent_name: canonicalID(form.get("agent_name"), "Agent name"),
            bundle_digest: String(form.get("bundle_digest") || "").trim(),
            capsule_dsse_base64: capsule,
            delegation_dsse_base64: delegation,
            disruption_budget: {max_unavailable: asInteger(form.get("max_unavailable"), "Maximum unavailable", 0, 4096)},
          },
        });
        return `${deploymentID} generation ${result.generation} now desires ${deploymentReplicaCount(result)} signed replica${deploymentReplicaCount(result) === 1 ? "" : "s"}.`;
      }}
    >
      {!deployment ? <label>Deployment ID<input name="deployment_id" required maxLength="128" placeholder="research-fleet" /></label> : null}
      <div className="form-grid">
        <label>Generation<input name="generation" type="number" min="1" required defaultValue={(deployment?.generation || 0) + 1} /></label>
        <label>Agent name<input name="agent_name" required maxLength="128" defaultValue={deployment?.agent_name || "hermes"} /></label>
        <label>Maximum unavailable<input name="max_unavailable" type="number" min="0" required defaultValue={deployment?.disruption_budget?.max_unavailable ?? 1} /></label>
      </div>
      <label>Bundle digest<input name="bundle_digest" required pattern="sha256:[a-f0-9]{64}" defaultValue={deployment?.bundle_digest || ""} placeholder="sha256:…" /></label>
      <label>Signed capsule<input ref={capsuleRef} type="file" required accept=".json,application/json" /></label>
      <label>Signed controller delegation<input ref={delegationRef} type="file" required accept=".json,application/json" /></label>
      <p className="microcopy">Steward validates the exact capsule/delegation binding. Executor verifies the tenant signature before every effect.</p>
    </OperatorAction>
  );
}

export function DeploymentsView({page, tenantID, onMutation}) {
  const deployments = Array.isArray(page?.deployments) ? page.deployments : [];
  return (
    <section className="view deployments-view" aria-labelledby="deployments-title">
      <header className="view-heading">
        <p className="eyebrow">SIGNED DESIRED STATE</p>
        <h1 id="deployments-title">Deployments</h1>
        <p>Create, scale, roll out, pause, and remove agent fleets. Control reconciles only authority already present in the uploaded signed delegation.</p>
      </header>
      {!tenantID ? <p className="empty-state">Select one tenant to manage deployments.</p> : (
        <div className="deployment-toolbar">
          <DeploymentApply tenantID={tenantID} onMutation={onMutation} />
          <span>Scaling is a signed generation change, not an unchecked replica field.</span>
        </div>
      )}
      <div className="deployment-board">
        {deployments.map((deployment) => {
          const replicas = deploymentReplicaCount(deployment);
          const running = deployment.instances?.filter((instance) => instance.phase === "running").length || 0;
          const paused = Boolean(deployment.rollout?.paused_at);
          return (
            <article className="deployment-card" key={deployment.deployment_id}>
              <header>
                <div><span className="panel-index">GEN {deployment.generation} · REV {deployment.revision}</span><h2>{deployment.deployment_id}</h2></div>
                <span className={"badge " + (deployment.phase === "ready" ? "is-ok" : deployment.phase === "degraded" ? "is-danger" : "is-warning")}>{deployment.phase}</span>
              </header>
              <div className="deployment-scale">
                <strong>{running}<small>running</small></strong>
                <span>/</span>
                <strong>{replicas}<small>signed replicas</small></strong>
              </div>
              <dl className="pool-facts">
                <div><dt>Agent</dt><dd>{deployment.agent_name}</dd></div>
                <div><dt>Desired state</dt><dd>{deployment.desired_state}</dd></div>
                <div><dt>Delegation expires</dt><dd>{deployment.delegation_expires_at}</dd></div>
                <div><dt>Allowed nodes</dt><dd>{deployment.allowed_node_ids?.join(", ") || "none"}</dd></div>
              </dl>
              <div className="deployment-instances">
                {deployment.instances?.map((instance) => (
                  <div key={instance.instance_id}>
                    <span className={"signal signal-" + (instance.phase === "running" ? "ok" : instance.phase === "failed" ? "error" : "pending")} />
                    <strong>{instance.instance_id}</strong><span>{instance.phase}{instance.node_id ? ` · ${instance.node_id}` : ""}</span>
                  </div>
                ))}
              </div>
              <div className="management-actions-row">
                <DeploymentApply tenantID={tenantID} deployment={deployment} onMutation={onMutation} />
                {deployment.rollout ? (
                  <OperatorAction
                    title={paused ? "Resume rollout" : "Pause rollout"}
                    description={paused ? "Allows the controller to continue the retained target rollout." : "Stops new rollout transitions without undoing completed instances."}
                    onSubmit={async () => {
                      await onMutation(`/v1/tenants/${encodeURIComponent(tenantID)}/deployments/${encodeURIComponent(deployment.deployment_id)}/rollout`, {
                        method: "PUT",
                        body: {expected_revision: deployment.revision, paused: !paused},
                      });
                      return `${deployment.deployment_id} rollout ${paused ? "resumed" : "paused"}.`;
                    }}
                  />
                ) : null}
                {deployment.desired_state !== "absent" ? (
                  <OperatorAction
                    title="Scale to zero and remove"
                    danger
                    description="Marks this deployment absent. Control drains and removes its signed instances; the retained evidence linkage remains."
                    submitLabel="Remove deployment"
                    onSubmit={async (form) => {
                      if (form.get("confirm") !== deployment.deployment_id) {
                        throw new Error(`Type ${deployment.deployment_id} exactly.`);
                      }
                      await onMutation(`/v1/tenants/${encodeURIComponent(tenantID)}/deployments/${encodeURIComponent(deployment.deployment_id)}`, {
                        method: "DELETE",
                        body: {expected_revision: deployment.revision},
                      });
                      return `${deployment.deployment_id} is converging to absent.`;
                    }}
                  >
                    <label>Type <code>{deployment.deployment_id}</code><input name="confirm" required autoComplete="off" /></label>
                  </OperatorAction>
                ) : null}
              </div>
            </article>
          );
        })}
      </div>
      {tenantID && !deployments.length ? <p className="empty-state">No desired deployments in this tenant.</p> : null}
    </section>
  );
}

export function NodePoolControls({status, onMutation}) {
  const pool = status.pool;
  return (
    <div className="management-actions-row pool-controls">
      <OperatorAction
        title="Change capacity"
        description="Changes provider-neutral desired capacity. Your fleet driver creates or removes only the exact resulting deficit or drained candidate."
        onSubmit={async (form) => {
          const min = asInteger(form.get("min_nodes"), "Minimum nodes", 0, 4096);
          const desired = asInteger(form.get("desired_nodes"), "Desired nodes", min, 4096);
          const max = asInteger(form.get("max_nodes"), "Maximum nodes", desired, 4096);
          await onMutation(`/v1/node-pools/${encodeURIComponent(pool.id)}`, {
            method: "PUT",
            body: {
              expected_revision: pool.revision,
              tenant_ids: pool.tenant_ids,
              architecture: pool.architecture || "",
              min_nodes: min,
              desired_nodes: desired,
              max_nodes: max,
              membership_key_id: pool.membership_key_id || "",
              membership_public_key_base64: pool.membership_public_key_base64 || "",
            },
          });
          return `${pool.id} now desires ${desired} eligible nodes.`;
        }}
      >
        <div className="form-grid">
          <label>Minimum<input name="min_nodes" type="number" min="0" max="4096" required defaultValue={pool.min_nodes} /></label>
          <label>Desired<input name="desired_nodes" type="number" min="0" max="4096" required defaultValue={pool.desired_nodes} /></label>
          <label>Maximum<input name="max_nodes" type="number" min="0" max="4096" required defaultValue={pool.max_nodes} /></label>
        </div>
      </OperatorAction>
      <OperatorAction
        title="Delete pool"
        danger
        description="Deletes capacity intent only. It does not revoke nodes or remove provider machines."
        onSubmit={async (form) => {
          if (form.get("confirm") !== pool.id) {
            throw new Error(`Type ${pool.id} exactly.`);
          }
          await onMutation(`/v1/node-pools/${encodeURIComponent(pool.id)}`, {method: "DELETE", body: {expected_revision: pool.revision}});
          return `${pool.id} capacity intent was deleted.`;
        }}
      >
        <label>Type <code>{pool.id}</code><input name="confirm" required autoComplete="off" /></label>
      </OperatorAction>
    </div>
  );
}

export function CreateNodePool({tenantID, onMutation}) {
  return (
    <OperatorAction
      title="Create capacity pool"
      description="Defines provider-neutral capacity intent. Cloud credentials remain in the external fleet driver."
      onSubmit={async (form) => {
        const poolID = canonicalID(form.get("pool_id"), "Pool ID");
        const tenantIDs = splitIDs(form.get("tenant_ids"), "Tenant IDs");
        const min = asInteger(form.get("min_nodes"), "Minimum nodes", 0, 4096);
        const desired = asInteger(form.get("desired_nodes"), "Desired nodes", min, 4096);
        const max = asInteger(form.get("max_nodes"), "Maximum nodes", desired, 4096);
        await onMutation(`/v1/node-pools/${encodeURIComponent(poolID)}`, {
          method: "PUT",
          body: {
            expected_revision: 0, tenant_ids: tenantIDs,
            architecture: String(form.get("architecture") || ""),
            min_nodes: min, desired_nodes: desired, max_nodes: max,
          },
        });
        return `${poolID} now desires ${desired} nodes.`;
      }}
    >
      <label>Pool ID<input name="pool_id" required maxLength="128" placeholder="hermes-amd64" /></label>
      <label>Tenant IDs<input name="tenant_ids" required defaultValue={tenantID} placeholder="research-team" /></label>
      <label>Architecture<select name="architecture" defaultValue="amd64"><option value="">Any reported architecture</option><option value="amd64">amd64</option><option value="arm64">arm64</option></select></label>
      <div className="form-grid">
        <label>Minimum<input name="min_nodes" type="number" min="0" max="4096" required defaultValue="1" /></label>
        <label>Desired<input name="desired_nodes" type="number" min="0" max="4096" required defaultValue="1" /></label>
        <label>Maximum<input name="max_nodes" type="number" min="0" max="4096" required defaultValue="10" /></label>
      </div>
    </OperatorAction>
  );
}

export function NodeControls({node, siteAdmin, onMutation}) {
  if (!siteAdmin) {
    return <small>Site administrator required.</small>;
  }
  const mode = node.placement?.mode || "schedulable";
  const drain = node.drain;
  return (
    <div className="node-actions">
      <OperatorAction
        title={mode === "schedulable" ? "Cordon" : mode === "cordoned" ? "Uncordon" : "Unquarantine"}
        description={mode === "schedulable" ? "Stops new placement without moving existing work." : "Restores scheduling after the retained condition is resolved."}
        onSubmit={async (form) => {
          const action = mode === "schedulable" ? "cordon" : mode === "cordoned" ? "uncordon" : "unquarantine";
          await onMutation(`/v1/nodes/${encodeURIComponent(node.node_id)}/placement`, {
            method: "POST",
            body: {action, ...(action === "cordon" ? {reason: String(form.get("reason") || "").trim()} : {})},
          });
          return `${node.node_id} placement changed.`;
        }}
      >
        {mode === "schedulable" ? <label>Reason<input name="reason" required maxLength="256" placeholder="Planned host maintenance" /></label> : null}
      </OperatorAction>
      {mode !== "quarantined" ? (
        <OperatorAction
          title="Quarantine"
          danger
          description="Immediately blocks new placement. Existing work is not automatically destroyed."
          onSubmit={async (form) => {
            await onMutation(`/v1/nodes/${encodeURIComponent(node.node_id)}/placement`, {
              method: "POST", body: {action: "quarantine", reason: String(form.get("reason") || "").trim()},
            });
            return `${node.node_id} is quarantined.`;
          }}
        >
          <label>Security reason<input name="reason" required maxLength="256" placeholder="Host integrity investigation" /></label>
        </OperatorAction>
      ) : null}
      {!drain || drain.state !== "active" ? (
        <OperatorAction
          title="Drain"
          description="Cordons the node, then moves eligible deployment instances within their disruption budgets."
          onSubmit={async (form) => {
            const id = requestID("console-drain");
            await onMutation(`/v1/nodes/${encodeURIComponent(node.node_id)}/drain`, {
              method: "PUT", body: {request_id: id, reason: String(form.get("reason") || "").trim()},
            });
            return `${node.node_id} drain ${id} started.`;
          }}
        >
          <label>Maintenance reason<input name="reason" required maxLength="256" placeholder="Kernel update" /></label>
        </OperatorAction>
      ) : (
        <OperatorAction
          title="Cancel drain"
          description="Stops new moves. Any already completed move remains completed."
          onSubmit={async () => {
            await onMutation(`/v1/nodes/${encodeURIComponent(node.node_id)}/drain`, {
              method: "DELETE", body: {request_id: drain.request_id},
            });
            return `${node.node_id} drain was cancelled.`;
          }}
        />
      )}
      <OperatorAction
        title="Revoke node"
        danger
        description="Revokes every node credential and makes the node inactive. Drain workloads first."
        onSubmit={async (form) => {
          if (form.get("confirm") !== node.node_id) {
            throw new Error(`Type ${node.node_id} exactly.`);
          }
          await onMutation(`/v1/nodes/${encodeURIComponent(node.node_id)}`, {method: "DELETE"});
          return `${node.node_id} was revoked.`;
        }}
      >
        <label>Type <code>{node.node_id}</code><input name="confirm" required autoComplete="off" /></label>
      </OperatorAction>
    </div>
  );
}

export function NodeEvidenceControls({node, tenantID, siteAdmin, onMutation}) {
  const [inspection, setInspection] = useState(null);
  if (!siteAdmin) {
    return null;
  }
  const nodeID = node.node_id;
  return (
    <details className="node-evidence-controls">
      <summary>Evidence and snapshot containment</summary>
      <div className="management-actions-row">
        <OperatorAction
          title="Inspect evidence"
          description="Loads the controller's bounded, witnessed evidence status for this node."
          onSubmit={async () => {
            const result = await onMutation(`/v1/nodes/${encodeURIComponent(nodeID)}/evidence`, {method: "GET"});
            setInspection(result);
            return `Evidence for ${nodeID} was loaded below.`;
          }}
        />
        <OperatorAction
          title="Export signed evidence"
          description="Downloads a controller-witnessed JSON envelope for offline verification or incident retention."
          onSubmit={async () => {
            const result = await onMutation(`/v1/nodes/${encodeURIComponent(nodeID)}/evidence/export`, {method: "GET"});
            downloadJSON(result, `${nodeID}-evidence.json`);
            return `Signed evidence for ${nodeID} was downloaded.`;
          }}
        />
        {tenantID ? (
          <OperatorAction
            title="Contain snapshot"
            danger
            description="Quarantines or clears one exact tenant, source-node, and snapshot identity. Running instances are unchanged."
            onSubmit={async (form) => {
              const snapshotID = canonicalID(form.get("snapshot_id"), "Snapshot ID");
              const action = String(form.get("action"));
              const path = `/v1/tenants/${encodeURIComponent(tenantID)}/nodes/${encodeURIComponent(nodeID)}/snapshots/${encodeURIComponent(snapshotID)}/quarantine`;
              const status = await onMutation(path, {method: "GET"});
              await onMutation(path, {
                method: "PUT",
                body: {
                  action,
                  expected_revision: status.revision || 0,
                  ...(action === "quarantine" ? {reason: String(form.get("reason") || "").trim()} : {}),
                },
              });
              return `${snapshotID} was ${action === "quarantine" ? "quarantined" : "cleared"}.`;
            }}
          >
            <label>Action<select name="action" defaultValue="quarantine"><option value="quarantine">Quarantine</option><option value="unquarantine">Clear quarantine</option></select></label>
            <label>Snapshot ID<input name="snapshot_id" required maxLength="128" /></label>
            <label>Investigation reason<input name="reason" maxLength="256" placeholder="Suspected state contamination" /></label>
          </OperatorAction>
        ) : null}
        <OperatorAction
          title="Arm evidence capture"
          description="Requests a short, bounded sequence of executor evidence frames for one exact activation."
          onSubmit={async (form) => {
            const captureID = canonicalID(form.get("capture_id"), "Capture ID");
            const result = await onMutation(`/v1/nodes/${encodeURIComponent(nodeID)}/evidence/captures`, {
              method: "POST",
              body: {
                capture_id: captureID,
                request_id: requestID("console-capture"),
                tenant_id: canonicalID(form.get("tenant_id"), "Tenant ID"),
                runtime_ref: canonicalID(form.get("runtime_ref"), "Runtime reference"),
                generation: asInteger(form.get("generation"), "Generation", 1),
                activation_id: canonicalID(form.get("activation_id"), "Activation ID"),
                activation_begin_digest: String(form.get("activation_begin_digest") || "").trim(),
                ttl_seconds: asInteger(form.get("ttl_seconds"), "Lifetime", 1, 3600),
              },
            });
            return `Evidence capture ${result.capture_id || captureID} is armed.`;
          }}
        >
          <div className="form-grid">
            <label>Capture ID<input name="capture_id" required maxLength="128" placeholder="incident-2026-07-25" /></label>
            <label>Tenant ID<input name="tenant_id" required maxLength="128" defaultValue={tenantID} /></label>
            <label>Runtime reference<input name="runtime_ref" required maxLength="128" /></label>
            <label>Generation<input name="generation" type="number" min="1" required /></label>
            <label>Activation ID<input name="activation_id" required maxLength="128" /></label>
            <label>Lifetime<select name="ttl_seconds" defaultValue="300"><option value="60">1 minute</option><option value="300">5 minutes</option><option value="900">15 minutes</option><option value="3600">1 hour</option></select></label>
          </div>
          <label>Activation-begin digest<input name="activation_begin_digest" required pattern="sha256:[a-f0-9]{64}" placeholder="sha256:…" /></label>
        </OperatorAction>
        <OperatorAction
          title="Manage capture"
          description="Seal a completed capture, download its signed export, or delete the retained capture."
          onSubmit={async (form) => {
            const captureID = canonicalID(form.get("capture_id"), "Capture ID");
            const action = String(form.get("action"));
            const path = `/v1/nodes/${encodeURIComponent(nodeID)}/evidence/captures/${encodeURIComponent(captureID)}`;
            if (action === "seal") {
              const commandID = canonicalID(form.get("canary_command_id"), "Canary command ID", 256);
              await onMutation(`${path}/seal`, {method: "POST", body: {canary_command_id: commandID}});
              return `${captureID} was sealed to ${commandID}.`;
            }
            if (action === "export") {
              const result = await onMutation(`${path}/export`, {method: "GET"});
              downloadJSON(result, `${nodeID}-${captureID}-evidence.json`);
              return `${captureID} was downloaded.`;
            }
            await onMutation(path, {method: "DELETE"});
            return `${captureID} was deleted.`;
          }}
        >
          <label>Action<select name="action" defaultValue="export"><option value="export">Download signed export</option><option value="seal">Seal with canary command</option><option value="delete">Delete capture</option></select></label>
          <label>Capture ID<input name="capture_id" required maxLength="128" /></label>
          <label>Canary command ID, for seal<input name="canary_command_id" maxLength="256" /></label>
        </OperatorAction>
      </div>
      {inspection ? <pre className="evidence-inspection">{JSON.stringify(inspection, null, 2)}</pre> : null}
    </details>
  );
}

export function CredentialControls({credential, siteAdmin, onMutation}) {
  if (!siteAdmin || credential.revoked) {
    return null;
  }
  const operator = credential.kind === "operator";
  const path = operator
    ? `/v1/operators/${encodeURIComponent(credential.id)}`
    : `/v1/node-credentials/${encodeURIComponent(credential.id)}`;
  return (
    <OperatorAction
      title="Revoke"
      danger
      description={`Immediately rejects future use of this ${operator ? "operator" : "node"} credential.`}
      onSubmit={async (form) => {
        if (form.get("confirm") !== credential.id) {
          throw new Error(`Type ${credential.id} exactly.`);
        }
        await onMutation(path, {method: "DELETE"});
        return `${credential.id} was revoked.`;
      }}
    >
      <label>Type <code>{credential.id}</code><input name="confirm" required autoComplete="off" /></label>
    </OperatorAction>
  );
}

export function ScheduleControls({schedule, tenantID, onMutation}) {
  const statement = schedule.schedule || {};
  if (schedule.state === "cancelled" || schedule.state === "expired") {
    return null;
  }
  return (
    <OperatorAction
      title="Cancel schedule"
      danger
      description="Prevents future dispatches. Already accepted tasks continue under their existing finite permit."
      onSubmit={async (form) => {
        if (form.get("confirm") !== statement.schedule_id) {
          throw new Error(`Type ${statement.schedule_id} exactly.`);
        }
        await onMutation(`/v1/tenants/${encodeURIComponent(tenantID)}/schedules/${encodeURIComponent(statement.schedule_id)}`, {method: "DELETE"});
        return `${statement.schedule_id} was cancelled.`;
      }}
    >
      <label>Type <code>{statement.schedule_id}</code><input name="confirm" required autoComplete="off" /></label>
    </OperatorAction>
  );
}

export function InteractionResponseControls({interaction, tenantID, onMutation}) {
  const permitRef = useRef(null);
  const responseRef = useRef(null);
  return (
    <OperatorAction
      title="Submit signed answer"
      description="Upload the exact public response permit and signed answer produced by your trusted signer. The browser cannot sign or alter their authority."
      submitLabel="Queue exact signed answer"
      onSubmit={async () => {
        const permit = await fileBase64(permitRef.current?.files?.[0], 256 * 1024, "the response permit");
        const response = await fileBase64(responseRef.current?.files?.[0], 64 * 1024, "the signed response");
        await onMutation(`/v1/tenants/${encodeURIComponent(tenantID)}/interactions/${encodeURIComponent(interaction.interaction_id)}/response`, {
          method: "POST",
          body: {permit_base64: permit, response_base64: response},
        });
        return `${interaction.interaction_id} has a signed answer queued for its exact workload.`;
      }}
    >
      <label>Response permit<input ref={permitRef} type="file" required accept=".json,application/json" /></label>
      <label>Signed answer<input ref={responseRef} type="file" required accept=".json,application/json" /></label>
    </OperatorAction>
  );
}

export function CreateWorkroom({tenantID, onMutation}) {
  return (
    <OperatorAction
      title="Create Workroom"
      description="Creates a durable project index. Artifact bytes remain in storage you control."
      onSubmit={async (form) => {
        const projectID = canonicalID(form.get("project_id"), "Project ID");
        await onMutation(`/v1/tenants/${encodeURIComponent(tenantID)}/projects/${encodeURIComponent(projectID)}`, {
          method: "PUT",
          body: {
            expected_revision: 0,
            name: String(form.get("name") || "").trim(),
            description: String(form.get("description") || "").trim(),
            agent_ref: String(form.get("agent_ref") || "").trim(),
            skills: String(form.get("skills") || "").split(",").map((item) => item.trim()).filter(Boolean),
            sessions: [], artifacts: [], memory_refs: [],
          },
        });
        return `${projectID} is ready for sessions and signed tasks.`;
      }}
    >
      <label>Project ID<input name="project_id" required maxLength="128" placeholder="market-research" /></label>
      <label>Name<input name="name" required maxLength="256" placeholder="Market research" /></label>
      <label>Description<textarea name="description" maxLength="2048" rows="3" placeholder="Evidence-backed research and monitoring" /></label>
      <label>Default agent reference<input name="agent_ref" maxLength="256" placeholder="researcher" /></label>
      <label>Skills, comma separated<input name="skills" maxLength="1024" placeholder="web-research, source-verification" /></label>
    </OperatorAction>
  );
}

export function WorkroomSessionControls({project, tenantID, onMutation}) {
  return (
    <OperatorAction
      title="Create session"
      description="Adds one active session while preserving every retained task, artifact, and memory reference."
      onSubmit={async (form) => {
        const sessionID = canonicalID(form.get("session_id"), "Session ID");
        if (project.sessions.some((session) => session.id === sessionID)) {
          throw new Error(`Session ${sessionID} already exists.`);
        }
        await onMutation(`/v1/tenants/${encodeURIComponent(tenantID)}/projects/${encodeURIComponent(project.id)}`, {
          method: "PUT",
          body: {
            expected_revision: project.revision,
            name: project.name,
            description: project.description || "",
            agent_ref: project.agent_ref || "",
            skills: project.skills || [],
            sessions: project.sessions.concat({id: sessionID, title: String(form.get("title") || "").trim(), state: "active", task_ids: []}),
            artifacts: project.artifacts || [],
            memory_refs: project.memory_refs || [],
          },
        });
        return `Session ${sessionID} was added to ${project.id}.`;
      }}
    >
      <label>Session ID<input name="session_id" required maxLength="128" placeholder="competitor-landscape" /></label>
      <label>Title<input name="title" required maxLength="256" placeholder="Competitor landscape" /></label>
    </OperatorAction>
  );
}

export function WorkroomProjectControls({project, tenantID, onMutation}) {
  return (
    <div className="management-actions-row">
      <OperatorAction
        title="Edit project"
        description="Updates project metadata while preserving every session, artifact reference, and selected memory reference."
        onSubmit={async (form) => {
          await onMutation(`/v1/tenants/${encodeURIComponent(tenantID)}/projects/${encodeURIComponent(project.id)}`, {
            method: "PUT",
            body: {
              expected_revision: project.revision,
              name: String(form.get("name") || "").trim(),
              description: String(form.get("description") || "").trim(),
              agent_ref: String(form.get("agent_ref") || "").trim(),
              skills: String(form.get("skills") || "").split(",").map((item) => item.trim()).filter(Boolean),
              sessions: project.sessions || [],
              artifacts: project.artifacts || [],
              memory_refs: project.memory_refs || [],
            },
          });
          return `${project.id} metadata was updated.`;
        }}
      >
        <label>Name<input name="name" required maxLength="256" defaultValue={project.name} /></label>
        <label>Description<textarea name="description" maxLength="2048" rows="3" defaultValue={project.description || ""} /></label>
        <label>Default agent reference<input name="agent_ref" maxLength="256" defaultValue={project.agent_ref || ""} /></label>
        <label>Skills, comma separated<input name="skills" maxLength="1024" defaultValue={(project.skills || []).join(", ")} /></label>
      </OperatorAction>
      <OperatorAction
        title="Delete project"
        danger
        description="Deletes Steward's retained project index. External artifact bytes are not deleted."
        submitLabel="Delete project index"
        onSubmit={async (form) => {
          if (form.get("confirm") !== project.id) {
            throw new Error(`Type ${project.id} exactly.`);
          }
          await onMutation(`/v1/tenants/${encodeURIComponent(tenantID)}/projects/${encodeURIComponent(project.id)}`, {
            method: "DELETE",
            body: {expected_revision: project.revision},
          });
          return `${project.id} was deleted.`;
        }}
      >
        <label>Type <code>{project.id}</code><input name="confirm" required autoComplete="off" /></label>
      </OperatorAction>
    </div>
  );
}

export function SubmitTaskControls({tenantID, onMutation}) {
  const permitRef = useRef(null);
  const requestRef = useRef(null);
  return (
    <OperatorAction
      title="Submit signed task"
      description="Queues one bounded request under an existing finite task permit. The browser receives no signing key."
      submitLabel="Queue signed task"
      onSubmit={async (form) => {
        const permitFile = permitRef.current?.files?.[0];
        if (!permitFile || permitFile.size <= 0 || permitFile.size > 256 * 1024) {
          throw new Error("Choose a task permit file of at most 256 KiB.");
        }
        const permit = (await permitFile.text()).trim();
        if (!permit) {
          throw new Error("The task permit file is empty.");
        }
        const request = await fileBase64(requestRef.current?.files?.[0], 64 * 1024, "the task request");
        const projectID = String(form.get("project_id") || "").trim();
        const sessionID = String(form.get("session_id") || "").trim();
        if ((projectID === "") !== (sessionID === "")) {
          throw new Error("Project ID and session ID must be supplied together.");
        }
        await onMutation(`/v1/tenants/${encodeURIComponent(tenantID)}/task-requests`, {
          method: "POST",
          body: {
            task_permit: permit,
            request_base64: request,
            ...(projectID ? {project_id: canonicalID(projectID, "Project ID"), session_id: canonicalID(sessionID, "Session ID")} : {}),
          },
        });
        return "The signed task is queued for controller dispatch.";
      }}
    >
      <label>Task permit<input ref={permitRef} type="file" required /></label>
      <label>Request body<input ref={requestRef} type="file" required /></label>
      <div className="form-grid">
        <label>Project ID, optional<input name="project_id" maxLength="128" /></label>
        <label>Session ID, optional<input name="session_id" maxLength="128" /></label>
      </div>
    </OperatorAction>
  );
}

export function CreateScheduleControls({tenantID, onMutation}) {
  const permitRef = useRef(null);
  const requestRef = useRef(null);
  return (
    <OperatorAction
      title="Create finite schedule"
      description="Uploads one signed schedule envelope and its exact request. Steward cannot extend the signed run count or time window."
      submitLabel="Create finite schedule"
      onSubmit={async () => {
        const permit = await fileBase64(permitRef.current?.files?.[0], 320 * 1024, "the schedule permit");
        const request = await fileBase64(requestRef.current?.files?.[0], 64 * 1024, "the scheduled request");
        const result = await onMutation(`/v1/tenants/${encodeURIComponent(tenantID)}/schedules`, {
          method: "POST",
          body: {schedule_permit_base64: permit, request_base64: request},
        });
        return `Schedule ${result.schedule?.schedule_id || "was"} retained with finite authority.`;
      }}
    >
      <label>Signed schedule permit<input ref={permitRef} type="file" required accept=".json,application/json" /></label>
      <label>Request body<input ref={requestRef} type="file" required /></label>
    </OperatorAction>
  );
}
