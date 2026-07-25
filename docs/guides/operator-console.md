---
title: Operate Steward from the web console
description: Manage tenants, agents, capacity, nodes, access, schedules, and incident controls without putting private signing keys or cloud credentials in the browser.
section: How-to guide
---

# Operate Steward from the web console

Steward Control includes a React web console at `/console/`. It is the main
surface for day-to-day fleet operations:

- create tenants and scoped operator access;
- create short-lived node enrollments;
- create and scale node pools;
- cordon, quarantine, drain, and revoke nodes;
- inspect and export witnessed evidence, capture incident evidence, and quarantine
  an exact snapshot;
- understand managed agents, replicated fleets, resumable forks, and temporary
  workers as agent computers;
- create, scale, roll out, pause, and remove signed agent deployments;
- set tenant resource ceilings;
- freeze command delivery during an incident;
- create Workrooms and sessions;
- submit signed tasks, finite schedules, and agent responses;
- review agent status, evidence posture, findings, commands, and access; and
- revoke operator and node credentials.

You do not need a terminal for these routine operations. Some actions still
need approval from a trusted signer. For those actions, the console accepts the
public signed file and sends its exact contents to Steward. It never asks for a
private signing key.

## Open the console

Open the Control URL followed by `/console/`:

```text
https://control.customer.example:8443/console/
```

The TLS certificate must be trusted by the browser and must contain the exact
DNS name or IP address in its Subject Alternative Names (SANs). Steward rejects
an unexpected `Host` header before it handles a console or API request.

If Control uses a private certificate authority that is not installed in the
browser, `stewardctl console` remains an optional connection helper:

```console
stewardctl console
```

It verifies Control with the selected context, then prints a temporary
loopback-only HTTP address for the browser. It does not place the operator token
in the URL or inject it into requests.

## Sign in with the narrowest role

Enter an existing operator bearer in the password field.

- A **tenant operator** sees and manages one tenant.
- A **site administrator** can select a site-wide view or one tenant and can
  change site resources such as nodes, capacity pools, quotas, and operator
  access.

The bearer is held only in JavaScript memory. Steward does not place it in a
cookie, `localStorage`, `sessionStorage`, a URL, or browser history. The page
clears it when you lock or leave the console, after 15 minutes without trusted
pointer or keyboard activity, or after eight hours.

The browser can still read a bearer while the session is open. Use a dedicated,
patched operator profile without unapproved extensions or cloud synchronization.

## Understand the operating model

The console separates ordinary desired state from cryptographic authority.

| Change | What the console does | What stays outside the browser |
| --- | --- | --- |
| Tenant, quota, freeze, access, enrollment | Calls the existing scoped Control API | Nothing additional |
| Node placement or drain | Records a bounded site-administrator action | Node runtime authority remains with Executor |
| Node-pool scale | Changes provider-neutral desired capacity | Cloud credentials stay in the external fleet driver |
| Agent create or scale | Uploads a signed capsule and controller delegation | Tenant and controller private signing keys |
| Task, schedule, or answer | Uploads a finite permit and exact request or response | Private task or response signing keys |
| Exact Executor command | Reviews and transfers an offline-signed envelope | Executor command signing key |

This distinction prevents a compromised browser or Control process from
inventing new agent authority. Control can converge only the exact instances,
nodes, resources, operations, and validity window already named by a signed
delegation. Executor verifies the signed scope again before every effect.

## Use the main views

### Overview and Needs review

**Overview** shows capacity, command state, evidence posture, workflow activity,
and the current tenant quota. **Needs review** explains each deterministic
finding with what happened, what it affects, and the safest next step.

Apply the recovery action in **Nodes**, **Deployments**, **Capacity pools**,
**Administration**, or **Access**. Findings are derived from retained state;
they are not acknowledgements and do not disappear merely because somebody
opened the page.

### Deployments

Select one tenant, then open **Deployments**.

To create or scale an agent fleet:

1. Ask your approved signing service for a capsule and controller delegation.
   The delegation contains the exact replica identities, allowed nodes,
   lifecycle operations, and expiry.
2. Choose **Create deployment** or **Roll out signed generation**.
3. Enter the generation, agent name, bundle digest, and maximum unavailable
   replicas.
4. Upload the signed capsule and delegation files.
5. Review the resulting signed replica count and rollout state.

Scaling is a new signed generation. It is intentionally not an unchecked number
field: adding a replica creates another workload identity and therefore needs
explicit authority.

During a rollout, use **Pause rollout** or **Resume rollout**. **Scale to zero
and remove** marks the deployment absent and preserves its evidence linkage.
This desired-state workflow is available when Control runs in
`bounded-autonomous` mode. A `strict-sovereign` controller rejects it and accepts
only exact externally signed Executor commands through **Activity**.

### Agent computers

Select one tenant, then open **Agent computers**. This is the workspace view for
people operating agents. It joins each retained signed deployment with the
latest Executor observation for the exact tenant and instance identity.

The lifecycle label explains how the existing deployment is shaped:

| Lifecycle | Meaning |
| --- | --- |
| Managed instance | One managed agent computer without snapshot ancestry; persistence is not implied |
| Replicated fleet | Several signed instance identities managed together |
| Resumable fork | One new identity created from an immutable snapshot, with no automatic cleanup time |
| Temporary worker | One snapshot-backed identity with a finite cleanup time |

Use the search field to find a workspace by deployment, instance, node,
connector, or egress route. **Create or scale** opens the signed deployment
surface. **Give work** opens finite task dispatch.

Connector and route badges mean that Executor observed those delegated paths.
They do not mean the agent received an upstream credential. Gateway keeps the
secret at the trusted outbound boundary and restricts the destination.

An observation that does not match a retained deployment appears under
**directly managed or historical runtimes**. This is expected for
strict-sovereign commands, older instances, and migration evidence. Steward
does not pretend those observations are managed workspaces.

### Capacity pools

Open **Capacity pools** as a site administrator.

- **Create capacity pool** defines minimum, desired, and maximum node counts.
- **Change capacity** changes the desired count with optimistic revision
  protection.
- **Delete pool** removes capacity intent; it does not revoke nodes or destroy
  provider machines.

Steward reports a precise scale-out deficit and only post-drain, empty-node
scale-in candidates. The external fleet driver performs provider operations.
Cloud credentials never enter Control or the console.

### Nodes

Open **Nodes** after selecting a tenant.

- **Cordon** stops new placement without moving current work.
- **Quarantine** strengthens placement isolation during a security incident.
- **Drain** cordons first, then moves eligible stateless deployment instances
  within their disruption budgets.
- **Cancel drain** stops new moves; completed moves remain completed.
- **Revoke node** revokes all node credentials and makes the node inactive.
- **Evidence and snapshot containment** inspects or downloads witnessed evidence,
  arms and seals a bounded capture, and quarantines one exact snapshot identity.

Drain before provider removal. A node-pool scale-in candidate appears only after
the exact node is drained, empty, and no longer ready.

### Administration

**Administration** contains:

- tenant creation;
- one-time operator bearer issuance;
- one-time node enrollment creation;
- site or tenant command-delivery freeze;
- tenant CPU, memory, process, and workload ceilings.

One-time bearers and enrollment tokens appear in a highlighted output panel.
Save them immediately, then choose **Clear from page**. Steward cannot show
their plaintext again.

Lowering a quota does not evict existing work. The tenant becomes over quota and
new admission remains blocked until usage falls below the retained ceiling.

A freeze blocks new command delivery for the selected scope. It does not hide
heartbeats, reports, or evidence, and it does not revoke work a node already
accepted.

### Tasks, Workrooms, Schedules, and Questions

These views accept public finite authority without handling its private key:

- **Tasks → Submit signed task** uploads a task permit and request body.
- **Workrooms → Create Workroom** creates a durable project index.
- **Create session** adds a session without replacing its existing tasks,
  artifacts, or selected memory. **Edit project** changes its metadata, and
  **Delete project** removes Steward's index without deleting external artifact
  bytes.
- **Schedules → Create finite schedule** uploads a signed schedule permit and
  exact request.
- **Questions → Submit signed answer** uploads a response permit and signed
  response bound to one workload and question.

The console displays agent-authored prompts and findings as untrusted content.
They are useful claims, not proof and not authority.

### Access

**Access** shows non-secret credential metadata. A site administrator can revoke
an active operator or node credential after typing its exact identifier.

Revocation prevents future authenticated use. It does not erase retained
history or retroactively cancel a command that a node already accepted.

## Submit an exact offline-signed Executor command

Use **Activity → Submit an offline-signed command** for strict-sovereign
operations or a one-off command approved elsewhere.

1. Choose the DSSE JSON file.
2. Compare the displayed SHA-256 digest, operation, tenant, node, runtime,
   lifecycle fences, validity window, and signature key IDs with the trusted
   signing record.
3. Type `SUBMIT <command_id>`.
4. Re-enter the current operator bearer.
5. Submit the unchanged envelope.

The preview is labeled **UNVERIFIED LOCAL PREVIEW**. Control validates the route
but does not replace Executor as the command-signature authority. Executor
verifies the original signed bytes before acting.

## Know what the console deliberately does not hold

The console does not hold:

- tenant, controller, task, response, or command private signing keys;
- cloud-provider credentials;
- inference-provider secret plaintext;
- agent prompts, task result bodies, or artifact bytes in fleet lists; or
- a second account database or authorization model.

Secrets needed by an agent are distributed through Steward's existing
host-local secret and Gateway boundaries. The console may show non-secret
metadata and rotation state, but it must not return the secret value after
creation.

The console is also not a root service supervisor. Initial installation,
disaster recovery, private-key signing, host-local secret materialization, and
the provider driver's credential setup stay in separate trust domains. After
those domains are configured, the console controls Steward's tenant, workload,
node, and desired-capacity state without a terminal. Keeping host repair and
cloud credentials out of Control prevents a stolen site-administrator bearer
from becoming root or provider-account access.

## Air-gapped and reproducible operation

The production bundle is committed under
`internal/controlplane/console/dist` and embedded into `steward-control`.
Installing or running Control does not require Node.js, npm, a CDN, telemetry,
or internet access.

Frontend maintainers reproduce the committed bundle with the lockfile-pinned
toolchain:

```console
npm ci --prefix internal/controlplane/console --ignore-scripts --no-audit --no-fund
npm audit --prefix internal/controlplane/console --audit-level=moderate
npm --prefix internal/controlplane/console run check
npm --prefix internal/controlplane/console run build
git diff --exit-code -- internal/controlplane/console/dist
```

`npm audit` contacts the configured registry and belongs to the maintainer build
lane, not an operator installation or disconnected Go build.

For the underlying API and authority details, see
[Operate the bundled Steward control plane]({{ '/guides/control-plane/' | relative_url }}).
The frontend dependency decision is recorded in
[Embed a React operator console]({{ '/decisions/0020-embedded-react-operator-console/' | relative_url }});
the operational mutation boundary is recorded in
[Use the console as the primary fleet surface]({{ '/decisions/0065-primary-console-operations/' | relative_url }});
the workspace projection is recorded in
[Project agent computers from existing signed state]({{ '/decisions/0066-project-agent-computers-from-existing-state/' | relative_url }}).
