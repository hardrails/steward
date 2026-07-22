---
title: Diagnose and recover Steward safely
description: Use status, explain, bounded recovery, node doctor, and support bundles without erasing uncertain state or issuing duplicate authority.
section: Operate
---

# Diagnose and recover Steward safely

Start with Steward's retained facts. Do not begin by deleting containers, state,
journals, or receipt files. Those records may be the only proof that an operation
ran—or that it did not.

## Get one health summary

<!-- cli-flags: status | -output -watch -->
```console
stewardctl status
```

The command uses the active CLI context and reads every configured Control and
local Executor connection. Its default output is for a person:

- `HEALTHY`: no current finding requires attention;
- `ATTENTION`: at least one warning needs review;
- `CRITICAL`: a finding may affect authority, isolation, or evidence integrity;
- `UNAVAILABLE`: Steward could not read one or more configured sources.

For automation, use stable JSON:

```console
stewardctl status -output json
```

For a terminal dashboard without adding another service or protocol:

```console
stewardctl status -watch 5s
```

`--watch` polls the same bounded HTTP resources. It does not stream prompts,
results, logs, or secret values.

## Ask why

<!-- cli-flags: explain | -output -->
```console
stewardctl explain
```

Every finding separates:

- **Cause:** the retained fact Steward observed;
- **Impact:** what is blocked or uncertain;
- **Next:** the safest action that does not widen authority.

To focus on one node, command, capacity resource, or runtime, pass its exact
identity:

```console
stewardctl explain node-a
```

The human explanation is derived from a stable reason code. Steward deliberately
does not copy raw Docker, upstream, prompt, task-result, or secret text into this
projection.

## Recover one proven-missing workload

Steward currently automates one degraded node recovery: reconciliation has proved
that exactly one signed agent container is absent, no journaled host mutation is
pending, and no other reconciliation failure was omitted.

Preview the recovery first:

<!-- cli-flags: recover | -apply -output -->
```console
sudo -H stewardctl recover executor-DIGEST
```

The preview changes nothing. If it reports `Safe: true`, review the runtime
identity and apply the same plan explicitly:

```console
sudo -H stewardctl recover executor-DIGEST --apply
```

Executor rechecks the container absence and every other precondition after the
CLI request arrives. If anything changed between preview and apply, recovery
fails closed. A successful recovery removes the deterministic remaining Gateway
grant, relay, capability network, and signed presence fence before allowing the
controller to create a fresh generation.

`recover` is not a general force command. It refuses pending journal operations,
unknown external outcomes, identity drift, evidence failures, multiple findings,
and truncated reconciliation reports.

## Run the host doctor

On the affected Linux node:

```console
sudo /usr/local/libexec/steward/node-doctor
```

The default check is read-only. It validates installed release integrity, service
state, Docker and gVisor, loopback health, Gateway control access, and bounded
store capacity. Add `--json` when a monitoring system needs the result.

Do not run a mutating canary with a newly issued task merely to test whether a
previous task ran. A new task carries new authority. Use the exact retained bundle
and task status first.

## Read common findings

| Finding | Meaning | Safe response |
| --- | --- | --- |
| `node_stale` | Control has not received a recent authenticated node report. | Restore the node service or uplink before placing or changing work. |
| `workload_missing` | Executor proved a signed workload container is absent. | Preview `stewardctl recover RUNTIME_REF`. |
| `journal_pending` | A prepared host mutation has no proven terminal result. | Preserve the journal and establish the external result; do not retry blindly. |
| `command_outcome_unknown` | Control cannot prove whether an authority-bearing command completed. | Reconcile retained node and external evidence before issuing replacement authority. |
| `workload_identity_drift` | The observed container no longer matches signed identity or hardening. | Preserve evidence, contain the node, and restore or retire the exact topology. |
| `rollback_detected` | A node reported an older evidence-chain position. | Quarantine the node and compare preserved checkpoints offline. |
| `equivocation_detected` | A node reported conflicting evidence at a witnessed position. | Quarantine and investigate before restoring authority. |
| `tenant_quota_exceeded` | The tenant's reserved resources reached a site limit. | Remove unused reservations or deliberately change the quota. |

## Preserve a support bundle

When Control is reachable, create a metadata-only support bundle before making
manual changes:

<!-- cli-flags: control support-bundle create | -tenant-id -out -->
```console
stewardctl control support-bundle create \
  -tenant-id tenant-a \
  -out /secure/incidents/steward-support.json
```

The bundle excludes prompts, task and connector bodies, terminal result text,
credentials, private keys, command envelopes, and logs. Preserve its SHA-256
digest through a separate trusted channel. The bundle is a bounded operational
snapshot, not a signed attestation or a complete audit history.

If `explain` cannot identify a safe action, stop. Preserve the node, Control
state, external-service facts, and receipt checkpoints before seeking an
operation-specific recovery.

