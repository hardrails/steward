---
title: Persist node maintenance before drain
description: Why Executor owns a restart-safe admission cordon and stewardctl composes it with the existing signed-runtime destroy API.
section: Architecture decision
---

# Persist node maintenance before drain

- Status: Accepted
- Date: 2026-07-17
- Rung: existing Executor admission store and lifecycle API

## Context

Release activation requires an empty execution boundary, but destroying workloads
one by one leaves a race: another authorized caller can admit or start work between
the final destroy and service shutdown. An in-memory flag clears on restart, exactly
when interrupted maintenance needs the strongest default. Deleting Docker objects
directly would bypass signed lifecycle checks, receipts, grant removal, and replay
fences.

This is an established infrastructure pattern, adapted to Steward's narrower
boundary. Nomad makes a draining node ineligible for new placement and keeps
eligibility as explicit state; Kubernetes marks a node unschedulable before safe
eviction ([Nomad drain](https://developer.hashicorp.com/nomad/commands/node/drain),
[Kubernetes drain](https://kubernetes.io/docs/tasks/administer-cluster/safely-drain-node/)).
NIST's 2026 agent-security RFI summary reports broad agreement that established
cybersecurity practices remain relevant but need adaptation for agent systems
([NIST CAISI 800-5](https://www.nist.gov/publications/summary-analysis-responses-request-information-regarding-security-considerations-ai)).
These sources motivate the operational pattern; they do not evaluate Steward.

## Decision

Store one node-wide maintenance state beside Executor's durable admission high-water
marks. The state contains a bounded reason and canonical entry time. Entry is
idempotent only for the exact same reason; a different reason conflicts. Exit is
explicit, idempotent, and unavailable until reconciliation is complete and no
journal operation is pending.

Executor serializes maintenance changes with signed admission, lifecycle mutation,
and reconciliation. While enabled, it blocks only authority-expanding operations:
new signed admission, workload start, activation canary dispatch, and activation
checkpoint. It still allows exact admission replay, status, logs, egress statistics,
stop, destroy, evidence publication, and recovery. The cordon survives process and
host restart.

`stewardctl node maintenance drain` first previews the exact active runtime
references returned by Executor. `-apply` enters maintenance before using the entry
response as its destroy inventory. It calls the existing destroy endpoint in stable
order, stops on the first failure, and leaves maintenance enabled. A retry resumes
from retained state. It never purges persistent volumes, clears an ambiguous
journal, removes a grant directly, migrates work, or exits maintenance.

The maintenance state advances the admission-fence writer to format 3. Release
manifests advertise readers 1 through 3 and writer 3 so activation rejects an older
binary that cannot preserve the cordon.

**Rejected:** a CLI-only flag because it cannot close races with uplink admission;
an in-memory Executor flag because restart would silently reopen the node; direct
Docker cleanup because it bypasses authority and evidence; automatic exit because a
failed upgrade must remain fail-closed; and a new scheduler or workflow engine
because Steward has no placement or migration contract.

## Consequences

Maintenance drain is destructive. It does not provide high availability, graceful
agent completion, disruption budgets, or replacement placement. Operators must plan
availability before `-apply`. A successful release transition also does not make the
node eligible automatically: an operator inspects readiness and exits maintenance.

The implementation adds no daemon, dependency, or second lifecycle path. Its safety
depends on the existing local bearer boundary, signed fence records, mutation lock,
journal, evidence log, Docker reconciliation, and release-format checks.
