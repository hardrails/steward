---
title: Require signed action permits for exact connector effects
description: Why Steward spends one authority-signed, request-bound permit before a connector can cause an external effect.
section: Architecture decision
---

# Require signed action permits for exact connector effects

- Status: Accepted
- Date: 2026-07-13
- Rung: in-house

## Context

A connector grant defines the maximum operations an instance may call, while task
and call budgets limit how often it may call them. Those controls do not prove that
a trusted action authority authorized one exact request for the tenant. A
manipulated agent could still choose different request content within an allowed
operation or race two valid calls before an operator notices.

The additional authorization must work on a disconnected node, fail before an
external effect, survive process restart, and remain linked to Steward's existing
signed admission, grant, connector-ledger, and receipt evidence. It must not turn
the Steward node into a general identity provider, policy service, workflow engine,
or transparency-log service.

## Decision

Steward requires an action-authority-signed **action permit** for connector
operations configured for exact-effect authorization. Here, exact effect means the
exact outbound request bytes and bound metadata; it does not mean exactly-once
delivery by the upstream service. The permit uses a DSSE (Dead Simple Signing
Envelope) statement signed with Ed25519. Its statement binds:

- `node_id`, `tenant_id`, `instance_id`, and `generation`;
- `capsule_digest`, `policy_digest`, and `route_policy_digest`;
- `connector_id`, `operation_id`, `operation_policy_digest`, and `task_id`;
- the exact request `request_digest` (SHA-256), `request_bytes`, and
  `content_type`; and
- canonical `not_before` and `expires_at` timestamps.

`operation_policy_digest` commits to the connector ID, canonical upstream origin,
credential injection mode, operator-managed credential epoch, operation ID, HTTP
method, and exact path. The mode identifies whether Gateway uses the
`Authorization` or `X-API-Key` header; the digest does not contain the credential
value. `content_type` is `application/json` for the
body-bearing methods POST, PUT, and PATCH, and empty for bodyless GET, HEAD, and
DELETE. A bodyless statement must bind the empty request.

There is no separate action identifier. `task_id` and the digest of the complete
DSSE envelope identify the authorization. Gateway verifies every binding against
the retained grant and the request it will send. The stable connector call digest
continues to derive from tenant, instance, task, connector, and operation. Gateway
records the permit digest beside that call digest in the signed receipt and
durably spends the call before opening the upstream request. A mismatched,
expired, not-yet-valid, replayed, or unrecordable permit fails before the external
effect. Signed terminal evidence retains the same permit, request, authority-key,
and call linkage for offline verification.

**Tradeoff:** this adds a signing step for exact-effect operations and requires the
permit format, ledger state, Gateway enforcement, and verification tools to evolve
as one contract. It preserves offline operation and makes authorization for the
specific request independently checkable after the workload is gone.

**Buy vs build:** **in-house**: reuse Steward's DSSE/Ed25519, Gateway, ledger, and
Go standard library; reject OAuth, Open Agent Passport (OAP), Open Policy Agent
(OPA), Supply Chain Integrity, Transparency, and Trust (SCITT), and a new service
because offline exact-effect enforcement is core and external systems do not
preserve the existing signed grant/receipt chain; revisit if a stable interoperable
permit standard covers the exact constraints.

[OAuth](https://www.rfc-editor.org/rfc/rfc6749.html) can still authorize access to
an upstream service, and an external policy or transparency system can complement
Steward. None is required in Gateway's pre-effect path. OAP is an
[emerging pre-action authorization design](https://arxiv.org/abs/2603.20953),
[OPA](https://www.openpolicyagent.org/docs) is a general policy engine, and
[SCITT](https://datatracker.ietf.org/doc/rfc9943/) defines an architecture for
transparent signed statements; adopting one would still leave Steward responsible
for exact request binding, durable one-time spend, grant linkage, and offline
receipt verification. The OAP publication is a preprint and is a design signal,
not evidence about Steward.

## Consequences

An action permit proves that an accepted action authority authorized the exact
request bytes and metadata bound by the statement for the named tenant and that
Gateway durably spent that permit before attempting the call. It does not prove the
natural-language task's meaning, the agent's intent, the upstream service's
behavior, or exactly-once delivery. A lost response can still leave the external
outcome ambiguous, and the spent permit must not be cleared merely to make a retry
convenient.

Broad connector grants remain an outer ceiling; a permit can narrow authority but
cannot add a connector, operation, route, artifact, tenant, or generation absent
from the retained grant. `stewardctl permit issue` and `permit verify` make issuance
and inspection scriptable, while `permit audit` correlates the signed permit with
the verified connector receipt chain. A standalone authorization service or
dossier product is not part of this decision.

Revisit this decision if a stable, independently implementable permit standard can
express every binding above, supports durable offline one-time spend before effect,
and preserves Steward's signed grant-to-receipt chain without adding a mandatory
online service.
