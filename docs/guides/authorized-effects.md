---
title: Authorize exact external effects
description: Require a signed, one-use permit before an agent can use a Steward connector to change an external system or send sensitive data.
section: How-to guide
---

# Authorize exact external effects

An email, calendar invitation, web page, document, tool result, or retained memory
is data from the user's point of view. To an agent, the same content can look like
instructions. In a demonstrated attack, malicious text in a calendar invitation
caused an agentic browser to enter an authenticated 1Password session, reveal
secrets, change account settings, and send recovery material to an attacker. The
attack used ordinary browser actions rather than a cryptographic break. Read the
[technical report](https://labs.zenity.io/p/perplexedbrowser-how-attackers-can-weaponize-comet-to-takeover-your-1password-vault)
and [1Password advisory](https://1password.com/blog/security-advisory-for-ai-assisted-browsing-with-the-1password-browser).

Prompt-injection classifiers, model self-review, and confirmation prompts can
reduce risk. They are not a deterministic authorization boundary: the model being
asked to recognize the attack has already received the hostile content, and an
approver can still misunderstand a plausible request. Research on
[contextual-integrity attacks](https://arxiv.org/abs/2605.17634) describes why an
attacker can make a prohibited flow appear contextually legitimate. Steward
therefore assumes the agent is fully compromised when it decides whether a managed
external effect may begin.

**Authorized Effects** moves that decision outside the workload. Signed tenant
policy pins action-authority public keys and an approval threshold to connector
IDs. The instance intent explicitly selects `"effect_mode":"authorized"`.
Gateway then accepts only a complete permit signed for the exact operation and
exact request bytes. It records the one-use spend on durable storage before DNS
resolution or any upstream connection, while the upstream credential remains
outside the workload.

This boundary is opt-in. Use it for account changes, secret-management operations,
messages, financial instructions, infrastructure mutations, or any connector call
whose consequence should require independent authority.

## What the boundary covers

Authorized Effects covers only calls that pass completely through a Steward named
connector. For those calls, it binds all of the following:

- the signed tenant, node, logical instance, generation, admitted capsule, and
  site policy;
- the selected connector, exact configured operation, credential epoch, and
  effective route policy;
- the exact request bytes, byte length, content type, one-use task ID, validity
  window, required approval count, and exact set of action-authority keys. One
  permit may bind one request, or an exact-effect bundle may bind up to eight
  independently one-use requests; and
- a durable signed authorization record written before DNS, followed by a signed
  terminal record when Gateway can observe one.

It does **not** cover:

- credentials, sockets, browser sessions, plugins, or network channels available
  outside Steward connectors;
- inference confidentiality or what a model provider retains;
- local filesystem changes, computer use, or side effects inside the agent;
- a compromised host root, kernel, Docker daemon, Gateway process, receipt key, or
  action-signing keys;
- whether an approver understood the request or whether the request matches a
  user's natural-language intent; or
- exactly-once behavior at the upstream service. A timeout after authorization can
  leave the external outcome unknown, and the same permit remains spent.

Do not describe Authorized Effects as prompt-injection prevention. It limits what
a manipulated agent can do through the managed connector boundary.

## Configure a required policy

The following procedure starts from a working
[signed-admission setup]({{ '/guides/signed-admission/' | relative_url }}) whose
publisher capsule already permits the `connector` capability and whose exact image
has been imported. Replace the repository and digest placeholders with the values
from that signed capsule. Keep the site-root, publisher, and action private keys off
the node.

On two separate signing workstations or operator profiles, create two dedicated
action-authority keys. Keep each private key under a different operator's control:

```console
mkdir -m 0700 authorized-effects
stewardctl keygen \
  -private-out authorized-effects/effects-approver-a.private.pem \
  -public-out authorized-effects/effects-approver-a.public \
  -key-id effects-approver-a
stewardctl keygen \
  -private-out authorized-effects/effects-approver-b.private.pem \
  -public-out authorized-effects/effects-approver-b.public \
  -key-id effects-approver-b
```

Create a complete site policy. This example requires Authorized Effects for the
tenant. Connector IDs in each key scope must be sorted and must also appear in the
tenant's `connector_ids` list.

```console
PUBLISHER_PUBLIC="$(tr -d '\n' < publisher.public)"
EFFECTS_PUBLIC_A="$(tr -d '\n' < authorized-effects/effects-approver-a.public)"
EFFECTS_PUBLIC_B="$(tr -d '\n' < authorized-effects/effects-approver-b.public)"
MANIFEST_DIGEST='sha256:PASTE_64_LOWERCASE_HEX'

cat > site-policy.json <<EOF
{
  "schema_version": "steward.admission.v1",
  "policy_id": "site-a",
  "policy_epoch": 2,
  "publishers": [{
    "key_id": "publisher-1",
    "public_key": "$PUBLISHER_PUBLIC",
    "revoked": false,
    "allowed_profiles": [{"id":"generic-v1","version":"v1"}],
    "allowed_repositories": ["registry.internal/approved-agent"],
    "allowed_manifest_digests": ["$MANIFEST_DIGEST"],
    "resource_ceiling": {
      "memory_bytes": 536870912,
      "cpu_millis": 1000,
      "pids": 128
    }
  }],
  "tenants": [{
    "tenant_id": "tenant-a",
    "publisher_key_ids": ["publisher-1"],
    "resource_ceiling": {
      "memory_bytes": 536870912,
      "cpu_millis": 1000,
      "pids": 128
    },
    "connector_ids": ["secrets-admin"],
    "authorized_effects": {
      "mode": "required",
      "min_approvals": 2,
      "keys": [{
        "key_id": "effects-approver-a",
        "public_key": "$EFFECTS_PUBLIC_A",
        "connector_ids": ["secrets-admin"]
      }, {
        "key_id": "effects-approver-b",
        "public_key": "$EFFECTS_PUBLIC_B",
        "connector_ids": ["secrets-admin"]
      }]
    }
  }]
}
EOF

unset PUBLISHER_PUBLIC EFFECTS_PUBLIC_A EFFECTS_PUBLIC_B MANIFEST_DIGEST

stewardctl policy sign \
  -in site-policy.json \
  -out site-policy.dsse.json \
  -key site-root.private.pem \
  -key-id site-root-1
stewardctl policy verify \
  -in site-policy.dsse.json \
  -public-key site-root.public \
  -key-id site-root-1
```

The example assumes the node has retained policy epoch 1. Use an epoch greater
than the node's retained high-water mark; never lower or reuse an epoch to make the
example pass.

`min_approvals` may be from 1 through 8 and cannot exceed the number of keys
available to every selected connector. Omitting it preserves the one-approver
policy. `"mode":"optional"` also pins the keys, but requires each instance intent to
choose either `"standard"` or `"authorized"`. `"mode":"required"` accepts only
`"authorized"`; omitting `effect_mode` or selecting `"standard"` is a signed-policy
downgrade and admission fails. An intent cannot select `"authorized"` when its
tenant has no `authorized_effects` policy.

## Configure Gateway without giving the agent a credential

Transfer only both action public keys, the signed policy, and the site-root public
key to the node through an authenticated process. Create the connector credential
as a Gateway-readable owner-controlled file. An external secret manager may
materialize this file; Steward does not require one. See
[Store and distribute Gateway credentials]({{ '/guides/secrets/' | relative_url }})
for the OpenBao handoff and provider-neutral readiness check.

```console
sudo install -d -o root -g root -m 0700 /root/steward-authorized-effects
sudo install -o root -g root -m 0644 authorized-effects/effects-approver-a.public \
  /root/steward-authorized-effects/effects-approver-a.public
sudo install -o root -g root -m 0644 authorized-effects/effects-approver-b.public \
  /root/steward-authorized-effects/effects-approver-b.public
sudo install -o root -g root -m 0644 site-policy.dsse.json \
  /root/steward-authorized-effects/site-policy.dsse.json
sudo install -o root -g root -m 0644 site-root.public \
  /root/steward-authorized-effects/site-root.public

sudo install -d -o root -g steward-gateway -m 0750 /etc/steward/credentials
sudo install -d -o root -g root -m 0700 /root/steward-staged-credentials
# First stage the value at this path as a root-owned mode-0600 regular file.
sudo install -o steward-gateway -g steward-gateway -m 0600 \
  /root/steward-staged-credentials/secrets-admin \
  /etc/steward/credentials/secrets-admin
sudo rm -- /root/steward-staged-credentials/secrets-admin

sudo stewardctl gateway connector set \
  -config /etc/steward/gateway.json \
  -id secrets-admin \
  -base-url https://accounts.example.com \
  -credential-file /etc/steward/credentials/secrets-admin \
  -credential-mode bearer \
  -credential-epoch 1 \
  -max-concurrent 1 \
  -max-request-bytes 65536 \
  -max-response-bytes 1048576 \
  -max-seconds 30 \
  -max-calls-per-grant 8 \
  -tenant-budget tenant-a=4194304 \
  -operation rotate-recovery=POST:/v1/recovery/rotate \
  -action-node-id node-a \
  -action-authority effects-approver-a=/root/steward-authorized-effects/effects-approver-a.public \
  -action-authority-tenant effects-approver-a=tenant-a \
  -action-authority effects-approver-b=/root/steward-authorized-effects/effects-approver-b.public \
  -action-authority-tenant effects-approver-b=tenant-a \
  -max-action-permit-seconds 300

sudo stewardctl gateway validate -config /etc/steward/gateway.json
sudo systemctl restart steward-gateway
```

The command writes the Gateway configuration atomically. Its security-relevant
result is equivalent to this fragment; the complete installed file also contains
Gateway sockets, identities, receipt paths, and limits:

```json
{
  "action_permit_node_id": "node-a",
  "action_authorities": [{
    "key_id": "effects-approver-a",
    "tenant_id": "tenant-a",
    "public_key": "BASE64_ED25519_PUBLIC_KEY_A"
  }, {
    "key_id": "effects-approver-b",
    "tenant_id": "tenant-a",
    "public_key": "BASE64_ED25519_PUBLIC_KEY_B"
  }],
  "connector_receipt_tenant_budgets": [{
    "tenant_id": "tenant-a",
    "bytes": 4194304
  }],
  "connectors": [{
    "id": "secrets-admin",
    "base_url": "https://accounts.example.com",
    "credential_file": "/etc/steward/credentials/secrets-admin",
    "credential_mode": "bearer",
    "credential_epoch": 1,
    "max_concurrent": 1,
    "max_request_bytes": 65536,
    "max_response_bytes": 1048576,
    "max_seconds": 30,
    "max_calls_per_grant": 8,
    "action_authority_ids": ["effects-approver-a", "effects-approver-b"],
    "max_action_permit_seconds": 300,
    "operations": [{
      "id": "rotate-recovery",
      "method": "POST",
      "path": "/v1/recovery/rotate"
    }]
  }]
}
```

## Create and check an explicit intent

Use the exact capsule-envelope digest printed by `stewardctl capsule sign`:

```console
CAPSULE_DIGEST='sha256:PASTE_CAPSULE_ENVELOPE_DIGEST'

cat > instance-intent.json <<EOF
{
  "tenant_id": "tenant-a",
  "node_id": "node-a",
  "instance_id": "agent-001",
  "lineage_id": "lineage-001",
  "generation": 1,
  "capsule_digest": "$CAPSULE_DIGEST",
  "resources": {
    "memory_bytes": 536870912,
    "cpu_millis": 1000,
    "pids": 128
  },
  "capabilities": {
    "state": false,
    "inference": false,
    "service": false,
    "egress": false,
    "connector": true
  },
  "state_disposition": "none",
  "connector_ids": ["secrets-admin"],
  "effect_mode": "authorized"
}
EOF

unset CAPSULE_DIGEST
```

Authorized mode prohibits the generic egress capability and every egress route.
Run the read-only readiness check before admission:

```console
sudo stewardctl gateway effects check \
  -config /etc/steward/gateway.json \
  -intent instance-intent.json \
  -policy /root/steward-authorized-effects/site-policy.dsse.json \
  -site-root-public-key /root/steward-authorized-effects/site-root.public \
  -site-root-key-id site-root-1
```

The command verifies the site-policy signature and checks that the intent explicitly
selects authorized mode, has no generic egress, and selects only connectors whose
Gateway action keys and approval threshold exactly match signed tenant policy. It
also checks that every selected connector has enough distinct approvers, node identity,
and the tenant's durable receipt budget. It prints only a bounded, non-secret
readiness summary and does not admit a workload or contact an upstream service.

Install the verified replacement policy with the existing signed-admission
transaction:

```console
sudo /usr/local/libexec/steward/configure-admission \
  --policy /root/steward-authorized-effects/site-policy.dsse.json \
  --site-root-public-key /root/steward-authorized-effects/site-root.public \
  --site-root-key-id site-root-1 \
  --node-id node-a \
  --allow-host-admin-intent
```

Admit the workload through the authenticated path. This host-local example
requires the explicitly enabled host-administrator intent option described in the
signed-admission guide. It also uses `jq` only to extract the opaque runtime
reference. A production tenant-admission path should omit
`--allow-host-admin-intent` and use its authenticated principal instead.

```console
sudo stewardctl node admit \
  -token-file /etc/steward/executor-token \
  -capsule capsule.dsse.json \
  -intent instance-intent.json > admission.json

RUNTIME_REF="$(jq -er '.runtime_ref | select(type == "string" and length > 0)' \
  admission.json)"
sudo stewardctl node start \
  -token-file /etc/steward/executor-token \
  -runtime-ref "$RUNTIME_REF"

sudo stewardctl gateway connector trust \
  -config /etc/steward/gateway.json \
  -tenant-id tenant-a > action-trust.json
```

Authenticate `admission.json` and the unsigned `action-trust.json` while
transferring them to the signing workstation. The inventory is mismatch preflight,
not authority; Gateway's active signed grant and validated configuration remain the
enforcement source.

## Collect two exact approvals

On the signing workstation, review the exact request bytes. Do not approve a
summary while signing different bytes.

```console
umask 077
printf '%s' \
  '{"account_id":"acct-42","new_recovery_destination":"security-ops@example.com"}' \
  > exact-request.json

stewardctl permit issue \
  -admission admission.json \
  -intent instance-intent.json \
  -trust action-trust.json \
  -request exact-request.json \
  -connector-id secrets-admin \
  -operation-id rotate-recovery \
  -task-id task-7f67c52a25d84f178a6b447f6d7a1091 \
  -valid-for 5m \
  -clock-skew 5s \
  -key authorized-effects/effects-approver-a.private.pem \
  -key-id effects-approver-a \
  -out action-permit.partial.dsse.json
```

Standard output contains only the exact permit digest. Standard error contains one
canonical JSON approval summary with tenant, instance generation, connector,
operation, method, path, request digest and byte count, validity window, authority
keys, approval count, threshold, completion state, and permit digest. Keep those streams separate in automation. The
summary deliberately excludes request content and hostile context; compare it with
the independently reviewed request bytes before releasing the permit. It cannot
prove that an approver understood the external effect.

Because the signed policy requires two approvals, `permit issue` emits an
incomplete `steward.action-permit.v3` artifact. It cannot emit an HTTP header and
Gateway will not accept it. Transfer that artifact, the exact request, admission,
intent, and authenticated trust inventory to the second signer. The second signer
reviews the same concrete action and adds a signature without changing the signed
payload:

```console
stewardctl permit approve \
  -in action-permit.partial.dsse.json \
  -admission admission.json \
  -intent instance-intent.json \
  -trust action-trust.json \
  -request exact-request.json \
  -key authorized-effects/effects-approver-b.private.pem \
  -key-id effects-approver-b \
  -out action-permit.dsse.json \
  -header-out action-permit.header
```

The command rejects an already used key, a changed payload or request, an
unadmitted signer, inconsistent operation trust, and an existing output path.
Signatures are stored in canonical key-ID order. Gateway requires exactly the
signed threshold of distinct valid signatures. A one-approver policy continues to
emit version 2 directly; version 1 is rejected for every authorized-effects grant.

Deliver the exact request and permit header to the workload through the agent's
approved task path. Inside the workload, the connector call is:

```console
ACTION_PERMIT="$(tr -d '\n' < action-permit.header)"
curl --fail-with-body \
  -H 'Content-Type: application/json' \
  -H 'X-Steward-Task-ID: task-7f67c52a25d84f178a6b447f6d7a1091' \
  -H "X-Steward-Action-Permit: $ACTION_PERMIT" \
  --data-binary @exact-request.json \
  "$STEWARD_CONNECTOR_URL/v1/connectors/secrets-admin/operations/rotate-recovery"
unset ACTION_PERMIT
```

Gateway durably spends the permit before DNS. A replay, altered body, wrong task,
wrong operation, expired permit, substituted key, or version-1 permit fails before
the upstream call. If the same retained grant repeatedly supplies invalid permits,
Gateway writes at most one signed `action_permit_denied` marker for that stable
denial code. The marker binds the request digest but deliberately claims no permit
or authority key. It is a first-observed, attacker-selectable sample: the
compromised workload can choose the task ID and request bytes that reach the marker
first. Later denials are not enumerated. Treat it as evidence that at least one
denial occurred, not as an exhaustive denial log. If that bounded evidence cannot
be persisted, the request fails closed with HTTP 503.

## Approve several exact effects together

Use an exact-effect bundle when an operator has reviewed a small set of concrete
requests and every subset and ordering is acceptable. A bundle reduces repeated
signing; it does not create a connector session or a workflow. The compromised
agent may use any unspent step in any order, omit a step, or stop. It cannot add a
step, change bytes, substitute a connector operation, reuse a task ID, cross the
admitted generation, or exceed the signed expiry.

Create each exact request as an owner-only file. Then create an owner-only plan.
`request_path` is local review metadata and must be an absolute, clean path. It is
not signed; `stewardctl` reads that file and signs its exact digest and byte count.
Omit `request_path` for GET, HEAD, and DELETE operations.

```json
{
  "schema_version": "steward.effect-bundle-input.v1",
  "bundle_id": "recovery-rotation-2026-07",
  "steps": [{
    "step_id": "01-primary",
    "connector_id": "secrets-admin",
    "operation_id": "rotate-recovery",
    "task_id": "task-rotate-primary-7f67c52a",
    "request_path": "/secure/review/rotate-primary.json"
  }, {
    "step_id": "02-secondary",
    "connector_id": "secrets-admin",
    "operation_id": "rotate-recovery",
    "task_id": "task-rotate-secondary-91ec883b",
    "request_path": "/secure/review/rotate-secondary.json"
  }]
}
```

The issuer sorts steps by `step_id`, checks the one-through-eight limit and unique
step and task IDs, and proves that the first key is admitted and trusted for every
connector. The shortest connector permit lifetime applies to the whole bundle.

```console
stewardctl permit bundle issue \
  -admission admission.json \
  -intent instance-intent.json \
  -trust action-trust.json \
  -plan exact-effects.json \
  -valid-for 5m \
  -key authorized-effects/effects-approver-a.private.pem \
  -key-id effects-approver-a \
  -out effect-bundle.partial.dsse.json

stewardctl permit bundle approve \
  -in effect-bundle.partial.dsse.json \
  -admission admission.json \
  -intent instance-intent.json \
  -trust action-trust.json \
  -plan exact-effects.json \
  -key authorized-effects/effects-approver-b.private.pem \
  -key-id effects-approver-b \
  -out effect-bundle.dsse.json \
  -header-out effect-bundle.header
```

Every approver rereads every request file, reconstructs every trusted operation,
and refuses to sign if the resulting statement differs from the existing bundle.
Every signer must be admitted and trusted for every connector in the set. Gateway
validates all steps and all signer scopes before accepting even one selected step.
The workload uses the same header for a listed call and selects that step with its
existing `X-Steward-Task-ID`. Gateway's durable task spend remains per step.

Verify the complete bundle and the request files, then correlate every spent or
unspent step with a copied receipt chain:

```console
stewardctl permit bundle verify \
  -in effect-bundle.dsse.json \
  -plan exact-effects.json \
  -authority effects-approver-a=authorized-effects/effects-approver-a.public \
  -authority effects-approver-b=authorized-effects/effects-approver-b.public

stewardctl permit bundle audit \
  -in effect-bundle.dsse.json \
  -plan exact-effects.json \
  -authority effects-approver-a=authorized-effects/effects-approver-a.public \
  -authority effects-approver-b=authorized-effects/effects-approver-b.public \
  -receipts connector-receipts.ndjson \
  -receipt-public-key connector-receipts.public \
  -receipt-node-id '<configured-connector-receipt-node-id>' \
  -receipt-epoch 1 \
  -expected-sequence '<retained-sequence>' \
  -expected-chain-hash 'sha256:<retained-chain-hash>'
```

Audit reports each step as `unspent`, `authorized`, or `terminal`. `authorized`
without a terminal record is an unknown external outcome, not proof that nothing
happened. The rationale and explicit unordered-set limitation are recorded in
[ADR 0022]({{ '/decisions/0022-native-exact-effect-bundles/' | relative_url }}).

## Verify the effect offline

Copy `action-permit.dsse.json`, `exact-request.json`, the Gateway connector receipt
ledger, its public key, and an independently retained receipt head to the offline
audit workstation. Use the configured Gateway receipt node ID and key epoch:

```console
stewardctl permit verify \
  -in action-permit.dsse.json \
  -authority effects-approver-a=authorized-effects/effects-approver-a.public \
  -authority effects-approver-b=authorized-effects/effects-approver-b.public \
  -request exact-request.json

stewardctl permit audit \
  -in action-permit.dsse.json \
  -authority effects-approver-a=authorized-effects/effects-approver-a.public \
  -authority effects-approver-b=authorized-effects/effects-approver-b.public \
  -request exact-request.json \
  -receipts connector-receipts.ndjson \
  -receipt-public-key connector-receipts.public \
  -receipt-node-id '<configured-connector-receipt-node-id>' \
  -receipt-epoch 1 \
  -expected-sequence '<retained-sequence>' \
  -expected-chain-hash 'sha256:<retained-chain-hash>'
```

Multi-party connector authorization and terminal events use receipt format 6. The
records bind `effect_mode`, the exact operation-policy digest, canonical signer
set, approval threshold, permit digest, request digest, and durable call identity
without storing request or response bodies, credentials, or raw task IDs. A
one-approver authorized call remains format 5 for compatibility. A missing terminal
record means the outcome is unknown; it is not evidence that the upstream did
nothing.

## How this differs from related defenses

These approaches are complementary:

- [Google Agent Origin Sets](https://blog.google/security/architecting-security-for-agentic/)
  separate readable and writable browser origins. They reduce cross-origin
  exposure inside a participating browser.
- [CaMeL](https://arxiv.org/abs/2503.18813) and
  [Fides](https://arxiv.org/abs/2505.23643) enforce control/data-flow or
  information-flow rules in an integrated agent planner.
- [NVIDIA OpenShell](https://docs.nvidia.com/openshell/reference/policy-schema)
  provides sandbox, filesystem, process, network, application-protocol, and
  credential-routing policy. NemoClaw can ask an operator to approve a blocked
  network destination for the current session; that is broader than one exact
  request and does not provide separation of duties.
- [Open Agent Passport](https://arxiv.org/abs/2603.20953) proposes deterministic
  pre-tool authorization and signed audit records.

Steward's narrower difference is complete mediation of selected Steward connector
calls for unmodified, containerized agents: signed tenant policy pins
connector-specific action keys and, when configured, a minimum number of distinct
approvers; one exact request or a bounded set of up to eight exact requests is
signed outside the agent, with each selected task durably consumed before DNS;
credentials stay outside the workload; and the permit-to-terminal evidence can be
verified offline. It does not require a
particular browser, planner, agent framework, hosted authorization service, or
public network. Use planner-level information-flow controls, browser origin
isolation, model screening, and human review as additional layers where available.

The architectural rationale is recorded in
[ADR 0018]({{ '/decisions/0018-native-authorized-effects/' | relative_url }}).
The separation-of-duties extension is recorded in
[ADR 0021]({{ '/decisions/0021-enforce-multi-party-authorized-effects/' | relative_url }}).
Bounded exact-effect sets are recorded in
[ADR 0022]({{ '/decisions/0022-native-exact-effect-bundles/' | relative_url }}).
