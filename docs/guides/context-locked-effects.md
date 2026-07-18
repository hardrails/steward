---
title: Invalidate approvals when agent context changes
description: Bind an exact connector permit to the signed history of connector responses that the agent has received.
section: How-to guide
---

# Invalidate approvals when agent context changes

An exact permit answers an important question: *may this agent send these exact
bytes to this exact connector operation?* It does not normally say which external
information the agent had received when an operator approved those bytes.

That distinction matters. Suppose an operator approves a payment, account change,
or outbound message. Before the agent uses the permit, another connector returns
new data. That data may be legitimate, mistaken, or hostile. A permit created
before the response should not silently remain valid after the agent's external
context has changed.

**Context-locked effects** make this rule enforceable outside the model. A signed
tenant policy can require every exact-request permit to include the current,
cryptographically reconstructed history of responses released through Steward
connectors. After Gateway completes another connector call for the same grant, the
old permit no longer matches and Gateway rejects it.

This is an optional stricter mode of
[Authorized Effects]({{ '/guides/authorized-effects/' | relative_url }}). Start
with that guide if you have not configured connector-scoped action keys yet.

## What changes

With context locking enabled, Steward applies four additional controls:

1. Gateway allows only one connector call at a time for the grant. This prevents
   two calls from racing against the same response history.
2. Every authorization and terminal receipt carries the current effect-context
   sequence and hash. A terminal receipt also commits the digest of the exact
   response bytes released by Gateway.
3. `stewardctl permit context` verifies a copied receipt chain and reconstructs
   one small `steward.effect-context.v1` document. It contains hashes and grant
   identity, not response content.
4. `stewardctl permit issue -context ...` signs that context into a version-5
   permit. Gateway accepts it only while it still matches the live grant history.

A terminal failure also advances the context when Gateway can record it. The
failure may itself influence the agent's next decision. If a call has an
authorization record but no terminal record, context derivation stops rather than
guessing what the agent observed.

## Enable it in signed tenant policy

Add `"context_binding":"required"` to the tenant's existing
`authorized_effects` object:

```json
{
  "authorized_effects": {
    "mode": "required",
    "context_binding": "required",
    "min_approvals": 2,
    "keys": [
      {
        "key_id": "effects-approver-a",
        "public_key": "BASE64_ED25519_PUBLIC_KEY",
        "connector_ids": ["secrets-admin"]
      },
      {
        "key_id": "effects-approver-b",
        "public_key": "BASE64_ED25519_PUBLIC_KEY",
        "connector_ids": ["secrets-admin"]
      }
    ]
  }
}
```

The field accepts only `"required"`. Omit it to keep ordinary Authorized Effects.
The requirement is retained with the runtime grant and cannot be removed by a
Gateway reload. Replacing the signed policy requires the normal admission and
grant lifecycle.

## Derive the current effect context

Copy these non-secret artifacts to the signing station through an authenticated
channel:

- the admission response and the exact instance intent used for admission;
- the signed Gateway connector receipt ledger;
- the Gateway receipt public key, node ID, and key epoch; and
- preferably, a receipt sequence and chain hash retained independently of the
  copied ledger.

Derive the current context:

```console
stewardctl permit context \
  -admission admission.json \
  -intent instance-intent.json \
  -receipts connector-receipts.ndjson \
  -receipt-public-key connector-receipts.public \
  -receipt-node-id steward-0123456789abcdef0123456789abcdef/gateway \
  -receipt-epoch 1 \
  -expected-sequence '<retained-sequence>' \
  -expected-chain-hash 'sha256:<retained-chain-hash>' \
  -out effect-context.json
```

The command verifies the entire signed ledger, selects only records for the
admitted grant, rejects overlapping or incomplete calls, and prints the resulting
context hash. The expected head is optional, but without an independently retained
head the command cannot detect that someone supplied an older valid prefix of the
ledger.

Protect `effect-context.json` as approval input. It contains no credential or
response body, but replacing it with an older valid context could cause an
operator to sign against stale information.

## Issue and approve the request

Add `-context effect-context.json` to the ordinary permit command:

```console
stewardctl permit issue \
  -admission admission.json \
  -intent instance-intent.json \
  -trust action-trust.json \
  -context effect-context.json \
  -request exact-request.json \
  -connector-id secrets-admin \
  -operation-id rotate-credential \
  -task-id task-4bd6ce188f8b4e09a92af56d59a5df0e \
  -valid-for 5m \
  -key effects-approver-a.private.pem \
  -key-id effects-approver-a \
  -out action-permit.partial.dsse.json
```

For a multi-party policy, add the remaining approval with `stewardctl permit
approve` exactly as described in the Authorized Effects guide. Every signer signs
the unchanged context sequence and hash. A one-approver policy may also write
`-header-out action-permit.header` during `permit issue`.

If another connector call completes before this permit is used, Gateway returns
HTTP 403 `action_permit_denied`. Derive a new context, review the request against
the new information, and issue a new permit with a new task ID. Do not merely copy
the old signatures onto a new context.

Exact-effect bundles are not accepted for a context-locked grant. A bundle would
approve several requests against one starting history even though each completed
response changes the history for the next request. Issue and review each request
separately.

## Security boundary and tradeoffs

Context locking proves that an accepted permit named the exact Gateway-mediated
response history for its grant. It does **not** prove that the response was safe,
that the agent interpreted it correctly, or that the approved request matches a
person's natural-language intent.

The history includes only completed connector calls that pass through Steward
Gateway. It does not include:

- the original task or prompt;
- inference responses;
- local files, retained agent memory, or computer-use observations;
- generic egress, browser sessions, plugins, or unmanaged credentials; or
- data transformed or withheld by the configured upstream service.

Use origin isolation, careful tool design, model-side screening, and
application-specific validation as additional layers. Context locking deliberately
reduces concurrency to one connector call per affected grant. That performance
cost is the price of an unambiguous history boundary.

Current research does not support treating a model as a complete prompt-injection
security boundary. A 2026 analysis describes why agents can be induced to accept
contextually plausible malicious flows, while NIST guidance recommends precise,
context-aware authorization, scoped credentials, and tamper-resistant logs.
Microsoft's PAuth research similarly binds task authorization to exact values and
their provenance. Steward implements a narrower, deployable control at its named
connector boundary; these sources motivate the design and do not evaluate or
certify Steward:

- [AI Agents May Always Fall for Prompt Injections](https://arxiv.org/abs/2605.17634)
- [NIST SP 800-228A, Guidelines for Secure AI System Development](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-228A.ipd.pdf)
- [NIST software and AI agent identity and authorization concept paper](https://www.nccoe.nist.gov/sites/default/files/2026-02/accelerating-the-adoption-of-software-and-ai-agent-identity-and-authorization-concept-paper.pdf)
- [PAuth: Precise Task-scoped Authorization for Agents](https://www.microsoft.com/en-us/research/publication/pauth-precise-task-scoped-authorization-for-agents/)
- [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
