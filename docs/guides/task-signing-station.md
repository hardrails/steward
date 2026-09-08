---
title: Run a private task signing station
description: Issue exact task bundles without sharing the task authority key with a host application.
section: Guides
---

# Run a private task signing station

To let a host application request task bundles without holding the task key, run
the optional station in a separate trusted process. You must already have an
authenticated admission response, its exact instance intent, service-trust
inventory, and an admitted Ed25519 task key.

```console
stewardctl task serve-issuer \
  -admission /secure/station/admission.json \
  -intent /secure/station/intent.json \
  -trust /secure/station/service-trust.json \
  -key /secure/station/task-authority.pem \
  -key-id task-authority \
  -operations hermes.run,hermes.stop \
  -valid-for 5m -capacity 1024 \
  -store /secure/station/issued \
  -client-gid 65533 \
  -socket /run/steward-task-issuer/station.sock
```

Use different non-root Unix users for the signer and host application. Reserve
a dedicated, non-root group for trusted signing clients (the example uses GID
`65533`); include the signer in this group so it can set the socket's group.
Never run the host under the signer's UID: that identity can read signing keys
and is part of the trusted operator boundary. Root and processes able to bypass
Unix permissions are also trusted operators, not isolated clients.

Before starting, create the store as signer-owned `0700`. Create the socket parent
as signer-owned `0710`, with its group set to the explicit `-client-gid`. The station
creates a signer-owned `0660` socket in that group. Clients can traverse the socket
directory but cannot list or modify it. The station refuses a missing or root
client group, mismatched directory group, or different directory permissions.
Do not give agents membership in this group. Keep signer keys, the `0700` store,
and owner-only temporary snapshots inaccessible to the host UID, including through
ACLs or supplementary groups; never grant that UID debugger or ptrace access to
the signer. Ancestors of the socket directory must allow the client to traverse
without allowing it to replace the directory.

For containers, share only a Linux socket volume, with distinct signer and client
UIDs and the same dedicated client GID. Keep the key, store and temporary directory
out of host-application and workload mounts. A macOS host socket is not a Docker VM
transport. Process separation alone, with matching UIDs, is not key isolation.

Choose operations from your authenticated service-trust inventory. The names in
the example are not automatically installed or authorized. Socket access grants
issuance authority for **any valid request body** within those operations and
limits. Do not mount the socket into an agent workload, publish it through a TCP
proxy, or treat it as a browser endpoint. The station is single-runtime and does
not verify business approvals; your host must retain the approved exact intent.

To request authority, send `POST /v1/tasks` over the Unix socket with
`Content-Type: application/json` and exactly these fields:

```json
{
  "task_id": "retained-task-1",
  "operation_id": "hermes.run",
  "request_base64": "eyJpbnB1dCI6ImJvdW5kZWQgd29yayJ9"
}
```

Retain the task ID and exact request before requesting a signature. A successful
response is an opaque native task bundle, at most 128 KiB, with media type
`application/octet-stream`. Verify it against your independently retained public
key, runtime identity, operation policy and request bytes before claiming or
dispatching work. A signature is not proof that a runtime is currently active.

To recover a lost response, repeat the original request. The station returns
byte-identical authority while it remains valid. A changed request, invalid file,
or expired bundle is not renewed. Reconcile the original task through Control;
do not invent a new task ID to bypass uncertainty.

To restart, preserve the store and supply identical authority inputs and limits.
The station refuses another writer, changed configuration and unknown artifacts.
It recovers only its signer-owned, client-group stale Unix socket, never a regular file or active
listener. Stop the process with SIGTERM and wait for it to exit before changing
mounts. An abrupt kill can leave owner-only temporary key snapshots; keep the
station's temporary storage private and remove orphaned snapshots only after
confirming their process has stopped.

At capacity, existing valid requests remain recoverable but new tasks receive
503. Capacity is 1–4096 retained task records; expiry does not erase records.
Do not clear the store to bypass the bound or recycle task identities. Plan a
separate operator-controlled runtime lifecycle before exhausting the finite
station. This version has no online rotation, retention compactor or fleet mode.

The station does not activate a runtime, dispatch work, sign connector effects,
sign owner answers, or replace Gateway replay enforcement. See the
[protocol contract](https://github.com/hardrails/steward/blob/main/openapi/steward-task-issuer.v1.yaml)
and [architecture decision](../decisions/0078-reuse-the-native-task-issuer-in-a-private-signing-station.md)
for boundaries and alternatives.
