---
title: Run your first useful Hermes task
description: Take a prepared Steward site from a healthy operator context to one deployed Hermes agent and one recoverable task result.
section: Getting started
---

# Run your first useful Hermes task

This tutorial deploys one Hermes agent and asks it to do useful work. It uses the
short operator commands. Each step also explains what Steward is protecting so
you do not have to understand its internal artifact formats first.

## What you need

Before starting, you need:

- Steward installed on the operator workstation and Linux node;
- a signed site package created with `stewardctl site init`;
- Steward Control running;
- one enrolled Linux node with Docker and gVisor;
- a locally built Hermes OCI or Docker archive;
- an inference route configured in Gateway; and
- an active CLI context created by `site connect`.

If those items are unfamiliar, follow [Install Steward]({{ '/getting-started/' |
relative_url }}), [Create site authority]({{ '/getting-started/site-authority/' |
relative_url }}), and [Enroll a node]({{ '/getting-started/enroll/' |
relative_url }}) first. Those steps establish the authority and isolation boundary;
this tutorial uses it.

## 1. Check the environment

Ask Steward for one combined Control and node summary:

<!-- cli-flags: status | -output -watch -->
```console
stewardctl status
```

Expected result:

```text
Steward: HEALTHY  context production
No current findings require operator attention.
```

The exact node and command counts will differ. If the state is `ATTENTION`,
`CRITICAL`, or `UNAVAILABLE`, do not guess. Run:

<!-- cli-flags: explain | -output -->
```console
stewardctl explain
```

Continue only when the reported problem is understood. See
[Diagnose and recover]({{ '/guides/troubleshooting/' | relative_url }}) for the
meaning of each section.

## 2. Create the agent project

Create a small Hermes application in the current directory:

<!-- cli-flags: agent create | -template -->
```console
stewardctl agent create workspace-auditor -template workspace
cd workspace-auditor
```

The `workspace` template gives a general-purpose Hermes agent the smallest
capability set. Use `stewardctl agent template list` to inspect the built-in
`research` and `developer` starting points. Templates are editable definitions,
not trusted policy and not permission to run.

The directory contains a CUE application definition. CUE is a configuration
language that validates values and relationships before Steward creates a signed
runtime bundle.

Build the portable bundle:

```console
stewardctl agent build
```

This does not start a container or receive a secret. It resolves and validates the
application contract.

## 3. Publish the exact image

Publish the image archive from the trusted workstation:

<!-- cli-flags: agent publish | -archive -->
```console
stewardctl agent publish ../steward-site \
  -archive /secure/builds/hermes/image.tar
```

Steward inspects the complete archive and signs its exact configuration digest.
It does not trust the image label, tag, or filename.

Authorize Control to manage this deployment on the intended node:

<!-- cli-flags: agent authorize | -controller-public-key -node-ids -->
```console
stewardctl agent authorize ../steward-site \
  -controller-public-key /secure/control/controller.public.pem \
  -node-ids node-a
```

The resulting delegation is time-bounded and permits only Steward's required
lifecycle operations. Control does not receive the tenant private key.

## 4. Activate the agent service

On the selected node, install or import the exact image through the signed image
workflow. Then activate the qualified Gateway service:

<!-- cli-flags: agent service activate | -bundle -tenant-id -node-id -trust-out -->
```console
sudo stewardctl agent service activate \
  -bundle agent.bundle.json \
  -tenant-id tenant-a \
  -node-id node-a \
  -trust-out /secure/steward/service-trust.json
```

Run the exact `systemctl` command printed by Steward. The generated
`service-trust.json` is not secret, but transfer it through an authenticated
channel so another party cannot substitute service identity.

Gateway holds the inference credential. Hermes receives a scoped local service
route, not the reusable upstream API key.

## 5. Connect task authority

Back on the trusted workstation, attach the service inventory and Gateway token
path to the active tenant context:

<!-- cli-flags: site task connect | -trust -gateway-token-file -->
```console
stewardctl site task connect ../steward-site \
  -trust /secure/steward/service-trust.json \
  -gateway-token-file /secure/steward/gateway-service.token
```

The context stores paths, not secret values. The task signing key remains in its
owner-only file outside the agent and Control.

## 6. Deploy and run

Apply the durable desired deployment:

```console
stewardctl agent apply workspace-auditor
```

Then run one useful task:

```console
stewardctl task run workspace-auditor \
  "Review this workspace and report one concrete issue with supporting evidence"
```

Steward writes the request, signed task bundle, and verified result into a new
owner-only run directory. It prints their paths without printing the prompt or
result body.

Keep that run directory. If the terminal disconnects after submission, reuse its
existing task bundle with `task submit` or `task wait`. Do not mint a new task ID
until Steward proves the original task did not dispatch; otherwise the work could
run twice.

## 7. Verify the result and boundary

Run `stewardctl status` again. The deployment should be running and no new critical
finding should appear.

For a stronger check:

- inspect the task's signed Gateway receipt;
- verify the Executor receipt chain offline;
- confirm the agent container has no upstream inference credential; and
- attempt an undeclared destination and confirm Gateway denies it.

Continue with [Run Hermes Agent]({{ '/guides/hermes-agent/' | relative_url }}) for
skills and model configuration, or [Build and run agents]({{ '/guides/build-agents/' | relative_url }})
for the complete expert workflow.
