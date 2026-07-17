---
title: Run OpenClaw with Steward
description: Build, qualify, inspect, and operate the exact pinned OpenClaw adapter with a real custom skill under Docker and gVisor.
section: Agent compatibility
---

# Run OpenClaw with Steward

Steward packages a narrow, qualified OpenClaw runtime for one-shot agent work. It
uses the real OpenClaw agent and skill system, but does not expose the full OpenClaw
Gateway, browser, channels, plugins, or administration interface.

This boundary is intentional. A calendar invite, email, web page, document, memory,
or tool response can contain instructions that manipulate an agent. Steward cannot
make those instructions safe. It can keep the resulting process inside gVisor,
limit its filesystem and network access, keep reusable inference credentials out of
the container, and require separate signed authority for sensitive external effects.

## What works

| Capability | Qualified behavior |
| --- | --- |
| upstream runtime | OpenClaw `2026.7.1`, exact source revision and official OCI image digest |
| platform | Linux on `amd64` |
| useful work | OpenClaw loads and runs the `steward-workspace-audit` custom skill |
| tools | `read` and `exec`, inside the outer Steward capsule |
| inference | one operator-selected OpenAI-compatible model alias through Steward's fixed relay |
| service | health, negotiation, submit run, and read run status on port `18789` |
| state | fixed `/home/node/.openclaw` lineage volume on an explicitly dedicated host |
| isolation | gVisor, UID/GID `65532:65532`, read-only root, no Linux capabilities, no public route during qualification |

The retained [qualification evidence]({{ '/reference/evidence/openclaw-feasibility.json' | relative_url }})
contains only hashes and gate outcomes. It records a real tool call, deterministic
workspace result, restart, and rejected skill tamper. It contains no prompt, model
response, tool output, or workspace content.

## Try the complete path

Use a disposable Linux `amd64` host with Docker, gVisor's `runsc` runtime, and at
least 6 GiB of free space. The qualification creates and removes temporary Docker
containers, a private network, a volume, and the loaded adapter image. Do not run it
on a host where those names or resources matter.

Create an owner-only build directory:

```console
mkdir -m 700 "$HOME/steward-openclaw"
```

On an installed Steward node, build one offline-transferable bundle:

```console
/usr/local/libexec/steward/build-openclaw-adapter \
  --output "$HOME/steward-openclaw/bundle"
```

From a source checkout, use `scripts/build-openclaw-adapter.sh` instead. Add
`--non-interactive` in automation. The builder pulls only the exact digest-pinned
official OpenClaw base image; Docker then assembles the adapter with build-time
network access disabled. The new bundle contains:

```text
bundle/
├── attestation.json
└── image.tar
```

`attestation.json` is canonical build metadata, not a signature. It records the
upstream and adapter revisions, archive hash, OCI manifest and config digests, and
runtime image ID. Authenticate the Steward release or checkout before trusting it.

Run the destructive qualification:

```console
mkdir -m 700 "$HOME/steward-openclaw/evidence"
STEWARD_ACCEPT_DISPOSABLE_HOST_RISK=YES \
  /usr/local/libexec/steward/openclaw-feasibility \
  --bundle "$HOME/steward-openclaw/bundle" \
  --output "$HOME/steward-openclaw/evidence/feasibility.json"
```

A successful final line is:

```text
OpenClaw feasibility passed; metadata-only evidence: /home/you/steward-openclaw/evidence/feasibility.json
```

This is more than a container health check. The gate makes OpenClaw call the real
custom skill through an OpenAI-compatible model fixture, verifies the deterministic
result, restarts the container and runs the skill again, then changes the persisted
skill and requires startup to fail closed.

## Inspect and admit the exact image

Inspect the archive without loading it into Docker:

```console
stewardctl image inspect \
  -archive "$HOME/steward-openclaw/bundle/image.tar"
```

Copy the returned `manifest_digest`, `config_digest`, and `platform` into the
publisher-signed capsule for profile `openclaw-v1@v1`. The signed runtime command is
`["serve"]`, and the declared service port is `18789`. Authorize the exact
repository provenance separately in site policy, then import the same archive
bytes:

```console
sudo stewardctl image import \
  -archive "$HOME/steward-openclaw/bundle/image.tar" \
  -capsule openclaw-capsule.dsse.json \
  -policy site-policy.dsse.json \
  -site-root-public-key site-root.public \
  -site-root-key-id site-root-1
```

Follow [signed admission]({{ '/guides/signed-admission/' | relative_url }}) for the
complete capsule, site-policy, and instance-intent workflow. Import proves the
archive identity and static image contract. The separate feasibility record proves
the tested OpenClaw behavior for the exact build; neither grants deployment
authority by itself.

## Submit agent work

The adapter accepts one active run and retains at most 64 completed run records.
Its private HTTP contract is:

```http
POST /v1/runs
Content-Type: application/json

{"message":"Run the Steward workspace audit.","session_id":"operator-example"}
```

It returns `202` with a `run_id`. Read the terminal record with:

```http
GET /v1/runs/run_0123456789abcdef0123456789abcdef
```

Do not publish port `18789`. Configure it as the capsule's one private service and
reach it through Steward's authenticated service path. For tenant-authorized work,
scope an off-node task key to the configured OpenClaw service operation, sign the
exact JSON request, then use `stewardctl task submit`, `task status`, or `task wait`.
The [task lifecycle reference]({{ '/reference/offline-tools/#submit-and-recover-a-service-task' | relative_url }})
explains retries and offline audit. A successful retry returns the recorded run ID
without dispatching the request again while the same Gateway ledger epoch remains.

## Security boundary

OpenClaw still decides when to use `read` or `exec`. Treat the model, prompt, skill,
workspace, configuration, and upstream image as untrusted. `exec` can run commands
inside the capsule and can damage the workload's own writable state. The security
claim is the outer boundary: exact admitted image, gVisor, fixed non-root identity,
read-only root, fixed state path, resource ceilings, mediated inference, and no
undeclared network route.

Do not place provider keys, passwords, recovery codes, channel tokens, OAuth
material, or a Docker socket in the image or workspace. Steward gives the agent a
fixed placeholder inference key; Gateway injects the real upstream credential only
on the trusted relay connection. Use the [secret materialization guide]({{ '/guides/secrets/' | relative_url }})
to keep inference and connector credentials in owner-only Gateway files.

For external changes such as sending a message, changing an account, or mutating
infrastructure, use [Authorized Effects]({{ '/guides/authorized-effects/' | relative_url }}).
It assumes the agent has been manipulated and requires separate signed authority
for the exact connector request before DNS. It does not cover unmanaged browser
sessions, local files, computer use, or credentials given directly to OpenClaw.

## Deliberate limits

The qualification does not include OpenClaw Gateway, Control UI, channels, browser
control, cron, plugins, remote nodes, multicast discovery, arbitrary skills, host
mounts, extra ports, or nested Docker sandboxes. Adding one of those features needs
a new signed capability contract and its own adversarial qualification. Another
OpenClaw installation reaching that feature is not evidence that it is safe or
supported through Steward.

The adapter reuses the exact official OCI release instead of reproducing it from
source. Sites that require a source-reproducible OpenClaw image must create and
qualify a separate build recipe. See [ADR 0025]({{ '/decisions/0025-qualify-a-closed-openclaw-agent-surface/' | relative_url }})
for this buy-versus-build decision and its tradeoffs.
