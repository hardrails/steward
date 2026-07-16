---
title: Install Steward without public network access
description: Import, verify, install, enroll, and activate Steward and a qualified Hermes release without contacting a public service from the target Linux server.
section: How-to guide
---

# Install Steward without public network access

The offline installer makes no public request from the target host. An activated
node may still poll its configured on-premises control plane. Authenticate the
release outside the facility, transfer it through approved media, and install from a
local directory.

## Build the import set

Download these files for the release and target architecture:

- `install-steward.sh`
- `install-control.sh` when the facility will run the bundled controller
- `checksums.txt`
- one matching `steward-control_<version>_linux_<arch>.tar.gz` for each controller
  host architecture
- one matching `steward-node_<version>_<arch>.deb`,
  `steward-node_<version>_<arch>.rpm`, or
  `steward_<version>_linux_<arch>.tar.gz`
- the control-plane CA certificate; when enrollment is handled by an already
  operating compatible external controller, also include its node-scoped Executor
  credential and optional generic supervisor credential
- for a multi-tenant Executor: the site-root-signed policy containing the tenant
  command keys and at least one cleanup key, plus the site-root public key

If gVisor is not already installed, also download the official `runsc` and
`containerd-shim-runsc-v1` binaries for the host architecture plus each matching
`.sha512` file.

## Authenticate before transfer

`checksums.txt` detects altered files only after independent manifest
authentication. Put the set in an organizational signed bundle, software
repository, or controlled-media manifest. Record:

- Steward release tag and Git commit;
- artifact SHA-256 values;
- source registry digests for approved agent images;
- gVisor release and SHA-512 values; and
- the identity and approval that authorized import.

## Stage and verify inside the facility

Treat removable media as transport, not as a trusted execution directory. Copy only
the authenticated files needed by this host into a root-owned staging directory.
This prevents an unprivileged process or a writable mount from replacing an
installer, archive, checksum manifest, or enrollment secret while root reads it.

```console
RELEASE_TAG="<release-tag>"
ARTIFACT="steward-node_${RELEASE_TAG}_amd64.deb" # select the transferred file
sudo install -d -o root -g root -m 0700 "/root/steward-$RELEASE_TAG"
sudo install -o root -g root -m 0700 \
  "/media/steward-$RELEASE_TAG/install-steward.sh" \
  "/root/steward-$RELEASE_TAG/install-steward.sh"
sudo install -o root -g root -m 0600 \
  "/media/steward-$RELEASE_TAG/checksums.txt" \
  "/root/steward-$RELEASE_TAG/checksums.txt"
sudo install -o root -g root -m 0600 \
  "/media/steward-$RELEASE_TAG/$ARTIFACT" \
  "/root/steward-$RELEASE_TAG/$ARTIFACT"
SELECTED_CHECKSUMS=$(sudo mktemp -p /root steward-checksums.XXXXXX)
sudo awk -v a="$ARTIFACT" '$2 == a || $2 == "./" a || $2 == "install-steward.sh" || $2 == "./install-steward.sh"' \
  "/root/steward-$RELEASE_TAG/checksums.txt" | \
  sudo tee "$SELECTED_CHECKSUMS" >/dev/null
test "$(sudo wc -l "$SELECTED_CHECKSUMS" | awk '{print $1}')" -eq 2
sudo /bin/bash -p -c 'cd "$1" && sha256sum -c "$2"' \
  steward-verify "/root/steward-$RELEASE_TAG" "$SELECTED_CHECKSUMS"
sudo rm -f "$SELECTED_CHECKSUMS"
```

On macOS staging systems use `shasum -a 256 -c selected-checksums.txt`; the target
Linux installer selects an available SHA-256 utility itself.

## Install Steward Control without network access

Install the controller on its management host before exchanging node enrollment
capabilities. The offline directory must contain `install-control.sh`,
`checksums.txt`, and the matching controller archive. After authenticating the
manifest, verify the controller installer and archive explicitly:

```console
RELEASE_TAG="<release-tag>"
CONTROL_ARCHIVE="steward-control_${RELEASE_TAG}_linux_amd64.tar.gz" # select the host architecture
sudo install -d -o root -g root -m 0700 "/root/steward-$RELEASE_TAG"
sudo install -o root -g root -m 0700 \
  "/media/steward-$RELEASE_TAG/install-control.sh" \
  "/root/steward-$RELEASE_TAG/install-control.sh"
sudo install -o root -g root -m 0600 \
  "/media/steward-$RELEASE_TAG/checksums.txt" \
  "/root/steward-$RELEASE_TAG/checksums.txt"
sudo install -o root -g root -m 0600 \
  "/media/steward-$RELEASE_TAG/$CONTROL_ARCHIVE" \
  "/root/steward-$RELEASE_TAG/$CONTROL_ARCHIVE"
CONTROL_CHECKSUMS=$(sudo mktemp -p /root steward-control-checksums.XXXXXX)
sudo awk -v a="$CONTROL_ARCHIVE" \
  '$2 == a || $2 == "./" a || $2 == "install-control.sh" || $2 == "./install-control.sh"' \
  "/root/steward-$RELEASE_TAG/checksums.txt" | \
  sudo tee "$CONTROL_CHECKSUMS" >/dev/null
test "$(sudo wc -l "$CONTROL_CHECKSUMS" | awk '{print $1}')" -eq 2
sudo /bin/bash -p -c 'cd "$1" && sha256sum -c "$2"' \
  steward-control-verify "/root/steward-$RELEASE_TAG" "$CONTROL_CHECKSUMS"
sudo rm -f "$CONTROL_CHECKSUMS"
```

Then stage the TLS identity through root-owned files and install:

```console
RELEASE_TAG="<release-tag>"
sudo install -d -o root -g root -m 0700 /root/steward-control-tls
sudo install -o root -g root -m 0644 \
  /media/steward-control-pki/server.crt /root/steward-control-tls/server.crt
sudo install -o root -g root -m 0600 \
  /media/steward-control-pki/server.key /root/steward-control-tls/server.key
sudo install -o root -g root -m 0644 \
  /media/steward-control-pki/ca.crt /root/steward-control-tls/ca.crt
sudo /bin/bash -p "/root/steward-$RELEASE_TAG/install-control.sh" \
  --non-interactive \
  --offline-dir "/root/steward-$RELEASE_TAG" \
  --admin-token-out /root/steward-control-admin.token \
  --addr 0.0.0.0:8443 \
  --tls-cert /root/steward-control-tls/server.crt \
  --tls-key /root/steward-control-tls/server.key
```

The installer makes no network fallback in offline mode. Distribute only the CA
certificate to operators and nodes; keep the CA key and controller server key in
their intended protected locations, and remove temporary staging and transfer-media
copies after successful installation. TLS inputs must be root-owned, single-link
regular files no larger than 1 MiB under a path whose complete directory chain is
root-owned and not group- or world-writable. The private key must be owner-only.
Staging with `install` above gives transferred files that metadata instead of
trusting the ownership reported by removable media. Before creating enrollments, verify the remote
certificate identity and readiness rather than relying only on the doctor's local
TCP check for a wildcard listener:

```console
sudo /usr/local/libexec/steward-control/control-doctor \
  --probe-url https://control.customer.example:8443 \
  --ca-file /root/steward-control-tls/ca.crt
```

Use `stewardctl` from the matching full release archive on a trusted administration
system to create tenants and exchange a short-lived enrollment. The dedicated
controller archive does not include operator clients. Generate the receipt key on
the staged node, use it for the enrollment proof, and retain it there. Transfer the
resulting node-scoped Executor credential, evidence config, and public CA
certificate through the facility's authenticated channel; tenant and site private
signing keys stay on their separate signing systems. Follow the
[control-plane guide]({{ '/guides/control-plane/' | relative_url }}) for the exact
commands and retry rules.

## Install without network access

```console
RELEASE_TAG="<release-tag>"
sudo install -d -o root -g root -m 0700 /root/steward-enrollment
sudo install -o root -g root -m 0600 \
  /media/enrollment/executor-node.json /root/steward-enrollment/executor-node.json
sudo install -o root -g root -m 0600 \
  /media/enrollment/executor-evidence.env /root/steward-enrollment/executor-evidence.env
sudo install -o root -g root -m 0600 \
  /secure/node-receipts.private.pem /root/steward-enrollment/node-receipts.private.pem
sudo install -o root -g root -m 0644 \
  /secure/node-receipts.public /root/steward-enrollment/node-receipts.public
sudo install -o root -g root -m 0644 \
  /media/enrollment/control-plane-ca.pem /root/steward-enrollment/control-plane-ca.pem
sudo install -o root -g root -m 0644 \
  /media/enrollment/site-policy.dsse.json /root/steward-enrollment/site-policy.dsse.json
sudo install -o root -g root -m 0644 \
  /media/enrollment/site-root.public /root/steward-enrollment/site-root.public
sudo /bin/bash -p "/root/steward-$RELEASE_TAG/install-steward.sh" \
  --offline-dir "/root/steward-$RELEASE_TAG" \
  --control-plane-url https://control.customer.example:8443 \
  --executor-credential /root/steward-enrollment/executor-node.json \
  --ca-file /root/steward-enrollment/control-plane-ca.pem \
  --admission-policy /root/steward-enrollment/site-policy.dsse.json \
  --site-root-public-key /root/steward-enrollment/site-root.public \
  --site-root-key-id site-root-1 \
  --node-id node-a \
  --executor-evidence-config /root/steward-enrollment/executor-evidence.env \
  --executor-evidence-private-key /root/steward-enrollment/node-receipts.private.pem \
  --executor-evidence-public-key /root/steward-enrollment/node-receipts.public
```

For offline gVisor installation add:

```console
  --install-gvisor --gvisor-dir /root/steward-gvisor
```

Stage the four gVisor files in `/root/steward-gvisor` with the same root-owned,
non-writable directory rule before using that option. The installer snapshots every
local input again before validation, but root staging is what establishes who may
replace the source.

For automation, add `--non-interactive`. When `--offline-dir` is present, the
installer fails instead of using the public network.

A node-scoped Executor credential authenticates the connection, not a tenant. The
command verifies policy and node ID, initializes both anti-replay stores, configures
the trusted relay, then activates the uplink. Executor creates an isolated network
later for each admitted workload that receives a network capability. Omit
signed-admission flags only for an intentional legacy single-tenant deployment.

## Import agent images separately

Executor never pulls images. Use an approved mirror, or transfer a single-image
Docker/OCI archive with its signed capsule, policy, and site-root public key. OCI is
the standard container image format. Inspect the archive before transfer and copy
its manifest digest, config digest, and platform into the capsule:

```console
chmod go-w agent-approved.tar
stewardctl image inspect -archive agent-approved.tar
```

Inside the facility, copy the authenticated inputs out of transport media, then
import only after Steward has verified that they agree:

```console
sudo install -d -o root -g root -m 0700 /root/steward-image-import
sudo install -o root -g root -m 0600 /media/images/agent-approved.tar \
  /root/steward-image-import/agent-approved.tar
sudo install -o root -g root -m 0644 /media/trust/capsule.dsse.json \
  /root/steward-image-import/capsule.dsse.json
sudo install -o root -g root -m 0644 /media/trust/site-policy.dsse.json \
  /root/steward-image-import/site-policy.dsse.json
sudo install -o root -g root -m 0644 /media/trust/site-root.public \
  /root/steward-image-import/site-root.public
sudo stewardctl image import \
  -archive /root/steward-image-import/agent-approved.tar \
  -capsule /root/steward-image-import/capsule.dsse.json \
  -policy /root/steward-image-import/site-policy.dsse.json \
  -site-root-public-key /root/steward-image-import/site-root.public \
  -site-root-key-id site-root-1
```

The importer verifies every blob and descriptor. It accepts one platform image with
no declared writable `VOLUME` and matches its manifest, config, and platform to the
capsule. Docker receives a sanitized archive with only selected image content, not
tags, unreferenced blobs, or the legacy `repositories` file. Steward then inspects
the local config digest and rejects mismatches. An existing valid image returns
`"imported":false`. Import authorizes storage; each workload still needs a
tenant-bound intent.

Do not substitute raw `docker load`: it authenticates neither capsule nor policy and
may lose the addressable repository digest. See
[image and evidence tools]({{ '/reference/offline-tools/' | relative_url }}) for the
accepted archive boundary.

## Activate a signed agent release without public Internet

For proof-carrying Hermes activation, add these authenticated files to the
facility's workload import set:

- the signed agent release and exact archive;
- the publisher public key and expected key ID through a separate trust channel;
- the qualification evidence and exact skill manifest identified by the release;
- the signed site policy and instance intent;
- the tenant task public key in policy; and
- the receipt and controller-witness public keys needed for offline review.

Keep the tenant task private key on its separate signing station. Inside the
facility, verify the release and exact transferred archive before activation:

```console
stewardctl agent-release verify \
  -in hermes-workspace-audit.release.dsse.json \
  -public-key publisher.public.pem \
  -key-id publisher-key-id \
  -archive hermes-agent-adapter.tar
```

The current Hermes activation recipe requires a dedicated host and a signed site
policy containing exactly one tenant. Configure Executor with
`--allow-host-admin-intent` and
`--allow-unquotaed-state-on-dedicated-host` before activation. The first flag
grants the host-local token administrator authority to select the signed tenant
intent and append the later activation checkpoint; it is not tenant
authentication. The second permits persistent Docker state without a hard byte
or inode quota. Neither setting is safe for a shared host.

Capture a current, finding-free controller evidence export before admission. On
the node, use `stewardctl activation create` with that baseline and the exact
release, policy, intent, archive, publisher key, site-root key, and witness key.
Then use `stewardctl activation run` with the same trust inputs. It uses only
local Docker, Executor, Gateway, and evidence paths unless you override their
packaged defaults.

The first run stops with `waiting_for: "canary_task"`. Copy these exact workspace
files to approved media or another authenticated internal transfer channel:

- `canary.challenge.json`
- `admission.json`
- `intent.json`
- `service-trust.json`
- `canary.request.json`

The signing station reviews those files and uses the existing `stewardctl task
issue` procedure to create `canary.task.json`. Return only that owner-only bundle,
attach it with:

```console
stewardctl activation attach \
  -dir "$ACTIVATION_DIR" \
  -kind canary-task \
  -in canary.task.json
```

Rerun the same `activation run` command. After the deterministic result, Steward
verifies Gateway's signed authorization, dispatch, and terminal receipts, then
asks Executor to append a content-free activation checkpoint. The request carries
the activation ID and checkpoint digest, not the begin digest. Executor matches
its persisted begin digest to the earlier signed marker and refuses the checkpoint
while readiness is degraded. It stops with `waiting_for: "final_witness"` only
after that checkpoint is durable. Wait for the evidence uplink to publish it,
then export a signed controller checkpoint. Verify the export before returning it
to the node:

```console
stewardctl control evidence verify \
  -in node-a.activation-final.json \
  -witness-public-key steward-control-witness.public.pem
```

The final export must be current and finding-free, use the same controller,
enrollment, receipt, and witness identities as the baseline, and have a greater
receipt sequence. It must cover the signed order `activation_begin`, fresh
admission allow, admission commit, runtime start, `activation_checkpoint`, then
the witness head. The node's Executor log must contain that coordinate. Unrelated
tenant receipts may follow the witnessed head; later receipts for this activation
may not. Receipt order supplies the causal link, so Gateway and controller clocks
are not compared. Confirm these conditions before attachment because the
attachment is write-once. Then attach it:

```console
stewardctl activation attach \
  -dir "$ACTIVATION_DIR" \
  -kind final-witness \
  -in node-a.activation-final.json
```

Rerun once more to reach `passed`. The tenant-specific service policy must remain
byte-for-byte consistent while live submission, observation, or Gateway receipt
collection is still required. Once the complete terminal result, status, and
portable evidence are retained, finalization and terminal recovery no longer need
the live Gateway configuration or receipt private key.

Transfer the complete workspace and pinned public keys to the audit station, then
verify without a network connection:

```console
stewardctl activation verify \
  -dir "$ACTIVATION_DIR" \
  -publisher-public-key publisher.public.pem \
  -publisher-key-id publisher-key-id \
  -site-root-public-key site-root.public \
  -site-root-key-id site-root-1 \
  -witness-public-key steward-control-witness.public.pem \
  -gateway-receipt-public-key connector-receipts.public
```

The portable Executor delta may contain non-content receipt metadata for events
from other tenants interleaved between the signed witness coordinates. Handle the
workspace as sensitive multi-tenant operational evidence; it also separately
retains the bounded canary result. Read
[agent activation]({{ '/guides/agent-activation/' | relative_url }}) for the
complete `create` and `run` commands, signing-station procedure, retry semantics,
and proof limits.

## Verify local inputs and the configured network policy

Run the node doctor and inspect service configuration. These checks validate
Steward's local inputs and observed node state; use facility firewall, proxy, DNS,
or flow records to validate the host's actual network behavior:

```console
sudo /usr/local/libexec/steward/node-doctor
sudo systemctl cat steward steward-executor steward-gateway
docker info --format '{% raw %}{{json .Runtimes}}{% endraw %}'
```

The doctor is fully local and read-only unless `--canary-bundle` and
`--canary-result` are supplied. A canary needs no public network when its signed
service operation and inference route resolve entirely inside the disconnected
environment.

Steward uplinks may target an on-premises control plane. During fully disconnected
staging, install with `--stage-only` and leave services disabled until the internal
control plane and PKI are ready.

See [release artifacts]({{ '/reference/release-artifacts/' | relative_url }}) for
the exact file matrix and [security model]({{ '/concepts/security-model/' | relative_url }})
for the trust assumptions this process does and does not remove.
