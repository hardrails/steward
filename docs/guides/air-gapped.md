---
title: Install Steward without public network access
description: Import, verify, install, and enroll Steward and gVisor without contacting a public release service from the target Linux server.
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
- `checksums.txt`
- one matching `steward-node_<version>_<arch>.deb`,
  `steward-node_<version>_<arch>.rpm`, or
  `steward_<version>_linux_<arch>.tar.gz`
- your two node credential JSON files and control-plane CA certificate
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

## Verify inside the facility

```console
RELEASE_TAG="<release-tag>"
cd "/media/steward-$RELEASE_TAG"
ARTIFACT="steward-node_${RELEASE_TAG}_amd64.deb" # select the transferred file
awk -v a="$ARTIFACT" '$2 == a || $2 == "./" a || $2 == "install-steward.sh" || $2 == "./install-steward.sh"' \
  checksums.txt > selected-checksums.txt
test "$(wc -l < selected-checksums.txt)" -eq 2
sha256sum -c selected-checksums.txt
```

On macOS staging systems use `shasum -a 256 -c selected-checksums.txt`; the target
Linux installer selects an available SHA-256 utility itself.

## Install without network access

```console
RELEASE_TAG="<release-tag>"
sudo bash "/media/steward-$RELEASE_TAG/install-steward.sh" \
  --offline-dir "/media/steward-$RELEASE_TAG" \
  --control-plane-url https://control.customer.example \
  --steward-credential /media/enrollment/steward.json \
  --executor-credential /media/enrollment/executor-node.json \
  --ca-file /media/enrollment/control-plane-ca.pem \
  --admission-policy /media/enrollment/site-policy.dsse.json \
  --site-root-public-key /media/enrollment/site-root.public \
  --site-root-key-id site-root-1 \
  --node-id node-a
```

For offline gVisor installation add:

```console
  --install-gvisor --gvisor-dir /media/gvisor
```

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

Inside the facility, import only after Steward has authenticated the artifacts and
verified that they agree:

```console
sudo stewardctl image import \
  -archive /media/images/agent-approved.tar \
  -capsule /media/trust/capsule.dsse.json \
  -policy /media/trust/site-policy.dsse.json \
  -site-root-public-key /media/trust/site-root.public \
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
