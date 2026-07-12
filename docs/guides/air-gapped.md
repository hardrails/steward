---
title: Install Steward in an air-gapped environment
description: Import, verify, install, enroll, and activate Steward and gVisor without network access from the target Linux server.
section: How-to guide
---

# Install Steward in an air-gapped environment

Steward's offline path performs no Steward network request from the target host.
Prepare and authenticate the release outside the facility, transfer it through your
approved media process, and install from a local directory.

## Build the import set

Download these files for the release and target architecture:

- `install-steward.sh`
- `checksums.txt`
- one matching `steward-node_<version>_<arch>.deb`,
  `steward-node_<version>_<arch>.rpm`, or
  `steward_<version>_linux_<arch>.tar.gz`
- your two node credential JSON files and control-plane CA certificate

If gVisor is not already installed, also download the official `runsc` and
`containerd-shim-runsc-v1` binaries for the host architecture plus each matching
`.sha512` file.

## Authenticate before transfer

`checksums.txt` detects an altered release file only after you have independently
authenticated the manifest. Put the complete set inside your organization's signed
outer bundle, software repository, or controlled-media manifest. Record:

- Steward release tag and Git commit;
- artifact SHA-256 values;
- source registry digests for approved agent images;
- gVisor release and SHA-512 values; and
- the identity and approval that authorized import.

## Verify inside the facility

```console
cd /media/steward-v1.2.0
sha256sum -c checksums.txt
```

On macOS staging systems use `shasum -a 256 -c checksums.txt`; the target Linux
installer selects an available SHA-256 utility itself.

## Install without network access

```console
sudo bash /media/steward-v1.2.0/install-steward.sh \
  --offline-dir /media/steward-v1.2.0 \
  --control-plane-url https://control.customer.example \
  --steward-credential /media/enrollment/steward.json \
  --executor-credential /media/enrollment/executor.json \
  --ca-file /media/enrollment/control-plane-ca.pem
```

For offline gVisor installation add:

```console
  --install-gvisor --gvisor-dir /media/gvisor
```

For automation, add `--non-interactive`. The installer fails rather than falling
back to the internet when `--offline-dir` is present.

## Import agent images separately

Executor never pulls an image. Use the facility's approved registry mirror or
transfer an OCI archive, verify its recorded digest, then load it before provisioning:

```console
docker load --input /media/images/agent-approved.tar
docker image inspect registry.internal/agent@sha256:<digest>
```

Use exactly that repository digest in the Executor workload. Tags and bare image IDs
are rejected.

## Prove the node stayed offline

Run preflight and inspect service configuration:

```console
sudo /usr/local/libexec/steward/node-preflight
sudo systemctl cat steward steward-executor
docker info --format '{% raw %}{{json .Runtimes}}{% endraw %}'
```

Steward's uplinks may target an on-premises control plane. In a fully disconnected
staging phase, install with `--stage-only` and leave services disabled until the
internal control plane and PKI are ready.

See [release artifacts]({{ '/reference/release-artifacts/' | relative_url }}) for
the exact file matrix and [security model]({{ '/concepts/security-model/' | relative_url }})
for the trust assumptions this process does and does not remove.
