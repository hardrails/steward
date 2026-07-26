---
title: Build a Steward management cluster
description: Form a pinned, hardened RKE2 cluster on connected or air-gapped Linux servers, add servers and workers safely, and verify failover.
section: How-to guide
---

# Build a Steward management cluster

Steward can turn clean systemd Linux servers into a pinned RKE2 cluster. The
installer downloads or consumes only the artifacts named by the installed
`stewardctl`, writes a reviewed CIS configuration, registers gVisor, and verifies
the resulting node.

This is a **management-cluster foundation**. It does not move agent workloads to
Kubernetes. Current agents still run through Steward Executor with Docker and
gVisor. That separation matters: Kubernetes administrators normally have host-level
authority over Kubernetes worker nodes, while Steward Control is intentionally
unable to mint tenant-signed agent authority.

## What the installer configures

- the exact RKE2 release pinned by the installed Steward binary;
- the RKE2 CIS profile and required host sysctls;
- Kubernetes secret encryption;
- Canal container networking;
- scheduled local etcd snapshots on server nodes;
- no bundled ingress controller;
- a `runsc` RuntimeClass;
- restricted `steward-system` and `steward-agents` namespaces;
- disabled default service-account token mounting; and
- default-deny ingress and egress in both Steward namespaces.

The installer refuses an active `firewalld`, unmanaged RKE2 or Kubernetes state,
unexpected archive contents, unsafe join-token permissions, and configuration
drift. Repeating the exact successful command is safe.

## Prepare every host

Use a clean `amd64` or `arm64` Linux server with systemd and iptables. RKE2's
minimum is 2 CPUs and 4 GiB RAM; 4 CPUs, 8 GiB RAM, and SSD-backed storage are the
practical starting point for a server. Give every node a unique name.

Install the matching Steward release and gVisor before running the cluster
installer. These regular executables must exist:

```console
/usr/local/bin/stewardctl
/usr/local/bin/runsc
/usr/local/bin/containerd-shim-runsc-v1
/usr/local/libexec/steward/install-cluster
```

RKE2 supplies containerd. A cluster-only node does not need Docker, although a
separate Steward Executor node still does.

If NetworkManager manages the host, configure it to ignore CNI-created interfaces.
Do not expose the Canal VXLAN port to the public Internet. Permit these flows only
between cluster nodes or from a protected management network:

| Protocol and port | Source | Destination | Purpose |
| --- | --- | --- | --- |
| TCP 9345 | All cluster nodes | Servers | RKE2 registration and supervisor |
| TCP 6443 | All cluster nodes and approved operators | Servers | Kubernetes API |
| TCP 10250 | Cluster nodes | Cluster nodes | kubelet and metrics |
| TCP 2379–2381 | Servers | Servers | etcd client, peer, and metrics |
| UDP 8472 | Cluster nodes | Cluster nodes | Canal VXLAN |
| TCP 9099 | Cluster nodes | Cluster nodes | Canal health |

Open NodePort range 30000–32767 only if a reviewed service requires it. The
baseline does not require public NodePorts.

## Inspect the exact plan

Planning is read-only and does not require root:

<!-- cli-flags: cluster plan init | -cluster -node -arch -air-gap -no-start -output -->
```console
stewardctl cluster plan init -cluster site-a -node server-1
stewardctl cluster plan init -cluster site-a -node server-1 -output config
```

Inspect the pinned dependency and artifact identities:

<!-- cli-flags: cluster artifact bundle | -arch -output -->
```console
stewardctl cluster artifact bundle -arch amd64
stewardctl cluster artifact images -arch amd64
```

The human plan explains the role, version, source, network mode, and security
baseline. The config form is the exact RKE2 configuration the privileged installer
will write.

## Create the first server

On the first clean host:

```console
sudo /usr/local/libexec/steward/install-cluster init \
  --cluster site-a \
  --node server-1
```

The connected path downloads the locked RKE2 bundle over TLS, bounds the transfer,
and verifies its exact size, SHA-256, archive inventory, file types, and embedded
version before writing the host.

RKE2 may report its systemd service active before Kubernetes has marked the node
Ready. Wait briefly, then run:

```console
sudo /usr/local/libexec/steward/install-cluster doctor --node server-1
```

The doctor checks the service, the real Kubernetes Ready condition, secret
encryption status, the `runsc` RuntimeClass, and the Steward namespace baseline.

## Add two more servers

Use three server nodes for embedded-etcd quorum. An even number does not increase
failure tolerance. Put a protected internal TCP load balancer, virtual IP, or
stable DNS name in front of healthy servers for subsequent joins and clients.

RKE2 writes the secure server token to:

```console
/var/lib/rancher/rke2/server/token
```

This is not an ordinary enrollment token. Anyone holding it effectively has full
cluster-administrator access, and RKE2 also uses it to protect bootstrap data.
Transfer it through an approved confidential channel, retain it with protected
etcd backups, and never place it in Terraform state, instance metadata, shell
history, or logs.

Stage the transferred token as a root-owned, single-link file on each joining
server:

```console
sudo install -o root -g root -m 0600 \
  /secure-transfer/server.token \
  /root/server.token
```

Then join each clean server:

```console
sudo /usr/local/libexec/steward/install-cluster join-server \
  --cluster site-a \
  --node server-2 \
  --server https://server-1.internal:9345 \
  --token-file /root/server.token

sudo rm -f /root/server.token
sudo /usr/local/libexec/steward/install-cluster doctor --node server-2
```

Repeat with a unique node name for the third server. The installer retains the
required credential at `/etc/rancher/rke2/steward-join-token` with mode `0600`.

## Add cluster workers with short-lived credentials

Do not distribute the server token to ordinary cluster workers. On an active
server, issue a secure bootstrap token that expires automatically:

```console
sudo /usr/local/libexec/steward/install-cluster token create \
  --out /root/worker.token \
  --ttl 15m
```

Transfer that file confidentially and stage it on the new worker with root
ownership and mode `0600`. Then run:

```console
sudo /usr/local/libexec/steward/install-cluster join-worker \
  --cluster site-a \
  --node worker-1 \
  --server https://cluster.internal:9345 \
  --token-file /root/worker.token

sudo rm -f /root/worker.token
sudo /usr/local/libexec/steward/install-cluster doctor --node worker-1
```

The wrapper accepts lifetimes from 1 minute through 1 hour. The secure token binds
the cluster CA hash, so the worker authenticates the cluster before sending its
credential. The worker doctor uses its kubelet credential, not a cluster-admin
kubeconfig.

## Verify the cluster

On a server:

```console
sudo /var/lib/rancher/rke2/bin/kubectl \
  --kubeconfig /etc/rancher/rke2/rke2.yaml \
  get nodes

sudo /var/lib/rancher/rke2/bin/kubectl \
  --kubeconfig /etc/rancher/rke2/rke2.yaml \
  -n kube-system get pods -l component=etcd
```

All expected nodes must be `Ready`; every server must have a ready etcd pod.
Also verify the defaults Steward relies on:

```console
sudo /var/lib/rancher/rke2/bin/kubectl \
  --kubeconfig /etc/rancher/rke2/rke2.yaml \
  get runtimeclass runsc

sudo /var/lib/rancher/rke2/bin/kubectl \
  --kubeconfig /etc/rancher/rke2/rke2.yaml \
  -n steward-agents get networkpolicy default-deny
```

Test quorum before relying on it: stop one server, use another server's local
kubeconfig to create, read, and delete a harmless ConfigMap, then restart the first
server and wait for all three etcd pods. A read alone does not prove that etcd can
commit new state.

## Install without public network access

On a connected staging system with the matching Steward release, ask the binary
for the exact filenames, URLs, sizes, and SHA-256 values:

```console
stewardctl cluster artifact bundle -arch amd64
stewardctl cluster artifact images -arch amd64
```

Download those two exact files, authenticate the Steward release and transfer
manifest through the site's normal supply-chain process, and copy them to each
target. Stage them under a root-owned directory using the filenames reported by
`stewardctl`:

```console
sudo install -d -o root -g root -m 0700 /root/steward-rke2
sudo install -o root -g root -m 0600 \
  /media/rke2/<bundle-file> \
  /root/steward-rke2/<bundle-file>
sudo install -o root -g root -m 0600 \
  /media/rke2/<images-file> \
  /root/steward-rke2/<images-file>
```

Run the same operation with the offline directory:

```console
sudo /usr/local/libexec/steward/install-cluster init \
  --cluster site-a \
  --node server-1 \
  --offline-dir /root/steward-rke2
```

The installer never falls back to the public network in offline mode. It imports
the complete image archive and configures containerd to disable default registry
endpoints. A missing image is routed to an unused loopback endpoint and fails
closed instead of attempting Docker Hub, GHCR, Quay, or another external registry.
Initial import can take several minutes.

An air-gapped security group or firewall still needs the internal cluster flows
listed above and an explicit return path for the site's approved management
connection. "Air-gapped" means no public dependency; it does not require breaking
the operator's authenticated internal SSH, serial-console, or management route.

Use `--no-start` when artifacts must be installed before the internal cluster
network is available. Start the recorded `rke2-server` or `rke2-agent` service only
after the intended network policy is active.

## Recovery and replacement

- Repeating the exact install command verifies the retained configuration and
  artifact lock. It does not silently rewrite drift.
- A different cluster, role, node name, version, baseline, join credential, or
  containerd runtime configuration is rejected.
- Preserve etcd snapshots and the server token together. A snapshot without the
  matching token is not a complete recovery set.
- Treat a failed or compromised node as disposable. Drain it when possible, remove
  its cluster membership from a healthy server, destroy the host, and rebuild from
  a known-good image.
- Do not treat `rke2-uninstall.sh` as a sanitization boundary. Qualification found
  that an interrupted or failed host can retain processes, mounts, or network
  state after an in-place uninstall.
- Keep the Kubernetes API, supervisor, etcd, kubelet, and CNI ports private.
- Monitor RKE2 security notices and review every proposed pin update. Steward's
  scheduled workflow opens a pull request; it never auto-merges a new substrate.

## Qualification scope

Disposable AWS testing covered:

- Ubuntu 24.04 `amd64`: connected server, worker, three-server HA, quorum loss and
  recovery, air-gapped install, reboot, gVisor, and default-deny egress;
- Ubuntu 24.04 `arm64`: connected server and a real gVisor workload;
- Amazon Linux 2023 `amd64`: connected server; and
- malformed joins, exact reruns, credential permissions, CIS mode, restricted
  namespaces, service-account tokens, secret encryption, and fail-closed image
  resolution.

This is not exhaustive operating-system certification or a workload-scale result.
Run the same acceptance on the exact kernel, image, network, storage, gVisor
release, and instance type selected for production.

For upstream operating details, see the
[RKE2 requirements](https://docs.rke2.io/install/requirements),
[token model](https://docs.rke2.io/security/token),
[CIS hardening guide](https://docs.rke2.io/security/hardening_guide), and
[air-gap guide](https://docs.rke2.io/install/airgap).
