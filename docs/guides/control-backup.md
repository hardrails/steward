---
title: Back up and restore Steward Control
description: Create, verify, transfer, and restore one bounded Steward Control checkpoint without copying an inconsistent write-ahead log or changing controller identities.
section: How-to guide
---

# Back up and restore Steward Control

A controller backup is the recovery copy of the site's authority and retained
fleet state. It contains the authentication key, online controller signing key,
evidence-witness private key, snapshots, and write-ahead log. Anyone who obtains
the archive may be able to impersonate the controller or validate stolen bearer
credentials. Any additional regular file in the state directory is included too;
that can include a plaintext bootstrap token in a manually initialized layout.
Encrypt the archive outside Steward, restrict its custody, and treat exposure as
a site-identity incident.

`stewardctl control backup` replaces manual state-directory copying for the
default packaged layout. It provides three guarantees:

- `create` acquires Control's exclusive writer lock and refuses a running
  controller. It validates the retained state and the complete default identity
  set before writing one new `0600` tar archive.
- `verify` parses the archive without extracting it. It rejects undeclared files,
  path traversal, links, unsafe modes, duplicate or non-canonical inventory,
  oversized content, trailing entries, and digest changes.
- `restore` writes only into a new directory. It verifies every file while
  extracting, reopens the restored state through Control's normal recovery
  reader, validates both signing identities, and publishes the directory only
  after those checks pass. Preview is the default; mutation requires `-apply`.

This is a crash-consistent checkpoint of one controller. It is not high
availability, replication, or protection against a controller that was already
compromised when the backup was created.

## Create a backup

The packaged service owns `/var/lib/steward-control`. Prepare a separate
owner-only working directory, stop Control, and run the command as that same
service identity:

```console
sudo install -d -m 0700 -o steward-control -g steward-control /var/lib/steward-recovery
sudo systemctl stop steward-control
sudo -u steward-control stewardctl control backup create \
  -state-dir /var/lib/steward-control \
  -out /var/lib/steward-recovery/control-backup.tar
```

The output is a small JSON report with the archive SHA-256 digest, checkpoint
generation and sequence, file count, and payload bytes. Record that report in a
separate trusted system. `create` refuses to overwrite an archive and refuses an
output path inside the live state directory.

Opening the stopped store applies the same narrow recovery rule as Control
startup: an incomplete final write-ahead-log frame may be truncated. A complete
frame, hash mismatch, invalid identity, unsafe file, or other corruption fails
closed.

Restart the unchanged controller after the archive and report have been moved to
approved custody:

```console
sudo systemctl start steward-control
sudo systemctl is-active --quiet steward-control
```

## Verify after transfer

Keep the archive owner-only on the verification system:

```console
chmod 0600 ./control-backup.tar
stewardctl control backup verify -in "$PWD/control-backup.tar"
```

Compare `archive_sha256` with the independently retained creation report. The
archive is self-checking, but an attacker who can replace both the archive and an
untrusted copy of its report has not been detected. Put the report or archive
digest under separate operator-controlled integrity protection.

## Preview and apply a restore

Never restore over the live directory. Create an owner-only staging parent on the
destination host and make the service identity its owner:

```console
sudo install -d -m 0700 -o steward-control -g steward-control /var/lib/steward-recovery
sudo install -m 0600 -o steward-control -g steward-control \
  ./control-backup.tar /var/lib/steward-recovery/control-backup.tar
```

Preview validates the full archive and reports the intended destination without
creating it:

```console
sudo -u steward-control stewardctl control backup restore \
  -in /var/lib/steward-recovery/control-backup.tar \
  -state-dir /var/lib/steward-recovery/restored-control
```

Apply the same restore only after reviewing that report:

```console
sudo -u steward-control stewardctl control backup restore \
  -in /var/lib/steward-recovery/control-backup.tar \
  -state-dir /var/lib/steward-recovery/restored-control \
  -apply
```

The destination and every restored file are owned by the identity running the
command. Running as `steward-control` avoids a recursive ownership repair that
could weaken permissions or cross filesystem boundaries.

## Cut over

Stop Control before changing directories. Preserve the failed or old directory;
do not merge individual files from it into the restored checkpoint.

```console
sudo systemctl stop steward-control
sudo mv /var/lib/steward-control /var/lib/steward-control.before-restore
sudo mv /var/lib/steward-recovery/restored-control /var/lib/steward-control
sudo steward-control -check-config -state-dir /var/lib/steward-control
sudo systemctl start steward-control
sudo systemctl is-active --quiet steward-control
```

Then verify the controller through its configured TLS origin and run the normal
node and command checks. A restored checkpoint intentionally rolls retained state
back to its recorded sequence. Nodes may have newer evidence or command outcomes;
inspect reconciliation and evidence findings before issuing new authority.

## Limits

- The supported archive contains at most 128 regular top-level state files,
  128 MiB per file, and 256 MiB of payload. The normal Control snapshot and
  write-ahead-log limits remain 64 MiB each.
- The command supports the default self-contained identity layout. If
  `-auth-key-file`, controller key paths, or witness key paths point outside the
  state directory, `create` fails. Backing up loosely related external files
  would not provide one atomic recovery boundary.
- TLS private keys, external policy roots, tenant signing keys, Gateway state,
  Executor receipts, workload state, secret-manager data, and application bundles
  are separate recovery domains.
- Restoring availability does not prove the checkpoint was honest. Retain witness
  public keys and evidence heads outside the controller so rollback or identity
  substitution remains detectable.
