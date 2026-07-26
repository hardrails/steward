#!/usr/bin/env python3
"""Update the AWS cluster module's gVisor lock from verified local archives."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import stat
import sys
import tarfile

VERSION = re.compile(r"^20[0-9]{6}(?:\.[0-9]+)?$")
MAX_ARCHIVE_BYTES = 200 * 1024 * 1024
EXPECTED_MEMBERS = {
    "containerd-shim-runsc-v1": "file",
    "gvisor-bin": "directory",
    "gvisor-bin/checkpointgofer": "file",
    "gvisor-bin/runsc-metric-server": "file",
    "runsc": "file",
}
ARCHES = {
    "amd64": "x86_64",
    "arm64": "aarch64",
}


def version_tuple(value: str) -> tuple[int, int]:
    if VERSION.fullmatch(value) is None:
        raise ValueError("gVisor version must be YYYYMMDD or YYYYMMDD.N")
    date, separator, revision = value.partition(".")
    return int(date), int(revision) if separator else 0


def inspect_archive(path: pathlib.Path) -> dict[str, object]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{path} must be a regular non-symlink file")
    size = path.stat().st_size
    if size <= 1 or size > MAX_ARCHIVE_BYTES:
        raise ValueError(f"{path} has an invalid size")

    digest = hashlib.sha512()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)

    with tarfile.open(path, mode="r:bz2") as archive:
        members = archive.getmembers()
        if len(members) != len(EXPECTED_MEMBERS):
            raise ValueError(f"{path} has an unexpected member count")
        observed: dict[str, str] = {}
        for member in members:
            kind = "directory" if member.isdir() else "file" if member.isfile() else "unsafe"
            if member.name in observed:
                raise ValueError(f"{path} repeats archive member {member.name}")
            observed[member.name] = kind
            if kind == "unsafe":
                raise ValueError(f"{path} contains a link or special member")
            if kind == "file" and not member.mode & stat.S_IXUSR:
                raise ValueError(f"{path} contains a non-executable gVisor binary")
        if observed != EXPECTED_MEMBERS:
            raise ValueError(f"{path} has an unexpected inventory")

    return {"size": size, "sha512": digest.hexdigest()}


def update(
    lock_path: pathlib.Path,
    version: str,
    archives: dict[str, pathlib.Path],
) -> bool:
    requested = version_tuple(version)
    current = json.loads(lock_path.read_text(encoding="utf-8"))
    if (
        not isinstance(current, dict)
        or current.get("schema_version") != "steward.aws-cluster-source-lock.v1"
        or not isinstance(current.get("steward"), dict)
        or not isinstance(current.get("gvisor"), dict)
        or not isinstance(current["gvisor"].get("version"), str)
    ):
        raise ValueError("current AWS cluster source lock is invalid")
    if requested < version_tuple(current["gvisor"]["version"]):
        raise ValueError("refusing to downgrade the gVisor lock")
    if set(archives) != set(ARCHES):
        raise ValueError("both amd64 and arm64 archives are required")

    archive_locks = {}
    for architecture, upstream_arch in ARCHES.items():
        archive_locks[architecture] = {
            "upstream_arch": upstream_arch,
            **inspect_archive(archives[architecture]),
        }

    candidate = {
        "schema_version": "steward.aws-cluster-source-lock.v1",
        "steward": current["steward"],
        "gvisor": {
            "repository": "https://github.com/google/gvisor",
            "license": "Apache-2.0",
            "version": version,
            "archives": archive_locks,
        },
    }
    encoded = json.dumps(candidate, indent=2) + "\n"
    if lock_path.read_text(encoding="utf-8") == encoded:
        return False
    lock_path.write_text(encoded, encoding="utf-8")
    return True


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lock", type=pathlib.Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--amd64-archive", type=pathlib.Path, required=True)
    parser.add_argument("--arm64-archive", type=pathlib.Path, required=True)
    args = parser.parse_args()
    try:
        changed = update(
            args.lock,
            args.version,
            {"amd64": args.amd64_archive, "arm64": args.arm64_archive},
        )
    except (OSError, ValueError, json.JSONDecodeError, tarfile.TarError) as error:
        print(f"update-aws-cluster-gvisor-pin: {error}", file=sys.stderr)
        return 2
    print("updated" if changed else "current")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
