#!/usr/bin/env python3
"""Update Steward's Hermes source pin from an exact, clean release checkout."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import stat
import subprocess
import sys
import tempfile
from typing import Any


REPOSITORY = "https://github.com/NousResearch/hermes-agent.git"
RELEASE_RE = re.compile(r"v[0-9]+(?:\.[0-9]+){2}")
VERSION_RE = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")
REVISION_RE = re.compile(r"[a-f0-9]{40}")
SHA256_RE = re.compile(r"[a-f0-9]{64}")
MAX_SOURCE_FILE_BYTES = 64 << 20
SOURCE_INPUTS = ("LICENSE", "pyproject.toml", "uv.lock", "package-lock.json")


def fail(message: str) -> "NoReturn":
    raise SystemExit(f"update-hermes-pin: {message}")


def git(source: pathlib.Path, *arguments: str) -> str:
    environment = dict(os.environ)
    for name in (
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_CEILING_DIRECTORIES",
        "GIT_COMMON_DIR",
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_PARAMETERS",
        "GIT_DIR",
        "GIT_INDEX_FILE",
        "GIT_NAMESPACE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_SHALLOW_FILE",
        "GIT_WORK_TREE",
    ):
        environment.pop(name, None)
    environment.update(
        {
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_NO_REPLACE_OBJECTS": "1",
        }
    )
    completed = subprocess.run(
        [
            "git",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.hooksPath=/dev/null",
            "-C",
            str(source),
            *arguments,
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
        env=environment,
    )
    if completed.returncode != 0 or completed.stderr:
        fail(f"git {' '.join(arguments)} failed")
    return completed.stdout.strip()


def read_source_file(source: pathlib.Path, relative: str) -> bytes:
    path = source / relative
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        fail(f"release checkout is missing {relative}")
    if not stat.S_ISREG(info.st_mode) or info.st_size <= 0 or info.st_size > MAX_SOURCE_FILE_BYTES:
        fail(f"release checkout has an invalid {relative}")
    with path.open("rb") as stream:
        before = os.fstat(stream.fileno())
        content = stream.read(MAX_SOURCE_FILE_BYTES + 1)
        after = os.fstat(stream.fileno())
    named_after = os.lstat(path)
    identity = lambda item: (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
    if len(content) != info.st_size or identity(info) != identity(before) or identity(before) != identity(after) or identity(after) != identity(named_after):
        fail(f"release checkout changed while reading {relative}")
    return content


def digest(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def replace_exact(content: str, old: str, new: str, label: str, expected: int = 1) -> str:
    if content.count(old) != expected:
        fail(f"{label} does not contain exactly {expected} expected pin occurrence(s)")
    return content.replace(old, new)


def write_atomic(path: pathlib.Path, content: bytes) -> None:
    mode = stat.S_IMODE(os.lstat(path).st_mode)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = pathlib.Path(temporary_name)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def canonical_json(document: Any) -> bytes:
    return (json.dumps(document, indent=2, ensure_ascii=True) + "\n").encode()


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Update Steward's Hermes pin from a clean checkout of an exact stable release tag."
    )
    parser.add_argument("--source-dir", required=True, help="clean Hermes release checkout")
    parser.add_argument("--release-tag", required=True, help="exact stable Hermes release tag")
    parser.add_argument(
        "--repository-root",
        default=str(pathlib.Path(__file__).resolve().parent.parent),
        help="Steward checkout to update",
    )
    parser.add_argument("--check", action="store_true", help="report drift without writing files")
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    release = arguments.release_tag
    if RELEASE_RE.fullmatch(release) is None:
        fail("release tag must be a stable vX.Y.Z tag")

    source = pathlib.Path(arguments.source_dir)
    root = pathlib.Path(arguments.repository_root)
    if source.is_symlink() or not source.is_dir():
        fail("source directory must be a real directory")
    if root.is_symlink() or not root.is_dir():
        fail("repository root must be a real directory")

    revision = git(source, "rev-parse", "HEAD")
    if REVISION_RE.fullmatch(revision) is None:
        fail("release checkout has an invalid commit ID")
    tagged_revision = git(source, "rev-parse", f"refs/tags/{release}^{{commit}}")
    if tagged_revision != revision:
        fail("release tag does not resolve to the checked-out commit")
    if git(source, "status", "--porcelain=v1", "--untracked-files=all"):
        fail("release checkout is not clean")

    source_files = {name: read_source_file(source, name) for name in SOURCE_INPUTS}
    pyproject = source_files["pyproject.toml"].decode("utf-8")
    versions = re.findall(r'^version = "([^"]+)"$', pyproject, flags=re.MULTILINE)
    if len(versions) != 1 or VERSION_RE.fullmatch(versions[0]) is None:
        fail("pyproject.toml does not declare one stable package version")
    version = versions[0]
    hashes = {name: digest(content) for name, content in source_files.items()}
    if any(SHA256_RE.fullmatch(value) is None for value in hashes.values()):
        fail("internal source digest is invalid")

    adapter_path = root / "adapters/hermes-agent/adapter.json"
    adapter = json.loads(adapter_path.read_text(encoding="utf-8"))
    upstream = adapter.get("upstream")
    if (
        adapter.get("schema_version") != "steward.adapter-source.v1"
        or not isinstance(upstream, dict)
        or upstream.get("repository") != REPOSITORY
        or REVISION_RE.fullmatch(str(upstream.get("revision", ""))) is None
    ):
        fail("Steward adapter metadata is not the expected Hermes contract")
    old_revision = upstream["revision"]
    upstream["release"] = release
    upstream["version"] = version
    upstream["revision"] = revision
    upstream["license_sha256"] = hashes["LICENSE"]

    build_inputs = adapter.get("build_inputs")
    expected_build_inputs = SOURCE_INPUTS[1:]
    if (
        not isinstance(build_inputs, list)
        or [item.get("path") for item in build_inputs if isinstance(item, dict)] != list(expected_build_inputs)
    ):
        fail("Steward adapter has an unexpected Hermes build-input inventory")
    for item in build_inputs:
        item["sha256"] = hashes[item["path"]]

    license_path = root / "adapters/hermes-agent/license-inventory.json"
    license_inventory = json.loads(license_path.read_text(encoding="utf-8"))
    if license_inventory.get("upstream_revision") != old_revision:
        fail("Hermes license inventory pin differs from adapter metadata")
    license_inventory["upstream_release"] = release
    license_inventory["upstream_version"] = version
    license_inventory["upstream_revision"] = revision
    license_inventory["source_license_sha256"] = hashes["LICENSE"]

    updates: dict[pathlib.Path, bytes] = {
        adapter_path: canonical_json(adapter),
        license_path: canonical_json(license_inventory),
        root / "adapters/hermes-agent/source-inputs.sha256": "".join(
            f"{hashes[name]}  {name}\n" for name in SOURCE_INPUTS
        ).encode(),
    }
    text_pin_files = (
        ("adapters/hermes-agent/entrypoint.py", 1),
        ("scripts/build-hermes-adapter.sh", 1),
        ("scripts/hermes-feasibility.sh", 1),
        ("docs/guides/hermes-agent.md", 2),
        ("docs/reference/release-artifacts.md", 1),
        ("docs/faq.md", 1),
        ("docs/llms.txt", 1),
    )
    for relative, expected_count in text_pin_files:
        path = root / relative
        original = path.read_text(encoding="utf-8")
        updates[path] = replace_exact(
            original, old_revision, revision, relative, expected_count
        ).encode()

    changed = []
    for path, content in updates.items():
        if path.read_bytes() != content:
            changed.append(path)
            if not arguments.check:
                write_atomic(path, content)

    result = {
        "changed": [path.relative_to(root).as_posix() for path in changed],
        "release": release,
        "revision": revision,
        "version": version,
    }
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))
    return 1 if arguments.check and changed else 0


if __name__ == "__main__":
    sys.exit(main())
