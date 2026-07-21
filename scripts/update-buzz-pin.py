#!/usr/bin/env python3
"""Update Steward's Buzz source lock from one exact stable release checkout."""

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
import tomllib
from typing import Any, NoReturn


REPOSITORY = "https://github.com/block/buzz.git"
RELEASE_RE = re.compile(r"v[0-9]+(?:\.[0-9]+){2}")
REVISION_RE = re.compile(r"[a-f0-9]{40}")
SHA256_RE = re.compile(r"[a-f0-9]{64}")
MAX_SOURCE_FILE_BYTES = 64 << 20
INPUTS = ("LICENSE", "Cargo.toml", "Cargo.lock", "rust-toolchain.toml")
COMPONENTS = ("buzz-cli",)
STEWARD_INPUTS = (
    "integrations/buzz/buzz-cli-verification.patch",
    "cmd/steward-buzz-bridge/main.go",
    "cmd/steward-buzz-bridge/main_test.go",
    "scripts/build-buzz-bridge.sh",
    "scripts/update-buzz-pin.py",
    "integrations/buzz/bridge.example.json",
    "deploy/systemd/steward-buzz-bridge.service",
    "integrations/buzz/build-release-bundle.sh",
)


def fail(message: str) -> NoReturn:
    raise SystemExit(f"update-buzz-pin: {message}")


def safe_git_environment() -> dict[str, str]:
    environment = dict(os.environ)
    for name in (
        "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_CEILING_DIRECTORIES", "GIT_COMMON_DIR",
        "GIT_CONFIG_COUNT", "GIT_CONFIG_PARAMETERS", "GIT_DIR", "GIT_INDEX_FILE",
        "GIT_NAMESPACE", "GIT_OBJECT_DIRECTORY", "GIT_SHALLOW_FILE", "GIT_WORK_TREE",
    ):
        environment.pop(name, None)
    environment.update({
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
    })
    return environment


def git(source: pathlib.Path, *arguments: str, binary: bool = False) -> bytes | str:
    completed = subprocess.run(
        ["git", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null",
         "-C", str(source), *arguments],
        check=False,
        capture_output=True,
        text=not binary,
        timeout=60,
        env=safe_git_environment(),
    )
    stderr = completed.stderr if isinstance(completed.stderr, str) else completed.stderr.decode("utf-8", "replace")
    if completed.returncode != 0 or stderr:
        fail(f"git {' '.join(arguments)} failed")
    if binary:
        return completed.stdout
    return completed.stdout.strip()


def read_source_file(source: pathlib.Path, relative: str) -> bytes:
    path = source / relative
    try:
        before = os.lstat(path)
    except FileNotFoundError:
        fail(f"release checkout is missing {relative}")
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size <= 0 or before.st_size > MAX_SOURCE_FILE_BYTES:
        fail(f"release checkout has an invalid {relative}")
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        content = os.read(descriptor, MAX_SOURCE_FILE_BYTES + 1)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    named = os.lstat(path)
    identity = lambda item: (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
    if len(content) != before.st_size or identity(before) != identity(opened) or identity(opened) != identity(after) or identity(after) != identity(named):
        fail(f"release checkout changed while reading {relative}")
    return content


def digest(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def canonical_json(document: Any) -> bytes:
    return (json.dumps(document, indent=2, ensure_ascii=True) + "\n").encode()


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


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Update the exact Buzz source lock.")
    parser.add_argument("--source-dir", required=True)
    parser.add_argument("--release-tag", required=True)
    parser.add_argument("--repository-root", default=str(pathlib.Path(__file__).resolve().parent.parent))
    parser.add_argument("--check", action="store_true")
    return parser.parse_args()


def workspace_version(root_manifest: dict[str, Any]) -> str:
    workspace = root_manifest.get("workspace")
    package = workspace.get("package") if isinstance(workspace, dict) else None
    version = package.get("version") if isinstance(package, dict) else None
    if not isinstance(version, str) or re.fullmatch(r"[0-9]+(?:\.[0-9]+){2}", version) is None:
        fail("root Cargo.toml has no stable workspace package version")
    return version


def component_version(manifest: dict[str, Any], inherited: str, name: str) -> str:
    package = manifest.get("package")
    if not isinstance(package, dict) or package.get("name") != name:
        fail(f"{name} manifest has an unexpected package name")
    version = package.get("version")
    if version == {"workspace": True}:
        return inherited
    if not isinstance(version, str) or re.fullmatch(r"[0-9]+(?:\.[0-9]+){2}", version) is None:
        fail(f"{name} manifest has an invalid version")
    return version


def main() -> int:
    arguments = parse_arguments()
    if RELEASE_RE.fullmatch(arguments.release_tag) is None:
        fail("release tag must be a stable vX.Y.Z tag")
    source = pathlib.Path(arguments.source_dir)
    root = pathlib.Path(arguments.repository_root)
    if source.is_symlink() or not source.is_dir() or root.is_symlink() or not root.is_dir():
        fail("source and repository roots must be real directories")

    revision = str(git(source, "rev-parse", "HEAD"))
    tagged = str(git(source, "rev-parse", f"refs/tags/{arguments.release_tag}^{{commit}}"))
    tree = str(git(source, "rev-parse", "HEAD^{tree}"))
    if REVISION_RE.fullmatch(revision) is None or REVISION_RE.fullmatch(tree) is None or tagged != revision:
        fail("release tag does not resolve to the checked-out commit")
    if git(source, "status", "--porcelain=v1", "--untracked-files=all"):
        fail("release checkout is not clean")

    input_bytes = {name: read_source_file(source, name) for name in INPUTS}
    input_hashes = {name: digest(value) for name, value in input_bytes.items()}
    root_manifest = tomllib.loads(input_bytes["Cargo.toml"].decode("utf-8"))
    inherited_version = workspace_version(root_manifest)
    component_entries = []
    for name in COMPONENTS:
        relative = f"crates/{name}/Cargo.toml"
        raw = read_source_file(source, relative)
        manifest = tomllib.loads(raw.decode("utf-8"))
        component_entries.append({
            "name": name,
            "version": component_version(manifest, inherited_version, name),
            "manifest": relative,
            "manifest_sha256": digest(raw),
        })
    toolchain = tomllib.loads(input_bytes["rust-toolchain.toml"].decode("utf-8"))
    rust = toolchain.get("toolchain", {}).get("channel")
    if not isinstance(rust, str) or re.fullmatch(r"[0-9]+(?:\.[0-9]+){2}", rust) is None:
        fail("rust-toolchain.toml does not pin one stable toolchain")
    archive = git(source, "archive", "--format=tar", "HEAD", binary=True)
    archive_hash = digest(archive if isinstance(archive, bytes) else archive.encode())

    lock_path = root / "integrations/buzz/source-lock.json"
    current = json.loads(lock_path.read_text(encoding="utf-8"))
    if current.get("schema_version") != "steward.buzz-source-lock.v1" or current.get("repository") != REPOSITORY:
        fail("existing Buzz source lock has an unexpected contract")
    current_revision = current.get("revision")
    if REVISION_RE.fullmatch(str(current_revision)) is None:
        fail("existing Buzz source lock has an invalid revision")
    if current_revision != revision:
        ancestor = subprocess.run(
            ["git", "-C", str(source), "merge-base", "--is-ancestor", str(current_revision), revision],
            check=False, capture_output=True, timeout=30, env=safe_git_environment(),
        )
        # A shallow automation checkout cannot prove ancestry. Exit code 1 is a
        # real non-descendant only when the old object is present locally.
        old_present = subprocess.run(
            ["git", "-C", str(source), "cat-file", "-e", f"{current_revision}^{{commit}}"],
            check=False, capture_output=True, timeout=30, env=safe_git_environment(),
        ).returncode == 0
        if old_present and ancestor.returncode != 0:
            fail("candidate is not a descendant of the existing pin")

    document = {
        "schema_version": "steward.buzz-source-lock.v1",
        "repository": REPOSITORY,
        "selection": {
            "lane": "desktop-source-snapshot",
            "release": arguments.release_tag,
            "component_identity": "source-commit",
        },
        "revision": revision,
        "git_tree": tree,
        "source_archive_sha256": archive_hash,
        "components": component_entries,
        "inputs": [{"path": name, "sha256": input_hashes[name]} for name in INPUTS],
        "steward_inputs": [
            {"path": name, "sha256": digest(read_source_file(root, name))}
            for name in STEWARD_INPUTS
        ],
        "toolchain": {"rust": rust},
        "license": {
            "spdx": "Apache-2.0",
            "source_sha256": input_hashes["LICENSE"],
        },
        "qualification_required": True,
    }
    encoded = canonical_json(document)
    changed = lock_path.read_bytes() != encoded
    if changed and not arguments.check:
        write_atomic(lock_path, encoded)
    print(json.dumps({
        "changed": ["integrations/buzz/source-lock.json"] if changed else [],
        "release": arguments.release_tag,
        "revision": revision,
        "git_tree": tree,
    }, separators=(",", ":"), sort_keys=True))
    return 1 if arguments.check and changed else 0


if __name__ == "__main__":
    sys.exit(main())
