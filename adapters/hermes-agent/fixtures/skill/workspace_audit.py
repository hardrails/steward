#!/usr/bin/env python3
"""Create a bounded, canonical inventory of /opt/data/workspace."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
from dataclasses import dataclass, field
from pathlib import Path

WORKSPACE = Path("/opt/data/workspace")
SCHEMA = "steward.workspace-audit.result.v1"
DIGEST_DOMAIN = b"steward.workspace-audit.manifest.v1\x00"
MAX_FILES = 128
MAX_DIRECTORIES = 128
MAX_DEPTH = 16
MAX_FILE_BYTES = 256 << 10
MAX_TOTAL_BYTES = 1 << 20
MAX_PATH_BYTES = 512
READ_CHUNK_BYTES = 64 << 10


class AuditError(Exception):
    """A stable, content-free workspace rejection."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass
class AuditState:
    entries: list[dict[str, object]] = field(default_factory=list)
    directories: int = 1
    total_bytes: int = 0


def canonical_json(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")


def checked_name(name: str, prefix: str) -> tuple[str, bytes]:
    try:
        encoded_name = name.encode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise AuditError("invalid_utf8_name") from exc
    if not encoded_name or b"/" in encoded_name or b"\x00" in encoded_name:
        raise AuditError("invalid_name")
    relative = f"{prefix}/{name}" if prefix else name
    try:
        encoded_relative = relative.encode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise AuditError("invalid_utf8_name") from exc
    if len(encoded_relative) > MAX_PATH_BYTES:
        raise AuditError("path_limit_exceeded")
    return relative, encoded_relative


def same_identity(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        left.st_dev,
        left.st_ino,
        stat.S_IFMT(left.st_mode),
        left.st_size,
        left.st_mtime_ns,
        left.st_ctime_ns,
    ) == (
        right.st_dev,
        right.st_ino,
        stat.S_IFMT(right.st_mode),
        right.st_size,
        right.st_mtime_ns,
        right.st_ctime_ns,
    )


def read_file(parent_fd: int, name: str, relative: str, before: os.stat_result, state: AuditState) -> None:
    if state.total_bytes + before.st_size > MAX_TOTAL_BYTES or before.st_size > MAX_FILE_BYTES:
        raise AuditError("byte_limit_exceeded")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(name, flags, dir_fd=parent_fd)
    except OSError as exc:
        raise AuditError("unsafe_file_open") from exc
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1 or not same_identity(before, opened):
            raise AuditError("unsafe_file_identity")
        digest = hashlib.sha256()
        observed = 0
        while True:
            chunk = os.read(fd, min(READ_CHUNK_BYTES, MAX_FILE_BYTES + 1 - observed))
            if not chunk:
                break
            observed += len(chunk)
            if observed > before.st_size or observed > MAX_FILE_BYTES:
                raise AuditError("concurrent_file_growth")
            digest.update(chunk)
        after = os.fstat(fd)
        try:
            named_after = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except OSError as exc:
            raise AuditError("concurrent_path_change") from exc
        if observed != before.st_size or not same_identity(opened, after) or not same_identity(after, named_after):
            raise AuditError("concurrent_file_change")
    finally:
        os.close(fd)
    state.total_bytes += observed
    state.entries.append({"path": relative, "sha256": digest.hexdigest(), "size": observed})


def walk_directory(directory_fd: int, prefix: str, depth: int, state: AuditState) -> None:
    if depth > MAX_DEPTH:
        raise AuditError("depth_limit_exceeded")
    before_directory = os.fstat(directory_fd)
    names: list[tuple[bytes, str]] = []
    try:
        with os.scandir(directory_fd) as iterator:
            for item in iterator:
                relative, encoded_relative = checked_name(item.name, prefix)
                names.append((encoded_relative, relative))
                if len(names) + len(state.entries) + state.directories > MAX_FILES + MAX_DIRECTORIES:
                    raise AuditError("entry_limit_exceeded")
    except AuditError:
        raise
    except OSError as exc:
        raise AuditError("directory_scan_failed") from exc

    for _encoded_relative, relative in sorted(names):
        name = relative.rsplit("/", 1)[-1]
        try:
            before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except OSError as exc:
            raise AuditError("concurrent_path_change") from exc
        if stat.S_ISLNK(before.st_mode):
            raise AuditError("symlink_rejected")
        if stat.S_ISDIR(before.st_mode):
            state.directories += 1
            if state.directories > MAX_DIRECTORIES:
                raise AuditError("directory_limit_exceeded")
            flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
            try:
                child_fd = os.open(name, flags, dir_fd=directory_fd)
            except OSError as exc:
                raise AuditError("unsafe_directory_open") from exc
            try:
                opened = os.fstat(child_fd)
                if not stat.S_ISDIR(opened.st_mode) or not same_identity(before, opened):
                    raise AuditError("unsafe_directory_identity")
                walk_directory(child_fd, relative, depth + 1, state)
                after = os.fstat(child_fd)
                named_after = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                if not same_identity(opened, after) or not same_identity(after, named_after):
                    raise AuditError("concurrent_directory_change")
            finally:
                os.close(child_fd)
        elif stat.S_ISREG(before.st_mode):
            if len(state.entries) >= MAX_FILES:
                raise AuditError("file_limit_exceeded")
            read_file(directory_fd, name, relative, before, state)
        else:
            raise AuditError("special_file_rejected")

    after_directory = os.fstat(directory_fd)
    if not same_identity(before_directory, after_directory):
        raise AuditError("concurrent_directory_change")


def audit_directory(workspace: Path) -> dict[str, object]:
    try:
        path_before = os.stat(workspace, follow_symlinks=False)
    except OSError as exc:
        raise AuditError("workspace_unavailable") from exc
    if not stat.S_ISDIR(path_before.st_mode):
        raise AuditError("workspace_not_directory")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
    try:
        root_fd = os.open(workspace, flags)
    except OSError as exc:
        raise AuditError("unsafe_workspace_open") from exc
    try:
        opened = os.fstat(root_fd)
        if not same_identity(path_before, opened):
            raise AuditError("unsafe_workspace_identity")
        state = AuditState()
        walk_directory(root_fd, "", 0, state)
        path_after = os.stat(workspace, follow_symlinks=False)
        if not same_identity(opened, path_after):
            raise AuditError("concurrent_workspace_change")
    finally:
        os.close(root_fd)

    entries = sorted(state.entries, key=lambda item: str(item["path"]).encode("utf-8"))
    body: dict[str, object] = {
        "entries": entries,
        "file_count": len(entries),
        "root": "workspace",
        "schema_version": SCHEMA,
        "total_bytes": state.total_bytes,
    }
    body["manifest_digest"] = "sha256:" + hashlib.sha256(DIGEST_DOMAIN + canonical_json(body)).hexdigest()
    return body


def main() -> int:
    if len(sys.argv) != 1:
        print("workspace-audit: arguments are not accepted", file=sys.stderr)
        return 2
    try:
        result = audit_directory(WORKSPACE)
    except AuditError as exc:
        print(f"workspace-audit: {exc.code}", file=sys.stderr)
        return 1
    sys.stdout.buffer.write(canonical_json(result) + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
