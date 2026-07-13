#!/usr/bin/env python3
"""Bounded host-side assertion that agent material excludes connector secrets."""

from __future__ import annotations

import os
import pathlib
import re
import stat
import sys

MAX_JSON_BYTES = 1 << 20
MAX_STREAM_BYTES = 2 << 30
READ_BYTES = 1 << 20


def read_credential(path_text: str) -> bytes:
    path = pathlib.Path(path_text)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) & 0o077 or not 0 < info.st_size <= 16384:
        raise SystemExit("fixture-secret-scan: credential file is unsafe")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        data = bytearray()
        while len(data) <= 16384:
            chunk = os.read(descriptor, min(65536, 16385 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        final = os.fstat(descriptor)
        named = path.lstat()
    finally:
        os.close(descriptor)
    identity = lambda item: (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
    if (
        len(data) != info.st_size
        or identity(info) != identity(opened)
        or identity(opened) != identity(final)
        or identity(final) != identity(named)
    ):
        raise SystemExit("fixture-secret-scan: credential changed while being read")
    value = bytes(data).strip()
    if not value or b"\n" in value or b"\r" in value:
        raise SystemExit("fixture-secret-scan: credential value is invalid")
    return value


def find_patterns(data: bytes, patterns: tuple[bytes, ...]) -> bool:
    return any(pattern in data for pattern in patterns)


def scan_stream(patterns: tuple[bytes, ...]) -> None:
    total = 0
    overlap = max(map(len, patterns)) - 1
    carry = b""
    while True:
        chunk = sys.stdin.buffer.read(READ_BYTES)
        if not chunk:
            break
        total += len(chunk)
        if total > MAX_STREAM_BYTES:
            raise SystemExit("fixture-secret-scan: agent material exceeds scan limit")
        combined = carry + chunk
        if find_patterns(combined, patterns):
            raise SystemExit("fixture-secret-scan: connector secret or origin reached the agent")
        carry = combined[-overlap:] if overlap else b""
    if total == 0:
        raise SystemExit("fixture-secret-scan: agent material stream is empty")


def scan_json(patterns: tuple[bytes, ...]) -> None:
    data = sys.stdin.buffer.read(MAX_JSON_BYTES + 1)
    if not data or len(data) > MAX_JSON_BYTES:
        raise SystemExit("fixture-secret-scan: container metadata is empty or oversized")
    if find_patterns(data, patterns):
        raise SystemExit("fixture-secret-scan: connector secret or origin reached the agent environment")


def material_patterns(credential_path: str, origin: str) -> tuple[bytes, ...]:
    credential = read_credential(credential_path)
    netloc = origin.removeprefix("http://")
    _host, separator, port = netloc.rpartition(":")
    if not separator or not port:
        raise SystemExit("fixture-secret-scan: origin authority is invalid")
    return (
        credential,
        origin.encode("ascii"),
        netloc.encode("ascii"),
        f":{port}".encode("ascii"),
        f": {port}".encode("ascii"),
        f"={port}".encode("ascii"),
        f'"{port}"'.encode("ascii"),
        os.fsencode(os.path.abspath(credential_path)),
    )


def main() -> int:
    if len(sys.argv) != 4 or sys.argv[1] not in {"json", "stream"}:
        print("usage: fixture_secret_scan.py MODE CREDENTIAL_FILE ORIGIN", file=sys.stderr)
        return 2
    origin = sys.argv[3]
    if re.fullmatch(r"http://127\.0\.0\.1:[0-9]{1,5}", origin) is None:
        raise SystemExit("fixture-secret-scan: origin is invalid")
    patterns = material_patterns(sys.argv[2], origin)
    if sys.argv[1] == "json":
        scan_json(patterns)
    else:
        scan_stream(patterns)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
