#!/usr/bin/env python3
"""Fixed-path, non-root feasibility entrypoint for pinned Hermes Agent."""

from __future__ import annotations

import base64
import hashlib
import http.client
import http.server
import json
import os
import pathlib
import re
import signal
import socket
import stat
import subprocess
import sys
import threading
import time
from typing import Any

REVISION = "3ef6bbd201263d354fd83ec55b3c306ded2eb72a"
STATE = pathlib.Path("/opt/data")
FIXTURE = pathlib.Path("/opt/steward/skills/steward.workspace-audit")
CONNECTOR_FIXTURE = pathlib.Path("/opt/steward/skills/steward.connector-work")
MODEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
RUN_PATH_RE = re.compile(r"^/v1/runs/run_[a-f0-9]{32}$")
INTERNAL_API_HOST = "127.0.0.1"
INTERNAL_API_PORT = 8642
INTERNAL_API_TOKEN = "steward-feasibility"
MAX_REQUEST_BODY = 64 << 10
MAX_RESPONSE_BODY = 1 << 20
SERVICE_TIMEOUT_SECONDS = 30
STARTUP_TIMEOUT_SECONDS = 120
SKILL_PUBLIC_KEY_SHA256 = "183e8cd011fa5e5f044700be4a61f3bc22e2eb61ad34469e62433d42f5af2452"
SKILL_LIMITS = {
    "max_depth": 16,
    "max_directories": 128,
    "max_file_bytes": 262144,
    "max_files": 128,
    "max_path_bytes": 512,
    "max_total_bytes": 1048576,
}
SKILL_FILES = {
    "SKILL.md": ("read", 0o444),
    "workspace-fixture-contract.json": ("read", 0o444),
    "workspace_audit.py": ("execute", 0o555),
}
CONNECTOR_SKILL_PUBLIC_KEY_SHA256 = "6eceb945f87b1979b2d5fde2235ddb493c38ae2fa2694c2c6d7dbd0a61a5e564"
CONNECTOR_SKILL_LIMITS = {
    "max_request_bytes": 4096,
    "max_response_bytes": 4096,
    "timeout_seconds": 10,
}
CONNECTOR_SKILL_FILES = {
    "SKILL.md": ("read", 0o444),
    "connector-fixture-contract.json": ("read", 0o444),
    "connector_work.py": ("execute", 0o555),
}
CONNECTOR_SKILL_AUTHORITY = {
    "id": "local-work",
    "logical_base_url": "http://steward-relay:8081",
    "operation_id": "perform",
    "operation_path": "/v1/connectors/local-work/operations/perform",
}
NEGOTIATION = {
    "schema_version": "steward.adapter-negotiation.v1",
    "adapter": "hermes-agent",
    "adapter_contract": "steward.hermes-agent.v1",
    "upstream_revision": REVISION,
    "task_protocol": "hermes.runs.v1",
    "native_protocols": ["http"],
    "capabilities": [
        {"id": "skill", "fixture_id": "steward.workspace-audit"},
        {"id": "skill", "fixture_id": "steward.connector-work"},
        {"id": "task", "fixture_id": "fixed-response"},
    ],
}


def fail(message: str) -> "NoReturn":
    print(f"hermes-adapter: {message}", file=sys.stderr)
    raise SystemExit(1)


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


def read_regular_nofollow(path: pathlib.Path, maximum: int, mode: int) -> bytes:
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        before = os.fstat(fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != 0
            or before.st_gid != 0
            or stat.S_IMODE(before.st_mode) != mode
            or before.st_size < 0
            or before.st_size > maximum
        ):
            fail("signed fixture contains an unsafe file")
        data = bytearray()
        while len(data) <= maximum:
            chunk = os.read(fd, min(65536, maximum + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        after = os.fstat(fd)
        named_after = os.stat(path, follow_symlinks=False)
        if len(data) != before.st_size or len(data) > maximum or not same_identity(before, after) or not same_identity(after, named_after):
            fail("signed fixture changed while being read")
        return bytes(data)
    finally:
        os.close(fd)


def read_regular_at(
    directory_fd: int,
    name: str,
    maximum: int,
    allowed_link_counts: frozenset[int] = frozenset({1}),
) -> tuple[bytes, os.stat_result]:
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(name, flags, dir_fd=directory_fd)
    try:
        before = os.fstat(fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink not in allowed_link_counts
            or before.st_size < 0
            or before.st_size > maximum
        ):
            fail("persisted skill contains an unsafe file")
        data = bytearray()
        while len(data) <= maximum:
            chunk = os.read(fd, min(65536, maximum + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        after = os.fstat(fd)
        named_after = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if len(data) != before.st_size or len(data) > maximum or not same_identity(before, after) or not same_identity(after, named_after):
            fail("persisted skill changed while being read")
        return bytes(data), after
    finally:
        os.close(fd)


def open_state_directory(*components: str) -> int:
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
    current = os.open(STATE, flags)
    try:
        root_stat = os.fstat(current)
        if root_stat.st_uid != 65532 or root_stat.st_gid != 65532:
            fail("state root ownership is invalid")
        for component in components:
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", component):
                fail("internal state directory name is invalid")
            try:
                os.mkdir(component, 0o700, dir_fd=current)
            except FileExistsError:
                pass
            child = os.open(component, flags, dir_fd=current)
            child_stat = os.fstat(child)
            if child_stat.st_uid != 65532 or child_stat.st_gid != 65532 or stat.S_IMODE(child_stat.st_mode) != 0o700:
                os.close(child)
                fail("state directory ownership or mode is invalid")
            os.close(current)
            current = child
        result = current
        current = -1
        return result
    finally:
        if current >= 0:
            os.close(current)


def publication_temp_name(name: str) -> str:
    return f".{name}.steward-publish"


def exact_publication_file(data: bytes, info: os.stat_result, expected: bytes, mode: int) -> bool:
    return (
        data == expected
        and info.st_uid == os.geteuid()
        and info.st_gid == os.getegid()
        and stat.S_IMODE(info.st_mode) == mode
    )


def remove_stale_publication_temp(directory_fd: int, temp: str, mode: int) -> None:
    try:
        info = os.stat(temp, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or info.st_uid != os.geteuid()
        or info.st_gid != os.getegid()
        or stat.S_IMODE(info.st_mode) != mode
    ):
        fail("persisted skill contains an unsafe publication file")
    # A lone reserved temporary file cannot have published its target. Its
    # contents may be partial because the prior process could have stopped at
    # any write. Removing only this exact owner-only regular file is safe; the
    # target name is never removed or replaced.
    os.unlink(temp, dir_fd=directory_fd)
    os.fsync(directory_fd)


def publish_exact(directory_fd: int, name: str, data: bytes, mode: int) -> None:
    temp = publication_temp_name(name)
    try:
        current, current_stat = read_regular_at(
            directory_fd,
            name,
            len(data),
            frozenset({1, 2}),
        )
    except FileNotFoundError:
        current = None
        current_stat = None
    if current is not None:
        if not exact_publication_file(current, current_stat, data, mode):
            fail(f"persisted skill drifted: {name}")
        try:
            pending, pending_stat = read_regular_at(
                directory_fd,
                temp,
                len(data),
                frozenset({1, 2}),
            )
        except FileNotFoundError:
            pending = None
            pending_stat = None
        if pending is None:
            if current_stat.st_nlink != 1:
                fail(f"persisted skill has an unexplained hard link: {name}")
            return
        if (
            not exact_publication_file(pending, pending_stat, data, mode)
            or current_stat.st_nlink != 2
            or pending_stat.st_nlink != 2
            or current_stat.st_dev != pending_stat.st_dev
            or current_stat.st_ino != pending_stat.st_ino
        ):
            fail(f"persisted skill publication is ambiguous: {name}")
        # The prior process completed the no-overwrite link but stopped before
        # removing its temporary name. Make that completed publication canonical.
        os.unlink(temp, dir_fd=directory_fd)
        os.fsync(directory_fd)
        final, final_stat = read_regular_at(directory_fd, name, len(data))
        if not exact_publication_file(final, final_stat, data, mode):
            fail(f"persisted skill changed during publication recovery: {name}")
        return

    remove_stale_publication_temp(directory_fd, temp, mode)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(temp, flags, mode, dir_fd=directory_fd)
    try:
        written = 0
        while written < len(data):
            written += os.write(fd, data[written:])
        os.fchmod(fd, mode)
        os.fsync(fd)
    finally:
        os.close(fd)
    try:
        os.link(temp, name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd, follow_symlinks=False)
    except FileExistsError:
        fail(f"persisted skill changed during publication: {name}")
    # Persist the target link before removing the only recovery name. A process
    # stop before the unlink leaves two exact links; a stop after it leaves the
    # canonical target. Both states are handled above on the next startup.
    os.fsync(directory_fd)
    os.unlink(temp, dir_fd=directory_fd)
    os.fsync(directory_fd)
    final, final_stat = read_regular_at(directory_fd, name, len(data))
    if not exact_publication_file(final, final_stat, data, mode):
        fail(f"persisted skill changed after publication: {name}")


def require_exact_directory_entries(directory_fd: int, expected: set[str]) -> None:
    before = os.fstat(directory_fd)
    try:
        with os.scandir(directory_fd) as iterator:
            observed = {entry.name for entry in iterator}
    except OSError as exc:
        fail(f"persisted skill directory cannot be inspected: {type(exc).__name__}")
    after = os.fstat(directory_fd)
    if observed != expected or not same_identity(before, after):
        fail("persisted skill directory contains unbound or unstable entries")


def verify_skill() -> dict[str, bytes]:
    fixture_fd = os.open(
        FIXTURE,
        os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        fixture_stat = os.fstat(fixture_fd)
        if fixture_stat.st_uid != 0 or fixture_stat.st_gid != 0 or stat.S_IMODE(fixture_stat.st_mode) & 0o022:
            fail("signed fixture directory ownership or mode is invalid")
        require_exact_directory_entries(fixture_fd, set(SKILL_FILES) | {"manifest.json", "manifest.sig", "public.pem"})
    finally:
        os.close(fixture_fd)
    manifest = read_regular_nofollow(FIXTURE / "manifest.json", 16384, 0o444)
    signature_text = read_regular_nofollow(FIXTURE / "manifest.sig", 256, 0o444)
    public_key = read_regular_nofollow(FIXTURE / "public.pem", 1024, 0o444)
    if hashlib.sha256(public_key).hexdigest() != SKILL_PUBLIC_KEY_SHA256:
        fail("signed fixture public key does not match the adapter trust root")
    signature = base64.b64decode(signature_text.strip(), validate=True)
    if len(signature) != 64:
        fail("signed fixture signature length is invalid")
    try:
        from cryptography.hazmat.primitives import serialization

        key = serialization.load_pem_public_key(public_key)
        key.verify(signature, manifest)
    except Exception as exc:
        fail(f"signed fixture skill verification failed: {type(exc).__name__}")
    try:
        descriptor = json.loads(manifest)
    except (TypeError, ValueError):
        fail("signed fixture manifest is not valid JSON")
    canonical = json.dumps(descriptor, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8") + b"\n"
    if manifest != canonical or not isinstance(descriptor, dict) or set(descriptor) != {
        "entrypoint", "files", "limits", "name", "network", "schema_version", "version", "workspace_root"
    }:
        fail("signed fixture manifest is not canonical or has unknown fields")
    if (
        descriptor["schema_version"] != "steward.fixture-skill-manifest.v1"
        or descriptor["name"] != "steward.workspace-audit"
        or descriptor["version"] != "1"
        or descriptor["network"] is not False
        or descriptor["entrypoint"] != "workspace_audit.py"
        or descriptor["workspace_root"] != "/opt/data/workspace"
        or descriptor["limits"] != SKILL_LIMITS
    ):
        fail("signed fixture manifest semantics are invalid")
    files = descriptor["files"]
    if not isinstance(files, list) or len(files) != len(SKILL_FILES):
        fail("signed fixture manifest file inventory is invalid")
    verified: dict[str, bytes] = {}
    prior = ""
    for item in files:
        if not isinstance(item, dict) or set(item) != {"mode", "path", "sha256"}:
            fail("signed fixture file descriptor is invalid")
        name = item.get("path")
        if not isinstance(name, str) or name <= prior or name not in SKILL_FILES:
            fail("signed fixture file order or name is invalid")
        expected_mode = SKILL_FILES[name][0]
        digest = item.get("sha256")
        if item.get("mode") != expected_mode or not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest):
            fail("signed fixture file authority is invalid")
        data = read_regular_nofollow(FIXTURE / name, 1 << 20, SKILL_FILES[name][1])
        if hashlib.sha256(data).hexdigest() != digest:
            fail(f"signed fixture file digest mismatch: {name}")
        verified[name] = data
        prior = name
    if set(verified) != set(SKILL_FILES):
        fail("signed fixture file inventory is incomplete")
    verify_connector_skill()
    return verified


def verify_connector_skill() -> dict[str, bytes]:
    fixture_fd = os.open(
        CONNECTOR_FIXTURE,
        os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        fixture_stat = os.fstat(fixture_fd)
        if fixture_stat.st_uid != 0 or fixture_stat.st_gid != 0 or stat.S_IMODE(fixture_stat.st_mode) & 0o022:
            fail("signed connector fixture directory ownership or mode is invalid")
        require_exact_directory_entries(
            fixture_fd,
            set(CONNECTOR_SKILL_FILES) | {"manifest.json", "manifest.sig", "public.pem"},
        )
    finally:
        os.close(fixture_fd)
    manifest = read_regular_nofollow(CONNECTOR_FIXTURE / "manifest.json", 16384, 0o444)
    signature_text = read_regular_nofollow(CONNECTOR_FIXTURE / "manifest.sig", 256, 0o444)
    public_key = read_regular_nofollow(CONNECTOR_FIXTURE / "public.pem", 1024, 0o444)
    if hashlib.sha256(public_key).hexdigest() != CONNECTOR_SKILL_PUBLIC_KEY_SHA256:
        fail("signed connector fixture public key does not match the adapter trust root")
    signature = base64.b64decode(signature_text.strip(), validate=True)
    if len(signature) != 64:
        fail("signed connector fixture signature length is invalid")
    try:
        from cryptography.hazmat.primitives import serialization

        key = serialization.load_pem_public_key(public_key)
        key.verify(signature, manifest)
    except Exception as exc:
        fail(f"signed connector fixture verification failed: {type(exc).__name__}")
    try:
        descriptor = json.loads(manifest)
    except (TypeError, ValueError):
        fail("signed connector fixture manifest is not valid JSON")
    canonical = json.dumps(descriptor, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8") + b"\n"
    if manifest != canonical or not isinstance(descriptor, dict) or set(descriptor) != {
        "connector", "entrypoint", "files", "limits", "name", "network", "schema_version", "version"
    }:
        fail("signed connector fixture manifest is not canonical or has unknown fields")
    if (
        descriptor["schema_version"] != "steward.fixture-skill-manifest.v1"
        or descriptor["name"] != "steward.connector-work"
        or descriptor["version"] != "1"
        or descriptor["network"] is not True
        or descriptor["entrypoint"] != "connector_work.py"
        or descriptor["connector"] != CONNECTOR_SKILL_AUTHORITY
        or descriptor["limits"] != CONNECTOR_SKILL_LIMITS
    ):
        fail("signed connector fixture manifest semantics are invalid")
    files = descriptor["files"]
    if not isinstance(files, list) or len(files) != len(CONNECTOR_SKILL_FILES):
        fail("signed connector fixture file inventory is invalid")
    verified: dict[str, bytes] = {}
    prior = ""
    for item in files:
        if not isinstance(item, dict) or set(item) != {"mode", "path", "sha256"}:
            fail("signed connector fixture file descriptor is invalid")
        name = item.get("path")
        if not isinstance(name, str) or name <= prior or name not in CONNECTOR_SKILL_FILES:
            fail("signed connector fixture file order or name is invalid")
        expected_mode = CONNECTOR_SKILL_FILES[name][0]
        digest = item.get("sha256")
        if item.get("mode") != expected_mode or not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest):
            fail("signed connector fixture file authority is invalid")
        data = read_regular_nofollow(CONNECTOR_FIXTURE / name, 1 << 20, CONNECTOR_SKILL_FILES[name][1])
        if hashlib.sha256(data).hexdigest() != digest:
            fail(f"signed connector fixture file digest mismatch: {name}")
        verified[name] = data
        prior = name
    if set(verified) != set(CONNECTOR_SKILL_FILES):
        fail("signed connector fixture file inventory is incomplete")
    return verified


def seed_state(model: str, qualification_mcp: bool) -> None:
    if os.getuid() != 65532 or os.getgid() != 65532:
        fail("runtime identity must be exactly 65532:65532")
    for relative in ("home", "sessions", "logs", "memories", "skills", "workspace", "steward"):
        directory_fd = open_state_directory(relative)
        os.close(directory_fd)
    config = f"""model:
  provider: custom
  name: {model}
  base_url: http://steward-relay:8080/v1
  api_key: steward-local
  api_mode: chat_completions
security:
  allow_lazy_installs: false
skills:
  external_dirs:
    - /opt/steward/skills
terminal:
  backend: local
"""
    if qualification_mcp:
        config += """mcp_servers:
  fixture_echo:
    url: http://steward-mcp:8767/mcp
    enabled: true
    connect_timeout: 5
    timeout: 10
    skip_preflight: true
    tools:
      include: [echo]
      resources: false
      prompts: false
"""
    config = config.encode()
    state_fd = open_state_directory()
    try:
        publish_exact(state_fd, "config.yaml", config, 0o600)
    finally:
        os.close(state_fd)


class BoundedHTTPServer(http.server.HTTPServer):
    """Single-worker service with a bounded accepted-connection queue and I/O time."""

    request_queue_size = 8

    def get_request(self) -> tuple[socket.socket, Any]:
        connection, address = super().get_request()
        connection.settimeout(SERVICE_TIMEOUT_SECONDS)
        return connection, address


class ServiceBridgeHandler(http.server.BaseHTTPRequestHandler):
    server_version = "steward-hermes-service/1"

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/steward/v1/negotiation":
            self._send_json(200, json.dumps(NEGOTIATION, separators=(",", ":"), sort_keys=True).encode())
            return
        if self.path == "/health" or RUN_PATH_RE.fullmatch(self.path):
            self._proxy("GET", None)
            return
        self._send_error(404, "route_not_allowed")

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/v1/runs":
            self._send_error(404, "route_not_allowed")
            return
        if self.headers.get("Transfer-Encoding") is not None:
            self._send_error(400, "transfer_encoding_not_allowed")
            return
        if self.headers.get("Expect") is not None:
            self._send_error(417, "expectation_not_supported")
            return
        lengths = self.headers.get_all("Content-Length", [])
        if not lengths:
            self._send_error(411, "content_length_required")
            return
        if len(lengths) != 1 or re.fullmatch(r"[0-9]{1,5}", lengths[0].strip()) is None:
            self._send_error(400, "invalid_content_length")
            return
        length = int(lengths[0])
        if length > MAX_REQUEST_BODY:
            self._send_error(413, "request_body_too_large")
            return
        try:
            body = self.rfile.read(length)
        except (OSError, TimeoutError):
            self._send_error(408, "request_body_timeout")
            return
        if len(body) != length:
            self._send_error(400, "incomplete_request_body")
            return
        self._proxy("POST", body)

    def _proxy(self, method: str, body: bytes | None) -> None:
        headers = {
            "Accept": "application/json",
            "Accept-Encoding": "identity",
            "Authorization": f"Bearer {INTERNAL_API_TOKEN}",
        }
        if body is not None:
            headers["Content-Length"] = str(len(body))
            headers["Content-Type"] = "application/json"
        connection = http.client.HTTPConnection(
            INTERNAL_API_HOST,
            INTERNAL_API_PORT,
            timeout=SERVICE_TIMEOUT_SECONDS,
        )
        deadline = time.monotonic() + SERVICE_TIMEOUT_SECONDS
        try:
            connection.request(method, self.path, body=body, headers=headers)
            if connection.sock is not None:
                connection.sock.settimeout(max(0.001, deadline - time.monotonic()))
            response = connection.getresponse()
            declared = response.headers.get_all("Content-Length", [])
            if len(declared) > 1:
                self._send_error(502, "invalid_upstream_response")
                return
            if declared:
                value = declared[0].strip()
                if re.fullmatch(r"[0-9]{1,7}", value) is None or int(value) > MAX_RESPONSE_BODY:
                    self._send_error(502, "upstream_response_too_large")
                    return
            encodings = response.headers.get_all("Content-Encoding", [])
            if len(encodings) > 1 or (encodings and encodings[0].strip().lower() != "identity"):
                self._send_error(502, "encoded_upstream_response_not_allowed")
                return
            if connection.sock is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError
                connection.sock.settimeout(remaining)
            response_body = response.read(MAX_RESPONSE_BODY + 1)
            if len(response_body) > MAX_RESPONSE_BODY:
                self._send_error(502, "upstream_response_too_large")
                return
            if response.status < 200 or response.status > 599:
                self._send_error(502, "invalid_upstream_response")
                return
            self._send_json(response.status, response_body)
        except TimeoutError:
            self._send_error(504, "upstream_timeout")
        except (ConnectionError, OSError, http.client.HTTPException):
            self._send_error(502, "upstream_unavailable")
        finally:
            connection.close()

    def _send_error(self, status_code: int, code: str) -> None:
        body = json.dumps({"error": code}, separators=(",", ":"), sort_keys=True).encode()
        self._send_json(status_code, body)

    def _send_json(self, status_code: int, body: bytes) -> None:
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *_args: Any) -> None:
        return


def wait_for_internal_api(process: subprocess.Popen[bytes]) -> None:
    deadline = time.monotonic() + STARTUP_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        if process.poll() is not None:
            fail("Hermes gateway exited before its API became ready")
        connection = http.client.HTTPConnection(
            INTERNAL_API_HOST,
            INTERNAL_API_PORT,
            timeout=min(1.0, max(0.001, deadline - time.monotonic())),
        )
        try:
            connection.request(
                "GET",
                "/health",
                headers={"Authorization": f"Bearer {INTERNAL_API_TOKEN}"},
            )
            response = connection.getresponse()
            body = response.read(MAX_RESPONSE_BODY + 1)
            if response.status == 200 and len(body) <= MAX_RESPONSE_BODY:
                return
        except (ConnectionError, OSError, TimeoutError, http.client.HTTPException):
            pass
        finally:
            connection.close()
        time.sleep(0.1)
    fail("Hermes API did not become ready before the startup deadline")


def main() -> int:
    if sys.argv[1:] != ["serve"]:
        fail("command must be exactly: serve")
    model = os.environ.get("OPENAI_MODEL", "steward-fixture-model")
    if not MODEL_RE.fullmatch(model):
        fail("OPENAI_MODEL is invalid")
    if os.environ.get("OPENAI_BASE_URL", "http://steward-relay:8080/v1") != "http://steward-relay:8080/v1":
        fail("OPENAI_BASE_URL must use Steward's fixed inference relay endpoint")
    qualification_mcp = os.environ.get("STEWARD_HERMES_QUALIFICATION_MCP", "disabled")
    if qualification_mcp not in {"disabled", "enabled"}:
        fail("STEWARD_HERMES_QUALIFICATION_MCP must be disabled or enabled")
    verify_skill()
    seed_state(model, qualification_mcp == "enabled")
    environment = os.environ.copy()
    environment.update(
        {
            "API_SERVER_ENABLED": "true",
            "API_SERVER_HOST": INTERNAL_API_HOST,
            "API_SERVER_PORT": "8642",
            "API_SERVER_KEY": INTERNAL_API_TOKEN,
            "HERMES_DISABLE_LAZY_INSTALLS": "1",
        }
    )
    process = subprocess.Popen(
        ["/opt/hermes/.venv/bin/hermes", "gateway", "run"],
        cwd=STATE,
        env=environment,
        stdin=subprocess.DEVNULL,
    )

    def stop(_signum: int, _frame: Any) -> None:
        process.terminate()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    server: BoundedHTTPServer | None = None
    try:
        wait_for_internal_api(process)
        server = BoundedHTTPServer(("0.0.0.0", 8766), ServiceBridgeHandler)
        thread = threading.Thread(target=server.serve_forever, name="service-bridge", daemon=True)
        thread.start()
        return process.wait()
    finally:
        if server is not None:
            server.shutdown()
            server.server_close()
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)


if __name__ == "__main__":
    raise SystemExit(main())
