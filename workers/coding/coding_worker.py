#!/usr/bin/env python3
"""Bounded HTTP supervisor for official Codex and Claude Code CLIs."""

from __future__ import annotations

import base64
import hashlib
import hmac
import http.server
import json
import os
import pathlib
import re
import signal
import stat
import subprocess
import sys
import threading
import time

MAX_REQUEST = 64 << 10
MAX_STREAM = 448 << 10
MAX_RESPONSE = 1 << 20
MAX_TASK = 16 << 10
MAX_TIMEOUT = 900
WORKSPACE = pathlib.Path("/workspace")


class WorkerError(Exception):
    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


def read_secret(path_text: str, label: str) -> bytes:
    if not path_text:
        raise RuntimeError(f"{label} file is required")
    path = pathlib.Path(path_text)
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) & 0o077
            or before.st_nlink != 1
            or before.st_size < 16
            or before.st_size > 4096
        ):
            raise RuntimeError(f"{label} file is unsafe")
        value = os.read(descriptor, 4097)
        after = os.fstat(descriptor)
        named = os.stat(path, follow_symlinks=False)
        identity = lambda item: (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
        if len(value) != before.st_size or identity(before) != identity(after) or identity(after) != identity(named):
            raise RuntimeError(f"{label} file changed while being read")
    finally:
        os.close(descriptor)
    value = value.rstrip(b"\n")
    if len(value) < 16 or len(value) > 4096 or any(byte < 0x21 or byte > 0x7E for byte in value):
        raise RuntimeError(f"{label} value is invalid")
    return value


def command_for(engine: str, task: str, mode: str) -> list[str]:
    if engine == "codex":
        sandbox = "read-only" if mode == "read" else "workspace-write"
        return [
            "/opt/worker/node_modules/.bin/codex", "exec", "--ephemeral", "--json",
            "--ignore-user-config", "--ignore-rules", "--sandbox", sandbox,
            "--cd", str(WORKSPACE), task,
        ]
    permission = "plan" if mode == "read" else "acceptEdits"
    return [
        "/usr/local/bin/claude", "-p", task, "--output-format", "json",
        "--permission-mode", permission, "--safe-mode", "--no-session-persistence",
        "--disable-slash-commands", "--no-chrome",
    ]


def clean_environment(engine: str) -> dict[str, str]:
    allowed = {
        "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy",
        "SSL_CERT_FILE", "SSL_CERT_DIR", "OPENAI_API_KEY", "ANTHROPIC_API_KEY",
        "CLAUDE_CODE_OAUTH_TOKEN", "CODEX_HOME", "CLAUDE_CONFIG_DIR",
    }
    environment = {key: value for key, value in os.environ.items() if key in allowed}
    environment.update({
        "HOME": "/home/worker",
        "PATH": "/opt/worker/node_modules/.bin:/usr/local/bin:/usr/bin:/bin",
        "TMPDIR": "/tmp",
        "CI": "true",
        "NO_COLOR": "1",
    })
    if engine == "codex":
        environment.setdefault("CODEX_HOME", "/home/worker/.codex")
    else:
        environment.setdefault("CLAUDE_CONFIG_DIR", "/home/worker/.claude")
    return environment


def git_status() -> tuple[str, ...]:
    try:
        result = subprocess.run(
            ["git", "-c", "core.fsmonitor=false", "-C", str(WORKSPACE), "status", "--porcelain=v1", "-z", "--untracked-files=all"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=10,
            env={"HOME": "/nonexistent", "PATH": "/usr/local/bin:/usr/bin:/bin"},
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise WorkerError(400, "invalid_workspace", "workspace must be a responsive Git worktree") from error
    if result.returncode != 0 or len(result.stdout) > MAX_RESPONSE:
        raise WorkerError(400, "invalid_workspace", "workspace must be a bounded Git worktree")
    entries = []
    for raw in result.stdout.split(b"\x00"):
        if not raw:
            continue
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as error:
            raise WorkerError(400, "invalid_workspace", "workspace status contains a non-UTF-8 path") from error
        path = text[3:] if len(text) > 3 else ""
        if not path or path.startswith("/") or "\x00" in path or len(path.encode()) > 4096:
            raise WorkerError(400, "invalid_workspace", "workspace status contains an invalid path")
        entries.append(text)
        if len(entries) > 4096:
            raise WorkerError(400, "invalid_workspace", "workspace has too many changed paths")
    return tuple(entries)


def drain(stream: object, output: bytearray, exceeded: threading.Event) -> None:
    while True:
        chunk = stream.read(65536)
        if not chunk:
            return
        remaining = MAX_STREAM - len(output)
        if remaining > 0:
            output.extend(chunk[:remaining])
        if len(chunk) > remaining:
            exceeded.set()
            return


def stop_process(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        return
    try:
        process.wait(timeout=5)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass
    process.wait(timeout=5)


def secret_markers(worker_token: bytes, environment: dict[str, str]) -> list[bytes]:
    raw_values = [worker_token]
    for name in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN"):
        value = environment.get(name, "").encode()
        if len(value) >= 8:
            raw_values.append(value)
    for root in (pathlib.Path(environment.get("CODEX_HOME", "")), pathlib.Path(environment.get("CLAUDE_CONFIG_DIR", ""))):
        if not str(root) or not root.is_dir():
            continue
        files = 0
        for path in sorted(root.rglob("*")):
            if not path.is_file() or path.is_symlink():
                continue
            files += 1
            if files > 64:
                raise WorkerError(500, "credential_inventory_too_large", "credential store exceeds the scan file limit")
            info = path.stat()
            if info.st_size > 64 << 10:
                continue
            value = path.read_bytes()
            if len(value) >= 8:
                raw_values.append(value)
            try:
                decoded = json.loads(value)
            except (UnicodeDecodeError, json.JSONDecodeError):
                continue
            stack = [decoded]
            while stack:
                current = stack.pop()
                if isinstance(current, dict):
                    stack.extend(current.values())
                elif isinstance(current, list):
                    stack.extend(current)
                elif isinstance(current, str) and len(current.encode()) >= 8:
                    raw_values.append(current.encode())
    markers: set[bytes] = set()
    for value in raw_values:
        if len(value) < 8:
            continue
        markers.add(value)
        markers.add(base64.b64encode(value))
        markers.add(base64.urlsafe_b64encode(value).rstrip(b"="))
        markers.add(value.hex().encode())
        markers.add(hashlib.sha256(value).hexdigest().encode())
    return sorted(markers, key=len, reverse=True)


def run_task(engine: str, worker_token: bytes, task: str, mode: str, timeout_seconds: int) -> dict[str, object]:
    before = git_status()
    if before and os.environ.get("STEWARD_ALLOW_DIRTY_WORKSPACE", "NO") != "YES":
        raise WorkerError(409, "workspace_not_clean", "coding worker requires a clean dedicated worktree")
    environment = clean_environment(engine)
    command = command_for(engine, task, mode)
    started = time.monotonic()
    try:
        process = subprocess.Popen(
            command,
            cwd=WORKSPACE,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
    except OSError as error:
        raise WorkerError(503, "engine_unavailable", f"{engine} CLI could not start") from error
    stdout = bytearray()
    stderr = bytearray()
    exceeded = threading.Event()
    readers = [
        threading.Thread(target=drain, args=(process.stdout, stdout, exceeded), daemon=True),
        threading.Thread(target=drain, args=(process.stderr, stderr, exceeded), daemon=True),
    ]
    for reader in readers:
        reader.start()
    deadline = started + timeout_seconds
    timed_out = False
    while process.poll() is None:
        if exceeded.is_set() or time.monotonic() >= deadline:
            timed_out = time.monotonic() >= deadline
            stop_process(process)
            break
        time.sleep(0.05)
    for reader in readers:
        reader.join(timeout=2)
    if any(reader.is_alive() for reader in readers):
        stop_process(process)
        raise WorkerError(502, "engine_stream_stalled", "coding engine output did not close")
    if exceeded.is_set():
        raise WorkerError(502, "engine_output_too_large", "coding engine output exceeded its 448 KiB stream limit")
    if timed_out:
        raise WorkerError(504, "engine_timeout", "coding engine exceeded the requested timeout")
    combined = bytes(stdout) + b"\x00" + bytes(stderr)
    if any(marker and marker in combined for marker in secret_markers(worker_token, environment)):
        raise WorkerError(502, "credential_output_blocked", "coding engine output matched protected credential material")
    after = git_status()
    if mode == "read" and after != before:
        raise WorkerError(409, "read_mode_modified_workspace", "read-only coding task changed the workspace")
    changed_paths = sorted({entry[3:] for entry in after if len(entry) > 3})
    return {
        "schema_version": "steward.coding-result.v1",
        "engine": engine,
        "mode": mode,
        "outcome": "completed" if process.returncode == 0 else "failed",
        "exit_code": process.returncode,
        "duration_ms": int((time.monotonic() - started) * 1000),
        "changed_paths": changed_paths,
        "stdout": bytes(stdout).decode("utf-8", "replace"),
        "stderr": bytes(stderr).decode("utf-8", "replace"),
    }


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "steward-coding-worker/1"

    def do_POST(self) -> None:  # noqa: N802
        try:
            self.authorize()
            if self.path != "/v1/run":
                raise WorkerError(404, "route_not_found", "route is not available")
            payload = self.read_payload()
            if set(payload) != {"schema_version", "task", "mode", "timeout_seconds"} or payload.get("schema_version") != "steward.coding-task.v1":
                raise WorkerError(400, "invalid_request", "coding request has an invalid contract")
            task, mode, timeout_seconds = payload.get("task"), payload.get("mode"), payload.get("timeout_seconds")
            if (
                not isinstance(task, str)
                or not task.strip()
                or task != task.strip()
                or len(task.encode()) > MAX_TASK
                or mode not in {"read", "write"}
                or type(timeout_seconds) is not int
                or not 30 <= timeout_seconds <= MAX_TIMEOUT
            ):
                raise WorkerError(400, "invalid_request", "task, mode, or timeout is outside its bound")
            result = run_task(self.server.engine, self.server.worker_token, task, mode, timeout_seconds)
            self.write_json(200, result)
        except WorkerError as error:
            self.write_json(error.status, {"error": error.code, "message": error.message})
        except Exception:
            self.write_json(500, {"error": "internal_error", "message": "coding worker failed safely"})

    def authorize(self) -> None:
        values = self.headers.get_all("Authorization", [])
        if len(values) != 1 or not values[0].startswith("Bearer "):
            raise WorkerError(401, "unauthorized", "one bearer credential is required")
        supplied = values[0][7:].encode("ascii", "ignore")
        if not hmac.compare_digest(supplied, self.server.worker_token):
            raise WorkerError(401, "unauthorized", "worker credential is invalid")

    def read_payload(self) -> dict[str, object]:
        if self.headers.get("Transfer-Encoding") is not None:
            raise WorkerError(400, "invalid_request", "transfer encoding is not accepted")
        values = self.headers.get_all("Content-Length", [])
        if len(values) != 1 or re.fullmatch(r"[0-9]{1,5}", values[0].strip()) is None:
            raise WorkerError(411, "content_length_required", "one canonical Content-Length is required")
        length = int(values[0])
        if length <= 0 or length > MAX_REQUEST:
            raise WorkerError(413, "request_too_large", "request must be 1 byte through 64 KiB")
        body = self.rfile.read(length)
        if len(body) != length:
            raise WorkerError(400, "incomplete_request", "request body is incomplete")
        try:
            value = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise WorkerError(400, "invalid_json", "request body is not valid JSON") from error
        if not isinstance(value, dict):
            raise WorkerError(400, "invalid_request", "request body must be a JSON object")
        return value

    def write_json(self, status: int, value: object) -> None:
        body = json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode()
        if len(body) > MAX_RESPONSE:
            status = 502
            body = b'{"error":"response_too_large","message":"coding result exceeded 1 MiB"}'
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format_text: str, *arguments: object) -> None:
        print(f"coding-worker: {self.command} {self.path}", file=sys.stderr)


class Server(http.server.HTTPServer):
    request_queue_size = 4

    def __init__(self, address: tuple[str, int], engine: str, token: bytes) -> None:
        super().__init__(address, Handler)
        self.engine = engine
        self.worker_token = token


def main() -> int:
    if os.geteuid() == 0 or os.getegid() == 0:
        raise RuntimeError("coding worker refuses to run as root")
    info = os.stat(WORKSPACE, follow_symlinks=False)
    if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) & 0o002:
        raise RuntimeError("/workspace must be a real directory that is not world-writable")
    engine = os.environ.get("STEWARD_CODING_ENGINE", "")
    if engine not in {"codex", "claude-code"}:
        raise RuntimeError("STEWARD_CODING_ENGINE must be codex or claude-code")
    token = read_secret(os.environ.get("STEWARD_WORKER_TOKEN_FILE", ""), "worker token")
    port_text = os.environ.get("STEWARD_WORKER_PORT", "8080")
    if re.fullmatch(r"[0-9]{2,5}", port_text) is None or not 1024 <= int(port_text) <= 65535:
        raise RuntimeError("STEWARD_WORKER_PORT is invalid")
    server = Server(("0.0.0.0", int(port_text)), engine, token)
    server.timeout = 1
    print(f"coding-worker: {engine} ready on :{port_text}", file=sys.stderr)
    try:
        while True:
            server.handle_request()
    except KeyboardInterrupt:
        return 0
    finally:
        server.server_close()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RuntimeError as error:
        print(f"coding-worker: {error}", file=sys.stderr)
        raise SystemExit(1)
