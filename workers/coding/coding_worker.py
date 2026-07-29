#!/usr/bin/env python3
"""Bounded HTTP supervisor for official Codex and Claude Code CLIs."""

from __future__ import annotations

import base64
import ctypes
import hashlib
import hmac
import http.server
import json
import os
import pathlib
import re
import signal
import socket
import socketserver
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unicodedata
import urllib.parse

MAX_REQUEST = 64 << 10
MAX_STREAM = 448 << 10
MAX_RESPONSE = 1 << 20
MAX_PORTABLE_RESULT = 448 << 10
MAX_HANDOFF_PATCH = 256 << 10
MAX_HANDOFF_STREAM = 16 << 10
MAX_V1_CHANGED_PATHS = 4096
MAX_CHANGED_PATHS = 512
MAX_CHANGED_PATH_BYTES = 48 << 10
MAX_CHANGED_FILE_BYTES = 4 << 20
MAX_CHANGED_TOTAL_BYTES = 8 << 20
MAX_PROTECTED_SCAN_BYTES = 16 << 20
MAX_WORKSPACE_ENTRIES = 100_000
MAX_GIT_METADATA_ENTRIES = 100_000
MAX_CREDENTIAL_ENTRIES = 512
MAX_CREDENTIAL_FILES = 64
MAX_CREDENTIAL_DEPTH = 16
MAX_CREDENTIAL_FILE_BYTES = 64 << 10
MAX_CREDENTIAL_VALUE_BYTES = 4 << 20
MAX_CREDENTIAL_VALUES = 512
MAX_CREDENTIAL_JSON_NODES = 8192
MAX_GIT_DIAGNOSTIC = 32 << 10
MAX_GIT_INVENTORY = 1 << 20
MAX_TASK = 16 << 10
MAX_TIMEOUT = 900
GIT_TIMEOUT = 15
HANDOFF_TIMEOUT = 45
CREDENTIAL_SCAN_TIMEOUT = 5
PREFLIGHT_TIMEOUT = 45
ENGINE_CLEANUP_TIMEOUT = 20
RESPONSE_TIMEOUT = 10
POSTFLIGHT_RESERVE = ENGINE_CLEANUP_TIMEOUT + HANDOFF_TIMEOUT + RESPONSE_TIMEOUT
REQUEST_OVERHEAD_TIMEOUT = PREFLIGHT_TIMEOUT + POSTFLIGHT_RESERVE
WORKSPACE = pathlib.Path("/workspace")
OBJECT_ID_LENGTHS = {"sha1": 40, "sha256": 64}
PR_SET_CHILD_SUBREAPER = 36


class WorkerError(Exception):
    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


def require_request_time(deadline: float) -> None:
    if time.monotonic() >= deadline:
        raise WorkerError(504, "request_timeout", "coding request exceeded its aggregate time limit")


def contains_protected(
    value: bytes,
    protected_markers: tuple[bytes, ...],
    *,
    deadline: float,
) -> bool:
    for marker in protected_markers:
        require_request_time(deadline)
        if marker and marker in value:
            return True
    require_request_time(deadline)
    return False


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
            "--cd", str(WORKSPACE), "--", task,
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


def drain(stream: object, output: bytearray, exceeded: threading.Event, maximum: int) -> None:
    while True:
        chunk = stream.read(65536)
        if not chunk:
            return
        remaining = maximum - len(output)
        if remaining > 0:
            output.extend(chunk[:remaining])
        if len(chunk) > remaining:
            exceeded.set()
            return


def feed_process_input(stream: object, value: bytes) -> None:
    view = memoryview(value)
    offset = 0
    try:
        descriptor = stream.fileno()
        while offset < len(view):
            written = os.write(descriptor, view[offset:])
            if written <= 0:
                return
            offset += written
    except (BrokenPipeError, OSError, ValueError):
        pass
    finally:
        try:
            stream.close()
        except (OSError, ValueError):
            pass


def process_group_exists(group_id: int) -> bool:
    try:
        os.killpg(group_id, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def reap_process_group_children(group_id: int) -> None:
    while True:
        try:
            child, _ = os.waitpid(-group_id, os.WNOHANG)
        except ChildProcessError:
            return
        if child <= 0:
            return


def stop_process(
    process: subprocess.Popen[bytes],
    *,
    deadline: float | None = None,
) -> bool:
    group_id = process.pid
    cleanup_deadline = deadline if deadline is not None else time.monotonic() + 10
    remaining = max(0.0, cleanup_deadline - time.monotonic())
    graceful_budget = min(5.0, remaining / 2)
    try:
        os.killpg(group_id, signal.SIGTERM)
    except ProcessLookupError:
        pass
    except PermissionError:
        return False
    graceful_deadline = min(cleanup_deadline, time.monotonic() + graceful_budget)
    while time.monotonic() < graceful_deadline:
        process.poll()
        if process.returncode is not None:
            reap_process_group_children(group_id)
        if not process_group_exists(group_id):
            return True
        time.sleep(0.02)
    try:
        os.killpg(group_id, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except PermissionError:
        return False
    force_deadline = cleanup_deadline
    while time.monotonic() < force_deadline:
        process.poll()
        if process.returncode is not None:
            reap_process_group_children(group_id)
        if not process_group_exists(group_id):
            return True
        time.sleep(0.02)
    process.poll()
    if process.returncode is not None:
        reap_process_group_children(group_id)
    return not process_group_exists(group_id)


def close_process_streams(process: subprocess.Popen[bytes]) -> None:
    for stream in (process.stdin, process.stdout, process.stderr):
        if stream is not None and not stream.closed:
            stream.close()


def defer_process_stream_close(
    process: subprocess.Popen[bytes],
    threads: tuple[threading.Thread, ...],
) -> None:
    def close_when_idle() -> None:
        for thread in threads:
            thread.join()
        try:
            close_process_streams(process)
        except Exception:
            pass

    try:
        closer = threading.Thread(target=close_when_idle, daemon=True)
        closer.start()
    except Exception:
        pass


def linux_child_processes() -> set[int] | None:
    if sys.platform != "linux":
        return None
    path = pathlib.Path(f"/proc/self/task/{os.getpid()}/children")
    try:
        raw = path.read_bytes()
    except OSError:
        return None
    if len(raw) > 64 << 10:
        return None
    children: set[int] = set()
    for value in raw.split():
        if not value.isdigit():
            return None
        child = int(value)
        if child > 1:
            children.add(child)
        if len(children) > 4096:
            return None
    return children


def prepare_engine_isolation() -> set[int] | None:
    if sys.platform != "linux":
        return None
    if os.getpid() != 1:
        try:
            libc = ctypes.CDLL(None, use_errno=True)
            result = libc.prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0)
        except (AttributeError, OSError):
            result = -1
        if result != 0:
            raise WorkerError(503, "engine_isolation_unavailable", "coding worker cannot contain engine descendants")
    children = linux_child_processes()
    if children is None:
        raise WorkerError(503, "engine_isolation_unavailable", "coding worker cannot inventory engine descendants")
    return children


def stop_engine_descendants(
    baseline: set[int] | None,
    *,
    deadline: float | None = None,
) -> bool:
    if baseline is None:
        return True
    quiet_since: float | None = None
    cleanup_deadline = min(
        deadline if deadline is not None else time.monotonic() + 5,
        time.monotonic() + 5,
    )
    force = False
    while time.monotonic() < cleanup_deadline:
        current = linux_child_processes()
        if current is None:
            return False
        unexpected = current - baseline
        if not unexpected:
            if quiet_since is None:
                quiet_since = time.monotonic()
            if time.monotonic() - quiet_since >= 0.2:
                return True
            time.sleep(0.02)
            continue
        quiet_since = None
        if not force and cleanup_deadline - time.monotonic() < 2:
            force = True
        signal_to_send = signal.SIGKILL if force else signal.SIGTERM
        for child in unexpected:
            try:
                os.kill(child, signal_to_send)
            except ProcessLookupError:
                continue
            except PermissionError:
                return False
        for child in unexpected:
            try:
                os.waitpid(child, os.WNOHANG)
            except ChildProcessError:
                pass
        time.sleep(0.02)
    return False


def run_bounded_process(
    command: list[str],
    *,
    cwd: pathlib.Path,
    environment: dict[str, str],
    timeout_seconds: float,
    stdout_limit: int,
    stderr_limit: int,
    input_bytes: bytes | None = None,
    absolute_deadline: float | None = None,
) -> tuple[int, bytes, bytes, bool, bool]:
    baseline_children = prepare_engine_isolation()
    try:
        process = subprocess.Popen(
            command,
            cwd=cwd,
            env=environment,
            stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
    except OSError as error:
        raise WorkerError(400, "invalid_workspace", "workspace command could not start") from error
    stdout = bytearray()
    stderr = bytearray()
    stdout_exceeded = threading.Event()
    stderr_exceeded = threading.Event()
    readers = [
        threading.Thread(
            target=drain,
            args=(process.stdout, stdout, stdout_exceeded, stdout_limit),
            daemon=True,
        ),
        threading.Thread(
            target=drain,
            args=(process.stderr, stderr, stderr_exceeded, stderr_limit),
            daemon=True,
        ),
    ]
    started_readers: list[threading.Thread] = []
    input_writer = None
    input_writer_started = False
    timed_out = False
    try:
        deadline = time.monotonic() + timeout_seconds
        if absolute_deadline is not None:
            deadline = min(deadline, absolute_deadline)
        for reader in readers:
            reader.start()
            started_readers.append(reader)
        if input_bytes is not None:
            input_writer = threading.Thread(
                target=feed_process_input,
                args=(process.stdin, input_bytes),
                daemon=True,
            )
            input_writer.start()
            input_writer_started = True
        while process.poll() is None:
            if stdout_exceeded.is_set() or stderr_exceeded.is_set() or time.monotonic() >= deadline:
                timed_out = time.monotonic() >= deadline
                break
            time.sleep(0.02)
    finally:
        cleanup_deadline = absolute_deadline if absolute_deadline is not None else time.monotonic() + 10
        remaining_cleanup = max(0.0, cleanup_deadline - time.monotonic())
        descendant_budget = min(5.0, remaining_cleanup / 2)
        process_cleanup_deadline = cleanup_deadline - descendant_budget
        try:
            stopped = stop_process(process, deadline=process_cleanup_deadline)
        except Exception:
            stopped = False
        unexpected_descendants = False
        descendant_inventory_safe = True
        if baseline_children is not None:
            current_children = linux_child_processes()
            if current_children is None:
                descendant_inventory_safe = False
            else:
                unexpected_descendants = bool(current_children - baseline_children)
        try:
            descendants_stopped = stop_engine_descendants(
                baseline_children,
                deadline=cleanup_deadline,
            )
        except Exception:
            descendants_stopped = False
        for reader in started_readers:
            remaining = cleanup_deadline - time.monotonic()
            if remaining <= 0:
                break
            reader.join(timeout=min(2, remaining))
        if input_writer is not None and input_writer_started:
            remaining = cleanup_deadline - time.monotonic()
            if remaining > 0:
                input_writer.join(timeout=min(2, remaining))
        threads_alive = any(reader.is_alive() for reader in started_readers) or (
            input_writer is not None
            and input_writer_started
            and input_writer.is_alive()
        )
        streams_closed = False
        if stopped and not threads_alive:
            try:
                close_process_streams(process)
                streams_closed = True
            except Exception:
                pass
        if (
            not stopped
            or not descendant_inventory_safe
            or not descendants_stopped
            or threads_alive
            or not streams_closed
        ):
            if not streams_closed:
                deferred_threads = tuple(started_readers)
                if input_writer is not None and input_writer_started:
                    deferred_threads = (*deferred_threads, input_writer)
                defer_process_stream_close(process, deferred_threads)
            raise WorkerError(
                502,
                "worker_cleanup_failed",
                "workspace command descendants did not stop",
            )
        if unexpected_descendants:
            raise WorkerError(
                400,
                "invalid_workspace",
                "workspace command launched an unsupported detached process",
            )
    return process.returncode, bytes(stdout), bytes(stderr), (
        stdout_exceeded.is_set() or stderr_exceeded.is_set()
    ), timed_out


def git_environment(extra: dict[str, str] | None = None) -> dict[str, str]:
    environment = {
        "HOME": "/nonexistent",
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "LC_ALL": "C",
        "LANG": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": "/bin/false",
        "GIT_PAGER": "cat",
        "GIT_EDITOR": "/bin/false",
        "GIT_SEQUENCE_EDITOR": "/bin/false",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_OPTIONAL_LOCKS": "0",
    }
    if extra:
        environment.update(extra)
    return environment


def run_git(
    arguments: list[str],
    *,
    stdout_limit: int = MAX_GIT_INVENTORY,
    acceptable: tuple[int, ...] = (0,),
    input_bytes: bytes | None = None,
    cwd: pathlib.Path | None = None,
    extra_environment: dict[str, str] | None = None,
    status: int = 400,
    code: str = "invalid_workspace",
    message: str = "workspace must be a bounded responsive Git checkout",
    overflow_code: str | None = None,
    deadline: float | None = None,
) -> bytes:
    timeout_seconds = float(GIT_TIMEOUT)
    if deadline is not None:
        remaining = deadline - time.monotonic()
        if remaining <= 2:
            raise WorkerError(504, "request_timeout", "coding request exceeded its aggregate time limit")
        timeout_seconds = min(timeout_seconds, remaining - 2)
    command = [
        "git",
        "--no-pager",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.attributesFile=/dev/null",
        "-c",
        "core.autocrlf=false",
        "-c",
        "core.filemode=true",
        "-c",
        "core.ignorecase=false",
        "-c",
        "core.precomposeunicode=false",
        "-c",
        "core.symlinks=true",
        "-c",
        "diff.external=",
        "-c",
        "diff.renames=false",
        *arguments,
    ]
    returncode, stdout, _, exceeded, timed_out = run_bounded_process(
        command,
        cwd=cwd or WORKSPACE,
        environment=git_environment(extra_environment),
        timeout_seconds=timeout_seconds,
        stdout_limit=stdout_limit,
        stderr_limit=MAX_GIT_DIAGNOSTIC,
        input_bytes=input_bytes,
        absolute_deadline=deadline,
    )
    if exceeded:
        raise WorkerError(
            status,
            overflow_code or code,
            "Git output exceeded the handoff bound" if overflow_code else message,
        )
    if timed_out:
        if deadline is not None:
            raise WorkerError(504, "request_timeout", "coding request exceeded its aggregate time limit")
        raise WorkerError(status, code, "workspace Git operation exceeded its time limit")
    if returncode not in acceptable:
        raise WorkerError(status, code, message)
    return stdout


def decode_nul_values(
    raw: bytes,
    *,
    label: str,
    maximum: int,
    overflow_status: int = 409,
    overflow_code: str = "workspace_too_large",
) -> tuple[str, ...]:
    values: list[str] = []
    for encoded in raw.split(b"\x00"):
        if not encoded:
            continue
        try:
            value = encoded.decode("utf-8")
        except UnicodeDecodeError as error:
            raise WorkerError(409, "unsupported_workspace", f"{label} contains a non-UTF-8 path") from error
        if not value or len(value.encode("utf-8")) > 4096:
            raise WorkerError(409, "unsupported_workspace", f"{label} contains an invalid path")
        values.append(value)
        if len(values) > maximum:
            raise WorkerError(overflow_status, overflow_code, f"{label} exceeds its path-count bound")
    return tuple(values)


def git_status(*, deadline: float | None = None) -> tuple[str, ...]:
    raw = run_git(
        ["status", "--porcelain=v1", "-z", "--untracked-files=all", "--ignore-submodules=none"],
        stdout_limit=MAX_GIT_INVENTORY,
        deadline=deadline,
    )
    return decode_nul_values(raw, label="workspace status", maximum=MAX_V1_CHANGED_PATHS)


def _open_nofollow_credential_root(root: pathlib.Path) -> int | None:
    if not root.is_absolute() or any(part in {"", ".", ".."} for part in root.parts[1:]):
        raise WorkerError(500, "credential_store_unsafe", "credential store path is not a safe absolute path")
    try:
        named = os.stat(root, follow_symlinks=False)
    except FileNotFoundError:
        return None
    except OSError as error:
        raise WorkerError(500, "credential_store_unsafe", "credential store cannot be inspected safely") from error
    if not stat.S_ISDIR(named.st_mode):
        raise WorkerError(500, "credential_store_unsafe", "credential store root must be a real directory")
    flags = (
        os.O_RDONLY
        | os.O_CLOEXEC
        | os.O_NONBLOCK
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open("/", flags)
    try:
        for component in root.parts[1:]:
            child = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
            info = os.fstat(descriptor)
            if not stat.S_ISDIR(info.st_mode):
                raise OSError("credential path component is not a directory")
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino):
            raise OSError("credential store changed while being opened")
        return descriptor
    except FileNotFoundError as error:
        os.close(descriptor)
        raise WorkerError(500, "credential_store_changed", "credential store changed during inventory") from error
    except OSError as error:
        os.close(descriptor)
        raise WorkerError(500, "credential_store_unsafe", "credential store cannot be opened without symlinks") from error


def _read_credential_file(directory: int, name: str) -> bytes:
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(name, flags, dir_fd=directory)
    except OSError as error:
        raise WorkerError(500, "credential_store_changed", "credential store changed during inventory") from error
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size > MAX_CREDENTIAL_FILE_BYTES
        ):
            raise WorkerError(
                500,
                "credential_inventory_too_large",
                "credential store file is unsafe or exceeds its byte limit",
            )
        value = bytearray()
        while len(value) <= before.st_size:
            chunk = os.read(descriptor, min(65536, before.st_size - len(value) + 1))
            if not chunk:
                break
            value.extend(chunk)
        after = os.fstat(descriptor)
        try:
            named = os.stat(name, dir_fd=directory, follow_symlinks=False)
        except OSError as error:
            raise WorkerError(
                500,
                "credential_store_changed",
                "credential store changed during inventory",
            ) from error
        identity = lambda item: (
            item.st_dev,
            item.st_ino,
            item.st_size,
            item.st_mtime_ns,
            item.st_ctime_ns,
        )
        if len(value) != before.st_size or identity(before) != identity(after) or identity(after) != identity(named):
            raise WorkerError(500, "credential_store_changed", "credential store changed during inventory")
        return bytes(value)
    finally:
        os.close(descriptor)


def secret_markers(
    worker_token: bytes,
    environment: dict[str, str],
    *,
    deadline: float | None = None,
) -> list[bytes]:
    scan_deadline = time.monotonic() + CREDENTIAL_SCAN_TIMEOUT
    if deadline is not None:
        scan_deadline = min(scan_deadline, deadline)
    raw_values: list[bytes] = []
    value_bytes = 0

    def protect(value: bytes) -> None:
        nonlocal value_bytes
        if len(value) < 8:
            return
        value_bytes += len(value)
        if len(raw_values) >= MAX_CREDENTIAL_VALUES or value_bytes > MAX_CREDENTIAL_VALUE_BYTES:
            raise WorkerError(
                500,
                "credential_inventory_too_large",
                "credential material exceeds its marker bound",
            )
        raw_values.append(value)

    protect(worker_token)
    for name in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN"):
        protect(environment.get(name, "").encode())
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
        value = environment.get(name, "")
        protect(value.encode())
        if not value:
            continue
        try:
            parsed = urllib.parse.urlsplit(value)
        except ValueError as error:
            raise WorkerError(
                500,
                "credential_store_unsafe",
                "proxy credential configuration is malformed",
            ) from error
        for component in (parsed.username, parsed.password):
            if component is not None:
                protect(urllib.parse.unquote(component).encode())

    seen_roots: set[str] = set()
    entries = 0
    files = 0
    json_nodes = 0
    for root_text in (environment.get("CODEX_HOME", ""), environment.get("CLAUDE_CONFIG_DIR", "")):
        if not root_text or root_text in seen_roots:
            continue
        seen_roots.add(root_text)
        require_request_time(scan_deadline)
        root_descriptor = _open_nofollow_credential_root(pathlib.Path(root_text))
        if root_descriptor is None:
            continue
        pending: list[tuple[int, int]] = [(root_descriptor, 0)]
        try:
            while pending:
                require_request_time(scan_deadline)
                directory, depth = pending.pop()
                try:
                    with os.scandir(directory) as iterator:
                        for entry in iterator:
                            require_request_time(scan_deadline)
                            entries += 1
                            if entries > MAX_CREDENTIAL_ENTRIES:
                                raise WorkerError(
                                    500,
                                    "credential_inventory_too_large",
                                    "credential store exceeds its entry-count limit",
                                )
                            try:
                                info = entry.stat(follow_symlinks=False)
                            except OSError as error:
                                raise WorkerError(
                                    500,
                                    "credential_store_changed",
                                    "credential store changed during inventory",
                                ) from error
                            if stat.S_ISLNK(info.st_mode):
                                raise WorkerError(
                                    500,
                                    "credential_store_unsafe",
                                    "credential store contains a symlink",
                                )
                            if stat.S_ISDIR(info.st_mode):
                                if depth >= MAX_CREDENTIAL_DEPTH:
                                    raise WorkerError(
                                        500,
                                        "credential_inventory_too_large",
                                        "credential store exceeds its directory-depth limit",
                                    )
                                flags = (
                                    os.O_RDONLY
                                    | os.O_CLOEXEC
                                    | os.O_NONBLOCK
                                    | getattr(os, "O_DIRECTORY", 0)
                                    | getattr(os, "O_NOFOLLOW", 0)
                                )
                                try:
                                    child = os.open(entry.name, flags, dir_fd=directory)
                                except OSError as error:
                                    raise WorkerError(
                                        500,
                                        "credential_store_changed",
                                        "credential store changed during inventory",
                                    ) from error
                                opened = os.fstat(child)
                                if (
                                    opened.st_dev != info.st_dev
                                    or opened.st_ino != info.st_ino
                                    or not stat.S_ISDIR(opened.st_mode)
                                ):
                                    os.close(child)
                                    raise WorkerError(
                                        500,
                                        "credential_store_changed",
                                        "credential store changed during inventory",
                                    )
                                pending.append((child, depth + 1))
                                continue
                            if not stat.S_ISREG(info.st_mode):
                                raise WorkerError(
                                    500,
                                    "credential_store_unsafe",
                                    "credential store contains a special file",
                                )
                            files += 1
                            if files > MAX_CREDENTIAL_FILES:
                                raise WorkerError(
                                    500,
                                    "credential_inventory_too_large",
                                    "credential store exceeds its file-count limit",
                                )
                            value = _read_credential_file(directory, entry.name)
                            protect(value)
                            try:
                                decoded = json.loads(value)
                            except (UnicodeDecodeError, json.JSONDecodeError):
                                continue
                            stack = [decoded]
                            while stack:
                                require_request_time(scan_deadline)
                                current = stack.pop()
                                json_nodes += 1
                                if json_nodes > MAX_CREDENTIAL_JSON_NODES:
                                    raise WorkerError(
                                        500,
                                        "credential_inventory_too_large",
                                        "credential JSON exceeds its node-count limit",
                                    )
                                if isinstance(current, dict):
                                    stack.extend(current.keys())
                                    stack.extend(current.values())
                                elif isinstance(current, list):
                                    stack.extend(current)
                                elif isinstance(current, str):
                                    protect(current.encode())
                finally:
                    os.close(directory)
        except Exception:
            for descriptor, _ in pending:
                os.close(descriptor)
            raise
    markers: set[bytes] = set()
    for value in raw_values:
        require_request_time(scan_deadline)
        if len(value) < 8:
            continue
        markers.add(value)
        markers.add(base64.b64encode(value))
        markers.add(base64.urlsafe_b64encode(value).rstrip(b"="))
        markers.add(value.hex().encode())
        markers.add(hashlib.sha256(value).hexdigest().encode())
    require_request_time(scan_deadline)
    return sorted(markers, key=len, reverse=True)


def validate_task_payload(payload: dict[str, object]) -> dict[str, object]:
    schema = payload.get("schema_version")
    fields = {"schema_version", "task", "mode", "timeout_seconds"}
    if schema == "steward.coding-task.v2":
        fields.add("expected_base_commit")
    if schema not in {"steward.coding-task.v1", "steward.coding-task.v2"} or set(payload) != fields:
        raise WorkerError(400, "invalid_request", "coding request has an invalid contract")
    task = payload.get("task")
    mode = payload.get("mode")
    timeout_seconds = payload.get("timeout_seconds")
    if (
        not isinstance(task, str)
        or not task.strip()
        or task != task.strip()
        or "\x00" in task
        or len(task.encode()) > MAX_TASK
        or mode not in {"read", "write"}
        or type(timeout_seconds) is not int
        or not 30 <= timeout_seconds <= MAX_TIMEOUT
    ):
        raise WorkerError(400, "invalid_request", "task, mode, or timeout is outside its bound")
    expected_base = payload.get("expected_base_commit")
    if schema == "steward.coding-task.v2" and (
        not isinstance(expected_base, str)
        or len(expected_base) not in OBJECT_ID_LENGTHS.values()
        or any(character not in "0123456789abcdef" for character in expected_base)
    ):
        raise WorkerError(400, "invalid_request", "expected base commit is not a canonical Git object ID")
    return {
        "schema_version": schema,
        "task": task,
        "mode": mode,
        "timeout_seconds": timeout_seconds,
        "expected_base_commit": expected_base,
    }


def git_text(
    arguments: list[str],
    *,
    extra_environment: dict[str, str] | None = None,
    code: str = "invalid_workspace",
    message: str = "workspace must be a bounded responsive Git checkout",
    deadline: float | None = None,
) -> str:
    raw = run_git(
        arguments,
        stdout_limit=8192,
        extra_environment=extra_environment,
        code=code,
        message=message,
        deadline=deadline,
    )
    try:
        value = raw.decode("ascii").strip()
    except UnicodeDecodeError as error:
        raise WorkerError(409, code, message) from error
    if not value or "\n" in value or "\r" in value:
        raise WorkerError(409, code, message)
    return value


def _repository_environment(identity: dict[str, object]) -> dict[str, str]:
    git_dir = identity.get("_git_dir")
    workspace_root = identity.get("_workspace_root")
    if (
        not isinstance(git_dir, str)
        or not pathlib.Path(git_dir).is_absolute()
        or not isinstance(workspace_root, str)
        or not pathlib.Path(workspace_root).is_absolute()
    ):
        raise WorkerError(409, "workspace_identity_changed", "workspace Git identity is unavailable")
    return {"GIT_DIR": git_dir, "GIT_WORK_TREE": workspace_root}


def _directory_open_flags() -> int:
    return (
        os.O_RDONLY
        | os.O_CLOEXEC
        | os.O_NONBLOCK
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )


def _validate_git_metadata_tree(
    metadata_descriptor: int,
    *,
    deadline: float | None = None,
) -> None:
    pending = [metadata_descriptor]
    visited = 0
    try:
        while pending:
            if deadline is not None:
                require_request_time(deadline)
            directory = pending.pop()
            try:
                with os.scandir(directory) as iterator:
                    for entry in iterator:
                        if deadline is not None:
                            require_request_time(deadline)
                        visited += 1
                        if visited > MAX_GIT_METADATA_ENTRIES:
                            raise WorkerError(
                                413,
                                "workspace_too_large",
                                "workspace Git metadata exceeds its entry-count bound",
                            )
                        try:
                            info = entry.stat(follow_symlinks=False)
                        except OSError as error:
                            raise WorkerError(
                                409,
                                "workspace_identity_changed",
                                "workspace Git metadata changed during inventory",
                            ) from error
                        if stat.S_ISLNK(info.st_mode):
                            raise WorkerError(
                                409,
                                "unsupported_workspace",
                                "workspace Git metadata must not contain symlinks",
                            )
                        if stat.S_ISDIR(info.st_mode):
                            try:
                                child = os.open(
                                    entry.name,
                                    _directory_open_flags(),
                                    dir_fd=directory,
                                )
                            except OSError as error:
                                raise WorkerError(
                                    409,
                                    "workspace_identity_changed",
                                    "workspace Git metadata changed during inventory",
                                ) from error
                            opened = os.fstat(child)
                            if (
                                opened.st_dev != info.st_dev
                                or opened.st_ino != info.st_ino
                                or not stat.S_ISDIR(opened.st_mode)
                            ):
                                os.close(child)
                                raise WorkerError(
                                    409,
                                    "workspace_identity_changed",
                                    "workspace Git metadata changed during inventory",
                                )
                            pending.append(child)
                        elif stat.S_ISREG(info.st_mode):
                            if info.st_nlink != 1:
                                raise WorkerError(
                                    409,
                                    "unsupported_workspace",
                                    "workspace Git metadata must use independent files",
                                )
                        else:
                            raise WorkerError(
                                409,
                                "unsupported_workspace",
                                "workspace Git metadata contains a special file",
                            )
            except WorkerError:
                raise
            except OSError as error:
                raise WorkerError(
                    409,
                    "unsupported_workspace",
                    "workspace Git metadata cannot be read safely",
                ) from error
            finally:
                os.close(directory)
    except Exception:
        for descriptor in pending:
            os.close(descriptor)
        raise


def _contained_git_metadata(root: pathlib.Path, *, deadline: float | None = None) -> pathlib.Path:
    metadata = root / ".git"
    root_descriptor = None
    metadata_descriptor = None
    try:
        root_descriptor = os.open(root, _directory_open_flags())
        root_info = os.fstat(root_descriptor)
        named_root = os.stat(root, follow_symlinks=False)
        if (
            root_info.st_dev != named_root.st_dev
            or root_info.st_ino != named_root.st_ino
            or not stat.S_ISDIR(root_info.st_mode)
        ):
            raise OSError("workspace root changed while being opened")
        named_metadata = os.stat(".git", dir_fd=root_descriptor, follow_symlinks=False)
        metadata_descriptor = os.open(
            ".git",
            _directory_open_flags(),
            dir_fd=root_descriptor,
        )
        opened_metadata = os.fstat(metadata_descriptor)
        if (
            opened_metadata.st_dev != named_metadata.st_dev
            or opened_metadata.st_ino != named_metadata.st_ino
            or not stat.S_ISDIR(opened_metadata.st_mode)
        ):
            raise OSError("workspace Git metadata changed while being opened")
    except OSError as error:
        if metadata_descriptor is not None:
            os.close(metadata_descriptor)
        raise WorkerError(
            409,
            "unsupported_workspace",
            "workspace must contain a standalone Git metadata directory",
        ) from error
    finally:
        if root_descriptor is not None:
            os.close(root_descriptor)
    _validate_git_metadata_tree(metadata_descriptor, deadline=deadline)
    return metadata


def _resolved_repository_paths(
    root: pathlib.Path,
    *,
    extra_environment: dict[str, str] | None = None,
    deadline: float | None = None,
) -> tuple[pathlib.Path, pathlib.Path, pathlib.Path]:
    git_dir = pathlib.Path(
        git_text(
            ["rev-parse", "--absolute-git-dir"],
            extra_environment=extra_environment,
            deadline=deadline,
        )
    )
    common_dir = pathlib.Path(
        git_text(
            ["rev-parse", "--git-common-dir"],
            extra_environment=extra_environment,
            deadline=deadline,
        )
    )
    object_path = pathlib.Path(
        git_text(
            ["rev-parse", "--git-path", "objects"],
            extra_environment=extra_environment,
            deadline=deadline,
        )
    )
    if not common_dir.is_absolute():
        common_dir = root / common_dir
    if not object_path.is_absolute():
        object_path = root / object_path
    try:
        return (
            git_dir.resolve(strict=True),
            common_dir.resolve(strict=True),
            object_path.resolve(strict=True),
        )
    except OSError as error:
        raise WorkerError(409, "unsupported_workspace", "workspace Git metadata is unavailable") from error


def _standalone_repository_shape(*, deadline: float | None = None) -> dict[str, object]:
    if deadline is not None:
        require_request_time(deadline)
    try:
        root = WORKSPACE.resolve(strict=True)
    except OSError as error:
        raise WorkerError(400, "invalid_workspace", "workspace directory is unavailable") from error
    metadata = _contained_git_metadata(root, deadline=deadline)
    top = pathlib.Path(git_text(["rev-parse", "--show-toplevel"], deadline=deadline))
    try:
        if top.resolve(strict=True) != root:
            raise WorkerError(409, "unsupported_workspace", "workspace must be the Git checkout root")
    except OSError as error:
        raise WorkerError(409, "unsupported_workspace", "workspace root cannot be resolved") from error
    git_dir, common_dir, object_path = _resolved_repository_paths(root, deadline=deadline)
    expected_object_path = metadata / "objects"
    try:
        object_info = os.stat(expected_object_path, follow_symlinks=False)
    except OSError as error:
        raise WorkerError(409, "unsupported_workspace", "workspace Git object store is unavailable") from error
    if (
        git_dir != metadata
        or common_dir != metadata
        or object_path != expected_object_path
        or not stat.S_ISDIR(object_info.st_mode)
        or os.pathsep in str(object_path)
    ):
        raise WorkerError(
            409,
            "unsupported_workspace",
            "workspace Git metadata must be contained in its standalone checkout",
        )
    if os.path.lexists(object_path / "info" / "alternates"):
        raise WorkerError(409, "unsupported_workspace", "alternate Git object stores are not supported")
    return {
        "_workspace_root": str(root),
        "_git_dir": str(git_dir),
        "_object_dir": str(object_path),
    }


def _assert_repository_identity(identity: dict[str, object], *, deadline: float | None = None) -> None:
    expected_root = identity.get("_workspace_root")
    expected_git = identity.get("_git_dir")
    expected_objects = identity.get("_object_dir")
    if (
        not isinstance(expected_root, str)
        or not isinstance(expected_git, str)
        or not isinstance(expected_objects, str)
    ):
        raise WorkerError(409, "workspace_identity_changed", "workspace Git identity is unavailable")
    current = _standalone_repository_shape(deadline=deadline)
    if (
        current["_workspace_root"] != expected_root
        or current["_git_dir"] != expected_git
        or current["_object_dir"] != expected_objects
    ):
        raise WorkerError(409, "workspace_identity_changed", "workspace Git identity changed")


def _ignored_paths(
    extra_environment: dict[str, str] | None = None,
    *,
    deadline: float | None = None,
) -> tuple[str, ...]:
    raw = run_git(
        ["ls-files", "--others", "--ignored", "--exclude-standard", "-z"],
        extra_environment=extra_environment,
        deadline=deadline,
    )
    return decode_nul_values(raw, label="ignored workspace inventory", maximum=MAX_CHANGED_PATHS)


def _reject_special_workspace_entries(*, deadline: float | None = None) -> None:
    pending: list[tuple[pathlib.Path, tuple[str, ...]]] = [(WORKSPACE, ())]
    portable_paths: set[str] = set()
    visited = 0
    while pending:
        if deadline is not None and time.monotonic() >= deadline:
            raise WorkerError(504, "request_timeout", "coding request exceeded its aggregate time limit")
        directory, parent_components = pending.pop()
        try:
            with os.scandir(directory) as iterator:
                for entry in iterator:
                    if deadline is not None and time.monotonic() >= deadline:
                        raise WorkerError(504, "request_timeout", "coding request exceeded its aggregate time limit")
                    if directory == WORKSPACE and entry.name == ".git":
                        continue
                    visited += 1
                    if visited > MAX_WORKSPACE_ENTRIES:
                        raise WorkerError(413, "workspace_too_large", "workspace exceeds its entry-count bound")
                    try:
                        info = entry.stat(follow_symlinks=False)
                    except OSError as error:
                        raise WorkerError(409, "workspace_changed", "workspace changed during inventory") from error
                    components = (*parent_components, entry.name)
                    portable_key = _portable_path_key(components)
                    if portable_key in portable_paths:
                        raise WorkerError(
                            409,
                            "unsupported_workspace",
                            "workspace paths collide on portable filesystems",
                        )
                    portable_paths.add(portable_key)
                    if stat.S_ISDIR(info.st_mode):
                        pending.append((pathlib.Path(entry.path), components))
                    elif stat.S_ISREG(info.st_mode) and info.st_nlink != 1:
                        raise WorkerError(
                            409,
                            "special_file_not_supported",
                            "handoff workspaces do not support hard-linked files",
                        )
                    elif not stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode):
                        raise WorkerError(
                            409,
                            "special_file_not_supported",
                            "handoff workspaces support only directories, regular files, and symlinks",
                        )
        except OSError as error:
            raise WorkerError(409, "unsupported_workspace", "workspace inventory cannot be read safely") from error


def _reject_unsupported_repository(
    base_commit: str,
    *,
    extra_environment: dict[str, str] | None = None,
    deadline: float | None = None,
) -> None:
    shallow = git_text(
        ["rev-parse", "--is-shallow-repository"],
        extra_environment=extra_environment,
        deadline=deadline,
    )
    if shallow != "false":
        raise WorkerError(409, "unsupported_workspace", "shallow repositories are not supported")
    executable_config = run_git(
        [
            "config",
            "--local",
            "--no-includes",
            "--get-regexp",
            r"^(include(if)?\.|filter\.|diff\..*\.(command|textconv)$)",
        ],
        acceptable=(0, 1),
        extra_environment=extra_environment,
        deadline=deadline,
    )
    if executable_config:
        raise WorkerError(
            409,
            "unsupported_workspace",
            "included or executable repository configuration is not supported",
        )
    unsafe_config = run_git(
        [
            "config",
            "--local",
            "--no-includes",
            "--get-regexp",
            r"^(extensions\.(partialclone|worktreeconfig)|remote\..*\.(promisor|partialclonefilter)|core\.sparsecheckout|core\.sparsecheckoutcone)$",
        ],
        acceptable=(0, 1),
        extra_environment=extra_environment,
        deadline=deadline,
    )
    if unsafe_config and any(
        value.lower() not in {"core.sparsecheckout false", "core.sparsecheckoutcone false"}
        for value in unsafe_config.decode("utf-8", "replace").strip().splitlines()
    ):
        raise WorkerError(409, "unsupported_workspace", "partial or sparse repositories are not supported")
    tracked_modules = run_git(
        ["ls-tree", "-z", "--name-only", base_commit, "--", ".gitmodules"],
        extra_environment=extra_environment,
        deadline=deadline,
    )
    if tracked_modules or os.path.lexists(WORKSPACE / ".gitmodules"):
        raise WorkerError(409, "submodules_not_supported", "coding handoffs do not support submodules")
    base_modes = run_git(
        ["ls-tree", "-r", "-z", "--full-tree", "--format=%(objectmode)", base_commit],
        stdout_limit=MAX_GIT_INVENTORY,
        extra_environment=extra_environment,
        status=409,
        code="unsupported_workspace",
        message="base tree inventory exceeds the supported bound",
        deadline=deadline,
    )
    if b"160000\x00" in base_modes:
        raise WorkerError(409, "submodules_not_supported", "coding handoffs do not support Git links")
    flags = run_git(
        ["ls-files", "-v", "-z"],
        extra_environment=extra_environment,
        deadline=deadline,
    )
    for entry in flags.split(b"\x00"):
        if not entry:
            continue
        tag = chr(entry[0])
        if tag == "S" or tag.islower():
            raise WorkerError(
                409,
                "unsupported_workspace",
                "skip-worktree and assume-unchanged entries are not supported",
            )


def workspace_identity(
    expected_base_commit: str,
    *,
    deadline: float | None = None,
) -> dict[str, object]:
    shape = _standalone_repository_shape(deadline=deadline)
    object_format = git_text(["rev-parse", "--show-object-format"], deadline=deadline)
    length = OBJECT_ID_LENGTHS.get(object_format)
    if length is None:
        raise WorkerError(409, "unsupported_workspace", "workspace uses an unsupported Git object format")
    if (
        not isinstance(expected_base_commit, str)
        or len(expected_base_commit) != length
        or any(character not in "0123456789abcdef" for character in expected_base_commit)
    ):
        raise WorkerError(409, "base_commit_mismatch", "expected base does not match the repository object format")
    base_commit = git_text(
        ["rev-parse", "--verify", "HEAD^{commit}"],
        code="base_commit_mismatch",
        message="workspace HEAD does not identify the expected base commit",
        deadline=deadline,
    )
    if base_commit != expected_base_commit:
        raise WorkerError(409, "base_commit_mismatch", "workspace HEAD does not match the expected base commit")
    base_tree = git_text(
        ["rev-parse", "--verify", f"{base_commit}^{{tree}}"],
        deadline=deadline,
    )
    identity: dict[str, object] = {
        **shape,
        "object_format": object_format,
        "base_commit": base_commit,
        "base_tree": base_tree,
    }
    repository_environment = _repository_environment(identity)
    _reject_unsupported_repository(
        base_commit,
        extra_environment=repository_environment,
        deadline=deadline,
    )
    _reject_special_workspace_entries(deadline=deadline)
    if git_status(deadline=deadline) or _ignored_paths(repository_environment, deadline=deadline):
        raise WorkerError(409, "workspace_not_clean", "version 2 coding tasks require a fully clean checkout")
    _assert_repository_identity(identity, deadline=deadline)
    return identity


def _portable_component(component: str) -> str:
    normalized = unicodedata.normalize("NFC", component).casefold()
    protected = normalized.rstrip(" .")
    device = protected.split(".", 1)[0]
    short_prefix, short_separator, short_suffix = protected.partition("~")
    gitmodules_fallback = (
        short_separator == "~"
        and 1 <= len(short_prefix) <= 6
        and "gi7eba".startswith(short_prefix)
        and len(short_prefix) + len(short_suffix) == 7
        and re.fullmatch(r"[1-9][0-9]*", short_suffix) is not None
    )
    if (
        not normalized
        or normalized in {".", ".."}
        or normalized[-1] in {" ", "."}
        or "\\" in normalized
        or ":" in normalized
        or any(character in '<>"|?*' for character in normalized)
        or any(
            "\u200c" <= character <= "\u200f"
            or "\u202a" <= character <= "\u202e"
            or "\u206a" <= character <= "\u206f"
            or character == "\ufeff"
            for character in normalized
        )
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in normalized)
        or protected in {".git", ".gitmodules"}
        or re.fullmatch(r"\.?git~[0-9]+", protected) is not None
        or re.fullmatch(r"gitmod~[1-4]", protected) is not None
        or gitmodules_fallback
        or device in {"con", "prn", "aux", "nul", "conin$", "conout$"}
        or re.fullmatch(r"(com|lpt)([1-9]|[¹²³])", device) is not None
    ):
        raise WorkerError(409, "unsupported_workspace", "handoff contains a non-portable path")
    return normalized


def _portable_path_key(components: tuple[str, ...]) -> str:
    return "/".join(_portable_component(component) for component in components)


def _validate_changed_path(path_text: str) -> tuple[pathlib.Path, bytes, str]:
    encoded = path_text.encode("utf-8")
    if (
        not path_text
        or path_text.startswith("/")
        or len(encoded) > 4096
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in path_text)
    ):
        raise WorkerError(409, "unsupported_workspace", "handoff contains an unsafe path")
    components = pathlib.PurePosixPath(path_text).parts
    if not components:
        raise WorkerError(409, "unsupported_workspace", "handoff contains an unsafe path")
    portable_key = _portable_path_key(components)
    current = WORKSPACE
    for component in components[:-1]:
        current /= component
        try:
            info = os.lstat(current)
        except FileNotFoundError:
            break
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise WorkerError(409, "unsupported_workspace", "handoff path has an unsafe parent")
    return WORKSPACE.joinpath(*components), encoded, portable_key


def _status_changed_paths(
    entries: tuple[str, ...],
    *,
    deadline: float,
) -> list[str]:
    paths: list[str] = []
    index = 0
    while index < len(entries):
        require_request_time(deadline)
        record = entries[index]
        if len(record) <= 3 or record[2] != " ":
            raise WorkerError(409, "unsupported_workspace", "workspace status is malformed")
        paths.append(record[3:])
        if "R" in record[:2] or "C" in record[:2]:
            index += 1
            if index >= len(entries):
                raise WorkerError(409, "unsupported_workspace", "workspace rename status is incomplete")
            paths.append(entries[index])
        index += 1
    result = sorted(set(paths))
    if len(result) > MAX_V1_CHANGED_PATHS:
        raise WorkerError(413, "workspace_too_large", "workspace status exceeds its changed-path count")
    portable_paths: set[str] = set()
    total_bytes = 0
    for path in result:
        _, encoded, portable_key = _validate_changed_path(path)
        if portable_key in portable_paths:
            raise WorkerError(409, "unsupported_workspace", "workspace status contains colliding paths")
        portable_paths.add(portable_key)
        total_bytes += len(encoded)
    if total_bytes > MAX_RESPONSE:
        raise WorkerError(413, "workspace_too_large", "workspace status exceeds its changed-path byte limit")
    return result


def _read_changed_entry(path: pathlib.Path, path_text: str) -> bytes | None:
    try:
        named = os.lstat(path)
    except FileNotFoundError:
        return None
    if stat.S_ISLNK(named.st_mode):
        target = os.readlink(path)
        if (
            os.path.isabs(target)
            or "\x00" in target
            or any(ord(character) < 0x20 or ord(character) == 0x7F for character in target)
        ):
            raise WorkerError(409, "unsupported_workspace", "handoff symlink target is unsafe")
        resolved = pathlib.PurePosixPath(path_text).parent.joinpath(target)
        if any(component == ".." for component in resolved.parts):
            raise WorkerError(409, "unsupported_workspace", "handoff symlink escapes the workspace")
        _portable_path_key(resolved.parts)
        return os.fsencode(target)
    if not stat.S_ISREG(named.st_mode) or named.st_nlink != 1:
        raise WorkerError(409, "special_file_not_supported", "handoff supports only regular files and safe symlinks")
    if named.st_size > MAX_CHANGED_FILE_BYTES:
        raise WorkerError(413, "handoff_too_large", "one changed file exceeds the handoff byte limit")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size != named.st_size:
            raise WorkerError(409, "workspace_changed", "changed file identity is unstable")
        value = os.read(descriptor, MAX_CHANGED_FILE_BYTES + 1)
        after = os.fstat(descriptor)
        current = os.lstat(path)
        identity = lambda item: (
            item.st_dev,
            item.st_ino,
            item.st_mode,
            item.st_nlink,
            item.st_size,
            item.st_mtime_ns,
            item.st_ctime_ns,
        )
        if len(value) != before.st_size or identity(before) != identity(after) or identity(after) != identity(current):
            raise WorkerError(409, "workspace_changed", "changed file identity is unstable")
        return value
    finally:
        os.close(descriptor)


def _changed_path_inventory(
    repository_environment: dict[str, str],
    *,
    deadline: float,
) -> tuple[str, ...]:
    tracked = decode_nul_values(
        run_git(
            ["diff", "--name-only", "-z", "--no-renames", "HEAD", "--"],
            stdout_limit=MAX_CHANGED_PATH_BYTES + MAX_CHANGED_PATHS,
            extra_environment=repository_environment,
            status=413,
            code="handoff_too_large",
            message="tracked change inventory exceeds the handoff bound",
            overflow_code="handoff_too_large",
            deadline=deadline,
        ),
        label="tracked change inventory",
        maximum=MAX_CHANGED_PATHS,
        overflow_status=413,
        overflow_code="handoff_too_large",
    )
    untracked = decode_nul_values(
        run_git(
            ["ls-files", "--others", "--exclude-standard", "-z"],
            stdout_limit=MAX_CHANGED_PATH_BYTES + MAX_CHANGED_PATHS,
            extra_environment=repository_environment,
            status=413,
            code="handoff_too_large",
            message="untracked change inventory exceeds the handoff bound",
            overflow_code="handoff_too_large",
            deadline=deadline,
        ),
        label="untracked change inventory",
        maximum=MAX_CHANGED_PATHS,
        overflow_status=413,
        overflow_code="handoff_too_large",
    )
    paths = tuple(sorted(set(tracked) | set(untracked)))
    if len(paths) > MAX_CHANGED_PATHS:
        raise WorkerError(413, "handoff_too_large", "handoff exceeds its changed-path count")
    if sum(len(path.encode("utf-8")) for path in paths) > MAX_CHANGED_PATH_BYTES:
        raise WorkerError(413, "handoff_too_large", "handoff changed paths exceed their byte limit")
    return paths


def _tree_entries(
    tree: str,
    paths: tuple[str, ...],
    repository_environment: dict[str, str],
    object_id_length: int,
    *,
    deadline: float,
) -> dict[str, tuple[str, str]]:
    if not paths:
        return {}
    pathspecs = [f":(literal){path}" for path in paths]
    raw = run_git(
        ["ls-tree", "-r", "-z", "--full-tree", tree, "--", *pathspecs],
        stdout_limit=MAX_GIT_INVENTORY,
        extra_environment=repository_environment,
        status=409,
        code="handoff_not_reproducible",
        message="handoff tree inventory is invalid or exceeds its bound",
        deadline=deadline,
    )
    expected_paths = set(paths)
    entries: dict[str, tuple[str, str]] = {}
    for record in raw.split(b"\x00"):
        if not record:
            continue
        try:
            metadata, encoded_path = record.split(b"\t", 1)
            mode, object_type, encoded_object_id = metadata.split(b" ", 2)
            path_text = encoded_path.decode("utf-8")
            object_id = encoded_object_id.decode("ascii")
        except (UnicodeDecodeError, ValueError) as error:
            raise WorkerError(409, "handoff_not_reproducible", "handoff tree inventory is malformed") from error
        if path_text not in expected_paths or path_text in entries:
            raise WorkerError(409, "handoff_not_reproducible", "handoff tree inventory changed unexpectedly")
        if mode == b"160000" or object_type == b"commit":
            raise WorkerError(409, "submodules_not_supported", "coding handoffs do not support Git links")
        if mode not in {b"100644", b"100755", b"120000"} or object_type != b"blob":
            raise WorkerError(409, "unsupported_workspace", "handoff tree contains an unsupported entry")
        if len(object_id) != object_id_length or any(character not in "0123456789abcdef" for character in object_id):
            raise WorkerError(409, "handoff_not_reproducible", "handoff tree contains an invalid object ID")
        entries[path_text] = (mode.decode("ascii"), object_id)
    return entries


def _blob_sizes(
    object_ids: tuple[str, ...],
    repository_environment: dict[str, str],
    *,
    deadline: float,
) -> dict[str, int]:
    if not object_ids:
        return {}
    request = ("\n".join(object_ids) + "\n").encode("ascii")
    raw = run_git(
        ["cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize)"],
        input_bytes=request,
        stdout_limit=len(object_ids) * 160,
        extra_environment=repository_environment,
        status=409,
        code="handoff_not_reproducible",
        message="handoff blob inventory is invalid",
        deadline=deadline,
    )
    lines = raw.splitlines()
    if len(lines) != len(object_ids):
        raise WorkerError(409, "handoff_not_reproducible", "handoff blob inventory is incomplete")
    sizes: dict[str, int] = {}
    for expected, line in zip(object_ids, lines, strict=True):
        parts = line.split(b" ")
        try:
            object_id = parts[0].decode("ascii")
            object_type = parts[1]
            size_text = parts[2].decode("ascii")
            size = int(size_text)
        except (IndexError, UnicodeDecodeError, ValueError) as error:
            raise WorkerError(409, "handoff_not_reproducible", "handoff blob inventory is malformed") from error
        if (
            len(parts) != 3
            or object_id != expected
            or object_type != b"blob"
            or str(size) != size_text
            or size < 0
            or size > MAX_CHANGED_FILE_BYTES
        ):
            raise WorkerError(413, "handoff_too_large", "handoff blob exceeds its supported bound")
        sizes[object_id] = size
    return sizes


def _scan_tree_blobs(
    base_entries: dict[str, tuple[str, str]],
    result_entries: dict[str, tuple[str, str]],
    repository_environment: dict[str, str],
    protected_markers: tuple[bytes, ...],
    *,
    deadline: float,
) -> None:
    object_ids = tuple(
        sorted({object_id for entries in (base_entries, result_entries) for _, object_id in entries.values()})
    )
    sizes = _blob_sizes(object_ids, repository_environment, deadline=deadline)
    for label, entries in (("base", base_entries), ("result", result_entries)):
        total = sum(sizes[object_id] for _, object_id in entries.values())
        if total > MAX_CHANGED_TOTAL_BYTES:
            raise WorkerError(413, "handoff_too_large", f"{label} blobs exceed the handoff byte limit")
    if not protected_markers or not object_ids:
        return
    unique_total = sum(sizes[object_id] for object_id in object_ids)
    if unique_total > MAX_PROTECTED_SCAN_BYTES:
        raise WorkerError(413, "handoff_too_large", "handoff credential scan exceeds its byte limit")
    request = ("\n".join(object_ids) + "\n").encode("ascii")
    raw = run_git(
        ["cat-file", "--batch"],
        input_bytes=request,
        stdout_limit=unique_total + len(object_ids) * 160,
        extra_environment=repository_environment,
        status=413,
        code="handoff_too_large",
        message="handoff credential scan exceeds its bound",
        overflow_code="handoff_too_large",
        deadline=deadline,
    )
    offset = 0
    for expected in object_ids:
        end = raw.find(b"\n", offset)
        if end < 0:
            raise WorkerError(409, "handoff_not_reproducible", "handoff blob stream is incomplete")
        header = raw[offset:end].split(b" ")
        try:
            object_id = header[0].decode("ascii")
            object_type = header[1]
            size = int(header[2].decode("ascii"))
        except (IndexError, UnicodeDecodeError, ValueError) as error:
            raise WorkerError(409, "handoff_not_reproducible", "handoff blob stream is malformed") from error
        offset = end + 1
        value = raw[offset:offset + size]
        offset += size
        if (
            len(header) != 3
            or object_id != expected
            or object_type != b"blob"
            or size != sizes[expected]
            or len(value) != size
            or offset >= len(raw)
            or raw[offset:offset + 1] != b"\n"
        ):
            raise WorkerError(409, "handoff_not_reproducible", "handoff blob stream is invalid")
        offset += 1
        if contains_protected(value, protected_markers, deadline=deadline):
            raise WorkerError(502, "credential_output_blocked", "handoff blob matched protected credential material")
    if offset != len(raw):
        raise WorkerError(409, "handoff_not_reproducible", "handoff blob stream has trailing data")


def _temporary_repository_environment(
    identity: dict[str, object],
    root: pathlib.Path,
) -> dict[str, str]:
    source_objects = identity.get("_object_dir")
    if not isinstance(source_objects, str):
        raise WorkerError(409, "workspace_identity_changed", "workspace object identity is unavailable")
    root.mkdir(mode=0o700)
    objects = root / "objects"
    objects.mkdir(mode=0o700)
    environment = _repository_environment(identity)
    environment.update(
        {
            "GIT_INDEX_FILE": str(root / "index"),
            "GIT_OBJECT_DIRECTORY": str(objects),
            "GIT_ALTERNATE_OBJECT_DIRECTORIES": source_objects,
        }
    )
    return environment


def _capture_snapshot(
    identity: dict[str, object],
    protected_markers: tuple[bytes, ...],
    *,
    deadline: float,
) -> tuple[bytes, tuple[str, ...], str]:
    repository_environment = _repository_environment(identity)
    _reject_unsupported_repository(
        str(identity["base_commit"]),
        extra_environment=repository_environment,
        deadline=deadline,
    )
    _reject_special_workspace_entries(deadline=deadline)
    if _ignored_paths(repository_environment, deadline=deadline):
        raise WorkerError(409, "unsupported_workspace", "ignored workspace output cannot enter a handoff")
    source_objects = identity.get("_object_dir")
    if not isinstance(source_objects, str) or os.path.lexists(pathlib.Path(source_objects) / "info" / "alternates"):
        raise WorkerError(409, "unsupported_workspace", "alternate Git object stores are not supported")
    paths = _changed_path_inventory(repository_environment, deadline=deadline)
    portable_names: set[str] = set()
    changed_bytes = 0
    for path_text in paths:
        if unicodedata.normalize("NFC", path_text).casefold() == ".gitmodules":
            raise WorkerError(409, "submodules_not_supported", "coding handoffs do not support submodules")
        path, encoded_path, portable_key = _validate_changed_path(path_text)
        if portable_key in portable_names:
            raise WorkerError(409, "unsupported_workspace", "handoff paths collide on portable filesystems")
        portable_names.add(portable_key)
        if contains_protected(encoded_path, protected_markers, deadline=deadline):
            raise WorkerError(502, "credential_output_blocked", "changed path matched protected credential material")
        value = _read_changed_entry(path, path_text)
        if value is None:
            continue
        changed_bytes += len(value)
        if changed_bytes > MAX_CHANGED_TOTAL_BYTES:
            raise WorkerError(413, "handoff_too_large", "changed files exceed the handoff byte limit")
        if contains_protected(value, protected_markers, deadline=deadline):
            raise WorkerError(502, "credential_output_blocked", "changed file matched protected credential material")
    object_id_length = OBJECT_ID_LENGTHS[str(identity["object_format"])]
    with tempfile.TemporaryDirectory(prefix="steward-coding-handoff-") as temporary:
        root = pathlib.Path(temporary)
        staged_environment = _temporary_repository_environment(identity, root / "staged")
        run_git(
            ["read-tree", str(identity["base_commit"])],
            extra_environment=staged_environment,
            deadline=deadline,
        )
        run_git(
            ["add", "--all", "--"],
            extra_environment=staged_environment,
            status=409,
            code="handoff_not_reproducible",
            message="workspace could not be projected into an isolated Git index",
            deadline=deadline,
        )
        result_tree = git_text(
            ["write-tree"],
            extra_environment=staged_environment,
            code="handoff_not_reproducible",
            message="handoff result tree could not be created",
            deadline=deadline,
        )
        staged_paths = decode_nul_values(
            run_git(
                [
                    "diff",
                    "--cached",
                    "--name-only",
                    "-z",
                    "--no-renames",
                    str(identity["base_commit"]),
                    "--",
                ],
                extra_environment=staged_environment,
                deadline=deadline,
            ),
            label="staged handoff inventory",
            maximum=MAX_CHANGED_PATHS,
        )
        if tuple(sorted(set(staged_paths))) != paths:
            raise WorkerError(409, "workspace_changed", "workspace changed while its handoff was staged")
        base_entries = _tree_entries(
            str(identity["base_tree"]),
            paths,
            staged_environment,
            object_id_length,
            deadline=deadline,
        )
        result_entries = _tree_entries(
            result_tree,
            paths,
            staged_environment,
            object_id_length,
            deadline=deadline,
        )
        if set(base_entries) | set(result_entries) != set(paths):
            raise WorkerError(409, "handoff_not_reproducible", "handoff path inventory does not match its trees")
        _scan_tree_blobs(
            base_entries,
            result_entries,
            staged_environment,
            protected_markers,
            deadline=deadline,
        )
        patch = run_git(
            [
                "diff",
                "--cached",
                "--binary",
                "--full-index",
                "--no-renames",
                "--no-ext-diff",
                "--no-textconv",
                "--src-prefix=a/",
                "--dst-prefix=b/",
                str(identity["base_commit"]),
                "--",
            ],
            stdout_limit=MAX_HANDOFF_PATCH,
            extra_environment=staged_environment,
            status=413,
            code="handoff_too_large",
            message="changes could not be encoded as a bounded handoff",
            overflow_code="handoff_too_large",
            deadline=deadline,
        )
        if len(patch) > MAX_HANDOFF_PATCH:
            raise WorkerError(413, "handoff_too_large", "handoff patch exceeds its byte limit")
        if contains_protected(patch, protected_markers, deadline=deadline):
            raise WorkerError(502, "credential_output_blocked", "handoff patch matched protected credential material")
        verified_environment = _temporary_repository_environment(identity, root / "verified")
        run_git(
            ["read-tree", str(identity["base_commit"])],
            extra_environment=verified_environment,
            deadline=deadline,
        )
        if patch:
            run_git(
                ["apply", "--cached", "--binary", "--whitespace=nowarn", "-"],
                input_bytes=patch,
                extra_environment=verified_environment,
                status=409,
                code="handoff_not_reproducible",
                message="handoff patch does not apply exactly to its base",
                deadline=deadline,
            )
        verified_tree = git_text(
            ["write-tree"],
            extra_environment=verified_environment,
            code="handoff_not_reproducible",
            message="handoff result tree could not be reproduced",
            deadline=deadline,
        )
        if verified_tree != result_tree:
            raise WorkerError(409, "handoff_not_reproducible", "handoff patch produced a different result tree")
    if len(result_tree) != object_id_length or any(character not in "0123456789abcdef" for character in result_tree):
        raise WorkerError(409, "handoff_not_reproducible", "handoff result tree is invalid")
    return patch, paths, result_tree


def capture_git_handoff(
    base_identity: dict[str, object],
    protected_markers: tuple[bytes, ...] = (),
    *,
    deadline: float | None = None,
) -> dict[str, object]:
    identity = dict(base_identity)
    handoff_deadline = time.monotonic() + HANDOFF_TIMEOUT
    if deadline is not None:
        handoff_deadline = min(handoff_deadline, deadline)
    require_request_time(handoff_deadline)
    _assert_repository_identity(identity, deadline=handoff_deadline)
    repository_environment = _repository_environment(identity)
    current = git_text(
        ["rev-parse", "--verify", "HEAD^{commit}"],
        extra_environment=repository_environment,
        code="workspace_history_changed",
        message="workspace history changed during coding",
        deadline=handoff_deadline,
    )
    if current != identity.get("base_commit"):
        raise WorkerError(409, "workspace_history_changed", "workspace history changed during coding")
    _reject_unsupported_repository(
        current,
        extra_environment=repository_environment,
        deadline=handoff_deadline,
    )
    _reject_special_workspace_entries(deadline=handoff_deadline)
    first_patch, first_paths, first_tree = _capture_snapshot(
        identity,
        protected_markers,
        deadline=handoff_deadline,
    )
    second_patch, second_paths, second_tree = _capture_snapshot(
        identity,
        protected_markers,
        deadline=handoff_deadline,
    )
    if first_patch != second_patch or first_paths != second_paths or first_tree != second_tree:
        raise WorkerError(409, "workspace_changed", "workspace changed while the handoff was captured")
    _assert_repository_identity(identity, deadline=handoff_deadline)
    return {
        "schema_version": "steward.git-handoff.v1",
        "object_format": identity["object_format"],
        "base_commit": identity["base_commit"],
        "base_tree": identity["base_tree"],
        "result_tree": first_tree,
        "patch_sha256": "sha256:" + hashlib.sha256(first_patch).hexdigest(),
        "patch_bytes": len(first_patch),
        "patch_base64": base64.b64encode(first_patch).decode("ascii"),
        "changed_paths": list(first_paths),
    }


def _current_head(*, deadline: float | None = None) -> str:
    return git_text(["rev-parse", "--verify", "HEAD^{commit}"], deadline=deadline)


def run_task(engine: str, worker_token: bytes, request: dict[str, object]) -> dict[str, object]:
    request_started = time.monotonic()
    task = str(request["task"])
    mode = str(request["mode"])
    timeout_seconds = int(request["timeout_seconds"])
    version = str(request["schema_version"])
    request_deadline = request_started + timeout_seconds + REQUEST_OVERHEAD_TIMEOUT
    preflight_deadline = min(
        request_started + PREFLIGHT_TIMEOUT,
        request_deadline - POSTFLIGHT_RESERVE,
    )
    base_identity: dict[str, object] | None = None
    if version == "steward.coding-task.v2":
        base_identity = workspace_identity(
            str(request["expected_base_commit"]),
            deadline=preflight_deadline,
        )
        repository_identity = base_identity
    else:
        repository_identity = _standalone_repository_shape(deadline=preflight_deadline)
        _reject_special_workspace_entries(deadline=preflight_deadline)
    before = git_status(deadline=preflight_deadline)
    if before and os.environ.get("STEWARD_ALLOW_DIRTY_WORKSPACE", "NO") != "YES":
        raise WorkerError(409, "workspace_not_clean", "coding worker requires a clean dedicated worktree")
    base_commit = str(base_identity["base_commit"]) if base_identity is not None else None
    environment = clean_environment(engine)
    protected_markers = tuple(
        secret_markers(
            worker_token,
            environment,
            deadline=preflight_deadline,
        )
    )
    command = command_for(engine, task, mode)
    baseline_children = prepare_engine_isolation()
    require_request_time(preflight_deadline)
    engine_deadline = min(
        time.monotonic() + timeout_seconds,
        request_deadline - POSTFLIGHT_RESERVE,
    )
    require_request_time(engine_deadline)
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
    stream_limit = MAX_HANDOFF_STREAM if version == "steward.coding-task.v2" else MAX_STREAM
    readers: list[threading.Thread] = []
    started_readers: list[threading.Thread] = []
    timed_out = False
    try:
        stdout = bytearray()
        stderr = bytearray()
        exceeded = threading.Event()
        readers = [
            threading.Thread(target=drain, args=(process.stdout, stdout, exceeded, stream_limit), daemon=True),
            threading.Thread(target=drain, args=(process.stderr, stderr, exceeded, stream_limit), daemon=True),
        ]
        for reader in readers:
            reader.start()
            started_readers.append(reader)
        while process.poll() is None:
            if exceeded.is_set() or time.monotonic() >= engine_deadline:
                timed_out = time.monotonic() >= engine_deadline
                break
            time.sleep(0.05)
    finally:
        cleanup_deadline = min(
            time.monotonic() + ENGINE_CLEANUP_TIMEOUT,
            request_deadline - HANDOFF_TIMEOUT - RESPONSE_TIMEOUT,
        )
        remaining_cleanup = max(0.0, cleanup_deadline - time.monotonic())
        descendant_budget = min(5.0, remaining_cleanup / 2)
        process_cleanup_deadline = cleanup_deadline - descendant_budget
        try:
            stopped = stop_process(process, deadline=process_cleanup_deadline)
        except Exception:
            stopped = False
        try:
            descendants_stopped = stop_engine_descendants(
                baseline_children,
                deadline=cleanup_deadline,
            )
        except Exception:
            descendants_stopped = False
        readers_alive = True
        try:
            for reader in started_readers:
                remaining = cleanup_deadline - time.monotonic()
                if remaining <= 0:
                    break
                reader.join(timeout=min(2, remaining))
            readers_alive = any(reader.is_alive() for reader in started_readers)
        except Exception:
            readers_alive = True
        streams_closed = False
        if stopped and descendants_stopped and not readers_alive:
            try:
                close_process_streams(process)
                streams_closed = True
            except Exception:
                pass
        if not streams_closed:
            defer_process_stream_close(process, tuple(started_readers))
        if (
            not stopped
            or not descendants_stopped
            or readers_alive
            or not streams_closed
        ):
            raise WorkerError(502, "engine_cleanup_failed", "coding engine descendants did not stop")
    if exceeded.is_set():
        raise WorkerError(
            502,
            "engine_output_too_large",
            f"coding engine output exceeded its {stream_limit >> 10} KiB per-stream limit",
        )
    if timed_out:
        raise WorkerError(504, "engine_timeout", "coding engine exceeded the requested timeout")
    postflight_deadline = min(
        time.monotonic() + HANDOFF_TIMEOUT,
        request_deadline - RESPONSE_TIMEOUT,
    )
    require_request_time(postflight_deadline)
    _assert_repository_identity(repository_identity, deadline=postflight_deadline)
    _reject_special_workspace_entries(deadline=postflight_deadline)
    protected_markers = tuple(
        sorted(
            set(protected_markers).union(
                secret_markers(
                    worker_token,
                    environment,
                    deadline=postflight_deadline,
                )
            ),
            key=len,
            reverse=True,
        )
    )
    combined = bytes(stdout) + b"\x00" + bytes(stderr)
    if contains_protected(combined, protected_markers, deadline=postflight_deadline):
        raise WorkerError(502, "credential_output_blocked", "coding engine output matched protected credential material")
    if base_commit is not None and _current_head(deadline=postflight_deadline) != base_commit:
        raise WorkerError(409, "workspace_history_changed", "coding engine changed workspace history")
    after = git_status(deadline=postflight_deadline)
    if mode == "read" and after != before:
        raise WorkerError(409, "read_mode_modified_workspace", "read-only coding task changed the workspace")
    common: dict[str, object] = {
        "engine": engine,
        "mode": mode,
        "outcome": "completed" if process.returncode == 0 else "failed",
        "exit_code": process.returncode,
        "duration_ms": 0,
        "stdout": bytes(stdout).decode("utf-8", "replace"),
        "stderr": bytes(stderr).decode("utf-8", "replace"),
    }
    if version == "steward.coding-task.v2":
        if base_identity is None:
            raise WorkerError(500, "internal_error", "coding handoff identity is unavailable")
        handoff = capture_git_handoff(
            base_identity,
            protected_markers,
            deadline=postflight_deadline,
        )
        if mode == "read" and handoff["patch_bytes"] != 0:
            raise WorkerError(409, "read_mode_modified_workspace", "read-only coding task changed the workspace")
        common["duration_ms"] = int((time.monotonic() - request_started) * 1000)
        result = {
            "schema_version": "steward.coding-result.v2",
            **common,
            "changed_paths": handoff["changed_paths"],
            "handoff": handoff,
        }
        encoded = json.dumps(result, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode()
        if len(encoded) > MAX_PORTABLE_RESULT:
            raise WorkerError(502, "response_too_large", "coding result exceeds its portable 448 KiB limit")
        require_request_time(request_deadline)
        return result
    changed_paths = _status_changed_paths(after, deadline=postflight_deadline)
    common["duration_ms"] = int((time.monotonic() - request_started) * 1000)
    require_request_time(request_deadline)
    return {
        "schema_version": "steward.coding-result.v1",
        **common,
        "changed_paths": changed_paths,
    }


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "steward-coding-worker/1"

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(RESPONSE_TIMEOUT)

    def do_POST(self) -> None:  # noqa: N802
        try:
            self.authorize()
            if self.path != "/v1/run":
                raise WorkerError(404, "route_not_found", "route is not available")
            request = validate_task_payload(self.read_payload())
            self.server.suspend_engine_ingress()
            try:
                result = run_task(self.server.engine, self.server.worker_token, request)
            except WorkerError as error:
                if error.code in {"engine_cleanup_failed", "worker_cleanup_failed"}:
                    self.server.poison_engine_ingress()
                raise
            finally:
                if not self.server.poisoned:
                    self.server.resume_engine_ingress()
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
    allow_reuse_address = True
    request_queue_size = 4

    def __init__(self, address: tuple[str, int], engine: str, token: bytes) -> None:
        super().__init__(address, Handler)
        self.engine = engine
        self.worker_token = token
        self.accepting = True
        self.poisoned = False

    def server_bind(self) -> None:
        socketserver.TCPServer.server_bind(self)
        self.server_name = str(self.server_address[0])
        self.server_port = int(self.server_address[1])

    def suspend_engine_ingress(self) -> None:
        if self.poisoned or not self.accepting:
            raise WorkerError(
                503,
                "engine_ingress_unavailable",
                "coding worker cannot isolate engine ingress",
            )
        self.accepting = False

    def resume_engine_ingress(self) -> None:
        if self.poisoned or self.accepting:
            raise WorkerError(
                503,
                "engine_ingress_unavailable",
                "coding worker cannot restore engine ingress",
            )
        address = self.server_address
        self.poisoned = True
        replacement = None
        try:
            self.server_close()
            replacement = socket.socket(self.address_family, self.socket_type)
            self.socket = replacement
            self.server_address = address
            self.server_bind()
            self.server_activate()
        except Exception as error:
            if replacement is not None:
                try:
                    replacement.close()
                except OSError:
                    pass
            self.poisoned = True
            raise WorkerError(
                503,
                "engine_ingress_unavailable",
                "coding worker cannot restore engine ingress",
            ) from error
        self.poisoned = False
        self.accepting = True

    def poison_engine_ingress(self) -> None:
        self.poisoned = True
        self.accepting = False


def main() -> int:
    if not sys.platform.startswith("linux"):
        raise RuntimeError("coding worker requires Linux process-containment support")
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
        while not server.poisoned:
            server.handle_request()
    except KeyboardInterrupt:
        return 0
    finally:
        server.server_close()
    return 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RuntimeError as error:
        print(f"coding-worker: {error}", file=sys.stderr)
        raise SystemExit(1)
