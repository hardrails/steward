#!/usr/bin/env python3
"""Authenticated deterministic work fixture for Steward connector qualification."""

from __future__ import annotations

import hashlib
import http.server
import json
import os
import pathlib
import socket
import stat
import sys
import threading
from typing import Any

ADDRESS = ("127.0.0.1", 18082)
MAX_BODY = 4096
REQUEST = {"input": "steward-hermes-connector-work-v1"}
REQUEST_BODY = json.dumps(REQUEST, separators=(",", ":"), sort_keys=True).encode()
RESULT_DOMAIN = b"steward.connector-work.result.v1\x00"
RESULT = {
    "result": "sha256:" + hashlib.sha256(RESULT_DOMAIN + REQUEST_BODY).hexdigest(),
    "schema_version": "steward.connector-work.result.v1",
}
RESULT_BODY = json.dumps(RESULT, separators=(",", ":"), sort_keys=True).encode()

_token = ""
_authenticated_calls = 0
_state_lock = threading.Lock()


def read_token(path_text: str) -> str:
    path = pathlib.Path(path_text)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) & 0o077 or not 0 < info.st_size <= 16384:
        raise SystemExit("fixture-connector: credential must be a bounded owner-only regular file")
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
        raise SystemExit("fixture-connector: credential changed while being read")
    try:
        value = bytes(data).decode("utf-8").strip()
    except UnicodeDecodeError as error:
        raise SystemExit("fixture-connector: credential is not UTF-8") from error
    if not value or "\n" in value or "\r" in value:
        raise SystemExit("fixture-connector: credential must contain one non-empty line")
    return value


class BoundedServer(http.server.HTTPServer):
    request_queue_size = 4

    def get_request(self) -> tuple[socket.socket, Any]:
        connection, address = super().get_request()
        connection.settimeout(10)
        return connection, address


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "steward-connector-fixture/1"

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/health":
            self._json(200, {"status": "ok"})
            return
        if self.path == "/status":
            with _state_lock:
                calls = _authenticated_calls
            self._json(
                200,
                {
                    "authenticated_calls": calls,
                    "request_sha256": hashlib.sha256(REQUEST_BODY).hexdigest(),
                    "status": "ok",
                },
            )
            return
        self._json(404, {"error": "not_found"})

    def do_POST(self) -> None:  # noqa: N802
        global _authenticated_calls
        if self.path != "/v1/work/execute" or self.headers.get("X-Steward-Task-ID") is not None:
            self._json(404, {"error": "not_found"})
            return
        if self.headers.get("Authorization") != f"Bearer {_token}":
            self._json(401, {"error": "unauthorized"})
            return
        if self.headers.get("Transfer-Encoding") is not None or self.headers.get("Expect") is not None:
            self._json(400, {"error": "invalid_transport"})
            return
        lengths = self.headers.get_all("Content-Length", [])
        if len(lengths) != 1 or not lengths[0].isdigit():
            self._json(411, {"error": "content_length_required"})
            return
        length = int(lengths[0])
        if length <= 0 or length > MAX_BODY:
            self._json(413, {"error": "request_too_large"})
            return
        if self.headers.get("Content-Type") != "application/json":
            self._json(415, {"error": "content_type_required"})
            return
        body = self.rfile.read(length)
        if body != REQUEST_BODY:
            self._json(422, {"error": "invalid_work"})
            return
        with _state_lock:
            _authenticated_calls += 1
        self._send(200, RESULT_BODY)

    def _json(self, status: int, payload: object) -> None:
        self._send(status, json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())

    def _send(self, status: int, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *_args: Any) -> None:
        return


def main() -> int:
    global _token
    if len(sys.argv) != 2:
        print("usage: fixture_connector.py CREDENTIAL_FILE", file=sys.stderr)
        return 2
    _token = read_token(sys.argv[1])
    server = BoundedServer(ADDRESS, Handler)
    try:
        server.serve_forever()
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
