#!/usr/bin/env python3
"""Finite managed-auth broker for reviewed Steward integration operations."""

from __future__ import annotations

import base64
import hmac
import http.client
import http.server
import json
import os
import pathlib
import re
import socket
import socketserver
import ssl
import stat
import sys
import threading
import urllib.parse
from collections.abc import Mapping

MAX_REQUEST = 16 << 10
MAX_UPSTREAM = 2 << 20
MAX_RESPONSE = 1 << 20
UPSTREAM_TIMEOUT_SECONDS = 30
CONNECT_TOKEN_SECONDS = 600
MAX_CONCURRENCY = 8
MAX_HEALTH_CONCURRENCY = 2
CLIENT_READ_TIMEOUT_SECONDS = 5
ACCOUNT_PAGE_SIZE = 100
MAX_ACCOUNT_RESULTS = 1000
PIPEDREAM_API_ORIGIN = "https://api.pipedream.com"
GOOGLE_DRIVE_APP = "google_drive"
GOOGLE_DRIVE_SCOPE = "https://www.googleapis.com/auth/drive.metadata.readonly"
GOOGLE_DRIVE_FIELDS = "nextPageToken,files(id,name,mimeType,modifiedTime,size,webViewLink)"
GOOGLE_DRIVE_TARGET = (
    "https://www.googleapis.com/drive/v3/files?"
    + urllib.parse.urlencode(
        {
            "fields": GOOGLE_DRIVE_FIELDS,
            "orderBy": "modifiedTime desc",
            "pageSize": "50",
        }
    )
)
EXTERNAL_USER_RE = re.compile(r"^ryu_[A-Za-z0-9_-]{16,120}$")
ACCOUNT_RE = re.compile(r"^apn_[A-Za-z0-9]+$")
PROJECT_RE = re.compile(r"^proj_[A-Za-z0-9]+$")
OAUTH_APP_RE = re.compile(r"^oa_[A-Za-z0-9]+$")


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
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) & 0o077
            or before.st_nlink != 1
            or not 12 <= before.st_size <= 4096
        ):
            raise RuntimeError(f"{label} file is unsafe")
        value = os.read(descriptor, 4097)
        after = os.fstat(descriptor)
        named = os.stat(path, follow_symlinks=False)
        identity = lambda item: (
            item.st_dev,
            item.st_ino,
            item.st_size,
            item.st_mtime_ns,
            item.st_ctime_ns,
        )
        if len(value) != before.st_size or identity(before) != identity(after) or identity(after) != identity(named):
            raise RuntimeError(f"{label} file changed while being read")
    finally:
        os.close(descriptor)
    value = value.rstrip(b"\n")
    if not 12 <= len(value) <= 4096 or any(byte < 0x21 or byte > 0x7E for byte in value):
        raise RuntimeError(f"{label} value is invalid")
    return value


def exact_object(value: object, fields: frozenset[str]) -> dict[str, object]:
    if not isinstance(value, dict) or frozenset(value) != fields:
        raise WorkerError(400, "invalid_request", "request fields do not match the operation contract")
    if any(not isinstance(key, str) for key in value):
        raise WorkerError(400, "invalid_request", "request field names must be strings")
    return value


def external_user(value: object) -> str:
    if not isinstance(value, str) or not EXTERNAL_USER_RE.fullmatch(value):
        raise WorkerError(400, "invalid_external_user", "external user handle is invalid")
    return value


def account_id(value: object) -> str:
    if not isinstance(value, str) or not ACCOUNT_RE.fullmatch(value):
        raise WorkerError(400, "invalid_account", "managed account handle is invalid")
    return value


class PipedreamClient:
    def __init__(
        self,
        *,
        client_id: bytes,
        client_secret: bytes,
        project_id: str,
        environment: str,
        oauth_app_id: str,
        api_origin: str = PIPEDREAM_API_ORIGIN,
    ) -> None:
        if not PROJECT_RE.fullmatch(project_id):
            raise RuntimeError("Pipedream project ID is invalid")
        if environment not in {"development", "production"}:
            raise RuntimeError("Pipedream environment is invalid")
        if not OAUTH_APP_RE.fullmatch(oauth_app_id):
            raise RuntimeError("Google Drive OAuth app ID is invalid")
        parsed = urllib.parse.urlsplit(api_origin)
        allow_http = os.environ.get("STEWARD_ALLOW_INSECURE_UPSTREAM", "NO") == "YES"
        if (
            parsed.scheme not in ({"http", "https"} if allow_http else {"https"})
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.path
            or parsed.query
            or parsed.fragment
        ):
            raise RuntimeError("Pipedream API origin is invalid")
        self.client_id = client_id
        self.client_secret = client_secret
        self.project_id = project_id
        self.environment = environment
        self.oauth_app_id = oauth_app_id
        self.origin = parsed

    def _request(
        self,
        method: str,
        path: str,
        *,
        payload: object | None = None,
        token: str | None = None,
    ) -> object:
        body = None if payload is None else json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
        headers = {
            "Accept": "application/json",
            "Accept-Encoding": "identity",
            "User-Agent": "steward-integration-worker/1",
        }
        if body is not None:
            headers["Content-Type"] = "application/json"
            headers["Content-Length"] = str(len(body))
        if token is not None:
            headers["Authorization"] = "Bearer " + token
            headers["X-PD-Environment"] = self.environment
        connection_type = http.client.HTTPSConnection if self.origin.scheme == "https" else http.client.HTTPConnection
        connection = connection_type(
            self.origin.hostname,
            self.origin.port,
            timeout=UPSTREAM_TIMEOUT_SECONDS,
            **({"context": ssl.create_default_context()} if self.origin.scheme == "https" else {}),
        )
        try:
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            raw = response.read(MAX_UPSTREAM + 1)
            if len(raw) > MAX_UPSTREAM:
                raise WorkerError(502, "broker_response_too_large", "managed-auth broker response exceeded 2 MiB")
            if response.status < 200 or response.status >= 300:
                code = "broker_rate_limited" if response.status == 429 else "broker_rejected"
                status = 503 if response.status == 429 or response.status >= 500 else 502
                raise WorkerError(status, code, f"managed-auth broker returned HTTP {response.status}")
            if not raw:
                return {}
            if response.headers.get_content_type() != "application/json":
                raise WorkerError(502, "invalid_broker_response", "managed-auth broker returned a non-JSON response")
            try:
                return json.loads(raw)
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                raise WorkerError(502, "invalid_broker_response", "managed-auth broker returned invalid JSON") from error
        except WorkerError:
            raise
        except (OSError, TimeoutError, http.client.HTTPException) as error:
            raise WorkerError(503, "broker_unavailable", "managed-auth broker is unavailable") from error
        finally:
            connection.close()

    def access_token(self, scope: str) -> str:
        result = self._request(
            "POST",
            "/v1/oauth/token",
            payload={
                "client_id": self.client_id.decode("ascii"),
                "client_secret": self.client_secret.decode("ascii"),
                "grant_type": "client_credentials",
                "scope": scope,
            },
        )
        if not isinstance(result, dict):
            raise WorkerError(502, "invalid_broker_response", "managed-auth broker token response is invalid")
        token = result.get("access_token")
        if (
            not isinstance(token, str)
            or not 16 <= len(token) <= 8192
            or any(ord(char) < 0x21 or ord(char) > 0x7E for char in token)
        ):
            raise WorkerError(502, "invalid_broker_response", "managed-auth broker token response is invalid")
        return token

    def connect_link(self, user: str) -> dict[str, object]:
        token = self.access_token("connect:tokens:create")
        result = self._request(
            "POST",
            f"/v1/connect/{self.project_id}/tokens",
            token=token,
            payload={
                "allow_progressive_scopes": False,
                "expires_in": CONNECT_TOKEN_SECONDS,
                "external_user_id": user,
                "scope": "connect:accounts:read connect:accounts:write",
            },
        )
        if not isinstance(result, dict):
            raise WorkerError(502, "invalid_broker_response", "managed-auth broker link response is invalid")
        raw_link = result.get("connect_link_url")
        expires_at = result.get("expires_at")
        if (
            not isinstance(raw_link, str)
            or not isinstance(expires_at, str)
            or not 20 <= len(expires_at) <= 64
            or not expires_at.endswith("Z")
        ):
            raise WorkerError(502, "invalid_broker_response", "managed-auth broker link response is invalid")
        parsed = urllib.parse.urlsplit(raw_link)
        if (
            parsed.scheme != "https"
            or parsed.hostname != "pipedream.com"
            or parsed.username
            or parsed.password
            or parsed.path != "/_static/connect.html"
            or parsed.fragment
            or len(raw_link) > 16384
        ):
            raise WorkerError(502, "invalid_broker_response", "managed-auth broker returned an unsafe link")
        query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        if any(key in {"app", "oauthAppId"} for key, _value in query):
            raise WorkerError(502, "invalid_broker_response", "managed-auth broker returned an ambiguous link")
        query.extend((("app", GOOGLE_DRIVE_APP), ("oauthAppId", self.oauth_app_id)))
        link = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urllib.parse.urlencode(query), ""))
        return {
            "schema_version": "steward.managed-connect-link.v1",
            "integration": "google-drive",
            "connect_url": link,
            "expires_at": expires_at,
        }

    def _accounts(self, user: str, scope: str) -> tuple[str, list[object]]:
        token = self.access_token(scope)
        accounts: list[object] = []
        after: str | None = None
        seen_cursors: set[str] = set()
        expected_total: int | None = None
        while len(accounts) < MAX_ACCOUNT_RESULTS:
            parameters = {
                "app": GOOGLE_DRIVE_APP,
                "external_user_id": user,
                "include_credentials": "false",
                "limit": str(ACCOUNT_PAGE_SIZE),
                "oauth_app_id": self.oauth_app_id,
            }
            if after is not None:
                parameters["after"] = after
            query = urllib.parse.urlencode(parameters)
            result = self._request(
                "GET",
                f"/v1/connect/{self.project_id}/accounts?{query}",
                token=token,
            )
            data = result.get("data") if isinstance(result, dict) else None
            page_info = result.get("page_info") if isinstance(result, dict) else None
            if not isinstance(data, list) or not isinstance(page_info, dict):
                raise WorkerError(502, "invalid_broker_response", "managed-auth broker account response is invalid")
            count = page_info.get("count")
            total = page_info.get("total_count")
            if (
                not isinstance(count, int)
                or isinstance(count, bool)
                or count != len(data)
                or not isinstance(total, int)
                or isinstance(total, bool)
                or total < len(accounts) + len(data)
            ):
                raise WorkerError(502, "invalid_broker_response", "managed-auth broker pagination is invalid")
            if total > MAX_ACCOUNT_RESULTS:
                raise WorkerError(502, "broker_result_limit", "managed-auth broker account set exceeds supported bound")
            if expected_total is None:
                expected_total = total
            elif total != expected_total:
                raise WorkerError(502, "invalid_broker_response", "managed-auth broker pagination changed during traversal")
            accounts.extend(data)
            if len(accounts) == total:
                return token, accounts
            cursor = page_info.get("end_cursor")
            if (
                not isinstance(cursor, str)
                or not 1 <= len(cursor) <= 1024
                or any(ord(char) < 0x21 or ord(char) > 0x7E for char in cursor)
                or cursor in seen_cursors
            ):
                raise WorkerError(502, "invalid_broker_response", "managed-auth broker pagination cursor is invalid")
            seen_cursors.add(cursor)
            after = cursor
        raise WorkerError(502, "broker_result_limit", "managed-auth broker account set exceeds supported bound")

    @staticmethod
    def _safe_account(value: object, user: str) -> dict[str, object] | None:
        if not isinstance(value, dict):
            return None
        identifier = value.get("id")
        external_id = value.get("external_id")
        app = value.get("app")
        scopes = value.get("authorized_scopes")
        if (
            not isinstance(identifier, str)
            or not ACCOUNT_RE.fullmatch(identifier)
            or external_id != user
            or not isinstance(app, dict)
            or app.get("name_slug") != GOOGLE_DRIVE_APP
            or not isinstance(scopes, list)
            or any(not isinstance(scope, str) for scope in scopes)
        ):
            return None
        healthy = value.get("healthy") is True and value.get("dead") is not True and not value.get("error")
        return {
            "account_id": identifier,
            "account_name": value.get("name") if isinstance(value.get("name"), str) else "Google Drive",
            "authorized_scopes": sorted(set(scopes)),
            "created_at": value.get("created_at") if isinstance(value.get("created_at"), str) else "",
            "healthy": healthy,
        }

    def reconcile(self, user: str, scope: str = "connect:accounts:read") -> tuple[str, dict[str, object]]:
        token, raw_accounts = self._accounts(user, scope)
        accounts = [safe for item in raw_accounts if (safe := self._safe_account(item, user)) is not None]
        accounts.sort(key=lambda item: (str(item["created_at"]), str(item["account_id"])), reverse=True)
        selected = next((item for item in accounts if self._account_ready(item)), None)
        if selected is None:
            selected = next((item for item in accounts if item["healthy"]), accounts[0] if accounts else None)
        if selected is None:
            return token, {
                "schema_version": "steward.managed-connection.v1",
                "integration": "google-drive",
                "status": "not_connected",
            }
        return token, {
            "schema_version": "steward.managed-connection.v1",
            "integration": "google-drive",
            "status": "ready" if self._account_ready(selected) else "needs_attention",
            "account_id": selected["account_id"],
            "account_name": selected["account_name"],
            "authorized_scopes": selected["authorized_scopes"],
            "required_scope": GOOGLE_DRIVE_SCOPE,
            "healthy": selected["healthy"],
        }

    @staticmethod
    def _account_ready(account: Mapping[str, object]) -> bool:
        scopes = account.get("authorized_scopes", [])
        drive_scopes = {
            scope
            for scope in scopes
            if isinstance(scope, str) and scope.startswith("https://www.googleapis.com/auth/drive")
        }
        return account.get("healthy") is True and drive_scopes == {GOOGLE_DRIVE_SCOPE}

    def _owned_account(self, user: str, requested_account: str, scope: str) -> tuple[str, dict[str, object]]:
        token = self.access_token(scope)
        query = urllib.parse.urlencode({"include_credentials": "false"})
        value = self._request(
            "GET",
            f"/v1/connect/{self.project_id}/accounts/{urllib.parse.quote(requested_account, safe='')}?{query}",
            token=token,
        )
        account = self._safe_account(value, user)
        if account is not None and account["account_id"] == requested_account:
            return token, account
        raise WorkerError(404, "connection_not_found", "managed connection was not found")

    def list_drive_metadata(self, user: str, requested_account: str) -> dict[str, object]:
        token, connection = self._owned_account(user, requested_account, "connect:accounts:read connect:proxy")
        if not self._account_ready(connection):
            raise WorkerError(409, "connection_not_ready", "Google Drive connection is not ready for this app")
        encoded_target = base64.urlsafe_b64encode(GOOGLE_DRIVE_TARGET.encode()).decode().rstrip("=")
        query = urllib.parse.urlencode({"account_id": requested_account, "external_user_id": user})
        result = self._request(
            "GET",
            f"/v1/connect/{self.project_id}/proxy/{encoded_target}?{query}",
            token=token,
        )
        if not isinstance(result, dict) or not isinstance(result.get("files", []), list):
            raise WorkerError(502, "invalid_provider_response", "Google Drive returned an invalid metadata result")
        raw_files = result.get("files", [])
        if len(raw_files) > 50:
            raise WorkerError(502, "invalid_provider_response", "Google Drive exceeded the metadata result bound")
        files: list[dict[str, str]] = []
        allowed = ("id", "mimeType", "modifiedTime", "name", "size", "webViewLink")
        for item in raw_files:
            if not isinstance(item, Mapping):
                raise WorkerError(502, "invalid_provider_response", "Google Drive returned invalid file metadata")
            normalized: dict[str, str] = {}
            for field in allowed:
                value = item.get(field)
                if value is None:
                    continue
                if not isinstance(value, str) or len(value.encode()) > 4096:
                    raise WorkerError(502, "invalid_provider_response", "Google Drive returned invalid file metadata")
                normalized[field] = value
            if "id" not in normalized or "name" not in normalized or "mimeType" not in normalized:
                raise WorkerError(502, "invalid_provider_response", "Google Drive omitted required file metadata")
            files.append(normalized)
        next_token = result.get("nextPageToken")
        if next_token is not None and (not isinstance(next_token, str) or len(next_token) > 4096):
            raise WorkerError(502, "invalid_provider_response", "Google Drive returned an invalid page token")
        return {
            "schema_version": "steward.google-drive-metadata.v1",
            "integration": "google-drive",
            "files": files,
            "result_count": len(files),
            "has_more": bool(next_token),
        }

    def revoke(self, user: str, requested_account: str) -> dict[str, object]:
        token, _connection = self._owned_account(
            user, requested_account, "connect:accounts:read connect:accounts:write"
        )
        self._request(
            "DELETE",
            f"/v1/connect/{self.project_id}/accounts/{urllib.parse.quote(requested_account, safe='')}",
            token=token,
        )
        return {
            "schema_version": "steward.managed-connection-revocation.v1",
            "integration": "google-drive",
            "account_id": requested_account,
            "revoked": True,
        }


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "steward-integration-worker"
    protocol_version = "HTTP/1.1"

    def log_message(self, _format: str, *_arguments: object) -> None:
        return

    @property
    def worker(self) -> "IntegrationServer":
        return self.server  # type: ignore[return-value]

    def _json(self, status: int, value: object) -> None:
        raw = json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
        if len(raw) > MAX_RESPONSE:
            status = 500
            raw = b'{"error":{"code":"response_too_large","message":"worker response exceeded 1 MiB"}}'
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(raw)

    def _authorized(self) -> bool:
        expected = b"Bearer " + self.worker.worker_token
        supplied = self.headers.get("Authorization", "").encode("utf-8", "surrogateescape")
        return len(supplied) == len(expected) and hmac.compare_digest(supplied, expected)

    def do_GET(self) -> None:
        self._json(404, {"error": {"code": "not_found", "message": "route not found"}})

    def do_POST(self) -> None:
        if not self._authorized():
            self._json(401, {"error": {"code": "unauthorized", "message": "worker credential is required"}})
            return
        try:
            length = int(self.headers.get("Content-Length", "-1"))
        except ValueError:
            length = -1
        if length < 2 or length > MAX_REQUEST or self.headers.get("Content-Type", "").split(";", 1)[0] != "application/json":
            self._json(400, {"error": {"code": "invalid_request", "message": "bounded JSON body is required"}})
            return
        raw = self.rfile.read(length)
        if len(raw) != length:
            self._json(400, {"error": {"code": "invalid_request", "message": "request body is incomplete"}})
            return
        self.worker.request_parsed(self.request)
        try:
            value = json.loads(raw)
            if self.path == "/v1/connections/google-drive/connect-link":
                body = exact_object(value, frozenset({"external_user_id"}))
                result = self.worker.client.connect_link(external_user(body["external_user_id"]))
            elif self.path == "/v1/connections/google-drive/reconcile":
                body = exact_object(value, frozenset({"external_user_id"}))
                _token, result = self.worker.client.reconcile(external_user(body["external_user_id"]))
            elif self.path == "/v1/connections/google-drive/files":
                body = exact_object(value, frozenset({"account_id", "external_user_id"}))
                result = self.worker.client.list_drive_metadata(
                    external_user(body["external_user_id"]), account_id(body["account_id"])
                )
            elif self.path == "/v1/connections/google-drive/revoke":
                body = exact_object(value, frozenset({"account_id", "external_user_id"}))
                result = self.worker.client.revoke(
                    external_user(body["external_user_id"]), account_id(body["account_id"])
                )
            else:
                raise WorkerError(404, "not_found", "route not found")
            self._json(200, result)
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._json(400, {"error": {"code": "invalid_json", "message": "request is not valid JSON"}})
        except WorkerError as error:
            self._json(error.status, {"error": {"code": error.code, "message": error.message}})


class IntegrationServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 16

    def __init__(
        self,
        address: tuple[str, int],
        token: bytes,
        client: PipedreamClient,
        *,
        client_read_timeout: float = CLIENT_READ_TIMEOUT_SECONDS,
    ) -> None:
        super().__init__(address, Handler)
        self.worker_token = token
        self.client = client
        self.client_read_timeout = client_read_timeout
        self._concurrency = threading.BoundedSemaphore(MAX_CONCURRENCY)
        self._deadline_lock = threading.Lock()
        self._deadlines: dict[int, threading.Timer] = {}

    def handle_error(self, _request: object, _client_address: object) -> None:
        return

    @staticmethod
    def _expire_request(request: object) -> None:
        try:
            request.shutdown(socket.SHUT_RDWR)  # type: ignore[attr-defined]
        except OSError:
            return

    def _cancel_deadline(self, request: object) -> None:
        with self._deadline_lock:
            timer = self._deadlines.pop(id(request), None)
        if timer is not None:
            timer.cancel()

    def request_parsed(self, request: object) -> None:
        self._cancel_deadline(request)

    def process_request(self, request: object, client_address: object) -> None:
        request.settimeout(self.client_read_timeout)  # type: ignore[attr-defined]
        if not self._concurrency.acquire(blocking=False):
            self.shutdown_request(request)  # type: ignore[arg-type]
            return
        timer = threading.Timer(self.client_read_timeout, self._expire_request, args=(request,))
        timer.daemon = True
        with self._deadline_lock:
            self._deadlines[id(request)] = timer
        timer.start()
        try:
            super().process_request(request, client_address)  # type: ignore[arg-type]
        except BaseException:
            self._cancel_deadline(request)
            self._concurrency.release()
            raise

    def process_request_thread(self, request: object, client_address: object) -> None:
        try:
            super().process_request_thread(request, client_address)  # type: ignore[arg-type]
        finally:
            self._cancel_deadline(request)
            self._concurrency.release()


class HealthHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        body = b'{"schema_version":"steward.integration-health.v1","status":"ready"}'
        response = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/json\r\n"
            + f"Content-Length: {len(body)}\r\n".encode("ascii")
            + b"Cache-Control: no-store\r\n"
            b"X-Content-Type-Options: nosniff\r\n"
            b"Connection: close\r\n\r\n"
            + body
        )
        self.request.settimeout(CLIENT_READ_TIMEOUT_SECONDS)
        self.request.sendall(response)


class HealthServer(socketserver.TCPServer):
    allow_reuse_address = True
    request_queue_size = MAX_HEALTH_CONCURRENCY


def main() -> int:
    worker_token = read_secret(os.environ.get("STEWARD_WORKER_TOKEN_FILE", ""), "worker token")
    client_id = read_secret(os.environ.get("STEWARD_PIPEDREAM_CLIENT_ID_FILE", ""), "Pipedream client ID")
    client_secret = read_secret(
        os.environ.get("STEWARD_PIPEDREAM_CLIENT_SECRET_FILE", ""), "Pipedream client secret"
    )
    client = PipedreamClient(
        client_id=client_id,
        client_secret=client_secret,
        project_id=os.environ.get("STEWARD_PIPEDREAM_PROJECT_ID", ""),
        environment=os.environ.get("STEWARD_PIPEDREAM_ENVIRONMENT", ""),
        oauth_app_id=os.environ.get("STEWARD_GOOGLE_DRIVE_OAUTH_APP_ID", ""),
        api_origin=os.environ.get("STEWARD_PIPEDREAM_API_ORIGIN", PIPEDREAM_API_ORIGIN),
    )
    server = IntegrationServer(("0.0.0.0", 8080), worker_token, client)
    health_server = HealthServer(("0.0.0.0", 8081), HealthHandler)
    health_thread = threading.Thread(
        target=health_server.serve_forever,
        kwargs={"poll_interval": 0.25},
        daemon=True,
        name="steward-integration-health",
    )
    health_thread.start()
    try:
        server.serve_forever(poll_interval=0.25)
    finally:
        health_server.shutdown()
        health_server.server_close()
        health_thread.join(timeout=2)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError) as error:
        print(f"steward-integration-worker: {error}", file=sys.stderr)
        raise SystemExit(1)
