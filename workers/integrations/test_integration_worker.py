#!/usr/bin/env python3
"""Adversarial contract tests for the finite managed integration worker."""

from __future__ import annotations

import base64
import contextlib
import http.client
import http.server
import importlib.util
import json
import os
import pathlib
import tempfile
import threading
import unittest
import urllib.parse
from collections.abc import Iterator
from typing import Any

MODULE_PATH = pathlib.Path(__file__).with_name("integration_worker.py")
SPEC = importlib.util.spec_from_file_location("steward_integration_worker", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
worker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(worker)


class BrokerState:
    def __init__(self) -> None:
        self.requests: list[dict[str, Any]] = []
        self.accounts: list[object] = []
        self.files: list[object] = []
        self.next_page_token: str | None = None
        self.connect_link_url = "https://pipedream.com/_static/connect.html?token=one-use-secret&connectLink=true"


class BrokerHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    @property
    def state(self) -> BrokerState:
        return self.server.state  # type: ignore[attr-defined,no-any-return]

    def log_message(self, _format: str, *_arguments: object) -> None:
        return

    def _body(self) -> object | None:
        length = int(self.headers.get("Content-Length", "0"))
        return json.loads(self.rfile.read(length)) if length else None

    def _respond(self, status: int, value: object) -> None:
        raw = json.dumps(value, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _record(self, body: object | None) -> None:
        self.state.requests.append(
            {
                "authorization": self.headers.get("Authorization", ""),
                "body": body,
                "environment": self.headers.get("X-PD-Environment", ""),
                "method": self.command,
                "path": self.path,
            }
        )

    def do_POST(self) -> None:
        body = self._body()
        self._record(body)
        if self.path == "/v1/oauth/token":
            assert isinstance(body, dict)
            scope = str(body["scope"])
            self._respond(200, {"access_token": "broker-token-for-" + scope.replace(" ", "_")})
            return
        if self.path == "/v1/connect/proj_test/tokens":
            self._respond(
                200,
                {
                    "connect_link_url": self.state.connect_link_url,
                    "expires_at": "2026-08-14T12:10:00Z",
                    "token": "must-not-be-returned-separately",
                },
            )
            return
        self._respond(404, {"error": "not found"})

    def do_GET(self) -> None:
        self._record(None)
        if self.path.startswith("/v1/connect/proj_test/accounts?"):
            self._respond(200, {"data": self.state.accounts, "page_info": {"count": len(self.state.accounts)}})
            return
        if self.path.startswith("/v1/connect/proj_test/proxy/"):
            value: dict[str, object] = {"files": self.state.files}
            if self.state.next_page_token is not None:
                value["nextPageToken"] = self.state.next_page_token
            self._respond(200, value)
            return
        self._respond(404, {"error": "not found"})

    def do_DELETE(self) -> None:
        self._record(None)
        if self.path == "/v1/connect/proj_test/accounts/apn_owned123":
            self._respond(200, {})
            return
        self._respond(404, {"error": "not found"})


class BrokerServer(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self) -> None:
        super().__init__(("127.0.0.1", 0), BrokerHandler)
        self.state = BrokerState()


@contextlib.contextmanager
def broker_client() -> Iterator[tuple[Any, BrokerState]]:
    server = BrokerServer()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    previous = os.environ.get("STEWARD_ALLOW_INSECURE_UPSTREAM")
    os.environ["STEWARD_ALLOW_INSECURE_UPSTREAM"] = "YES"
    thread.start()
    try:
        client = worker.PipedreamClient(
            client_id=b"client-id-value",
            client_secret=b"client-secret-value",
            project_id="proj_test",
            environment="development",
            oauth_app_id="oa_test",
            api_origin=f"http://127.0.0.1:{server.server_port}",
        )
        yield client, server.state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        if previous is None:
            os.environ.pop("STEWARD_ALLOW_INSECURE_UPSTREAM", None)
        else:
            os.environ["STEWARD_ALLOW_INSECURE_UPSTREAM"] = previous


def connected_account(*, scopes: list[str] | None = None, identifier: str = "apn_owned123") -> dict[str, object]:
    return {
        "id": identifier,
        "name": "Operations Drive",
        "external_id": "ryu_abcdefghijklmnop",
        "healthy": True,
        "dead": False,
        "app": {"name_slug": "google_drive"},
        "authorized_scopes": scopes or [worker.GOOGLE_DRIVE_SCOPE],
        "created_at": "2026-08-14T12:00:00Z",
        "credentials": {
            "oauth_access_token": "provider-access-secret",
            "oauth_refresh_token": "provider-refresh-secret",
        },
    }


class PipedreamClientTests(unittest.TestCase):
    def test_connect_link_uses_exact_scopes_and_returns_only_one_use_url(self) -> None:
        with broker_client() as (client, state):
            result = client.connect_link("ryu_abcdefghijklmnop")

        self.assertEqual(result["schema_version"], "steward.managed-connect-link.v1")
        link = urllib.parse.urlsplit(str(result["connect_url"]))
        query = urllib.parse.parse_qs(link.query)
        self.assertEqual(query["app"], ["google_drive"])
        self.assertEqual(query["oauthAppId"], ["oa_test"])
        self.assertNotIn("token", result)
        token_request, link_request = state.requests
        self.assertEqual(token_request["body"]["scope"], "connect:tokens:create")
        self.assertEqual(
            link_request["body"],
            {
                "allow_progressive_scopes": False,
                "expires_in": 600,
                "external_user_id": "ryu_abcdefghijklmnop",
                "scope": "connect:accounts:read connect:accounts:write",
            },
        )

    def test_reconcile_normalizes_account_and_never_returns_credentials(self) -> None:
        with broker_client() as (client, state):
            state.accounts = [connected_account()]
            _token, result = client.reconcile("ryu_abcdefghijklmnop")

        encoded = json.dumps(result)
        self.assertEqual(result["status"], "ready")
        self.assertEqual(result["account_id"], "apn_owned123")
        self.assertNotIn("provider-access-secret", encoded)
        self.assertNotIn("provider-refresh-secret", encoded)
        account_request = state.requests[-1]
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(account_request["path"]).query)
        self.assertEqual(query["external_user_id"], ["ryu_abcdefghijklmnop"])
        self.assertEqual(query["app"], ["google_drive"])
        self.assertEqual(query["oauth_app_id"], ["oa_test"])
        self.assertEqual(query["include_credentials"], ["false"])

    def test_reconcile_fails_closed_when_metadata_scope_is_absent(self) -> None:
        with broker_client() as (client, state):
            state.accounts = [connected_account(scopes=["https://www.googleapis.com/auth/drive"])]
            _token, result = client.reconcile("ryu_abcdefghijklmnop")
        self.assertEqual(result["status"], "needs_attention")
        self.assertEqual(result["required_scope"], worker.GOOGLE_DRIVE_SCOPE)

    def test_reconcile_fails_closed_when_broader_drive_scope_is_present(self) -> None:
        with broker_client() as (client, state):
            state.accounts = [
                connected_account(
                    scopes=[worker.GOOGLE_DRIVE_SCOPE, "https://www.googleapis.com/auth/drive"]
                )
            ]
            _token, result = client.reconcile("ryu_abcdefghijklmnop")
        self.assertEqual(result["status"], "needs_attention")

    def test_list_metadata_freezes_target_and_bounds_output(self) -> None:
        with broker_client() as (client, state):
            state.accounts = [connected_account()]
            state.files = [
                {
                    "id": "file-1",
                    "name": "Site plan.pdf",
                    "mimeType": "application/pdf",
                    "modifiedTime": "2026-08-14T11:00:00Z",
                    "size": "1234",
                    "webViewLink": "https://drive.google.com/file/d/file-1/view",
                    "owners": [{"emailAddress": "must-not-leave-steward@example.test"}],
                }
            ]
            state.next_page_token = "opaque-next-token"
            result = client.list_drive_metadata("ryu_abcdefghijklmnop", "apn_owned123")

        self.assertEqual(result["result_count"], 1)
        self.assertTrue(result["has_more"])
        self.assertNotIn("owners", result["files"][0])
        token_request = state.requests[0]
        self.assertEqual(token_request["body"]["scope"], "connect:accounts:read connect:proxy")
        proxy_request = state.requests[-1]
        parsed = urllib.parse.urlsplit(proxy_request["path"])
        encoded_target = parsed.path.rsplit("/", 1)[-1]
        encoded_target += "=" * (-len(encoded_target) % 4)
        target = base64.urlsafe_b64decode(encoded_target).decode()
        self.assertEqual(target, worker.GOOGLE_DRIVE_TARGET)
        self.assertEqual(
            urllib.parse.parse_qs(parsed.query),
            {"account_id": ["apn_owned123"], "external_user_id": ["ryu_abcdefghijklmnop"]},
        )

    def test_list_metadata_rejects_unowned_account_before_proxy(self) -> None:
        with broker_client() as (client, state):
            state.accounts = [connected_account()]
            with self.assertRaisesRegex(worker.WorkerError, "not ready") as caught:
                client.list_drive_metadata("ryu_abcdefghijklmnop", "apn_other123")
        self.assertEqual(caught.exception.status, 409)
        self.assertFalse(any("/proxy/" in request["path"] for request in state.requests))

    def test_revoke_verifies_ownership_then_uses_write_scope(self) -> None:
        with broker_client() as (client, state):
            state.accounts = [connected_account()]
            result = client.revoke("ryu_abcdefghijklmnop", "apn_owned123")
        self.assertTrue(result["revoked"])
        self.assertEqual(state.requests[0]["body"]["scope"], "connect:accounts:read connect:accounts:write")
        self.assertEqual(state.requests[-1]["method"], "DELETE")

    def test_connect_link_rejects_broker_supplied_redirect_origin(self) -> None:
        with broker_client() as (client, state):
            state.connect_link_url = "https://evil.example/connect?token=secret"
            with self.assertRaisesRegex(worker.WorkerError, "unsafe link"):
                client.connect_link("ryu_abcdefghijklmnop")


class StubClient:
    def connect_link(self, user: str) -> dict[str, object]:
        return {"schema_version": "test", "user": user}

    def reconcile(self, user: str) -> tuple[str, dict[str, object]]:
        return "not-returned", {"schema_version": "test", "user": user}

    def list_drive_metadata(self, user: str, account: str) -> dict[str, object]:
        return {"schema_version": "test", "user": user, "account": account}

    def revoke(self, user: str, account: str) -> dict[str, object]:
        return {"schema_version": "test", "user": user, "account": account, "revoked": True}


@contextlib.contextmanager
def integration_server() -> Iterator[int]:
    server = worker.IntegrationServer(("127.0.0.1", 0), b"worker-token-value", StubClient())
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_port
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def call_worker(port: int, path: str, body: bytes, *, token: str = "worker-token-value") -> tuple[int, dict[str, Any], dict[str, str]]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
    try:
        connection.request(
            "POST",
            path,
            body=body,
            headers={
                "Authorization": "Bearer " + token,
                "Content-Length": str(len(body)),
                "Content-Type": "application/json",
            },
        )
        response = connection.getresponse()
        return response.status, json.loads(response.read()), dict(response.headers)
    finally:
        connection.close()


class HTTPContractTests(unittest.TestCase):
    def test_routes_require_worker_auth_and_exact_request_fields(self) -> None:
        with integration_server() as port:
            status, body, _headers = call_worker(
                port,
                "/v1/connections/google-drive/connect-link",
                b'{"external_user_id":"ryu_abcdefghijklmnop"}',
                token="wrong-worker-token",
            )
            self.assertEqual((status, body["error"]["code"]), (401, "unauthorized"))

            status, body, _headers = call_worker(
                port,
                "/v1/connections/google-drive/connect-link",
                b'{"external_user_id":"ryu_abcdefghijklmnop","surprise":true}',
            )
            self.assertEqual((status, body["error"]["code"]), (400, "invalid_request"))

    def test_connect_link_response_is_non_cacheable(self) -> None:
        with integration_server() as port:
            status, body, headers = call_worker(
                port,
                "/v1/connections/google-drive/connect-link",
                b'{"external_user_id":"ryu_abcdefghijklmnop"}',
            )
        self.assertEqual(status, 200)
        self.assertEqual(body["user"], "ryu_abcdefghijklmnop")
        self.assertEqual(headers["Cache-Control"], "no-store")

    def test_invalid_handles_fail_before_client_dispatch(self) -> None:
        with integration_server() as port:
            status, body, _headers = call_worker(
                port,
                "/v1/connections/google-drive/files",
                b'{"account_id":"../../other","external_user_id":"tenant-a"}',
            )
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"], "invalid_external_user")


class SecretFileTests(unittest.TestCase):
    def test_read_secret_rejects_group_readable_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory, "secret")
            path.write_bytes(b"long-enough-secret")
            path.chmod(0o640)
            with self.assertRaisesRegex(RuntimeError, "unsafe"):
                worker.read_secret(str(path), "test secret")

    def test_read_secret_accepts_owner_only_regular_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory, "secret")
            path.write_bytes(b"long-enough-secret")
            path.chmod(0o600)
            self.assertEqual(worker.read_secret(str(path), "test secret"), b"long-enough-secret")


if __name__ == "__main__":
    unittest.main()
