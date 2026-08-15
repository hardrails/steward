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
import socket
import tempfile
import threading
import time
import unittest
import urllib.parse
from collections.abc import Iterator
from typing import Any
from unittest import mock

MODULE_PATH = pathlib.Path(__file__).with_name("integration_worker.py")
SPEC = importlib.util.spec_from_file_location("steward_integration_worker", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
worker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(worker)


class BrokerState:
    def __init__(self) -> None:
        self.requests: list[dict[str, Any]] = []
        self.accounts: list[object] = []
        self.account_pages: list[list[object]] | None = None
        self.files: list[object] = []
        self.file_details: dict[str, object] = {}
        self.file_contents: dict[str, bytes] = {}
        self.next_page_token: str | None = None
        self.gmail_messages: list[object] = []
        self.gmail_message_details: dict[str, object] = {}
        self.gmail_next_page_token: str | None = None
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

    def _respond_raw(self, status: int, value: bytes, media_type: str = "text/plain") -> None:
        self.send_response(status)
        self.send_header("Content-Type", media_type)
        self.send_header("Content-Length", str(len(value)))
        self.end_headers()
        self.wfile.write(value)

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
            pages = self.state.account_pages or [self.state.accounts]
            query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
            after = query.get("after", [None])[0]
            page_index = 0 if after is None else int(str(after).removeprefix("cursor-")) + 1
            page = pages[page_index]
            page_info: dict[str, object] = {
                "count": len(page),
                "total_count": sum(len(item) for item in pages),
            }
            if page_index + 1 < len(pages):
                page_info["end_cursor"] = f"cursor-{page_index}"
            self._respond(200, {"data": page, "page_info": page_info})
            return
        if self.path.startswith("/v1/connect/proj_test/accounts/"):
            account = next(
                (
                    value
                    for value in self.state.accounts
                    if isinstance(value, dict)
                    and self.path.split("?", 1)[0].endswith("/" + str(value.get("id")))
                ),
                None,
            )
            self._respond(200, account if account is not None else {"error": "not found"})
            return
        if self.path.startswith("/v1/connect/proj_test/proxy/"):
            parsed = urllib.parse.urlsplit(self.path)
            encoded_target = parsed.path.rsplit("/", 1)[-1]
            encoded_target += "=" * (-len(encoded_target) % 4)
            target = urllib.parse.urlsplit(base64.urlsafe_b64decode(encoded_target).decode())
            target_parts = target.path.split("/")
            if target.hostname == "gmail.googleapis.com":
                if target.path == "/gmail/v1/users/me/messages":
                    value: dict[str, object] = {"messages": self.state.gmail_messages}
                    if self.state.gmail_next_page_token is not None:
                        value["nextPageToken"] = self.state.gmail_next_page_token
                    self._respond(200, value)
                    return
                message_id = target_parts[-1]
                detail = self.state.gmail_message_details.get(message_id)
                self._respond(200 if detail is not None else 404, detail or {"error": "not found"})
                return
            if len(target_parts) >= 6 and target_parts[-1] == "export":
                file_id = target_parts[-2]
                content = self.state.file_contents.get(file_id)
                if content is None:
                    self._respond(404, {"error": "not found"})
                else:
                    self._respond_raw(200, content)
                return
            if len(target_parts) >= 5 and target_parts[-1] != "files":
                file_id = target_parts[-1]
                target_query = urllib.parse.parse_qs(target.query)
                if target_query.get("alt") == ["media"]:
                    content = self.state.file_contents.get(file_id)
                    if content is None:
                        self._respond(404, {"error": "not found"})
                    else:
                        self._respond_raw(200, content)
                    return
                detail = self.state.file_details.get(file_id)
                self._respond(200 if detail is not None else 404, detail or {"error": "not found"})
                return
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
            gmail_oauth_app_id="oa_gmailtest",
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


def connected_gmail_account(
    *,
    scopes: list[str] | None = None,
    identifier: str = "apn_owned123",
) -> dict[str, object]:
    value = connected_account(scopes=scopes or [worker.GMAIL_SCOPE], identifier=identifier)
    value["name"] = "Operations Inbox"
    value["app"] = {"name_slug": "gmail"}
    return value


def gmail_message(
    message_id: str,
    *,
    body: str = "Please prepare the renewal summary by Friday.",
) -> dict[str, object]:
    encoded = base64.urlsafe_b64encode(body.encode()).decode().rstrip("=")
    return {
        "id": message_id,
        "threadId": "thread_" + message_id,
        "labelIds": ["INBOX", "UNREAD"],
        "snippet": "Please prepare the renewal summary…",
        "internalDate": "1786723200000",
        "payload": {
            "mimeType": "multipart/alternative",
            "headers": [
                {"name": "From", "value": "Customer <customer@example.com>"},
                {"name": "To", "value": "ops@example.com"},
                {"name": "Subject", "value": "Renewal next steps"},
                {"name": "Date", "value": "Fri, 14 Aug 2026 12:00:00 -0700"},
            ],
            "body": {"size": 0},
            "parts": [
                {
                    "mimeType": "text/plain",
                    "headers": [],
                    "body": {"data": encoded, "size": len(body.encode())},
                }
            ],
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

    def test_gmail_connect_and_reconcile_are_profile_scoped(self) -> None:
        with broker_client() as (client, state):
            link = client.connect_link("ryu_abcdefghijklmnop", "gmail")
            state.accounts = [connected_gmail_account()]
            _token, connection = client.reconcile(
                "ryu_abcdefghijklmnop",
                integration="gmail",
            )

        query = urllib.parse.parse_qs(
            urllib.parse.urlsplit(str(link["connect_url"])).query
        )
        self.assertEqual(link["integration"], "gmail")
        self.assertEqual(query["app"], ["gmail"])
        self.assertEqual(query["oauthAppId"], ["oa_gmailtest"])
        self.assertEqual(connection["status"], "ready")
        self.assertEqual(connection["required_scope"], worker.GMAIL_SCOPE)
        account_request = next(
            request for request in state.requests if "/accounts?" in request["path"]
        )
        account_query = urllib.parse.parse_qs(
            urllib.parse.urlsplit(account_request["path"]).query
        )
        self.assertEqual(account_query["app"], ["gmail"])
        self.assertEqual(account_query["oauth_app_id"], ["oa_gmailtest"])

    def test_unconfigured_gmail_fails_without_contacting_broker(self) -> None:
        with broker_client() as (client, state):
            client.oauth_app_ids["gmail"] = ""
            with self.assertRaisesRegex(worker.WorkerError, "not configured"):
                client.connect_link("ryu_abcdefghijklmnop", "gmail")
        self.assertEqual(state.requests, [])

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

    def test_reconcile_fails_closed_when_readonly_scope_is_absent(self) -> None:
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

    def test_reconcile_prefers_ready_account_over_newer_over_scoped_account(self) -> None:
        with broker_client() as (client, state):
            ready = connected_account()
            ready["created_at"] = "2026-08-13T00:00:00Z"
            broader = connected_account(
                identifier="apn_broader123",
                scopes=[worker.GOOGLE_DRIVE_SCOPE, "https://www.googleapis.com/auth/drive"],
            )
            broader["created_at"] = "2026-08-14T00:00:00Z"
            state.accounts = [broader, ready]
            _token, result = client.reconcile("ryu_abcdefghijklmnop")
        self.assertEqual(result["status"], "ready")
        self.assertEqual(result["account_id"], "apn_owned123")

    def test_reconcile_follows_all_account_pages(self) -> None:
        with broker_client() as (client, state):
            broader_accounts = [
                connected_account(
                    identifier=f"apn_broader{index}",
                    scopes=[worker.GOOGLE_DRIVE_SCOPE, "https://www.googleapis.com/auth/drive"],
                )
                for index in range(100)
            ]
            state.account_pages = [broader_accounts, [connected_account()]]
            _token, result = client.reconcile("ryu_abcdefghijklmnop")
        self.assertEqual(result["status"], "ready")
        self.assertEqual(result["account_id"], "apn_owned123")
        account_requests = [request for request in state.requests if "/accounts?" in request["path"]]
        self.assertEqual(len(account_requests), 2)
        second_query = urllib.parse.parse_qs(urllib.parse.urlsplit(account_requests[1]["path"]).query)
        self.assertEqual(second_query["after"], ["cursor-0"])

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
            with self.assertRaisesRegex(worker.WorkerError, "not found") as caught:
                client.list_drive_metadata("ryu_abcdefghijklmnop", "apn_other123")
        self.assertEqual(caught.exception.status, 404)
        self.assertFalse(any("/proxy/" in request["path"] for request in state.requests))

    def test_list_metadata_uses_requested_owned_account_when_multiple_exist(self) -> None:
        with broker_client() as (client, state):
            state.accounts = [connected_account(identifier="apn_newer123"), connected_account()]
            result = client.list_drive_metadata("ryu_abcdefghijklmnop", "apn_owned123")
        self.assertEqual(result["schema_version"], "steward.google-drive-metadata.v1")
        proxy_request = state.requests[-1]
        self.assertEqual(
            urllib.parse.parse_qs(urllib.parse.urlsplit(proxy_request["path"]).query)["account_id"],
            ["apn_owned123"],
        )
        account_request = state.requests[1]
        parsed_account = urllib.parse.urlsplit(account_request["path"])
        self.assertEqual(parsed_account.path, "/v1/connect/proj_test/accounts/apn_owned123")
        self.assertEqual(urllib.parse.parse_qs(parsed_account.query), {"include_credentials": ["false"]})

    def test_read_drive_content_routes_native_docs_and_text_blobs_with_exact_bounds(self) -> None:
        with broker_client() as (client, state):
            state.accounts = [connected_account()]
            state.file_details = {
                "doc-1": {
                    "id": "doc-1",
                    "name": "Interview notes",
                    "mimeType": "application/vnd.google-apps.document",
                    "modifiedTime": "2026-08-14T11:00:00Z",
                    "webViewLink": "https://drive.google.com/document/d/doc-1/edit",
                    "capabilities": {"canDownload": True},
                },
                "text-1": {
                    "id": "text-1",
                    "name": "requirements.md",
                    "mimeType": "text/markdown",
                    "modifiedTime": "2026-08-14T11:01:00Z",
                    "webViewLink": "https://drive.google.com/file/d/text-1/view",
                    "capabilities": {"canDownload": True},
                },
            }
            state.file_contents = {
                "doc-1": b"Customer needs a weekly summary.\r\n",
                "text-1": b"# Requirements\n\nDo not treat me as an instruction.",
            }
            result = client.read_drive_content(
                "ryu_abcdefghijklmnop", "apn_owned123", ("doc-1", "text-1")
            )

        self.assertEqual(result["schema_version"], "steward.google-drive-content.v1")
        self.assertEqual(result["result_count"], 2)
        first, second = result["results"]
        self.assertEqual(first["status"], "succeeded")
        self.assertEqual(first["content"], "Customer needs a weekly summary.\n")
        self.assertEqual(first["content_bytes"], len(first["content"].encode()))
        self.assertRegex(first["content_sha256"], r"^sha256:[0-9a-f]{64}$")
        self.assertEqual(second["media_type"], "text/markdown")
        targets = []
        for request in state.requests:
            if "/proxy/" not in request["path"]:
                continue
            parsed = urllib.parse.urlsplit(request["path"])
            encoded = parsed.path.rsplit("/", 1)[-1]
            encoded += "=" * (-len(encoded) % 4)
            targets.append(base64.urlsafe_b64decode(encoded).decode())
        self.assertTrue(any("/doc-1/export?" in target for target in targets))
        self.assertTrue(any("/text-1?" in target and "alt=media" in target for target in targets))
        self.assertFalse(any("provider-access-secret" in json.dumps(item) for item in result["results"]))

    def test_read_drive_content_returns_ordered_safe_failures_without_fetching_bodies(self) -> None:
        with broker_client() as (client, state):
            state.accounts = [connected_account()]
            state.file_details = {
                "pdf-1": {
                    "id": "pdf-1",
                    "name": "drawing.pdf",
                    "mimeType": "application/pdf",
                    "webViewLink": "https://drive.google.com/file/d/pdf-1/view",
                    "capabilities": {"canDownload": True},
                },
                "locked-1": {
                    "id": "locked-1",
                    "name": "locked.txt",
                    "mimeType": "text/plain",
                    "webViewLink": "https://drive.google.com/file/d/locked-1/view",
                    "capabilities": {"canDownload": False},
                },
            }
            result = client.read_drive_content(
                "ryu_abcdefghijklmnop",
                "apn_owned123",
                ("missing-1", "pdf-1", "locked-1"),
            )

        self.assertEqual(
            [item["status"] for item in result["results"]],
            ["not_found", "unsupported", "not_downloadable"],
        )
        proxy_targets = [item for item in state.requests if "/proxy/" in item["path"]]
        self.assertEqual(len(proxy_targets), 3)

    def test_read_drive_content_rejects_oversize_and_invalid_text_per_item(self) -> None:
        with broker_client() as (client, state):
            state.accounts = [connected_account()]
            state.file_details = {
                file_id: {
                    "id": file_id,
                    "name": file_id + ".txt",
                    "mimeType": "text/plain",
                    "webViewLink": f"https://drive.google.com/file/d/{file_id}/view",
                    "capabilities": {"canDownload": True},
                }
                for file_id in ("large-1", "binary-1", "control-1")
            }
            state.file_contents = {
                "large-1": b"a" * (worker.MAX_FILE_CONTENT_BYTES + 1),
                "binary-1": b"\xff\xfe",
                "control-1": b"hello\x00world",
            }
            result = client.read_drive_content(
                "ryu_abcdefghijklmnop",
                "apn_owned123",
                ("large-1", "binary-1", "control-1"),
            )
        self.assertEqual(
            [item["status"] for item in result["results"]],
            ["too_large", "invalid_text", "invalid_text"],
        )
        self.assertFalse(any("content" in item for item in result["results"]))

    def test_read_drive_content_worst_case_escaping_stays_within_response_bound(self) -> None:
        selected_ids = tuple(f"escaped-{index}" for index in range(worker.MAX_CONTENT_FILES))
        per_file_bytes = worker.MAX_TOTAL_CONTENT_BYTES // len(selected_ids)
        with broker_client() as (client, state):
            state.accounts = [connected_account()]
            state.file_details = {
                file_id: {
                    "id": file_id,
                    "name": '"' * worker.GOOGLE_DRIVE_CONTENT_FIELD_BYTES["name"],
                    "mimeType": "text/plain",
                    "webViewLink": f"https://drive.google.com/file/d/{file_id}/view",
                    "capabilities": {"canDownload": True},
                }
                for file_id in selected_ids
            }
            state.file_contents = {
                file_id: b'"' * per_file_bytes for file_id in selected_ids
            }
            result = client.read_drive_content(
                "ryu_abcdefghijklmnop", "apn_owned123", selected_ids
            )

        serialized = json.dumps(
            result,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        self.assertEqual(
            sum(int(item["content_bytes"]) for item in result["results"]),
            worker.MAX_TOTAL_CONTENT_BYTES,
        )
        self.assertLessEqual(len(serialized), worker.MAX_CONTENT_RESPONSE)

    def test_read_drive_content_uses_one_deadline_for_the_whole_batch(self) -> None:
        class DeadlineClient(worker.PipedreamClient):
            def __init__(self) -> None:
                self.deadlines: list[float] = []

            def _owned_account(
                self,
                user: str,
                requested_account: str,
                scope: str,
                *,
                deadline: float | None = None,
            ) -> tuple[str, dict[str, object]]:
                del user, requested_account, scope
                assert deadline is not None
                self.deadlines.append(deadline)
                return "token", {
                    "healthy": True,
                    "authorized_scopes": [worker.GOOGLE_DRIVE_SCOPE],
                }

            def _drive_file_metadata(
                self,
                token: str,
                *,
                user: str,
                account: str,
                selected_id: str,
                deadline: float,
            ) -> dict[str, object]:
                del token, user, account
                self.deadlines.append(deadline)
                return {
                    "id": selected_id,
                    "name": selected_id,
                    "mimeType": "application/pdf",
                    "webViewLink": f"https://drive.google.com/file/d/{selected_id}/view",
                    "canDownload": True,
                }

            def _drive_file_content(
                self,
                token: str,
                *,
                user: str,
                account: str,
                metadata: dict[str, object],
                deadline: float,
            ) -> dict[str, object]:
                del token, user, account
                self.deadlines.append(deadline)
                return {"file_id": metadata["id"], "status": "unsupported"}

        client = DeadlineClient()
        with mock.patch.object(worker.time, "monotonic", return_value=100.0):
            client.read_drive_content(
                "ryu_abcdefghijklmnop", "apn_owned123", ("one", "two")
            )

        self.assertEqual(
            client.deadlines,
            [100.0 + worker.CONTENT_BATCH_TIMEOUT_SECONDS] * 5,
        )

    def test_upstream_watchdog_enforces_absolute_deadline_during_slow_body(self) -> None:
        released = threading.Event()

        class BlockingSocket:
            def settimeout(self, _timeout: float) -> None:
                return

            def shutdown(self, _how: int) -> None:
                released.set()

        class Headers:
            def get(self, _key: str, default: str = "") -> str:
                return default

            def get_content_type(self) -> str:
                return "application/json"

        class BlockingResponse:
            status = 200
            headers = Headers()

            def read1(self, _maximum: int) -> bytes:
                released.wait(timeout=1)
                return b""

        class BlockingConnection:
            def __init__(self, *_args: object, **_kwargs: object) -> None:
                self.sock = BlockingSocket()

            def request(self, *_args: object, **_kwargs: object) -> None:
                return

            def getresponse(self) -> BlockingResponse:
                return BlockingResponse()

            def close(self) -> None:
                released.set()

        with broker_client() as (client, _state), mock.patch.object(
            worker,
            "_ResolvedHTTPConnection",
            BlockingConnection,
        ):
            started = time.monotonic()
            with self.assertRaises(worker.WorkerError) as raised:
                client._request_bytes(
                    "GET",
                    "/slow",
                    maximum_bytes=1024,
                    deadline=time.monotonic() + 0.05,
                )
            elapsed = time.monotonic() - started

        self.assertEqual(raised.exception.code, "operation_deadline_exceeded")
        self.assertLess(elapsed, 0.5)

    def test_upstream_deadline_is_enforced_before_dns_returns(self) -> None:
        class BlockingProcess:
            def __init__(self) -> None:
                self.returncode: int | None = None
                self.terminated = False

            def communicate(self, timeout: float) -> tuple[bytes, bytes]:
                time.sleep(timeout)
                raise worker.subprocess.TimeoutExpired("resolver", timeout)

            def poll(self) -> int | None:
                return self.returncode

            def terminate(self) -> None:
                self.terminated = True
                self.returncode = -15

            def kill(self) -> None:
                self.returncode = -9

            def wait(self, timeout: float) -> int:
                del timeout
                assert self.returncode is not None
                return self.returncode

        processes: list[BlockingProcess] = []

        def blocking_resolution(*_args: object) -> BlockingProcess:
            process = BlockingProcess()
            processes.append(process)
            return process

        client = worker.PipedreamClient(
            client_id=b"client-id-value",
            client_secret=b"client-secret-value",
            project_id="proj_test",
            environment="development",
            oauth_app_id="oa_test",
            api_origin="https://broker.invalid",
        )
        with mock.patch.object(worker, "_resolver_process", blocking_resolution):
            started = time.monotonic()
            for _attempt in range(worker.MAX_CONCURRENCY + 2):
                with self.assertRaises(worker.WorkerError) as raised:
                    client._request_bytes(
                        "GET",
                        "/dns-stall",
                        maximum_bytes=1024,
                        deadline=time.monotonic() + 0.05,
                    )
            elapsed = time.monotonic() - started

        self.assertEqual(raised.exception.code, "operation_deadline_exceeded")
        self.assertLess(elapsed, 1)
        self.assertEqual(len(processes), worker.MAX_CONCURRENCY + 2)
        self.assertTrue(all(process.terminated for process in processes))

        class ReadyProcess(BlockingProcess):
            def __init__(self) -> None:
                super().__init__()
                self.returncode = 0

            def communicate(self, timeout: float) -> tuple[bytes, bytes]:
                del timeout
                return (
                    b'[[2,1,6,"",["127.0.0.1",443]]]',
                    b"",
                )

        recovered = ReadyProcess()
        with mock.patch.object(
            worker,
            "_resolver_process",
            return_value=recovered,
        ):
            addresses = worker._resolved_addresses(
                "broker.invalid",
                443,
                deadline=time.monotonic() + 0.5,
            )
        self.assertEqual(addresses[0][-1], ("127.0.0.1", 443))

    def test_read_drive_content_rejects_unowned_account_and_invalid_ids_before_proxy(self) -> None:
        with broker_client() as (client, state):
            state.accounts = [connected_account()]
            with self.assertRaisesRegex(worker.WorkerError, "not found"):
                client.read_drive_content(
                    "ryu_abcdefghijklmnop", "apn_other123", ("file-1",)
                )
            with self.assertRaisesRegex(worker.WorkerError, "file IDs"):
                client.read_drive_content(
                    "ryu_abcdefghijklmnop", "apn_owned123", ("../secret",)
                )
        self.assertFalse(any("/proxy/" in request["path"] for request in state.requests))

    def test_read_recent_gmail_freezes_window_and_normalizes_bounded_text(self) -> None:
        with broker_client() as (client, state):
            state.accounts = [connected_gmail_account()]
            state.gmail_messages = [{"id": "msg_1", "threadId": "thread_msg_1"}]
            state.gmail_message_details["msg_1"] = gmail_message("msg_1")
            result = client.read_recent_gmail(
                "ryu_abcdefghijklmnop",
                "apn_owned123",
            )

        self.assertEqual(result["schema_version"], "steward.gmail-recent-messages.v1")
        self.assertEqual(result["window_days"], 30)
        message = result["results"][0]
        self.assertEqual(message["subject"], "Renewal next steps")
        self.assertEqual(message["content_source"], "text/plain")
        self.assertEqual(
            message["content"],
            "Please prepare the renewal summary by Friday.",
        )
        proxy_targets = []
        for request in state.requests:
            if "/proxy/" not in request["path"]:
                continue
            encoded = urllib.parse.urlsplit(request["path"]).path.rsplit("/", 1)[-1]
            encoded += "=" * (-len(encoded) % 4)
            proxy_targets.append(base64.urlsafe_b64decode(encoded).decode())
        self.assertEqual(proxy_targets[0], worker.GMAIL_LIST_TARGET)
        detail = urllib.parse.urlsplit(proxy_targets[1])
        self.assertEqual(detail.hostname, "gmail.googleapis.com")
        self.assertEqual(detail.path, "/gmail/v1/users/me/messages/msg_1")
        self.assertEqual(
            urllib.parse.parse_qs(detail.query),
            {"fields": [worker.GMAIL_MESSAGE_FIELDS], "format": ["full"]},
        )

    def test_read_recent_gmail_uses_snippet_fallback_and_rejects_broader_scope(self) -> None:
        with broker_client() as (client, state):
            state.accounts = [connected_gmail_account()]
            state.gmail_messages = [{"id": "msg_1"}]
            detail = gmail_message("msg_1")
            detail["payload"]["parts"] = []
            state.gmail_message_details["msg_1"] = detail
            result = client.read_recent_gmail(
                "ryu_abcdefghijklmnop",
                "apn_owned123",
            )
            self.assertEqual(result["results"][0]["content_source"], "snippet")

            state.accounts = [
                connected_gmail_account(
                    scopes=[worker.GMAIL_SCOPE, "https://www.googleapis.com/auth/gmail.modify"]
                )
            ]
            with self.assertRaisesRegex(worker.WorkerError, "not ready"):
                client.read_recent_gmail(
                    "ryu_abcdefghijklmnop",
                    "apn_owned123",
                )

    def test_read_recent_gmail_rejects_duplicate_or_excess_messages_before_fetch(self) -> None:
        with broker_client() as (client, state):
            state.accounts = [connected_gmail_account()]
            state.gmail_messages = [{"id": "msg_1"}, {"id": "msg_1"}]
            with self.assertRaisesRegex(worker.WorkerError, "identifiers"):
                client.read_recent_gmail(
                    "ryu_abcdefghijklmnop",
                    "apn_owned123",
                )
        detail_requests = [
            request
            for request in state.requests
            if "/proxy/" in request["path"]
            and "messages%2Fmsg" in request["path"]
        ]
        self.assertEqual(detail_requests, [])

    def test_read_recent_gmail_rejects_invalid_page_token(self) -> None:
        with broker_client() as (client, state):
            state.accounts = [connected_gmail_account()]
            state.gmail_messages = []
            state.gmail_next_page_token = "bad\nsecret"
            with self.assertRaisesRegex(worker.WorkerError, "page token"):
                client.read_recent_gmail(
                    "ryu_abcdefghijklmnop",
                    "apn_owned123",
                )

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
    def connect_link(
        self,
        user: str,
        integration: str = "google-drive",
    ) -> dict[str, object]:
        return {"schema_version": "test", "user": user, "integration": integration}

    def reconcile(
        self,
        user: str,
        scope: str = "connect:accounts:read",
        integration: str = "google-drive",
    ) -> tuple[str, dict[str, object]]:
        del scope
        return "not-returned", {
            "schema_version": "test",
            "user": user,
            "integration": integration,
        }

    def list_drive_metadata(self, user: str, account: str) -> dict[str, object]:
        return {"schema_version": "test", "user": user, "account": account}

    def read_drive_content(
        self, user: str, account: str, file_ids: tuple[str, ...]
    ) -> dict[str, object]:
        return {
            "schema_version": "test",
            "user": user,
            "account": account,
            "file_ids": list(file_ids),
        }

    def read_recent_gmail(self, user: str, account: str) -> dict[str, object]:
        return {
            "schema_version": "test",
            "user": user,
            "account": account,
            "integration": "gmail",
        }

    def revoke(
        self,
        user: str,
        account: str,
        integration: str = "google-drive",
    ) -> dict[str, object]:
        return {
            "schema_version": "test",
            "user": user,
            "account": account,
            "integration": integration,
            "revoked": True,
        }


@contextlib.contextmanager
def integration_server(
    *,
    client: object | None = None,
    client_read_timeout: float = worker.CLIENT_READ_TIMEOUT_SECONDS,
) -> Iterator[int]:
    server = worker.IntegrationServer(
        ("127.0.0.1", 0),
        b"worker-token-value",
        client or StubClient(),
        client_read_timeout=client_read_timeout,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield int(server.server_address[1])
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@contextlib.contextmanager
def health_server() -> Iterator[int]:
    server = worker.HealthServer(("127.0.0.1", 0), worker.HealthHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield int(server.server_address[1])
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
    def test_admission_deadline_race_has_one_unambiguous_winner(self) -> None:
        class FakeRequest:
            def __init__(self) -> None:
                self.expired = False

            def shutdown(self, _how: int) -> None:
                self.expired = True

        server = worker.IntegrationServer(
            ("127.0.0.1", 0),
            b"worker-token-value",
            StubClient(),
        )
        try:
            for _index in range(100):
                request = FakeRequest()
                timer = threading.Timer(60, lambda: None)
                with server._deadline_lock:
                    server._deadlines[id(request)] = timer
                barrier = threading.Barrier(3)
                admitted: list[bool] = []

                def parse() -> None:
                    barrier.wait()
                    admitted.append(server.request_parsed(request))

                def expire() -> None:
                    barrier.wait()
                    server._expire_request(request)

                parse_thread = threading.Thread(target=parse)
                expire_thread = threading.Thread(target=expire)
                parse_thread.start()
                expire_thread.start()
                barrier.wait()
                parse_thread.join(timeout=1)
                expire_thread.join(timeout=1)
                self.assertEqual(admitted, [not request.expired])
        finally:
            server.server_close()

    def test_health_remains_ready_when_all_operation_slots_are_busy(self) -> None:
        class BlockingClient(StubClient):
            def __init__(self) -> None:
                self.entered = 0
                self.all_entered = threading.Event()
                self.release = threading.Event()
                self.lock = threading.Lock()

            def reconcile(self, user: str) -> tuple[str, dict[str, object]]:
                with self.lock:
                    self.entered += 1
                    if self.entered == worker.MAX_CONCURRENCY:
                        self.all_entered.set()
                self.release.wait(timeout=2)
                return super().reconcile(user)

        blocking = BlockingClient()
        results: list[int] = []

        def call_operation(port: int) -> None:
            status, _body, _headers = call_worker(
                port,
                "/v1/connections/google-drive/reconcile",
                b'{"external_user_id":"ryu_abcdefghijklmnop"}',
            )
            results.append(status)

        with integration_server(client=blocking) as port, health_server() as health_port:
            threads = [
                threading.Thread(target=call_operation, args=(port,))
                for _index in range(worker.MAX_CONCURRENCY)
            ]
            for thread in threads:
                thread.start()
            self.assertTrue(blocking.all_entered.wait(timeout=1))
            overflow = socket.create_connection(("127.0.0.1", port), timeout=0.5)
            overflow.sendall(
                b"POST /v1/connections/google-drive/reconcile HTTP/1.1\r\n"
                b"Authorization: Bearer worker-token-value\r\n"
                b"Content-Type: application/json\r\n"
                b"Content-Length: 43\r\n\r\n"
                b'{"external_user_id":"ryu_abcdefghijklmnop"}'
            )
            time.sleep(0.05)
            fragmented = socket.create_connection(("127.0.0.1", health_port), timeout=0.5)
            fragmented.sendall(b"GET /hea")
            fragmented_response = fragmented.recv(4096)
            connection = http.client.HTTPConnection("127.0.0.1", health_port, timeout=0.5)
            try:
                started = time.monotonic()
                connection.request("GET", "/healthz")
                response = connection.getresponse()
                body = json.loads(response.read())
                elapsed = time.monotonic() - started
            finally:
                connection.close()
                fragmented.close()
                overflow.close()
                blocking.release.set()
            for thread in threads:
                thread.join(timeout=2)

        self.assertEqual(response.status, 200)
        self.assertEqual(body["status"], "ready")
        self.assertIn(b"200 OK", fragmented_response)
        self.assertLess(elapsed, 0.5)
        self.assertEqual(results, [200] * worker.MAX_CONCURRENCY)

    def test_slow_unauthenticated_clients_release_all_worker_slots(self) -> None:
        sockets: list[socket.socket] = []
        with integration_server(client_read_timeout=0.05) as port:
            for _index in range(worker.MAX_CONCURRENCY):
                client = socket.create_connection(("127.0.0.1", port), timeout=1)
                client.sendall(b"P")
                sockets.append(client)
            time.sleep(0.03)
            for client in sockets:
                client.sendall(b"O")
            time.sleep(0.08)
            status, _body, _headers = call_worker(
                port,
                "/v1/connections/google-drive/reconcile",
                b'{"external_user_id":"ryu_abcdefghijklmnop"}',
            )
        for client in sockets:
            client.close()
        self.assertEqual(status, 200)

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

    def test_content_route_requires_one_to_ten_unique_canonical_file_ids(self) -> None:
        with integration_server() as port:
            status, body, _headers = call_worker(
                port,
                "/v1/connections/google-drive/content",
                b'{"account_id":"apn_owned123","external_user_id":"ryu_abcdefghijklmnop","file_ids":["doc-1","text-1"]}',
            )
            self.assertEqual(status, 200)
            self.assertEqual(body["file_ids"], ["doc-1", "text-1"])

            status, body, _headers = call_worker(
                port,
                "/v1/connections/google-drive/content",
                b'{"account_id":"apn_owned123","external_user_id":"ryu_abcdefghijklmnop","file_ids":["doc-1","doc-1"]}',
            )
            self.assertEqual((status, body["error"]["code"]), (400, "invalid_file_ids"))

    def test_gmail_routes_dispatch_only_exact_finite_operations(self) -> None:
        with integration_server() as port:
            status, body, _headers = call_worker(
                port,
                "/v1/connections/gmail/connect-link",
                b'{"external_user_id":"ryu_abcdefghijklmnop"}',
            )
            self.assertEqual(status, 200)
            self.assertEqual(body["integration"], "gmail")

            status, body, _headers = call_worker(
                port,
                "/v1/connections/gmail/recent-messages",
                b'{"account_id":"apn_owned123","external_user_id":"ryu_abcdefghijklmnop"}',
            )
            self.assertEqual(status, 200)
            self.assertEqual(body["integration"], "gmail")

            status, body, _headers = call_worker(
                port,
                "/v1/connections/gmail/recent-messages",
                b'{"account_id":"apn_owned123","external_user_id":"ryu_abcdefghijklmnop","q":"from:ceo"}',
            )
            self.assertEqual((status, body["error"]["code"]), (400, "invalid_request"))


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
