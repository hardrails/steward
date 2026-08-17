#!/usr/bin/env python3
"""Adversarial contract tests for the finite managed integration worker."""

from __future__ import annotations

import base64
import contextlib
import datetime
import hashlib
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
        self.calendar_events: list[object] = []
        self.calendar_next_page_token: str | None = None
        self.calendar_time_zone = "America/Los_Angeles"
        self.microsoft_outlook_messages: list[object] = []
        self.microsoft_outlook_message_next_link: str | None = None
        self.microsoft_outlook_events: list[object] = []
        self.microsoft_outlook_event_next_link: str | None = None
        self.slack_channels: list[object] = []
        self.slack_channel_info: object | None = None
        self.slack_channel_cursor = ""
        self.slack_messages: list[object] = []
        self.slack_message_cursor = ""
        self.slack_has_more = False
        self.slack_list_error: str | None = None
        self.slack_history_error: str | None = None
        self.hubspot_deals: list[object] = []
        self.hubspot_total = 0
        self.hubspot_after: str | None = None
        self.hubspot_pipelines: list[object] = []
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
                "proxy_prefer": self.headers.get("X-PD-Proxy-Prefer", ""),
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
        if self.path.startswith("/v1/connect/proj_test/proxy/"):
            parsed = urllib.parse.urlsplit(self.path)
            encoded_target = parsed.path.rsplit("/", 1)[-1]
            encoded_target += "=" * (-len(encoded_target) % 4)
            target = urllib.parse.urlsplit(base64.urlsafe_b64decode(encoded_target).decode())
            if (
                target.hostname == "api.hubapi.com"
                and target.path == "/crm/objects/2026-03/deals/search"
            ):
                value: dict[str, object] = {
                    "results": self.state.hubspot_deals,
                    "total": self.state.hubspot_total,
                }
                if self.state.hubspot_after is not None:
                    value["paging"] = {
                        "next": {
                            "after": self.state.hubspot_after,
                            "link": "https://api.hubapi.com/next",
                        }
                    }
                self._respond(200, value)
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
            if (
                target.hostname == "www.googleapis.com"
                and target.path == "/calendar/v3/calendars/primary/events"
            ):
                calendar_value: dict[str, object] = {
                    "items": self.state.calendar_events,
                    "timeZone": self.state.calendar_time_zone,
                }
                if self.state.calendar_next_page_token is not None:
                    calendar_value["nextPageToken"] = self.state.calendar_next_page_token
                self._respond(200, calendar_value)
                return
            if target.hostname == "graph.microsoft.com":
                if target.path == "/v1.0/me/mailFolders/inbox/messages":
                    mail_value: dict[str, object] = {
                        "value": self.state.microsoft_outlook_messages
                    }
                    if self.state.microsoft_outlook_message_next_link is not None:
                        mail_value["@odata.nextLink"] = (
                            self.state.microsoft_outlook_message_next_link
                        )
                    self._respond(200, mail_value)
                    return
                if target.path == "/v1.0/me/calendarView":
                    event_value: dict[str, object] = {
                        "value": self.state.microsoft_outlook_events
                    }
                    if self.state.microsoft_outlook_event_next_link is not None:
                        event_value["@odata.nextLink"] = (
                            self.state.microsoft_outlook_event_next_link
                        )
                    self._respond(200, event_value)
                    return
            if target.hostname == "slack.com" and target.path == "/api/conversations.list":
                if self.state.slack_list_error is not None:
                    self._respond(200, {"ok": False, "error": self.state.slack_list_error})
                    return
                self._respond(
                    200,
                    {
                        "ok": True,
                        "channels": self.state.slack_channels,
                        "response_metadata": {
                            "next_cursor": self.state.slack_channel_cursor,
                        },
                    },
                )
                return
            if target.hostname == "slack.com" and target.path == "/api/conversations.history":
                if self.state.slack_history_error is not None:
                    self._respond(200, {"ok": False, "error": self.state.slack_history_error})
                    return
                self._respond(
                    200,
                    {
                        "ok": True,
                        "messages": self.state.slack_messages,
                        "has_more": self.state.slack_has_more,
                        "response_metadata": {
                            "next_cursor": self.state.slack_message_cursor,
                        },
                    },
                )
                return
            if target.hostname == "slack.com" and target.path == "/api/conversations.info":
                channel = self.state.slack_channel_info
                if channel is None:
                    self._respond(200, {"ok": False, "error": "channel_not_found"})
                else:
                    self._respond(200, {"ok": True, "channel": channel})
                return
            if (
                target.hostname == "api.hubapi.com"
                and target.path == "/crm/pipelines/2026-03/deals"
            ):
                self._respond(200, {"results": self.state.hubspot_pipelines})
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
            google_calendar_oauth_app_id="oa_calendartest",
            microsoft_outlook_oauth_app_id="oa_outlooktest",
            microsoft_outlook_calendar_oauth_app_id="oa_outlookcaltest",
            slack_oauth_app_id="oa_slacktest",
            hubspot_oauth_app_id="oa_hubspottest",
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


def connected_calendar_account(
    *,
    scopes: list[str] | None = None,
    identifier: str = "apn_owned123",
) -> dict[str, object]:
    value = connected_account(
        scopes=scopes or [worker.GOOGLE_CALENDAR_SCOPE],
        identifier=identifier,
    )
    value["name"] = "Operations Calendar"
    value["app"] = {"name_slug": "google_calendar"}
    return value


def connected_microsoft_outlook_account(
    *,
    scopes: list[str] | None = None,
    identifier: str = "apn_owned123",
) -> dict[str, object]:
    value = connected_account(
        scopes=scopes or [worker.MICROSOFT_OUTLOOK_SCOPE],
        identifier=identifier,
    )
    value["name"] = "Operations Outlook"
    value["app"] = {"name_slug": "microsoft_outlook"}
    return value


def connected_microsoft_outlook_calendar_account(
    *,
    scopes: list[str] | None = None,
    identifier: str = "apn_owned123",
) -> dict[str, object]:
    value = connected_account(
        scopes=scopes or [worker.MICROSOFT_OUTLOOK_CALENDAR_SCOPE],
        identifier=identifier,
    )
    value["name"] = "Operations Outlook Calendar"
    value["app"] = {"name_slug": "microsoft_outlook_calendar"}
    return value


def connected_slack_account(
    *,
    scopes: list[str] | None = None,
    identifier: str = "apn_owned123",
) -> dict[str, object]:
    value = connected_account(
        scopes=scopes or list(worker.SLACK_SCOPES),
        identifier=identifier,
    )
    value["name"] = "Operations Slack"
    value["app"] = {"name_slug": "slack"}
    return value


def connected_hubspot_account(
    *,
    scopes: list[str] | None = None,
    identifier: str = "apn_owned123",
) -> dict[str, object]:
    value = connected_account(
        scopes=scopes or [worker.HUBSPOT_SCOPE],
        identifier=identifier,
    )
    value["name"] = "Revenue HubSpot"
    value["app"] = {"name_slug": "hubspot"}
    return value


def hubspot_pipeline() -> dict[str, object]:
    return {
        "id": "default",
        "label": "Sales Pipeline",
        "archived": False,
        "stages": [
            {
                "id": "qualifiedtobuy",
                "label": "Qualified to buy",
                "archived": False,
            },
            {
                "id": "closedwon",
                "label": "Closed won",
                "archived": False,
            },
        ],
    }


def hubspot_deal(deal_id: str = "123456") -> dict[str, object]:
    return {
        "id": deal_id,
        "archived": False,
        "createdAt": "2026-08-01T12:00:00Z",
        "updatedAt": "2026-08-15T17:30:00Z",
        "properties": {
            "amount": "125000.00",
            "closedate": "2026-09-30T00:00:00Z",
            "createdate": "2026-08-01T12:00:00Z",
            "dealname": "Acme expansion",
            "dealstage": "qualifiedtobuy",
            "hs_is_closed": "false",
            "hs_lastmodifieddate": "2026-08-15T17:30:00Z",
            "pipeline": "default",
        },
    }


def slack_channel(channel_id: str = "C123TEAM") -> dict[str, object]:
    return {
        "id": channel_id,
        "name": "sales-operations",
        "is_archived": False,
        "is_private": False,
        "topic": {"value": "Sales blockers and decisions"},
        "purpose": {"value": "Coordinate the revenue team"},
        "num_members": 37,
    }


def slack_message(timestamp: str = "1786723200.000100") -> dict[str, object]:
    return {
        "type": "message",
        "ts": timestamp,
        "user": "U123TEAM",
        "text": "The renewal is blocked on security review.",
        "reactions": [{"name": "eyes", "count": 3}],
    }


def calendar_event(event_id: str = "event_1") -> dict[str, object]:
    return {
        "id": event_id,
        "status": "confirmed",
        "summary": "Customer renewal review",
        "description": "Review renewal risks and next steps.",
        "location": "Conference room A",
        "eventType": "default",
        "transparency": "opaque",
        "visibility": "default",
        "start": {
            "dateTime": "2026-08-16T09:00:00-07:00",
            "timeZone": "America/Los_Angeles",
        },
        "end": {
            "dateTime": "2026-08-16T09:30:00-07:00",
            "timeZone": "America/Los_Angeles",
        },
        "organizer": {
            "email": "ops@example.com",
            "displayName": "Operations",
            "self": True,
        },
        "attendees": [
            {
                "email": "customer@example.com",
                "displayName": "Customer",
                "responseStatus": "accepted",
                "optional": False,
            }
        ],
        "attendeesOmitted": False,
    }


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


def microsoft_outlook_message(message_id: str = "AAMk_message_1=") -> dict[str, object]:
    return {
        "id": message_id,
        "conversationId": "AAQk_conversation_1=",
        "subject": "Renewal next steps",
        "from": {
            "emailAddress": {
                "name": "Customer",
                "address": "customer@example.com",
            }
        },
        "toRecipients": [
            {
                "emailAddress": {
                    "name": "Operations",
                    "address": "ops@example.com",
                }
            }
        ],
        "receivedDateTime": "2026-08-14T19:00:00Z",
        "isRead": False,
        "importance": "high",
        "bodyPreview": "Please prepare the renewal summary by Friday.",
    }


def microsoft_outlook_event(event_id: str = "AAMk_event_1=") -> dict[str, object]:
    return {
        "id": event_id,
        "subject": "Customer renewal review",
        "start": {"dateTime": "2026-08-18T16:00:00", "timeZone": "UTC"},
        "end": {"dateTime": "2026-08-18T17:00:00", "timeZone": "UTC"},
        "location": {"displayName": "Conference room 1"},
        "organizer": {
            "emailAddress": {"name": "Operations", "address": "ops@example.com"}
        },
        "attendees": [
            {
                "emailAddress": {
                    "name": "Customer",
                    "address": "customer@example.com",
                },
                "type": "required",
                "status": {"response": "accepted"},
            }
        ],
        "isAllDay": False,
        "isCancelled": False,
        "showAs": "busy",
        "sensitivity": "normal",
        "type": "singleInstance",
    }


class PipedreamClientTests(unittest.TestCase):
    def test_each_managed_integration_can_be_configured_independently(self) -> None:
        gmail_only = worker.PipedreamClient(
            client_id=b"client-id-value",
            client_secret=b"client-secret-value",
            project_id="proj_test",
            environment="development",
            oauth_app_id="",
            gmail_oauth_app_id="oa_gmailtest",
            api_origin="https://broker.invalid",
        )
        self.assertEqual(gmail_only.oauth_app_ids["google-drive"], "")
        self.assertEqual(gmail_only.oauth_app_ids["gmail"], "oa_gmailtest")
        self.assertEqual(gmail_only.oauth_app_ids["google-calendar"], "")
        with self.assertRaisesRegex(RuntimeError, "at least one"):
            worker.PipedreamClient(
                client_id=b"client-id-value",
                client_secret=b"client-secret-value",
                project_id="proj_test",
                environment="development",
                oauth_app_id="",
                gmail_oauth_app_id="",
                api_origin="https://broker.invalid",
            )

        calendar_only = worker.PipedreamClient(
            client_id=b"client-id-value",
            client_secret=b"client-secret-value",
            project_id="proj_test",
            environment="development",
            oauth_app_id="",
            google_calendar_oauth_app_id="oa_calendartest",
            api_origin="https://broker.invalid",
        )
        self.assertEqual(
            calendar_only.oauth_app_ids["google-calendar"],
            "oa_calendartest",
        )

        slack_only = worker.PipedreamClient(
            client_id=b"client-id-value",
            client_secret=b"client-secret-value",
            project_id="proj_test",
            environment="development",
            oauth_app_id="",
            slack_oauth_app_id="oa_slacktest",
            api_origin="https://broker.invalid",
        )
        self.assertEqual(slack_only.oauth_app_ids["slack"], "oa_slacktest")

        hubspot_only = worker.PipedreamClient(
            client_id=b"client-id-value",
            client_secret=b"client-secret-value",
            project_id="proj_test",
            environment="development",
            oauth_app_id="",
            hubspot_oauth_app_id="oa_hubspottest",
            api_origin="https://broker.invalid",
        )
        self.assertEqual(hubspot_only.oauth_app_ids["hubspot"], "oa_hubspottest")

        outlook_only = worker.PipedreamClient(
            client_id=b"client-id-value",
            client_secret=b"client-secret-value",
            project_id="proj_test",
            environment="development",
            oauth_app_id="",
            microsoft_outlook_oauth_app_id="oa_outlooktest",
            api_origin="https://broker.invalid",
        )
        self.assertEqual(
            outlook_only.oauth_app_ids["microsoft-outlook-mail"],
            "oa_outlooktest",
        )

        outlook_calendar_only = worker.PipedreamClient(
            client_id=b"client-id-value",
            client_secret=b"client-secret-value",
            project_id="proj_test",
            environment="development",
            oauth_app_id="",
            microsoft_outlook_calendar_oauth_app_id="oa_outlookcaltest",
            api_origin="https://broker.invalid",
        )
        self.assertEqual(
            outlook_calendar_only.oauth_app_ids["microsoft-outlook-calendar"],
            "oa_outlookcaltest",
        )

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

    def test_account_list_is_bounded_sorted_and_credential_free(self) -> None:
        older = connected_gmail_account(identifier="apn_older123")
        older["name"] = "Older Inbox"
        older["created_at"] = "2026-08-13T12:00:00Z"
        over_scoped = connected_gmail_account(
            scopes=[worker.GMAIL_SCOPE, worker.GOOGLE_DRIVE_SCOPE],
            identifier="apn_newer123",
        )
        over_scoped["name"] = "Needs review"
        over_scoped["created_at"] = "2026-08-15T12:00:00Z"
        with broker_client() as (client, state):
            state.accounts = [older, over_scoped]
            result = client.list_connections("ryu_abcdefghijklmnop", "gmail")

        self.assertEqual(result["schema_version"], "steward.managed-account-list.v1")
        self.assertEqual(result["required_scope"], worker.GMAIL_SCOPE)
        self.assertEqual(result["result_count"], 2)
        self.assertEqual(
            [item["account_id"] for item in result["accounts"]],
            ["apn_newer123", "apn_older123"],
        )
        self.assertEqual(
            [item["status"] for item in result["accounts"]],
            ["needs_attention", "ready"],
        )
        encoded = json.dumps(result)
        self.assertNotIn("credentials", encoded)
        self.assertNotIn("created_at", encoded)
        self.assertNotIn("provider-access-secret", encoded)

    def test_account_list_rejects_duplicate_identity_and_bounds_display_name(self) -> None:
        malformed_name = connected_account()
        malformed_name["name"] = "x" * 257
        with broker_client() as (client, state):
            state.accounts = [malformed_name]
            result = client.list_connections("ryu_abcdefghijklmnop")
        self.assertEqual(result["accounts"][0]["account_name"], "Google Drive")

        with broker_client() as (client, state):
            state.accounts = [connected_account(), connected_account()]
            with self.assertRaisesRegex(worker.WorkerError, "duplicate accounts"):
                client.list_connections("ryu_abcdefghijklmnop")

    def test_account_list_retains_international_names_and_caps_newest_hundred(self) -> None:
        international = connected_account(identifier="apn_international")
        international["name"] = "東京" * 128
        accounts = [international]
        for index in range(105):
            account = connected_account(identifier=f"apn_choice{index:03d}")
            account["created_at"] = f"2026-08-15T12:{index // 60:02d}:{index % 60:02d}Z"
            accounts.append(account)
        with broker_client() as (client, state):
            state.accounts = accounts
            result = client.list_connections("ryu_abcdefghijklmnop")

        self.assertEqual(result["result_count"], 100)
        self.assertEqual(len(result["accounts"]), 100)
        self.assertEqual(result["accounts"][0]["account_id"], "apn_choice104")

        with broker_client() as (client, state):
            state.accounts = [international]
            result = client.list_connections("ryu_abcdefghijklmnop")
        self.assertEqual(result["accounts"][0]["account_name"], "東京" * 128)

    def test_calendar_connect_and_reconcile_are_profile_scoped(self) -> None:
        with broker_client() as (client, state):
            link = client.connect_link("ryu_abcdefghijklmnop", "google-calendar")
            state.accounts = [connected_calendar_account()]
            _token, connection = client.reconcile(
                "ryu_abcdefghijklmnop",
                integration="google-calendar",
            )

        query = urllib.parse.parse_qs(
            urllib.parse.urlsplit(str(link["connect_url"])).query
        )
        self.assertEqual(link["integration"], "google-calendar")
        self.assertEqual(query["app"], ["google_calendar"])
        self.assertEqual(query["oauthAppId"], ["oa_calendartest"])
        self.assertEqual(connection["status"], "ready")
        self.assertEqual(connection["required_scope"], worker.GOOGLE_CALENDAR_SCOPE)

    def test_calendar_rejects_every_broader_or_cross_integration_scope(self) -> None:
        with broker_client() as (client, state):
            for extra_scope in (
                "https://www.googleapis.com/auth/calendar",
                "https://www.googleapis.com/auth/calendar.readonly",
                "https://www.googleapis.com/auth/calendar.events",
                worker.GMAIL_SCOPE,
                worker.GOOGLE_DRIVE_SCOPE,
            ):
                with self.subTest(extra_scope=extra_scope):
                    state.accounts = [
                        connected_calendar_account(
                            scopes=[worker.GOOGLE_CALENDAR_SCOPE, extra_scope]
                        )
                    ]
                    _token, result = client.reconcile(
                        "ryu_abcdefghijklmnop",
                        integration="google-calendar",
                    )
                    self.assertEqual(result["status"], "needs_attention")

    def test_microsoft_outlook_profiles_use_distinct_apps_and_exact_permissions(self) -> None:
        with broker_client() as (client, state):
            mail_link = client.connect_link(
                "ryu_abcdefghijklmnop", "microsoft-outlook-mail"
            )
            state.accounts = [
                connected_microsoft_outlook_account(
                    scopes=[
                        worker.MICROSOFT_OUTLOOK_SCOPE,
                        "User.Read",
                        "offline_access",
                        "openid",
                        "profile",
                    ]
                )
            ]
            _token, mail = client.reconcile(
                "ryu_abcdefghijklmnop",
                integration="microsoft-outlook-mail",
            )

            calendar_link = client.connect_link(
                "ryu_abcdefghijklmnop", "microsoft-outlook-calendar"
            )
            state.accounts = [connected_microsoft_outlook_calendar_account()]
            _token, calendar = client.reconcile(
                "ryu_abcdefghijklmnop",
                integration="microsoft-outlook-calendar",
            )

        mail_query = urllib.parse.parse_qs(
            urllib.parse.urlsplit(str(mail_link["connect_url"])).query
        )
        calendar_query = urllib.parse.parse_qs(
            urllib.parse.urlsplit(str(calendar_link["connect_url"])).query
        )
        self.assertEqual(mail_query["app"], ["microsoft_outlook"])
        self.assertEqual(mail_query["oauthAppId"], ["oa_outlooktest"])
        self.assertEqual(calendar_query["app"], ["microsoft_outlook_calendar"])
        self.assertEqual(calendar_query["oauthAppId"], ["oa_outlookcaltest"])
        self.assertEqual(mail["status"], "ready")
        self.assertEqual(mail["required_scope"], worker.MICROSOFT_OUTLOOK_SCOPE)
        self.assertEqual(calendar["status"], "ready")
        self.assertEqual(
            calendar["required_scope"], worker.MICROSOFT_OUTLOOK_CALENDAR_SCOPE
        )

        with broker_client() as (client, state):
            for account, integration, broader_scope in (
                (
                    connected_microsoft_outlook_account(
                        scopes=[worker.MICROSOFT_OUTLOOK_SCOPE, "Mail.Send"]
                    ),
                    "microsoft-outlook-mail",
                    "Mail.Send",
                ),
                (
                    connected_microsoft_outlook_calendar_account(
                        scopes=[
                            worker.MICROSOFT_OUTLOOK_CALENDAR_SCOPE,
                            "Calendars.ReadWrite",
                        ]
                    ),
                    "microsoft-outlook-calendar",
                    "Calendars.ReadWrite",
                ),
            ):
                with self.subTest(broader_scope=broader_scope):
                    state.accounts = [account]
                    _token, result = client.reconcile(
                        "ryu_abcdefghijklmnop", integration=integration
                    )
                    self.assertEqual(result["status"], "needs_attention")

    def test_slack_connect_and_reconcile_require_exact_multi_scope_profile(self) -> None:
        with broker_client() as (client, state):
            link = client.connect_link("ryu_abcdefghijklmnop", "slack")
            state.accounts = [connected_slack_account()]
            _token, connection = client.reconcile(
                "ryu_abcdefghijklmnop",
                integration="slack",
            )

        query = urllib.parse.parse_qs(
            urllib.parse.urlsplit(str(link["connect_url"])).query
        )
        self.assertEqual(query["app"], ["slack"])
        self.assertEqual(query["oauthAppId"], ["oa_slacktest"])
        self.assertEqual(connection["schema_version"], "steward.managed-connection.v2")
        self.assertEqual(connection["status"], "ready")
        self.assertEqual(connection["required_scopes"], list(worker.SLACK_SCOPES))
        self.assertNotIn("required_scope", connection)

        with broker_client() as (client, state):
            for scopes in (
                ["channels:history"],
                ["channels:read"],
                [*worker.SLACK_SCOPES, "chat:write"],
                [*worker.SLACK_SCOPES, "openid"],
            ):
                with self.subTest(scopes=scopes):
                    state.accounts = [connected_slack_account(scopes=scopes)]
                    _token, result = client.reconcile(
                        "ryu_abcdefghijklmnop",
                        integration="slack",
                    )
                    self.assertEqual(result["status"], "needs_attention")

    def test_list_slack_channels_freezes_caller_choice_and_bounds_projection(self) -> None:
        with broker_client() as (client, state):
            state.accounts = [connected_slack_account()]
            state.slack_channels = [slack_channel()]
            state.slack_channel_info = slack_channel()
            state.slack_channel_cursor = "next-page"
            result = client.list_slack_channels(
                "ryu_abcdefghijklmnop",
                "apn_owned123",
            )

        self.assertEqual(result["schema_version"], "steward.slack-channels.v1")
        self.assertEqual(result["result_count"], 1)
        self.assertTrue(result["has_more"])
        self.assertEqual(
            result["channels"],
            [
                {
                    "channel_id": "C123TEAM",
                    "name": "sales-operations",
                    "topic": "Sales blockers and decisions",
                    "purpose": "Coordinate the revenue team",
                }
            ],
        )
        proxy_request = state.requests[-1]
        parsed = urllib.parse.urlsplit(proxy_request["path"])
        encoded_target = parsed.path.rsplit("/", 1)[-1]
        encoded_target += "=" * (-len(encoded_target) % 4)
        target = urllib.parse.urlsplit(
            base64.urlsafe_b64decode(encoded_target).decode()
        )
        self.assertEqual(target.hostname, "slack.com")
        self.assertEqual(target.path, "/api/conversations.list")
        self.assertEqual(
            urllib.parse.parse_qs(target.query),
            {
                "exclude_archived": ["true"],
                "limit": ["100"],
                "types": ["public_channel"],
            },
        )

    def test_read_slack_messages_rechecks_public_channel_then_reads_fifteen_items(self) -> None:
        with broker_client() as (client, state):
            state.accounts = [connected_slack_account()]
            state.slack_channels = [slack_channel()]
            state.slack_channel_info = slack_channel()
            ignored = slack_message("1786723199.000100")
            ignored["subtype"] = "channel_join"
            thread_reply = slack_message("1786723198.000100")
            thread_reply["thread_ts"] = "1786723100.000100"
            broadcast = slack_message("1786723197.000100")
            broadcast["subtype"] = "thread_broadcast"
            state.slack_messages = [slack_message(), ignored, thread_reply, broadcast]
            state.slack_has_more = True
            result = client.read_recent_slack_messages(
                "ryu_abcdefghijklmnop",
                "apn_owned123",
                "C123TEAM",
            )

        self.assertEqual(
            result["schema_version"],
            "steward.slack-recent-messages.v1",
        )
        self.assertEqual(result["channel_id"], "C123TEAM")
        self.assertEqual(result["result_count"], 1)
        self.assertTrue(result["has_more"])
        message = result["messages"][0]
        self.assertEqual(message["author_id"], "U123TEAM")
        self.assertEqual(message["author_kind"], "member")
        self.assertEqual(
            message["content_sha256"],
            "sha256:" + hashlib.sha256(message["text"].encode()).hexdigest(),
        )
        proxy_request = state.requests[-1]
        parsed = urllib.parse.urlsplit(proxy_request["path"])
        encoded_target = parsed.path.rsplit("/", 1)[-1]
        encoded_target += "=" * (-len(encoded_target) % 4)
        target = urllib.parse.urlsplit(
            base64.urlsafe_b64decode(encoded_target).decode()
        )
        self.assertEqual(target.path, "/api/conversations.history")
        self.assertEqual(
            urllib.parse.parse_qs(target.query),
            {
                "channel": ["C123TEAM"],
                "include_all_metadata": ["false"],
                "limit": ["15"],
            },
        )

    def test_read_slack_messages_rejects_channel_that_is_no_longer_public(self) -> None:
        with broker_client() as (client, state):
            state.accounts = [connected_slack_account()]
            state.slack_channel_info = None
            with self.assertRaisesRegex(worker.WorkerError, "choose the channel again") as caught:
                client.read_recent_slack_messages(
                    "ryu_abcdefghijklmnop",
                    "apn_owned123",
                    "C123TEAM",
                )

        self.assertEqual(caught.exception.status, 409)
        self.assertFalse(any("conversations.history" in str(item) for item in state.requests))

    def test_read_slack_messages_checks_selected_channel_without_first_page_dependency(self) -> None:
        with broker_client() as (client, state):
            state.accounts = [connected_slack_account()]
            state.slack_channels = [slack_channel("COTHERTEAM")]
            state.slack_channel_cursor = "later-pages"
            state.slack_channel_info = slack_channel()
            result = client.read_recent_slack_messages(
                "ryu_abcdefghijklmnop",
                "apn_owned123",
                "C123TEAM",
            )

        self.assertEqual(result["channel_id"], "C123TEAM")
        self.assertEqual(result["result_count"], 0)

    def test_slack_access_change_and_invalid_channel_fail_without_leaking_provider_detail(self) -> None:
        with broker_client() as (client, state):
            state.accounts = [connected_slack_account()]
            state.slack_channels = [slack_channel()]
            state.slack_channel_info = slack_channel()
            state.slack_history_error = "channel_not_found"
            with self.assertRaisesRegex(worker.WorkerError, "choose the channel again") as caught:
                client.read_recent_slack_messages(
                    "ryu_abcdefghijklmnop",
                    "apn_owned123",
                    "C123TEAM",
                )
            self.assertEqual(caught.exception.status, 409)

            before = len(state.requests)
            with self.assertRaisesRegex(worker.WorkerError, "identifier is invalid"):
                client.read_recent_slack_messages(
                    "ryu_abcdefghijklmnop",
                    "apn_owned123",
                    "../private",
                )
            self.assertEqual(len(state.requests), before)

    def test_slack_read_uses_one_deadline_for_all_broker_calls(self) -> None:
        class DeadlineClient(worker.PipedreamClient):
            def __init__(self) -> None:
                self.deadlines: list[float] = []

            def _owned_account(
                self,
                user: str,
                requested_account: str,
                scope: str,
                *,
                integration: str = "google-drive",
                deadline: float | None = None,
            ) -> tuple[str, dict[str, object]]:
                del user, requested_account, scope, integration
                assert deadline is not None
                self.deadlines.append(deadline)
                return "token", {
                    "healthy": True,
                    "authorized_scopes": list(worker.SLACK_SCOPES),
                }

            def _proxy_json(
                self,
                token: str,
                *,
                user: str,
                account: str,
                target: str,
                deadline: float | None = None,
            ) -> object:
                del token, user, account
                assert deadline is not None
                self.deadlines.append(deadline)
                if "conversations.info" in target:
                    return {"ok": True, "channel": slack_channel()}
                return {"ok": True, "messages": []}

        client = DeadlineClient()
        with mock.patch.object(worker.time, "monotonic", return_value=100.0):
            client.read_recent_slack_messages(
                "ryu_abcdefghijklmnop", "apn_owned123", "C123TEAM"
            )

        self.assertEqual(
            client.deadlines,
            [100.0 + worker.SLACK_OPERATION_TIMEOUT_SECONDS] * 3,
        )

    def test_hubspot_connect_reconcile_and_deal_read_are_exact_and_bounded(self) -> None:
        with broker_client() as (client, state):
            link = client.connect_link("ryu_abcdefghijklmnop", "hubspot")
            state.accounts = [connected_hubspot_account()]
            _token, connection = client.reconcile(
                "ryu_abcdefghijklmnop",
                integration="hubspot",
            )
            state.hubspot_pipelines = [hubspot_pipeline()]
            state.hubspot_deals = [hubspot_deal()]
            state.hubspot_total = 137
            state.hubspot_after = "123457"
            result = client.read_recent_hubspot_deals(
                "ryu_abcdefghijklmnop",
                "apn_owned123",
            )

        link_query = urllib.parse.parse_qs(urllib.parse.urlsplit(str(link["connect_url"])).query)
        self.assertEqual(link_query["app"], ["hubspot"])
        self.assertEqual(link_query["oauthAppId"], ["oa_hubspottest"])
        self.assertEqual(connection["status"], "ready")
        self.assertEqual(connection["required_scope"], worker.HUBSPOT_SCOPE)
        self.assertEqual(result["schema_version"], "steward.hubspot-recent-deals.v1")
        self.assertEqual(result["integration"], "hubspot")
        self.assertEqual(result["result_count"], 1)
        self.assertEqual(result["total_available"], 137)
        self.assertTrue(result["has_more"])
        self.assertEqual(
            result["deals"],
            [
                {
                    "deal_id": "123456",
                    "name": "Acme expansion",
                    "amount": "125000.00",
                    "closed": False,
                    "close_date": "2026-09-30T00:00:00Z",
                    "created_at": "2026-08-01T12:00:00Z",
                    "updated_at": "2026-08-15T17:30:00Z",
                    "pipeline_id": "default",
                    "pipeline_name": "Sales Pipeline",
                    "stage_id": "qualifiedtobuy",
                    "stage_name": "Qualified to buy",
                }
            ],
        )
        proxy_requests = [request for request in state.requests if "/proxy/" in request["path"]]
        self.assertEqual([request["method"] for request in proxy_requests], ["GET", "POST"])
        self.assertEqual(
            proxy_requests[-1]["body"],
            {
                "filterGroups": [],
                "limit": worker.MAX_HUBSPOT_DEALS,
                "properties": list(worker.HUBSPOT_DEAL_PROPERTIES),
                "sorts": ["-hs_lastmodifieddate"],
            },
        )
        self.assertNotIn("provider-access-secret", json.dumps(result))

    def test_hubspot_read_rejects_extra_scope_before_provider_egress(self) -> None:
        with broker_client() as (client, state):
            state.accounts = [
                connected_hubspot_account(
                    scopes=[worker.HUBSPOT_SCOPE, "crm.objects.deals.write"]
                )
            ]
            with self.assertRaisesRegex(worker.WorkerError, "not ready"):
                client.read_recent_hubspot_deals(
                    "ryu_abcdefghijklmnop",
                    "apn_owned123",
                )
        self.assertFalse(any("/proxy/" in request["path"] for request in state.requests))

    def test_hubspot_read_rejects_duplicate_and_unbounded_provider_content(self) -> None:
        with broker_client() as (client, state):
            state.accounts = [connected_hubspot_account()]
            state.hubspot_pipelines = [hubspot_pipeline()]
            state.hubspot_deals = [hubspot_deal(), hubspot_deal()]
            state.hubspot_total = 2
            with self.assertRaisesRegex(worker.WorkerError, "duplicate"):
                client.read_recent_hubspot_deals(
                    "ryu_abcdefghijklmnop",
                    "apn_owned123",
                )

            oversized = hubspot_deal("123457")
            properties = oversized["properties"]
            assert isinstance(properties, dict)
            properties["dealname"] = "x" * (worker.MAX_HUBSPOT_DEAL_TEXT_BYTES + 1)
            state.hubspot_deals = [oversized]
            state.hubspot_total = 1
            with self.assertRaisesRegex(worker.WorkerError, "invalid text"):
                client.read_recent_hubspot_deals(
                    "ryu_abcdefghijklmnop",
                    "apn_owned123",
                )

    def test_hubspot_read_rejects_invalid_pagination_and_timestamps(self) -> None:
        with broker_client() as (client, state):
            state.accounts = [connected_hubspot_account()]
            state.hubspot_pipelines = [hubspot_pipeline()]
            state.hubspot_deals = [hubspot_deal()]
            state.hubspot_total = 1
            state.hubspot_after = "bad\nsecret"
            with self.assertRaisesRegex(worker.WorkerError, "pagination"):
                client.read_recent_hubspot_deals(
                    "ryu_abcdefghijklmnop",
                    "apn_owned123",
                )

            invalid_timestamp = hubspot_deal()
            invalid_timestamp["createdAt"] = 1723723200000
            state.hubspot_deals = [invalid_timestamp]
            state.hubspot_after = None
            with self.assertRaisesRegex(worker.WorkerError, "timestamps"):
                client.read_recent_hubspot_deals(
                    "ryu_abcdefghijklmnop",
                    "apn_owned123",
                )

    def test_hubspot_read_rejects_aggregate_pipeline_content(self) -> None:
        with broker_client() as (client, state):
            state.accounts = [connected_hubspot_account()]
            state.hubspot_pipelines = [
                {
                    "id": f"pipeline_{index}",
                    "label": "x" * worker.MAX_HUBSPOT_DEAL_TEXT_BYTES,
                    "archived": False,
                    "stages": [],
                }
                for index in range(
                    worker.MAX_HUBSPOT_TOTAL_BYTES
                    // worker.MAX_HUBSPOT_DEAL_TEXT_BYTES
                    + 1
                )
            ]
            with self.assertRaisesRegex(worker.WorkerError, "pipeline content"):
                client.read_recent_hubspot_deals(
                    "ryu_abcdefghijklmnop",
                    "apn_owned123",
                )

    def test_hubspot_read_uses_one_deadline_for_all_broker_calls(self) -> None:
        class DeadlineClient(worker.PipedreamClient):
            def __init__(self) -> None:
                self.deadlines: list[float] = []

            def _owned_account(
                self,
                user: str,
                requested_account: str,
                scope: str,
                *,
                integration: str = "google-drive",
                deadline: float | None = None,
            ) -> tuple[str, dict[str, object]]:
                del user, requested_account, scope, integration
                assert deadline is not None
                self.deadlines.append(deadline)
                return "token", {
                    "healthy": True,
                    "authorized_scopes": [worker.HUBSPOT_SCOPE],
                }

            def _proxy_json(
                self,
                token: str,
                *,
                user: str,
                account: str,
                target: str,
                deadline: float | None = None,
            ) -> object:
                del token, user, account, target
                assert deadline is not None
                self.deadlines.append(deadline)
                return {"results": [hubspot_pipeline()]}

            def _proxy_json_post(
                self,
                token: str,
                *,
                user: str,
                account: str,
                target: str,
                payload: object,
                deadline: float | None = None,
            ) -> object:
                del token, user, account, target, payload
                assert deadline is not None
                self.deadlines.append(deadline)
                return {"results": [], "total": 0}

        client = DeadlineClient()
        with mock.patch.object(worker.time, "monotonic", return_value=100.0):
            client.read_recent_hubspot_deals(
                "ryu_abcdefghijklmnop", "apn_owned123"
            )

        self.assertEqual(
            client.deadlines,
            [100.0 + worker.HUBSPOT_OPERATION_TIMEOUT_SECONDS] * 3,
        )

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

    def test_reconcile_allows_only_reviewed_identity_scopes_beside_the_operation(self) -> None:
        with broker_client() as (client, state):
            state.accounts = [
                connected_gmail_account(scopes=[worker.GMAIL_SCOPE, "openid", "email"])
            ]
            _token, result = client.reconcile(
                "ryu_abcdefghijklmnop",
                integration="gmail",
            )
            self.assertEqual(result["status"], "ready")

            for extra_scope in (
                worker.GOOGLE_DRIVE_SCOPE,
                "https://www.googleapis.com/auth/calendar.readonly",
                "https://www.googleapis.com/auth/cloud-platform",
                "vendor.example/arbitrary",
            ):
                with self.subTest(extra_scope=extra_scope):
                    state.accounts = [
                        connected_gmail_account(
                            scopes=[worker.GMAIL_SCOPE, extra_scope]
                        )
                    ]
                    _token, result = client.reconcile(
                        "ryu_abcdefghijklmnop",
                        integration="gmail",
                    )
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

            state.accounts = [
                connected_gmail_account(
                    scopes=[worker.GMAIL_SCOPE, worker.GMAIL_FULL_ACCESS_SCOPE]
                )
            ]
            with self.assertRaisesRegex(worker.WorkerError, "not ready"):
                client.read_recent_gmail(
                    "ryu_abcdefghijklmnop",
                    "apn_owned123",
                )

    def test_read_recent_gmail_ignores_text_attachments(self) -> None:
        with broker_client() as (client, state):
            state.accounts = [connected_gmail_account()]
            state.gmail_messages = [{"id": "msg_1"}]
            detail = gmail_message("msg_1", body="inline body")
            attachment_text = base64.urlsafe_b64encode(b"private attachment").decode()
            detail["payload"]["parts"].insert(
                0,
                {
                    "filename": "private.txt",
                    "mimeType": "text/plain",
                    "headers": [
                        {"name": "Content-Disposition", "value": "attachment"}
                    ],
                    "body": {"data": attachment_text, "size": 18},
                },
            )
            state.gmail_message_details["msg_1"] = detail
            result = client.read_recent_gmail(
                "ryu_abcdefghijklmnop",
                "apn_owned123",
            )

        self.assertEqual(result["results"][0]["content"], "inline body")

    def test_read_recent_gmail_ignores_text_nested_below_attachment_container(self) -> None:
        with broker_client() as (client, state):
            state.accounts = [connected_gmail_account()]
            state.gmail_messages = [{"id": "msg_1"}]
            detail = gmail_message("msg_1", body="inline body")
            attachment_text = base64.urlsafe_b64encode(b"private attachment").decode()
            detail["payload"]["parts"].insert(
                0,
                {
                    "filename": "archive.mime",
                    "mimeType": "multipart/mixed",
                    "headers": [
                        {"name": "Content-Disposition", "value": "attachment"}
                    ],
                    "body": {},
                    "parts": [
                        {
                            "filename": "",
                            "mimeType": "text/plain",
                            "headers": [],
                            "body": {"data": attachment_text, "size": 18},
                        }
                    ],
                },
            )
            state.gmail_message_details["msg_1"] = detail
            result = client.read_recent_gmail(
                "ryu_abcdefghijklmnop",
                "apn_owned123",
            )

        self.assertEqual(result["results"][0]["content"], "inline body")

    def test_read_recent_gmail_revalidates_inbox_after_listing(self) -> None:
        with broker_client() as (client, state):
            state.accounts = [connected_gmail_account()]
            state.gmail_messages = [{"id": "msg_1"}]
            detail = gmail_message("msg_1")
            detail["labelIds"] = ["UNREAD"]
            state.gmail_message_details["msg_1"] = detail
            with self.assertRaisesRegex(worker.WorkerError, "left the recent-inbox"):
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

    def test_read_upcoming_calendar_freezes_primary_window_and_normalizes_events(self) -> None:
        now = datetime.datetime(2026, 8, 15, 16, 0, tzinfo=datetime.UTC)
        with broker_client() as (client, state):
            state.accounts = [connected_calendar_account()]
            state.calendar_events = [calendar_event()]
            state.calendar_next_page_token = "more-events"
            result = client.read_upcoming_calendar(
                "ryu_abcdefghijklmnop",
                "apn_owned123",
                now=now,
            )

        self.assertEqual(
            result["schema_version"],
            "steward.google-calendar-upcoming-events.v1",
        )
        self.assertEqual(result["calendar"], "primary")
        self.assertEqual(result["window_start"], "2026-08-15T16:00:00Z")
        self.assertEqual(result["window_end"], "2026-08-29T16:00:00Z")
        self.assertTrue(result["has_more"])
        event = result["results"][0]
        self.assertEqual(event["summary"], "Customer renewal review")
        self.assertEqual(event["start"]["kind"], "date_time")
        self.assertEqual(event["organizer"]["email"], "ops@example.com")
        self.assertEqual(event["attendees"][0]["response_status"], "accepted")

        proxy_request = next(
            request
            for request in state.requests
            if "/proxy/" in request["path"]
        )
        encoded = urllib.parse.urlsplit(proxy_request["path"]).path.rsplit("/", 1)[-1]
        encoded += "=" * (-len(encoded) % 4)
        target = urllib.parse.urlsplit(base64.urlsafe_b64decode(encoded).decode())
        self.assertEqual(target.hostname, "www.googleapis.com")
        self.assertEqual(target.path, "/calendar/v3/calendars/primary/events")
        self.assertEqual(
            urllib.parse.parse_qs(target.query),
            {
                "fields": [worker.GOOGLE_CALENDAR_FIELDS],
                "maxAttendees": ["20"],
                "maxResults": ["50"],
                "orderBy": ["startTime"],
                "showDeleted": ["false"],
                "singleEvents": ["true"],
                "timeMax": ["2026-08-29T16:00:00Z"],
                "timeMin": ["2026-08-15T16:00:00Z"],
            },
        )

    def test_read_upcoming_calendar_supports_all_day_events(self) -> None:
        event = calendar_event()
        event["start"] = {"date": "2026-08-18"}
        event["end"] = {"date": "2026-08-19"}
        event.pop("organizer")
        event.pop("attendees")
        with broker_client() as (client, state):
            state.accounts = [connected_calendar_account()]
            state.calendar_events = [event]
            result = client.read_upcoming_calendar(
                "ryu_abcdefghijklmnop",
                "apn_owned123",
            )
        self.assertEqual(
            result["results"][0]["start"],
            {"kind": "date", "value": "2026-08-18"},
        )
        self.assertIsNone(result["results"][0]["organizer"])
        self.assertEqual(result["results"][0]["attendees"], [])

    def test_read_upcoming_calendar_rejects_broader_scope_before_proxy(self) -> None:
        with broker_client() as (client, state):
            state.accounts = [
                connected_calendar_account(
                    scopes=[
                        worker.GOOGLE_CALENDAR_SCOPE,
                        "https://www.googleapis.com/auth/calendar.readonly",
                    ]
                )
            ]
            with self.assertRaisesRegex(worker.WorkerError, "not ready"):
                client.read_upcoming_calendar(
                    "ryu_abcdefghijklmnop",
                    "apn_owned123",
                )
        self.assertFalse(any("/proxy/" in request["path"] for request in state.requests))

    def test_read_upcoming_calendar_rejects_duplicates_and_invalid_page_tokens(self) -> None:
        with broker_client() as (client, state):
            state.accounts = [connected_calendar_account()]
            state.calendar_events = [calendar_event(), calendar_event()]
            with self.assertRaisesRegex(worker.WorkerError, "duplicate"):
                client.read_upcoming_calendar(
                    "ryu_abcdefghijklmnop",
                    "apn_owned123",
                )

            state.calendar_events = []
            state.calendar_next_page_token = "bad\nsecret"
            with self.assertRaisesRegex(worker.WorkerError, "page token"):
                client.read_upcoming_calendar(
                    "ryu_abcdefghijklmnop",
                    "apn_owned123",
                )

    def test_read_upcoming_calendar_rejects_unbounded_or_invalid_event_content(self) -> None:
        cases: tuple[tuple[str, object], ...] = (
            ("description", "x" * ((16 << 10) + 1)),
            ("attendees", [{}] * (worker.MAX_CALENDAR_ATTENDEES + 1)),
            ("start", {"dateTime": "2026-08-16T09:00:00"}),
        )
        with broker_client() as (client, state):
            state.accounts = [connected_calendar_account()]
            for field, invalid in cases:
                with self.subTest(field=field):
                    event = calendar_event()
                    event[field] = invalid
                    state.calendar_events = [event]
                    with self.assertRaises(worker.WorkerError):
                        client.read_upcoming_calendar(
                            "ryu_abcdefghijklmnop",
                            "apn_owned123",
                        )

    def test_read_recent_microsoft_outlook_mail_freezes_query_and_normalizes_preview(self) -> None:
        now = datetime.datetime(2026, 8, 15, 16, 0, tzinfo=datetime.UTC)
        with broker_client() as (client, state):
            state.accounts = [connected_microsoft_outlook_account()]
            state.microsoft_outlook_messages = [microsoft_outlook_message()]
            state.microsoft_outlook_message_next_link = (
                "https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messages?$skiptoken=next"
            )
            result = client.read_recent_microsoft_outlook_messages(
                "ryu_abcdefghijklmnop", "apn_owned123", now=now
            )

        self.assertEqual(
            result["schema_version"],
            "steward.microsoft-outlook-recent-messages.v1",
        )
        self.assertEqual(result["window_start"], "2026-07-16T16:00:00Z")
        self.assertEqual(result["window_end"], "2026-08-15T16:00:00Z")
        self.assertTrue(result["has_more"])
        message = result["results"][0]
        self.assertEqual(message["subject"], "Renewal next steps")
        self.assertEqual(message["content_source"], "body_preview")
        self.assertEqual(message["from"]["email"], "customer@example.com")
        self.assertEqual(message["to"][0]["email"], "ops@example.com")

        proxy_request = next(
            request for request in state.requests if "/proxy/" in request["path"]
        )
        encoded = urllib.parse.urlsplit(proxy_request["path"]).path.rsplit("/", 1)[-1]
        encoded += "=" * (-len(encoded) % 4)
        target = urllib.parse.urlsplit(base64.urlsafe_b64decode(encoded).decode())
        self.assertEqual(target.hostname, "graph.microsoft.com")
        self.assertEqual(target.path, "/v1.0/me/mailFolders/inbox/messages")
        self.assertEqual(
            urllib.parse.parse_qs(target.query),
            {
                "$filter": ["receivedDateTime ge 2026-07-16T16:00:00Z"],
                "$orderby": ["receivedDateTime desc"],
                "$select": [
                    "id,conversationId,subject,from,toRecipients,receivedDateTime,"
                    "isRead,importance,bodyPreview"
                ],
                "$top": ["20"],
            },
        )

    def test_read_upcoming_microsoft_outlook_calendar_freezes_window_and_normalizes(self) -> None:
        now = datetime.datetime(2026, 8, 15, 16, 0, tzinfo=datetime.UTC)
        with broker_client() as (client, state):
            state.accounts = [connected_microsoft_outlook_calendar_account()]
            state.microsoft_outlook_events = [microsoft_outlook_event()]
            result = client.read_upcoming_microsoft_outlook_events(
                "ryu_abcdefghijklmnop", "apn_owned123", now=now
            )

        self.assertEqual(
            result["schema_version"],
            "steward.microsoft-outlook-upcoming-events.v2",
        )
        self.assertEqual(result["window_start"], "2026-08-15T16:00:00Z")
        self.assertEqual(result["window_end"], "2026-08-29T16:00:00Z")
        event = result["results"][0]
        self.assertEqual(event["subject"], "Customer renewal review")
        self.assertEqual(event["location"], "Conference room 1")
        self.assertEqual(event["attendees"][0]["response"], "accepted")
        self.assertEqual(event["start"], {"date_time": "2026-08-18T16:00:00", "time_zone": "UTC"})

        proxy_request = next(
            request for request in state.requests if "/proxy/" in request["path"]
        )
        encoded = urllib.parse.urlsplit(proxy_request["path"]).path.rsplit("/", 1)[-1]
        encoded += "=" * (-len(encoded) % 4)
        target = urllib.parse.urlsplit(base64.urlsafe_b64decode(encoded).decode())
        query = urllib.parse.parse_qs(target.query)
        self.assertEqual(target.hostname, "graph.microsoft.com")
        self.assertEqual(target.path, "/v1.0/me/calendarView")
        self.assertEqual(query["$top"], ["50"])
        self.assertEqual(query["startDateTime"], ["2026-08-15T16:00:00Z"])
        self.assertEqual(query["endDateTime"], ["2026-08-29T16:00:00Z"])
        self.assertEqual(proxy_request["proxy_prefer"], 'outlook.timezone="UTC"')

    def test_read_upcoming_microsoft_outlook_calendar_accepts_absent_location(self) -> None:
        with broker_client() as (client, state):
            state.accounts = [connected_microsoft_outlook_calendar_account()]
            event = microsoft_outlook_event()
            event["location"] = None
            state.microsoft_outlook_events = [event]
            result = client.read_upcoming_microsoft_outlook_events(
                "ryu_abcdefghijklmnop", "apn_owned123"
            )

        self.assertEqual(result["results"][0]["location"], "")

    def test_microsoft_outlook_operations_reject_broader_scopes_and_unsafe_results(self) -> None:
        with broker_client() as (client, state):
            state.accounts = [
                connected_microsoft_outlook_account(
                    scopes=[worker.MICROSOFT_OUTLOOK_SCOPE, "Mail.Send"]
                )
            ]
            with self.assertRaisesRegex(worker.WorkerError, "not ready"):
                client.read_recent_microsoft_outlook_messages(
                    "ryu_abcdefghijklmnop", "apn_owned123"
                )
            self.assertFalse(any("/proxy/" in item["path"] for item in state.requests))

        with broker_client() as (client, state):
            state.accounts = [connected_microsoft_outlook_calendar_account()]
            local_time = microsoft_outlook_event()
            local_time["start"] = {
                "dateTime": "2026-08-18T09:00:00",
                "timeZone": "Pacific Standard Time",
            }
            state.microsoft_outlook_events = [local_time]
            with self.assertRaisesRegex(worker.WorkerError, "non-UTC"):
                client.read_upcoming_microsoft_outlook_events(
                    "ryu_abcdefghijklmnop", "apn_owned123"
                )

        with broker_client() as (client, state):
            state.accounts = [connected_microsoft_outlook_calendar_account()]
            state.microsoft_outlook_events = [
                microsoft_outlook_event(), microsoft_outlook_event()
            ]
            with self.assertRaisesRegex(worker.WorkerError, "duplicate"):
                client.read_upcoming_microsoft_outlook_events(
                    "ryu_abcdefghijklmnop", "apn_owned123"
                )

            state.microsoft_outlook_events = []
            state.microsoft_outlook_event_next_link = "https://evil.example/next"
            with self.assertRaisesRegex(worker.WorkerError, "unsafe continuation"):
                client.read_upcoming_microsoft_outlook_events(
                    "ryu_abcdefghijklmnop", "apn_owned123"
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

    def list_connections(
        self,
        user: str,
        integration: str = "google-drive",
    ) -> dict[str, object]:
        return {
            "accounts": [],
            "integration": integration,
            "result_count": 0,
            "schema_version": "steward.managed-account-list.v1",
            "user": user,
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

    def read_upcoming_calendar(self, user: str, account: str) -> dict[str, object]:
        return {
            "schema_version": "test",
            "user": user,
            "account": account,
            "integration": "google-calendar",
        }

    def read_recent_microsoft_outlook_messages(
        self, user: str, account: str
    ) -> dict[str, object]:
        return {
            "schema_version": "test",
            "user": user,
            "account": account,
            "integration": "microsoft-outlook-mail",
        }

    def read_upcoming_microsoft_outlook_events(
        self, user: str, account: str
    ) -> dict[str, object]:
        return {
            "schema_version": "test",
            "user": user,
            "account": account,
            "integration": "microsoft-outlook-calendar",
        }

    def list_slack_channels(self, user: str, account: str) -> dict[str, object]:
        return {
            "schema_version": "test",
            "user": user,
            "account": account,
            "integration": "slack",
        }

    def read_recent_slack_messages(
        self,
        user: str,
        account: str,
        channel: str,
    ) -> dict[str, object]:
        return {
            "schema_version": "test",
            "user": user,
            "account": account,
            "channel": channel,
            "integration": "slack",
        }

    def read_recent_hubspot_deals(self, user: str, account: str) -> dict[str, object]:
        return {
            "schema_version": "test",
            "user": user,
            "account": account,
            "integration": "hubspot",
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

    def test_account_list_routes_are_closed_to_released_integrations(self) -> None:
        with integration_server() as port:
            for integration in (
                "google-drive",
                "gmail",
                "google-calendar",
                "microsoft-outlook-mail",
                "microsoft-outlook-calendar",
                "slack",
                "hubspot",
            ):
                with self.subTest(integration=integration):
                    status, body, headers = call_worker(
                        port,
                        f"/v1/connections/{integration}/accounts",
                        b'{"external_user_id":"ryu_abcdefghijklmnop"}',
                    )
                    self.assertEqual(status, 200)
                    self.assertEqual(body["integration"], integration)
                    self.assertEqual(body["user"], "ryu_abcdefghijklmnop")
                    self.assertEqual(headers["Cache-Control"], "no-store")

            status, body, _headers = call_worker(
                port,
                "/v1/connections/not-released/accounts",
                b'{"external_user_id":"ryu_abcdefghijklmnop"}',
            )
            self.assertEqual((status, body["error"]["code"]), (404, "not_found"))

            status, body, _headers = call_worker(
                port,
                "/v1/connections/gmail/accounts",
                b'{"external_user_id":"ryu_abcdefghijklmnop","include_credentials":true}',
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

    def test_calendar_routes_dispatch_only_exact_finite_operations(self) -> None:
        with integration_server() as port:
            for path, payload in (
                (
                    "/v1/connections/google-calendar/connect-link",
                    b'{"external_user_id":"ryu_abcdefghijklmnop"}',
                ),
                (
                    "/v1/connections/google-calendar/reconcile",
                    b'{"external_user_id":"ryu_abcdefghijklmnop"}',
                ),
                (
                    "/v1/connections/google-calendar/upcoming-events",
                    b'{"account_id":"apn_owned123","external_user_id":"ryu_abcdefghijklmnop"}',
                ),
                (
                    "/v1/connections/google-calendar/revoke",
                    b'{"account_id":"apn_owned123","external_user_id":"ryu_abcdefghijklmnop"}',
                ),
            ):
                with self.subTest(path=path):
                    status, body, _headers = call_worker(port, path, payload)
                    self.assertEqual(status, 200)
                    self.assertEqual(body["integration"], "google-calendar")

            status, body, _headers = call_worker(
                port,
                "/v1/connections/google-calendar/upcoming-events",
                b'{"account_id":"apn_owned123","calendar_id":"other","external_user_id":"ryu_abcdefghijklmnop"}',
            )
            self.assertEqual((status, body["error"]["code"]), (400, "invalid_request"))

    def test_microsoft_outlook_routes_dispatch_only_exact_finite_operations(self) -> None:
        with integration_server() as port:
            for integration, operation in (
                ("microsoft-outlook-mail", "recent-messages"),
                ("microsoft-outlook-calendar", "upcoming-events"),
            ):
                for suffix, payload in (
                    ("connect-link", b'{"external_user_id":"ryu_abcdefghijklmnop"}'),
                    ("reconcile", b'{"external_user_id":"ryu_abcdefghijklmnop"}'),
                    (
                        operation,
                        b'{"account_id":"apn_owned123","external_user_id":"ryu_abcdefghijklmnop"}',
                    ),
                    (
                        "revoke",
                        b'{"account_id":"apn_owned123","external_user_id":"ryu_abcdefghijklmnop"}',
                    ),
                ):
                    path = f"/v1/connections/{integration}/{suffix}"
                    with self.subTest(path=path):
                        status, body, _headers = call_worker(port, path, payload)
                        self.assertEqual(status, 200)
                        self.assertEqual(body["integration"], integration)

            status, body, _headers = call_worker(
                port,
                "/v1/connections/microsoft-outlook-mail/recent-messages",
                b'{"account_id":"apn_owned123","external_user_id":"ryu_abcdefghijklmnop","limit":100}',
            )
            self.assertEqual((status, body["error"]["code"]), (400, "invalid_request"))

    def test_slack_routes_dispatch_only_exact_finite_operations(self) -> None:
        with integration_server() as port:
            for path, payload in (
                (
                    "/v1/connections/slack/connect-link",
                    b'{"external_user_id":"ryu_abcdefghijklmnop"}',
                ),
                (
                    "/v1/connections/slack/reconcile",
                    b'{"external_user_id":"ryu_abcdefghijklmnop"}',
                ),
                (
                    "/v1/connections/slack/channels",
                    b'{"account_id":"apn_owned123","external_user_id":"ryu_abcdefghijklmnop"}',
                ),
                (
                    "/v1/connections/slack/recent-messages",
                    b'{"account_id":"apn_owned123","channel_id":"C123TEAM","external_user_id":"ryu_abcdefghijklmnop"}',
                ),
                (
                    "/v1/connections/slack/revoke",
                    b'{"account_id":"apn_owned123","external_user_id":"ryu_abcdefghijklmnop"}',
                ),
            ):
                with self.subTest(path=path):
                    status, body, _headers = call_worker(port, path, payload)
                    self.assertEqual(status, 200)
                    self.assertEqual(body["integration"], "slack")

            status, body, _headers = call_worker(
                port,
                "/v1/connections/slack/recent-messages",
                b'{"account_id":"apn_owned123","channel_id":"C123TEAM","external_user_id":"ryu_abcdefghijklmnop","limit":100}',
            )
            self.assertEqual((status, body["error"]["code"]), (400, "invalid_request"))

    def test_hubspot_routes_dispatch_only_exact_finite_operations(self) -> None:
        with integration_server() as port:
            for path, payload in (
                (
                    "/v1/connections/hubspot/connect-link",
                    b'{"external_user_id":"ryu_abcdefghijklmnop"}',
                ),
                (
                    "/v1/connections/hubspot/reconcile",
                    b'{"external_user_id":"ryu_abcdefghijklmnop"}',
                ),
                (
                    "/v1/connections/hubspot/recent-deals",
                    b'{"account_id":"apn_owned123","external_user_id":"ryu_abcdefghijklmnop"}',
                ),
                (
                    "/v1/connections/hubspot/revoke",
                    b'{"account_id":"apn_owned123","external_user_id":"ryu_abcdefghijklmnop"}',
                ),
            ):
                with self.subTest(path=path):
                    status, body, _headers = call_worker(port, path, payload)
                    self.assertEqual(status, 200)
                    self.assertEqual(body["integration"], "hubspot")

            status, body, _headers = call_worker(
                port,
                "/v1/connections/hubspot/recent-deals",
                b'{"account_id":"apn_owned123","external_user_id":"ryu_abcdefghijklmnop","limit":1000}',
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
