#!/usr/bin/env python3
"""Finite managed-auth broker for reviewed Steward integration operations."""

from __future__ import annotations

import base64
import datetime
import hashlib
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
import subprocess
import sys
import threading
import time
import unicodedata
import urllib.parse
from collections.abc import Mapping

MAX_REQUEST = 16 << 10
MAX_UPSTREAM = 2 << 20
MAX_RESPONSE = 1 << 20
UPSTREAM_TIMEOUT_SECONDS = 30
CONTENT_BATCH_TIMEOUT_SECONDS = 30
CONNECT_TOKEN_SECONDS = 600
MAX_CONCURRENCY = 8
MAX_HEALTH_CONCURRENCY = 2
CLIENT_READ_TIMEOUT_SECONDS = 5
ACCOUNT_PAGE_SIZE = 100
MAX_ACCOUNT_RESULTS = 1000
PIPEDREAM_API_ORIGIN = "https://api.pipedream.com"
GOOGLE_DRIVE_APP = "google_drive"
GOOGLE_DRIVE_SCOPE = "https://www.googleapis.com/auth/drive.readonly"
GMAIL_APP = "gmail"
GMAIL_SCOPE = "https://www.googleapis.com/auth/gmail.readonly"
GMAIL_FULL_ACCESS_SCOPE = "https://mail.google.com/"
GOOGLE_CALENDAR_APP = "google_calendar"
GOOGLE_CALENDAR_SCOPE = "https://www.googleapis.com/auth/calendar.events.readonly"
MICROSOFT_OUTLOOK_APP = "microsoft_outlook"
MICROSOFT_OUTLOOK_SCOPE = "Mail.Read"
MICROSOFT_OUTLOOK_CALENDAR_APP = "microsoft_outlook_calendar"
MICROSOFT_OUTLOOK_CALENDAR_SCOPE = "Calendars.ReadBasic"
SLACK_APP = "slack"
SLACK_SCOPES = ("channels:history", "channels:read")
HUBSPOT_APP = "hubspot"
HUBSPOT_SCOPE = "crm.objects.deals.read"
GOOGLE_DRIVE_FIELDS = "nextPageToken,files(id,name,mimeType,modifiedTime,size,webViewLink)"
GOOGLE_DRIVE_CONTENT_FIELDS = (
    "id,name,mimeType,modifiedTime,size,webViewLink,capabilities(canDownload)"
)
GOOGLE_DRIVE_CONTENT_FIELD_BYTES = {
    "id": 256,
    "name": 1024,
    "mimeType": 256,
    "modifiedTime": 64,
    "size": 32,
    "webViewLink": 4096,
}
GOOGLE_DOCUMENT_MEDIA_TYPE = "application/vnd.google-apps.document"
GOOGLE_TEXT_EXPORT_MEDIA_TYPE = "text/plain"
SUPPORTED_TEXT_MEDIA_TYPES = frozenset({"text/plain", "text/markdown"})
MAX_CONTENT_FILES = 10
MAX_FILE_CONTENT_BYTES = 64 << 10
MAX_TOTAL_CONTENT_BYTES = 240 << 10
MAX_CONTENT_RESPONSE = 512 << 10
MAX_GMAIL_MESSAGES = 20
MAX_GMAIL_MESSAGE_BYTES = 32 << 10
MAX_GMAIL_TOTAL_BYTES = 240 << 10
MAX_GMAIL_PARTS = 100
MAX_GMAIL_PART_DEPTH = 12
GOOGLE_CALENDAR_WINDOW_DAYS = 14
MAX_CALENDAR_EVENTS = 50
MAX_CALENDAR_ATTENDEES = 20
MAX_CALENDAR_EVENT_BYTES = 32 << 10
MAX_CALENDAR_TOTAL_BYTES = 240 << 10
MICROSOFT_OUTLOOK_WINDOW_DAYS = 30
MAX_MICROSOFT_OUTLOOK_MESSAGES = 20
MAX_MICROSOFT_OUTLOOK_RECIPIENTS = 20
MAX_MICROSOFT_OUTLOOK_MESSAGE_BYTES = 32 << 10
MAX_MICROSOFT_OUTLOOK_TOTAL_BYTES = 240 << 10
MICROSOFT_OUTLOOK_CALENDAR_WINDOW_DAYS = 14
MAX_MICROSOFT_OUTLOOK_EVENTS = 50
MAX_MICROSOFT_OUTLOOK_ATTENDEES = 20
MAX_MICROSOFT_OUTLOOK_EVENT_BYTES = 32 << 10
MAX_MICROSOFT_OUTLOOK_CALENDAR_TOTAL_BYTES = 240 << 10
MAX_SLACK_CHANNELS = 100
MAX_SLACK_MESSAGES = 15
MAX_SLACK_CHANNEL_TEXT_BYTES = 2 << 10
MAX_SLACK_MESSAGE_BYTES = 32 << 10
MAX_SLACK_TOTAL_BYTES = 240 << 10
SLACK_OPERATION_TIMEOUT_SECONDS = 30
MAX_HUBSPOT_DEALS = 100
MAX_HUBSPOT_PIPELINES = 100
MAX_HUBSPOT_STAGES_PER_PIPELINE = 100
MAX_HUBSPOT_DEAL_TEXT_BYTES = 8 << 10
MAX_HUBSPOT_TOTAL_BYTES = 240 << 10
MAX_HUBSPOT_TOTAL_AVAILABLE = (1 << 53) - 1
HUBSPOT_OPERATION_TIMEOUT_SECONDS = 30
HUBSPOT_DEAL_PROPERTIES = (
    "amount",
    "closedate",
    "createdate",
    "dealname",
    "dealstage",
    "hs_is_closed",
    "hs_lastmodifieddate",
    "pipeline",
)
HUBSPOT_DEALS_SEARCH_TARGET = (
    "https://api.hubapi.com/crm/objects/2026-03/deals/search"
)
HUBSPOT_PIPELINES_TARGET = "https://api.hubapi.com/crm/pipelines/2026-03/deals"
GMAIL_MESSAGE_FIELDS = (
    "id,threadId,labelIds,snippet,internalDate,"
    "payload(filename,headers,mimeType,body(data,size),parts)"
)
GMAIL_LIST_TARGET = (
    "https://gmail.googleapis.com/gmail/v1/users/me/messages?"
    + urllib.parse.urlencode(
        {
            "labelIds": "INBOX",
            "maxResults": str(MAX_GMAIL_MESSAGES),
            "q": "newer_than:30d",
        }
    )
)
GOOGLE_CALENDAR_FIELDS = (
    "nextPageToken,timeZone,items(id,status,summary,description,location,eventType,"
    "transparency,visibility,attendeesOmitted,start(date,dateTime,timeZone),"
    "end(date,dateTime,timeZone),organizer(displayName,email,self),"
    "attendees(displayName,email,self,responseStatus,optional))"
)
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
FILE_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,256}$")
CALENDAR_EVENT_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,1024}$")
MICROSOFT_GRAPH_ID_RE = re.compile(r"^[A-Za-z0-9_+=/-]{1,1024}$")
SLACK_CHANNEL_ID_RE = re.compile(r"^C[A-Z0-9]{1,255}$")
SLACK_MESSAGE_TS_RE = re.compile(r"^[0-9]{1,20}\.[0-9]{1,12}$")
SLACK_AUTHOR_ID_RE = re.compile(r"^[A-Z][A-Z0-9]{1,255}$")
HUBSPOT_ID_RE = re.compile(r"^[0-9]{1,32}$")
HUBSPOT_OPAQUE_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")

INTEGRATION_PROFILES = {
    "google-drive": {
        "app": GOOGLE_DRIVE_APP,
        "default_name": "Google Drive",
        "required_scopes": (GOOGLE_DRIVE_SCOPE,),
    },
    "gmail": {
        "app": GMAIL_APP,
        "default_name": "Gmail",
        "required_scopes": (GMAIL_SCOPE,),
    },
    "google-calendar": {
        "app": GOOGLE_CALENDAR_APP,
        "default_name": "Google Calendar",
        "required_scopes": (GOOGLE_CALENDAR_SCOPE,),
    },
    "microsoft-outlook-mail": {
        "app": MICROSOFT_OUTLOOK_APP,
        "default_name": "Outlook Mail",
        "required_scopes": (MICROSOFT_OUTLOOK_SCOPE,),
    },
    "microsoft-outlook-calendar": {
        "app": MICROSOFT_OUTLOOK_CALENDAR_APP,
        "default_name": "Outlook Calendar",
        "required_scopes": (MICROSOFT_OUTLOOK_CALENDAR_SCOPE,),
    },
    "slack": {
        "app": SLACK_APP,
        "default_name": "Slack",
        "required_scopes": SLACK_SCOPES,
    },
    "hubspot": {
        "app": HUBSPOT_APP,
        "default_name": "HubSpot",
        "required_scopes": (HUBSPOT_SCOPE,),
    },
}
REVIEWED_IDENTITY_SCOPES = frozenset(
    {
        "email",
        "openid",
        "profile",
        "https://www.googleapis.com/auth/userinfo.email",
        "https://www.googleapis.com/auth/userinfo.profile",
    }
)
MICROSOFT_IDENTITY_SCOPES = frozenset(
    {"User.Read", "email", "offline_access", "openid", "profile"}
)


class WorkerError(Exception):
    def __init__(
        self,
        status: int,
        code: str,
        message: str,
        *,
        upstream_status: int | None = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.upstream_status = upstream_status


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


def file_ids(value: object) -> tuple[str, ...]:
    if (
        not isinstance(value, list)
        or not 1 <= len(value) <= MAX_CONTENT_FILES
        or any(not isinstance(item, str) or FILE_ID_RE.fullmatch(item) is None for item in value)
        or len(set(value)) != len(value)
    ):
        raise WorkerError(
            400,
            "invalid_file_ids",
            "file IDs must be one through ten unique canonical identifiers",
        )
    return tuple(value)


def slack_channel_id(value: object) -> str:
    if not isinstance(value, str) or SLACK_CHANNEL_ID_RE.fullmatch(value) is None:
        raise WorkerError(
            400,
            "invalid_channel",
            "Slack channel identifier is invalid",
        )
    return value


def _deadline_error() -> WorkerError:
    return WorkerError(
        503,
        "operation_deadline_exceeded",
        "managed integration operation exceeded its deadline",
    )


def _resolver_process(host: str, port: int) -> subprocess.Popen[bytes]:
    script = (
        "import json,socket,sys;"
        "json.dump(socket.getaddrinfo(sys.argv[1],int(sys.argv[2]),"
        "type=socket.SOCK_STREAM),sys.stdout,separators=(',',':'))"
    )
    return subprocess.Popen(
        [sys.executable, "-I", "-c", script, host, str(port)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )


def _validated_resolved_addresses(value: object) -> tuple[tuple[int, int, int, str, tuple], ...]:
    if not isinstance(value, list) or not 1 <= len(value) <= 64:
        raise WorkerError(503, "broker_unavailable", "managed-auth broker is unavailable")
    result: list[tuple[int, int, int, str, tuple]] = []
    for item in value:
        if (
            not isinstance(item, list)
            or len(item) != 5
            or not all(isinstance(item[index], int) for index in range(3))
            or not isinstance(item[3], str)
            or not isinstance(item[4], list)
            or len(item[4]) not in {2, 4}
            or not isinstance(item[4][0], str)
            or not isinstance(item[4][1], int)
        ):
            raise WorkerError(503, "broker_unavailable", "managed-auth broker is unavailable")
        family, socket_type, protocol = item[:3]
        if family not in {socket.AF_INET, socket.AF_INET6} or socket_type != socket.SOCK_STREAM:
            raise WorkerError(503, "broker_unavailable", "managed-auth broker is unavailable")
        try:
            socket.inet_pton(family, item[4][0])
        except OSError:
            raise WorkerError(
                503, "broker_unavailable", "managed-auth broker is unavailable"
            ) from None
        result.append((family, socket_type, protocol, item[3], tuple(item[4])))
    return tuple(result)


def _resolved_addresses(
    host: str,
    port: int,
    *,
    deadline: float | None,
) -> tuple[tuple[int, int, int, str, tuple[object, ...]], ...]:
    """Resolve a configured upstream without letting DNS escape a deadline."""

    if deadline is None:
        return tuple(socket.getaddrinfo(host, port, type=socket.SOCK_STREAM))
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise _deadline_error()
    process = _resolver_process(host, port)
    try:
        raw, _stderr = process.communicate(
            timeout=max(0.0, deadline - time.monotonic())
        )
    except subprocess.TimeoutExpired as error:
        raise _deadline_error() from error
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=1)
    if time.monotonic() >= deadline:
        raise _deadline_error()
    if process.returncode != 0 or len(raw) > 64 << 10:
        raise WorkerError(
            503,
            "broker_unavailable",
            "managed-auth broker is unavailable",
        )
    try:
        return _validated_resolved_addresses(json.loads(raw))
    except (UnicodeError, json.JSONDecodeError):
        raise WorkerError(
            503, "broker_unavailable", "managed-auth broker is unavailable"
        ) from None


def _open_resolved_socket(
    connection: http.client.HTTPConnection,
    addresses: tuple[tuple[int, int, int, str, tuple[object, ...]], ...],
    *,
    deadline: float | None,
) -> None:
    last_error: OSError | None = None
    for family, socket_type, protocol, _canonical_name, address in addresses:
        candidate = socket.socket(family, socket_type, protocol)
        connection.sock = candidate
        try:
            timeout = connection.timeout
            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise _deadline_error()
                timeout = min(timeout, remaining) if timeout is not None else remaining
            candidate.settimeout(timeout)
            candidate.connect(address)
            return
        except WorkerError:
            candidate.close()
            connection.sock = None
            raise
        except OSError as error:
            last_error = error
            candidate.close()
            connection.sock = None
    raise last_error or OSError("managed upstream has no usable address")


class _ResolvedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, *args: object, addresses: tuple, deadline: float | None, **kwargs: object) -> None:
        self._resolved_addresses = addresses
        self._absolute_deadline = deadline
        super().__init__(*args, **kwargs)

    def connect(self) -> None:
        _open_resolved_socket(self, self._resolved_addresses, deadline=self._absolute_deadline)


class _ResolvedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, *args: object, addresses: tuple, deadline: float | None, **kwargs: object) -> None:
        self._resolved_addresses = addresses
        self._absolute_deadline = deadline
        super().__init__(*args, **kwargs)

    def connect(self) -> None:
        _open_resolved_socket(self, self._resolved_addresses, deadline=self._absolute_deadline)
        assert self.sock is not None
        self.sock = self._context.wrap_socket(self.sock, server_hostname=self.host)


class PipedreamClient:
    def __init__(
        self,
        *,
        client_id: bytes,
        client_secret: bytes,
        project_id: str,
        environment: str,
        oauth_app_id: str,
        gmail_oauth_app_id: str = "",
        google_calendar_oauth_app_id: str = "",
        microsoft_outlook_oauth_app_id: str = "",
        microsoft_outlook_calendar_oauth_app_id: str = "",
        slack_oauth_app_id: str = "",
        hubspot_oauth_app_id: str = "",
        api_origin: str = PIPEDREAM_API_ORIGIN,
    ) -> None:
        if not PROJECT_RE.fullmatch(project_id):
            raise RuntimeError("Pipedream project ID is invalid")
        if environment not in {"development", "production"}:
            raise RuntimeError("Pipedream environment is invalid")
        if oauth_app_id and not OAUTH_APP_RE.fullmatch(oauth_app_id):
            raise RuntimeError("Google Drive OAuth app ID is invalid")
        if gmail_oauth_app_id and not OAUTH_APP_RE.fullmatch(gmail_oauth_app_id):
            raise RuntimeError("Gmail OAuth app ID is invalid")
        if google_calendar_oauth_app_id and not OAUTH_APP_RE.fullmatch(
            google_calendar_oauth_app_id
        ):
            raise RuntimeError("Google Calendar OAuth app ID is invalid")
        if microsoft_outlook_oauth_app_id and not OAUTH_APP_RE.fullmatch(
            microsoft_outlook_oauth_app_id
        ):
            raise RuntimeError("Outlook Mail OAuth app ID is invalid")
        if microsoft_outlook_calendar_oauth_app_id and not OAUTH_APP_RE.fullmatch(
            microsoft_outlook_calendar_oauth_app_id
        ):
            raise RuntimeError("Outlook Calendar OAuth app ID is invalid")
        if slack_oauth_app_id and not OAUTH_APP_RE.fullmatch(slack_oauth_app_id):
            raise RuntimeError("Slack OAuth app ID is invalid")
        if hubspot_oauth_app_id and not OAUTH_APP_RE.fullmatch(hubspot_oauth_app_id):
            raise RuntimeError("HubSpot OAuth app ID is invalid")
        if (
            not oauth_app_id
            and not gmail_oauth_app_id
            and not google_calendar_oauth_app_id
            and not microsoft_outlook_oauth_app_id
            and not microsoft_outlook_calendar_oauth_app_id
            and not slack_oauth_app_id
            and not hubspot_oauth_app_id
        ):
            raise RuntimeError("at least one managed OAuth app ID is required")
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
        self.oauth_app_ids = {
            "google-drive": oauth_app_id,
            "gmail": gmail_oauth_app_id,
            "google-calendar": google_calendar_oauth_app_id,
            "microsoft-outlook-mail": microsoft_outlook_oauth_app_id,
            "microsoft-outlook-calendar": microsoft_outlook_calendar_oauth_app_id,
            "slack": slack_oauth_app_id,
            "hubspot": hubspot_oauth_app_id,
        }
        self.origin = parsed

    def _profile(self, integration: str) -> tuple[str, str, tuple[str, ...], str]:
        value = INTEGRATION_PROFILES.get(integration)
        oauth_app_id = self.oauth_app_ids.get(integration, "")
        if value is None or not oauth_app_id:
            raise WorkerError(
                503,
                "integration_not_configured",
                "managed integration is not configured",
            )
        return (
            str(value["app"]),
            str(value["default_name"]),
            tuple(str(scope) for scope in value["required_scopes"]),
            oauth_app_id,
        )

    @staticmethod
    def _allowed_extra_scopes(integration: str) -> frozenset[str]:
        if integration in {"hubspot", "slack"}:
            return frozenset()
        if integration.startswith("microsoft-outlook-"):
            return MICROSOFT_IDENTITY_SCOPES
        return REVIEWED_IDENTITY_SCOPES

    def _request(
        self,
        method: str,
        path: str,
        *,
        payload: object | None = None,
        token: str | None = None,
        proxy_headers: Mapping[str, str] | None = None,
        deadline: float | None = None,
    ) -> object:
        raw, media_type = self._request_bytes(
            method,
            path,
            payload=payload,
            token=token,
            proxy_headers=proxy_headers,
            maximum_bytes=MAX_UPSTREAM,
            deadline=deadline,
        )
        if not raw:
            return {}
        if media_type != "application/json":
            raise WorkerError(
                502,
                "invalid_broker_response",
                "managed-auth broker returned a non-JSON response",
            )
        try:
            return json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise WorkerError(
                502,
                "invalid_broker_response",
                "managed-auth broker returned invalid JSON",
            ) from error

    def _request_bytes(
        self,
        method: str,
        path: str,
        *,
        payload: object | None = None,
        token: str | None = None,
        proxy_headers: Mapping[str, str] | None = None,
        maximum_bytes: int,
        deadline: float | None = None,
    ) -> tuple[bytes, str]:
        if not 1 <= maximum_bytes <= MAX_UPSTREAM:
            raise ValueError("managed-auth response bound is invalid")
        body = (
            None
            if payload is None
            else json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
        )
        headers = {
            "Accept": "*/*",
            "Accept-Encoding": "identity",
            "User-Agent": "steward-integration-worker/1",
        }
        if body is not None:
            headers["Content-Type"] = "application/json"
            headers["Content-Length"] = str(len(body))
        if token is not None:
            headers["Authorization"] = "Bearer " + token
            headers["X-PD-Environment"] = self.environment
        if proxy_headers is not None:
            for name, value in proxy_headers.items():
                if (
                    re.fullmatch(r"X-PD-Proxy-[A-Za-z0-9-]{1,64}", name) is None
                    or not isinstance(value, str)
                    or not 1 <= len(value) <= 256
                    or any(ord(character) < 0x20 or ord(character) > 0x7E for character in value)
                    or name.casefold() in {header.casefold() for header in headers}
                ):
                    raise ValueError("managed-auth proxy header is invalid")
                headers[name] = value
        headers["Host"] = self.origin.netloc
        timeout = UPSTREAM_TIMEOUT_SECONDS
        if deadline is not None:
            timeout = min(timeout, deadline - time.monotonic())
            if timeout <= 0:
                raise _deadline_error()
        port = self.origin.port or (443 if self.origin.scheme == "https" else 80)
        addresses = _resolved_addresses(self.origin.hostname, port, deadline=deadline)
        connection_type = (
            _ResolvedHTTPSConnection if self.origin.scheme == "https" else _ResolvedHTTPConnection
        )
        connection = connection_type(
            self.origin.hostname,
            self.origin.port,
            timeout=timeout,
            addresses=addresses,
            deadline=deadline,
            **({"context": ssl.create_default_context()} if self.origin.scheme == "https" else {}),
        )
        expired = threading.Event()
        deadline_timer: threading.Timer | None = None
        if deadline is not None:
            def expire_connection() -> None:
                expired.set()
                active_socket = connection.sock
                if active_socket is not None:
                    try:
                        active_socket.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
                connection.close()

            deadline_timer = threading.Timer(timeout, expire_connection)
            deadline_timer.daemon = True
            deadline_timer.start()

        def require_live_deadline() -> None:
            if expired.is_set() or (
                deadline is not None and time.monotonic() >= deadline
            ):
                raise _deadline_error()

        try:
            connection.request(method, path, body=body, headers=headers)
            require_live_deadline()
            response = connection.getresponse()
            require_live_deadline()
            chunks: list[bytes] = []
            received = 0
            while received <= maximum_bytes:
                require_live_deadline()
                active_socket = connection.sock
                if active_socket is not None and deadline is not None:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        require_live_deadline()
                    active_socket.settimeout(min(UPSTREAM_TIMEOUT_SECONDS, remaining))
                chunk = response.read1(min(64 << 10, maximum_bytes + 1 - received))
                require_live_deadline()
                if not chunk:
                    break
                chunks.append(chunk)
                received += len(chunk)
            raw = b"".join(chunks)
            if len(raw) > maximum_bytes:
                raise WorkerError(
                    502,
                    "broker_response_too_large",
                    "managed-auth broker response exceeded the operation bound",
                )
            if response.headers.get("Content-Encoding", "identity").lower() != "identity":
                raise WorkerError(
                    502,
                    "invalid_broker_response",
                    "managed-auth broker returned encoded content",
                )
            if response.status < 200 or response.status >= 300:
                code = "broker_rate_limited" if response.status == 429 else "broker_rejected"
                status = 503 if response.status == 429 or response.status >= 500 else 502
                raise WorkerError(
                    status,
                    code,
                    f"managed-auth broker returned HTTP {response.status}",
                    upstream_status=response.status,
                )
            return raw, response.headers.get_content_type().lower()
        except WorkerError:
            raise
        except (OSError, TimeoutError, http.client.HTTPException) as error:
            if expired.is_set():
                raise WorkerError(
                    503,
                    "operation_deadline_exceeded",
                    "managed integration operation exceeded its deadline",
                ) from error
            raise WorkerError(503, "broker_unavailable", "managed-auth broker is unavailable") from error
        finally:
            if deadline_timer is not None:
                deadline_timer.cancel()
            connection.close()

    def access_token(self, scope: str, *, deadline: float | None = None) -> str:
        result = self._request(
            "POST",
            "/v1/oauth/token",
            payload={
                "client_id": self.client_id.decode("ascii"),
                "client_secret": self.client_secret.decode("ascii"),
                "grant_type": "client_credentials",
                "scope": scope,
            },
            deadline=deadline,
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

    def connect_link(self, user: str, integration: str = "google-drive") -> dict[str, object]:
        app, _default_name, _required_scopes, oauth_app_id = self._profile(integration)
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
        query.extend((("app", app), ("oauthAppId", oauth_app_id)))
        link = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urllib.parse.urlencode(query), ""))
        return {
            "schema_version": "steward.managed-connect-link.v1",
            "integration": integration,
            "connect_url": link,
            "expires_at": expires_at,
        }

    def _accounts(
        self,
        user: str,
        scope: str,
        integration: str = "google-drive",
    ) -> tuple[str, list[object]]:
        app, _default_name, _required_scopes, oauth_app_id = self._profile(integration)
        token = self.access_token(scope)
        accounts: list[object] = []
        after: str | None = None
        seen_cursors: set[str] = set()
        expected_total: int | None = None
        while len(accounts) < MAX_ACCOUNT_RESULTS:
            parameters = {
                "app": app,
                "external_user_id": user,
                "include_credentials": "false",
                "limit": str(ACCOUNT_PAGE_SIZE),
                "oauth_app_id": oauth_app_id,
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
    def _safe_account(
        value: object,
        user: str,
        *,
        expected_app: str = GOOGLE_DRIVE_APP,
        default_name: str = "Google Drive",
    ) -> dict[str, object] | None:
        if not isinstance(value, dict):
            return None
        identifier = value.get("id")
        external_id = value.get("external_id")
        provider_app = value.get("app")
        scopes = value.get("authorized_scopes")
        if (
            not isinstance(identifier, str)
            or not ACCOUNT_RE.fullmatch(identifier)
            or external_id != user
            or not isinstance(provider_app, dict)
            or provider_app.get("name_slug") != expected_app
            or not isinstance(scopes, list)
            or any(not isinstance(scope, str) for scope in scopes)
        ):
            return None
        healthy = value.get("healthy") is True and value.get("dead") is not True and not value.get("error")
        account_name = value.get("name")
        if (
            not isinstance(account_name, str)
            or not account_name
            or len(account_name) > 256
            or len(account_name.encode("utf-8")) > 1_024
        ):
            account_name = default_name
        return {
            "account_id": identifier,
            "account_name": account_name,
            "authorized_scopes": sorted(set(scopes)),
            "created_at": value.get("created_at") if isinstance(value.get("created_at"), str) else "",
            "healthy": healthy,
        }

    def _normalized_accounts(
        self,
        user: str,
        scope: str,
        integration: str,
    ) -> tuple[str, tuple[dict[str, object], ...], tuple[str, ...]]:
        app, default_name, required_scopes, _oauth_app_id = self._profile(integration)
        token, raw_accounts = self._accounts(user, scope, integration)
        accounts = [
            safe
            for item in raw_accounts
            if (
                safe := self._safe_account(
                    item,
                    user,
                    expected_app=app,
                    default_name=default_name,
                )
            )
            is not None
        ]
        identifiers = [str(item["account_id"]) for item in accounts]
        if len(set(identifiers)) != len(identifiers):
            raise WorkerError(
                502,
                "invalid_broker_response",
                "managed-auth broker returned duplicate accounts",
            )
        accounts.sort(
            key=lambda item: (str(item["created_at"]), str(item["account_id"])),
            reverse=True,
        )
        return token, tuple(accounts), required_scopes

    def list_connections(
        self,
        user: str,
        integration: str = "google-drive",
    ) -> dict[str, object]:
        """Return bounded credential-free choices for one reviewed integration."""

        _token, accounts, required_scopes = self._normalized_accounts(
            user,
            "connect:accounts:read",
            integration,
        )
        allowed_extra_scopes = self._allowed_extra_scopes(integration)
        projected = [
            {
                "account_id": item["account_id"],
                "account_name": item["account_name"],
                "authorized_scopes": item["authorized_scopes"],
                "healthy": item["healthy"],
                "status": (
                    "ready"
                    if self._account_ready(
                        item,
                        required_scopes,
                        allowed_extra_scopes=allowed_extra_scopes,
                    )
                    else "needs_attention"
                ),
            }
            for item in accounts[:100]
        ]
        result: dict[str, object] = {
            "accounts": projected,
            "integration": integration,
            "result_count": len(projected),
            "schema_version": "steward.managed-account-list.v1",
        }
        if len(required_scopes) == 1:
            result["required_scope"] = required_scopes[0]
        else:
            result["required_scopes"] = list(required_scopes)
        return result

    def reconcile(
        self,
        user: str,
        scope: str = "connect:accounts:read",
        integration: str = "google-drive",
    ) -> tuple[str, dict[str, object]]:
        token, normalized, required_scopes = self._normalized_accounts(
            user,
            scope,
            integration,
        )
        accounts = list(normalized)
        selected = next(
            (
                item
                for item in accounts
                if self._account_ready(
                    item,
                    required_scopes,
                    allowed_extra_scopes=self._allowed_extra_scopes(integration),
                )
            ),
            None,
        )
        if selected is None:
            selected = next((item for item in accounts if item["healthy"]), accounts[0] if accounts else None)
        if selected is None:
            return token, {
                "schema_version": (
                    "steward.managed-connection.v2"
                    if len(required_scopes) > 1
                    else "steward.managed-connection.v1"
                ),
                "integration": integration,
                "status": "not_connected",
            }
        result: dict[str, object] = {
            "schema_version": (
                "steward.managed-connection.v2"
                if len(required_scopes) > 1
                else "steward.managed-connection.v1"
            ),
            "integration": integration,
            "status": (
                "ready"
                if self._account_ready(
                    selected,
                    required_scopes,
                    allowed_extra_scopes=self._allowed_extra_scopes(integration),
                )
                else "needs_attention"
            ),
            "account_id": selected["account_id"],
            "account_name": selected["account_name"],
            "authorized_scopes": selected["authorized_scopes"],
            "healthy": selected["healthy"],
        }
        if len(required_scopes) == 1:
            result["required_scope"] = required_scopes[0]
        else:
            result["required_scopes"] = list(required_scopes)
        return token, result

    @staticmethod
    def _account_ready(
        account: Mapping[str, object],
        required_scopes: tuple[str, ...] = (GOOGLE_DRIVE_SCOPE,),
        *,
        allowed_extra_scopes: frozenset[str] = REVIEWED_IDENTITY_SCOPES,
    ) -> bool:
        scopes = account.get("authorized_scopes", [])
        authorized = {scope for scope in scopes if isinstance(scope, str)}
        allowed = set(required_scopes)
        allowed.update(allowed_extra_scopes)
        return (
            account.get("healthy") is True
            and set(required_scopes) <= authorized
            and authorized <= allowed
        )

    def _owned_account(
        self,
        user: str,
        requested_account: str,
        scope: str,
        *,
        integration: str = "google-drive",
        deadline: float | None = None,
    ) -> tuple[str, dict[str, object]]:
        app, default_name, _required_scopes, _oauth_app_id = self._profile(integration)
        token = self.access_token(scope, deadline=deadline)
        query = urllib.parse.urlencode({"include_credentials": "false"})
        value = self._request(
            "GET",
            f"/v1/connect/{self.project_id}/accounts/{urllib.parse.quote(requested_account, safe='')}?{query}",
            token=token,
            deadline=deadline,
        )
        account = self._safe_account(
            value,
            user,
            expected_app=app,
            default_name=default_name,
        )
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

    def list_slack_channels(
        self,
        user: str,
        requested_account: str,
    ) -> dict[str, object]:
        deadline = time.monotonic() + SLACK_OPERATION_TIMEOUT_SECONDS
        token, connection = self._owned_account(
            user,
            requested_account,
            "connect:accounts:read connect:proxy",
            integration="slack",
            deadline=deadline,
        )
        if not self._account_ready(
            connection,
            SLACK_SCOPES,
            allowed_extra_scopes=frozenset(),
        ):
            raise WorkerError(
                409,
                "connection_not_ready",
                "Slack connection is not ready for this app",
            )
        target = "https://slack.com/api/conversations.list?" + urllib.parse.urlencode(
            {
                "exclude_archived": "true",
                "limit": str(MAX_SLACK_CHANNELS),
                "types": "public_channel",
            }
        )
        value = self._slack_result(
            self._proxy_json(
                token,
                user=user,
                account=requested_account,
                target=target,
                deadline=deadline,
            ),
            operation="channel list",
        )
        raw_channels = value.get("channels")
        response_metadata = value.get("response_metadata", {})
        if (
            not isinstance(raw_channels, list)
            or len(raw_channels) > MAX_SLACK_CHANNELS
            or not isinstance(response_metadata, Mapping)
        ):
            raise WorkerError(
                502,
                "invalid_provider_response",
                "Slack returned an invalid channel list",
            )
        channels: list[dict[str, str]] = []
        seen_ids: set[str] = set()
        for item in raw_channels:
            channel = self._slack_channel(item)
            channel_id = channel["channel_id"]
            if channel_id in seen_ids:
                raise WorkerError(
                    502,
                    "invalid_provider_response",
                    "Slack returned duplicate channel identifiers",
                )
            seen_ids.add(channel_id)
            channels.append(channel)
        cursor = response_metadata.get("next_cursor", "")
        if (
            not isinstance(cursor, str)
            or len(cursor.encode()) > 4096
            or any(ord(character) < 0x21 or ord(character) > 0x7E for character in cursor)
        ) and cursor != "":
            raise WorkerError(
                502,
                "invalid_provider_response",
                "Slack returned an invalid channel cursor",
            )
        return {
            "schema_version": "steward.slack-channels.v1",
            "integration": "slack",
            "channels": channels,
            "result_count": len(channels),
            "has_more": bool(cursor),
        }

    def read_recent_slack_messages(
        self,
        user: str,
        requested_account: str,
        requested_channel: str,
    ) -> dict[str, object]:
        """Read the trusted caller's selected channel after provider revalidation.

        End-user choice is authenticated and persisted by the trusted service
        caller. This credential-boundary worker independently verifies
        account ownership, exact scopes, and current public-channel membership;
        it does not claim to authenticate an interactive human.
        """
        channel = slack_channel_id(requested_channel)
        deadline = time.monotonic() + SLACK_OPERATION_TIMEOUT_SECONDS
        token, connection = self._owned_account(
            user,
            requested_account,
            "connect:accounts:read connect:proxy",
            integration="slack",
            deadline=deadline,
        )
        if not self._account_ready(
            connection,
            SLACK_SCOPES,
            allowed_extra_scopes=frozenset(),
        ):
            raise WorkerError(
                409,
                "connection_not_ready",
                "Slack connection is not ready for this app",
            )
        channel_target = "https://slack.com/api/conversations.info?" + urllib.parse.urlencode(
            {
                "channel": channel,
                "include_locale": "false",
                "include_num_members": "false",
            }
        )
        channel_value = self._slack_result(
            self._proxy_json(
                token,
                user=user,
                account=requested_account,
                target=channel_target,
                deadline=deadline,
            ),
            operation="channel check",
        )
        verified_channel = self._slack_channel(channel_value.get("channel"))
        if verified_channel["channel_id"] != channel:
            raise WorkerError(
                502,
                "invalid_provider_response",
                "Slack returned invalid channel metadata",
            )
        target = "https://slack.com/api/conversations.history?" + urllib.parse.urlencode(
            {
                "channel": channel,
                "include_all_metadata": "false",
                "limit": str(MAX_SLACK_MESSAGES),
            }
        )
        value = self._slack_result(
            self._proxy_json(
                token,
                user=user,
                account=requested_account,
                target=target,
                deadline=deadline,
            ),
            operation="channel history",
        )
        raw_messages = value.get("messages")
        response_metadata = value.get("response_metadata", {})
        provider_has_more = value.get("has_more", False)
        if (
            not isinstance(raw_messages, list)
            or len(raw_messages) > MAX_SLACK_MESSAGES
            or not isinstance(response_metadata, Mapping)
            or not isinstance(provider_has_more, bool)
        ):
            raise WorkerError(
                502,
                "invalid_provider_response",
                "Slack returned an invalid channel history",
            )
        messages: list[dict[str, object]] = []
        seen_timestamps: set[str] = set()
        total_bytes = 0
        for item in raw_messages:
            message = self._slack_message(item)
            if message is None:
                continue
            timestamp = str(message["timestamp"])
            if timestamp in seen_timestamps:
                raise WorkerError(
                    502,
                    "invalid_provider_response",
                    "Slack returned duplicate message identifiers",
                )
            seen_timestamps.add(timestamp)
            total_bytes += int(message["content_bytes"])
            if total_bytes > MAX_SLACK_TOTAL_BYTES:
                raise WorkerError(
                    502,
                    "provider_result_limit",
                    "Slack content exceeded the aggregate operation bound",
                )
            messages.append(message)
        cursor = response_metadata.get("next_cursor", "")
        if (
            not isinstance(cursor, str)
            or len(cursor.encode()) > 4096
            or any(ord(character) < 0x21 or ord(character) > 0x7E for character in cursor)
        ) and cursor != "":
            raise WorkerError(
                502,
                "invalid_provider_response",
                "Slack returned an invalid history cursor",
            )
        return {
            "schema_version": "steward.slack-recent-messages.v1",
            "integration": "slack",
            "channel_id": channel,
            "messages": messages,
            "result_count": len(messages),
            "has_more": provider_has_more or bool(cursor),
        }

    def read_recent_hubspot_deals(
        self,
        user: str,
        requested_account: str,
    ) -> dict[str, object]:
        """Read one fixed, bounded CRM pipeline projection.

        The caller cannot choose a query, property, sort, pipeline, stage, page,
        association, or API target. Pipeline labels are joined inside this
        credential boundary so downstream consumers never need another HubSpot
        permission merely to understand the selected deal and stage IDs.
        """

        deadline = time.monotonic() + HUBSPOT_OPERATION_TIMEOUT_SECONDS
        token, connection = self._owned_account(
            user,
            requested_account,
            "connect:accounts:read connect:proxy",
            integration="hubspot",
            deadline=deadline,
        )
        if not self._account_ready(
            connection,
            (HUBSPOT_SCOPE,),
            allowed_extra_scopes=frozenset(),
        ):
            raise WorkerError(
                409,
                "connection_not_ready",
                "HubSpot connection is not ready for this app",
            )
        pipelines_value = self._proxy_json(
            token,
            user=user,
            account=requested_account,
            target=HUBSPOT_PIPELINES_TARGET,
            deadline=deadline,
        )
        pipeline_names, stage_names = self._hubspot_pipeline_labels(pipelines_value)
        deals_value = self._proxy_json_post(
            token,
            user=user,
            account=requested_account,
            target=HUBSPOT_DEALS_SEARCH_TARGET,
            payload={
                "filterGroups": [],
                "limit": MAX_HUBSPOT_DEALS,
                "properties": list(HUBSPOT_DEAL_PROPERTIES),
                "sorts": ["-hs_lastmodifieddate"],
            },
            deadline=deadline,
        )
        if not isinstance(deals_value, Mapping):
            raise WorkerError(
                502,
                "invalid_provider_response",
                "HubSpot returned an invalid deal result",
            )
        raw_deals = deals_value.get("results")
        total_available = deals_value.get("total")
        paging = deals_value.get("paging")
        if (
            not isinstance(raw_deals, list)
            or len(raw_deals) > MAX_HUBSPOT_DEALS
            or not isinstance(total_available, int)
            or isinstance(total_available, bool)
            or total_available < len(raw_deals)
            or total_available > MAX_HUBSPOT_TOTAL_AVAILABLE
            or (paging is not None and not isinstance(paging, Mapping))
        ):
            raise WorkerError(
                502,
                "invalid_provider_response",
                "HubSpot returned an invalid deal result",
            )
        deals: list[dict[str, object]] = []
        seen_ids: set[str] = set()
        total_bytes = 0
        for item in raw_deals:
            deal = self._hubspot_deal(
                item,
                pipeline_names=pipeline_names,
                stage_names=stage_names,
            )
            deal_id = str(deal["deal_id"])
            if deal_id in seen_ids:
                raise WorkerError(
                    502,
                    "invalid_provider_response",
                    "HubSpot returned duplicate deal identifiers",
                )
            seen_ids.add(deal_id)
            total_bytes += len(
                json.dumps(
                    deal,
                    ensure_ascii=False,
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode()
            )
            if total_bytes > MAX_HUBSPOT_TOTAL_BYTES:
                raise WorkerError(
                    502,
                    "provider_result_limit",
                    "HubSpot deal content exceeded the aggregate operation bound",
                )
            deals.append(deal)
        has_more = self._hubspot_has_more(paging)
        return {
            "schema_version": "steward.hubspot-recent-deals.v1",
            "integration": "hubspot",
            "deals": deals,
            "result_count": len(deals),
            "total_available": total_available,
            "has_more": has_more,
        }

    def read_drive_content(
        self,
        user: str,
        requested_account: str,
        requested_file_ids: tuple[str, ...],
    ) -> dict[str, object]:
        selected_ids = file_ids(list(requested_file_ids))
        deadline = time.monotonic() + CONTENT_BATCH_TIMEOUT_SECONDS
        token, connection = self._owned_account(
            user,
            requested_account,
            "connect:accounts:read connect:proxy",
            deadline=deadline,
        )
        if not self._account_ready(connection):
            raise WorkerError(
                409,
                "connection_not_ready",
                "Google Drive connection is not ready for this app",
            )
        results: list[dict[str, object]] = []
        total_content_bytes = 0
        for selected_id in selected_ids:
            metadata = self._drive_file_metadata(
                token,
                user=user,
                account=requested_account,
                selected_id=selected_id,
                deadline=deadline,
            )
            if metadata is None:
                results.append({"file_id": selected_id, "status": "not_found"})
                continue
            result = self._drive_file_content(
                token,
                user=user,
                account=requested_account,
                metadata=metadata,
                deadline=deadline,
            )
            content_bytes = result.get("content_bytes", 0)
            if isinstance(content_bytes, int) and not isinstance(content_bytes, bool):
                total_content_bytes += content_bytes
            if total_content_bytes > MAX_TOTAL_CONTENT_BYTES:
                raise WorkerError(
                    502,
                    "provider_result_limit",
                    "Google Drive content exceeded the aggregate operation bound",
                )
            results.append(result)
        return {
            "schema_version": "steward.google-drive-content.v1",
            "integration": "google-drive",
            "results": results,
            "result_count": len(results),
        }

    def _drive_file_metadata(
        self,
        token: str,
        *,
        user: str,
        account: str,
        selected_id: str,
        deadline: float,
    ) -> dict[str, object] | None:
        target = (
            "https://www.googleapis.com/drive/v3/files/"
            + urllib.parse.quote(selected_id, safe="")
            + "?"
            + urllib.parse.urlencode(
                {
                    "fields": GOOGLE_DRIVE_CONTENT_FIELDS,
                    "supportsAllDrives": "true",
                }
            )
        )
        try:
            value = self._proxy_json(
                token,
                user=user,
                account=account,
                target=target,
                deadline=deadline,
            )
        except WorkerError as error:
            if error.upstream_status == 404:
                return None
            raise
        if not isinstance(value, Mapping):
            raise WorkerError(
                502,
                "invalid_provider_response",
                "Google Drive returned invalid file metadata",
            )
        required = ("id", "name", "mimeType", "webViewLink")
        normalized: dict[str, object] = {}
        for field in (*required, "modifiedTime", "size"):
            item = value.get(field)
            if item is None:
                continue
            if (
                not isinstance(item, str)
                or len(item.encode()) > GOOGLE_DRIVE_CONTENT_FIELD_BYTES[field]
            ):
                raise WorkerError(
                    502,
                    "invalid_provider_response",
                    "Google Drive returned invalid file metadata",
                )
            normalized[field] = item
        capabilities = value.get("capabilities")
        if (
            any(field not in normalized for field in required)
            or normalized["id"] != selected_id
            or not isinstance(capabilities, Mapping)
            or not isinstance(capabilities.get("canDownload"), bool)
        ):
            raise WorkerError(
                502,
                "invalid_provider_response",
                "Google Drive returned invalid file metadata",
            )
        view_url = urllib.parse.urlsplit(str(normalized["webViewLink"]))
        if (
            view_url.scheme != "https"
            or view_url.hostname != "drive.google.com"
            or view_url.username
            or view_url.password
            or view_url.fragment
        ):
            raise WorkerError(
                502,
                "invalid_provider_response",
                "Google Drive returned an unsafe file link",
            )
        normalized["canDownload"] = capabilities["canDownload"]
        return normalized

    def _drive_file_content(
        self,
        token: str,
        *,
        user: str,
        account: str,
        metadata: Mapping[str, object],
        deadline: float,
    ) -> dict[str, object]:
        common = {
            "file_id": metadata["id"],
            "name": metadata["name"],
            "media_type": metadata["mimeType"],
            "modified_at": metadata.get("modifiedTime"),
            "view_url": metadata["webViewLink"],
        }
        if metadata["canDownload"] is not True:
            return {**common, "status": "not_downloadable"}
        provider_media_type = str(metadata["mimeType"])
        selected_id = str(metadata["id"])
        if provider_media_type == GOOGLE_DOCUMENT_MEDIA_TYPE:
            target = (
                "https://www.googleapis.com/drive/v3/files/"
                + urllib.parse.quote(selected_id, safe="")
                + "/export?"
                + urllib.parse.urlencode({"mimeType": GOOGLE_TEXT_EXPORT_MEDIA_TYPE})
            )
            expected_response_types = {GOOGLE_TEXT_EXPORT_MEDIA_TYPE}
        elif provider_media_type in SUPPORTED_TEXT_MEDIA_TYPES:
            target = (
                "https://www.googleapis.com/drive/v3/files/"
                + urllib.parse.quote(selected_id, safe="")
                + "?"
                + urllib.parse.urlencode({"alt": "media", "supportsAllDrives": "true"})
            )
            expected_response_types = {provider_media_type, "text/plain"}
        else:
            return {**common, "status": "unsupported"}
        try:
            raw, response_media_type = self._proxy_bytes(
                token,
                user=user,
                account=account,
                target=target,
                maximum_bytes=MAX_FILE_CONTENT_BYTES,
                deadline=deadline,
            )
        except WorkerError as error:
            if error.code == "broker_response_too_large":
                return {**common, "status": "too_large"}
            if error.upstream_status == 404:
                return {"file_id": selected_id, "status": "not_found"}
            raise
        if response_media_type not in expected_response_types:
            return {**common, "status": "invalid_text"}
        try:
            text = unicodedata.normalize("NFC", raw.decode("utf-8"))
        except UnicodeDecodeError:
            return {**common, "status": "invalid_text"}
        text = text.replace("\r\n", "\n").replace("\r", "\n")
        if any(ord(character) < 0x20 and character not in "\t\n" for character in text):
            return {**common, "status": "invalid_text"}
        normalized = text.encode("utf-8")
        if len(normalized) > MAX_FILE_CONTENT_BYTES:
            return {**common, "status": "too_large"}
        return {
            **common,
            "status": "succeeded",
            "content": text,
            "content_bytes": len(normalized),
            "content_sha256": "sha256:" + hashlib.sha256(normalized).hexdigest(),
        }

    def read_recent_gmail(self, user: str, requested_account: str) -> dict[str, object]:
        deadline = time.monotonic() + CONTENT_BATCH_TIMEOUT_SECONDS
        token, connection = self._owned_account(
            user,
            requested_account,
            "connect:accounts:read connect:proxy",
            integration="gmail",
            deadline=deadline,
        )
        if not self._account_ready(connection, (GMAIL_SCOPE,)):
            raise WorkerError(
                409,
                "connection_not_ready",
                "Gmail connection is not ready for this app",
            )
        listed = self._proxy_json(
            token,
            user=user,
            account=requested_account,
            target=GMAIL_LIST_TARGET,
            deadline=deadline,
        )
        if not isinstance(listed, Mapping):
            raise WorkerError(
                502,
                "invalid_provider_response",
                "Gmail returned an invalid message list",
            )
        raw_messages = listed.get("messages", [])
        next_page_token = listed.get("nextPageToken")
        if not isinstance(raw_messages, list) or len(raw_messages) > MAX_GMAIL_MESSAGES:
            raise WorkerError(
                502,
                "invalid_provider_response",
                "Gmail exceeded the recent-message result bound",
            )
        if next_page_token is not None and (
            not isinstance(next_page_token, str)
            or not 1 <= len(next_page_token) <= 4096
            or any(ord(character) < 0x21 or ord(character) > 0x7E for character in next_page_token)
        ):
            raise WorkerError(
                502,
                "invalid_provider_response",
                "Gmail returned an invalid page token",
            )
        message_ids: list[str] = []
        for item in raw_messages:
            if (
                not isinstance(item, Mapping)
                or not isinstance(item.get("id"), str)
                or FILE_ID_RE.fullmatch(str(item["id"])) is None
                or item["id"] in message_ids
            ):
                raise WorkerError(
                    502,
                    "invalid_provider_response",
                    "Gmail returned invalid message identifiers",
                )
            message_ids.append(str(item["id"]))
        results: list[dict[str, object]] = []
        total_content_bytes = 0
        for message_id in message_ids:
            target = (
                "https://gmail.googleapis.com/gmail/v1/users/me/messages/"
                + urllib.parse.quote(message_id, safe="")
                + "?"
                + urllib.parse.urlencode(
                    {"fields": GMAIL_MESSAGE_FIELDS, "format": "full"}
                )
            )
            try:
                value = self._proxy_json(
                    token,
                    user=user,
                    account=requested_account,
                    target=target,
                    deadline=deadline,
                )
            except WorkerError as error:
                if error.upstream_status == 404:
                    results.append({"message_id": message_id, "status": "not_found"})
                    continue
                if error.code == "broker_response_too_large":
                    results.append({"message_id": message_id, "status": "too_large"})
                    continue
                raise
            result = self._gmail_message(value, message_id)
            content_bytes = result.get("content_bytes", 0)
            if isinstance(content_bytes, int) and not isinstance(content_bytes, bool):
                total_content_bytes += content_bytes
            if total_content_bytes > MAX_GMAIL_TOTAL_BYTES:
                raise WorkerError(
                    502,
                    "provider_result_limit",
                    "Gmail content exceeded the aggregate operation bound",
                )
            results.append(result)
        return {
            "schema_version": "steward.gmail-recent-messages.v1",
            "integration": "gmail",
            "window_days": 30,
            "results": results,
            "result_count": len(results),
            "has_more": next_page_token is not None,
        }

    def read_upcoming_calendar(
        self,
        user: str,
        requested_account: str,
        *,
        now: datetime.datetime | None = None,
    ) -> dict[str, object]:
        deadline = time.monotonic() + CONTENT_BATCH_TIMEOUT_SECONDS
        token, connection = self._owned_account(
            user,
            requested_account,
            "connect:accounts:read connect:proxy",
            integration="google-calendar",
            deadline=deadline,
        )
        if not self._account_ready(connection, (GOOGLE_CALENDAR_SCOPE,)):
            raise WorkerError(
                409,
                "connection_not_ready",
                "Google Calendar connection is not ready for this app",
            )
        window_start = now or datetime.datetime.now(datetime.UTC)
        if window_start.tzinfo is None or window_start.utcoffset() is None:
            raise ValueError("calendar clock must be timezone-aware")
        window_start = window_start.astimezone(datetime.UTC).replace(microsecond=0)
        window_end = window_start + datetime.timedelta(days=GOOGLE_CALENDAR_WINDOW_DAYS)
        parameters = {
            "fields": GOOGLE_CALENDAR_FIELDS,
            "maxAttendees": str(MAX_CALENDAR_ATTENDEES),
            "maxResults": str(MAX_CALENDAR_EVENTS),
            "orderBy": "startTime",
            "showDeleted": "false",
            "singleEvents": "true",
            "timeMax": self._rfc3339(window_end),
            "timeMin": self._rfc3339(window_start),
        }
        target = (
            "https://www.googleapis.com/calendar/v3/calendars/primary/events?"
            + urllib.parse.urlencode(parameters)
        )
        value = self._proxy_json(
            token,
            user=user,
            account=requested_account,
            target=target,
            deadline=deadline,
        )
        if not isinstance(value, Mapping):
            raise WorkerError(
                502,
                "invalid_provider_response",
                "Google Calendar returned an invalid event list",
            )
        raw_events = value.get("items", [])
        page_token = value.get("nextPageToken")
        calendar_time_zone = value.get("timeZone", "")
        if (
            not isinstance(raw_events, list)
            or len(raw_events) > MAX_CALENDAR_EVENTS
            or not isinstance(calendar_time_zone, str)
            or not 1 <= len(calendar_time_zone.encode()) <= 256
        ):
            raise WorkerError(
                502,
                "invalid_provider_response",
                "Google Calendar exceeded the upcoming-event result bound",
            )
        if page_token is not None and (
            not isinstance(page_token, str)
            or not 1 <= len(page_token) <= 4096
            or any(
                ord(character) < 0x21 or ord(character) > 0x7E
                for character in page_token
            )
        ):
            raise WorkerError(
                502,
                "invalid_provider_response",
                "Google Calendar returned an invalid page token",
            )
        results: list[dict[str, object]] = []
        seen_ids: set[str] = set()
        total_bytes = 0
        for raw_event in raw_events:
            event = self._calendar_event(raw_event)
            event_id = str(event["event_id"])
            if event_id in seen_ids:
                raise WorkerError(
                    502,
                    "invalid_provider_response",
                    "Google Calendar returned duplicate event identifiers",
                )
            seen_ids.add(event_id)
            event_bytes = len(
                json.dumps(
                    event,
                    ensure_ascii=False,
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode()
            )
            if event_bytes > MAX_CALENDAR_EVENT_BYTES:
                raise WorkerError(
                    502,
                    "provider_result_limit",
                    "Google Calendar event content exceeded its bound",
                )
            total_bytes += event_bytes
            if total_bytes > MAX_CALENDAR_TOTAL_BYTES:
                raise WorkerError(
                    502,
                    "provider_result_limit",
                    "Google Calendar content exceeded the aggregate operation bound",
                )
            results.append(event)
        return {
            "schema_version": "steward.google-calendar-upcoming-events.v1",
            "integration": "google-calendar",
            "calendar": "primary",
            "calendar_time_zone": self._safe_text(
                calendar_time_zone,
                maximum_bytes=256,
                provider="Google Calendar",
            ),
            "window_start": self._rfc3339(window_start),
            "window_end": self._rfc3339(window_end),
            "results": results,
            "result_count": len(results),
            "has_more": page_token is not None,
        }

    def read_recent_microsoft_outlook_messages(
        self,
        user: str,
        requested_account: str,
        *,
        now: datetime.datetime | None = None,
    ) -> dict[str, object]:
        deadline = time.monotonic() + CONTENT_BATCH_TIMEOUT_SECONDS
        token, connection = self._owned_account(
            user,
            requested_account,
            "connect:accounts:read connect:proxy",
            integration="microsoft-outlook-mail",
            deadline=deadline,
        )
        if not self._account_ready(
            connection,
            (MICROSOFT_OUTLOOK_SCOPE,),
            allowed_extra_scopes=MICROSOFT_IDENTITY_SCOPES,
        ):
            raise WorkerError(
                409,
                "connection_not_ready",
                "Outlook Mail connection is not ready for this app",
            )
        window_end = now or datetime.datetime.now(datetime.UTC)
        if window_end.tzinfo is None or window_end.utcoffset() is None:
            raise ValueError("Outlook Mail clock must be timezone-aware")
        window_end = window_end.astimezone(datetime.UTC).replace(microsecond=0)
        window_start = window_end - datetime.timedelta(days=MICROSOFT_OUTLOOK_WINDOW_DAYS)
        parameters = {
            "$filter": f"receivedDateTime ge {self._rfc3339(window_start)}",
            "$orderby": "receivedDateTime desc",
            "$select": (
                "id,conversationId,subject,from,toRecipients,receivedDateTime,"
                "isRead,importance,bodyPreview"
            ),
            "$top": str(MAX_MICROSOFT_OUTLOOK_MESSAGES),
        }
        target = (
            "https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messages?"
            + urllib.parse.urlencode(parameters)
        )
        value = self._proxy_json(
            token,
            user=user,
            account=requested_account,
            target=target,
            deadline=deadline,
        )
        if not isinstance(value, Mapping):
            raise WorkerError(
                502,
                "invalid_provider_response",
                "Outlook Mail returned an invalid message list",
            )
        raw_messages = value.get("value", [])
        next_link = value.get("@odata.nextLink")
        if not isinstance(raw_messages, list) or len(raw_messages) > MAX_MICROSOFT_OUTLOOK_MESSAGES:
            raise WorkerError(
                502,
                "invalid_provider_response",
                "Outlook Mail exceeded the recent-message result bound",
            )
        self._validate_microsoft_next_link(next_link, provider="Outlook Mail")
        results: list[dict[str, object]] = []
        seen_ids: set[str] = set()
        total_bytes = 0
        for raw_message in raw_messages:
            message = self._microsoft_outlook_message(raw_message)
            message_id = str(message["message_id"])
            if message_id in seen_ids:
                raise WorkerError(
                    502,
                    "invalid_provider_response",
                    "Outlook Mail returned duplicate message identifiers",
                )
            seen_ids.add(message_id)
            message_bytes = len(
                json.dumps(message, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode()
            )
            if message_bytes > MAX_MICROSOFT_OUTLOOK_MESSAGE_BYTES:
                raise WorkerError(
                    502,
                    "provider_result_limit",
                    "Outlook Mail message content exceeded its bound",
                )
            total_bytes += message_bytes
            if total_bytes > MAX_MICROSOFT_OUTLOOK_TOTAL_BYTES:
                raise WorkerError(
                    502,
                    "provider_result_limit",
                    "Outlook Mail content exceeded the aggregate operation bound",
                )
            results.append(message)
        return {
            "schema_version": "steward.microsoft-outlook-recent-messages.v1",
            "integration": "microsoft-outlook-mail",
            "folder": "inbox",
            "window_days": MICROSOFT_OUTLOOK_WINDOW_DAYS,
            "window_start": self._rfc3339(window_start),
            "window_end": self._rfc3339(window_end),
            "results": results,
            "result_count": len(results),
            "has_more": next_link is not None,
        }

    def read_upcoming_microsoft_outlook_events(
        self,
        user: str,
        requested_account: str,
        *,
        now: datetime.datetime | None = None,
    ) -> dict[str, object]:
        deadline = time.monotonic() + CONTENT_BATCH_TIMEOUT_SECONDS
        token, connection = self._owned_account(
            user,
            requested_account,
            "connect:accounts:read connect:proxy",
            integration="microsoft-outlook-calendar",
            deadline=deadline,
        )
        if not self._account_ready(
            connection,
            (MICROSOFT_OUTLOOK_CALENDAR_SCOPE,),
            allowed_extra_scopes=MICROSOFT_IDENTITY_SCOPES,
        ):
            raise WorkerError(
                409,
                "connection_not_ready",
                "Outlook Calendar connection is not ready for this app",
            )
        window_start = now or datetime.datetime.now(datetime.UTC)
        if window_start.tzinfo is None or window_start.utcoffset() is None:
            raise ValueError("Outlook Calendar clock must be timezone-aware")
        window_start = window_start.astimezone(datetime.UTC).replace(microsecond=0)
        window_end = window_start + datetime.timedelta(
            days=MICROSOFT_OUTLOOK_CALENDAR_WINDOW_DAYS
        )
        parameters = {
            "$orderby": "start/dateTime",
            "$select": (
                "id,subject,start,end,location,organizer,attendees,isAllDay,"
                "isCancelled,showAs,sensitivity,type"
            ),
            "$top": str(MAX_MICROSOFT_OUTLOOK_EVENTS),
            "endDateTime": self._rfc3339(window_end),
            "startDateTime": self._rfc3339(window_start),
        }
        target = (
            "https://graph.microsoft.com/v1.0/me/calendarView?"
            + urllib.parse.urlencode(parameters)
        )
        value = self._proxy_json(
            token,
            user=user,
            account=requested_account,
            target=target,
            proxy_headers={"X-PD-Proxy-Prefer": 'outlook.timezone="UTC"'},
            deadline=deadline,
        )
        if not isinstance(value, Mapping):
            raise WorkerError(
                502,
                "invalid_provider_response",
                "Outlook Calendar returned an invalid event list",
            )
        raw_events = value.get("value", [])
        next_link = value.get("@odata.nextLink")
        if not isinstance(raw_events, list) or len(raw_events) > MAX_MICROSOFT_OUTLOOK_EVENTS:
            raise WorkerError(
                502,
                "invalid_provider_response",
                "Outlook Calendar exceeded the upcoming-event result bound",
            )
        self._validate_microsoft_next_link(next_link, provider="Outlook Calendar")
        results: list[dict[str, object]] = []
        seen_ids: set[str] = set()
        total_bytes = 0
        for raw_event in raw_events:
            event = self._microsoft_outlook_event(raw_event)
            event_id = str(event["event_id"])
            if event_id in seen_ids:
                raise WorkerError(
                    502,
                    "invalid_provider_response",
                    "Outlook Calendar returned duplicate event identifiers",
                )
            seen_ids.add(event_id)
            event_bytes = len(
                json.dumps(event, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode()
            )
            if event_bytes > MAX_MICROSOFT_OUTLOOK_EVENT_BYTES:
                raise WorkerError(
                    502,
                    "provider_result_limit",
                    "Outlook Calendar event content exceeded its bound",
                )
            total_bytes += event_bytes
            if total_bytes > MAX_MICROSOFT_OUTLOOK_CALENDAR_TOTAL_BYTES:
                raise WorkerError(
                    502,
                    "provider_result_limit",
                    "Outlook Calendar content exceeded the aggregate operation bound",
                )
            results.append(event)
        return {
            "schema_version": "steward.microsoft-outlook-upcoming-events.v2",
            "integration": "microsoft-outlook-calendar",
            "calendar": "primary",
            "window_start": self._rfc3339(window_start),
            "window_end": self._rfc3339(window_end),
            "results": results,
            "result_count": len(results),
            "has_more": next_link is not None,
        }

    @staticmethod
    def _rfc3339(value: datetime.datetime) -> str:
        return value.astimezone(datetime.UTC).isoformat().replace("+00:00", "Z")

    @staticmethod
    def _validate_microsoft_next_link(value: object, *, provider: str) -> None:
        if value is None:
            return
        if (
            not isinstance(value, str)
            or not 1 <= len(value) <= 16384
            or any(ord(character) < 0x21 or ord(character) > 0x7E for character in value)
        ):
            raise WorkerError(
                502,
                "invalid_provider_response",
                f"{provider} returned an invalid continuation link",
            )
        parsed = urllib.parse.urlsplit(value)
        if (
            parsed.scheme != "https"
            or parsed.hostname != "graph.microsoft.com"
            or parsed.username
            or parsed.password
            or parsed.fragment
        ):
            raise WorkerError(
                502,
                "invalid_provider_response",
                f"{provider} returned an unsafe continuation link",
            )

    @classmethod
    def _microsoft_outlook_message(cls, value: object) -> dict[str, object]:
        if not isinstance(value, Mapping):
            raise WorkerError(
                502,
                "invalid_provider_response",
                "Outlook Mail returned invalid message content",
            )
        message_id = value.get("id")
        conversation_id = value.get("conversationId")
        received_at = value.get("receivedDateTime")
        is_read = value.get("isRead")
        importance = value.get("importance")
        recipients = value.get("toRecipients", [])
        if (
            not isinstance(message_id, str)
            or MICROSOFT_GRAPH_ID_RE.fullmatch(message_id) is None
            or not isinstance(conversation_id, str)
            or MICROSOFT_GRAPH_ID_RE.fullmatch(conversation_id) is None
            or not isinstance(is_read, bool)
            or importance not in {"low", "normal", "high"}
            or not isinstance(recipients, list)
            or len(recipients) > MAX_MICROSOFT_OUTLOOK_RECIPIENTS
        ):
            raise WorkerError(
                502,
                "invalid_provider_response",
                "Outlook Mail returned invalid message content",
            )
        content = cls._safe_text(
            cls._microsoft_optional_text(value.get("bodyPreview"), provider="Outlook Mail"),
            maximum_bytes=16 << 10,
            provider="Outlook Mail",
        )
        content_bytes = content.encode("utf-8")
        sender = value.get("from")
        normalized_sender = (
            {"display_name": "", "email": ""}
            if sender is None
            else cls._microsoft_person(sender, provider="Outlook Mail")
        )
        return {
            "message_id": message_id,
            "conversation_id": conversation_id,
            "status": "succeeded",
            "received_at": cls._microsoft_datetime(received_at, provider="Outlook Mail"),
            "from": normalized_sender,
            "to": [
                cls._microsoft_person(item, provider="Outlook Mail") for item in recipients
            ],
            "subject": cls._safe_text(
                cls._microsoft_optional_text(value.get("subject"), provider="Outlook Mail"),
                maximum_bytes=4096,
                provider="Outlook Mail",
            ),
            "is_read": is_read,
            "importance": importance,
            "content": content,
            "content_source": "body_preview",
            "content_bytes": len(content_bytes),
            "content_sha256": "sha256:" + hashlib.sha256(content_bytes).hexdigest(),
        }

    @classmethod
    def _microsoft_outlook_event(cls, value: object) -> dict[str, object]:
        if not isinstance(value, Mapping):
            raise WorkerError(
                502,
                "invalid_provider_response",
                "Outlook Calendar returned invalid event content",
            )
        event_id = value.get("id")
        is_all_day = value.get("isAllDay")
        is_cancelled = value.get("isCancelled")
        show_as = value.get("showAs")
        sensitivity = value.get("sensitivity")
        event_type = value.get("type")
        attendees = value.get("attendees", [])
        if (
            not isinstance(event_id, str)
            or MICROSOFT_GRAPH_ID_RE.fullmatch(event_id) is None
            or not isinstance(is_all_day, bool)
            or not isinstance(is_cancelled, bool)
            or show_as not in {"free", "tentative", "busy", "oof", "workingElsewhere", "unknown"}
            or sensitivity not in {"normal", "personal", "private", "confidential"}
            or event_type not in {"singleInstance", "occurrence", "exception", "seriesMaster"}
            or not isinstance(attendees, list)
            or len(attendees) > MAX_MICROSOFT_OUTLOOK_ATTENDEES
        ):
            raise WorkerError(
                502,
                "invalid_provider_response",
                "Outlook Calendar returned invalid event content",
            )
        location = value.get("location")
        if location is None:
            location = {}
        if not isinstance(location, Mapping):
            raise WorkerError(
                502,
                "invalid_provider_response",
                "Outlook Calendar returned invalid location data",
            )
        organizer = value.get("organizer")
        return {
            "event_id": event_id,
            "subject": cls._safe_text(
                cls._microsoft_optional_text(value.get("subject"), provider="Outlook Calendar"),
                maximum_bytes=4096,
                provider="Outlook Calendar",
            ),
            "start": cls._microsoft_calendar_when(value.get("start")),
            "end": cls._microsoft_calendar_when(value.get("end")),
            "location": cls._safe_text(
                cls._microsoft_optional_text(
                    location.get("displayName"), provider="Outlook Calendar"
                ),
                maximum_bytes=4096,
                provider="Outlook Calendar",
            ),
            "organizer": (
                None
                if organizer is None
                else cls._microsoft_person(organizer, provider="Outlook Calendar")
            ),
            "attendees": [cls._microsoft_attendee(item) for item in attendees],
            "is_all_day": is_all_day,
            "is_cancelled": is_cancelled,
            "show_as": show_as,
            "sensitivity": sensitivity,
            "event_type": event_type,
        }

    @staticmethod
    def _microsoft_optional_text(value: object, *, provider: str) -> str:
        if value is None:
            return ""
        if not isinstance(value, str):
            raise WorkerError(
                502,
                "invalid_provider_response",
                f"{provider} returned invalid text",
            )
        return value

    @classmethod
    def _microsoft_datetime(cls, value: object, *, provider: str) -> str:
        if not isinstance(value, str) or not 1 <= len(value) <= 64:
            raise WorkerError(
                502,
                "invalid_provider_response",
                f"{provider} returned an invalid timestamp",
            )
        try:
            parsed = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            raise WorkerError(
                502,
                "invalid_provider_response",
                f"{provider} returned an invalid timestamp",
            ) from None
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise WorkerError(
                502,
                "invalid_provider_response",
                f"{provider} returned a timezone-free timestamp",
            )
        return cls._rfc3339(parsed)

    @classmethod
    def _microsoft_person(cls, value: object, *, provider: str) -> dict[str, str]:
        if not isinstance(value, Mapping):
            raise WorkerError(
                502,
                "invalid_provider_response",
                f"{provider} returned invalid participant data",
            )
        address = value.get("emailAddress")
        if not isinstance(address, Mapping):
            raise WorkerError(
                502,
                "invalid_provider_response",
                f"{provider} returned invalid participant data",
            )
        name = address.get("name", "")
        email = address.get("address", "")
        if not isinstance(name, str) or not isinstance(email, str):
            raise WorkerError(
                502,
                "invalid_provider_response",
                f"{provider} returned invalid participant data",
            )
        return {
            "display_name": cls._safe_text(name, maximum_bytes=1024, provider=provider),
            "email": cls._safe_text(email, maximum_bytes=1024, provider=provider),
        }

    @classmethod
    def _microsoft_attendee(cls, value: object) -> dict[str, object]:
        if not isinstance(value, Mapping):
            raise WorkerError(
                502,
                "invalid_provider_response",
                "Outlook Calendar returned invalid attendee data",
            )
        attendee_type = value.get("type")
        status = value.get("status", {})
        if attendee_type not in {"required", "optional", "resource"} or not isinstance(status, Mapping):
            raise WorkerError(
                502,
                "invalid_provider_response",
                "Outlook Calendar returned invalid attendee data",
            )
        response = status.get("response")
        if response not in {
            "none",
            "organizer",
            "tentativelyAccepted",
            "accepted",
            "declined",
            "notResponded",
        }:
            raise WorkerError(
                502,
                "invalid_provider_response",
                "Outlook Calendar returned invalid attendee data",
            )
        return {
            **cls._microsoft_person(value, provider="Outlook Calendar"),
            "type": attendee_type,
            "response": response,
        }

    @classmethod
    def _microsoft_calendar_when(cls, value: object) -> dict[str, str]:
        if not isinstance(value, Mapping):
            raise WorkerError(
                502,
                "invalid_provider_response",
                "Outlook Calendar returned an invalid event time",
            )
        date_time = value.get("dateTime")
        time_zone = value.get("timeZone")
        if not isinstance(date_time, str) or not isinstance(time_zone, str):
            raise WorkerError(
                502,
                "invalid_provider_response",
                "Outlook Calendar returned an invalid event time",
            )
        if not 1 <= len(date_time) <= 64:
            raise WorkerError(
                502,
                "invalid_provider_response",
                "Outlook Calendar returned an invalid event time",
            )
        try:
            parsed = datetime.datetime.fromisoformat(date_time.replace("Z", "+00:00"))
        except ValueError:
            raise WorkerError(
                502,
                "invalid_provider_response",
                "Outlook Calendar returned an invalid event time",
            ) from None
        if time_zone != "UTC":
            raise WorkerError(
                502,
                "invalid_provider_response",
                "Outlook Calendar returned a non-UTC event time",
            )
        if parsed.tzinfo is not None and parsed.utcoffset() is not None:
            parsed = parsed.astimezone(datetime.UTC).replace(tzinfo=None)
        return {
            "date_time": cls._safe_text(
                parsed.isoformat(), maximum_bytes=64, provider="Outlook Calendar"
            ),
            "time_zone": cls._safe_text(
                time_zone, maximum_bytes=256, provider="Outlook Calendar"
            ),
        }

    @classmethod
    def _calendar_event(cls, value: object) -> dict[str, object]:
        if not isinstance(value, Mapping):
            raise WorkerError(
                502,
                "invalid_provider_response",
                "Google Calendar returned invalid event content",
            )
        event_id = value.get("id")
        status = value.get("status")
        event_type = value.get("eventType", "default")
        transparency = value.get("transparency", "opaque")
        visibility = value.get("visibility", "default")
        attendees_omitted = value.get("attendeesOmitted", False)
        if (
            not isinstance(event_id, str)
            or CALENDAR_EVENT_ID_RE.fullmatch(event_id) is None
            or status not in {"confirmed", "tentative", "cancelled"}
            or event_type not in {
                "birthday",
                "default",
                "focusTime",
                "fromGmail",
                "outOfOffice",
                "workingLocation",
            }
            or transparency not in {"opaque", "transparent"}
            or visibility not in {"confidential", "default", "private", "public"}
            or not isinstance(attendees_omitted, bool)
        ):
            raise WorkerError(
                502,
                "invalid_provider_response",
                "Google Calendar returned invalid event content",
            )
        attendees = value.get("attendees", [])
        if not isinstance(attendees, list) or len(attendees) > MAX_CALENDAR_ATTENDEES:
            raise WorkerError(
                502,
                "invalid_provider_response",
                "Google Calendar exceeded the attendee result bound",
            )
        result: dict[str, object] = {
            "event_id": event_id,
            "status": status,
            "event_type": event_type,
            "transparency": transparency,
            "visibility": visibility,
            "summary": cls._safe_text(
                cls._optional_text(value.get("summary")),
                maximum_bytes=4096,
                provider="Google Calendar",
            ),
            "description": cls._safe_text(
                cls._optional_text(value.get("description")),
                maximum_bytes=16 << 10,
                provider="Google Calendar",
            ),
            "location": cls._safe_text(
                cls._optional_text(value.get("location")),
                maximum_bytes=4096,
                provider="Google Calendar",
            ),
            "start": cls._calendar_when(value.get("start")),
            "end": cls._calendar_when(value.get("end")),
            "attendees": [
                cls._calendar_person(item, attendee=True) for item in attendees
            ],
            "attendees_omitted": attendees_omitted,
        }
        organizer = value.get("organizer")
        result["organizer"] = (
            None
            if organizer is None
            else cls._calendar_person(organizer, attendee=False)
        )
        return result

    @staticmethod
    def _optional_text(value: object) -> str:
        if value is None:
            return ""
        if not isinstance(value, str):
            raise WorkerError(
                502,
                "invalid_provider_response",
                "Google Calendar returned invalid event text",
            )
        return value

    @classmethod
    def _calendar_when(cls, value: object) -> dict[str, str]:
        if not isinstance(value, Mapping):
            raise WorkerError(
                502,
                "invalid_provider_response",
                "Google Calendar returned an invalid event time",
            )
        date_value = value.get("date")
        date_time = value.get("dateTime")
        time_zone = value.get("timeZone")
        if (date_value is None) == (date_time is None):
            raise WorkerError(
                502,
                "invalid_provider_response",
                "Google Calendar returned an invalid event time",
            )
        if date_value is not None:
            if (
                not isinstance(date_value, str)
                or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", date_value)
                or time_zone is not None
            ):
                raise WorkerError(
                    502,
                    "invalid_provider_response",
                    "Google Calendar returned an invalid all-day event time",
                )
            try:
                datetime.date.fromisoformat(date_value)
            except ValueError:
                raise WorkerError(
                    502,
                    "invalid_provider_response",
                    "Google Calendar returned an invalid all-day event time",
                ) from None
            return {"kind": "date", "value": date_value}
        if not isinstance(date_time, str) or (
            time_zone is not None
            and (not isinstance(time_zone, str) or len(time_zone.encode()) > 256)
        ):
            raise WorkerError(
                502,
                "invalid_provider_response",
                "Google Calendar returned an invalid timed event",
            )
        try:
            parsed = datetime.datetime.fromisoformat(date_time.replace("Z", "+00:00"))
        except ValueError:
            raise WorkerError(
                502,
                "invalid_provider_response",
                "Google Calendar returned an invalid timed event",
            ) from None
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise WorkerError(
                502,
                "invalid_provider_response",
                "Google Calendar returned a timezone-free event",
            )
        result = {"kind": "date_time", "value": date_time}
        if time_zone is not None:
            result["time_zone"] = cls._safe_text(
                time_zone,
                maximum_bytes=256,
                provider="Google Calendar",
            )
        return result

    @classmethod
    def _calendar_person(cls, value: object, *, attendee: bool) -> dict[str, object]:
        if not isinstance(value, Mapping):
            raise WorkerError(
                502,
                "invalid_provider_response",
                "Google Calendar returned invalid participant data",
            )
        email = value.get("email", "")
        display_name = value.get("displayName", "")
        self_value = value.get("self", False)
        if (
            not isinstance(email, str)
            or not isinstance(display_name, str)
            or not isinstance(self_value, bool)
        ):
            raise WorkerError(
                502,
                "invalid_provider_response",
                "Google Calendar returned invalid participant data",
            )
        result: dict[str, object] = {
            "email": cls._safe_text(
                email,
                maximum_bytes=1024,
                provider="Google Calendar",
            ),
            "display_name": cls._safe_text(
                display_name,
                maximum_bytes=1024,
                provider="Google Calendar",
            ),
            "self": self_value,
        }
        if attendee:
            response_status = value.get("responseStatus", "needsAction")
            optional = value.get("optional", False)
            if response_status not in {
                "accepted",
                "declined",
                "needsAction",
                "tentative",
            } or not isinstance(optional, bool):
                raise WorkerError(
                    502,
                    "invalid_provider_response",
                    "Google Calendar returned invalid attendee data",
                )
            result["response_status"] = response_status
            result["optional"] = optional
        return result

    @classmethod
    def _hubspot_pipeline_labels(
        cls,
        value: object,
    ) -> tuple[dict[str, str], dict[tuple[str, str], str]]:
        if not isinstance(value, Mapping):
            raise WorkerError(
                502,
                "invalid_provider_response",
                "HubSpot returned an invalid pipeline result",
            )
        raw_pipelines = value.get("results")
        if not isinstance(raw_pipelines, list) or len(raw_pipelines) > MAX_HUBSPOT_PIPELINES:
            raise WorkerError(
                502,
                "invalid_provider_response",
                "HubSpot exceeded the pipeline result bound",
            )
        pipeline_names: dict[str, str] = {}
        stage_names: dict[tuple[str, str], str] = {}
        total_bytes = 0
        for raw_pipeline in raw_pipelines:
            if not isinstance(raw_pipeline, Mapping):
                raise WorkerError(
                    502,
                    "invalid_provider_response",
                    "HubSpot returned invalid pipeline content",
                )
            pipeline_id = raw_pipeline.get("id")
            label = raw_pipeline.get("label")
            archived = raw_pipeline.get("archived", False)
            raw_stages = raw_pipeline.get("stages")
            if (
                not isinstance(pipeline_id, str)
                or HUBSPOT_OPAQUE_ID_RE.fullmatch(pipeline_id) is None
                or not isinstance(label, str)
                or not isinstance(archived, bool)
                or not isinstance(raw_stages, list)
                or len(raw_stages) > MAX_HUBSPOT_STAGES_PER_PIPELINE
                or pipeline_id in pipeline_names
            ):
                raise WorkerError(
                    502,
                    "invalid_provider_response",
                    "HubSpot returned invalid pipeline content",
                )
            if archived:
                continue
            pipeline_label = cls._safe_text(
                label,
                maximum_bytes=MAX_HUBSPOT_DEAL_TEXT_BYTES,
                provider="HubSpot",
            )
            pipeline_names[pipeline_id] = pipeline_label
            total_bytes += len(pipeline_label.encode())
            if total_bytes > MAX_HUBSPOT_TOTAL_BYTES:
                raise WorkerError(
                    502,
                    "provider_result_limit",
                    "HubSpot pipeline content exceeded the aggregate operation bound",
                )
            for raw_stage in raw_stages:
                if not isinstance(raw_stage, Mapping):
                    raise WorkerError(
                        502,
                        "invalid_provider_response",
                        "HubSpot returned invalid pipeline stage content",
                    )
                stage_id = raw_stage.get("id")
                stage_label = raw_stage.get("label")
                stage_archived = raw_stage.get("archived", False)
                if (
                    not isinstance(stage_id, str)
                    or HUBSPOT_OPAQUE_ID_RE.fullmatch(stage_id) is None
                    or not isinstance(stage_label, str)
                    or not isinstance(stage_archived, bool)
                ):
                    raise WorkerError(
                        502,
                        "invalid_provider_response",
                        "HubSpot returned invalid pipeline stage content",
                    )
                stage_key = (pipeline_id, stage_id)
                if stage_key in stage_names:
                    raise WorkerError(
                        502,
                        "invalid_provider_response",
                        "HubSpot returned invalid pipeline stage content",
                    )
                if stage_archived:
                    continue
                normalized_stage = cls._safe_text(
                    stage_label,
                    maximum_bytes=MAX_HUBSPOT_DEAL_TEXT_BYTES,
                    provider="HubSpot",
                )
                stage_names[stage_key] = normalized_stage
                total_bytes += len(normalized_stage.encode())
                if total_bytes > MAX_HUBSPOT_TOTAL_BYTES:
                    raise WorkerError(
                        502,
                        "provider_result_limit",
                        "HubSpot pipeline content exceeded the aggregate operation bound",
                    )
        return pipeline_names, stage_names

    @classmethod
    def _hubspot_deal(
        cls,
        value: object,
        *,
        pipeline_names: Mapping[str, str],
        stage_names: Mapping[tuple[str, str], str],
    ) -> dict[str, object]:
        if not isinstance(value, Mapping):
            raise WorkerError(
                502,
                "invalid_provider_response",
                "HubSpot returned invalid deal content",
            )
        deal_id = value.get("id")
        archived = value.get("archived")
        properties = value.get("properties")
        if (
            not isinstance(deal_id, str)
            or HUBSPOT_ID_RE.fullmatch(deal_id) is None
            or archived is not False
            or not isinstance(properties, Mapping)
        ):
            raise WorkerError(
                502,
                "invalid_provider_response",
                "HubSpot returned invalid deal content",
            )
        selected: dict[str, str] = {}
        for name in HUBSPOT_DEAL_PROPERTIES:
            raw = properties.get(name)
            if raw is None:
                selected[name] = ""
            elif isinstance(raw, str):
                selected[name] = cls._safe_text(
                    raw,
                    maximum_bytes=MAX_HUBSPOT_DEAL_TEXT_BYTES,
                    provider="HubSpot",
                )
            else:
                raise WorkerError(
                    502,
                    "invalid_provider_response",
                    "HubSpot returned invalid deal properties",
                )
        pipeline_id = selected["pipeline"]
        stage_id = selected["dealstage"]
        if (
            pipeline_id
            and HUBSPOT_OPAQUE_ID_RE.fullmatch(pipeline_id) is None
        ) or (stage_id and HUBSPOT_OPAQUE_ID_RE.fullmatch(stage_id) is None):
            raise WorkerError(
                502,
                "invalid_provider_response",
                "HubSpot returned invalid deal properties",
            )
        closed_value = selected["hs_is_closed"]
        if closed_value not in {"", "false", "true"}:
            raise WorkerError(
                502,
                "invalid_provider_response",
                "HubSpot returned invalid deal properties",
            )
        for field in ("closedate", "createdate", "hs_lastmodifieddate"):
            cls._hubspot_timestamp(selected[field])
        created_at = value.get("createdAt")
        updated_at = value.get("updatedAt")
        if not isinstance(created_at, str) or not isinstance(updated_at, str):
            raise WorkerError(
                502,
                "invalid_provider_response",
                "HubSpot returned invalid deal timestamps",
            )
        normalized_created_at = cls._hubspot_timestamp(created_at)
        normalized_updated_at = cls._hubspot_timestamp(updated_at)
        if not normalized_created_at or not normalized_updated_at:
            raise WorkerError(
                502,
                "invalid_provider_response",
                "HubSpot returned invalid deal timestamps",
            )
        return {
            "deal_id": deal_id,
            "name": selected["dealname"],
            "amount": selected["amount"],
            "closed": None if not closed_value else closed_value == "true",
            "close_date": selected["closedate"],
            "created_at": normalized_created_at,
            "updated_at": normalized_updated_at,
            "pipeline_id": pipeline_id,
            "pipeline_name": pipeline_names.get(pipeline_id, ""),
            "stage_id": stage_id,
            "stage_name": stage_names.get((pipeline_id, stage_id), ""),
        }

    @staticmethod
    def _hubspot_timestamp(value: str) -> str:
        if not value:
            return ""
        if len(value.encode()) > 64:
            raise WorkerError(
                502,
                "invalid_provider_response",
                "HubSpot returned an invalid timestamp",
            )
        try:
            parsed = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            raise WorkerError(
                502,
                "invalid_provider_response",
                "HubSpot returned an invalid timestamp",
            ) from None
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise WorkerError(
                502,
                "invalid_provider_response",
                "HubSpot returned an invalid timestamp",
            )
        return value

    @staticmethod
    def _hubspot_has_more(value: object) -> bool:
        if value is None:
            return False
        if not isinstance(value, Mapping):
            raise WorkerError(
                502,
                "invalid_provider_response",
                "HubSpot returned invalid deal pagination",
            )
        next_page = value.get("next")
        after = next_page.get("after") if isinstance(next_page, Mapping) else None
        if (
            not isinstance(after, str)
            or not 1 <= len(after.encode()) <= 256
            or any(ord(character) < 0x21 or ord(character) > 0x7E for character in after)
        ):
            raise WorkerError(
                502,
                "invalid_provider_response",
                "HubSpot returned invalid deal pagination",
            )
        return True

    @staticmethod
    def _slack_result(value: object, *, operation: str) -> Mapping[str, object]:
        if not isinstance(value, Mapping) or not isinstance(value.get("ok"), bool):
            raise WorkerError(
                502,
                "invalid_provider_response",
                f"Slack returned an invalid {operation}",
            )
        if value["ok"] is True:
            return value
        error = value.get("error")
        if error in {"channel_not_found", "not_in_channel", "team_access_not_granted"}:
            raise WorkerError(
                409,
                "provider_access_changed",
                "Slack channel access changed; choose the channel again",
            )
        if error in {"account_inactive", "invalid_auth", "not_authed", "token_expired", "token_revoked"}:
            raise WorkerError(
                409,
                "connection_not_ready",
                "Slack connection needs attention",
            )
        if error == "ratelimited":
            raise WorkerError(
                503,
                "provider_rate_limited",
                "Slack is temporarily rate limited",
            )
        raise WorkerError(
            502,
            "provider_rejected",
            f"Slack rejected the {operation}",
        )

    @classmethod
    def _slack_channel(cls, value: object) -> dict[str, str]:
        if not isinstance(value, Mapping):
            raise WorkerError(
                502,
                "invalid_provider_response",
                "Slack returned invalid channel metadata",
            )
        channel_id = value.get("id")
        name = value.get("name")
        is_archived = value.get("is_archived")
        is_private = value.get("is_private")
        topic = value.get("topic", {})
        purpose = value.get("purpose", {})
        if (
            not isinstance(channel_id, str)
            or SLACK_CHANNEL_ID_RE.fullmatch(channel_id) is None
            or not isinstance(name, str)
            or not name
            or is_archived is not False
            or is_private is not False
            or not isinstance(topic, Mapping)
            or not isinstance(purpose, Mapping)
            or not isinstance(topic.get("value", ""), str)
            or not isinstance(purpose.get("value", ""), str)
        ):
            raise WorkerError(
                502,
                "invalid_provider_response",
                "Slack returned invalid channel metadata",
            )
        return {
            "channel_id": channel_id,
            "name": cls._safe_text(
                name,
                maximum_bytes=256,
                provider="Slack",
            ),
            "topic": cls._safe_text(
                str(topic.get("value", "")),
                maximum_bytes=MAX_SLACK_CHANNEL_TEXT_BYTES,
                provider="Slack",
            ),
            "purpose": cls._safe_text(
                str(purpose.get("value", "")),
                maximum_bytes=MAX_SLACK_CHANNEL_TEXT_BYTES,
                provider="Slack",
            ),
        }

    @classmethod
    def _slack_message(cls, value: object) -> dict[str, object] | None:
        if not isinstance(value, Mapping) or value.get("type") != "message":
            raise WorkerError(
                502,
                "invalid_provider_response",
                "Slack returned invalid message content",
            )
        subtype = value.get("subtype")
        if subtype not in {None, "bot_message"}:
            return None
        timestamp = value.get("ts")
        text = value.get("text")
        user = value.get("user")
        bot_id = value.get("bot_id")
        thread_timestamp = value.get("thread_ts", "")
        if (
            not isinstance(timestamp, str)
            or SLACK_MESSAGE_TS_RE.fullmatch(timestamp) is None
            or not isinstance(text, str)
            or (user is not None and not isinstance(user, str))
            or (bot_id is not None and not isinstance(bot_id, str))
            or not isinstance(thread_timestamp, str)
            or (
                thread_timestamp
                and SLACK_MESSAGE_TS_RE.fullmatch(thread_timestamp) is None
            )
        ):
            raise WorkerError(
                502,
                "invalid_provider_response",
                "Slack returned invalid message content",
            )
        if thread_timestamp and thread_timestamp != timestamp:
            return None
        author = user or bot_id or ""
        if author and SLACK_AUTHOR_ID_RE.fullmatch(author) is None:
            raise WorkerError(
                502,
                "invalid_provider_response",
                "Slack returned invalid message identity",
            )
        normalized = cls._safe_text(
            text,
            maximum_bytes=MAX_SLACK_MESSAGE_BYTES,
            provider="Slack",
        )
        encoded = normalized.encode("utf-8")
        return {
            "timestamp": timestamp,
            "author_id": author,
            "author_kind": "member" if user else ("app" if bot_id else "unknown"),
            "text": normalized,
            "thread_root": thread_timestamp in {"", timestamp},
            "content_bytes": len(encoded),
            "content_sha256": "sha256:" + hashlib.sha256(encoded).hexdigest(),
        }

    def _gmail_message(self, value: object, expected_id: str) -> dict[str, object]:
        if not isinstance(value, Mapping) or value.get("id") != expected_id:
            raise WorkerError(
                502,
                "invalid_provider_response",
                "Gmail returned invalid message content",
            )
        thread_id = value.get("threadId")
        internal_date = value.get("internalDate")
        labels = value.get("labelIds", [])
        snippet = value.get("snippet", "")
        payload = value.get("payload")
        if (
            not isinstance(thread_id, str)
            or FILE_ID_RE.fullmatch(thread_id) is None
            or not isinstance(internal_date, str)
            or not internal_date.isdecimal()
            or len(internal_date) > 20
            or not isinstance(labels, list)
            or len(labels) > 100
            or any(not isinstance(label, str) or len(label.encode()) > 256 for label in labels)
            or not isinstance(snippet, str)
            or len(snippet.encode()) > 4096
            or not isinstance(payload, Mapping)
        ):
            raise WorkerError(
                502,
                "invalid_provider_response",
                "Gmail returned invalid message content",
            )
        if "INBOX" not in labels:
            raise WorkerError(
                502,
                "message_left_inbox",
                "Gmail message left the recent-inbox boundary before it was read",
            )
        headers = self._gmail_headers(payload.get("headers"))
        body = self._gmail_text_body(payload)
        content_source = "text/plain"
        if body is None:
            body = self._safe_text(snippet, maximum_bytes=4096)
            content_source = "snippet"
        normalized = body.encode("utf-8")
        return {
            "message_id": expected_id,
            "thread_id": thread_id,
            "status": "succeeded",
            "received_at_epoch_ms": internal_date,
            "labels": sorted(set(labels)),
            "from": headers.get("from", ""),
            "to": headers.get("to", ""),
            "subject": headers.get("subject", ""),
            "sent_at": headers.get("date", ""),
            "content": body,
            "content_source": content_source,
            "content_bytes": len(normalized),
            "content_sha256": "sha256:" + hashlib.sha256(normalized).hexdigest(),
        }

    @staticmethod
    def _gmail_headers(value: object) -> dict[str, str]:
        if not isinstance(value, list) or len(value) > 200:
            raise WorkerError(
                502,
                "invalid_provider_response",
                "Gmail returned invalid message headers",
            )
        selected: dict[str, str] = {}
        allowed = {"date", "from", "subject", "to"}
        for item in value:
            if not isinstance(item, Mapping):
                raise WorkerError(
                    502,
                    "invalid_provider_response",
                    "Gmail returned invalid message headers",
                )
            name = item.get("name")
            header_value = item.get("value")
            if not isinstance(name, str) or not isinstance(header_value, str):
                raise WorkerError(
                    502,
                    "invalid_provider_response",
                    "Gmail returned invalid message headers",
                )
            normalized_name = name.lower()
            if normalized_name in allowed and normalized_name not in selected:
                selected[normalized_name] = PipedreamClient._safe_text(
                    header_value,
                    maximum_bytes=4096,
                )
        return selected

    @staticmethod
    def _safe_text(
        value: str,
        *,
        maximum_bytes: int,
        provider: str = "Gmail",
    ) -> str:
        normalized = unicodedata.normalize("NFC", value).replace("\r\n", "\n").replace("\r", "\n")
        encoded = normalized.encode("utf-8")
        if (
            len(encoded) > maximum_bytes
            or any(ord(character) < 0x20 and character not in "\t\n" for character in normalized)
        ):
            raise WorkerError(
                502,
                "invalid_provider_response",
                f"{provider} returned invalid text",
            )
        return normalized

    @staticmethod
    def _gmail_text_body(payload: Mapping[str, object]) -> str | None:
        stack: list[tuple[Mapping[str, object], int]] = [(payload, 0)]
        inspected = 0
        while stack:
            part, depth = stack.pop()
            inspected += 1
            if inspected > MAX_GMAIL_PARTS or depth > MAX_GMAIL_PART_DEPTH:
                raise WorkerError(
                    502,
                    "invalid_provider_response",
                    "Gmail message structure exceeded its bound",
                )
            mime_type = part.get("mimeType", "")
            filename = part.get("filename", "")
            headers = part.get("headers", [])
            body = part.get("body", {})
            parts = part.get("parts", [])
            if (
                not isinstance(mime_type, str)
                or not isinstance(filename, str)
                or len(filename.encode()) > 1024
                or not isinstance(headers, list)
                or len(headers) > 200
                or any(not isinstance(header, Mapping) for header in headers)
                or not isinstance(body, Mapping)
                or not isinstance(parts, list)
                or any(not isinstance(child, Mapping) for child in parts)
            ):
                raise WorkerError(
                    502,
                    "invalid_provider_response",
                    "Gmail returned an invalid message structure",
                )
            content_disposition = ""
            for header in headers:
                name = header.get("name")
                value = header.get("value")
                if not isinstance(name, str) or not isinstance(value, str):
                    raise WorkerError(
                        502,
                        "invalid_provider_response",
                        "Gmail returned an invalid message structure",
                    )
                if name.lower() == "content-disposition":
                    content_disposition = value.strip().lower()
            is_attachment = bool(filename) or content_disposition.startswith("attachment")
            if (
                not is_attachment
                and mime_type.lower() == "text/plain"
                and isinstance(body.get("data"), str)
            ):
                encoded = str(body["data"])
                if len(encoded) > ((MAX_GMAIL_MESSAGE_BYTES + 2) * 4 // 3) + 4:
                    return None
                try:
                    raw = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
                    text = raw.decode("utf-8")
                except (ValueError, UnicodeDecodeError):
                    return None
                return PipedreamClient._safe_text(
                    text,
                    maximum_bytes=MAX_GMAIL_MESSAGE_BYTES,
                )
            if not is_attachment:
                stack.extend((child, depth + 1) for child in reversed(parts))
        return None

    def _proxy_json(
        self,
        token: str,
        *,
        user: str,
        account: str,
        target: str,
        proxy_headers: Mapping[str, str] | None = None,
        deadline: float | None = None,
    ) -> object:
        path = self._proxy_path(user=user, account=account, target=target)
        return self._request(
            "GET",
            path,
            token=token,
            proxy_headers=proxy_headers,
            deadline=deadline,
        )

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
        path = self._proxy_path(user=user, account=account, target=target)
        return self._request(
            "POST",
            path,
            payload=payload,
            token=token,
            deadline=deadline,
        )

    def _proxy_bytes(
        self,
        token: str,
        *,
        user: str,
        account: str,
        target: str,
        maximum_bytes: int,
        deadline: float | None = None,
    ) -> tuple[bytes, str]:
        path = self._proxy_path(user=user, account=account, target=target)
        return self._request_bytes(
            "GET",
            path,
            token=token,
            maximum_bytes=maximum_bytes,
            deadline=deadline,
        )

    def _proxy_path(self, *, user: str, account: str, target: str) -> str:
        encoded_target = base64.urlsafe_b64encode(target.encode()).decode().rstrip("=")
        query = urllib.parse.urlencode({"account_id": account, "external_user_id": user})
        return f"/v1/connect/{self.project_id}/proxy/{encoded_target}?{query}"

    def revoke(
        self,
        user: str,
        requested_account: str,
        integration: str = "google-drive",
    ) -> dict[str, object]:
        token, _connection = self._owned_account(
            user,
            requested_account,
            "connect:accounts:read connect:accounts:write",
            integration=integration,
        )
        self._request(
            "DELETE",
            f"/v1/connect/{self.project_id}/accounts/{urllib.parse.quote(requested_account, safe='')}",
            token=token,
        )
        return {
            "schema_version": "steward.managed-connection-revocation.v1",
            "integration": integration,
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

    def _json(self, status: int, value: object, *, maximum_bytes: int = MAX_RESPONSE) -> None:
        raw = json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        if len(raw) > maximum_bytes:
            status = 500
            raw = b'{"error":{"code":"response_too_large","message":"worker response exceeded its bound"}}'
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
        if not self.worker.request_parsed(self.request):
            return
        try:
            value = json.loads(raw)
            account_list_prefix = "/v1/connections/"
            account_list_suffix = "/accounts"
            if (
                self.path.startswith(account_list_prefix)
                and self.path.endswith(account_list_suffix)
                and self.path.count("/") == 4
            ):
                integration = self.path[
                    len(account_list_prefix) : -len(account_list_suffix)
                ]
                if integration not in INTEGRATION_PROFILES:
                    raise WorkerError(404, "not_found", "route not found")
                body = exact_object(value, frozenset({"external_user_id"}))
                result = self.worker.client.list_connections(
                    external_user(body["external_user_id"]),
                    integration,
                )
            elif self.path == "/v1/connections/google-drive/connect-link":
                body = exact_object(value, frozenset({"external_user_id"}))
                result = self.worker.client.connect_link(external_user(body["external_user_id"]))
            elif self.path == "/v1/connections/gmail/connect-link":
                body = exact_object(value, frozenset({"external_user_id"}))
                result = self.worker.client.connect_link(
                    external_user(body["external_user_id"]),
                    "gmail",
                )
            elif self.path == "/v1/connections/google-calendar/connect-link":
                body = exact_object(value, frozenset({"external_user_id"}))
                result = self.worker.client.connect_link(
                    external_user(body["external_user_id"]),
                    "google-calendar",
                )
            elif self.path == "/v1/connections/microsoft-outlook-mail/connect-link":
                body = exact_object(value, frozenset({"external_user_id"}))
                result = self.worker.client.connect_link(
                    external_user(body["external_user_id"]),
                    "microsoft-outlook-mail",
                )
            elif self.path == "/v1/connections/microsoft-outlook-calendar/connect-link":
                body = exact_object(value, frozenset({"external_user_id"}))
                result = self.worker.client.connect_link(
                    external_user(body["external_user_id"]),
                    "microsoft-outlook-calendar",
                )
            elif self.path == "/v1/connections/slack/connect-link":
                body = exact_object(value, frozenset({"external_user_id"}))
                result = self.worker.client.connect_link(
                    external_user(body["external_user_id"]),
                    "slack",
                )
            elif self.path == "/v1/connections/hubspot/connect-link":
                body = exact_object(value, frozenset({"external_user_id"}))
                result = self.worker.client.connect_link(
                    external_user(body["external_user_id"]),
                    "hubspot",
                )
            elif self.path == "/v1/connections/google-drive/reconcile":
                body = exact_object(value, frozenset({"external_user_id"}))
                _token, result = self.worker.client.reconcile(external_user(body["external_user_id"]))
            elif self.path == "/v1/connections/gmail/reconcile":
                body = exact_object(value, frozenset({"external_user_id"}))
                _token, result = self.worker.client.reconcile(
                    external_user(body["external_user_id"]),
                    integration="gmail",
                )
            elif self.path == "/v1/connections/google-calendar/reconcile":
                body = exact_object(value, frozenset({"external_user_id"}))
                _token, result = self.worker.client.reconcile(
                    external_user(body["external_user_id"]),
                    integration="google-calendar",
                )
            elif self.path == "/v1/connections/microsoft-outlook-mail/reconcile":
                body = exact_object(value, frozenset({"external_user_id"}))
                _token, result = self.worker.client.reconcile(
                    external_user(body["external_user_id"]),
                    integration="microsoft-outlook-mail",
                )
            elif self.path == "/v1/connections/microsoft-outlook-calendar/reconcile":
                body = exact_object(value, frozenset({"external_user_id"}))
                _token, result = self.worker.client.reconcile(
                    external_user(body["external_user_id"]),
                    integration="microsoft-outlook-calendar",
                )
            elif self.path == "/v1/connections/slack/reconcile":
                body = exact_object(value, frozenset({"external_user_id"}))
                _token, result = self.worker.client.reconcile(
                    external_user(body["external_user_id"]),
                    integration="slack",
                )
            elif self.path == "/v1/connections/hubspot/reconcile":
                body = exact_object(value, frozenset({"external_user_id"}))
                _token, result = self.worker.client.reconcile(
                    external_user(body["external_user_id"]),
                    integration="hubspot",
                )
            elif self.path == "/v1/connections/google-drive/files":
                body = exact_object(
                    value,
                    frozenset({"account_id", "external_user_id"}),
                )
                result = self.worker.client.list_drive_metadata(
                    external_user(body["external_user_id"]), account_id(body["account_id"])
                )
            elif self.path == "/v1/connections/google-drive/content":
                body = exact_object(
                    value,
                    frozenset({"account_id", "external_user_id", "file_ids"}),
                )
                result = self.worker.client.read_drive_content(
                    external_user(body["external_user_id"]),
                    account_id(body["account_id"]),
                    file_ids(body["file_ids"]),
                )
            elif self.path == "/v1/connections/gmail/recent-messages":
                body = exact_object(
                    value,
                    frozenset({"account_id", "external_user_id"}),
                )
                result = self.worker.client.read_recent_gmail(
                    external_user(body["external_user_id"]),
                    account_id(body["account_id"]),
                )
            elif self.path == "/v1/connections/google-calendar/upcoming-events":
                body = exact_object(
                    value,
                    frozenset({"account_id", "external_user_id"}),
                )
                result = self.worker.client.read_upcoming_calendar(
                    external_user(body["external_user_id"]),
                    account_id(body["account_id"]),
                )
            elif self.path == "/v1/connections/microsoft-outlook-mail/recent-messages":
                body = exact_object(
                    value,
                    frozenset({"account_id", "external_user_id"}),
                )
                result = self.worker.client.read_recent_microsoft_outlook_messages(
                    external_user(body["external_user_id"]),
                    account_id(body["account_id"]),
                )
            elif self.path == "/v1/connections/microsoft-outlook-calendar/upcoming-events":
                body = exact_object(
                    value,
                    frozenset({"account_id", "external_user_id"}),
                )
                result = self.worker.client.read_upcoming_microsoft_outlook_events(
                    external_user(body["external_user_id"]),
                    account_id(body["account_id"]),
                )
            elif self.path == "/v1/connections/slack/channels":
                body = exact_object(
                    value,
                    frozenset({"account_id", "external_user_id"}),
                )
                result = self.worker.client.list_slack_channels(
                    external_user(body["external_user_id"]),
                    account_id(body["account_id"]),
                )
            elif self.path == "/v1/connections/slack/recent-messages":
                body = exact_object(
                    value,
                    frozenset({"account_id", "channel_id", "external_user_id"}),
                )
                result = self.worker.client.read_recent_slack_messages(
                    external_user(body["external_user_id"]),
                    account_id(body["account_id"]),
                    slack_channel_id(body["channel_id"]),
                )
            elif self.path == "/v1/connections/hubspot/recent-deals":
                body = exact_object(
                    value,
                    frozenset({"account_id", "external_user_id"}),
                )
                result = self.worker.client.read_recent_hubspot_deals(
                    external_user(body["external_user_id"]),
                    account_id(body["account_id"]),
                )
            elif self.path == "/v1/connections/google-drive/revoke":
                body = exact_object(value, frozenset({"account_id", "external_user_id"}))
                result = self.worker.client.revoke(
                    external_user(body["external_user_id"]), account_id(body["account_id"])
                )
            elif self.path == "/v1/connections/gmail/revoke":
                body = exact_object(value, frozenset({"account_id", "external_user_id"}))
                result = self.worker.client.revoke(
                    external_user(body["external_user_id"]),
                    account_id(body["account_id"]),
                    "gmail",
                )
            elif self.path == "/v1/connections/google-calendar/revoke":
                body = exact_object(value, frozenset({"account_id", "external_user_id"}))
                result = self.worker.client.revoke(
                    external_user(body["external_user_id"]),
                    account_id(body["account_id"]),
                    "google-calendar",
                )
            elif self.path == "/v1/connections/microsoft-outlook-mail/revoke":
                body = exact_object(value, frozenset({"account_id", "external_user_id"}))
                result = self.worker.client.revoke(
                    external_user(body["external_user_id"]),
                    account_id(body["account_id"]),
                    "microsoft-outlook-mail",
                )
            elif self.path == "/v1/connections/microsoft-outlook-calendar/revoke":
                body = exact_object(value, frozenset({"account_id", "external_user_id"}))
                result = self.worker.client.revoke(
                    external_user(body["external_user_id"]),
                    account_id(body["account_id"]),
                    "microsoft-outlook-calendar",
                )
            elif self.path == "/v1/connections/slack/revoke":
                body = exact_object(value, frozenset({"account_id", "external_user_id"}))
                result = self.worker.client.revoke(
                    external_user(body["external_user_id"]),
                    account_id(body["account_id"]),
                    "slack",
                )
            elif self.path == "/v1/connections/hubspot/revoke":
                body = exact_object(value, frozenset({"account_id", "external_user_id"}))
                result = self.worker.client.revoke(
                    external_user(body["external_user_id"]),
                    account_id(body["account_id"]),
                    "hubspot",
                )
            else:
                raise WorkerError(404, "not_found", "route not found")
            self._json(
                200,
                result,
                maximum_bytes=(
                    MAX_CONTENT_RESPONSE
                    if self.path
                    in {
                        "/v1/connections/google-drive/content",
                        "/v1/connections/gmail/recent-messages",
                        "/v1/connections/google-calendar/upcoming-events",
                        "/v1/connections/microsoft-outlook-mail/recent-messages",
                        "/v1/connections/microsoft-outlook-calendar/upcoming-events",
                        "/v1/connections/slack/recent-messages",
                        "/v1/connections/hubspot/recent-deals",
                    }
                    else MAX_RESPONSE
                ),
            )
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

    def _expire_request(self, request: object) -> None:
        with self._deadline_lock:
            timer = self._deadlines.pop(id(request), None)
            if timer is None:
                return
            try:
                request.shutdown(socket.SHUT_RDWR)  # type: ignore[attr-defined]
            except OSError:
                return

    def _cancel_deadline(self, request: object) -> bool:
        with self._deadline_lock:
            timer = self._deadlines.pop(id(request), None)
        if timer is not None:
            timer.cancel()
            return True
        return False

    def request_parsed(self, request: object) -> bool:
        return self._cancel_deadline(request)

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
        gmail_oauth_app_id=os.environ.get("STEWARD_GMAIL_OAUTH_APP_ID", ""),
        google_calendar_oauth_app_id=os.environ.get(
            "STEWARD_GOOGLE_CALENDAR_OAUTH_APP_ID", ""
        ),
        microsoft_outlook_oauth_app_id=os.environ.get(
            "STEWARD_MICROSOFT_OUTLOOK_OAUTH_APP_ID", ""
        ),
        microsoft_outlook_calendar_oauth_app_id=os.environ.get(
            "STEWARD_MICROSOFT_OUTLOOK_CALENDAR_OAUTH_APP_ID", ""
        ),
        slack_oauth_app_id=os.environ.get("STEWARD_SLACK_OAUTH_APP_ID", ""),
        hubspot_oauth_app_id=os.environ.get("STEWARD_HUBSPOT_OAUTH_APP_ID", ""),
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
