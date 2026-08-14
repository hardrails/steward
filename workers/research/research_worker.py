#!/usr/bin/env python3
"""Credential-isolating search adapter and SSRF-safe public page extractor."""

from __future__ import annotations

import hmac
import html.parser
import http.client
import http.server
import ipaddress
import json
import os
import pathlib
import re
import selectors
import signal
import socket
import ssl
import stat
import subprocess
import sys
import time
import urllib.parse
from collections.abc import Callable

MAX_REQUEST = 64 << 10
MAX_UPSTREAM = 4 << 20
MAX_RESPONSE = 1 << 20
MAX_SOURCE_TEXT = 256 << 10
MAX_JSON_NODES = 8192
MAX_JSON_DEPTH = 64
MAX_V2_SOURCE_TEXT = 32 << 10
UPSTREAM_TIMEOUT = 45
BRAVE_API_BASE = urllib.parse.urlsplit("https://api.search.brave.com")
BRAVE_TRANSIENT_STATUS_CODES = frozenset({429, 500, 502, 503, 504})
BRAVE_RETRY_DELAYS_SECONDS = (1.0, 2.0)
MAX_REDIRECTS = 5
V2_MAX_CONCURRENCY = 4
V2_SOURCE_SECONDS = 15
V2_BATCH_SECONDS = 50
V2_CLEANUP_RESERVE_SECONDS = 1
V2_MAX_PENDING_REAPS = 32
MAX_PDF_PAGES = 200
MAX_PDF_RECOVERY_OBJECTS = 1000
MAX_PDF_CHILD_RESPONSE = (MAX_SOURCE_TEXT * 2) + (8 << 10)
MAX_V2_CHILD_RESPONSE = (MAX_V2_SOURCE_TEXT * 2) + (32 << 10)
PDF_CPU_SECONDS = 4
PDF_WALL_SECONDS = 5
PDF_MEMORY_BYTES = 128 << 20
PDF_CHILD_MODE = "--extract-pdf"
V2_SOURCE_CHILD_MODE = "--extract-source-v2"
V2_SOURCE_FAILURE_CODES = frozenset({
    "source_unresolvable",
    "private_source_denied",
    "source_unavailable",
    "invalid_source_redirect",
    "source_rejected",
    "unsupported_source",
    "source_too_large",
    "pdf_extraction_timeout",
})
V2_SOURCE_MEDIA_TYPES = frozenset({
    "text/html",
    "application/xhtml+xml",
    "text/plain",
    "application/pdf",
    "application/json",
})
V2_PENDING_REAPS: list[subprocess.Popen[bytes]] = []


class WorkerError(Exception):
    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


class PDFInputRejected(Exception):
    """The bounded PDF helper rejected application content."""


class V2SourceProcess:
    def __init__(
        self,
        *,
        index: int,
        requested_url: str,
        process: subprocess.Popen[bytes],
        deadline: float,
        output: bytearray,
        stdout_fd: int | None,
    ) -> None:
        self.index = index
        self.requested_url = requested_url
        self.process = process
        self.deadline = deadline
        self.output = output
        self.stdout_fd = stdout_fd


def read_secret(path_text: str, label: str, required: bool = True) -> bytes | None:
    if not path_text:
        if required:
            raise RuntimeError(f"{label} file is required")
        return None
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


def parse_upstream(value: str, label: str) -> urllib.parse.SplitResult | None:
    if not value:
        return None
    parsed = urllib.parse.urlsplit(value)
    allow_http = os.environ.get("STEWARD_ALLOW_INSECURE_UPSTREAM", "NO") == "YES"
    if (
        parsed.scheme not in ({"https", "http"} if allow_http else {"https"})
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise RuntimeError(f"{label} must be a canonical {'HTTP(S)' if allow_http else 'HTTPS'} base URL")
    try:
        _ = parsed.port
    except ValueError as error:
        raise RuntimeError(f"{label} contains an invalid port") from error
    return parsed


def request_path(base: urllib.parse.SplitResult, suffix: str, query: str = "") -> str:
    prefix = base.path.rstrip("/")
    return (prefix + suffix or "/") + (("?" + query) if query else "")


def upstream_json(
    base: urllib.parse.SplitResult,
    method: str,
    path: str,
    payload: object | None,
    token: bytes | None = None,
    subscription_token: bytes | None = None,
    retryable_statuses: frozenset[int] = frozenset(),
    retry_delays_seconds: tuple[float, ...] = (),
) -> object:
    body = None if payload is None else json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode()
    headers = {"Accept": "application/json", "Accept-Encoding": "identity", "User-Agent": "steward-research-worker/1"}
    if body is not None:
        headers.update({"Content-Type": "application/json", "Content-Length": str(len(body))})
    if token is not None:
        headers["Authorization"] = "Bearer " + token.decode("ascii")
    if subscription_token is not None:
        headers["X-Subscription-Token"] = subscription_token.decode("ascii")
    if (
        type(retryable_statuses) is not frozenset
        or any(type(status) is not int for status in retryable_statuses)
        or type(retry_delays_seconds) is not tuple
        or any(
            type(delay) is not float or not 0.0 < delay <= 5.0
            for delay in retry_delays_seconds
        )
    ):
        raise RuntimeError("upstream retry policy is invalid")
    connection_type = http.client.HTTPSConnection if base.scheme == "https" else http.client.HTTPConnection
    for attempt in range(len(retry_delays_seconds) + 1):
        connection = connection_type(base.hostname, base.port, timeout=UPSTREAM_TIMEOUT)
        try:
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            content = response.read(MAX_UPSTREAM + 1)
            if len(content) > MAX_UPSTREAM:
                raise WorkerError(502, "upstream_response_too_large", "research upstream exceeded 4 MiB")
            if response.status < 200 or response.status >= 300:
                if (
                    response.status in retryable_statuses
                    and attempt < len(retry_delays_seconds)
                ):
                    time.sleep(retry_delays_seconds[attempt])
                    continue
                raise WorkerError(502, "upstream_rejected", f"research upstream returned HTTP {response.status}")
            try:
                return json.loads(content)
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                raise WorkerError(502, "invalid_upstream_response", "research upstream returned invalid JSON") from error
        except (OSError, TimeoutError, http.client.HTTPException) as error:
            raise WorkerError(502, "upstream_unavailable", "research upstream is unavailable") from error
        finally:
            connection.close()
    raise AssertionError("upstream retry loop exhausted without a terminal result")


def clean_text(value: object, maximum: int) -> str:
    if not isinstance(value, str):
        return ""
    encoded = value.encode("utf-8")
    if len(encoded) <= maximum:
        return value
    return encoded[:maximum].decode("utf-8", "ignore")


def normalized_json_text(decoded: str) -> str:
    value = json.loads(decoded)
    pending: list[tuple[object, int]] = [(value, 0)]
    nodes = 0
    while pending:
        item, depth = pending.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES or depth > MAX_JSON_DEPTH:
            raise ValueError("public JSON structure exceeded its bound")
        if isinstance(item, str):
            item.encode("utf-8")
        elif isinstance(item, list):
            pending.extend((child, depth + 1) for child in item)
        elif isinstance(item, dict):
            for key, child in item.items():
                key.encode("utf-8")
                pending.append((child, depth + 1))
    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True)


def normalized_v2_text(value: str) -> tuple[str, bool]:
    printable = "".join(
        character
        if character in "\t\n\r" or 0x20 <= ord(character) < 0x7F or ord(character) > 0x9F
        else " "
        for character in value
    )
    encoded = printable.encode("utf-8")
    return clean_text(printable, MAX_V2_SOURCE_TEXT), len(encoded) > MAX_V2_SOURCE_TEXT


def normalize_pdf_fragment(value: object) -> str:
    if not isinstance(value, str):
        return ""
    printable = "".join(
        " " if ord(character) < 0x20 or 0x7F <= ord(character) <= 0x9F else character
        for character in value
    )
    return " ".join(printable.split())


def parse_pdf_payload(raw: bytes) -> dict[str, str]:
    if not raw.startswith(b"%PDF-"):
        raise PDFInputRejected("PDF header is invalid")

    import io
    import logging

    from pypdf import PdfReader

    logging.getLogger("pypdf").setLevel(logging.ERROR)
    reader = PdfReader(
        io.BytesIO(raw),
        strict=True,
        root_object_recovery_limit=MAX_PDF_RECOVERY_OBJECTS,
    )
    try:
        if reader.is_encrypted:
            raise PDFInputRejected("encrypted PDFs are not supported")
        if len(reader.pages) > MAX_PDF_PAGES:
            raise PDFInputRejected("PDF page count exceeded its bound")

        parts: list[str] = []
        used = 0

        class OutputLimitReached(Exception):
            pass

        def visit_text(
            text: str,
            _current_matrix: object,
            _text_matrix: object,
            _font_dictionary: object,
            _font_size: object,
        ) -> None:
            nonlocal used
            fragment = normalize_pdf_fragment(text)
            if not fragment:
                return
            prefix = "\n" if parts else ""
            bounded = clean_text(prefix + fragment, MAX_SOURCE_TEXT - used)
            if bounded:
                parts.append(bounded)
                used += len(bounded.encode("utf-8"))
            if used >= MAX_SOURCE_TEXT:
                raise OutputLimitReached

        for page in reader.pages:
            try:
                page.extract_text(visitor_text=visit_text)
            except OutputLimitReached:
                break
        content = "".join(parts)
        if not content:
            raise PDFInputRejected("PDF contains no extractable text")
        return {"title": "", "content": content}
    finally:
        reader.close()


def constrain_pdf_process() -> None:
    import resource

    for limit, maximum in (
        (resource.RLIMIT_AS, PDF_MEMORY_BYTES),
        (resource.RLIMIT_CORE, 0),
        (resource.RLIMIT_CPU, PDF_CPU_SECONDS),
        (resource.RLIMIT_FSIZE, MAX_PDF_CHILD_RESPONSE),
        (resource.RLIMIT_NOFILE, 16),
    ):
        _soft, hard = resource.getrlimit(limit)
        bounded = maximum if hard == resource.RLIM_INFINITY else min(maximum, hard)
        resource.setrlimit(limit, (bounded, bounded))


def pdf_child() -> int:
    try:
        constrain_pdf_process()
        raw = sys.stdin.buffer.read(MAX_UPSTREAM + 1)
        if not raw or len(raw) > MAX_UPSTREAM:
            return 1
        result = parse_pdf_payload(raw)
        body = json.dumps(result, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode()
        if len(body) > MAX_PDF_CHILD_RESPONSE:
            return 1
        sys.stdout.buffer.write(body)
        return 0
    except Exception:
        return 1


def extract_pdf_text(raw: bytes, *, wall_seconds: float = PDF_WALL_SECONDS) -> tuple[str, str]:
    if not raw.startswith(b"%PDF-"):
        raise WorkerError(502, "unsupported_source", "PDF source has an invalid header")
    try:
        completed = subprocess.run(
            [sys.executable, "-I", os.path.abspath(__file__), PDF_CHILD_MODE],
            input=raw,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=wall_seconds,
            check=False,
            close_fds=True,
            cwd="/",
            env={"PYTHONDONTWRITEBYTECODE": "1", "PYTHONUNBUFFERED": "1"},
        )
    except subprocess.TimeoutExpired:
        message = (
            "PDF text extraction exceeded 5 seconds"
            if wall_seconds == PDF_WALL_SECONDS
            else "PDF text extraction exceeded the source deadline"
        )
        raise WorkerError(502, "pdf_extraction_timeout", message) from None
    except OSError:
        raise WorkerError(502, "unsupported_source", "PDF text extraction is unavailable") from None
    if completed.returncode != 0 or len(completed.stdout) > MAX_PDF_CHILD_RESPONSE:
        raise WorkerError(502, "unsupported_source", "PDF source could not be safely extracted")
    try:
        result = json.loads(completed.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise WorkerError(502, "unsupported_source", "PDF source could not be safely extracted") from None
    if (
        not isinstance(result, dict)
        or set(result) != {"title", "content"}
        or not isinstance(result.get("title"), str)
        or not isinstance(result.get("content"), str)
    ):
        raise WorkerError(502, "unsupported_source", "PDF source could not be safely extracted")
    title = clean_text(result["title"], 2048)
    content = clean_text(result["content"], MAX_SOURCE_TEXT)
    if not content:
        raise WorkerError(502, "unsupported_source", "PDF source contains no extractable text")
    return title, content


def normalized_url_host(hostname: str) -> str:
    host = hostname[:-1] if hostname.endswith(".") else hostname
    if not host or len(host) > 253 or "%" in host:
        raise WorkerError(400, "invalid_source_url", "source URL is invalid")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        labels = host.split(".")
        if any(
            not 1 <= len(label) <= 63
            or label[0] == "-"
            or label[-1] == "-"
            or any(
                not (character.isascii() and (character.isalnum() or character == "-"))
                for character in label
            )
            for label in labels
        ):
            raise WorkerError(400, "invalid_source_url", "source URL is invalid")
    return host.lower()


def public_url_shape(value: object) -> tuple[str, urllib.parse.SplitResult, str, int]:
    if not isinstance(value, str):
        raise WorkerError(400, "invalid_source_url", "source URL is invalid")
    try:
        encoded = value.encode("ascii")
    except UnicodeError as error:
        raise WorkerError(400, "invalid_source_url", "source URL is invalid") from error
    if (
        len(encoded) > 2048
        or "\\" in value
        or any(
            ord(character) <= 0x20 or ord(character) == 0x7F
            for character in value
        )
    ):
        raise WorkerError(400, "invalid_source_url", "source URL is invalid")
    try:
        parsed = urllib.parse.urlsplit(value)
        hostname = parsed.hostname
    except (UnicodeError, ValueError) as error:
        raise WorkerError(400, "invalid_source_url", "source URL is invalid") from error
    if (
        parsed.scheme not in {"http", "https"}
        or not hostname
        or parsed.username
        or parsed.password
        or parsed.fragment
    ):
        raise WorkerError(400, "invalid_source_url", "source URL must be absolute HTTP(S) without user information")
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError as error:
        raise WorkerError(400, "invalid_source_url", "source URL contains an invalid port") from error
    host = normalized_url_host(hostname)
    return value, parsed, host, port


def public_destination(value: object) -> tuple[str, urllib.parse.SplitResult, list[str]]:
    url, parsed, host, port = public_url_shape(value)
    if host == "localhost" or host.endswith(".localhost") or host.endswith(".local") or host.endswith(".internal"):
        raise WorkerError(400, "private_source_denied", "private and local source names are not allowed")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if address is not None and not address.is_global:
        raise WorkerError(400, "private_source_denied", "non-public source addresses are not allowed")
    addresses = resolve_public_addresses(host, port)
    return url, parsed, addresses


def resolve_public_addresses(host: str, port: int) -> list[str]:
    try:
        records = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError) as error:
        raise WorkerError(400, "source_unresolvable", "source hostname could not be resolved") from error
    addresses = []
    for record in records:
        candidate = record[4][0]
        try:
            address = ipaddress.ip_address(candidate)
        except ValueError as error:
            raise WorkerError(400, "source_unresolvable", "source resolver returned an invalid address") from error
        if not address.is_global:
            raise WorkerError(400, "private_source_denied", "source hostname resolved to a non-public address")
        canonical = address.compressed
        if canonical not in addresses:
            addresses.append(canonical)
    if not addresses:
        raise WorkerError(400, "source_unresolvable", "source hostname returned no usable address")
    return addresses


def public_url(value: object) -> str:
    return public_destination(value)[0]


class PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host: str, address: str, port: int, timeout: float = UPSTREAM_TIMEOUT) -> None:
        super().__init__(host, port=port, timeout=timeout)
        self.address = address

    def connect(self) -> None:
        self.sock = socket.create_connection((self.address, self.port), self.timeout, self.source_address)


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, address: str, port: int, timeout: float = UPSTREAM_TIMEOUT) -> None:
        super().__init__(host, port=port, timeout=timeout, context=ssl.create_default_context())
        self.address = address

    def connect(self) -> None:
        raw = socket.create_connection((self.address, self.port), self.timeout, self.source_address)
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except Exception:
            raw.close()
            raise


class PageTextParser(html.parser.HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.title_parts: list[str] = []
        self.hidden = 0
        self.in_title = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in {"script", "style", "template", "noscript"}:
            self.hidden += 1
        if tag == "title" and self.hidden == 0:
            self.in_title = True

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self.in_title = False
        if tag in {"script", "style", "template", "noscript"} and self.hidden > 0:
            self.hidden -= 1

    def handle_data(self, data: str) -> None:
        if self.hidden > 0:
            return
        clean = " ".join(data.split())
        if not clean:
            return
        self.parts.append(clean)
        if self.in_title:
            self.title_parts.append(clean)


def request_public_page(
    parsed: urllib.parse.SplitResult,
    addresses: list[str],
    *,
    deadline: float | None = None,
) -> tuple[http.client.HTTPResponse, http.client.HTTPConnection]:
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = urllib.parse.urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
    last_error: Exception | None = None
    for address in addresses:
        connection_type = PinnedHTTPSConnection if parsed.scheme == "https" else PinnedHTTPConnection
        if deadline is None:
            connection = connection_type(parsed.hostname, address, port)
        else:
            connection = connection_type(parsed.hostname, address, port, remaining_source_seconds(deadline))
        try:
            connection.request("GET", path, headers={
                "Accept": (
                    "text/html,application/xhtml+xml,application/json,"
                    "application/*+json;q=0.95,application/pdf;q=0.9,text/plain;q=0.8"
                ),
                "Accept-Encoding": "identity",
                "User-Agent": "steward-research-worker/1",
            })
            return connection.getresponse(), connection
        except (OSError, TimeoutError, http.client.HTTPException, ssl.SSLError) as error:
            last_error = error
            connection.close()
    raise WorkerError(502, "source_unavailable", "public source is unavailable") from last_error


def remaining_source_seconds(deadline: float | None) -> float:
    if deadline is None:
        return UPSTREAM_TIMEOUT
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise WorkerError(502, "source_unavailable", "public source exceeded its deadline")
    return min(float(UPSTREAM_TIMEOUT), remaining)


def constrain_connection_to_deadline(connection: http.client.HTTPConnection, deadline: float | None) -> None:
    if deadline is None:
        return
    remaining = remaining_source_seconds(deadline)
    sock = getattr(connection, "sock", None)
    if sock is not None:
        sock.settimeout(remaining)


def public_page_result(
    url: str,
    title: str,
    content: str,
    source_media_type: str,
    *,
    include_source_media: bool,
) -> tuple[str, str, str] | tuple[str, str, str, str]:
    result = (url, title, content)
    if include_source_media:
        return (*result, source_media_type)
    return result


def fetch_public_page(
    value: object,
    *,
    deadline: float | None = None,
    include_source_media: bool = False,
) -> tuple[str, str, str] | tuple[str, str, str, str]:
    current = value
    visited: set[str] = set()
    for redirect in range(MAX_REDIRECTS + 1):
        remaining_source_seconds(deadline)
        url, parsed, addresses = public_destination(current)
        if url in visited:
            raise WorkerError(502, "invalid_source_redirect", "public source redirect loop was rejected")
        visited.add(url)
        if deadline is None:
            response, connection = request_public_page(parsed, addresses)
        else:
            response, connection = request_public_page(parsed, addresses, deadline=deadline)
        try:
            if response.status in {301, 302, 303, 307, 308}:
                locations = response.headers.get_all("Location", [])
                if redirect == MAX_REDIRECTS or len(locations) != 1 or len(locations[0].encode()) > 2048:
                    raise WorkerError(502, "invalid_source_redirect", "public source redirect was rejected")
                current = urllib.parse.urljoin(url, locations[0])
                continue
            if response.status < 200 or response.status >= 300:
                raise WorkerError(502, "source_rejected", f"public source returned HTTP {response.status}")
            if response.headers.get("Content-Encoding", "identity").lower() != "identity":
                raise WorkerError(502, "unsupported_source", "compressed public source is not accepted")
            content_type = response.headers.get_content_type().lower()
            json_content = content_type == "application/json" or (
                content_type.startswith("application/") and content_type.endswith("+json")
            )
            if (
                content_type
                not in {"text/html", "application/xhtml+xml", "application/pdf", "text/plain"}
                and not json_content
            ):
                raise WorkerError(502, "unsupported_source", "public source content type is not supported")
            constrain_connection_to_deadline(connection, deadline)
            raw = response.read(MAX_UPSTREAM + 1)
            if len(raw) > MAX_UPSTREAM:
                raise WorkerError(502, "source_too_large", "public source exceeded 4 MiB")
            if content_type == "application/pdf":
                if deadline is None:
                    title, content = extract_pdf_text(raw)
                else:
                    title, content = extract_pdf_text(
                        raw,
                        wall_seconds=min(float(PDF_WALL_SECONDS), remaining_source_seconds(deadline)),
                    )
                return public_page_result(
                    url,
                    title,
                    content,
                    content_type,
                    include_source_media=include_source_media,
                )
            charset = response.headers.get_content_charset() or "utf-8"
            try:
                decoded = raw.decode(charset, "replace")
            except LookupError as error:
                raise WorkerError(502, "unsupported_source", "public source character set is not supported") from error
            if json_content:
                try:
                    normalized = normalized_json_text(decoded)
                    content = clean_text(normalized, MAX_SOURCE_TEXT)
                except (ValueError, RecursionError, UnicodeError) as error:
                    raise WorkerError(
                        502,
                        "unsupported_source",
                        "public JSON source could not be safely normalized",
                    ) from error
                return public_page_result(
                    url,
                    "",
                    content,
                    "application/json",
                    include_source_media=include_source_media,
                )
            if content_type == "text/plain":
                return public_page_result(
                    url,
                    "",
                    clean_text(decoded, MAX_SOURCE_TEXT),
                    content_type,
                    include_source_media=include_source_media,
                )
            parser = PageTextParser()
            parser.feed(decoded)
            parser.close()
            return public_page_result(
                url,
                clean_text(" ".join(parser.title_parts), 2048),
                clean_text("\n".join(parser.parts), MAX_SOURCE_TEXT),
                content_type,
                include_source_media=include_source_media,
            )
        finally:
            connection.close()
    raise WorkerError(502, "invalid_source_redirect", "public source redirect was rejected")


def search(
    payload: dict[str, object],
    upstream: urllib.parse.SplitResult | None,
    brave_api_key: bytes | None = None,
) -> dict[str, object]:
    if set(payload) != {"query", "limit"} or not isinstance(payload.get("query"), str) or type(payload.get("limit")) is not int:
        raise WorkerError(400, "invalid_request", "search requires exact query and limit fields")
    query = payload["query"]
    limit = payload["limit"]
    if not query.strip() or query != query.strip() or len(query.encode()) > 2048 or not 1 <= limit <= 20:
        raise WorkerError(400, "invalid_request", "search query or limit is outside its bound")
    if brave_api_key is not None:
        return search_brave(query, limit, brave_api_key)
    if upstream is None:
        raise WorkerError(503, "search_not_configured", "search upstream is not configured")
    encoded = urllib.parse.urlencode({"q": query, "format": "json"})
    value = upstream_json(upstream, "GET", request_path(upstream, "/search", encoded), None)
    if not isinstance(value, dict) or not isinstance(value.get("results"), list):
        raise WorkerError(502, "invalid_upstream_response", "SearXNG response has no result list")
    results = []
    for item in value["results"]:
        if len(results) >= limit:
            break
        if not isinstance(item, dict):
            continue
        try:
            url = public_url(item.get("url"))
        except WorkerError:
            continue
        results.append({
            "title": clean_text(item.get("title"), 2048),
            "url": url,
            "snippet": clean_text(item.get("content"), 8192),
            "engine": clean_text(item.get("engine"), 128),
        })
    return {"schema_version": "steward.research-search-result.v1", "results": results}


def search_brave(query: str, limit: int, api_key: bytes) -> dict[str, object]:
    """Normalize Brave Web Search into the fixed research-search v1 result."""

    value = upstream_json(
        BRAVE_API_BASE,
        "GET",
        request_path(
            BRAVE_API_BASE,
            "/res/v1/web/search",
            urllib.parse.urlencode({"q": query, "count": limit}),
        ),
        None,
        subscription_token=api_key,
        retryable_statuses=BRAVE_TRANSIENT_STATUS_CODES,
        retry_delays_seconds=BRAVE_RETRY_DELAYS_SECONDS,
    )
    if not isinstance(value, dict) or value.get("type") != "search":
        raise WorkerError(502, "invalid_upstream_response", "Brave response is not a search result")
    if "web" not in value:
        return {"schema_version": "steward.research-search-result.v1", "results": []}
    web = value["web"]
    if not isinstance(web, dict) or not isinstance(web.get("results"), list):
        raise WorkerError(502, "invalid_upstream_response", "Brave response has no web result list")
    results = []
    for item in web["results"]:
        if len(results) >= limit:
            break
        if not isinstance(item, dict):
            continue
        try:
            url = public_url(item.get("url"))
        except WorkerError:
            continue
        results.append({
            "title": clean_text(item.get("title"), 2048),
            "url": url,
            "snippet": clean_text(item.get("description"), 8192),
            "engine": "brave",
        })
    return {"schema_version": "steward.research-search-result.v1", "results": results}


def extract(payload: dict[str, object]) -> dict[str, object]:
    if set(payload) != {"urls"} or not isinstance(payload.get("urls"), list) or not 1 <= len(payload["urls"]) <= 10:
        raise WorkerError(400, "invalid_request", "extract requires one to ten URLs")
    sources = []
    for raw_url in payload["urls"]:
        url, title, content = fetch_public_page(raw_url)
        sources.append({
            "url": url,
            "title": title,
            "content": content,
            "content_type": "text/plain",
        })
    return {"schema_version": "steward.research-extract-result.v1", "sources": sources}


def validate_extract_v2_url(value: object) -> str:
    try:
        url, _parsed, _host, _port = public_url_shape(value)
    except (UnicodeError, ValueError) as error:
        raise WorkerError(400, "invalid_source_url", "source URL is invalid") from error
    return url


def extract_v2_outcome(requested_url: str, batch_deadline: float) -> dict[str, object]:
    source_deadline = min(batch_deadline, time.monotonic() + V2_SOURCE_SECONDS)
    try:
        resolved_url, title, content, source_media_type = fetch_public_page(
            requested_url,
            deadline=source_deadline,
            include_source_media=True,
        )
    except WorkerError as error:
        if error.code not in V2_SOURCE_FAILURE_CODES:
            raise
        return {
            "requested_url": requested_url,
            "disposition": "failed",
            "failure_code": error.code,
        }
    if (
        not isinstance(resolved_url, str)
        or not isinstance(title, str)
        or not isinstance(content, str)
        or source_media_type not in V2_SOURCE_MEDIA_TYPES
    ):
        raise RuntimeError("public source extractor violated its result contract")
    normalized, truncated = normalized_v2_text(content)
    return {
        "requested_url": requested_url,
        "disposition": "extracted",
        "resolved_url": resolved_url,
        "source_media_type": source_media_type,
        "title": title,
        "content": normalized,
        "content_type": "text/plain",
        "content_truncated": truncated,
    }


def failed_v2_outcome(requested_url: str, code: str) -> dict[str, object]:
    return {
        "requested_url": requested_url,
        "disposition": "failed",
        "failure_code": code,
    }


def v2_source_child() -> int:
    try:
        raw = sys.stdin.buffer.read(MAX_REQUEST + 1)
        if not raw or len(raw) > MAX_REQUEST:
            return 1
        payload = json.loads(raw)
        if not isinstance(payload, dict) or set(payload) != {"url"}:
            return 1
        requested_url = validate_extract_v2_url(payload["url"])
        try:
            result: object = extract_v2_outcome(
                requested_url,
                time.monotonic() + V2_SOURCE_SECONDS,
            )
        except WorkerError as error:
            if error.code != "invalid_source_url":
                return 1
            result = {"error": "invalid_source_url"}
        body = json.dumps(result, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode()
        if len(body) > MAX_V2_CHILD_RESPONSE:
            return 1
        sys.stdout.buffer.write(body)
        return 0
    except Exception:
        return 1


def start_v2_source_process(index: int, requested_url: str, batch_deadline: float) -> V2SourceProcess:
    body = json.dumps({"url": requested_url}, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode()
    process = subprocess.Popen(
        [sys.executable, "-I", os.path.abspath(__file__), V2_SOURCE_CHILD_MODE],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        close_fds=True,
        cwd="/",
        env={"PYTHONDONTWRITEBYTECODE": "1", "PYTHONUNBUFFERED": "1"},
        start_new_session=True,
    )
    if process.stdin is None or process.stdout is None:
        process.kill()
        process.wait()
        raise RuntimeError("v2 source process pipes are unavailable")
    try:
        process.stdin.write(body)
    except BrokenPipeError:
        pass
    finally:
        process.stdin.close()
    stdout_fd = process.stdout.fileno()
    os.set_blocking(stdout_fd, False)
    return V2SourceProcess(
        index=index,
        requested_url=requested_url,
        process=process,
        deadline=min(batch_deadline, time.monotonic() + V2_SOURCE_SECONDS),
        output=bytearray(),
        stdout_fd=stdout_fd,
    )


def stop_v2_source_process(
    selector: selectors.BaseSelector,
    source: V2SourceProcess,
    *,
    kill: bool,
) -> None:
    if source.stdout_fd is not None:
        try:
            selector.unregister(source.stdout_fd)
        except KeyError:
            pass
        if source.process.stdout is not None:
            source.process.stdout.close()
        source.stdout_fd = None
    if kill:
        try:
            os.killpg(source.process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    if source.process.poll() is None:
        try:
            source.process.wait(timeout=0.05)
        except subprocess.TimeoutExpired:
            if source.process not in V2_PENDING_REAPS:
                V2_PENDING_REAPS.append(source.process)


def reap_v2_source_processes() -> None:
    V2_PENDING_REAPS[:] = [
        process for process in V2_PENDING_REAPS
        if process.poll() is None
    ]
    if len(V2_PENDING_REAPS) >= V2_MAX_PENDING_REAPS:
        raise RuntimeError("v2 source process reaping capacity is exhausted")


def decode_v2_source_result(source: V2SourceProcess) -> dict[str, object]:
    if source.process.returncode != 0:
        raise RuntimeError("v2 source process failed")
    try:
        value = json.loads(source.output)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError("v2 source process returned invalid JSON") from error
    if value == {"error": "invalid_source_url"}:
        raise WorkerError(400, "invalid_source_url", "source redirect URL is invalid")
    if not isinstance(value, dict) or value.get("requested_url") != source.requested_url:
        raise RuntimeError("v2 source process returned an invalid outcome")
    if value.get("disposition") == "failed":
        if set(value) != {"requested_url", "disposition", "failure_code"}:
            raise RuntimeError("v2 source process returned an invalid failure")
        if value.get("failure_code") not in V2_SOURCE_FAILURE_CODES:
            raise RuntimeError("v2 source process returned an unknown failure")
        return value
    if value.get("disposition") != "extracted" or set(value) != {
        "requested_url",
        "disposition",
        "resolved_url",
        "source_media_type",
        "title",
        "content",
        "content_type",
        "content_truncated",
    }:
        raise RuntimeError("v2 source process returned an invalid extraction")
    if (
        not isinstance(value.get("resolved_url"), str)
        or not isinstance(value.get("title"), str)
        or not isinstance(value.get("content"), str)
        or value.get("source_media_type") not in V2_SOURCE_MEDIA_TYPES
        or value.get("content_type") != "text/plain"
        or type(value.get("content_truncated")) is not bool
    ):
        raise RuntimeError("v2 source process returned invalid extraction fields")
    try:
        public_url_shape(value["resolved_url"])
        normalized, truncated = normalized_v2_text(value["content"])
    except (UnicodeError, ValueError, WorkerError) as error:
        raise RuntimeError("v2 source process returned unsafe extraction fields") from error
    if (
        normalized != value["content"]
        or truncated
        or len(value["title"].encode("utf-8")) > 2048
    ):
        raise RuntimeError("v2 source process exceeded an extraction field bound")
    return value


def run_v2_source_processes(
    urls: list[str],
    process_factory: Callable[[int, str, float], V2SourceProcess] | None = None,
) -> list[dict[str, object]]:
    if process_factory is None:
        process_factory = start_v2_source_process
    reap_v2_source_processes()
    cleanup_reserve = min(
        float(V2_CLEANUP_RESERVE_SECONDS),
        V2_BATCH_SECONDS / 4,
    )
    batch_deadline = time.monotonic() + V2_BATCH_SECONDS - cleanup_reserve
    outcomes: list[dict[str, object] | None] = [None] * len(urls)
    running: list[V2SourceProcess] = []
    next_index = 0
    selector = selectors.DefaultSelector()
    try:
        while next_index < len(urls) or running:
            now = time.monotonic()
            if now >= batch_deadline:
                for source in running:
                    stop_v2_source_process(selector, source, kill=True)
                    outcomes[source.index] = failed_v2_outcome(source.requested_url, "source_unavailable")
                running.clear()
                while next_index < len(urls):
                    outcomes[next_index] = failed_v2_outcome(urls[next_index], "source_unavailable")
                    next_index += 1
                break

            while next_index < len(urls) and len(running) < V2_MAX_CONCURRENCY:
                if time.monotonic() >= batch_deadline:
                    break
                source = process_factory(next_index, urls[next_index], batch_deadline)
                if not isinstance(source, V2SourceProcess) or source.stdout_fd is None:
                    raise RuntimeError("v2 source process factory returned an invalid process")
                selector.register(source.stdout_fd, selectors.EVENT_READ, source)
                running.append(source)
                next_index += 1

            completed: list[V2SourceProcess] = []
            now = time.monotonic()
            for source in running:
                if now >= source.deadline:
                    stop_v2_source_process(selector, source, kill=True)
                    outcomes[source.index] = failed_v2_outcome(source.requested_url, "source_unavailable")
                    completed.append(source)
                elif source.stdout_fd is None and source.process.poll() is not None:
                    outcomes[source.index] = decode_v2_source_result(source)
                    stop_v2_source_process(selector, source, kill=False)
                    completed.append(source)
            if completed:
                running = [source for source in running if source not in completed]
                continue

            wake_deadline = min([batch_deadline, *(source.deadline for source in running)])
            timeout = max(0.0, min(0.05, wake_deadline - time.monotonic()))
            for key, _events in selector.select(timeout):
                source = key.data
                try:
                    chunk = os.read(key.fd, min(64 << 10, MAX_V2_CHILD_RESPONSE + 1 - len(source.output)))
                except BlockingIOError:
                    continue
                if chunk:
                    source.output.extend(chunk)
                    if len(source.output) > MAX_V2_CHILD_RESPONSE:
                        raise RuntimeError("v2 source process response exceeded its bound")
                    continue
                selector.unregister(key.fd)
                if source.process.stdout is not None:
                    source.process.stdout.close()
                source.stdout_fd = None
    finally:
        for source in running:
            stop_v2_source_process(selector, source, kill=True)
        selector.close()
        reap_v2_source_processes()
    if any(outcome is None for outcome in outcomes):
        raise RuntimeError("v2 extraction did not produce every outcome")
    return [outcome for outcome in outcomes if outcome is not None]


def extract_v2(payload: dict[str, object]) -> dict[str, object]:
    if set(payload) != {"urls"} or not isinstance(payload.get("urls"), list) or not 1 <= len(payload["urls"]) <= 10:
        raise WorkerError(400, "invalid_request", "extract requires one to ten URLs")
    urls = [validate_extract_v2_url(value) for value in payload["urls"]]
    outcomes = run_v2_source_processes(urls)
    return {"schema_version": "steward.research-extract-result.v2", "outcomes": outcomes}


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "steward-research-worker/1"

    def do_POST(self) -> None:  # noqa: N802
        try:
            self.authorize()
            payload = self.read_payload()
            if self.path == "/v1/search":
                result = search(
                    payload,
                    self.server.search_upstream,
                    self.server.brave_api_key,
                )
            elif self.path == "/v1/extract":
                result = extract(payload)
            elif self.path == "/v2/extract":
                result = extract_v2(payload)
            else:
                raise WorkerError(404, "route_not_found", "route is not available")
            self.write_json(200, result)
        except WorkerError as error:
            self.write_json(error.status, {"error": error.code, "message": error.message})
        except Exception:
            self.write_json(500, {"error": "internal_error", "message": "research worker failed safely"})

    def authorize(self) -> None:
        values = self.headers.get_all("Authorization", [])
        prefix = "Bearer "
        if len(values) != 1 or not values[0].startswith(prefix):
            raise WorkerError(401, "unauthorized", "one bearer credential is required")
        supplied = values[0][len(prefix):].encode("ascii", "ignore")
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
            body = b'{"error":"response_too_large","message":"normalized research result exceeded 1 MiB"}'
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format_text: str, *arguments: object) -> None:
        print(f"research-worker: {self.command} {self.path.split('?', 1)[0]}", file=sys.stderr)


class Server(http.server.HTTPServer):
    request_queue_size = 8

    def __init__(self, address: tuple[str, int]) -> None:
        super().__init__(address, Handler)
        self.worker_token = read_secret(os.environ.get("STEWARD_WORKER_TOKEN_FILE", ""), "worker token")
        self.search_upstream = parse_upstream(os.environ.get("STEWARD_SEARCH_URL", ""), "search upstream")
        self.brave_api_key = read_secret(
            os.environ.get("STEWARD_BRAVE_API_KEY_FILE", ""),
            "Brave Search API key",
            required=False,
        )


def main() -> int:
    if os.geteuid() == 0 or os.getegid() == 0:
        raise RuntimeError("research worker refuses to run as root")
    port_text = os.environ.get("STEWARD_WORKER_PORT", "8080")
    if re.fullmatch(r"[0-9]{2,5}", port_text) is None or not 1024 <= int(port_text) <= 65535:
        raise RuntimeError("STEWARD_WORKER_PORT is invalid")
    server = Server(("0.0.0.0", int(port_text)))
    server.timeout = 1
    print(f"research-worker: ready on :{port_text}", file=sys.stderr)
    try:
        while True:
            server.handle_request()
    except KeyboardInterrupt:
        return 0
    finally:
        server.server_close()


if __name__ == "__main__":
    if sys.argv[1:] == [PDF_CHILD_MODE]:
        raise SystemExit(pdf_child())
    if sys.argv[1:] == [V2_SOURCE_CHILD_MODE]:
        raise SystemExit(v2_source_child())
    if sys.argv[1:]:
        print("research-worker: unsupported arguments", file=sys.stderr)
        raise SystemExit(1)
    try:
        raise SystemExit(main())
    except RuntimeError as error:
        print(f"research-worker: {error}", file=sys.stderr)
        raise SystemExit(1)
