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
import socket
import ssl
import stat
import sys
import time
import urllib.parse

MAX_REQUEST = 64 << 10
MAX_UPSTREAM = 4 << 20
MAX_RESPONSE = 1 << 20
MAX_SOURCE_TEXT = 256 << 10
UPSTREAM_TIMEOUT = 45
MAX_REDIRECTS = 5


class WorkerError(Exception):
    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


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
) -> object:
    body = None if payload is None else json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode()
    headers = {"Accept": "application/json", "Accept-Encoding": "identity", "User-Agent": "steward-research-worker/1"}
    if body is not None:
        headers.update({"Content-Type": "application/json", "Content-Length": str(len(body))})
    if token is not None:
        headers["Authorization"] = "Bearer " + token.decode("ascii")
    connection_type = http.client.HTTPSConnection if base.scheme == "https" else http.client.HTTPConnection
    connection = connection_type(base.hostname, base.port, timeout=UPSTREAM_TIMEOUT)
    try:
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        content = response.read(MAX_UPSTREAM + 1)
        if len(content) > MAX_UPSTREAM:
            raise WorkerError(502, "upstream_response_too_large", "research upstream exceeded 4 MiB")
        if response.status < 200 or response.status >= 300:
            raise WorkerError(502, "upstream_rejected", f"research upstream returned HTTP {response.status}")
        try:
            return json.loads(content)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise WorkerError(502, "invalid_upstream_response", "research upstream returned invalid JSON") from error
    except (OSError, TimeoutError, http.client.HTTPException) as error:
        raise WorkerError(502, "upstream_unavailable", "research upstream is unavailable") from error
    finally:
        connection.close()


def clean_text(value: object, maximum: int) -> str:
    if not isinstance(value, str):
        return ""
    encoded = value.encode("utf-8")
    if len(encoded) <= maximum:
        return value
    return encoded[:maximum].decode("utf-8", "ignore")


def public_destination(value: object) -> tuple[str, urllib.parse.SplitResult, list[str]]:
    if not isinstance(value, str) or len(value.encode()) > 2048:
        raise WorkerError(400, "invalid_source_url", "source URL is invalid")
    parsed = urllib.parse.urlsplit(value)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.fragment
    ):
        raise WorkerError(400, "invalid_source_url", "source URL must be absolute HTTP(S) without user information")
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError as error:
        raise WorkerError(400, "invalid_source_url", "source URL contains an invalid port") from error
    host = parsed.hostname.rstrip(".").lower()
    if host == "localhost" or host.endswith(".localhost") or host.endswith(".local") or host.endswith(".internal"):
        raise WorkerError(400, "private_source_denied", "private and local source names are not allowed")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if address is not None and not address.is_global:
        raise WorkerError(400, "private_source_denied", "non-public source addresses are not allowed")
    addresses = resolve_public_addresses(host, port)
    return value, parsed, addresses


def resolve_public_addresses(host: str, port: int) -> list[str]:
    try:
        records = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
    except socket.gaierror as error:
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
    def __init__(self, host: str, address: str, port: int) -> None:
        super().__init__(host, port=port, timeout=UPSTREAM_TIMEOUT)
        self.address = address

    def connect(self) -> None:
        self.sock = socket.create_connection((self.address, self.port), self.timeout, self.source_address)


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, address: str, port: int) -> None:
        super().__init__(host, port=port, timeout=UPSTREAM_TIMEOUT, context=ssl.create_default_context())
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
) -> tuple[http.client.HTTPResponse, http.client.HTTPConnection]:
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = urllib.parse.urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
    last_error: Exception | None = None
    for address in addresses:
        connection_type = PinnedHTTPSConnection if parsed.scheme == "https" else PinnedHTTPConnection
        connection = connection_type(parsed.hostname, address, port)
        try:
            connection.request("GET", path, headers={
                "Accept": "text/html,application/xhtml+xml,text/plain;q=0.9",
                "Accept-Encoding": "identity",
                "User-Agent": "steward-research-worker/1",
            })
            return connection.getresponse(), connection
        except (OSError, TimeoutError, http.client.HTTPException, ssl.SSLError) as error:
            last_error = error
            connection.close()
    raise WorkerError(502, "source_unavailable", "public source is unavailable") from last_error


def fetch_public_page(value: object) -> tuple[str, str, str]:
    current = value
    visited: set[str] = set()
    for redirect in range(MAX_REDIRECTS + 1):
        url, parsed, addresses = public_destination(current)
        if url in visited:
            raise WorkerError(502, "invalid_source_redirect", "public source redirect loop was rejected")
        visited.add(url)
        response, connection = request_public_page(parsed, addresses)
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
            if content_type not in {"text/html", "application/xhtml+xml", "text/plain"}:
                raise WorkerError(502, "unsupported_source", "public source content type is not supported")
            raw = response.read(MAX_UPSTREAM + 1)
            if len(raw) > MAX_UPSTREAM:
                raise WorkerError(502, "source_too_large", "public source exceeded 4 MiB")
            charset = response.headers.get_content_charset() or "utf-8"
            try:
                decoded = raw.decode(charset, "replace")
            except LookupError as error:
                raise WorkerError(502, "unsupported_source", "public source character set is not supported") from error
            if content_type == "text/plain":
                return url, "", clean_text(decoded, MAX_SOURCE_TEXT)
            parser = PageTextParser()
            parser.feed(decoded)
            parser.close()
            return url, clean_text(" ".join(parser.title_parts), 2048), clean_text("\n".join(parser.parts), MAX_SOURCE_TEXT)
        finally:
            connection.close()
    raise WorkerError(502, "invalid_source_redirect", "public source redirect was rejected")


def search(payload: dict[str, object], upstream: urllib.parse.SplitResult | None) -> dict[str, object]:
    if upstream is None:
        raise WorkerError(503, "search_not_configured", "search upstream is not configured")
    if set(payload) != {"query", "limit"} or not isinstance(payload.get("query"), str) or type(payload.get("limit")) is not int:
        raise WorkerError(400, "invalid_request", "search requires exact query and limit fields")
    query = payload["query"]
    limit = payload["limit"]
    if not query.strip() or query != query.strip() or len(query.encode()) > 2048 or not 1 <= limit <= 20:
        raise WorkerError(400, "invalid_request", "search query or limit is outside its bound")
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


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "steward-research-worker/1"

    def do_POST(self) -> None:  # noqa: N802
        try:
            self.authorize()
            payload = self.read_payload()
            if self.path == "/v1/search":
                result = search(payload, self.server.search_upstream)
            elif self.path == "/v1/extract":
                result = extract(payload)
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
    try:
        raise SystemExit(main())
    except RuntimeError as error:
        print(f"research-worker: {error}", file=sys.stderr)
        raise SystemExit(1)
