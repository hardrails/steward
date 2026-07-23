#!/usr/bin/env python3
"""Bounded research and finding client for Steward's Hermes research profile."""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import sys
import urllib.parse

CONNECTOR_ORIGIN = "http://steward-relay:8081"
EVENT_ORIGIN = "http://steward-relay:8083"
MAX_REQUEST = 64 << 10
MAX_RESPONSE = 1 << 20


def bounded_text(value: str, maximum: int) -> str:
    if not value or len(value.encode("utf-8")) > maximum or value.strip() != value:
        raise ValueError("text is empty, padded, or exceeds its byte limit")
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        raise ValueError("text contains a control character")
    return value


def post_json(origin: str, path: str, value: object, maximum: int = MAX_RESPONSE) -> object:
    parsed = urllib.parse.urlsplit(origin)
    expected_port = 8083 if path == "/v1/events" else 8081
    if parsed.scheme != "http" or parsed.hostname != "steward-relay" or parsed.port != expected_port or parsed.path or parsed.query or parsed.fragment:
        raise ValueError("Steward service origin is invalid")
    raw = json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    if not raw or len(raw) > MAX_REQUEST:
        raise ValueError("request exceeds the bounded connector payload")
    connection = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=30)
    try:
        connection.request(
            "POST", path, body=raw,
            headers={"Accept": "application/json", "Content-Type": "application/json", "Content-Length": str(len(raw))},
        )
        response = connection.getresponse()
        body = response.read(maximum + 1)
        if len(body) > maximum:
            raise RuntimeError("response exceeds the bounded result size")
        if response.status < 200 or response.status >= 300:
            raise RuntimeError(f"Steward service returned HTTP {response.status}")
        decoded = json.loads(body)
        if not isinstance(decoded, dict):
            raise RuntimeError("Steward service returned a non-object result")
        return decoded
    finally:
        connection.close()


def search(arguments: argparse.Namespace) -> object:
    return post_json(
        CONNECTOR_ORIGIN,
        "/v1/connectors/steward-research-search/operations/search",
        {"query": bounded_text(arguments.query, 2048), "limit": arguments.limit},
    )


def extract(arguments: argparse.Namespace) -> object:
    urls: list[str] = []
    for value in arguments.url:
        bounded_text(value, 2048)
        parsed = urllib.parse.urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("source URL must be an absolute HTTP(S) URL without user information")
        urls.append(value)
    return post_json(
        CONNECTOR_ORIGIN,
        "/v1/connectors/steward-research-extract/operations/extract",
        {"urls": urls},
    )


def browser_search(arguments: argparse.Namespace) -> object:
    return post_json(
        CONNECTOR_ORIGIN,
        "/v1/connectors/steward-browser-search/operations/search",
        {"query": bounded_text(arguments.query, 2048), "limit": arguments.limit},
    )


def browser_read(arguments: argparse.Namespace) -> object:
    refs: list[str] = []
    for value in arguments.source_ref:
        refs.append(bounded_text(value, 128))
    return post_json(
        CONNECTOR_ORIGIN,
        "/v1/connectors/steward-browser-read/operations/read",
        {"source_refs": refs, "screenshot": arguments.screenshot},
    )


def report(arguments: argparse.Namespace) -> object:
    source_url = ""
    if arguments.source_url:
        source_url = bounded_text(arguments.source_url, 2048)
        parsed = urllib.parse.urlsplit(source_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("source URL must be an absolute HTTP(S) URL without user information")
    attributes = {"source_url": source_url} if source_url else {}
    content = {
        "schema_version": "steward.instance-event.v1",
        "idempotency_key": arguments.idempotency_key or hashlib.sha256(
            (arguments.code + "\x00" + arguments.summary + "\x00" + source_url).encode("utf-8")
        ).hexdigest(),
        "kind": "finding",
        "code": bounded_text(arguments.code, 128),
        "severity": arguments.severity,
        "summary": bounded_text(arguments.summary, 1024),
        "attributes": attributes,
    }
    return post_json(EVENT_ORIGIN, "/v1/events", content, 16 << 10)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(prog="steward-research")
    commands = result.add_subparsers(dest="command", required=True)
    search_command = commands.add_parser("search")
    search_command.add_argument("--query", required=True)
    search_command.add_argument("--limit", type=int, choices=range(1, 21), default=5)
    extract_command = commands.add_parser("extract")
    extract_command.add_argument("--url", action="append", required=True)
    browser_search_command = commands.add_parser("browser-search")
    browser_search_command.add_argument("--query", required=True)
    browser_search_command.add_argument("--limit", type=int, choices=range(1, 21), default=5)
    browser_read_command = commands.add_parser("browser-read")
    browser_read_command.add_argument("--source-ref", action="append", required=True)
    browser_read_command.add_argument("--screenshot", action="store_true")
    report_command = commands.add_parser("report")
    report_command.add_argument("--code", required=True)
    report_command.add_argument("--summary", required=True)
    report_command.add_argument("--source-url", default="")
    report_command.add_argument("--severity", choices=("info", "warning", "critical"), default="info")
    report_command.add_argument("--idempotency-key", default="")
    return result


def main() -> int:
    arguments = parser().parse_args()
    if arguments.command == "search":
        value = search(arguments)
    elif arguments.command == "extract":
        if len(arguments.url) > 10:
            raise ValueError("at most 10 URLs may be extracted per call")
        value = extract(arguments)
    elif arguments.command == "browser-search":
        value = browser_search(arguments)
    elif arguments.command == "browser-read":
        if len(arguments.source_ref) > 5:
            raise ValueError("at most 5 browser source references may be read per call")
        value = browser_read(arguments)
    else:
        value = report(arguments)
    json.dump(value, sys.stdout, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, RuntimeError, json.JSONDecodeError, OSError) as error:
        print(f"steward-research: {error}", file=sys.stderr)
        raise SystemExit(1)
