#!/usr/bin/env python3
"""Finite connector client for separately isolated Codex and Claude Code workers."""

from __future__ import annotations

import argparse
import http.client
import json
import sys
import urllib.parse

CONNECTOR_ORIGIN = "http://steward-relay:8081"
MAX_REQUEST = 64 << 10
MAX_RESPONSE = 1 << 20


def bounded_text(value: str, maximum: int) -> str:
    if not value or len(value.encode("utf-8")) > maximum or value.strip() != value:
        raise ValueError("text is empty, padded, or exceeds its byte limit")
    if "\x00" in value:
        raise ValueError("text contains NUL")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(prog="steward-coding-worker")
    parser.add_argument("--worker", choices=("codex", "claude-code"), required=True)
    parser.add_argument("--task", required=True)
    parser.add_argument("--mode", choices=("read", "write"), default="read")
    parser.add_argument("--timeout-seconds", type=int, choices=range(30, 901), default=600)
    arguments = parser.parse_args()
    task = bounded_text(arguments.task, 16384)
    connector = "steward-codex" if arguments.worker == "codex" else "steward-claude-code"
    origin = urllib.parse.urlsplit(CONNECTOR_ORIGIN)
    if origin.scheme != "http" or origin.hostname != "steward-relay" or origin.port != 8081 or origin.path or origin.query or origin.fragment:
        raise ValueError("Steward connector origin is invalid")
    raw = json.dumps(
        {"schema_version": "steward.coding-task.v1", "task": task, "mode": arguments.mode,
         "timeout_seconds": arguments.timeout_seconds},
        ensure_ascii=False, separators=(",", ":"), sort_keys=True,
    ).encode("utf-8")
    if len(raw) > MAX_REQUEST:
        raise ValueError("coding task exceeds the bounded connector payload")
    connection = http.client.HTTPConnection(origin.hostname, origin.port, timeout=arguments.timeout_seconds + 15)
    try:
        connection.request(
            "POST", f"/v1/connectors/{connector}/operations/run", body=raw,
            headers={"Accept": "application/json", "Content-Type": "application/json", "Content-Length": str(len(raw))},
        )
        response = connection.getresponse()
        body = response.read(MAX_RESPONSE + 1)
        if len(body) > MAX_RESPONSE:
            raise RuntimeError("coding-worker response exceeds 1 MiB")
        if response.status < 200 or response.status >= 300:
            raise RuntimeError(f"coding worker returned HTTP {response.status}")
        value = json.loads(body)
        if not isinstance(value, dict) or value.get("schema_version") != "steward.coding-result.v1":
            raise RuntimeError("coding worker returned an invalid result contract")
        json.dump(value, sys.stdout, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
        sys.stdout.write("\n")
        return 0
    finally:
        connection.close()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, RuntimeError, json.JSONDecodeError, OSError) as error:
        print(f"steward-coding-worker: {error}", file=sys.stderr)
        raise SystemExit(1)
