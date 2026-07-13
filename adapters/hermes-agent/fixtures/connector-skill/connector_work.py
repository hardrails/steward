#!/usr/bin/env python3
"""Perform or negatively probe the fixed Steward connector operation."""

from __future__ import annotations

import http.client
import json
import os
import re
import sys

LOGICAL_BASE = "http://steward-relay:8081"
CONNECTOR_ID = "local-work"
ALLOWED_OPERATION = "perform"
FORBIDDEN_OPERATION = "forbidden"
REQUEST = {"input": "steward-hermes-connector-work-v1"}
EXPECTED_RESULT = {
    "result": "sha256:63fc95de3acbc505e04bf92268ca1bb94c3b1f8c70c0581a8260da0839e72467",
    "schema_version": "steward.connector-work.result.v1",
}
MAX_RESPONSE_BYTES = 4096
TIMEOUT_SECONDS = 10
TASK_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")


class ConnectorError(Exception):
    pass


def canonical_json(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode()


def call(operation: str, task_id: str) -> tuple[int, object]:
    if os.environ.get("STEWARD_CONNECTOR_URL") != LOGICAL_BASE:
        raise ConnectorError("logical_connector_url_unavailable")
    body = canonical_json(REQUEST)
    path = f"/v1/connectors/{CONNECTOR_ID}/operations/{operation}"
    connection = http.client.HTTPConnection("steward-relay", 8081, timeout=TIMEOUT_SECONDS)
    try:
        connection.request(
            "POST",
            path,
            body=body,
            headers={
                "Accept": "application/json",
                "Content-Length": str(len(body)),
                "Content-Type": "application/json",
                "X-Steward-Task-ID": task_id,
            },
        )
        response = connection.getresponse()
        if response.getheader("Content-Encoding") not in (None, "identity"):
            raise ConnectorError("encoded_response_denied")
        declared = response.getheader("Content-Length")
        if declared is not None and (not declared.isdigit() or int(declared) > MAX_RESPONSE_BYTES):
            raise ConnectorError("response_too_large")
        raw = response.read(MAX_RESPONSE_BYTES + 1)
        if len(raw) > MAX_RESPONSE_BYTES:
            raise ConnectorError("response_too_large")
        if response.getheader("Content-Type") != "application/json":
            raise ConnectorError("invalid_response_type")
        try:
            payload = json.loads(raw)
        except (TypeError, ValueError) as error:
            raise ConnectorError("invalid_response_json") from error
        return response.status, payload
    except (ConnectionError, OSError, TimeoutError, http.client.HTTPException) as error:
        raise ConnectorError("connector_unavailable") from error
    finally:
        connection.close()


def main() -> int:
    if len(sys.argv) != 3 or sys.argv[1] not in {"perform", "replay", "forbidden"} or TASK_ID.fullmatch(sys.argv[2]) is None:
        print("connector-work: expected MODE and one bounded task ID", file=sys.stderr)
        return 2
    mode, task_id = sys.argv[1:]
    operation = FORBIDDEN_OPERATION if mode == "forbidden" else ALLOWED_OPERATION
    try:
        status, payload = call(operation, task_id)
    except ConnectorError as error:
        print(f"connector-work: {error}", file=sys.stderr)
        return 1

    if mode == "perform":
        if status != 200 or payload != EXPECTED_RESULT:
            print("connector-work: deterministic work result was invalid", file=sys.stderr)
            return 1
        result = payload
    else:
        expected_status = 409 if mode == "replay" else 403
        expected_error = "connector_task_replayed" if mode == "replay" else "connector_denied"
        if (
            status != expected_status
            or not isinstance(payload, dict)
            or set(payload) != {"error", "message"}
            or payload.get("error") != expected_error
            or not isinstance(payload.get("message"), str)
        ):
            print(f"connector-work: {mode} did not fail closed", file=sys.stderr)
            return 1
        result = {
            "error": expected_error,
            "schema_version": "steward.connector-work.denial.v1",
            "status": expected_status,
        }
    sys.stdout.buffer.write(canonical_json(result) + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
