#!/usr/bin/env python3
"""Finite connector client for separately isolated Codex and Claude Code workers."""

from __future__ import annotations

import argparse
import base64
import hashlib
import http.client
import json
import re
import sys
import unicodedata
import urllib.parse

CONNECTOR_ORIGIN = "http://steward-relay:8081"
MAX_REQUEST = 64 << 10
MAX_RESPONSE = 1 << 20
MAX_PORTABLE_RESULT = 448 << 10
MAX_HANDOFF_PATCH = 256 << 10
MAX_STREAM = 448 << 10
MAX_HANDOFF_STREAM = 16 << 10
MAX_V1_CHANGED_PATHS = 4096
MAX_CHANGED_PATHS = 512
MAX_CHANGED_PATH_BYTES = 48 << 10
MAX_TASK = 16 << 10
MAX_TIMEOUT = 900
CONNECTOR_GRACE_SECONDS = 150
TASK_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
HEX_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
OBJECT_ID_LENGTHS = {"sha1": 40, "sha256": 64}
RESULT_FIELDS = {
    "schema_version",
    "engine",
    "mode",
    "outcome",
    "exit_code",
    "duration_ms",
    "changed_paths",
    "stdout",
    "stderr",
}
HANDOFF_FIELDS = {
    "schema_version",
    "object_format",
    "base_commit",
    "base_tree",
    "result_tree",
    "patch_sha256",
    "patch_bytes",
    "patch_base64",
    "changed_paths",
}


def bounded_text(value: str, maximum: int) -> str:
    if not value or len(value.encode("utf-8")) > maximum or value.strip() != value:
        raise ValueError("text is empty, padded, or exceeds its byte limit")
    if "\x00" in value:
        raise ValueError("text contains NUL")
    return value


def bounded_task_id(value: str) -> str:
    if TASK_ID.fullmatch(value) is None:
        raise ValueError("task ID must use 1-128 letters, digits, dot, underscore, or hyphen")
    return value


def canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def decode_json(raw: bytes) -> object:
    def exact_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON object field")
            result[key] = value
        return result

    def invalid_constant(value: str) -> object:
        raise ValueError(f"non-finite JSON number {value}")

    try:
        decoded = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=exact_object,
            parse_constant=invalid_constant,
        )
    except (UnicodeDecodeError, ValueError) as error:
        raise RuntimeError("coding worker returned invalid JSON") from error
    if canonical_json(decoded) != raw:
        raise RuntimeError("coding worker returned non-canonical JSON")
    return decoded


def object_id(value: object, length: int, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != length
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise RuntimeError(f"coding worker returned an invalid {label}")
    return value


def decoded_source_bytes(value: str) -> int:
    return sum(
        1 if character == "\ufffd" else len(character.encode("utf-8"))
        for character in value
    )


def _portable_component(component: str) -> str:
    normalized = unicodedata.normalize("NFC", component).casefold()
    protected = normalized.rstrip(" .")
    device = protected.split(".", 1)[0]
    short_prefix, short_separator, short_suffix = protected.partition("~")
    gitmodules_fallback = (
        short_separator == "~"
        and 1 <= len(short_prefix) <= 6
        and "gi7eba".startswith(short_prefix)
        and len(short_prefix) + len(short_suffix) == 7
        and re.fullmatch(r"[1-9][0-9]*", short_suffix) is not None
    )
    if (
        not normalized
        or normalized in {".", ".."}
        or normalized[-1] in {" ", "."}
        or "\\" in normalized
        or ":" in normalized
        or any(character in '<>"|?*' for character in normalized)
        or any(
            "\u200c" <= character <= "\u200f"
            or "\u202a" <= character <= "\u202e"
            or "\u206a" <= character <= "\u206f"
            or character == "\ufeff"
            for character in normalized
        )
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in normalized)
        or protected in {".git", ".gitmodules"}
        or re.fullmatch(r"\.?git~[0-9]+", protected) is not None
        or re.fullmatch(r"gitmod~[1-4]", protected) is not None
        or gitmodules_fallback
        or device in {"con", "prn", "aux", "nul", "conin$", "conout$"}
        or re.fullmatch(r"(com|lpt)([1-9]|[¹²³])", device) is not None
    ):
        raise RuntimeError("coding worker returned a non-portable changed path")
    return normalized


def _portable_path_key(components: tuple[str, ...]) -> str:
    return "/".join(_portable_component(component) for component in components)


def changed_paths(
    value: object,
    *,
    maximum: int,
    maximum_bytes: int,
) -> list[str]:
    if not isinstance(value, list) or len(value) > maximum:
        raise RuntimeError("coding worker returned an invalid changed-path inventory")
    result: list[str] = []
    portable_paths: set[str] = set()
    total = 0
    for path in value:
        if not isinstance(path, str):
            raise RuntimeError("coding worker returned a non-text changed path")
        encoded = path.encode("utf-8")
        components = path.split("/")
        if (
            not encoded
            or len(encoded) > 4096
            or path.startswith("/")
            or any(component in {"", ".", ".."} for component in components)
            or any(ord(character) < 0x20 or ord(character) == 0x7F for character in path)
        ):
            raise RuntimeError("coding worker returned an unsafe changed path")
        portable_key = _portable_path_key(tuple(components))
        if portable_key in portable_paths:
            raise RuntimeError("coding worker returned colliding changed paths")
        portable_paths.add(portable_key)
        total += len(encoded)
        result.append(path)
    if total > maximum_bytes or result != sorted(set(result)):
        raise RuntimeError("coding worker returned a non-canonical changed-path inventory")
    return result


def validate_common(
    value: dict[str, object],
    arguments: argparse.Namespace,
    *,
    schema_version: str,
    maximum_paths: int,
    maximum_path_bytes: int,
) -> list[str]:
    expected_fields = RESULT_FIELDS | ({"handoff"} if schema_version == "steward.coding-result.v2" else set())
    if set(value) != expected_fields or value.get("schema_version") != schema_version:
        raise RuntimeError("coding worker returned an invalid result contract")
    if value.get("engine") != arguments.worker or value.get("mode") != arguments.mode:
        raise RuntimeError("coding worker result does not match the requested engine and mode")
    outcome = value.get("outcome")
    exit_code = value.get("exit_code")
    duration = value.get("duration_ms")
    stdout = value.get("stdout")
    stderr = value.get("stderr")
    stream_limit = MAX_HANDOFF_STREAM if schema_version == "steward.coding-result.v2" else MAX_STREAM
    if (
        outcome not in {"completed", "failed"}
        or type(exit_code) is not int
        or not -(1 << 31) <= exit_code < (1 << 31)
        or (outcome == "completed") != (exit_code == 0)
        or type(duration) is not int
        or not 0 <= duration <= (arguments.timeout_seconds + CONNECTOR_GRACE_SECONDS) * 1000
        or not isinstance(stdout, str)
        or not isinstance(stderr, str)
        or decoded_source_bytes(stdout) > stream_limit
        or decoded_source_bytes(stderr) > stream_limit
    ):
        raise RuntimeError("coding worker returned invalid execution metadata")
    return changed_paths(
        value.get("changed_paths"),
        maximum=maximum_paths,
        maximum_bytes=maximum_path_bytes,
    )


def validate_handoff(
    handoff: object,
    expected_base_commit: str,
    top_level_paths: list[str],
    *,
    read_only: bool,
) -> None:
    if not isinstance(handoff, dict) or set(handoff) != HANDOFF_FIELDS:
        raise RuntimeError("coding worker returned an invalid Git handoff contract")
    object_format = handoff.get("object_format")
    object_id_length = OBJECT_ID_LENGTHS.get(object_format) if isinstance(object_format, str) else None
    if handoff.get("schema_version") != "steward.git-handoff.v1" or object_id_length is None:
        raise RuntimeError("coding worker returned an unsupported Git handoff")
    if len(expected_base_commit) != object_id_length:
        raise RuntimeError("coding worker handoff object format does not match the requested base")
    base_commit = object_id(handoff.get("base_commit"), object_id_length, "handoff base commit")
    base_tree = object_id(handoff.get("base_tree"), object_id_length, "handoff base tree")
    result_tree = object_id(handoff.get("result_tree"), object_id_length, "handoff result tree")
    if base_commit != expected_base_commit:
        raise RuntimeError("coding worker handoff does not match the requested base")
    paths = changed_paths(
        handoff.get("changed_paths"),
        maximum=MAX_CHANGED_PATHS,
        maximum_bytes=MAX_CHANGED_PATH_BYTES,
    )
    if paths != top_level_paths:
        raise RuntimeError("coding worker result and handoff path inventories differ")
    encoded = handoff.get("patch_base64")
    patch_bytes = handoff.get("patch_bytes")
    digest = handoff.get("patch_sha256")
    if (
        not isinstance(encoded, str)
        or type(patch_bytes) is not int
        or not 0 <= patch_bytes <= MAX_HANDOFF_PATCH
        or not isinstance(digest, str)
        or HEX_DIGEST.fullmatch(digest) is None
    ):
        raise RuntimeError("coding worker returned invalid handoff patch metadata")
    try:
        patch = base64.b64decode(encoded, validate=True)
    except ValueError as error:
        raise RuntimeError("coding worker returned invalid handoff patch encoding") from error
    if (
        base64.b64encode(patch).decode("ascii") != encoded
        or len(patch) != patch_bytes
        or digest != "sha256:" + hashlib.sha256(patch).hexdigest()
    ):
        raise RuntimeError("coding worker handoff patch does not match its digest or length")
    if not patch and (paths or base_tree != result_tree):
        raise RuntimeError("empty coding handoff does not preserve its base tree")
    if patch and not paths:
        raise RuntimeError("non-empty coding handoff has no changed paths")
    if read_only and (patch or paths or base_tree != result_tree):
        raise RuntimeError("read-only coding handoff changed the workspace")


def validate_result(
    value: object,
    arguments: argparse.Namespace,
    expected_base_commit: str | None,
) -> dict[str, object]:
    if not isinstance(value, dict):
        raise RuntimeError("coding worker returned a non-object result")
    if expected_base_commit is None:
        validate_common(
            value,
            arguments,
            schema_version="steward.coding-result.v1",
            maximum_paths=MAX_V1_CHANGED_PATHS,
            maximum_path_bytes=MAX_RESPONSE,
        )
    else:
        paths = validate_common(
            value,
            arguments,
            schema_version="steward.coding-result.v2",
            maximum_paths=MAX_CHANGED_PATHS,
            maximum_path_bytes=MAX_CHANGED_PATH_BYTES,
        )
        validate_handoff(
            value.get("handoff"),
            expected_base_commit,
            paths,
            read_only=arguments.mode == "read",
        )
    return value


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(prog="steward-coding-worker")
    result.add_argument("--worker", choices=("codex", "claude-code"), required=True)
    result.add_argument("--task-id", required=True)
    result.add_argument("--task", required=True)
    result.add_argument("--mode", choices=("read", "write"), default="read")
    result.add_argument("--timeout-seconds", type=int, choices=range(30, MAX_TIMEOUT + 1), default=600)
    result.add_argument("--expected-base-commit")
    return result


def main() -> int:
    arguments = parser().parse_args()
    task = bounded_text(arguments.task, MAX_TASK)
    task_id = bounded_task_id(arguments.task_id)
    expected_base_commit = arguments.expected_base_commit
    if expected_base_commit is not None:
        if (
            len(expected_base_commit) not in OBJECT_ID_LENGTHS.values()
            or any(character not in "0123456789abcdef" for character in expected_base_commit)
        ):
            raise ValueError("expected base commit must be one lowercase SHA-1 or SHA-256 object ID")
    connector = "steward-codex" if arguments.worker == "codex" else "steward-claude-code"
    origin = urllib.parse.urlsplit(CONNECTOR_ORIGIN)
    if (
        origin.scheme != "http"
        or origin.hostname != "steward-relay"
        or origin.port != 8081
        or origin.path
        or origin.query
        or origin.fragment
    ):
        raise ValueError("Steward connector origin is invalid")
    request: dict[str, object] = {
        "schema_version": "steward.coding-task.v1",
        "task": task,
        "mode": arguments.mode,
        "timeout_seconds": arguments.timeout_seconds,
    }
    maximum_response = MAX_RESPONSE
    if expected_base_commit is not None:
        request["schema_version"] = "steward.coding-task.v2"
        request["expected_base_commit"] = expected_base_commit
        maximum_response = MAX_PORTABLE_RESULT
    raw = canonical_json(request)
    if len(raw) > MAX_REQUEST:
        raise ValueError("coding task exceeds the bounded connector payload")
    connection = http.client.HTTPConnection(
        origin.hostname,
        origin.port,
        timeout=arguments.timeout_seconds + CONNECTOR_GRACE_SECONDS,
    )
    try:
        connection.request(
            "POST",
            f"/v1/connectors/{connector}/operations/run",
            body=raw,
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                "Content-Length": str(len(raw)),
                "X-Steward-Task-ID": task_id,
            },
        )
        response = connection.getresponse()
        if response.getheader("Content-Encoding") not in (None, "identity"):
            raise RuntimeError("coding-worker response encoding is not accepted")
        declared = response.getheader("Content-Length")
        if declared is not None and (not declared.isdigit() or int(declared) > maximum_response):
            raise RuntimeError("coding-worker response exceeds its byte limit")
        body = response.read(maximum_response + 1)
        if len(body) > maximum_response:
            raise RuntimeError("coding-worker response exceeds its byte limit")
        if response.getheader("Content-Type") != "application/json":
            raise RuntimeError("coding-worker response is not JSON")
        if response.status < 200 or response.status >= 300:
            raise RuntimeError(f"coding worker returned HTTP {response.status}")
        value = validate_result(decode_json(body), arguments, expected_base_commit)
        sys.stdout.buffer.write(canonical_json(value) + b"\n")
        return 0 if value["outcome"] == "completed" else 1
    finally:
        connection.close()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, RuntimeError, OSError, http.client.HTTPException) as error:
        print(f"steward-coding-worker: {error}", file=sys.stderr)
        raise SystemExit(1)
