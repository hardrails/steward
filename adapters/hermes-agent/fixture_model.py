#!/usr/bin/env python3
"""Deterministic OpenAI-compatible model fixture; no model content is logged."""

from __future__ import annotations

import hashlib
import http.server
import json
from typing import Any

MAX_BODY = 1 << 20
NONCE = "steward-hermes-phase1"
DIGEST = hashlib.sha256(NONCE.encode()).hexdigest()


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/v1/models":
            self._json(200, {"object": "list", "data": [{"id": "steward-fixture-model", "object": "model"}]})
        else:
            self.send_error(404)

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/v1/chat/completions":
            self.send_error(404)
            return
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0 or length > MAX_BODY:
            self.send_error(413)
            return
        payload = json.loads(self.rfile.read(length))
        messages = payload.get("messages") if isinstance(payload, dict) else None
        if not isinstance(messages, list):
            self.send_error(400)
            return
        last = messages[-1] if messages else {}
        last_text = str(last.get("content", "")) if isinstance(last, dict) else ""
        tool_result = next(
            (str(item.get("content", "")) for item in reversed(messages) if isinstance(item, dict) and item.get("role") == "tool"),
            "",
        )
        if tool_result:
            content = tool_result.strip()
            message: dict[str, Any] = {"role": "assistant", "content": content}
            finish = "stop"
        elif "STEWARD_SKILL_FIXTURE" in last_text:
            message = {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "call_steward_skill",
                        "type": "function",
                        "function": {
                            "name": "terminal",
                            "arguments": json.dumps(
                                {
                                    "command": "python3 /opt/data/skills/fixture-sha256/fixture_sha256.py steward-hermes-phase1"
                                },
                                separators=(",", ":"),
                            ),
                        },
                    }
                ],
            }
            finish = "tool_calls"
        elif "STEWARD_MCP_FIXTURE" in last_text:
            message = {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "call_steward_mcp",
                        "type": "function",
                        "function": {
                            "name": "mcp_fixture_echo_echo",
                            "arguments": json.dumps({"value": NONCE}, separators=(",", ":")),
                        },
                    }
                ],
            }
            finish = "tool_calls"
        else:
            message = {"role": "assistant", "content": f"steward-task:{DIGEST}"}
            finish = "stop"
        self._json(
            200,
            {
                "id": "chatcmpl-steward-fixture",
                "object": "chat.completion",
                "created": 0,
                "model": "steward-fixture-model",
                "choices": [{"index": 0, "message": message, "finish_reason": finish}],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
            },
        )

    def _json(self, status: int, payload: object) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *_args: Any) -> None:
        return


if __name__ == "__main__":
    http.server.ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
