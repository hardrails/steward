#!/usr/bin/env python3
"""Fixed-path, non-root feasibility entrypoint for pinned Hermes Agent."""

from __future__ import annotations

import base64
import hashlib
import http.server
import json
import os
import pathlib
import re
import shutil
import signal
import subprocess
import sys
import threading
from typing import Any

REVISION = "095b9eed3801c251796df93f48a8f2a527ff6e70"
STATE = pathlib.Path("/opt/data")
FIXTURE = pathlib.Path("/opt/steward/fixtures/skill")
MODEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
NEGOTIATION = {
    "schema_version": "steward.adapter-negotiation.v1",
    "adapter": "hermes-agent",
    "adapter_contract": "steward.hermes-agent.v1",
    "upstream_revision": REVISION,
    "task_protocol": "hermes.runs.v1",
    "event_protocol": "hermes.runs.sse.v1",
    "native_protocols": ["http", "sse"],
    "capabilities": [
        {"id": "mcp", "fixture_id": "fixture_echo"},
        {"id": "skill", "fixture_id": "fixture.sha256"},
        {"id": "task", "fixture_id": "fixed-response"},
    ],
}


def fail(message: str) -> "NoReturn":
    print(f"hermes-adapter: {message}", file=sys.stderr)
    raise SystemExit(1)


def atomic_write(path: pathlib.Path, data: bytes, mode: int) -> None:
    temp = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(temp, flags, mode)
    try:
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(fd)
    os.replace(temp, path)
    directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def verify_skill() -> None:
    manifest = FIXTURE.joinpath("manifest.json").read_bytes()
    signature = base64.b64decode(FIXTURE.joinpath("manifest.sig").read_text().strip(), validate=True)
    try:
        from cryptography.hazmat.primitives import serialization

        key = serialization.load_pem_public_key(FIXTURE.joinpath("public.pem").read_bytes())
        key.verify(signature, manifest)
    except Exception as exc:
        fail(f"signed fixture skill verification failed: {type(exc).__name__}")
    descriptor = json.loads(manifest)
    script = FIXTURE.joinpath("fixture_sha256.py").read_bytes()
    if hashlib.sha256(script).hexdigest() != descriptor.get("entrypoint_sha256"):
        fail("fixture skill entrypoint digest mismatch")


def seed_state(model: str) -> None:
    if os.getuid() != 65532 or os.getgid() != 65532:
        fail("runtime identity must be exactly 65532:65532")
    for relative in ("home", "sessions", "logs", "memories", "skills", "workspace", "steward"):
        STATE.joinpath(relative).mkdir(mode=0o700, parents=True, exist_ok=True)
    skill_root = STATE / "skills" / "fixture-sha256"
    skill_root.mkdir(mode=0o700, exist_ok=True)
    for name, mode in (("SKILL.md", 0o400), ("fixture_sha256.py", 0o500), ("manifest.json", 0o400)):
        source = FIXTURE / name
        target = skill_root / name
        if target.exists() and hashlib.sha256(target.read_bytes()).digest() != hashlib.sha256(source.read_bytes()).digest():
            fail(f"existing fixture skill file drifted: {name}")
        if not target.exists():
            shutil.copyfile(source, target)
            os.chmod(target, mode)
    config = f"""model:
  provider: custom
  name: {model}
  base_url: http://steward-model:8080/v1
  api_key: steward-local
  api_mode: chat_completions
security:
  allow_lazy_installs: false
terminal:
  backend: local
mcp_servers:
  fixture_echo:
    url: http://steward-mcp:8767/mcp
    enabled: true
    connect_timeout: 5
    timeout: 10
    skip_preflight: true
    tools:
      include: [echo]
      resources: false
      prompts: false
""".encode()
    config_path = STATE / "config.yaml"
    if config_path.exists() and config_path.read_bytes() != config:
        fail("existing config.yaml differs from the authorized feasibility configuration")
    if not config_path.exists():
        atomic_write(config_path, config, 0o600)


class NegotiationHandler(http.server.BaseHTTPRequestHandler):
    server_version = "steward-hermes-negotiation/1"

    def do_GET(self) -> None:  # noqa: N802
        if self.path != "/steward/v1/negotiation":
            self.send_error(404)
            return
        body = json.dumps(NEGOTIATION, separators=(",", ":"), sort_keys=True).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *_args: Any) -> None:
        return


def main() -> int:
    model = os.environ.get("OPENAI_MODEL", "steward-fixture-model")
    if not MODEL_RE.fullmatch(model):
        fail("OPENAI_MODEL is invalid")
    if os.environ.get("OPENAI_BASE_URL", "http://steward-model:8080/v1") != "http://steward-model:8080/v1":
        fail("OPENAI_BASE_URL must use the fixed feasibility relay endpoint")
    verify_skill()
    seed_state(model)
    server = http.server.ThreadingHTTPServer(("0.0.0.0", 8766), NegotiationHandler)
    thread = threading.Thread(target=server.serve_forever, name="negotiation", daemon=True)
    thread.start()
    environment = os.environ.copy()
    environment.update(
        {
            "API_SERVER_ENABLED": "true",
            "API_SERVER_HOST": "0.0.0.0",
            "API_SERVER_PORT": "8642",
            "API_SERVER_KEY": "steward-feasibility",
            "HERMES_DISABLE_LAZY_INSTALLS": "1",
        }
    )
    process = subprocess.Popen(
        ["/opt/hermes/.venv/bin/hermes", "gateway", "run"],
        cwd=STATE,
        env=environment,
        stdin=subprocess.DEVNULL,
    )

    def stop(_signum: int, _frame: Any) -> None:
        process.terminate()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    return_code = process.wait()
    server.shutdown()
    server.server_close()
    return return_code


if __name__ == "__main__":
    raise SystemExit(main())
