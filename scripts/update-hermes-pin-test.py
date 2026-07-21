#!/usr/bin/env python3
"""Regression tests for the Hermes pin updater."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parent.parent
UPDATER = ROOT / "scripts/update-hermes-pin.py"
STEWARD_INPUTS = (
    "adapters/hermes-agent/adapter.json",
    "adapters/hermes-agent/entrypoint.py",
    "adapters/hermes-agent/license-inventory.json",
    "adapters/hermes-agent/source-inputs.sha256",
    "scripts/build-hermes-adapter.sh",
    "scripts/hermes-feasibility.sh",
    "docs/guides/hermes-agent.md",
    "docs/reference/release-artifacts.md",
    "docs/faq.md",
    "docs/llms.txt",
)


def run(*arguments: str, cwd: pathlib.Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(arguments),
        cwd=cwd,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
        env={**os.environ, "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1"},
    )


class HermesPinUpdaterTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        temporary = pathlib.Path(self.temporary.name)
        self.steward = temporary / "steward"
        self.source = temporary / "hermes"
        for relative in STEWARD_INPUTS:
            destination = self.steward / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, destination)

        self.source.mkdir()
        fixtures = {
            "LICENSE": b"fixture license\n",
            "pyproject.toml": b'[project]\nname = "hermes-agent"\nversion = "9.8.7"\n',
            "uv.lock": b"version = 1\n",
            "package-lock.json": b'{"lockfileVersion":3}\n',
        }
        for name, content in fixtures.items():
            (self.source / name).write_bytes(content)
        self.assertEqual(run("git", "init", "-q", cwd=self.source).returncode, 0)
        self.assertEqual(run("git", "add", ".", cwd=self.source).returncode, 0)
        committed = run(
            "git",
            "-c",
            "user.name=Steward Test",
            "-c",
            "user.email=steward-test@example.invalid",
            "commit",
            "-q",
            "-m",
            "fixture",
            cwd=self.source,
        )
        self.assertEqual(committed.returncode, 0, committed.stderr)
        self.assertEqual(run("git", "tag", "v2099.1.1", cwd=self.source).returncode, 0)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def update(self, *extra: str) -> subprocess.CompletedProcess[str]:
        return run(
            "python3",
            "-I",
            str(UPDATER),
            "--source-dir",
            str(self.source),
            "--release-tag",
            "v2099.1.1",
            "--repository-root",
            str(self.steward),
            *extra,
        )

    def test_update_is_exact_and_idempotent(self) -> None:
        completed = self.update()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        result = json.loads(completed.stdout)
        revision = run("git", "rev-parse", "HEAD", cwd=self.source).stdout.strip()
        self.assertEqual(result["release"], "v2099.1.1")
        self.assertEqual(result["version"], "9.8.7")
        self.assertEqual(result["revision"], revision)
        self.assertTrue(result["changed"])

        adapter = json.loads((self.steward / "adapters/hermes-agent/adapter.json").read_text())
        self.assertEqual(
            adapter["upstream"],
            {
                "repository": "https://github.com/NousResearch/hermes-agent.git",
                "revision": revision,
                "license": "MIT",
                "license_sha256": hashlib.sha256(b"fixture license\n").hexdigest(),
                "release": "v2099.1.1",
                "version": "9.8.7",
            },
        )
        checked = self.update("--check")
        self.assertEqual(checked.returncode, 0, checked.stderr)
        self.assertEqual(json.loads(checked.stdout)["changed"], [])

    def test_dirty_source_is_rejected_without_writes(self) -> None:
        before = (self.steward / "adapters/hermes-agent/adapter.json").read_bytes()
        (self.source / "unexpected").write_text("untrusted\n")
        completed = self.update()
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("release checkout is not clean", completed.stderr)
        self.assertEqual((self.steward / "adapters/hermes-agent/adapter.json").read_bytes(), before)

    def test_tag_must_resolve_to_checked_out_commit(self) -> None:
        (self.source / "LICENSE").write_text("second commit\n")
        self.assertEqual(run("git", "add", "LICENSE", cwd=self.source).returncode, 0)
        committed = run(
            "git",
            "-c",
            "user.name=Steward Test",
            "-c",
            "user.email=steward-test@example.invalid",
            "commit",
            "-q",
            "-m",
            "not tagged",
            cwd=self.source,
        )
        self.assertEqual(committed.returncode, 0, committed.stderr)
        completed = self.update()
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("release tag does not resolve", completed.stderr)


if __name__ == "__main__":
    unittest.main()
