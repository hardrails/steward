#!/usr/bin/env python3
"""Regression tests for the Buzz source-lock updater."""

from __future__ import annotations

import json
import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parent.parent
UPDATER = ROOT / "scripts/update-buzz-pin.py"


def run(*arguments: str, cwd: pathlib.Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(arguments), cwd=cwd, check=False, capture_output=True, text=True,
        timeout=60, env={**os.environ, "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1"},
    )


class BuzzPinUpdaterTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        base = pathlib.Path(self.temporary.name)
        self.steward = base / "steward"
        self.source = base / "buzz"
        (self.steward / "integrations/buzz").mkdir(parents=True)
        shutil.copy2(ROOT / "integrations/buzz/source-lock.json", self.steward / "integrations/buzz/source-lock.json")
        for directory in (self.source / "crates/buzz-acp", self.source / "crates/buzz-cli"):
            directory.mkdir(parents=True)
        fixtures = {
            "LICENSE": "fixture Apache license\n",
            "Cargo.toml": '[workspace]\nmembers = ["crates/buzz-acp", "crates/buzz-cli"]\n[workspace.package]\nversion = "9.8.7"\n',
            "Cargo.lock": "version = 4\n",
            "rust-toolchain.toml": '[toolchain]\nchannel = "1.95.0"\n',
            "crates/buzz-acp/Cargo.toml": '[package]\nname = "buzz-acp"\nversion.workspace = true\n',
            "crates/buzz-cli/Cargo.toml": '[package]\nname = "buzz-cli"\nversion.workspace = true\n',
        }
        for relative, content in fixtures.items():
            (self.source / relative).write_text(content, encoding="utf-8")
        self.assertEqual(run("git", "init", "-q", cwd=self.source).returncode, 0)
        self.assertEqual(run("git", "add", ".", cwd=self.source).returncode, 0)
        committed = run("git", "-c", "user.name=Steward Test", "-c", "user.email=test@example.invalid",
                        "commit", "-q", "-m", "fixture", cwd=self.source)
        self.assertEqual(committed.returncode, 0, committed.stderr)
        self.assertEqual(run("git", "tag", "v2099.1.1", cwd=self.source).returncode, 0)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def update(self, *extra: str) -> subprocess.CompletedProcess[str]:
        return run("python3", "-I", str(UPDATER), "--source-dir", str(self.source),
                   "--release-tag", "v2099.1.1", "--repository-root", str(self.steward), *extra)

    def test_update_is_exact_idempotent_and_checkable(self) -> None:
        completed = self.update()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        result = json.loads(completed.stdout)
        revision = run("git", "rev-parse", "HEAD", cwd=self.source).stdout.strip()
        self.assertEqual(result["release"], "v2099.1.1")
        self.assertEqual(result["revision"], revision)
        self.assertEqual(result["changed"], ["integrations/buzz/source-lock.json"])
        lock = json.loads((self.steward / "integrations/buzz/source-lock.json").read_text())
        self.assertEqual(lock["revision"], revision)
        self.assertEqual([entry["version"] for entry in lock["components"]], ["9.8.7", "9.8.7"])
        checked = self.update("--check")
        self.assertEqual(checked.returncode, 0, checked.stderr)
        self.assertEqual(json.loads(checked.stdout)["changed"], [])

    def test_dirty_checkout_is_rejected_without_writes(self) -> None:
        before = (self.steward / "integrations/buzz/source-lock.json").read_bytes()
        (self.source / "unexpected").write_text("untrusted\n")
        completed = self.update()
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("not clean", completed.stderr)
        self.assertEqual((self.steward / "integrations/buzz/source-lock.json").read_bytes(), before)

    def test_tag_mismatch_and_symlink_input_are_rejected(self) -> None:
        (self.source / "LICENSE").write_text("new commit\n")
        self.assertEqual(run("git", "add", "LICENSE", cwd=self.source).returncode, 0)
        self.assertEqual(run("git", "-c", "user.name=Steward Test", "-c", "user.email=test@example.invalid",
                             "commit", "-q", "-m", "later", cwd=self.source).returncode, 0)
        mismatch = self.update()
        self.assertNotEqual(mismatch.returncode, 0)
        self.assertIn("does not resolve", mismatch.stderr)
        self.assertEqual(run("git", "reset", "--hard", "v2099.1.1", cwd=self.source).returncode, 0)
        (self.source / "LICENSE").unlink()
        (self.source / "LICENSE").symlink_to("Cargo.lock")
        linked = self.update()
        self.assertNotEqual(linked.returncode, 0)
        self.assertTrue("invalid LICENSE" in linked.stderr or "not clean" in linked.stderr)


if __name__ == "__main__":
    unittest.main()
