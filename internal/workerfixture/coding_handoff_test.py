#!/usr/bin/env python3
"""Standard-library contract tests for immutable coding-worker Git handoffs."""

from __future__ import annotations

import base64
import contextlib
import hashlib
import http.client
import importlib.util
import json
import os
import pathlib
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from collections.abc import Callable, Iterator, Mapping
from typing import Any
from unittest import mock


if len(sys.argv) < 2:
    raise SystemExit("usage: coding_handoff_test.py /path/to/coding_worker.py")

WORKER_PATH = pathlib.Path(sys.argv[1]).resolve()
sys.argv = [sys.argv[0], *sys.argv[2:]]
SPEC = importlib.util.spec_from_file_location("steward_coding_worker", WORKER_PATH)
if SPEC is None or SPEC.loader is None:
    raise SystemExit(f"cannot import {WORKER_PATH}")
worker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(worker)

OID_PATTERN = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")


def git(
    repository: pathlib.Path,
    *arguments: str,
    input_bytes: bytes | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[bytes]:
    environment = {
        name: os.environ[name]
        for name in ("HOME", "PATH", "TMPDIR", "TMP", "TEMP", "SYSTEMROOT")
        if name in os.environ
    }
    environment.update(
        {
            "GIT_ASKPASS": "/bin/false",
            "GIT_ATTR_NOSYSTEM": "1",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_EDITOR": "/bin/false",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_PAGER": "cat",
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "LC_ALL": "C",
            "LANG": "C",
        }
    )
    result = subprocess.run(
        [
            shutil.which("git") or "git",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.hooksPath=/dev/null",
            "-C",
            str(repository),
            *arguments,
        ],
        check=False,
        stdin=subprocess.DEVNULL if input_bytes is None else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        input=input_bytes,
        timeout=20,
        env=environment,
    )
    if check and result.returncode != 0:
        raise AssertionError(
            f"git {' '.join(arguments)} failed ({result.returncode}): "
            f"{result.stderr.decode('utf-8', 'replace')}"
        )
    return result


def write(repository: pathlib.Path, relative: str, value: bytes, mode: int = 0o644) -> pathlib.Path:
    path = repository / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(value)
    path.chmod(mode)
    return path


def initialize_repository(
    parent: pathlib.Path,
    name: str = "repository",
    object_format: str = "sha1",
) -> tuple[pathlib.Path, str, str]:
    repository = parent / name
    repository.mkdir()
    result = git(repository, "init", "-q", f"--object-format={object_format}", check=False)
    if result.returncode != 0:
        raise unittest.SkipTest(f"Git does not support {object_format} repositories")
    git(repository, "config", "user.name", "Steward Fixture")
    git(repository, "config", "user.email", "fixture@steward.invalid")
    git(repository, "config", "core.autocrlf", "false")
    git(repository, "config", "core.filemode", "true")
    write(repository, "modify.txt", b"before\n")
    write(repository, "delete.txt", b"remove me\n")
    write(repository, "tool.sh", b"#!/bin/sh\nexit 0\n")
    git(repository, "add", "--all")
    git(repository, "commit", "-q", "-m", "base")
    commit = git(repository, "rev-parse", "HEAD").stdout.decode().strip()
    tree = git(repository, "rev-parse", "HEAD^{tree}").stdout.decode().strip()
    return repository, commit, tree


@contextlib.contextmanager
def workspace(repository: pathlib.Path) -> Iterator[None]:
    previous = worker.WORKSPACE
    worker.WORKSPACE = repository
    try:
        yield
    finally:
        worker.WORKSPACE = previous


def record_fields(value: object) -> dict[str, object]:
    if isinstance(value, Mapping):
        return dict(value)
    if hasattr(value, "_asdict"):
        return dict(value._asdict())
    names = (
        "schema_version",
        "task",
        "mode",
        "timeout_seconds",
        "expected_base_commit",
        "object_format",
        "base_commit",
        "base_tree",
    )
    return {name: getattr(value, name) for name in names if hasattr(value, name)}


def validated_fields(value: object) -> dict[str, object]:
    fields = record_fields(value)
    if fields:
        fields.setdefault("expected_base_commit", None)
        return fields
    if isinstance(value, tuple):
        if len(value) == 4:
            task, mode, timeout_seconds, expected_base_commit = value
            schema_version = (
                "steward.coding-task.v2"
                if expected_base_commit is not None
                else "steward.coding-task.v1"
            )
        elif len(value) == 5:
            schema_version, task, mode, timeout_seconds, expected_base_commit = value
        else:
            raise AssertionError(f"unsupported validated request tuple: {value!r}")
        return {
            "schema_version": schema_version,
            "task": task,
            "mode": mode,
            "timeout_seconds": timeout_seconds,
            "expected_base_commit": expected_base_commit,
        }
    raise AssertionError(f"unsupported validated request value: {value!r}")


def identity_fields(value: object) -> dict[str, str]:
    fields = record_fields(value)
    required = {"object_format", "base_commit", "base_tree"}
    if required <= fields.keys():
        return {name: str(fields[name]) for name in required}
    if isinstance(value, tuple) and len(value) == 3:
        object_format = next((item for item in value if item in {"sha1", "sha256"}), None)
        object_ids = [item for item in value if isinstance(item, str) and OID_PATTERN.fullmatch(item)]
        if object_format is not None and len(object_ids) == 2:
            return {
                "object_format": object_format,
                "base_commit": object_ids[0],
                "base_tree": object_ids[1],
            }
    raise AssertionError(f"unsupported workspace identity: {value!r}")


def patch_bytes(handoff: Mapping[str, object]) -> bytes:
    encoded = handoff.get("patch_base64")
    if not isinstance(encoded, str):
        raise AssertionError(f"handoff patch_base64 is not text: {encoded!r}")
    try:
        raw = base64.b64decode(encoded, validate=True)
    except ValueError as error:
        raise AssertionError("handoff patch is not valid base64") from error
    if base64.b64encode(raw).decode() != encoded:
        raise AssertionError("handoff patch is not canonical base64")
    return raw


def digest_hex(value: object) -> str:
    if not isinstance(value, str):
        raise AssertionError(f"patch digest is not text: {value!r}")
    return value.removeprefix("sha256:")


def metadata_snapshot(repository: pathlib.Path) -> dict[str, str]:
    git_directory = repository / ".git"
    paths = [git_directory / "HEAD", git_directory / "index"]
    paths.extend(path for root in ("objects", "refs") for path in (git_directory / root).rglob("*"))
    snapshot: dict[str, str] = {}
    for path in sorted(paths):
        if path.is_file() and not path.is_symlink():
            snapshot[str(path.relative_to(git_directory))] = hashlib.sha256(path.read_bytes()).hexdigest()
    return snapshot


class CodingHandoffContractTest(unittest.TestCase):
    maxDiff = None

    def assert_worker_error(
        self,
        action: Callable[[], object],
        *,
        status: int | None = None,
        code: str | None = None,
    ) -> Any:
        with self.assertRaises(worker.WorkerError) as caught:
            action()
        if status is not None:
            self.assertEqual(caught.exception.status, status)
        if code is not None:
            self.assertEqual(caught.exception.code, code)
        self.assertTrue(caught.exception.code)
        self.assertTrue(caught.exception.message)
        return caught.exception

    def identity(self, repository: pathlib.Path, expected_base_commit: str) -> tuple[object, dict[str, str]]:
        with workspace(repository):
            value = worker.workspace_identity(expected_base_commit)
        return value, identity_fields(value)

    def capture(
        self,
        repository: pathlib.Path,
        identity: object,
        protected_markers: tuple[bytes, ...] = (),
    ) -> dict[str, object]:
        with workspace(repository):
            value = worker.capture_git_handoff(identity, protected_markers)
        self.assertIsInstance(value, dict)
        return value

    def assert_handoff_shape(
        self,
        handoff: Mapping[str, object],
        *,
        base_commit: str,
        base_tree: str,
    ) -> bytes:
        self.assertEqual(
            set(handoff),
            {
                "schema_version",
                "object_format",
                "base_commit",
                "base_tree",
                "result_tree",
                "patch_sha256",
                "patch_bytes",
                "patch_base64",
                "changed_paths",
            },
        )
        self.assertEqual(handoff["schema_version"], "steward.git-handoff.v1")
        self.assertEqual(handoff["base_commit"], base_commit)
        self.assertEqual(handoff["base_tree"], base_tree)
        self.assertIn(handoff["object_format"], {"sha1", "sha256"})
        self.assertRegex(str(handoff["result_tree"]), rf"^[0-9a-f]{{{len(base_tree)}}}$")
        changed_paths = handoff["changed_paths"]
        self.assertIsInstance(changed_paths, list)
        self.assertEqual(changed_paths, sorted(set(changed_paths)))
        raw = patch_bytes(handoff)
        self.assertEqual(handoff["patch_bytes"], len(raw))
        self.assertEqual(digest_hex(handoff["patch_sha256"]), hashlib.sha256(raw).hexdigest())
        return raw

    def test_validate_task_payload_preserves_v1_and_accepts_bounded_v2(self) -> None:
        v1 = {
            "schema_version": "steward.coding-task.v1",
            "task": "Inspect the repository",
            "mode": "read",
            "timeout_seconds": 30,
        }
        expected_sha1 = "a" * 40
        v2 = {
            "schema_version": "steward.coding-task.v2",
            "task": "Implement the bounded change",
            "mode": "write",
            "timeout_seconds": 900,
            "expected_base_commit": expected_sha1,
        }
        self.assertEqual(
            validated_fields(worker.validate_task_payload(v1)),
            {**v1, "expected_base_commit": None},
        )
        self.assertEqual(
            validated_fields(worker.validate_task_payload(v2)),
            v2,
        )
        sha256_request = dict(v2, expected_base_commit="b" * 64)
        self.assertEqual(
            validated_fields(worker.validate_task_payload(sha256_request)),
            sha256_request,
        )

    def test_validate_task_payload_rejects_non_exact_or_malformed_contracts(self) -> None:
        valid_v1 = {
            "schema_version": "steward.coding-task.v1",
            "task": "Inspect",
            "mode": "read",
            "timeout_seconds": 30,
        }
        valid_v2 = {
            "schema_version": "steward.coding-task.v2",
            "task": "Change",
            "mode": "write",
            "timeout_seconds": 60,
            "expected_base_commit": "a" * 40,
        }
        invalid = [
            {**valid_v1, "unknown": True},
            {**valid_v1, "expected_base_commit": "a" * 40},
            {key: value for key, value in valid_v2.items() if key != "expected_base_commit"},
            {**valid_v2, "expected_base_commit": "A" * 40},
            {**valid_v2, "expected_base_commit": "a" * 39},
            {**valid_v2, "expected_base_commit": "g" * 40},
            {**valid_v2, "timeout_seconds": True},
            {**valid_v2, "timeout_seconds": 29},
            {**valid_v2, "mode": "admin"},
            {**valid_v2, "task": " padded "},
            {**valid_v2, "schema_version": "steward.coding-task.v3"},
        ]
        for payload in invalid:
            with self.subTest(payload=payload):
                self.assert_worker_error(
                    lambda payload=payload: worker.validate_task_payload(payload),
                    status=400,
                    code="invalid_request",
                )

    def test_worker_git_environment_ignores_ambient_git_process_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            repository, base_commit, base_tree = initialize_repository(root, "workspace")
            decoy, _, _ = initialize_repository(root, "decoy")
            inherited = {
                "GIT_ALTERNATE_OBJECT_DIRECTORIES": str(decoy / ".git" / "objects"),
                "GIT_CEILING_DIRECTORIES": str(root),
                "GIT_COMMON_DIR": str(decoy / ".git"),
                "GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_KEY_0": "core.bare",
                "GIT_CONFIG_VALUE_0": "true",
                "GIT_DIR": str(decoy / ".git"),
                "GIT_INDEX_FILE": str(decoy / ".git" / "index"),
                "GIT_NAMESPACE": "hostile-fixture",
                "GIT_OBJECT_DIRECTORY": str(decoy / ".git" / "objects"),
                "GIT_WORK_TREE": str(decoy),
            }
            with mock.patch.dict(os.environ, inherited, clear=False):
                clean = worker.git_environment()
                for name in inherited:
                    self.assertNotIn(name, clean)
                self.assertEqual(clean["GIT_CONFIG_NOSYSTEM"], "1")
                self.assertEqual(clean["GIT_CONFIG_GLOBAL"], os.devnull)
                self.assertEqual(clean["GIT_NO_REPLACE_OBJECTS"], "1")
                self.assertEqual(clean["GIT_OPTIONAL_LOCKS"], "0")
                with workspace(repository):
                    identity = identity_fields(worker.workspace_identity(base_commit))
            self.assertEqual(
                identity,
                {
                    "object_format": "sha1",
                    "base_commit": base_commit,
                    "base_tree": base_tree,
                },
            )

    def test_bounded_process_times_out_when_a_child_does_not_read_input(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            started = time.monotonic()
            _, stdout, stderr, exceeded, timed_out = worker.run_bounded_process(
                [sys.executable, "-I", "-B", "-c", "import time; time.sleep(10)"],
                cwd=pathlib.Path(temporary),
                environment=worker.git_environment(),
                timeout_seconds=0.05,
                stdout_limit=1024,
                stderr_limit=1024,
                input_bytes=b"x" * (256 << 10),
            )
        self.assertLess(time.monotonic() - started, 2)
        self.assertEqual(stdout, b"")
        self.assertEqual(stderr, b"")
        self.assertFalse(exceeded)
        self.assertTrue(timed_out)

    def test_stop_process_preserves_a_force_kill_observation_budget(self) -> None:
        process = subprocess.Popen(
            [
                sys.executable,
                "-I",
                "-B",
                "-c",
                (
                    "import signal,time; "
                    "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                    "print('ready', flush=True); "
                    "time.sleep(10)"
                ),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        try:
            self.assertEqual(process.stdout.readline(), b"ready\n")
            started = time.monotonic()
            self.assertTrue(
                worker.stop_process(
                    process,
                    deadline=started + 0.4,
                )
            )
            self.assertLess(time.monotonic() - started, 0.8)
            self.assertFalse(worker.process_group_exists(process.pid))
        finally:
            worker.stop_process(process, deadline=time.monotonic() + 1)
            worker.close_process_streams(process)

    def test_bounded_process_cleans_a_term_ignoring_child_before_absolute_deadline(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            pid_path = root / "child.pid"
            source = (
                "import os,pathlib,signal,time; "
                "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                f"pathlib.Path({str(pid_path)!r}).write_text(str(os.getpid())); "
                "time.sleep(10)"
            )
            started = time.monotonic()
            _, _, _, exceeded, timed_out = worker.run_bounded_process(
                [sys.executable, "-I", "-B", "-c", source],
                cwd=root,
                environment=worker.git_environment(),
                timeout_seconds=0.25,
                stdout_limit=1024,
                stderr_limit=1024,
                absolute_deadline=started + 1,
            )
            self.assertLess(time.monotonic() - started, 1.2)
            self.assertFalse(exceeded)
            self.assertTrue(timed_out)
            process_id = int(pid_path.read_text())
            with self.assertRaises(ProcessLookupError):
                os.kill(process_id, 0)

    def test_bounded_process_does_not_block_closing_a_live_reader(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            pid_path = root / "detached.pid"
            child_source = "import time; time.sleep(10)"
            source = (
                "import pathlib,subprocess,sys; "
                "child=subprocess.Popen("
                f"[sys.executable, '-I', '-B', '-c', {child_source!r}], "
                "stdin=subprocess.DEVNULL, start_new_session=True); "
                f"pathlib.Path({str(pid_path)!r}).write_text(str(child.pid))"
            )
            started = time.monotonic()
            try:
                self.assert_worker_error(
                    lambda: worker.run_bounded_process(
                        [sys.executable, "-I", "-B", "-c", source],
                        cwd=root,
                        environment=worker.git_environment(),
                        timeout_seconds=0.1,
                        stdout_limit=1024,
                        stderr_limit=1024,
                        absolute_deadline=started + 0.5,
                    ),
                    status=502,
                    code="worker_cleanup_failed",
                )
                self.assertLess(time.monotonic() - started, 0.9)
            finally:
                if pid_path.exists():
                    try:
                        os.kill(int(pid_path.read_text()), signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                time.sleep(0.05)

    def test_empty_handoff_binds_equal_trees_and_an_empty_patch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository, base_commit, base_tree = initialize_repository(pathlib.Path(temporary))
            identity, fields = self.identity(repository, base_commit)
            self.assertEqual(
                fields,
                {
                    "object_format": "sha1",
                    "base_commit": base_commit,
                    "base_tree": base_tree,
                },
            )
            handoff = self.capture(repository, identity)
            raw = self.assert_handoff_shape(
                handoff,
                base_commit=base_commit,
                base_tree=base_tree,
            )
            self.assertEqual(raw, b"")
            self.assertEqual(handoff["result_tree"], base_tree)
            self.assertEqual(handoff["changed_paths"], [])

    def test_handoff_reproduces_add_modify_delete_binary_mode_symlink_and_unicode(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            repository, base_commit, base_tree = initialize_repository(root)
            identity, _ = self.identity(repository, base_commit)
            before_metadata = metadata_snapshot(repository)

            write(repository, "modify.txt", b"after\n")
            (repository / "delete.txt").unlink()
            write(repository, "added.txt", b"new file\n")
            write(repository, "image.bin", b"\x00\xff\x10binary\r\n\x00tail")
            (repository / "tool.sh").chmod(0o755)
            os.symlink("added.txt", repository / "link-to-added")
            write(repository, "notes/naïve snow.txt", "valid UTF-8 path\n".encode())

            first = self.capture(repository, identity)
            second = self.capture(repository, identity)
            patch = self.assert_handoff_shape(
                first,
                base_commit=base_commit,
                base_tree=base_tree,
            )
            self.assertEqual(first, second)
            self.assertEqual(
                first["changed_paths"],
                sorted(
                    [
                        "added.txt",
                        "delete.txt",
                        "image.bin",
                        "link-to-added",
                        "modify.txt",
                        "notes/naïve snow.txt",
                        "tool.sh",
                    ]
                ),
            )
            self.assertEqual(metadata_snapshot(repository), before_metadata)

            review = root / "review"
            git(root, "clone", "-q", "--no-local", str(repository), str(review))
            patch_path = root / "handoff.patch"
            patch_path.write_bytes(patch)
            git(review, "apply", "--index", "--binary", str(patch_path))
            result_tree = git(review, "write-tree").stdout.decode().strip()
            self.assertEqual(result_tree, first["result_tree"])
            self.assertEqual((review / "modify.txt").read_bytes(), b"after\n")
            self.assertFalse((review / "delete.txt").exists())
            self.assertEqual((review / "added.txt").read_bytes(), b"new file\n")
            self.assertEqual((review / "image.bin").read_bytes(), b"\x00\xff\x10binary\r\n\x00tail")
            self.assertEqual(os.readlink(review / "link-to-added"), "added.txt")
            self.assertEqual((review / "notes/naïve snow.txt").read_text(), "valid UTF-8 path\n")
            executable_mode = git(review, "ls-files", "-s", "--", "tool.sh").stdout.decode().split()[0]
            self.assertEqual(executable_mode, "100755")

    def test_workspace_identity_supports_declared_sha256_repositories(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository, base_commit, base_tree = initialize_repository(
                pathlib.Path(temporary),
                object_format="sha256",
            )
            _, fields = self.identity(repository, base_commit)
            self.assertEqual(
                fields,
                {
                    "object_format": "sha256",
                    "base_commit": base_commit,
                    "base_tree": base_tree,
                },
            )

    def test_sha256_handoff_reproduces_in_an_independent_checkout(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            repository, base_commit, base_tree = initialize_repository(
                root,
                object_format="sha256",
            )
            identity, _ = self.identity(repository, base_commit)
            write(repository, "modify.txt", b"sha256 result\n")
            write(repository, "sha256.bin", b"\x00sha256\xffresult")

            handoff = self.capture(repository, identity)
            patch = self.assert_handoff_shape(
                handoff,
                base_commit=base_commit,
                base_tree=base_tree,
            )
            self.assertEqual(handoff["object_format"], "sha256")
            self.assertEqual(len(str(handoff["result_tree"])), 64)
            self.assertEqual(handoff["changed_paths"], ["modify.txt", "sha256.bin"])

            review = root / "sha256-review"
            git(root, "clone", "-q", "--no-local", str(repository), str(review))
            patch_path = root / "sha256-handoff.patch"
            patch_path.write_bytes(patch)
            git(review, "apply", "--index", "--binary", str(patch_path))
            self.assertEqual(
                git(review, "write-tree").stdout.decode().strip(),
                handoff["result_tree"],
            )
            self.assertEqual((review / "modify.txt").read_bytes(), b"sha256 result\n")
            self.assertEqual((review / "sha256.bin").read_bytes(), b"\x00sha256\xffresult")

    def test_wrong_base_and_changed_history_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository, base_commit, _ = initialize_repository(pathlib.Path(temporary))
            wrong = ("0" if base_commit[0] != "0" else "1") + base_commit[1:]
            with workspace(repository):
                mismatch = self.assert_worker_error(
                    lambda: worker.workspace_identity(wrong),
                    status=409,
                )
            self.assertIn("base", mismatch.code)

            identity, _ = self.identity(repository, base_commit)
            write(repository, "history.txt", b"new history\n")
            git(repository, "add", "--all")
            git(repository, "commit", "-q", "-m", "move head")
            with workspace(repository):
                changed = self.assert_worker_error(
                    lambda: worker.capture_git_handoff(identity),
                    status=409,
                )
            self.assertTrue(
                "history" in changed.code or "base" in changed.code or "workspace" in changed.code
            )

    def test_gitlink_only_base_without_gitmodules_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            repository, _, _ = initialize_repository(root, "gitlink-parent")
            nested, nested_commit, _ = initialize_repository(repository, "nested")
            self.assertTrue((nested / ".git").is_dir())
            git(
                repository,
                "update-index",
                "--add",
                "--cacheinfo",
                f"160000,{nested_commit},nested",
            )
            git(repository, "commit", "-q", "-m", "gitlink without metadata")
            base_commit = git(repository, "rev-parse", "HEAD").stdout.decode().strip()
            self.assertFalse((repository / ".gitmodules").exists())
            self.assertEqual(git(repository, "status", "--porcelain=v1").stdout, b"")

            with workspace(repository):
                self.assert_worker_error(
                    lambda: worker.workspace_identity(base_commit),
                    status=409,
                    code="submodules_not_supported",
                )

    def test_worktree_config_and_late_alternate_object_store_are_refused(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            configured, configured_base, _ = initialize_repository(root, "worktree-config")
            included = root / "included.config"
            included.write_text("[core]\n\tbare = false\n", encoding="utf-8")
            git(configured, "config", "extensions.worktreeConfig", "true")
            git(configured, "config", "--worktree", "include.path", str(included))
            with workspace(configured):
                self.assert_worker_error(
                    lambda: worker.workspace_identity(configured_base),
                    status=409,
                    code="unsupported_workspace",
                )

            repository, base_commit, _ = initialize_repository(root, "late-alternate")
            decoy, _, _ = initialize_repository(root, "alternate-source")
            identity, _ = self.identity(repository, base_commit)
            alternates = repository / ".git" / "objects" / "info" / "alternates"
            alternates.write_text(
                str((decoy / ".git" / "objects").resolve()) + "\n",
                encoding="utf-8",
            )
            with workspace(repository):
                self.assert_worker_error(
                    lambda: worker.capture_git_handoff(identity),
                    status=409,
                    code="unsupported_workspace",
                )

    def test_git_metadata_must_be_standalone_contained_and_independent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            origin, base_commit, _ = initialize_repository(root, "origin")

            independent = root / "independent"
            git(root, "clone", "-q", "--no-local", str(origin), str(independent))
            with workspace(independent):
                worker.workspace_identity(base_commit)

            local = root / "local"
            git(root, "clone", "-q", "--local", str(origin), str(local))
            self.assertTrue(
                any(
                    path.is_file() and not path.is_symlink() and path.stat().st_nlink > 1
                    for path in (local / ".git").rglob("*")
                ),
                "the local-clone fixture did not create shared metadata files",
            )
            with workspace(local):
                self.assert_worker_error(
                    lambda: worker.workspace_identity(base_commit),
                    status=409,
                    code="unsupported_workspace",
                )

            linked = root / "linked"
            git(origin, "worktree", "add", "-q", "--detach", str(linked), base_commit)
            self.assertTrue((linked / ".git").is_file())
            with workspace(linked):
                self.assert_worker_error(
                    lambda: worker.workspace_identity(base_commit),
                    status=409,
                    code="unsupported_workspace",
                )

            linked_metadata, linked_base, _ = initialize_repository(root, "linked-metadata")
            external_metadata = root / "external-metadata"
            (linked_metadata / ".git").rename(external_metadata)
            os.symlink(external_metadata, linked_metadata / ".git", target_is_directory=True)
            with workspace(linked_metadata):
                self.assert_worker_error(
                    lambda: worker.workspace_identity(linked_base),
                    status=409,
                    code="unsupported_workspace",
                )

    def test_late_external_object_store_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            repository, base_commit, _ = initialize_repository(root)
            identity, _ = self.identity(repository, base_commit)
            external_objects = root / "external-objects"
            (repository / ".git" / "objects").rename(external_objects)
            os.symlink(
                external_objects,
                repository / ".git" / "objects",
                target_is_directory=True,
            )
            with workspace(repository):
                self.assert_worker_error(
                    lambda: worker.capture_git_handoff(identity),
                    status=409,
                    code="unsupported_workspace",
                )

    def test_changed_base_blobs_with_protected_material_are_refused(self) -> None:
        marker = b"fixture-protected-base-secret-927451"
        cases: tuple[tuple[str, bytes, bytes | None], ...] = (
            ("text-delete", b"prefix\n" + marker + b"\nsuffix\n", None),
            ("text-replace", b"prefix\n" + marker + b"\nsuffix\n", b"redacted\n"),
            ("binary-delete", b"\x00\xffprefix" + marker + b"\x00suffix", None),
            ("binary-replace", b"\x00\xffprefix" + marker + b"\x00suffix", b"\x00safe\xff"),
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            for name, before, after in cases:
                with self.subTest(name=name):
                    repository, _, _ = initialize_repository(root, name)
                    protected = write(repository, "protected.bin", before)
                    git(repository, "add", "--all")
                    git(repository, "commit", "-q", "-m", "protected base")
                    base_commit = git(repository, "rev-parse", "HEAD").stdout.decode().strip()
                    identity, _ = self.identity(repository, base_commit)
                    if after is None:
                        protected.unlink()
                    else:
                        protected.write_bytes(after)
                    with workspace(repository):
                        self.assert_worker_error(
                            lambda: worker.capture_git_handoff(identity, (marker,)),
                            status=502,
                            code="credential_output_blocked",
                        )

    def test_metadata_symlink_and_nonportable_or_colliding_names_are_refused(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            repository, base_commit, _ = initialize_repository(root, "metadata-link")
            identity, _ = self.identity(repository, base_commit)
            try:
                os.symlink(".git/config", repository / "metadata-link")
            except OSError as error:
                raise unittest.SkipTest(f"symlink fixture unavailable: {error}") from error
            with workspace(repository):
                self.assert_worker_error(
                    lambda: worker.capture_git_handoff(identity),
                    status=409,
                    code="unsupported_workspace",
                )

            case_sensitive = not (repository / ".GiT").exists()
            cases = [
                ("windows-device", "CON.txt"),
                ("trailing-dot", "trailing."),
            ]
            if case_sensitive:
                cases.append(("git-alias", ".GiT"))
            for name, unsafe_path in cases:
                with self.subTest(name=name):
                    unsafe, unsafe_base, _ = initialize_repository(root, name)
                    unsafe_identity, _ = self.identity(unsafe, unsafe_base)
                    try:
                        write(unsafe, unsafe_path, b"unsafe\n")
                    except OSError:
                        continue
                    with workspace(unsafe):
                        self.assert_worker_error(
                            lambda: worker.capture_git_handoff(unsafe_identity),
                            status=409,
                            code="unsupported_workspace",
                        )

            if case_sensitive:
                collision, _, _ = initialize_repository(root, "case-collision")
                write(collision, "CaseName.txt", b"base\n")
                git(collision, "add", "--all")
                git(collision, "commit", "-q", "-m", "portable collision base")
                collision_base = git(collision, "rev-parse", "HEAD").stdout.decode().strip()
                collision_identity, _ = self.identity(collision, collision_base)
                write(collision, "casename.txt", b"result\n")
                with workspace(collision):
                    self.assert_worker_error(
                        lambda: worker.capture_git_handoff(collision_identity),
                        status=409,
                        code="unsupported_workspace",
                    )

    def test_untracked_file_handoff_is_bounded_and_independently_reproducible(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            repository, base_commit, _ = initialize_repository(root)
            identity, _ = self.identity(repository, base_commit)
            for index in range(4):
                write(repository, f"untracked-{index}.txt", f"value {index}\n".encode())

            original_run_git = worker.run_git
            calls: list[tuple[str, ...]] = []

            def recording_run_git(arguments: list[str], **kwargs: object) -> bytes:
                calls.append(tuple(arguments))
                return original_run_git(arguments, **kwargs)

            with workspace(repository), mock.patch.object(
                worker,
                "run_git",
                side_effect=recording_run_git,
            ):
                handoff = worker.capture_git_handoff(identity)

            self.assertEqual(
                handoff["changed_paths"],
                [f"untracked-{index}.txt" for index in range(4)],
            )
            self.assertLessEqual(len(calls), 64, calls)
            review = root / "untracked-review"
            git(root, "clone", "-q", "--no-local", str(repository), str(review))
            git(review, "apply", "--index", "--binary", "-", input_bytes=patch_bytes(handoff))
            self.assertEqual(
                git(review, "write-tree").stdout.decode().strip(),
                handoff["result_tree"],
            )

    def test_handoff_enforces_exact_path_and_patch_boundaries(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository, base_commit, _ = initialize_repository(pathlib.Path(temporary))
            identity, _ = self.identity(repository, base_commit)
            for index in range(worker.MAX_CHANGED_PATHS):
                write(repository, f"bounded-{index:03d}.txt", b"x\n")
            with workspace(repository):
                environment = worker._repository_environment(identity)
                paths = worker._changed_path_inventory(
                    environment,
                    deadline=time.monotonic() + 20,
                )
            self.assertEqual(len(paths), worker.MAX_CHANGED_PATHS)
            write(repository, "one-too-many.txt", b"x\n")
            with workspace(repository):
                self.assert_worker_error(
                    lambda: worker._changed_path_inventory(
                        environment,
                        deadline=time.monotonic() + 20,
                    ),
                    status=413,
                    code="handoff_too_large",
                )

        for size, expected_code in (
            (worker.MAX_HANDOFF_PATCH, "handoff_not_reproducible"),
            (worker.MAX_HANDOFF_PATCH + 1, "handoff_too_large"),
        ):
            with self.subTest(patch_bytes=size), tempfile.TemporaryDirectory() as temporary:
                repository, base_commit, _ = initialize_repository(pathlib.Path(temporary))
                identity, _ = self.identity(repository, base_commit)
                write(repository, "changed.txt", b"result\n")
                original_run_git = worker.run_git

                def bounded_patch(arguments: list[str], **kwargs: object) -> bytes:
                    if arguments and arguments[0] == "diff" and "--binary" in arguments:
                        return b"x" * size
                    return original_run_git(arguments, **kwargs)

                with workspace(repository), mock.patch.object(
                    worker,
                    "run_git",
                    side_effect=bounded_patch,
                ):
                    self.assert_worker_error(
                        lambda: worker.capture_git_handoff(identity),
                        code=expected_code,
                    )

    def test_workspace_entry_bound_is_enforced_while_streaming(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = pathlib.Path(temporary)
            for index in range(3):
                write(repository, f"entry-{index}.txt", b"x\n")
            with workspace(repository), mock.patch.object(worker, "MAX_WORKSPACE_ENTRIES", 2):
                self.assert_worker_error(
                    worker._reject_special_workspace_entries,
                    status=413,
                    code="workspace_too_large",
                )

    def test_changed_path_raw_inventory_overflow_uses_the_handoff_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository, base_commit, _ = initialize_repository(pathlib.Path(temporary))
            identity, _ = self.identity(repository, base_commit)
            write(repository, "a" * 40, b"a\n")
            write(repository, "b" * 40, b"b\n")
            with workspace(repository), mock.patch.object(
                worker,
                "MAX_CHANGED_PATH_BYTES",
                64,
            ), mock.patch.object(worker, "MAX_CHANGED_PATHS", 2):
                environment = worker._repository_environment(identity)
                self.assert_worker_error(
                    lambda: worker._changed_path_inventory(
                        environment,
                        deadline=time.monotonic() + 10,
                    ),
                    status=413,
                    code="handoff_too_large",
                )

    def test_hardlinked_workspace_file_is_refused_before_engine_execution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            repository, _, _ = initialize_repository(root)
            external = write(root, "outside.txt", b"outside remains unchanged\n")
            os.link(external, repository / "shared.txt")
            with workspace(repository), mock.patch.object(
                worker,
                "command_for",
                side_effect=AssertionError("engine must not start"),
            ):
                self.assert_worker_error(
                    lambda: worker.run_task(
                        "codex",
                        b"fixture-worker-token-value",
                        worker.validate_task_payload(
                            {
                                "schema_version": "steward.coding-task.v1",
                                "task": "Change the shared file",
                                "mode": "write",
                                "timeout_seconds": 30,
                            }
                        ),
                    ),
                    status=409,
                    code="special_file_not_supported",
                )
            self.assertEqual(external.read_bytes(), b"outside remains unchanged\n")

    def test_credential_inventory_is_bounded_nofollow_and_complete(self) -> None:
        token = b"fixture-worker-token-value"
        key_secret = b"fixture-json-key-secret-73915"
        proxy = "http://proxy-user:secret%2Fpass@proxy.invalid:8080"
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            credential_home = root / "credentials"
            credential_home.mkdir(mode=0o700)
            (credential_home / "auth.json").write_bytes(
                json.dumps({key_secret.decode(): True}).encode()
            )
            markers = worker.secret_markers(
                token,
                {
                    "CODEX_HOME": str(credential_home),
                    "HTTPS_PROXY": proxy,
                },
            )
            for protected in (
                token,
                key_secret,
                proxy.encode(),
                b"proxy-user",
                b"secret/pass",
            ):
                self.assertIn(protected, markers)

            linked_home = root / "linked-credentials"
            os.symlink(credential_home, linked_home, target_is_directory=True)
            self.assert_worker_error(
                lambda: worker.secret_markers(
                    token,
                    {"CODEX_HOME": str(linked_home)},
                ),
                status=500,
                code="credential_store_unsafe",
            )

            (credential_home / "oversized").write_bytes(
                b"x" * (worker.MAX_CREDENTIAL_FILE_BYTES + 1)
            )
            self.assert_worker_error(
                lambda: worker.secret_markers(
                    token,
                    {"CODEX_HOME": str(credential_home)},
                ),
                status=500,
                code="credential_inventory_too_large",
            )

    def test_credential_entry_and_value_bounds_fail_closed(self) -> None:
        token = b"fixture-worker-token-value"
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            entries = root / "entries"
            entries.mkdir(mode=0o700)
            for index in range(3):
                (entries / f"value-{index}").write_bytes(b"credential-value")
            with mock.patch.object(worker, "MAX_CREDENTIAL_ENTRIES", 2):
                self.assert_worker_error(
                    lambda: worker.secret_markers(
                        token,
                        {"CODEX_HOME": str(entries)},
                    ),
                    status=500,
                    code="credential_inventory_too_large",
                )

            values = root / "values"
            values.mkdir(mode=0o700)
            (values / "auth.json").write_text(
                json.dumps(
                    {
                        f"credential-key-{index:04d}": True
                        for index in range(worker.MAX_CREDENTIAL_VALUES)
                    }
                ),
                encoding="utf-8",
            )
            self.assert_worker_error(
                lambda: worker.secret_markers(
                    token,
                    {"CODEX_HOME": str(values)},
                ),
                status=500,
                code="credential_inventory_too_large",
            )

    def test_protected_marker_scan_honors_its_absolute_deadline(self) -> None:
        with mock.patch.object(worker.time, "monotonic", side_effect=(0.0, 2.0)):
            self.assert_worker_error(
                lambda: worker.contains_protected(
                    b"safe output",
                    (b"first-missing-marker", b"second-missing-marker"),
                    deadline=1.0,
                ),
                status=504,
                code="request_timeout",
            )

    def test_handoff_rejects_an_expired_caller_deadline(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository, base_commit, _ = initialize_repository(pathlib.Path(temporary))
            identity, _ = self.identity(repository, base_commit)
            with workspace(repository):
                self.assert_worker_error(
                    lambda: worker.capture_git_handoff(
                        identity,
                        deadline=time.monotonic() - 1,
                    ),
                    status=504,
                    code="request_timeout",
                )

    def test_v2_dirty_start_ignores_the_v1_development_escape_hatch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository, base_commit, _ = initialize_repository(pathlib.Path(temporary))
            write(repository, "dirty.txt", b"not part of the approved base\n")
            with mock.patch.dict(os.environ, {"STEWARD_ALLOW_DIRTY_WORKSPACE": "YES"}):
                with workspace(repository):
                    error = self.assert_worker_error(
                        lambda: worker.workspace_identity(base_commit),
                        status=409,
                    )
            self.assertIn("clean", error.code)

    def test_gitmodules_change_and_existing_submodule_are_refused(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            repository, base_commit, _ = initialize_repository(root, "changed-modules")
            identity, _ = self.identity(repository, base_commit)
            write(
                repository,
                ".gitmodules",
                b'[submodule "nested"]\n\tpath = nested\n\turl = https://invalid.example/nested\n',
            )
            with workspace(repository):
                changed = self.assert_worker_error(
                    lambda: worker.capture_git_handoff(identity),
                    status=409,
                )
            self.assertTrue("module" in changed.code or "workspace" in changed.code)

            child, _, _ = initialize_repository(root, "child")
            parent, _, _ = initialize_repository(root, "with-submodule")
            git(
                parent,
                "-c",
                "protocol.file.allow=always",
                "submodule",
                "add",
                "-q",
                str(child),
                "nested",
            )
            git(parent, "commit", "-q", "-am", "add submodule")
            submodule_base = git(parent, "rev-parse", "HEAD").stdout.decode().strip()
            with workspace(parent):
                existing = self.assert_worker_error(
                    lambda: worker.workspace_identity(submodule_base),
                    status=409,
                )
            self.assertTrue("module" in existing.code or "workspace" in existing.code)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO fixtures require POSIX")
    def test_special_file_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository, base_commit, _ = initialize_repository(pathlib.Path(temporary))
            identity, _ = self.identity(repository, base_commit)
            os.mkfifo(repository / "engine.pipe", 0o600)
            try:
                with workspace(repository):
                    error = self.assert_worker_error(
                        lambda: worker.capture_git_handoff(identity),
                        status=409,
                    )
                self.assertTrue("special" in error.code or "workspace" in error.code)
            finally:
                (repository / "engine.pipe").unlink(missing_ok=True)

    def run_engine(
        self,
        repository: pathlib.Path,
        payload: dict[str, object],
        source: str,
    ) -> dict[str, object]:
        request = worker.validate_task_payload(payload)
        command = [sys.executable, "-I", "-B", "-c", source]
        with workspace(repository), mock.patch.object(
            worker,
            "command_for",
            return_value=command,
        ):
            result = worker.run_task("codex", b"fixture-worker-token-value", request)
        self.assertIsInstance(result, dict)
        return result

    def background_writer_source(
        self,
        release_path: str,
        output_path: str,
        *,
        detached: bool,
    ) -> str:
        child = (
            "import pathlib,time\n"
            f"release = pathlib.Path({release_path!r})\n"
            "deadline = time.monotonic() + 5\n"
            "while time.monotonic() < deadline:\n"
            "    if release.exists():\n"
            f"        pathlib.Path({output_path!r}).write_bytes(b'late output\\n')\n"
            "        break\n"
            "    time.sleep(0.02)\n"
        )
        detached_option = ", start_new_session=True" if detached else ""
        return (
            "import subprocess,sys; "
            "subprocess.Popen("
            f"[sys.executable, '-I', '-B', '-c', {child!r}], "
            "stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, "
            f"stderr=subprocess.DEVNULL{detached_option})"
        )

    def assert_result_shape(
        self,
        result: Mapping[str, object],
        schema_version: str,
    ) -> None:
        fields = {
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
        if schema_version == "steward.coding-result.v2":
            fields.add("handoff")
        self.assertEqual(set(result), fields)
        self.assertEqual(result["schema_version"], schema_version)
        self.assertEqual(result["engine"], "codex")
        self.assertIs(type(result["exit_code"]), int)
        self.assertIs(type(result["duration_ms"]), int)
        self.assertGreaterEqual(result["duration_ms"], 0)
        self.assertIsInstance(result["changed_paths"], list)
        self.assertIsInstance(result["stdout"], str)
        self.assertIsInstance(result["stderr"], str)

    def test_run_task_preserves_the_version_1_result_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository, _, _ = initialize_repository(pathlib.Path(temporary))
            result = self.run_engine(
                repository,
                {
                    "schema_version": "steward.coding-task.v1",
                    "task": "Inspect the repository",
                    "mode": "read",
                    "timeout_seconds": 30,
                },
                'import sys; print("version one"); print("diagnostic", file=sys.stderr)',
            )
        self.assert_result_shape(result, "steward.coding-result.v1")
        self.assertEqual(result["mode"], "read")
        self.assertEqual(result["outcome"], "completed")
        self.assertEqual(result["exit_code"], 0)
        self.assertEqual(result["changed_paths"], [])
        self.assertEqual(result["stdout"], "version one\n")
        self.assertEqual(result["stderr"], "diagnostic\n")

    def test_run_task_version_1_supports_a_clean_unborn_repository(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = pathlib.Path(temporary) / "unborn"
            repository.mkdir()
            git(repository, "init", "-q")
            result = self.run_engine(
                repository,
                {
                    "schema_version": "steward.coding-task.v1",
                    "task": "Inspect the unborn repository",
                    "mode": "read",
                    "timeout_seconds": 30,
                },
                'print("unborn repository")',
            )
        self.assert_result_shape(result, "steward.coding-result.v1")
        self.assertEqual(result["outcome"], "completed")
        self.assertEqual(result["changed_paths"], [])

    def test_run_task_version_1_write_preserves_dirty_escape_and_failure_result(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository, _, _ = initialize_repository(pathlib.Path(temporary))
            write(repository, "existing-dirty.txt", b"operator fixture\n")
            with mock.patch.dict(
                os.environ,
                {"STEWARD_ALLOW_DIRTY_WORKSPACE": "YES"},
                clear=False,
            ):
                result = self.run_engine(
                    repository,
                    {
                        "schema_version": "steward.coding-task.v1",
                        "task": "Write a partial result",
                        "mode": "write",
                        "timeout_seconds": 30,
                    },
                    (
                        "import pathlib; "
                        "pathlib.Path('engine-output.txt').write_bytes(b'partial\\n'); "
                        "raise SystemExit(7)"
                    ),
                )
        self.assert_result_shape(result, "steward.coding-result.v1")
        self.assertEqual(result["outcome"], "failed")
        self.assertEqual(result["exit_code"], 7)
        self.assertEqual(
            result["changed_paths"],
            ["engine-output.txt", "existing-dirty.txt"],
        )

    def test_run_task_stops_same_group_background_children_before_returning(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository, base_commit, _ = initialize_repository(pathlib.Path(temporary))
            result = self.run_engine(
                repository,
                {
                    "schema_version": "steward.coding-task.v2",
                    "task": "Do not leave background processes",
                    "mode": "write",
                    "timeout_seconds": 30,
                    "expected_base_commit": base_commit,
                },
                self.background_writer_source(
                    "release-same-group",
                    "late-same-group.txt",
                    detached=False,
                ),
            )
            self.assertEqual(result["outcome"], "completed")
            write(repository, "release-same-group", b"release\n")
            time.sleep(0.4)
            self.assertFalse(
                (repository / "late-same-group.txt").exists(),
                "an engine child mutated the workspace after run_task returned",
            )

    @unittest.skipUnless(sys.platform.startswith("linux"), "detached child coverage requires Linux")
    def test_run_task_contains_detached_background_children_before_returning(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository, base_commit, _ = initialize_repository(pathlib.Path(temporary))
            for version in ("steward.coding-task.v1", "steward.coding-task.v2"):
                suffix = version.rsplit(".", 1)[-1]
                payload: dict[str, object] = {
                    "schema_version": version,
                    "task": "Do not leave detached background processes",
                    "mode": "write",
                    "timeout_seconds": 30,
                }
                if version == "steward.coding-task.v2":
                    payload["expected_base_commit"] = base_commit
                result = self.run_engine(
                    repository,
                    payload,
                    self.background_writer_source(
                        f"release-detached-{suffix}",
                        f"late-detached-{suffix}.txt",
                        detached=True,
                    ),
                )
                self.assertEqual(result["outcome"], "completed")
                release = write(repository, f"release-detached-{suffix}", b"release\n")
                time.sleep(0.4)
                self.assertFalse(
                    (repository / f"late-detached-{suffix}.txt").exists(),
                    f"a detached {version} engine child mutated the workspace after run_task returned",
                )
                release.unlink()

    def test_credential_created_during_engine_run_is_blocked_from_output(self) -> None:
        token = "fixture-refreshed-credential-864209"
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            repository, _, _ = initialize_repository(root)
            credential_home = root / "codex-home"
            credential_home.mkdir(mode=0o700)
            source = (
                "import json,os,pathlib; "
                "home=pathlib.Path(os.environ['CODEX_HOME']); "
                f"token={token!r}; "
                "(home/'session.json').write_text("
                "json.dumps({'access_token':token}),encoding='utf-8'); "
                "print(token)"
            )
            with mock.patch.dict(
                os.environ,
                {"CODEX_HOME": str(credential_home.resolve())},
                clear=False,
            ):
                self.assert_worker_error(
                    lambda: self.run_engine(
                        repository,
                        {
                            "schema_version": "steward.coding-task.v1",
                            "task": "Refresh the provider session",
                            "mode": "read",
                            "timeout_seconds": 30,
                        },
                        source,
                    ),
                    status=502,
                    code="credential_output_blocked",
                )

    def test_run_task_version_2_read_returns_an_exact_empty_handoff(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository, base_commit, base_tree = initialize_repository(pathlib.Path(temporary))
            result = self.run_engine(
                repository,
                {
                    "schema_version": "steward.coding-task.v2",
                    "task": "Inspect the immutable base",
                    "mode": "read",
                    "timeout_seconds": 30,
                    "expected_base_commit": base_commit,
                },
                'print("version two")',
            )
        self.assert_result_shape(result, "steward.coding-result.v2")
        self.assertEqual(result["mode"], "read")
        self.assertEqual(result["outcome"], "completed")
        self.assertEqual(result["exit_code"], 0)
        self.assertEqual(result["changed_paths"], [])
        handoff = result["handoff"]
        self.assertIsInstance(handoff, dict)
        raw = self.assert_handoff_shape(
            handoff,
            base_commit=base_commit,
            base_tree=base_tree,
        )
        self.assertEqual(raw, b"")
        self.assertEqual(handoff["result_tree"], base_tree)
        self.assertEqual(handoff["changed_paths"], [])

    def test_run_task_version_2_failed_write_returns_a_reproducible_handoff(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            repository, base_commit, base_tree = initialize_repository(root)
            result = self.run_engine(
                repository,
                {
                    "schema_version": "steward.coding-task.v2",
                    "task": "Write a bounded result, then report failure",
                    "mode": "write",
                    "timeout_seconds": 30,
                    "expected_base_commit": base_commit,
                },
                (
                    "import pathlib,sys; "
                    'pathlib.Path("engine-output.txt").write_bytes(b"bounded output\\n"); '
                    'print("partial result"); print("fixture failure", file=sys.stderr); '
                    "raise SystemExit(7)"
                ),
            )
            self.assert_result_shape(result, "steward.coding-result.v2")
            self.assertEqual(result["mode"], "write")
            self.assertEqual(result["outcome"], "failed")
            self.assertEqual(result["exit_code"], 7)
            self.assertEqual(result["changed_paths"], ["engine-output.txt"])
            handoff = result["handoff"]
            self.assertIsInstance(handoff, dict)
            patch = self.assert_handoff_shape(
                handoff,
                base_commit=base_commit,
                base_tree=base_tree,
            )
            self.assertEqual(handoff["changed_paths"], ["engine-output.txt"])

            review = root / "failed-review"
            git(root, "clone", "-q", "--no-local", str(repository), str(review))
            patch_path = root / "failed-handoff.patch"
            patch_path.write_bytes(patch)
            git(review, "apply", "--index", "--binary", str(patch_path))
            self.assertEqual(
                git(review, "write-tree").stdout.decode().strip(),
                handoff["result_tree"],
            )
            self.assertEqual(
                (review / "engine-output.txt").read_bytes(),
                b"bounded output\n",
            )

    def test_server_refuses_authenticated_recursive_ingress_during_engine_run(self) -> None:
        token = b"fixture-worker-token-value"
        payload = {
            "schema_version": "steward.coding-task.v1",
            "task": "Attempt a recursive dispatch",
            "mode": "read",
            "timeout_seconds": 30,
        }
        encoded = json.dumps(payload).encode()
        server = worker.Server(("127.0.0.1", 0), "codex", token)
        server.timeout = 0.05
        stop = threading.Event()
        calls: list[dict[str, object]] = []
        recursive_errors: list[BaseException] = []

        def serve() -> None:
            while not stop.is_set() and not server.poisoned:
                server.handle_request()

        def fake_run_task(
            engine: str,
            worker_token: bytes,
            request: dict[str, object],
        ) -> dict[str, object]:
            self.assertEqual(engine, "codex")
            self.assertEqual(worker_token, token)
            calls.append(request)
            recursive = http.client.HTTPConnection(
                server.server_address[0],
                server.server_address[1],
                timeout=0.2,
            )
            try:
                recursive.request(
                    "POST",
                    "/v1/run",
                    body=encoded,
                    headers={
                        "Authorization": f"Bearer {token.decode()}",
                        "Content-Type": "application/json",
                    },
                )
                recursive.getresponse()
            except OSError as error:
                recursive_errors.append(error)
            finally:
                recursive.close()
            return {"schema_version": "fixture-result", "outcome": "completed"}

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        try:
            with mock.patch.object(worker, "run_task", side_effect=fake_run_task):
                for expected_calls in (1, 2):
                    connection = http.client.HTTPConnection(
                        server.server_address[0],
                        server.server_address[1],
                        timeout=2,
                    )
                    try:
                        connection.request(
                            "POST",
                            "/v1/run",
                            body=encoded,
                            headers={
                                "Authorization": f"Bearer {token.decode()}",
                                "Content-Type": "application/json",
                            },
                        )
                        response = connection.getresponse()
                        body = json.loads(response.read())
                    finally:
                        connection.close()
                    self.assertEqual(response.status, 200)
                    self.assertEqual(body["outcome"], "completed")
                    self.assertEqual(len(calls), expected_calls)
                    self.assertTrue(server.accepting)
                    self.assertFalse(server.poisoned)
        finally:
            stop.set()
            thread.join(timeout=1)
            server.server_close()
        self.assertFalse(thread.is_alive())
        self.assertEqual(len(recursive_errors), 2)
        self.assertEqual(len(calls), 2)

    def test_server_never_rearms_after_uncertain_engine_cleanup(self) -> None:
        token = b"fixture-worker-token-value"
        payload = json.dumps(
            {
                "schema_version": "steward.coding-task.v1",
                "task": "Fail cleanup",
                "mode": "read",
                "timeout_seconds": 30,
            }
        ).encode()
        server = worker.Server(("127.0.0.1", 0), "codex", token)
        server.timeout = 0.05

        def serve() -> None:
            while not server.poisoned:
                server.handle_request()

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        try:
            with mock.patch.object(
                worker,
                "run_task",
                side_effect=worker.WorkerError(
                    502,
                    "engine_cleanup_failed",
                    "coding engine descendants did not stop",
                ),
            ):
                connection = http.client.HTTPConnection(
                    server.server_address[0],
                    server.server_address[1],
                    timeout=2,
                )
                try:
                    connection.request(
                        "POST",
                        "/v1/run",
                        body=payload,
                        headers={
                            "Authorization": f"Bearer {token.decode()}",
                            "Content-Type": "application/json",
                        },
                    )
                    response = connection.getresponse()
                    body = json.loads(response.read())
                finally:
                    connection.close()
            self.assertEqual(response.status, 502)
            self.assertEqual(body["error"], "engine_cleanup_failed")
            self.assertTrue(server.poisoned)
            self.assertFalse(server.accepting)
            thread.join(timeout=1)
            self.assertFalse(thread.is_alive())
            with self.assertRaises(OSError):
                probe = socket.create_connection(server.server_address, timeout=0.2)
                probe.close()
        finally:
            server.server_close()

    def test_server_guard_transition_failures_poison_ingress(self) -> None:
        token = b"fixture-worker-token-value"
        creation_failure = worker.Server(("127.0.0.1", 0), "codex", token)
        try:
            with mock.patch.object(
                worker.socket,
                "socket",
                side_effect=OSError("fixture descriptor exhaustion"),
            ):
                self.assert_worker_error(
                    creation_failure.suspend_engine_ingress,
                    status=503,
                    code="engine_ingress_unavailable",
                )
            self.assertTrue(creation_failure.poisoned)
            self.assertFalse(creation_failure.accepting)
            self.assertEqual(creation_failure.socket.fileno(), -1)
        finally:
            creation_failure.server_close()

        activation_failure = worker.Server(("127.0.0.1", 0), "codex", token)
        try:
            activation_failure.suspend_engine_ingress()
            with mock.patch.object(
                activation_failure,
                "server_activate",
                side_effect=OSError("fixture listen failure"),
            ):
                self.assert_worker_error(
                    activation_failure.resume_engine_ingress,
                    status=503,
                    code="engine_ingress_unavailable",
                )
            self.assertTrue(activation_failure.poisoned)
            self.assertFalse(activation_failure.accepting)
            with self.assertRaises(OSError):
                probe = socket.create_connection(
                    activation_failure.server_address,
                    timeout=0.2,
                )
                probe.close()
        finally:
            activation_failure.server_close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
