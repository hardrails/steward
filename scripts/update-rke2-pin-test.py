#!/usr/bin/env python3
"""Hermetic tests for the RKE2 pin updater."""

from __future__ import annotations

import importlib.util
import json
import pathlib
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "update-rke2-pin.py"
SPEC = importlib.util.spec_from_file_location("update_rke2_pin", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def release(version: str) -> dict[str, object]:
    assets: list[dict[str, object]] = []
    for arch in ("amd64", "arm64"):
        for name, size, marker in (
            (f"rke2.linux-{arch}.tar.gz", 40_000_000, "1"),
            (f"rke2-images.linux-{arch}.tar.zst", 800_000_000, "2"),
            (f"sha256sum-{arch}.txt", 3_000, "3"),
        ):
            assets.append(
                {
                    "name": name,
                    "size": size,
                    "digest": "sha256:" + marker * 64,
                    "browser_download_url": (
                        "https://github.com/rancher/rke2/releases/download/"
                        + version.replace("+", "%2B")
                        + "/"
                        + name
                    ),
                }
            )
    return {
        "tag_name": version,
        "draft": False,
        "prerelease": False,
        "published_at": "2026-08-01T00:00:00Z",
        "assets": assets,
    }


with tempfile.TemporaryDirectory() as directory:
    work = pathlib.Path(directory)
    lock = work / "source-lock.json"
    lock.write_text(
        (ROOT / "internal/clustersubstrate/source-lock.json").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    response = work / "release.json"
    next_version = "v1.35.7+rke2r1"
    response.write_text(json.dumps(release(next_version)), encoding="utf-8")
    assert MODULE.update(lock, response, next_version) is True
    updated = json.loads(lock.read_text(encoding="utf-8"))
    assert updated["version"] == next_version
    assert updated["architectures"]["amd64"]["bundle"]["sha256"] == "1" * 64
    assert MODULE.update(lock, response, next_version) is False

    for mutate in (
        lambda value: value.update({"draft": True}),
        lambda value: value["assets"][0].update({"digest": None}),
        lambda value: value["assets"][0].update(
            {"browser_download_url": "https://example.com/payload"}
        ),
        lambda value: value.update({"tag_name": "v1.35.8+rke2r1"}),
    ):
        candidate = release(next_version)
        mutate(candidate)
        response.write_text(json.dumps(candidate), encoding="utf-8")
        try:
            MODULE.update(lock, response, next_version)
        except ValueError:
            pass
        else:
            raise AssertionError("unsafe RKE2 release metadata was accepted")

    response.write_text(
        json.dumps(release("v1.34.1+rke2r1")), encoding="utf-8"
    )
    try:
        MODULE.update(lock, response, "v1.34.1+rke2r1")
    except ValueError:
        pass
    else:
        raise AssertionError("RKE2 downgrade was accepted")

print("update-rke2-pin-test: updater contracts pass")
