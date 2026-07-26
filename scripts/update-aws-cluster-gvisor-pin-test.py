#!/usr/bin/env python3
"""Hermetic tests for the AWS cluster gVisor lock updater."""

from __future__ import annotations

import importlib.util
import io
import json
import pathlib
import tarfile
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "update-aws-cluster-gvisor-pin.py"
SPEC = importlib.util.spec_from_file_location("update_aws_cluster_gvisor_pin", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def write_archive(path: pathlib.Path, *, unsafe: bool = False) -> None:
    with tarfile.open(path, mode="w:bz2") as archive:
        for name, kind in MODULE.EXPECTED_MEMBERS.items():
            info = tarfile.TarInfo(name)
            info.mode = 0o755
            if kind == "directory":
                info.type = tarfile.DIRTYPE
                archive.addfile(info)
            elif unsafe and name == "runsc":
                info.type = tarfile.SYMTYPE
                info.linkname = "/tmp/runsc"
                archive.addfile(info)
            else:
                payload = (name + "\n").encode()
                info.size = len(payload)
                archive.addfile(info, io.BytesIO(payload))


with tempfile.TemporaryDirectory() as directory:
    work = pathlib.Path(directory)
    lock = work / "source-lock.json"
    lock.write_text(
        (
            ROOT
            / "integrations/terraform/modules/aws-steward-cluster/source-lock.json"
        ).read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    amd64 = work / "amd64.tar.bz2"
    arm64 = work / "arm64.tar.bz2"
    write_archive(amd64)
    write_archive(arm64)

    assert MODULE.update(
        lock, "20260722.0", {"amd64": amd64, "arm64": arm64}
    ) is True
    updated = json.loads(lock.read_text(encoding="utf-8"))
    assert updated["gvisor"]["version"] == "20260722.0"
    assert updated["gvisor"]["archives"]["amd64"]["size"] == amd64.stat().st_size
    assert len(updated["gvisor"]["archives"]["arm64"]["sha512"]) == 128
    assert MODULE.update(
        lock, "20260722.0", {"amd64": amd64, "arm64": arm64}
    ) is False

    try:
        MODULE.update(lock, "20260721.0", {"amd64": amd64, "arm64": arm64})
    except ValueError:
        pass
    else:
        raise AssertionError("gVisor downgrade was accepted")

    unsafe = work / "unsafe.tar.bz2"
    write_archive(unsafe, unsafe=True)
    try:
        MODULE.update(lock, "20260723.0", {"amd64": unsafe, "arm64": arm64})
    except ValueError:
        pass
    else:
        raise AssertionError("unsafe gVisor archive was accepted")

print("update-aws-cluster-gvisor-pin-test: updater contracts pass")
