#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import json
import pathlib
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("updater", ROOT / "scripts" / "update-playwright-pin.py")
assert spec and spec.loader
updater = importlib.util.module_from_spec(spec)
spec.loader.exec_module(updater)


with tempfile.TemporaryDirectory() as temporary:
    root = pathlib.Path(temporary)
    browser = root / "workers" / "browser"
    browser.mkdir(parents=True)
    (browser / "package.json").write_text(
        '{"name":"fixture","dependencies":{"playwright":"1.0.0"}}\n',
        encoding="utf-8",
    )
    (browser / "Dockerfile").write_text(
        "FROM mcr.microsoft.com/playwright:v1.0.0-noble@sha256:" + "a" * 64 + "\n",
        encoding="utf-8",
    )
    updater.update(root, "1.61.0", "sha256:" + "b" * 64)
    package = json.loads((browser / "package.json").read_text(encoding="utf-8"))
    assert package["dependencies"]["playwright"] == "1.61.0"
    assert "v1.61.0-noble@sha256:" + "b" * 64 in (browser / "Dockerfile").read_text(encoding="utf-8")
    for version, digest in [("latest", "sha256:" + "b" * 64), ("1.61.0", "sha256:bad")]:
        try:
            updater.update(root, version, digest)
        except ValueError:
            pass
        else:
            raise AssertionError("invalid Playwright identity was accepted")
