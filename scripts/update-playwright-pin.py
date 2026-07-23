#!/usr/bin/env python3
"""Update Steward's exact Playwright package and official image identity."""

from __future__ import annotations

import argparse
import json
import pathlib
import re

VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
IMAGE = re.compile(
    r"mcr\.microsoft\.com/playwright:v[0-9]+\.[0-9]+\.[0-9]+-noble@sha256:[0-9a-f]{64}"
)


def update(root: pathlib.Path, version: str, manifest_digest: str) -> None:
    if VERSION.fullmatch(version) is None or DIGEST.fullmatch(manifest_digest) is None:
        raise ValueError("Playwright version or manifest-list digest is invalid")
    package_path = root / "workers" / "browser" / "package.json"
    dockerfile_path = root / "workers" / "browser" / "Dockerfile"
    package = json.loads(package_path.read_text(encoding="utf-8"))
    dependencies = package.get("dependencies")
    if not isinstance(dependencies, dict) or dependencies.get("playwright") is None:
        raise ValueError("browser package has no Playwright dependency")
    dependencies["playwright"] = version
    package_path.write_text(
        json.dumps(package, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    dockerfile = dockerfile_path.read_text(encoding="utf-8")
    replacement = f"mcr.microsoft.com/playwright:v{version}-noble@{manifest_digest}"
    updated, count = IMAGE.subn(replacement, dockerfile)
    if count != 1:
        raise ValueError("browser Dockerfile must contain one exact official Playwright image")
    dockerfile_path.write_text(updated, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True)
    parser.add_argument("--manifest-digest", required=True)
    parser.add_argument("--root", type=pathlib.Path, default=pathlib.Path(__file__).resolve().parents[1])
    arguments = parser.parse_args()
    update(arguments.root.resolve(), arguments.version, arguments.manifest_digest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
