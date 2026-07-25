#!/usr/bin/env python3
"""Update Steward's RKE2 lock from one already-fetched GitHub release."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import pathlib
import re
import sys
import urllib.parse

VERSION = re.compile(r"^v([1-9][0-9]*)\.([0-9]+)\.([0-9]+)\+rke2r([1-9][0-9]*)$")
SHA256 = re.compile(r"^sha256:([0-9a-f]{64})$")
ARCHES = ("amd64", "arm64")
KINDS = {
    "bundle": "rke2.linux-{arch}.tar.gz",
    "images": "rke2-images.linux-{arch}.tar.zst",
    "checksums": "sha256sum-{arch}.txt",
}
REPOSITORY = "https://github.com/rancher/rke2"


def version_tuple(value: str) -> tuple[int, int, int, int]:
    match = VERSION.fullmatch(value)
    if match is None:
        raise ValueError("RKE2 version must be vX.Y.Z+rke2rN")
    return tuple(int(part) for part in match.groups())  # type: ignore[return-value]


def validated_release(document: object, expected_version: str) -> dict[str, object]:
    if not isinstance(document, dict):
        raise ValueError("GitHub release response must be an object")
    if (
        document.get("tag_name") != expected_version
        or document.get("draft") is not False
        or document.get("prerelease") is not False
    ):
        raise ValueError("GitHub release is not the requested stable release")
    published = document.get("published_at")
    if not isinstance(published, str):
        raise ValueError("GitHub release has no publication time")
    parsed = dt.datetime.fromisoformat(published.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("GitHub release publication time has no timezone")
    assets = document.get("assets")
    if not isinstance(assets, list) or len(assets) > 256:
        raise ValueError("GitHub release asset inventory is invalid")
    return document


def release_assets(document: dict[str, object], version: str) -> dict[str, dict[str, object]]:
    raw_assets = document["assets"]
    assert isinstance(raw_assets, list)
    by_name: dict[str, object] = {}
    for raw in raw_assets:
        if not isinstance(raw, dict) or not isinstance(raw.get("name"), str):
            raise ValueError("GitHub release contains an invalid asset")
        name = raw["name"]
        if name in by_name:
            raise ValueError(f"GitHub release repeats asset {name}")
        by_name[name] = raw

    result: dict[str, dict[str, object]] = {}
    for arch in ARCHES:
        result[arch] = {}
        for kind, pattern in KINDS.items():
            name = pattern.format(arch=arch)
            raw = by_name.get(name)
            if not isinstance(raw, dict):
                raise ValueError(f"GitHub release is missing {name}")
            size = raw.get("size")
            digest = raw.get("digest")
            url = raw.get("browser_download_url")
            match = SHA256.fullmatch(digest) if isinstance(digest, str) else None
            parsed = urllib.parse.urlparse(url) if isinstance(url, str) else None
            expected_path = f"/rancher/rke2/releases/download/{version}/{name}"
            if (
                not isinstance(size, int)
                or isinstance(size, bool)
                or size <= 0
                or size > 2 * 1024 * 1024 * 1024
                or match is None
                or parsed is None
                or parsed.scheme != "https"
                or parsed.netloc != "github.com"
                or urllib.parse.unquote(parsed.path) != expected_path
                or parsed.params
                or parsed.query
                or parsed.fragment
            ):
                raise ValueError(f"GitHub release metadata for {name} is invalid")
            result[arch][kind] = {
                "name": name,
                "url": url,
                "size": size,
                "sha256": match.group(1),
            }
    return result


def update(lock_path: pathlib.Path, release_path: pathlib.Path, version: str) -> bool:
    version_tuple(version)
    current = json.loads(lock_path.read_text(encoding="utf-8"))
    if not isinstance(current, dict) or not isinstance(current.get("version"), str):
        raise ValueError("current RKE2 lock is invalid")
    if version_tuple(version) < version_tuple(current["version"]):
        raise ValueError("refusing to downgrade the RKE2 lock")
    release = validated_release(
        json.loads(release_path.read_text(encoding="utf-8")), version
    )
    published = release["published_at"]
    assert isinstance(published, str)
    candidate = {
        "schema_version": "steward.cluster-substrate-lock.v1",
        "provider": "rke2",
        "channel": "stable",
        "version": version,
        "observed_at": published,
        "repository": REPOSITORY,
        "license": "Apache-2.0",
        "architectures": release_assets(release, version),
    }
    encoded = json.dumps(candidate, indent=2, sort_keys=False) + "\n"
    if lock_path.read_text(encoding="utf-8") == encoded:
        return False
    lock_path.write_text(encoded, encoding="utf-8")
    return True


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lock", type=pathlib.Path, required=True)
    parser.add_argument("--release-json", type=pathlib.Path, required=True)
    parser.add_argument("--version", required=True)
    args = parser.parse_args()
    try:
        changed = update(args.lock, args.release_json, args.version)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"update-rke2-pin: {error}", file=sys.stderr)
        return 2
    print("updated" if changed else "current")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
