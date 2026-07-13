#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import sys


def main() -> int:
    if len(sys.argv) != 2 or not 1 <= len(sys.argv[1]) <= 128:
        print("usage: fixture_sha256.py NONCE", file=sys.stderr)
        return 2
    print(hashlib.sha256(sys.argv[1].encode()).hexdigest())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
