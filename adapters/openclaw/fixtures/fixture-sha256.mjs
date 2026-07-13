#!/usr/bin/env node
import { createHash } from "node:crypto";

const nonce = process.argv[2] ?? "";
if (!/^[a-f0-9]{16,64}$/.test(nonce)) {
  process.stderr.write("fixture.sha256: nonce must be 16-64 lowercase hexadecimal characters\n");
  process.exit(2);
}
process.stdout.write(`${createHash("sha256").update(nonce).digest("hex")}\n`);
