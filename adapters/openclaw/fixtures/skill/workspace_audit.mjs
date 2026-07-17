#!/usr/bin/env node

import { createHash } from "node:crypto";
import {
  closeSync,
  constants,
  fsyncSync,
  lstatSync,
  openSync,
  readFileSync,
  readdirSync,
  renameSync,
  writeFileSync,
} from "node:fs";
import { join, relative } from "node:path";

const ROOT = "/home/node/.openclaw/workspace/qualification/input";
const OUTPUT = "/home/node/.openclaw/workspace/qualification/result.json";
const MAX_FILES = 128;
const MAX_FILE_BYTES = 256 << 10;
const MAX_TOTAL_BYTES = 1 << 20;

const entries = [];
function visit(directory) {
  const names = readdirSync(directory).sort();
  for (const name of names) {
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(name)) throw new Error("unsafe workspace entry name");
    const path = join(directory, name);
    const info = lstatSync(path);
    if (info.isSymbolicLink()) throw new Error("workspace links are not allowed");
    if (info.isDirectory()) {
      visit(path);
      continue;
    }
    if (!info.isFile() || info.nlink !== 1 || info.size > MAX_FILE_BYTES) throw new Error("unsafe workspace file");
    const content = readFileSync(path);
    if (content.length !== info.size) throw new Error("workspace file changed while reading");
    entries.push({
      bytes: content.length,
      path: relative(ROOT, path).split("\\").join("/"),
      sha256: createHash("sha256").update(content).digest("hex"),
    });
    if (entries.length > MAX_FILES || entries.reduce((sum, entry) => sum + entry.bytes, 0) > MAX_TOTAL_BYTES) {
      throw new Error("workspace exceeds audit limits");
    }
  }
}

visit(ROOT);
const digest = createHash("sha256").update(JSON.stringify(entries)).digest("hex");
const result = {
  digest,
  file_count: entries.length,
  files: entries,
  schema_version: "steward.workspace-audit.result.v1",
  total_bytes: entries.reduce((sum, entry) => sum + entry.bytes, 0),
};
const encoded = `${JSON.stringify(result)}\n`;
const temporary = `${OUTPUT}.${process.pid}`;
const descriptor = openSync(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
try {
  writeFileSync(descriptor, encoded, "utf8");
  fsyncSync(descriptor);
} finally {
  closeSync(descriptor);
}
renameSync(temporary, OUTPUT);
process.stdout.write(encoded);
