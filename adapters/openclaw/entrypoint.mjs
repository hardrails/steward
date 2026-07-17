#!/usr/bin/env node

import { createHash, randomBytes } from "node:crypto";
import { createServer } from "node:http";
import { spawn } from "node:child_process";
import {
  chmodSync,
  closeSync,
  constants,
  existsSync,
  fsyncSync,
  fstatSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import { canonicalJSON, sanitizeOpenClawResult } from "/opt/steward/result.mjs";

const REVISION = "2d2ddc43d0dcf71f31283d780f9fe9ff4cc04fe4";
const STATE = "/home/node/.openclaw";
const WORKSPACE = `${STATE}/workspace`;
const CONFIG = "/tmp/steward-openclaw.json";
const OPENCLAW = "/app/openclaw.mjs";
const PORT = 18789;
const MAX_REQUEST_BYTES = 64 << 10;
const MAX_RESULT_BYTES = 1 << 20;
const RUN_TIMEOUT_MS = 120_000;
const MAX_RETAINED_RUNS = 64;
const MODEL_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/;
const SESSION_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const RUN_PATTERN = /^run_[a-f0-9]{32}$/;
const FIXTURE_SOURCE = "/opt/steward/skills/steward-workspace-audit";
const FIXTURE_TARGET = `${WORKSPACE}/skills/steward-workspace-audit`;
const AUDIT_RESULT = `${WORKSPACE}/qualification/result.json`;
const AUDIT_MANIFEST = "8a88036085cd27e3e0a85ab10f3fbfed492633fa76fd18a85bb478747c4d56d5";
const AUDIT_FILES = [
  { bytes: 40, path: "alpha.txt", sha256: "3e056c4704264fdc5b636bc7cfb9c9aece659721fe5327ded69d02bf8e56c5d9" },
  { bytes: 93, path: "nested.json", sha256: "9bb742b5f09ef2c81ffcc169c649ac2821e8c51f56c9f2b7a19ee1099568e7ea" },
];
const runs = new Map();
let activeRuns = 0;
let pendingRuns = 0;

function fail(message) {
  process.stderr.write(`openclaw-adapter: ${message}\n`);
  process.exit(1);
}

function isSafeDirectory(path, mode) {
  const info = lstatSync(path);
  return info.isDirectory() && !info.isSymbolicLink() && info.uid === 65532 &&
    info.gid === 65532 && (info.mode & 0o777) === mode;
}

function requireDirectory(path, mode = 0o700) {
  if (!existsSync(path)) {
    mkdirSync(path, { mode });
  }
  if (!isSafeDirectory(path, mode)) {
    fail(`unsafe state directory: ${path}`);
  }
}

function publishExactFile(name, mode) {
  const source = join(FIXTURE_SOURCE, name);
  const target = join(FIXTURE_TARGET, name);
  const expected = readFileSync(source);
  const sourceInfo = lstatSync(source);
  if (!sourceInfo.isFile() || sourceInfo.isSymbolicLink() || sourceInfo.uid !== 0 ||
      sourceInfo.gid !== 0 || (sourceInfo.mode & 0o777) !== mode || expected.length > (64 << 10)) {
    fail(`unsafe built-in skill file: ${name}`);
  }
  if (existsSync(target)) {
    const currentInfo = lstatSync(target);
    const current = readFileSync(target);
    if (!currentInfo.isFile() || currentInfo.isSymbolicLink() || currentInfo.uid !== 65532 ||
        currentInfo.gid !== 65532 || (currentInfo.mode & 0o777) !== mode ||
        !current.equals(expected)) {
      fail(`persisted skill drifted: ${name}`);
    }
    return;
  }
  const temporary = join(FIXTURE_TARGET, `.${name}.steward-${process.pid}`);
  let descriptor;
  try {
    descriptor = openSync(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, mode);
    writeFileSync(descriptor, expected);
    fsyncSync(descriptor);
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
  renameSync(temporary, target);
  chmodSync(target, mode);
  const published = lstatSync(target);
  if (!published.isFile() || published.isSymbolicLink() || published.uid !== 65532 ||
      published.gid !== 65532 || (published.mode & 0o777) !== mode) {
    fail(`skill publication failed: ${name}`);
  }
}

function configure() {
  if (process.getuid?.() !== 65532 || process.getgid?.() !== 65532) {
    fail("process identity must be 65532:65532");
  }
  if (process.env.OPENAI_BASE_URL !== "http://steward-relay:8080/v1" ||
      process.env.OPENAI_API_KEY !== "steward-local") {
    fail("inference must use Steward's fixed relay environment");
  }
  const model = process.env.OPENAI_MODEL ?? "";
  if (!MODEL_PATTERN.test(model)) {
    fail("OPENAI_MODEL is missing or invalid");
  }
  requireDirectory(STATE);
  requireDirectory(WORKSPACE);
  requireDirectory(`${WORKSPACE}/skills`);
  requireDirectory(FIXTURE_TARGET);
  publishExactFile("SKILL.md", 0o444);
  publishExactFile("workspace_audit.mjs", 0o555);

  const modelRef = `steward/${model}`;
  const config = {
    agents: {
      defaults: {
        model: { primary: modelRef },
        models: { [modelRef]: { agentRuntime: { id: "openclaw" } } },
        skills: ["steward-workspace-audit"],
        skipBootstrap: true,
        thinkingDefault: "off",
        timeoutSeconds: 90,
        workspace: WORKSPACE,
      },
    },
    models: {
      mode: "replace",
      providers: {
        steward: {
          api: "openai-completions",
          apiKey: "${OPENAI_API_KEY}",
          baseUrl: "${OPENAI_BASE_URL}",
          models: [{
            agentRuntime: { id: "openclaw" },
            contextWindow: 65536,
            id: model,
            input: ["text"],
            maxTokens: 4096,
            name: model,
            reasoning: false,
          }],
        },
      },
    },
    plugins: { allow: [] },
    tools: {
      allow: ["exec", "read"],
      exec: { ask: "off", security: "full", timeoutSec: 30 },
      loopDetection: { enabled: true },
    },
  };
  const encoded = `${JSON.stringify(config, null, 2)}\n`;
  const temporary = `${CONFIG}.${process.pid}`;
  const descriptor = openSync(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try {
    writeFileSync(descriptor, encoded, "utf8");
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
  renameSync(temporary, CONFIG);
  chmodSync(CONFIG, 0o600);
  return model;
}

function sendJSON(response, status, value) {
  const encoded = Buffer.from(`${JSON.stringify(value)}\n`);
  response.writeHead(status, {
    "cache-control": "no-store",
    "content-length": String(encoded.length),
    "content-type": "application/json",
    "x-content-type-options": "nosniff",
  });
  response.end(encoded);
}

function readBody(request) {
  return new Promise((resolve, reject) => {
    const declared = request.headers["content-length"];
    if (declared !== undefined && (!/^\d+$/.test(declared) || Number(declared) > MAX_REQUEST_BYTES)) {
      reject(new Error("request body exceeds 64 KiB"));
      request.resume();
      return;
    }
    const chunks = [];
    let size = 0;
    let oversized = false;
    request.on("data", (chunk) => {
      size += chunk.length;
      if (size > MAX_REQUEST_BYTES) {
        oversized = true;
        return;
      }
      if (!oversized) chunks.push(chunk);
    });
    request.on("end", () => {
      if (oversized) reject(new Error("request body exceeds 64 KiB"));
      else resolve(Buffer.concat(chunks));
    });
    request.on("error", reject);
  });
}

function boundedCapture(stream, child, onComplete) {
  const chunks = [];
  let size = 0;
  stream.on("data", (chunk) => {
    size += chunk.length;
    if (size > MAX_RESULT_BYTES) {
      child.kill("SIGKILL");
      return;
    }
    chunks.push(chunk);
  });
  stream.on("end", () => onComplete(Buffer.concat(chunks), size > MAX_RESULT_BYTES));
}

function readQualifiedAudit() {
  const descriptor = openSync(AUDIT_RESULT, constants.O_RDONLY | constants.O_NOFOLLOW);
  let raw;
  try {
    const info = fstatSync(descriptor);
    if (!info.isFile() || info.nlink !== 1 || info.uid !== 65532 || info.gid !== 65532 ||
        (info.mode & 0o777) !== 0o600 || info.size < 1 || info.size > (64 << 10)) {
      throw new Error("workspace audit result has an unsafe file identity");
    }
    raw = readFileSync(descriptor);
    if (raw.length !== info.size) throw new Error("workspace audit result changed while reading");
  } finally {
    closeSync(descriptor);
  }
  const audit = JSON.parse(raw.toString("utf8"));
  const keys = audit && typeof audit === "object" && !Array.isArray(audit) ? Object.keys(audit).sort() : [];
  if (keys.join(",") !== "digest,file_count,files,schema_version,total_bytes" ||
      audit.digest !== AUDIT_MANIFEST || audit.file_count !== AUDIT_FILES.length ||
      audit.schema_version !== "steward.workspace-audit.result.v1" || audit.total_bytes !== 133 ||
      JSON.stringify(audit.files) !== JSON.stringify(AUDIT_FILES) ||
      !raw.equals(Buffer.from(`${JSON.stringify(audit)}\n`))) {
    throw new Error("workspace audit result is not the qualified fixture result");
  }
  return {
    fixture_id: "steward.workspace-audit.qualification.v1",
    workspace_manifest_digest: `sha256:${audit.digest}`,
  };
}

async function executeRun(record, message, sessionID, model) {
  activeRuns += 1;
  record.status = "running";
  const messagePath = `/tmp/${record.run_id}.message`;
  try {
    try { unlinkSync(AUDIT_RESULT); } catch (error) {
      if (error?.code !== "ENOENT") throw error;
    }
    const descriptor = openSync(messagePath, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    try {
      writeFileSync(descriptor, message, "utf8");
      fsyncSync(descriptor);
    } finally {
      closeSync(descriptor);
    }
    const child = spawn(process.execPath, [
      OPENCLAW,
      "agent",
      "--local",
      "--agent", "main",
      "--session-key", `agent:main:${sessionID}`,
      "--message-file", messagePath,
      "--thinking", "off",
      "--timeout", "90",
      "--json",
    ], {
      env: process.env,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout;
    let stderr;
    let stdoutOversized = false;
    let stderrOversized = false;
    boundedCapture(child.stdout, child, (value, oversized) => { stdout = value; stdoutOversized = oversized; });
    boundedCapture(child.stderr, child, (value, oversized) => { stderr = value; stderrOversized = oversized; });
    const timedOut = await new Promise((resolve, reject) => {
      let expired = false;
      const timer = setTimeout(() => {
        expired = true;
        child.kill("SIGKILL");
      }, RUN_TIMEOUT_MS);
      child.once("error", (error) => {
        clearTimeout(timer);
        reject(error);
      });
      child.once("close", (code, signal) => {
        clearTimeout(timer);
        resolve({ code, expired, signal });
      });
    });
    if (timedOut.expired) throw new Error("OpenClaw run timed out");
    if (stdoutOversized || stderrOversized) throw new Error("OpenClaw output exceeded 1 MiB");
    if (timedOut.code !== 0) {
      throw new Error(`OpenClaw exited with status ${timedOut.code ?? "unknown"}`);
    }
    const result = sanitizeOpenClawResult(
      JSON.parse((stdout ?? Buffer.alloc(0)).toString("utf8")),
      model,
    );
    const canonical = Buffer.from(canonicalJSON(result));
    if (canonical.length > MAX_RESULT_BYTES) throw new Error("OpenClaw result exceeded 1 MiB");
    record.result = result;
    record.result_sha256 = createHash("sha256").update(canonical).digest("hex");
    record.qualification = readQualifiedAudit();
    record.status = "completed";
  } catch (error) {
    record.error = error instanceof Error ? error.message.slice(0, 1024) : "OpenClaw run failed";
    record.status = "failed";
  } finally {
    activeRuns -= 1;
    try { unlinkSync(messagePath); } catch (error) {
      if (error?.code !== "ENOENT") process.stderr.write("openclaw-adapter: could not remove bounded message file\n");
    }
  }
}

function pruneRuns() {
  if (runs.size < MAX_RETAINED_RUNS) return;
  for (const [id, record] of runs) {
    if (record.status === "completed" || record.status === "failed") {
      runs.delete(id);
      return;
    }
  }
}

async function handle(request, response, model) {
  const url = new URL(request.url ?? "/", "http://adapter.invalid");
  if (request.method === "GET" && url.pathname === "/health") {
    sendJSON(response, 200, { status: "ok" });
    return;
  }
  if (request.method === "GET" && url.pathname === "/steward/v1/negotiation") {
    sendJSON(response, 200, {
      adapter: "openclaw",
      adapter_contract: "steward.openclaw.v1",
      capabilities: [{ fixture_id: "steward-workspace-audit", id: "skill" }, { fixture_id: "agent-turn", id: "task" }],
      native_protocols: ["http"],
      schema_version: "steward.adapter-negotiation.v1",
      task_protocol: "lifecycle-v1",
      upstream_revision: REVISION,
      model_alias: model,
    });
    return;
  }
  if (request.method === "POST" && url.pathname === "/v1/runs") {
    if (activeRuns + pendingRuns >= 1) {
      sendJSON(response, 429, { error: "capacity_exceeded", message: "one OpenClaw run is already active" });
      request.resume();
      return;
    }
    pruneRuns();
    if (runs.size >= MAX_RETAINED_RUNS) {
      sendJSON(response, 503, { error: "capacity_exceeded", message: "run history is full" });
      request.resume();
      return;
    }
    let document;
    pendingRuns += 1;
    try {
      document = JSON.parse((await readBody(request)).toString("utf8"));
    } catch (error) {
      const oversized = error instanceof Error && error.message === "request body exceeds 64 KiB";
      sendJSON(response, oversized ? 413 : 400, {
        error: oversized ? "request_too_large" : "invalid_request",
        message: error instanceof Error ? error.message : "invalid JSON",
      });
      return;
    } finally {
      pendingRuns -= 1;
    }
    const keys = document && typeof document === "object" && !Array.isArray(document) ? Object.keys(document).sort() : [];
    if (!(keys.length === 1 && keys[0] === "message" || keys.length === 2 && keys[0] === "message" && keys[1] === "session_id") ||
        typeof document.message !== "string" || document.message.length < 1 || Buffer.byteLength(document.message) > 32768 ||
        (document.session_id !== undefined && (typeof document.session_id !== "string" || !SESSION_PATTERN.test(document.session_id)))) {
      sendJSON(response, 400, { error: "invalid_request", message: "message or session_id is invalid" });
      return;
    }
    const runID = `run_${randomBytes(16).toString("hex")}`;
    const sessionID = document.session_id ?? runID.slice(4);
    const record = { run_id: runID, status: "queued" };
    runs.set(runID, record);
    void executeRun(record, document.message, sessionID, model);
    sendJSON(response, 202, record);
    return;
  }
  const match = url.pathname.match(/^\/v1\/runs\/(run_[a-f0-9]{32})$/);
  if (request.method === "GET" && match && RUN_PATTERN.test(match[1])) {
    const record = runs.get(match[1]);
    if (!record) {
      sendJSON(response, 404, { error: "not_found", message: "run was not found" });
      return;
    }
    sendJSON(response, 200, record);
    return;
  }
  sendJSON(response, 404, { error: "not_found", message: "route was not found" });
}

if (process.argv.length !== 3 || process.argv[2] !== "serve") {
  fail("the only supported command is serve");
}
const model = configure();
const server = createServer((request, response) => {
  void handle(request, response, model).catch(() => {
    if (!response.headersSent) sendJSON(response, 500, { error: "internal_error", message: "request failed" });
    else response.destroy();
  });
});
server.requestTimeout = 15_000;
server.headersTimeout = 10_000;
server.keepAliveTimeout = 5_000;
server.maxRequestsPerSocket = 100;
server.maxConnections = 32;
server.on("error", (error) => fail(`service listener failed: ${error.message}`));
server.listen(PORT, "0.0.0.0");

function shutdown() {
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(1), 10_000).unref();
}
process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);
