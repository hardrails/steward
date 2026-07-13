#!/usr/bin/env node
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { chmodSync, copyFileSync, existsSync, lstatSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import http from "node:http";
import net from "node:net";

const revision = "7197eef3ebeb5ac294da51ca073fff33277ed429";
const state = "/home/node/.openclaw";
const secretPath = "/home/node/.config/openclaw/gateway-token";
const model = process.env.OPENAI_MODEL ?? "steward-fixture-model";

function stop(message) {
  process.stderr.write(`openclaw-adapter: ${message}\n`);
  process.exit(1);
}
if (process.getuid() !== 65532 || process.getgid() !== 65532) stop("runtime identity must be 65532:65532");
if (!/^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/.test(model)) stop("OPENAI_MODEL is invalid");
if (process.env.OPENAI_BASE_URL !== "http://steward-model:18080/v1") stop("OPENAI_BASE_URL must be the fixed feasibility endpoint");
const secretStat = lstatSync(secretPath);
if (!secretStat.isFile() || secretStat.isSymbolicLink() || secretStat.size < 16 || secretStat.size > 4096) stop("gateway token handle is not a bounded regular file");
const token = readFileSync(secretPath, "utf8").trim();
if (token.length < 16 || token.length > 4096 || token.includes("\n")) stop("gateway token is invalid");

mkdirSync(`${state}/workspace/skills/fixture-sha256`, { recursive: true, mode: 0o700 });
for (const name of ["SKILL.md", "fixture-sha256.mjs"]) {
  const source = `/opt/steward/fixtures/${name}`;
  const target = `${state}/workspace/skills/fixture-sha256/${name}`;
  const bytes = readFileSync(source);
  if (existsSync(target)) {
    if (createHash("sha256").update(readFileSync(target)).digest("hex") !== createHash("sha256").update(bytes).digest("hex")) stop(`fixture drift: ${name}`);
  } else {
    copyFileSync(source, target);
    chmodSync(target, name.endsWith(".mjs") ? 0o500 : 0o400);
  }
}

const config = {
  agents: { defaults: { model: { primary: `steward/${model}` }, workspace: `${state}/workspace` } },
  gateway: { auth: { mode: "token" }, bind: "loopback", channelHealthCheckMinutes: 0, port: 18790 },
  mcp: { servers: { fixture_echo: { connectTimeout: 5, timeout: 10, toolFilter: { include: ["echo"] }, transport: "streamable-http", url: "http://steward-mcp:19090/mcp" } } },
  models: { mode: "replace", pricing: { enabled: false }, providers: { steward: { api: "openai-completions", apiKey: "steward-local", baseUrl: process.env.OPENAI_BASE_URL, models: [{ contextWindow: 8192, cost: { cacheRead: 0, cacheWrite: 0, input: 0, output: 0 }, id: model, input: ["text"], maxTokens: 1024, name: "Steward fixture model", reasoning: false }] } } },
  tools: { allow: ["exec", "fixture-echo__*"], exec: { ask: "off", host: "gateway", security: "full", timeoutSec: 10 } },
};
const configPath = "/tmp/openclaw.json";
writeFileSync(configPath, `${JSON.stringify(config)}\n`, { encoding: "utf8", flag: "wx", mode: 0o600 });

const negotiation = JSON.stringify({
  adapter: "openclaw", adapter_contract: "steward.openclaw.v1",
  capabilities: [{ fixture_id: "fixture_echo", id: "mcp" }, { fixture_id: "fixture.sha256", id: "skill" }, { fixture_id: "chat.send", id: "task" }],
  event_protocol: "openclaw.gateway.events.v4", native_protocols: ["http", "websocket"],
  schema_version: "steward.adapter-negotiation.v1", task_protocol: "openclaw.gateway.chat.v4", upstream_revision: revision,
});
const child = spawn("node", ["/app/openclaw.mjs", "gateway", "--port", "18790"], {
  cwd: `${state}/workspace`, env: { ...process.env, OPENCLAW_CONFIG_PATH: configPath, OPENCLAW_GATEWAY_TOKEN: token }, stdio: ["ignore", "inherit", "inherit"],
});

const server = http.createServer((request, response) => {
  if (request.method === "GET" && request.url === "/steward/v1/negotiation") {
    response.writeHead(200, { "content-length": Buffer.byteLength(negotiation), "content-type": "application/json" });
    response.end(negotiation);
    return;
  }
  const upstream = http.request({ headers: request.headers, host: "127.0.0.1", method: request.method, path: request.url, port: 18790 }, (upstreamResponse) => {
    response.writeHead(upstreamResponse.statusCode ?? 502, upstreamResponse.headers);
    upstreamResponse.pipe(response);
  });
  upstream.on("error", () => { if (!response.headersSent) response.writeHead(502); response.end(); });
  request.pipe(upstream);
});
server.on("upgrade", (request, socket, head) => {
  const upstream = net.connect(18790, "127.0.0.1", () => {
    let raw = `${request.method} ${request.url} HTTP/${request.httpVersion}\r\n`;
    for (let index = 0; index < request.rawHeaders.length; index += 2) raw += `${request.rawHeaders[index]}: ${request.rawHeaders[index + 1]}\r\n`;
    upstream.write(`${raw}\r\n`); if (head.length) upstream.write(head); socket.pipe(upstream).pipe(socket);
  });
  upstream.on("error", () => socket.destroy());
});
server.listen(18789, "0.0.0.0");

function shutdown() { server.close(); child.kill("SIGTERM"); }
process.on("SIGINT", shutdown); process.on("SIGTERM", shutdown);
child.on("exit", (code, signal) => { server.close(); process.exitCode = signal ? 1 : (code ?? 1); });
