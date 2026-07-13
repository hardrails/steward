#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";

const nonce = process.argv[2] ?? "";
if (!/^[a-f0-9]{16,64}$/.test(nonce)) throw new Error("invalid nonce");
const token = readFileSync("/home/node/.config/openclaw/gateway-token", "utf8").trim();
const digest = (value) => createHash("sha256").update(typeof value === "string" ? value : JSON.stringify(value)).digest("hex");

async function connect(authToken) {
  const socket = new WebSocket("ws://127.0.0.1:18789");
  const messages = [];
  socket.addEventListener("message", (event) => { try { messages.push(JSON.parse(String(event.data))); } catch {} });
  await new Promise((resolve, reject) => { socket.addEventListener("open", resolve, { once: true }); socket.addEventListener("error", reject, { once: true }); });
  const deadline = Date.now() + 10000;
  while (!messages.some((item) => item.type === "event" && item.event === "connect.challenge")) { if (Date.now() > deadline) throw new Error("challenge timeout"); await new Promise((resolve) => setTimeout(resolve, 25)); }
  const id = randomUUID();
  socket.send(JSON.stringify({ id, method: "connect", params: { auth: { token: authToken }, caps: [], client: { id: "gateway-client", mode: "backend", platform: "linux", version: "steward-feasibility-1" }, commands: [], maxProtocol: 4, minProtocol: 4, permissions: {}, role: "operator", scopes: ["operator.read", "operator.write"] }, type: "req" }));
  while (!messages.some((item) => item.type === "res" && item.id === id)) { if (Date.now() > deadline) throw new Error("connect timeout"); await new Promise((resolve) => setTimeout(resolve, 25)); }
  return { messages, socket, response: messages.find((item) => item.type === "res" && item.id === id) };
}
async function rpc(connection, method, params) {
  const id = randomUUID(); connection.socket.send(JSON.stringify({ id, method, params, type: "req" }));
  const deadline = Date.now() + 30000;
  while (!connection.messages.some((item) => item.type === "res" && item.id === id)) { if (Date.now() > deadline) throw new Error(`${method} timeout`); await new Promise((resolve) => setTimeout(resolve, 25)); }
  const response = connection.messages.find((item) => item.type === "res" && item.id === id);
  if (!response.ok) throw new Error(`${method} rejected`); return response.payload;
}

const negotiationResponse = await fetch("http://127.0.0.1:18789/steward/v1/negotiation");
const negotiation = await negotiationResponse.json();
const denied = await connect(`${token}-wrong`);
if (denied.response?.ok !== false) throw new Error("unauthorized connect was not denied"); denied.socket.close();
const connection = await connect(token);
if (connection.response?.ok !== true || connection.response?.payload?.type !== "hello-ok") throw new Error("authorized connect failed");
const health = await rpc(connection, "health", {});
const idempotencyKey = `steward-${nonce}`;
const first = await rpc(connection, "chat.send", { idempotencyKey, message: `Reply with exactly STEWARD-TASK-${nonce}`, sessionKey: "main" });
if (typeof first?.runId !== "string") throw new Error("task did not start");
const terminal = await rpc(connection, "agent.wait", { runId: first.runId, timeoutMs: 20000 });
if (terminal?.status !== "ok") throw new Error("task did not complete");
const replay = await rpc(connection, "chat.send", { idempotencyKey, message: `Reply with exactly STEWARD-TASK-${nonce}`, sessionKey: "main" });
const history = await rpc(connection, "chat.history", { limit: 16, sessionKey: "main" });
if (!JSON.stringify(history).includes(`STEWARD-TASK-${nonce}`)) throw new Error("task result marker missing");
connection.socket.close();
const skillDigest = execFileSync("node", ["/opt/steward/fixtures/fixture-sha256.mjs", nonce], { encoding: "utf8", timeout: 5000 }).trim();
const mcpInit = await fetch("http://steward-mcp:19090/mcp", { body: JSON.stringify({ id: 1, jsonrpc: "2.0", method: "initialize", params: { capabilities: {}, clientInfo: { name: "steward-feasibility", version: "1" }, protocolVersion: "2025-11-25" } }), headers: { "content-type": "application/json" }, method: "POST" });
if (!mcpInit.ok) throw new Error("MCP initialize failed");
const mcpCall = await fetch("http://steward-mcp:19090/mcp", { body: JSON.stringify({ id: 2, jsonrpc: "2.0", method: "tools/call", params: { arguments: { nonce }, name: "echo" } }), headers: { "content-type": "application/json" }, method: "POST" });
const mcpResult = await mcpCall.json();
if (!JSON.stringify(mcpResult).includes(nonce)) throw new Error("MCP echo mismatch");
process.stdout.write(`${JSON.stringify({ authenticated_connect: true, challenge: true, health_digest: digest(health), idempotent_replay: replay?.runId === first.runId || replay?.status === "ok", mcp_fixture: true, negotiation_digest: digest(negotiation), result_digest: digest(history), skill_digest: skillDigest, task_terminal: true, unauthorized_denied: true })}\n`);
