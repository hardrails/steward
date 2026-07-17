#!/usr/bin/env node

import { createServer } from "node:http";

const portText = process.env.STEWARD_FIXTURE_MODEL_PORT ?? "8080";
if (!(portText === "0" || /^[1-9][0-9]{0,4}$/.test(portText)) || Number(portText) > 65535) {
  throw new Error("STEWARD_FIXTURE_MODEL_PORT is invalid");
}
const PORT = Number(portText);
const MAX_BODY = 1 << 20;
const MODEL = "steward-openclaw-fixture";
const COMMAND = "node /home/node/.openclaw/workspace/skills/steward-workspace-audit/workspace_audit.mjs";

function readBody(request) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    let oversized = false;
    request.on("data", (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY) {
        oversized = true;
        return;
      }
      if (!oversized) chunks.push(chunk);
    });
    request.on("end", () => {
      if (oversized) reject(new Error("oversized model request"));
      else resolve(Buffer.concat(chunks));
    });
    request.on("error", reject);
  });
}

function normalResponse(toolResult) {
  const message = toolResult
    ? { role: "assistant", content: "STEWARD_OPENCLAW_WORKSPACE_AUDIT_OK" }
    : {
        role: "assistant",
        content: null,
        tool_calls: [{
          id: "call_steward_workspace_audit",
          type: "function",
          function: { name: "exec", arguments: JSON.stringify({ command: COMMAND }) },
        }],
      };
  return {
    id: "chatcmpl-steward-openclaw",
    object: "chat.completion",
    created: 1,
    model: MODEL,
    choices: [{ index: 0, message, finish_reason: toolResult ? "stop" : "tool_calls" }],
    usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 },
  };
}

function streamResponse(response, toolResult) {
  response.writeHead(200, {
    "cache-control": "no-store",
    "content-type": "text/event-stream",
  });
  const base = { id: "chatcmpl-steward-openclaw", object: "chat.completion.chunk", created: 1, model: MODEL };
  const delta = toolResult
    ? { role: "assistant", content: "STEWARD_OPENCLAW_WORKSPACE_AUDIT_OK" }
    : {
        role: "assistant",
        tool_calls: [{
          index: 0,
          id: "call_steward_workspace_audit",
          type: "function",
          function: { name: "exec", arguments: JSON.stringify({ command: COMMAND }) },
        }],
      };
  response.write(`data: ${JSON.stringify({ ...base, choices: [{ index: 0, delta, finish_reason: null }] })}\n\n`);
  response.write(`data: ${JSON.stringify({ ...base, choices: [{ index: 0, delta: {}, finish_reason: toolResult ? "stop" : "tool_calls" }] })}\n\n`);
  response.end("data: [DONE]\n\n");
}

const server = createServer(async (request, response) => {
  if (request.method === "GET" && request.url === "/health") {
    response.writeHead(200, { "content-type": "application/json" });
    response.end('{"status":"ok"}\n');
    return;
  }
  if (request.method !== "POST" || request.url !== "/v1/chat/completions" || request.headers.authorization !== "Bearer steward-local") {
    response.writeHead(404, { "content-type": "application/json" });
    response.end('{"error":{"message":"not found","type":"invalid_request_error"}}\n');
    return;
  }
  try {
    const document = JSON.parse((await readBody(request)).toString("utf8"));
    if (document.model !== MODEL || !Array.isArray(document.messages) ||
        !Array.isArray(document.tools) || !document.tools.some((tool) => tool?.function?.name === "exec")) {
      throw new Error("unexpected model contract");
    }
    const toolMessages = document.messages.filter((message) => message?.role === "tool");
    const toolResult = toolMessages.length > 0;
    if (toolResult && !toolMessages.some((message) => String(message.content).includes("steward.workspace-audit.result.v1"))) {
      throw new Error("workspace audit result was not returned to the model");
    }
    if (document.stream === true) {
      streamResponse(response, toolResult);
      return;
    }
    const encoded = Buffer.from(`${JSON.stringify(normalResponse(toolResult))}\n`);
    response.writeHead(200, {
      "content-length": String(encoded.length),
      "content-type": "application/json",
    });
    response.end(encoded);
  } catch (error) {
    const encoded = Buffer.from(`${JSON.stringify({ error: { message: error.message, type: "invalid_request_error" } })}\n`);
    response.writeHead(400, { "content-length": String(encoded.length), "content-type": "application/json" });
    response.end(encoded);
  }
});
server.requestTimeout = 15_000;
server.headersTimeout = 10_000;
server.keepAliveTimeout = 5_000;
server.listen(PORT, "0.0.0.0", () => {
  if (PORT !== 0) return;
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("fixture model did not bind TCP");
  process.stdout.write(`${JSON.stringify({ port: address.port })}\n`);
});
