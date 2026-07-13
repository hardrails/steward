#!/usr/bin/env node
import http from "node:http";

const server = http.createServer((request, response) => {
  if (request.method !== "POST" || request.url !== "/mcp") { response.writeHead(404); response.end(); return; }
  let size = 0; const chunks = [];
  request.on("data", (chunk) => { size += chunk.length; if (size > 65536) request.destroy(); else chunks.push(chunk); });
  request.on("end", () => {
    let message; try { message = JSON.parse(Buffer.concat(chunks).toString("utf8")); } catch { response.writeHead(400); response.end(); return; }
    if (!message.id) { response.writeHead(202); response.end(); return; }
    let result;
    if (message.method === "initialize") result = { capabilities: { tools: {} }, protocolVersion: message.params?.protocolVersion ?? "2025-11-25", serverInfo: { name: "fixture_echo", version: "1" } };
    else if (message.method === "tools/list") result = { tools: [{ description: "Return a fixed hexadecimal nonce", inputSchema: { additionalProperties: false, properties: { nonce: { pattern: "^[a-f0-9]{16,64}$", type: "string" } }, required: ["nonce"], type: "object" }, name: "echo" }] };
    else if (message.method === "tools/call" && message.params?.name === "echo" && /^[a-f0-9]{16,64}$/.test(message.params?.arguments?.nonce ?? "")) result = { content: [{ text: message.params.arguments.nonce, type: "text" }] };
    else { response.writeHead(400); response.end(); return; }
    const body = JSON.stringify({ id: message.id, jsonrpc: "2.0", result });
    response.writeHead(200, { "content-length": Buffer.byteLength(body), "content-type": "application/json" }); response.end(body);
  });
});
server.listen(19090, "0.0.0.0");
