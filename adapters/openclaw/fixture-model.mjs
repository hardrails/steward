#!/usr/bin/env node
import http from "node:http";

const server = http.createServer((request, response) => {
  if (request.method === "GET" && request.url === "/v1/models") {
    const body = JSON.stringify({ data: [{ id: "steward-fixture-model", object: "model" }], object: "list" });
    response.writeHead(200, { "content-length": Buffer.byteLength(body), "content-type": "application/json" }); response.end(body); return;
  }
  if (request.method !== "POST" || request.url !== "/v1/chat/completions") { response.writeHead(404); response.end(); return; }
  let size = 0; const chunks = [];
  request.on("data", (chunk) => { size += chunk.length; if (size > 1048576) request.destroy(); else chunks.push(chunk); });
  request.on("end", () => {
    let input; try { input = JSON.parse(Buffer.concat(chunks).toString("utf8")); } catch { response.writeHead(400); response.end(); return; }
    const joined = JSON.stringify(input.messages ?? []);
    const nonce = joined.match(/STEWARD-TASK-([a-f0-9]{16,64})/)?.[1];
    if (!nonce) { response.writeHead(400); response.end(); return; }
    const body = JSON.stringify({ choices: [{ finish_reason: "stop", index: 0, message: { content: `STEWARD-TASK-${nonce}`, role: "assistant" } }], created: 0, id: "steward-fixture", model: "steward-fixture-model", object: "chat.completion", usage: { completion_tokens: 1, prompt_tokens: 1, total_tokens: 2 } });
    response.writeHead(200, { "content-length": Buffer.byteLength(body), "content-type": "application/json" }); response.end(body);
  });
});
server.listen(18080, "0.0.0.0");
