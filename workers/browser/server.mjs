#!/usr/bin/env node

import { createServer } from "node:http";
import { constants as fsConstants, open } from "node:fs/promises";
import { isIP } from "node:net";
import { pathToFileURL } from "node:url";
import { chromium } from "playwright";
import {
  BoundaryError,
  DestinationError,
  SourceStore,
  publicTarget,
  readBoundedWebBody,
} from "./security.mjs";

const MAX_REQUEST = 64 << 10;
const MAX_RESPONSE = 1 << 20;
const MAX_TEXT = 256 << 10;
const MAX_SCREENSHOT = 512 << 10;
const MAX_SEARCH_RESPONSE = 4 << 20;
const UPSTREAM_TIMEOUT_MS = 30_000;
const PAGE_TIMEOUT_MS = 30_000;

class WorkerError extends Error {
  constructor(status, code, message) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

function boundedText(value, maximum) {
  if (typeof value !== "string") return "";
  const raw = Buffer.from(value, "utf8");
  return raw.length <= maximum ? value : raw.subarray(0, maximum).toString("utf8");
}

async function readSecret(path, label, required = true) {
  if (!path) {
    if (required) throw new Error(`${label} file is required`);
    return null;
  }
  const handle = await open(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  try {
    const before = await handle.stat();
    if (!before.isFile() || before.uid !== process.geteuid() || (before.mode & 0o077) !== 0 ||
        before.nlink !== 1 || before.size < 16 || before.size > 4096) {
      throw new Error(`${label} file is unsafe`);
    }
    const raw = Buffer.alloc(before.size);
    const { bytesRead } = await handle.read(raw, 0, raw.length, 0);
    const after = await handle.stat();
    if (bytesRead !== raw.length || before.dev !== after.dev || before.ino !== after.ino ||
        before.size !== after.size || before.mtimeMs !== after.mtimeMs || before.ctimeMs !== after.ctimeMs) {
      throw new Error(`${label} file changed while being read`);
    }
    const value = raw.toString("ascii").replace(/\n$/, "");
    if (Buffer.byteLength(value) < 16 || Buffer.byteLength(value) > 4096 || /[^\x21-\x7e]/.test(value)) {
      throw new Error(`${label} value is invalid`);
    }
    return value;
  } finally {
    await handle.close();
  }
}

function parseUpstream(value) {
  if (!value) throw new Error("STEWARD_SEARCH_BASE_URL is required");
  const upstream = new URL(value);
  const allowHTTP = process.env.STEWARD_ALLOW_INSECURE_UPSTREAM === "YES";
  if ((!allowHTTP && upstream.protocol !== "https:") ||
      (allowHTTP && !["http:", "https:"].includes(upstream.protocol)) ||
      upstream.username || upstream.password || upstream.search || upstream.hash) {
    throw new Error("search base URL must be a canonical HTTPS URL");
  }
  return upstream;
}

function exactObject(value, names) {
  return value && typeof value === "object" && !Array.isArray(value) &&
    Object.keys(value).sort().join("\0") === [...names].sort().join("\0");
}

async function search(payload, config, sources) {
  if (!exactObject(payload, ["query", "limit"]) || typeof payload.query !== "string" ||
      !Number.isInteger(payload.limit) || payload.query.trim() !== payload.query ||
      !payload.query || Buffer.byteLength(payload.query) > 2048 || payload.limit < 1 || payload.limit > 20) {
    throw new WorkerError(400, "invalid_request", "search requires a bounded query and limit from 1 to 20");
  }
  const upstream = new URL(config.searchBase);
  upstream.pathname = `${upstream.pathname.replace(/\/$/, "")}/search`;
  upstream.search = new URLSearchParams({ q: payload.query, format: "json" }).toString();
  const headers = { Accept: "application/json", "Accept-Encoding": "identity", "User-Agent": "steward-browser-worker/1" };
  if (config.searchToken) headers.Authorization = `Bearer ${config.searchToken}`;
  let response;
  try {
    response = await fetch(upstream, {
      method: "GET", headers, redirect: "error", signal: AbortSignal.timeout(UPSTREAM_TIMEOUT_MS),
    });
  } catch {
    throw new WorkerError(502, "search_unavailable", "search upstream is unavailable");
  }
  if (!response.ok) throw new WorkerError(502, "search_rejected", `search upstream returned HTTP ${response.status}`);
  const raw = await readBoundedWebBody(response, MAX_SEARCH_RESPONSE);
  let decoded;
  try {
    decoded = JSON.parse(raw);
  } catch {
    throw new WorkerError(502, "invalid_search_response", "search upstream returned invalid JSON");
  }
  if (!Array.isArray(decoded?.results)) throw new WorkerError(502, "invalid_search_response", "search response has no result list");
  const candidates = [];
  for (const item of decoded.results) {
    if (candidates.length >= payload.limit || !item || typeof item !== "object") continue;
    try {
      const target = await publicTarget(item.url);
      candidates.push({
        url: target.url,
        title: boundedText(item.title, 2048),
        snippet: boundedText(item.content, 8192),
        display_url: target.url,
      });
    } catch (error) {
      if (!(error instanceof DestinationError)) throw error;
    }
  }
  const sourceRefs = sources.putMany(candidates.map((candidate) => candidate.url));
  const results = candidates.map(({ url: _, ...candidate }, index) => ({
    source_ref: sourceRefs[index],
    ...candidate,
  }));
  return { schema_version: "steward.browser-search-result.v1", trust: "untrusted_web_content", results };
}

function sameOrigin(left, right) {
  return left.protocol === right.protocol && left.hostname === right.hostname && left.port === right.port;
}

async function renderOne(sourceRef, screenshot, sources) {
  if (typeof sourceRef !== "string" || !/^source_[a-f0-9]{32}$/.test(sourceRef)) {
    throw new WorkerError(400, "invalid_source_ref", "source reference is invalid");
  }
  const selected = await publicTarget(sources.get(sourceRef));
  const mappedAddress = selected.address.includes(":") ? `[${selected.address}]` : selected.address;
  const resolverRules = isIP(selected.target.hostname) ?
    [] : [`--host-resolver-rules=MAP ${selected.target.hostname} ${mappedAddress},EXCLUDE localhost`];
  const browser = await chromium.launch({
    headless: true,
    args: [
      ...resolverRules,
      "--disable-background-networking",
      "--disable-component-update",
      "--disable-domain-reliability",
      "--disable-features=OptimizationHints,MediaRouter",
      "--disable-sync",
      "--metrics-recording-only",
      "--no-first-run",
    ],
  });
  try {
    const context = await browser.newContext({
      acceptDownloads: false,
      bypassCSP: false,
      ignoreHTTPSErrors: false,
      javaScriptEnabled: true,
      locale: "en-US",
      permissions: [],
      serviceWorkers: "block",
      viewport: { width: 1280, height: 720 },
    });
    try {
      await context.route("**/*", async (route) => {
        const requestURL = new URL(route.request().url());
        if (["data:", "blob:"].includes(requestURL.protocol) || sameOrigin(requestURL, selected.target)) {
          await route.continue();
        } else {
          await route.abort("blockedbyclient");
        }
      });
      const page = await context.newPage();
      page.on("dialog", (dialog) => void dialog.dismiss());
      await page.goto(selected.url, { waitUntil: "domcontentloaded", timeout: PAGE_TIMEOUT_MS });
      await page.waitForTimeout(500);
      const title = boundedText(await page.title(), 2048);
      const content = boundedText(await page.locator("body").innerText({ timeout: 5000 }), MAX_TEXT);
      const result = {
        source_ref: sourceRef,
        url: selected.url,
        title,
        content,
        content_type: "text/plain",
      };
      if (screenshot) {
        const raw = await page.screenshot({ type: "png", fullPage: false, animations: "disabled", timeout: 5000 });
        if (raw.length <= MAX_SCREENSHOT) {
          result.screenshot_base64 = raw.toString("base64");
          result.screenshot_media_type = "image/png";
        } else {
          result.screenshot_omitted = "size_limit";
        }
      }
      return result;
    } finally {
      await context.close();
    }
  } catch (error) {
    if (error instanceof WorkerError || error instanceof DestinationError) throw error;
    throw new WorkerError(502, "browser_read_failed", "credential-free browser rendering failed");
  } finally {
    await browser.close();
  }
}

async function read(payload, sources) {
  if (!exactObject(payload, ["source_refs", "screenshot"]) || !Array.isArray(payload.source_refs) ||
      payload.source_refs.length < 1 || payload.source_refs.length > 5 || typeof payload.screenshot !== "boolean") {
    throw new WorkerError(400, "invalid_request", "read requires one to five source_refs and an explicit screenshot boolean");
  }
  const pages = [];
  for (const sourceRef of payload.source_refs) pages.push(await renderOne(sourceRef, payload.screenshot, sources));
  return { schema_version: "steward.browser-read-result.v1", trust: "untrusted_web_content", pages };
}

async function readBody(request) {
  if (request.headers["transfer-encoding"] !== undefined) {
    throw new WorkerError(400, "invalid_request", "transfer encoding is not accepted");
  }
  const values = request.headers["content-length"];
  if (typeof values !== "string" || !/^[0-9]{1,5}$/.test(values)) {
    throw new WorkerError(411, "content_length_required", "one canonical Content-Length is required");
  }
  const length = Number(values);
  if (length < 1 || length > MAX_REQUEST) throw new WorkerError(413, "request_too_large", "request exceeds 64 KiB");
  const chunks = [];
  let received = 0;
  for await (const chunk of request) {
    received += chunk.length;
    if (received > length) throw new WorkerError(400, "invalid_request", "request body exceeds Content-Length");
    chunks.push(chunk);
  }
  if (received !== length) throw new WorkerError(400, "incomplete_request", "request body is incomplete");
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    throw new WorkerError(400, "invalid_json", "request body is not valid JSON");
  }
}

function writeJSON(response, status, value) {
  let raw = Buffer.from(JSON.stringify(value));
  if (raw.length > MAX_RESPONSE) {
    status = 502;
    raw = Buffer.from('{"error":"response_too_large","message":"normalized browser result exceeded 1 MiB"}');
  }
  response.writeHead(status, {
    "Cache-Control": "no-store",
    "Content-Length": raw.length,
    "Content-Type": "application/json",
    "X-Content-Type-Options": "nosniff",
  });
  response.end(raw);
}

export async function loadConfig() {
  const listen = process.env.STEWARD_BROWSER_LISTEN || "0.0.0.0:8080";
  const separator = listen.lastIndexOf(":");
  const port = Number(listen.slice(separator + 1));
  if (separator < 1 || !Number.isInteger(port) || port < 1 || port > 65535) throw new Error("browser listen address is invalid");
  return {
    host: listen.slice(0, separator),
    port,
    workerToken: await readSecret(process.env.STEWARD_WORKER_TOKEN_FILE || "", "worker credential"),
    searchToken: await readSecret(process.env.STEWARD_SEARCH_TOKEN_FILE || "", "search credential", false),
    searchBase: parseUpstream(process.env.STEWARD_SEARCH_BASE_URL || "").toString(),
  };
}

export function createBrowserServer(config, sources = new SourceStore()) {
  let active = 0;
  return createServer(async (request, response) => {
    try {
      if (request.method !== "POST") throw new WorkerError(405, "method_not_allowed", "only POST is accepted");
      const authorization = request.headers.authorization;
      if (authorization !== `Bearer ${config.workerToken}`) throw new WorkerError(401, "unauthorized", "worker credential is invalid");
      if (active >= 2) throw new WorkerError(503, "worker_busy", "browser worker concurrency is exhausted");
      active++;
      try {
        const payload = await readBody(request);
        if (request.url === "/v1/search") writeJSON(response, 200, await search(payload, config, sources));
        else if (request.url === "/v1/read") writeJSON(response, 200, await read(payload, sources));
        else throw new WorkerError(404, "route_not_found", "route is not available");
      } finally {
        active--;
      }
    } catch (error) {
      const safe = error instanceof WorkerError || error instanceof BoundaryError ?
        error : new WorkerError(500, "internal_error", "browser worker failed safely");
      writeJSON(response, safe.status, { error: safe.code, message: safe.message });
    }
  });
}

async function main() {
  const config = await loadConfig();
  const server = createBrowserServer(config);
  server.listen(config.port, config.host, () => {
    process.stdout.write(`steward browser worker listening on ${config.host}:${config.port}\n`);
  });
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    process.stderr.write(`steward-browser-worker: ${error.message}\n`);
    process.exitCode = 1;
  });
}
