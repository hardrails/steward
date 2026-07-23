import { randomUUID } from "node:crypto";
import { promises as dns } from "node:dns";
import { isIP } from "node:net";

const DEFAULT_MAX_REFS = 512;
const DEFAULT_REF_TTL_MS = 15 * 60 * 1000;

export class BoundaryError extends Error {
  constructor(status, code, message) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

export class DestinationError extends BoundaryError {}

function parseIPv4(value) {
  const parts = value.split(".").map(Number);
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return null;
  return parts;
}

function parseIPv6(value) {
  if (value.includes(".")) return null;
  const halves = value.toLowerCase().split("::");
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(":") : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  if (left.concat(right).some((word) => !/^[0-9a-f]{1,4}$/.test(word))) return null;
  const missing = 8 - left.length - right.length;
  if ((halves.length === 1 && missing !== 0) || (halves.length === 2 && missing < 1)) return null;
  const words = [...left, ...Array(missing).fill("0"), ...right];
  if (words.length !== 8) return null;
  return words.reduce((result, word) => (result << 16n) | BigInt(`0x${word}`), 0n);
}

function ipv6Prefix(value, prefix, bits) {
  const address = parseIPv6(value);
  const network = parseIPv6(prefix);
  if (address === null || network === null) return false;
  const shift = BigInt(128 - bits);
  return address >> shift === network >> shift;
}

export function isPublicAddress(value) {
  const family = isIP(value);
  if (family === 4) {
    const parts = parseIPv4(value);
    if (!parts) return false;
    const [a, b, c] = parts;
    return !(
      a === 0 || a === 10 || a === 127 || a >= 224 ||
      a === 100 && b >= 64 && b <= 127 ||
      a === 169 && b === 254 ||
      a === 172 && b >= 16 && b <= 31 ||
      a === 192 && b === 0 ||
      a === 192 && b === 168 ||
      a === 198 && (b === 18 || b === 19) ||
      a === 198 && b === 51 && c === 100 ||
      a === 203 && b === 0 && c === 113
    );
  }
  if (family === 6) {
    const normalized = value.toLowerCase();
    if (!ipv6Prefix(normalized, "2000::", 3)) return false;
    // IANA special-purpose ranges that sit inside 2000::/3 are not safe
    // internet destinations. This deliberately fails closed for the entire
    // 2001:0000::/23 protocol-assignment block.
    return ![
      ["2001::", 23],
      ["2001:db8::", 32],
      ["2002::", 16],
      ["3fff::", 20],
    ].some(([prefix, bits]) => ipv6Prefix(normalized, prefix, bits));
  }
  return false;
}

export class SourceStore {
  constructor(now = () => Date.now(), maximum = DEFAULT_MAX_REFS, ttlMilliseconds = DEFAULT_REF_TTL_MS) {
    if (!Number.isSafeInteger(maximum) || maximum < 1 ||
        !Number.isSafeInteger(ttlMilliseconds) || ttlMilliseconds < 1) {
      throw new TypeError("source store limits are invalid");
    }
    this.now = now;
    this.maximum = maximum;
    this.ttlMilliseconds = ttlMilliseconds;
    this.values = new Map();
  }

  putMany(urls) {
    this.prune();
    if (!Array.isArray(urls) || urls.some((url) => typeof url !== "string")) {
      throw new TypeError("source URLs are invalid");
    }
    if (urls.length > this.maximum - this.values.size) {
      throw new BoundaryError(
        503,
        "source_capacity_exhausted",
        "source reference capacity is exhausted; retry after existing references expire",
      );
    }
    const createdAt = this.now();
    const ids = [];
    for (const url of urls) {
      let id;
      do {
        id = `source_${randomUUID().replaceAll("-", "")}`;
      } while (this.values.has(id));
      this.values.set(id, { url, createdAt });
      ids.push(id);
    }
    return ids;
  }

  get(id) {
    this.prune();
    const value = this.values.get(id);
    if (!value) throw new BoundaryError(404, "source_ref_not_found", "source reference is missing or expired");
    return value.url;
  }

  prune() {
    const cutoff = this.now() - this.ttlMilliseconds;
    for (const [id, value] of this.values) {
      if (value.createdAt >= cutoff) break;
      this.values.delete(id);
    }
  }
}

export async function readBoundedWebBody(response, maximum) {
  if (!Number.isSafeInteger(maximum) || maximum < 1) throw new TypeError("response limit is invalid");
  const contentLength = response.headers?.get?.("content-length");
  if (contentLength !== null && contentLength !== undefined &&
      (!/^[0-9]+$/.test(contentLength) || Number(contentLength) > maximum)) {
    throw new BoundaryError(502, "search_response_too_large", "search upstream exceeded 4 MiB");
  }
  const reader = response.body?.getReader?.();
  if (!reader) throw new BoundaryError(502, "invalid_search_response", "search upstream returned no response body");
  const chunks = [];
  let received = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      received += value.byteLength;
      if (received > maximum) {
        await reader.cancel();
        throw new BoundaryError(502, "search_response_too_large", "search upstream exceeded 4 MiB");
      }
      chunks.push(Buffer.from(value));
    }
  } finally {
    reader.releaseLock();
  }
  return Buffer.concat(chunks, received);
}

export async function publicTarget(value, lookup = dns.lookup) {
  if (typeof value !== "string" || Buffer.byteLength(value) > 2048) {
    throw new DestinationError(400, "invalid_source", "source URL is invalid");
  }
  let target;
  try {
    target = new URL(value);
  } catch {
    throw new DestinationError(400, "invalid_source", "source URL must be absolute");
  }
  if (!["http:", "https:"].includes(target.protocol) || target.username || target.password || target.hash) {
    throw new DestinationError(400, "invalid_source", "source URL must be HTTP(S) without credentials or a fragment");
  }
  const host = target.hostname.replace(/\.$/, "").toLowerCase();
  if (!host || host === "localhost" || host.endsWith(".localhost") || host.endsWith(".local") || host.endsWith(".internal")) {
    throw new DestinationError(400, "private_source_denied", "private and local source names are denied");
  }
  let records;
  try {
    records = isIP(host) ? [{ address: host, family: isIP(host) }] : await lookup(host, { all: true, verbatim: true });
  } catch {
    throw new DestinationError(400, "source_unresolvable", "source hostname could not be resolved");
  }
  const addresses = [...new Set(records.map((record) => record.address))].sort();
  if (addresses.length === 0 || addresses.some((address) => !isPublicAddress(address))) {
    throw new DestinationError(400, "private_source_denied", "source hostname resolved to a non-public address");
  }
  target.hostname = host;
  return { url: target.toString(), target, address: addresses[0] };
}
