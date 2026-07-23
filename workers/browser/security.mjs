import { promises as dns } from "node:dns";
import { isIP } from "node:net";

export class DestinationError extends Error {
  constructor(status, code, message) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

function parseIPv4(value) {
  const parts = value.split(".").map(Number);
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return null;
  return parts;
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
    if (normalized.includes(".")) return false;
    const first = Number.parseInt(normalized.split(":")[0] || "0", 16);
    return first >= 0x2000 && first <= 0x3fff && !normalized.startsWith("2001:db8:");
  }
  return false;
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
