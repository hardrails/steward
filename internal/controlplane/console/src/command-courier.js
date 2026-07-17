export const EXECUTOR_COMMAND_PAYLOAD_TYPE = "application/vnd.steward.executor-command.v2+json";
export const EXECUTOR_COMMAND_SCHEMA = "steward.executor-command.v2";
export const MAX_COMMAND_FILE_BYTES = 750 * 1024;
export const COMMAND_REVIEW_WINDOW_MILLISECONDS = 5 * 60 * 1000;

const MAX_PAYLOAD_BYTES = 512 * 1024;
const MAX_SIGNATURES = 16;
const commandKinds = new Set(["admit", "start", "stop", "destroy", "read", "purge", "activation-canary"]);

function plainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function boundedString(value, maximum) {
  return typeof value === "string" && value.trim() !== "" && value.length <= maximum && !value.includes("\0");
}

function positiveInteger(value) {
  return Number.isSafeInteger(value) && value > 0;
}

function decodeCanonicalBase64(value, label, maximumBytes) {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(label + " must be canonical standard Base64.");
  }
  let binary;
  try {
    binary = atob(value);
  } catch {
    throw new Error(label + " must be canonical standard Base64.");
  }
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  if (bytes.length > maximumBytes || encodeBase64(bytes) !== value) {
    throw new Error(label + " must be canonical standard Base64 within its size limit.");
  }
  return bytes;
}

function decodeJSON(bytes, label) {
  let text;
  try {
    text = new TextDecoder("utf-8", {fatal: true}).decode(bytes);
  } catch {
    throw new Error(label + " must be valid UTF-8 JSON.");
  }
  try {
    return JSON.parse(text);
  } catch {
    throw new Error(label + " must be valid JSON.");
  }
}

function encodeBase64(bytes) {
  const chunkSize = 0x8000;
  let binary = "";
  for (let offset = 0; offset < bytes.length; offset += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + chunkSize));
  }
  return btoa(binary);
}

function validateSignature(signature, seenKeyIDs) {
  if (!plainObject(signature) || !boundedString(signature.keyid, 256) || typeof signature.sig !== "string") {
    throw new Error("Every DSSE signature must contain one bounded key ID and signature.");
  }
  if (seenKeyIDs.has(signature.keyid)) {
    throw new Error("DSSE signature key IDs must be unique.");
  }
  seenKeyIDs.add(signature.keyid);
  const decoded = decodeCanonicalBase64(signature.sig, "DSSE signature", 64);
  if (decoded.length !== 64) {
    throw new Error("Every DSSE signature must be one Ed25519 signature.");
  }
}

function validateStatement(statement) {
  if (!plainObject(statement) || statement.schema_version !== EXECUTOR_COMMAND_SCHEMA) {
    throw new Error("The DSSE payload must contain one Executor command v2 statement.");
  }
  for (const [field, maximum] of [
    ["command_id", 256], ["tenant_id", 128], ["node_id", 128],
    ["instance_id", 256], ["runtime_ref", 1024],
  ]) {
    if (!boundedString(statement[field], maximum)) {
      throw new Error("The signed command has an invalid " + field + ".");
    }
  }
  if (!commandKinds.has(statement.kind)) {
    throw new Error("The signed command names an unsupported operation.");
  }
  for (const field of ["claim_generation", "instance_generation", "command_sequence"]) {
    if (!positiveInteger(statement[field])) {
      throw new Error("The signed command has an invalid " + field + ".");
    }
  }
  if (!boundedString(statement.issued_at, 64) || !boundedString(statement.expires_at, 64)) {
    throw new Error("The signed command must contain bounded issue and expiry times.");
  }
  const issuedAt = Date.parse(statement.issued_at);
  const expiresAt = Date.parse(statement.expires_at);
  if (!Number.isFinite(issuedAt) || !Number.isFinite(expiresAt) || expiresAt <= issuedAt || expiresAt - issuedAt > 15 * 60 * 1000) {
    throw new Error("The signed command has an invalid validity window.");
  }
  if (!("payload" in statement)) {
    throw new Error("The signed command payload is missing.");
  }
}

export function commandConfirmation(commandID) {
  return "SUBMIT " + commandID;
}

export function commandReviewCurrent(preview, now = Date.now()) {
  return Boolean(preview) && now - preview.loadedAt < COMMAND_REVIEW_WINDOW_MILLISECONDS &&
    Date.parse(preview.statement.expires_at) > now;
}

export async function decodeSignedCommand(input, now = Date.now()) {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
  if (bytes.length === 0 || bytes.length > MAX_COMMAND_FILE_BYTES) {
    throw new Error("Choose one signed command file no larger than 750 KiB.");
  }
  const envelope = decodeJSON(bytes, "The signed command file");
  if (!plainObject(envelope) || envelope.payloadType !== EXECUTOR_COMMAND_PAYLOAD_TYPE ||
      typeof envelope.payload !== "string" || !Array.isArray(envelope.signatures) ||
      envelope.signatures.length === 0 || envelope.signatures.length > MAX_SIGNATURES) {
    throw new Error("The file must contain one bounded Executor command DSSE envelope.");
  }
  const seenKeyIDs = new Set();
  for (const signature of envelope.signatures) {
    validateSignature(signature, seenKeyIDs);
  }
  const payloadBytes = decodeCanonicalBase64(envelope.payload, "The DSSE payload", MAX_PAYLOAD_BYTES);
  const statement = decodeJSON(payloadBytes, "The DSSE payload");
  validateStatement(statement);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  return {
    loadedAt: now,
    byteLength: bytes.length,
    envelopeBase64: encodeBase64(bytes),
    digest: "sha256:" + Array.from(digest, (value) => value.toString(16).padStart(2, "0")).join(""),
    keyIDs: envelope.signatures.map((signature) => signature.keyid),
    statement,
  };
}
