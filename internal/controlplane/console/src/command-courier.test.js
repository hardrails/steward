import assert from "node:assert/strict";
import {createHash} from "node:crypto";
import test from "node:test";

import {
  COMMAND_REVIEW_WINDOW_MILLISECONDS,
  EXECUTOR_COMMAND_PAYLOAD_TYPE,
  MAX_COMMAND_FILE_BYTES,
  commandConfirmation,
  commandReviewCurrent,
  decodeSignedCommand,
} from "./command-courier.js";

const encoder = new TextEncoder();

function fixture(overrides = {}) {
  const statement = {
    schema_version: "steward.executor-command.v2",
    command_id: "command-17",
    tenant_id: "tenant-a",
    node_id: "node-a",
    instance_id: "agent-a",
    runtime_ref: "runtime-a",
    kind: "start",
    claim_generation: 2,
    instance_generation: 3,
    command_sequence: 4,
    issued_at: "2030-01-01T00:00:00Z",
    expires_at: "2030-01-01T00:10:00Z",
    payload: {acknowledge: true},
    ...overrides,
  };
  const payload = Buffer.from(JSON.stringify(statement)).toString("base64");
  return encoder.encode(JSON.stringify({
    payloadType: EXECUTOR_COMMAND_PAYLOAD_TYPE,
    payload,
    signatures: [{keyid: "operator-a", sig: Buffer.alloc(64, 7).toString("base64")}],
  }));
}

test("decodes an unverified preview while preserving the exact envelope bytes", async () => {
  const raw = fixture();
  const preview = await decodeSignedCommand(raw, Date.parse("2029-12-31T23:59:00Z"));
  assert.equal(preview.statement.command_id, "command-17");
  assert.equal(preview.statement.tenant_id, "tenant-a");
  assert.deepEqual(preview.keyIDs, ["operator-a"]);
  assert.equal(preview.byteLength, raw.length);
  assert.equal(Buffer.from(preview.envelopeBase64, "base64").compare(Buffer.from(raw)), 0);
  assert.equal(preview.digest, "sha256:" + createHash("sha256").update(raw).digest("hex"));
  assert.equal(commandConfirmation(preview.statement.command_id), "SUBMIT command-17");
  assert.equal(commandReviewCurrent(preview, Date.parse("2030-01-01T00:00:00Z")), true);
});

test("expires the local review independently of the signed command", async () => {
  const loadedAt = Date.parse("2029-12-31T23:59:00Z");
  const preview = await decodeSignedCommand(fixture(), loadedAt);
  assert.equal(commandReviewCurrent(preview, loadedAt + COMMAND_REVIEW_WINDOW_MILLISECONDS - 1), true);
  assert.equal(commandReviewCurrent(preview, loadedAt + COMMAND_REVIEW_WINDOW_MILLISECONDS), false);
  assert.equal(commandReviewCurrent(preview, Date.parse("2030-01-01T00:10:00Z")), false);
});

test("rejects malformed, oversized, and noncanonical envelopes", async () => {
  await assert.rejects(decodeSignedCommand(new Uint8Array()), /no larger than 750 KiB/u);
  await assert.rejects(decodeSignedCommand(new Uint8Array(MAX_COMMAND_FILE_BYTES + 1)), /no larger/u);
  await assert.rejects(decodeSignedCommand(Uint8Array.of(0xff)), /valid UTF-8/u);
  await assert.rejects(decodeSignedCommand(encoder.encode("[]")), /DSSE envelope/u);

  const parsed = JSON.parse(new TextDecoder().decode(fixture()));
  parsed.payload += "\n";
  await assert.rejects(decodeSignedCommand(encoder.encode(JSON.stringify(parsed))), /canonical standard Base64/u);

  parsed.payload = Buffer.from(JSON.stringify({...JSON.parse(Buffer.from(parsed.payload.trim(), "base64")), kind: "shell"})).toString("base64");
  await assert.rejects(decodeSignedCommand(encoder.encode(JSON.stringify(parsed))), /unsupported operation/u);
});

test("rejects duplicate signature identities and unsafe command fields", async () => {
  const parsed = JSON.parse(new TextDecoder().decode(fixture()));
  parsed.signatures = [
    {keyid: "operator-a", sig: Buffer.alloc(64, 1).toString("base64")},
    {keyid: "operator-a", sig: Buffer.alloc(64, 2).toString("base64")},
  ];
  await assert.rejects(decodeSignedCommand(encoder.encode(JSON.stringify(parsed))), /must be unique/u);
  await assert.rejects(decodeSignedCommand(fixture({tenant_id: "  "})), /invalid tenant_id/u);
  await assert.rejects(decodeSignedCommand(fixture({command_sequence: 0})), /invalid command_sequence/u);
  await assert.rejects(decodeSignedCommand(fixture({expires_at: "2030-01-01T00:20:00Z"})), /validity window/u);
});
