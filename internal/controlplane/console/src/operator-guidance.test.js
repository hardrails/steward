import assert from "node:assert/strict";
import test from "node:test";

import {attentionCommand, attentionGuidance} from "./operator-guidance.js";

test("builds copyable diagnostic commands only from bounded identities", () => {
  assert.equal(attentionCommand({node_id: "node-a"}), "stewardctl explain node-a");
  assert.equal(attentionCommand({command_id: "command-17"}), "stewardctl explain command-17");
  assert.equal(attentionCommand({node_id: "node-a; rm -rf /"}), "stewardctl explain");
  assert.equal(attentionCommand({}), "stewardctl explain");
});

test("uses server guidance and keeps a bounded compatibility fallback", () => {
  assert.deepEqual(attentionGuidance({
    reason: "node_stale",
    title: "Node report is stale",
    explanation: "The node stopped reporting.",
    impact: "Placement is blocked.",
    next_step: "Run the node doctor.",
  }), {
    title: "Node report is stale",
    explanation: "The node stopped reporting.",
    impact: "Placement is blocked.",
    nextStep: "Run the node doctor.",
  });
  assert.equal(attentionGuidance({reason: "node_stale"}).title, "node stale");
});
