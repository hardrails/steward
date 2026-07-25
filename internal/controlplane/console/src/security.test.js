import assert from "node:assert/strict";
import {readFile} from "node:fs/promises";
import test from "node:test";

test("the React console keeps credentials ephemeral and routes mutations through an explicit allowlist", async () => {
  const source = await readFile(new URL("./App.jsx", import.meta.url), "utf8");
  for (const forbidden of [
    "localStorage",
    "sessionStorage",
    "document.cookie",
    "dangerouslySetInnerHTML",
    "innerHTML",
    "outerHTML",
    "insertAdjacentHTML",
    "window.open",
    "crypto.subtle.sign",
    "crypto.subtle.generateKey",
    "privateKey",
  ]) {
    assert.equal(source.includes(forbidden), false, `forbidden browser boundary: ${forbidden}`);
  }
  for (const required of [
    'credentials: "omit"',
    'redirect: "error"',
    'referrerPolicy: "no-referrer"',
    "url.origin !== window.location.origin",
    'credentialRef.current = ""',
    "armDeadline(authenticationTimeoutMilliseconds",
    'window.addEventListener("pagehide", onPageHide)',
    'window.removeEventListener("pagehide", onPageHide)',
    "clearAuthority();",
    "displayStringList(node.capabilities)",
    "page.next_after",
    "More nodes exist.",
    "tenantPage.next_after",
    "Load 500 more",
    "OPERATE HERE. SIGNING KEYS STAY OUTSIDE THE BROWSER.",
    "consoleMutationAllowed(method, url.pathname)",
    "Control-owned desired state, capacity, access, containment, and enrollment",
    'projectedPath("/v1/operations/agents"',
    'projectedPath("/v1/operations/timeline"',
    'api("/v1/tenants/" + encodeURIComponent(tenantID) + "/instance-events?limit=100"',
    'api("/v1/tenants/" + encodeURIComponent(tenantID) + "/tasks?limit=100"',
    'api("/v1/tenants/" + encodeURIComponent(tenantID) + "/interactions?limit=100"',
    'api("/v1/tenants/" + encodeURIComponent(tenantID) + "/schedules?limit=100"',
    'api("/v1/node-pools?limit=500"',
    "CAPACITY IS NOT PERMISSION.",
    "A pool label is only discovery metadata.",
    "READ AS A CLAIM, NOT AS PROOF.",
    "REPORTED STATE · NOT VERIFIED OUTCOME",
    "THE PROMPT IS UNTRUSTED. YOUR RESPONSE IS EXACTLY BOUND.",
    "USE AN APPROVED SIGNER",
    'encodeURIComponent(tenantID) + "/quota"',
    "Fleet-wide resource quota",
    "Existing work is not evicted when a limit is lowered.",
    "This is observed state, not desired state.",
    "A COMPUTER, WITH A BOUNDARY.",
    "Gateway injects credentials only at the trusted outbound boundary",
    "These observations do not match a retained deployment.",
    "THIS IS A CURRENT VIEW, NOT A COMPLETE AUDIT LOG.",
    "A workspace combines signed desired state with the latest exact Executor observation",
    "No freeze is active for tenant ",
    "The console attempted an unsupported mutation.",
    'method: "POST"',
    "reenteredCredential !== credentialRef.current",
    "commandReviewCurrent(preview)",
    "command_dsse_base64: preview.envelopeBase64",
    "credentialInputRef.current.value = \"\"",
  ]) {
    assert.equal(source.includes(required), true, `missing browser boundary: ${required}`);
  }
  assert.equal(source.includes('method: "PATCH"'), false);
});

test("every labelled console section points at a real heading", async () => {
  const source = await readFile(new URL("./App.jsx", import.meta.url), "utf8");
  const labelledBy = Array.from(
    source.matchAll(/aria-labelledby="([^"]+)"/gu),
    (match) => match[1],
  );
  assert.ok(labelledBy.length >= 10);
  for (const id of labelledBy) {
    assert.equal(source.includes(`id="${id}"`), true, `missing heading id: ${id}`);
  }
});

test("the command courier has no signing, key import, persistence, or network authority", async () => {
  const source = await readFile(new URL("./command-courier.js", import.meta.url), "utf8");
  for (const forbidden of [
    "fetch(",
    "XMLHttpRequest",
    "WebSocket",
    "localStorage",
    "sessionStorage",
    "document.cookie",
    "crypto.subtle.sign",
    "crypto.subtle.generateKey",
    "crypto.subtle.importKey",
    "privateKey",
  ]) {
    assert.equal(source.includes(forbidden), false, `forbidden courier authority: ${forbidden}`);
  }
  assert.equal(source.includes('crypto.subtle.digest("SHA-256", bytes)'), true);
});

test("source assets do not depend on a network-served asset", async () => {
  const files = await Promise.all([
    readFile(new URL("../index.html", import.meta.url), "utf8"),
    readFile(new URL("./app.css", import.meta.url), "utf8"),
    readFile(new URL("./App.jsx", import.meta.url), "utf8"),
    readFile(new URL("./command-courier.js", import.meta.url), "utf8"),
    readFile(new URL("./interaction-guidance.js", import.meta.url), "utf8"),
    readFile(new URL("./operator-guidance.js", import.meta.url), "utf8"),
    readFile(new URL("./operations-console.jsx", import.meta.url), "utf8"),
    readFile(new URL("./console-api.js", import.meta.url), "utf8"),
    readFile(new URL("./workspace-model.js", import.meta.url), "utf8"),
  ]);
  const source = files.join("\n");
  assert.equal(/https?:\/\//u.test(source), false);
  assert.equal(source.includes("//cdn."), false);
});
