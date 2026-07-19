import assert from "node:assert/strict";
import {readFile} from "node:fs/promises";
import test from "node:test";

test("the React source keeps credentials ephemeral and limits mutation to signed command couriering", async () => {
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
    'method: "PUT"',
    'method: "PATCH"',
    'method: "DELETE"',
    "/v1/enrollments",
    "/v1/operators",
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
    "OBSERVE HERE. AUTHORIZE WITH YOUR KEYS.",
    'projectedPath("/v1/operations/agents"',
    "This is observed state, not desired state.",
    "The status above is the last successful workload observation.",
    'method !== "GET" && !commandSubmission',
    "The console attempted an unsupported mutation.",
    'method: "POST"',
    "reenteredCredential !== credentialRef.current",
    "commandReviewCurrent(preview)",
    "command_dsse_base64: preview.envelopeBase64",
    "credentialInputRef.current.value = \"\"",
  ]) {
    assert.equal(source.includes(required), true, `missing browser boundary: ${required}`);
  }
  const explicitMutations = Array.from(source.matchAll(/method:\s*"(POST|PUT|PATCH|DELETE)"/gu), (match) => match[1]);
  assert.deepEqual(explicitMutations, ["POST"]);
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
  ]);
  const source = files.join("\n");
  assert.equal(/https?:\/\//u.test(source), false);
  assert.equal(source.includes("//cdn."), false);
});
