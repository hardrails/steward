import assert from "node:assert/strict";
import {readFile} from "node:fs/promises";
import test from "node:test";

test("the React source keeps credentials ephemeral and the console read-only", async () => {
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
    'method: "POST"',
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
    "OBSERVE HERE. AUTHORIZE ELSEWHERE.",
  ]) {
    assert.equal(source.includes(required), true, `missing browser boundary: ${required}`);
  }
});

test("source assets do not depend on a network-served asset", async () => {
  const files = await Promise.all([
    readFile(new URL("../index.html", import.meta.url), "utf8"),
    readFile(new URL("./app.css", import.meta.url), "utf8"),
    readFile(new URL("./App.jsx", import.meta.url), "utf8"),
  ]);
  const source = files.join("\n");
  assert.equal(/https?:\/\//u.test(source), false);
  assert.equal(source.includes("//cdn."), false);
});
