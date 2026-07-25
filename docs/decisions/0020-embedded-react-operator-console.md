---
title: Embed a React operator console
description: Why Steward commits and embeds a React SPA while keeping frontend dependencies outside its runtime and ordinary air-gapped build.
section: Architecture decision
---

# Embed a React operator console

- Status: Accepted
- Date: 2026-07-16
- Rung: open-source build dependency

## Context

Operators need a fast way to inspect fleet posture without reconstructing
multiple bounded API responses by hand. The interface must work on a disconnected
management host, preserve existing site and tenant authorization, avoid a second
server or identity store, and preserve the existing Control API's signing,
secret-retrieval, and approval boundaries.

Steward's Go module intentionally uses only the standard library. Adding a
JavaScript dependency to the running controller or to ordinary Go builds would
weaken independent, air-gapped rebuilds. Building a bespoke DOM framework would
avoid a package lock but make session fencing, projection changes, loading states,
accessible navigation, and ongoing interface work harder to review and maintain.

## Decision

Build the operator interface as a React single-page application with Vite as the
maintainer build tool. Commit the production HTML, JavaScript, CSS, icon, and
third-party notice files, then embed that exact distribution in
`steward-control` with `go:embed`.

The installed service and ordinary `go build` path do not invoke Node.js, npm, a
package registry, a CDN, or telemetry. React and Vite are lockfile-pinned
build-time inputs. CI installs them with lifecycle scripts disabled, audits the
tree, runs source-level security and session tests, rebuilds the production
distribution, and rejects any generated diff.

The console uses the existing control origin and operator Bearer identity. It
performs only same-origin requests against the bounded Control API. The bearer
stays in a JavaScript memory reference and is cleared with displayed state on
lock, navigation, inactivity, or the absolute session deadline. A separate Host
gate covers both API and console routes, and restrictive response headers deny
external assets, framing, forms, workers, and broad browser capabilities.

**Tradeoff:** React provides a maintained component and rendering model for a
stateful operator surface, while committed assets preserve runtime and disconnected
build independence. The cost is a larger reviewed bundle and a frontend supply
chain that maintainers must audit and reproduce.

**Rejected:** hand-built DOM state management, because the apparent dependency
savings would move more browser lifecycle and rendering code into Steward without
improving the runtime trust boundary. Server-rendered pages were also rejected
because the console already consumes the bounded JSON Control API and needs
stateful projection, review, and session fencing.

## Consequences

Browser extensions and the browser process remain trusted enough to read the
operator credential and fleet metadata. Content Security Policy cannot protect
against a privileged extension. Operators need a dedicated hardened browser
profile, and browser-side timeouts do not revoke the server credential.

The original observation-only mutation constraint was superseded by
[ADR 0065](0065-primary-console-operations.md) after the existing Control API's
bounded mutations, role checks, optimistic revisions, and signed-artifact
boundaries were exposed through an explicit browser allowlist. The React
embedding, reproducible build, ephemeral credential, and hardened browser
decisions remain unchanged. Revisit React if
reproducible builds become unreliable, the dependency audit cannot be kept clean,
or a substantially smaller maintained option can satisfy the same tested session
and accessibility boundary.
