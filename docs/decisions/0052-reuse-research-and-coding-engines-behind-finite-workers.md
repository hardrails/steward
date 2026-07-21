---
title: Reuse research and coding engines behind finite workers
description: Why Steward owns small worker protocols instead of a crawler, search engine, or coding agent.
section: Architecture decision
---

# Reuse research and coding engines behind finite workers

- Status: Accepted
- Date: 2026-07-21
- Rung: open-source

## Context

Hermes needs to search and extract public sources and to delegate repository work
to Codex or Claude Code. Search indexes, browser-grade extraction, and coding
agents are large context capabilities that change quickly. Steward's core concern
is different: keep their credentials out of an untrusted agent, constrain the
operations an agent can request, and retain evidence about those requests.

The solution must remain deployable without a cloud vendor, work with self-hosted
services, and avoid adding a private or third-party dependency to Steward's Go
authority processes. Consumer-subscription authentication must stay inside the
official user-operated CLI and must never become a Steward authentication broker.

## Decision

Use replaceable external engines behind two small, versioned HTTP worker
contracts. The reference research worker normalizes SearXNG search and a
Firecrawl-compatible extraction service. The reference coding worker invokes the
official, pinned Codex or Claude Code CLI in a separate hardened container with a
dedicated workspace and credential volume. Gateway remains the only interface
visible to Hermes and injects the worker credential.

Steward owns the request validation, byte and time limits, fixed operation paths,
safe process invocation, and normalized result envelopes. It does not own search
ranking, crawling, page rendering, coding-agent logic, or subscription login.

**Tradeoff:** Operators deploy additional services, but each can be replaced
without changing the Hermes skill or giving provider authority to the agent.

**Rejected:** Building a crawler, search engine, or coding agent in Steward would
duplicate mature context capabilities and create an unsafe maintenance burden.
Embedding the CLIs or their credentials in Hermes would collapse the isolation
boundary. Requiring a hosted search vendor would break sovereign and air-gapped
deployments.

## Consequences

Public-web research still requires reachable public-web infrastructure; an
air-gapped deployment must point the same contract at an imported index or corpus.
Coding workers can use API keys or an official CLI's user-operated subscription
login. Their credential stores and writable workspaces are never mounted into the
Hermes container.

Revisit if a stable, vendor-neutral protocol covers both the needed research or
coding operation and Steward's byte, time, authentication, and evidence semantics.
