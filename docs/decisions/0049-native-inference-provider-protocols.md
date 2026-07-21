---
title: Add native bounded inference provider protocols
description: Why Gateway uses a small protocol profile instead of provider SDKs or a general model gateway.
section: Architecture decision
---

# Add native bounded inference provider protocols

- Status: Accepted
- Date: 2026-07-20

## Context

Steward agents need mediated access to hosted and self-managed inference without
receiving reusable provider credentials. OpenAI, OpenRouter, Mistral, vLLM, Ollama,
llama.cpp, LocalAI, LiteLLM, LM Studio, SGLang, and TGI use an OpenAI-compatible HTTP shape, but their
base-path prefixes differ. Anthropic uses its Messages API, requires a fixed API
version, and normally authenticates with `x-api-key` instead of bearer
authentication.

The repository must remain buildable and operable offline with no third-party Go
dependency. The Relay/Gateway boundary also needs a small, auditable request
allowlist rather than the complete administration surface of every provider.

## Decision

Decision: use in-house: a thin standard-library protocol profile inside the
existing Gateway. Tradeoff: it preserves exact path, model, byte, concurrency,
revocation, and credential controls while adding only the protocol differences that
affect dispatch. Rejected: provider SDKs and a general model-gateway dependency
because they add dependency, packaging, upgrade, and attack surface without helping
an HTTP reverse proxy. Revisit if a required provider cannot be represented by a
fixed base-path prefix, bounded path set, static credential header, and fixed API
version.

An inference route pins:

- `openai` or `anthropic` request protocol;
- an exact HTTP(S) API base URL with a canonical path prefix;
- `bearer`, `x-api-key`, or `api-key` credential injection;
- a fixed Anthropic API version when applicable; and
- the existing model alias and concurrency limit.

Gateway strips agent-supplied provider credentials and Anthropic control headers,
then adds only the route-owned values. It maps the stable Relay `/v1` surface onto
the configured upstream prefix. It does not translate request or response bodies.
Protocol, prefix, authentication mode, and API version are included in the retained
route-policy digest.

Existing configuration with omitted protocol fields keeps its original OpenAI and
bearer behavior and its prior digest format. New protocol-aware routes use policy
document version 10.

## Consequences

OpenRouter's `/api/v1` path and native Anthropic Messages calls work without giving
their credentials to an agent. Provider presets reduce operator error for common
hosted and local systems, while `compatible` covers another OpenAI-shaped service.

Steward does not claim full API compatibility with every system. Cloud-specific
request signing, query-based API versions, realtime sockets, provider
administration, files, batches, and arbitrary beta features remain excluded. A
provider can also implement only a subset of the OpenAI paths that Steward permits;
Gateway cannot supply a feature absent upstream.

The current protocol facts are grounded in the providers' primary documentation:
[OpenRouter API](https://openrouter.ai/docs/api/reference/overview),
[Anthropic API overview](https://platform.claude.com/docs/en/api/overview),
[OpenAI API authentication](https://platform.openai.com/docs/api-reference/backward-compatibility),
[Mistral Chat API](https://docs.mistral.ai/api),
[vLLM OpenAI-compatible server](https://docs.vllm.ai/en/latest/serving/openai_compatible_server/),
[Ollama OpenAI compatibility](https://docs.ollama.com/api/openai-compatibility),
[llama.cpp server](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md),
[LM Studio compatibility](https://lmstudio.ai/docs/developer/openai-compat),
[SGLang API](https://docs.sglang.io/),
and [Hugging Face TGI API](https://huggingface.co/docs/text-generation-inference/reference/api_reference).
