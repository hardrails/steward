---
title: Connect an inference provider
description: Configure OpenAI, OpenRouter, Anthropic, Mistral, vLLM, Ollama, llama.cpp, LocalAI, LiteLLM, LM Studio, SGLang, TGI, or another compatible model endpoint without giving its credential to an agent.
section: How-to guide
---

# Connect an inference provider

Steward keeps the inference credential in Gateway, outside the untrusted agent.
The agent receives one stable Relay address and authority for one exact model alias.
Gateway checks the request path and model before it contacts the provider.

Steward does not run or schedule the model server. The provider can be a local
service, a service elsewhere in your private network, or a public API.

## Choose a preset

`stewardctl gateway inference set -provider PROVIDER` supplies the usual protocol,
authentication mode, and API base URL. Override `-base-url` when the service uses a
different address.

| Provider | Default Gateway target | Protocol sent upstream | Credential header |
| --- | --- | --- | --- |
| `openai` | `https://api.openai.com/v1` | OpenAI | `Authorization: Bearer …` |
| `openrouter` | `https://openrouter.ai/api/v1` | OpenAI-compatible | `Authorization: Bearer …` |
| `anthropic` | `https://api.anthropic.com/v1` | Anthropic Messages | `x-api-key: …` |
| `mistral` | `https://api.mistral.ai/v1` | OpenAI-compatible | `Authorization: Bearer …` |
| `vllm` | `http://127.0.0.1:8000/v1` | OpenAI-compatible | none unless configured |
| `ollama` | `http://127.0.0.1:11434/v1` | OpenAI-compatible | none unless configured |
| `llamacpp` | `http://127.0.0.1:8080/v1` | OpenAI-compatible | none unless configured |
| `localai` | `http://127.0.0.1:8080/v1` | OpenAI-compatible | none unless configured |
| `litellm` | `http://127.0.0.1:4000/v1` | OpenAI-compatible | none unless configured |
| `lmstudio` | `http://127.0.0.1:1234/v1` | OpenAI-compatible | none unless configured |
| `sglang` | `http://127.0.0.1:30000/v1` | OpenAI-compatible | none unless configured |
| `tgi` | `http://127.0.0.1:3000/v1` | OpenAI-compatible | none unless configured |

The local addresses are defaults, not deployment requirements. Gateway runs on the
host, so a loopback target is appropriate when the model server runs on that host.

## Configure a hosted provider

Copy the API key from a protected source into an owner-only file. Do not put the
key in a command argument, environment variable, agent configuration, or browser.

```console
sudo install -o steward-gateway -g steward-gateway -m 0600 \
  /secure/openrouter.key /etc/steward/openrouter.key

sudo stewardctl gateway inference set \
  -provider openrouter \
  -credential-file /etc/steward/openrouter.key

sudo systemctl reload steward-gateway.service
sudo stewardctl gateway inference list
```

The `openrouter` preset preserves OpenRouter's `/api/v1` prefix. An agent still uses
the normal OpenAI-compatible Relay base URL; Gateway maps that fixed local path to
the provider prefix.

Anthropic uses its native Messages API:

```console
sudo install -o steward-gateway -g steward-gateway -m 0600 \
  /secure/anthropic.key /etc/steward/anthropic.key

sudo stewardctl gateway inference set \
  -provider anthropic \
  -credential-file /etc/steward/anthropic.key

sudo systemctl reload steward-gateway.service
```

The preset fixes `anthropic-version` to `2023-06-01`. To deliberately select a
different published API version, add `-anthropic-version YYYY-MM-DD`. Gateway
removes agent-supplied authentication and `Anthropic-*` control headers before
adding its configured values. Anthropic workload-identity tokens can
use `-credential-mode bearer` instead of the API-key default, but the token is read
from the same owner-only credential file.

## Configure a local model server

For vLLM using its standard port:

```console
sudo stewardctl gateway inference set -provider vllm
sudo systemctl reload steward-gateway.service
```

For a server on another private address:

```console
sudo stewardctl gateway inference set \
  -provider vllm \
  -id private-vllm \
  -base-url https://models.internal.example/v1 \
  -credential-file /etc/steward/private-vllm.key
```

The same pattern works with `ollama`, `llamacpp`, `localai`, `litellm`,
`lmstudio`, `sglang`, and `tgi`.
The model server decides which OpenAI features it implements. A preset guarantees
correct Steward routing and authentication; it cannot add an endpoint or request
field the model server does not support.

## Configure another compatible service

Use `compatible` for another OpenAI-shaped endpoint:

```console
sudo stewardctl gateway inference set \
  -provider compatible \
  -id private-models \
  -base-url https://models.example.net/custom/v1 \
  -protocol openai \
  -credential-mode bearer \
  -credential-file /etc/steward/private-models.key
```

`-credential-mode` accepts `bearer`, `x-api-key`, or `api-key`. The base URL can
contain a canonical path prefix, but not a query, fragment, user information,
percent-encoded path, or `.`/`..` segment. This keeps the retained destination
unambiguous.

“Compatible” means the upstream accepts one of Steward's bounded request shapes.
Steward does not translate request or response bodies. Cloud-specific request
signing, query-based API versions, realtime sockets, provider administration,
batch APIs, file APIs, and arbitrary inference paths are outside this interface.

## Configure the agent-facing address

For an OpenAI-compatible client, use:

```text
http://steward-relay:8080/v1
```

For an Anthropic client, use the Relay origin and let its SDK add `/v1/messages`:

```text
http://steward-relay:8080
```

The API key value required by some client libraries is only a placeholder. Gateway
removes it before dispatch. The real credential never enters the agent container.

The signed tenant policy must allow the route ID and model alias, and the instance
intent must select both. The request's top-level `model` must exactly equal that
alias. Use the provider's real model identifier as the alias unless an upstream
gateway already maps aliases.

## Allowed inference calls

OpenAI routes accept:

- `POST /v1/chat/completions`
- `POST /v1/completions`
- `POST /v1/embeddings`
- `POST /v1/responses`
- `GET /v1/models`, generated locally with only the granted alias

Anthropic routes accept:

- `POST /v1/messages`
- `POST /v1/messages/count_tokens`
- `GET /v1/models`, generated locally with only the granted alias

Gateway rejects every query string and every other inference path. Request bodies
are limited to 4 MiB, responses to 32 MiB, and concurrency to the route's
`max_concurrent` setting. Token streams remain streaming and are canceled when the
grant is revoked.
