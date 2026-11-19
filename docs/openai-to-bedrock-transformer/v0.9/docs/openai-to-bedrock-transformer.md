---
title: "Overview"
---
# OpenAI to Bedrock Transformer

## Overview

The OpenAI to Bedrock Transformer policy lets OpenAI Chat Completions clients use the AWS Bedrock Converse API without changing their request or response handling. It rewrites requests to Bedrock's `/model/{modelId}/converse` or `/model/{modelId}/converse-stream` endpoint and translates Bedrock responses back to the OpenAI format.

The policy supports two modes:

- **Single-provider mode** — attach the transformer directly to a proxy that uses Bedrock as its upstream provider.
- **Multi-provider mode** — attach the transformer to a Bedrock provider in a proxy with multiple providers. The transformer applies to requests routed to that provider.

## Features

- Converts OpenAI messages, system/developer prompts, inference settings, stop sequences, and tools to Bedrock Converse format.
- Maps OpenAI assistant tool calls and tool results to Bedrock `toolUse` and `toolResult` content blocks.
- Supports base64 data-URI images in OpenAI `image_url` blocks.
- Rewrites non-streaming Converse responses, usage, tool calls, finish reasons, and errors to OpenAI ChatCompletion JSON.
- Decodes Bedrock's binary Amazon event-stream responses and emits OpenAI-compatible Server-Sent Events, including usage and the final `[DONE]` marker.
- Supports Bedrock model IDs and inference-profile IDs in the upstream path.

## Parameters

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `model` | No | Request `model` | Fallback Bedrock model or inference-profile ID for the Converse request path, used when the request payload names none. It does **not** override a model the client named. |
| `providerId` | No | — | Bedrock provider ID used in multi-provider configurations. |

## Model resolution

`model` is optional, and it is a **fallback**. It does not override what the client asks for. The model that serves a request is resolved in one order, the same order every WSO2 LLM transformer uses:

1. the `model` field of the request payload, whenever it names one, this takes priority;
2. otherwise the `model` parameter configured on this policy;
3. if neither supplies one, the request is rejected with a 400 naming both sources.

An absent, `null` or empty (`""`) request `model` counts as naming none, so the configured value applies. A **whitespace-only** `model` is rejected as malformed even when a model is configured, it is bad input rather than a missing value. A non-string `model` is rejected as a bad request.

Set `model` to give clients that name no model a sensible default. There is no way to force every request onto one model: a client that names a model is always served the model it named.

Responses report the model that actually served the request, in buffered and streamed
responses alike, not the configured value, which may be unset. A response therefore never misattributes its own output.

## Example

For a multi-provider LLM proxy, attach the transformer to the Bedrock provider. The provider `id` (or its `as` alias) is supplied by the gateway as `providerId`, so it is not repeated in `params`:

```yaml
additionalProviders:
  - id: bedrock-provider
    auth:
      type: api-key
      header: Authorization
      value: Bearer REPLACE_WITH_BEDROCK_API_KEY
    transformer:
      type: openai-to-bedrock-transformer
      version: v1
      params:
        model: us.anthropic.claude-sonnet-4-5-20250929-v1:0
```

For a single-provider proxy, attach the policy directly:

```yaml
operationPolicies:
  - name: openai-to-bedrock-transformer
    version: v1
    paths:
      - path: /chat/completions
        methods: [POST]
        params:
          model: us.amazon.nova-lite-v1:0
```

## Notes

- The policy translates payloads and paths only. Configure Bedrock authentication on the upstream provider.
- When `model` is omitted from the policy configuration, the OpenAI request's `model` field must contain a valid Bedrock model or inference-profile ID.
- Remote image URLs are not fetched; use base64 data URIs for image input.
- Streaming translation expects Bedrock's `application/vnd.amazon.eventstream` framing.
