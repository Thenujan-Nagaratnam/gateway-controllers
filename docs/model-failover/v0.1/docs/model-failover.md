---
title: "Overview"
---
# Model Failover

## Overview

The Model Failover policy gives each requested model its own ordered fallback chain. A chain is a **primary** model and its **fallbacks**, each fallback a provider attached to the proxy plus the model to request from it. The model in the request picks the chain: the gateway sends the request to that model, and when it is rate-limited, returns a configured server error, can't be reached, or takes too long, sends the same request to the primary's next fallback. The client gets one answer, or one clear error if the whole chain fails. A request for a model that has no chain is forwarded unchanged, with a single attempt.

Fallbacks can be the same model in different regions (two Azure OpenAI deployments), different OpenAI-compatible providers, or providers with a different API format (Anthropic, AWS Bedrock, Google Gemini, Mistral). For a different format, the provider's own transformer converts the request and the response, streaming included, so the client keeps sending OpenAI Chat Completions requests.

## Features

- One ordered fallback chain per requested model, each model tried at most once per request
- Requests for models without a chain pass through untouched
- Failover on selected status codes (default `429`, `500`, `502`, `503`, `504`), connection failures, resets and per-attempt timeouts
- Each target uses its own credentials and API format
- A target that fails repeatedly is suspended, then brought back only after successful probe requests
- No failover once the answer has started streaming to the client
- A fixed error when no target can answer: `503` with code `all_targets_unavailable`

## How it works

The gateway splits the proxy route into two:

- **The front route** is the one clients call. Your other policies (guardrails, rate limits) run here once. It reads the requested model, picks that model's chain, builds the list of models to try (skipping suspended ones), and uses the gateway's built-in retry to send the request onward.
- **The dispatch route** is internal and can't be reached from outside. Every attempt passes through it. It picks the next target, applies that target's transformer and credentials, and forwards the request to the provider. When the answer is a failure that should move the request on, it marks the answer, and the front route retries with the next target.

## Configuration

Attach the policy to an `LlmProxy` operation, or to an `LlmProvider` to fall back across that provider's own models (see [On an LLM provider](#on-an-llm-provider)). A chain's primary runs on the provider the request is routed to (the proxy's primary provider). Every provider named on a fallback must be attached to the proxy (`provider`, `additionalProviders` or `providers`); a fallback without a provider uses the primary's provider. A provider with a different API format needs its `transformer` declared on the attachment.

### User Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `chains` | `Chain` array | Yes | - | One chain per primary model, 1 to 20, with at most 50 distinct provider and model pairs across all chains. Each primary model may have only one chain. |
| `failoverOn.statusCodes` | integer array | No | `[429, 500, 502, 503, 504]` | Status codes that move the request to the next target. Each must be `429` or `500`–`599`. Other statuses are returned to the client unchanged. |
| `failoverOn.connectFailure` | boolean | No | `true` | Fail over when the provider can't be reached. |
| `failoverOn.reset` | boolean | No | `true` | Fail over when the connection is reset before an answer. |
| `failoverOn.timeout` | boolean | No | `true` | Fail over when a target doesn't answer within `perAttemptTimeout`. When `false`, the timeout is returned to the client as a `504`. |
| `perAttemptTimeout` | duration | No | `30s` | How long to wait for a target to start answering, `1s`–`300s`. Streaming answers are not cut off once they start. |
| `suspendAfterConsecutiveFailures` | integer | No | `3` | Failures in a row that suspend a target, `1`–`100`. |
| `suspendDuration` | duration | No | `30s` | How long a suspended target gets no normal traffic, `1s`–`60m`. |
| `probeConcurrency` | integer | No | `1` | Probe requests allowed at once to a target in recovery, `1`–`10`. |
| `recoverAfterSuccessfulProbes` | integer | No | `2` | Successful probes in a row that return a target to normal traffic, `1`–`20`. |

Durations use `ms`, `s` or `m`, for example `500ms`, `30s`, `2m`.

### Chain

| Property | Type | Required | Description |
|----------|------|----------|-------------|
| `primary.model` | string | Yes | The requested model this chain applies to, matched exactly (case-sensitive), up to 256 characters. The primary has no `provider`: it is the provider the request is routed to. |
| `fallbacks` | `Fallback` array | Yes | Tried in order after the primary fails, 1 to 9. The same provider and model may not appear twice in one chain. |

### Fallback

| Property | Type | Required | Description |
|----------|------|----------|-------------|
| `provider` | string | No | On an `LlmProxy`, the id or alias of a provider attached to the proxy; omitted means the primary's provider. On an `LlmProvider`, omit it (or give the provider's own name). |
| `model` | string | Yes | The model to request from this provider, up to 256 characters. |

### Requests without a chain

A request whose model matches no chain's primary, or whose model can't be read, is forwarded to where it would go without the policy, with its model unchanged and a single attempt. The upstream's answer, including a `429` or `5xx`, reaches the client as it is. That single attempt is still bounded by `perAttemptTimeout`; past it the client gets a `504`.

## Example

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: LlmProxy
metadata:
  name: assistant-proxy
spec:
  displayName: Assistant Proxy
  version: v1.0
  context: /assistant
  provider:
    id: azure-sweden
  additionalProviders:
    - id: azure-spain
    - id: anthropic
      transformer:
        type: openai-to-anthropic-transformer
        version: v0
        params:
          model: claude-sonnet-4-5
  operationPolicies:
    - name: model-failover
      version: v0
      paths:
        - path: /chat/completions
          methods: [POST]
          params:
            chains:
              - primary: { model: gpt-4o }           # on azure-sweden, the proxy's provider
                fallbacks:
                  - provider: azure-spain
                    model: gpt-4o
                  - provider: anthropic
                    model: claude-sonnet-4-5
              - primary: { model: gpt-4.1 }
                fallbacks:
                  - model: gpt-4.1-mini              # also on azure-sweden
            perAttemptTimeout: 20s
            suspendAfterConsecutiveFailures: 3
            suspendDuration: 60s
```

## On an LLM provider

Attached to an `LlmProvider`, the policy falls back across that provider's own models. For example, a request for `gpt-4o` falls back to `gpt-4o-mini` when `gpt-4o` is rate-limited. Every attempt goes to the provider's own upstream with its own credentials; only the model changes.

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: LlmProvider
metadata:
  name: openai
spec:
  template: openai
  context: /openai
  upstream:
    url: https://api.openai.com
    auth: { type: api-key, header: Authorization, value: Bearer <key> }
  accessControl: { mode: allow_all }
  operationPolicies:
    - name: model-failover
      version: v0
      paths:
        - path: /chat/completions
          methods: [POST]
          params:
            chains:
              - primary: { model: gpt-4o }
                fallbacks:
                  - model: gpt-4o-mini
```

- **Fallbacks name models only.** `provider` can be left out, or set to the provider's own name. Naming another provider is rejected; put the providers behind an `LlmProxy` for that.
- **The requested model is read, and each fallback's model written, where the provider's template says**  (the template's `requestModel`): the request body for OpenAI, Anthropic, Mistral, Azure AI Foundry and Azure OpenAI, or the URL path for Gemini (`/models/<model>:generateContent`) and AWS Bedrock (`/model/<model>/...`). Header and query-parameter locations in custom templates work too.
- **For a path model, attach the policy to a wildcard path** such as `/models/*`. A path that names one model (`/models/gemini-2.5-pro:generateContent`) is rejected, because the rewritten request would no longer match it.
- **Azure OpenAI:** the deployment in the URL usually decides the model, so rewriting the body model may have no effect. To fail over between Azure deployments, attach one provider per deployment to an `LlmProxy`.
- **Every other parameter, the failover conditions, suspension and recovery, and the exhaustion response work exactly as on a proxy.**
- **Nesting:** a proxy may list a provider that has its own model-failover. Each layer walks its own chain, so the attempts multiply (proxy chain length × provider chain length).

## Error response

When every target fails, or every target is suspended, the client receives:

```json
HTTP/1.1 503 Service Unavailable
{"error":{"message":"All configured model targets are currently unavailable. Please retry later.","type":"model_failover_exhausted","param":null,"code":"all_targets_unavailable"}}
```

The body is always the same. It never includes provider names, endpoints or upstream error details.

## Limitations

- Clients must send OpenAI Chat Completions requests.
- A request body larger than the gateway's failover buffer (`router.failover.max_request_body_bytes`, default 4 MiB) is sent to the first target only.
- Target health is tracked by each gateway instance separately.
- Once an answer has started streaming, a failure part-way through is not failed over.
- On the same operation, the policy can't be combined with policies that choose a provider (`llm-header-router`, `intelligent-model-routing`, `cost-based-model-routing`, `semantic-model-routing`, `time-based-model-routing`, or a round-robin entry that names a provider). Policies on other operations are unaffected.

## With model round-robin

`model-round-robin` and `model-weighted-round-robin` can share an operation with model-failover when none of their entries names a provider and they come **before** model-failover. Round-robin then picks the requested model, and model-failover walks that model's chain. Placing round-robin after model-failover on the same operation is rejected. Round-robin sees only the final answer, so a primary rescued by a fallback is not suspended by round-robin; set its `suspendDuration: 0` and let model-failover track health.

**Note:**

Inside the `gateway/build.yaml`, ensure the policy module is added under `policies:`:

```yaml
- name: model-failover
  gomodule: github.com/wso2/gateway-controllers/policies/model-failover@v0
```
