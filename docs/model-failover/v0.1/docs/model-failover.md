---
title: "Overview"
---
# Model Failover

## Overview

The Model Failover policy sends each request on an LLM proxy to an ordered chain of targets. Each target is a provider attached to the proxy plus the model to request from it. When a target is rate-limited, returns a configured server error, can't be reached, or takes too long, the gateway sends the same request to the next target. The client gets one answer, or one clear error if every target fails.

Targets can be the same model in different regions (two Azure OpenAI deployments), different OpenAI-compatible providers, or providers with a different API format (Anthropic, AWS Bedrock, Google Gemini, Mistral). For a different format, the provider's own transformer converts the request and the response, streaming included, so the client keeps sending OpenAI Chat Completions requests.

## Features

- Ordered failover across providers and models, each target tried at most once per request
- Failover on selected status codes (default `429`, `500`, `502`, `503`, `504`), connection failures, resets and per-attempt timeouts
- Each target uses its own credentials and API format
- A target that fails repeatedly is suspended, then brought back only after successful probe requests
- No failover once the answer has started streaming to the client
- A fixed error when no target can answer: `503` with code `all_targets_unavailable`

## How it works

The gateway splits the proxy route into two:

- **The front route** is the one clients call. Your other policies (guardrails, rate limits) run here once. It builds the list of targets to try for this request, skipping suspended ones, and uses the gateway's built-in retry to send the request onward.
- **The dispatch route** is internal and can't be reached from outside. Every attempt passes through it. It picks the next target, applies that target's transformer and credentials, and forwards the request to the provider. When the answer is a failure that should move the request on, it marks the answer, and the front route retries with the next target.

## Configuration

Attach the policy to an `LlmProxy` operation. Every provider named in `targets` must be attached to the proxy (`provider`, `additionalProviders` or `providers`). A provider with a different API format needs its `transformer` declared on the attachment.

### User Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `targets` | `Target` array | Yes | - | Ordered targets, 1 to 10. The first is the primary. The same provider and model may not appear twice. |
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

### Target

| Property | Type | Required | Description |
|----------|------|----------|-------------|
| `provider` | string | Yes | The id or alias of a provider attached to this proxy. |
| `model` | string | Yes | The model to request from this provider, up to 256 characters. |

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
            targets:
              - provider: azure-sweden
                model: gpt-4o
              - provider: azure-spain
                model: gpt-4o
              - provider: anthropic
                model: claude-sonnet-4-5
            perAttemptTimeout: 20s
            suspendAfterConsecutiveFailures: 3
            suspendDuration: 60s
```

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
- The policy can't be combined with other policies that choose a provider on the same proxy (`llm-header-router`, `model-round-robin`, `model-weighted-round-robin`, `intelligent-model-routing`, `cost-based-model-routing`, `semantic-model-routing`, `time-based-model-routing`).

**Note:**

Inside the `gateway/build.yaml`, ensure the policy module is added under `policies:`:

```yaml
- name: model-failover
  gomodule: github.com/wso2/gateway-controllers/policies/model-failover@v0
```
