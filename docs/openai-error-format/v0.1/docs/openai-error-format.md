---
title: "Overview"
---
# OpenAI Error Format

## Overview

The OpenAI Error Format policy is a **fault policy** for `LlmProvider` and `LlmProxy` APIs. It returns the errors the gateway produces in the OpenAI error envelope, so a client built on an OpenAI SDK can parse them:

```json
{"error":{"message":"Violation of applied word count constraints detected","type":"invalid_request_error","param":null,"code":null}}
```

Without it, a gateway rejection on an LLM API is whatever shape the rejecting policy wrote, such as a guardrail's own JSON or the proxy's plain-text `no healthy upstream`. An OpenAI SDK can't parse those bodies and raises a generic error instead of the reason.

The policy is opt-in per API. APIs that don't attach it keep the error bodies they've always returned, so existing clients aren't affected when you upgrade the gateway.

## Features

- Returns policy rejections (authentication, authorization, rate limiting, guardrails, validation) in the OpenAI envelope.
- Maps the gateway's failure class to OpenAI's error `type`, and its error code to `code`.
- Keeps the rejecting policy's own reason as `message`, including the assessment a shipped guardrail writes.
- **Never changes the HTTP status code**, and keeps the other response headers (for example `WWW-Authenticate` or `Retry-After`).
- Passes the backend provider's own error responses through unchanged.
- Runs only when a request fails. It adds no processing to successful requests.
- Idempotent: an error body that's already in the OpenAI envelope is left as it is.

## Configuration

The policy is attached as a **fault policy**, through `globalFaultPolicies` or `operationFaultPolicies`, not through `globalPolicies`/`operationPolicies`. It has no system parameters.

### User Parameters (API Definition)

All parameters are optional.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `fault.maxInspectBytes` | integer | No | `65536` | Largest error body (in bytes) read to recover the rejecting policy's message. Larger or compressed bodies fall back to the failure's description or the status text. `0` disables body inspection. |

## Reference Scenarios

### Example 1: Attach to an LLM provider

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: LlmProvider
metadata:
  name: openai-provider
spec:
  displayName: OpenAI Provider
  version: v1.0
  template: openai
  context: /openai
  upstream:
    url: https://api.openai.com/v1
  accessControl:
    mode: allow_all
  globalPolicies:
    - name: word-count-guardrail
      version: v1
      params:
        request:
          min: 1
          max: 500
  globalFaultPolicies:
    - name: openai-error-format
      version: v0
```

A request the guardrail rejects returns the guardrail's status (422) with:

```json
{
  "error": {
    "message": "Violation of applied word count constraints detected",
    "type": "invalid_request_error",
    "param": null,
    "code": null,
    "guardrail": {
      "interveningGuardrail": "word-count-guardrail",
      "action": "GUARDRAIL_INTERVENED",
      "actionReason": "Violation of applied word count constraints detected"
    }
  }
}
```

### Example 2: Attach to a single operation

```yaml
  operationFaultPolicies:
    - name: openai-error-format
      version: v0
      paths:
        - path: /chat/completions
          methods: [POST]
          params: {}
```

### Example 3: Attach to an LLM proxy

`LlmProxy` uses the same `globalFaultPolicies` and `operationFaultPolicies` fields.

## How the envelope is built

| Field | Value |
|---|---|
| `message` | The failure's message as described by the rejecting policy; otherwise the message found in the error body the policy wrote (`error.message`, `message`, a guardrail's `message.actionReason`, `error_description`, `detail`, `error`, or a short single line of plain text); otherwise the HTTP status text |
| `type` | From the failure class, as in the table below; otherwise derived from the status |
| `param` | Always `null` |
| `code` | The failure's error code (for example `900902` or `906201`), or `null` |
| `guardrail` | Present only when a guardrail intervened. Contains what the guardrail itself chose to show |

| Failure class | `type` |
|---|---|
| `authentication` | `authentication_error` |
| `authorization` | `permission_error` |
| `throttling` | `rate_limit_error` |
| `guardrail`, `validation`, `requestSize` | `invalid_request_error` |
| `routing` | `not_found_error` |
| `upstream`, `internal` | `server_error` |
| none, or any other class | by status: 401 → `authentication_error`, 403 → `permission_error`, 404 → `not_found_error`, 429 → `rate_limit_error`, other 4xx → `invalid_request_error`, 5xx → `server_error` |

## Upgrading an existing gateway

Existing LLM APIs keep their current error bodies, because nothing changes unless an API attaches this policy. Attach it to new LLM providers and proxies whose clients use OpenAI SDKs. Move an existing API over when its clients are ready.

## Using it with other fault policies

Fault policies run in declaration order, and each one sees what the previous one wrote.

- **Declare it first** if your own fault policies should have the last word on the response.
- **Declare it last** if the OpenAI envelope must be what the client receives.

An error body that's already in the OpenAI envelope is never rewritten.

## Router failures

Failures the gateway's proxy produces because the upstream couldn't be reached (no healthy upstream, connection refused, upstream timeout) reach fault policies **only** when the gateway runs with:

```toml
[policy_engine.fault_policies]
handle_upstream_faults = true
```

With that setting on, those failures are returned in the OpenAI envelope (`type` `server_error`), and the backend's own errors still pass through unchanged.

With it off (the default), router failures keep the proxy's existing plain-text reply. `handle_upstream_faults` is gateway-wide: turning it on also stops **response** policies from seeing upstream and router errors on every API. Review that effect before enabling it.

## Not covered

- Requests that match no API: there is no API, so there are no fault policies.
- A failure after a streamed (SSE) response has started sending.
- Other API kinds (`RestApi`, `Mcp`, `Agent`, …): attaching the policy there has no effect.
