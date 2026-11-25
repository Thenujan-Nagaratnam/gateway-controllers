---
title: "Overview"
---
# PII Masking Regex Guardrail

## Overview

The PII Masking Regex Guardrail masks or redacts Personally Identifiable Information (PII) from request and response bodies using configurable regular expression patterns. This guardrail helps protect sensitive user data by replacing PII with placeholders or redaction markers before content is processed or returned.

This policy supports SSE streaming responses. When the upstream returns a streaming response (`stream: true`), the guardrail detects PII placeholders in the streamed assistant text and restores masked values across event and chunk boundaries. It is not tied to one vendor's wire format: the OpenAI chat/legacy completions shape (and every provider that speaks it), Anthropic Messages, Google Gemini, and Amazon Bedrock are handled out of the box, with no configuration required.

## Features

- Configurable PII entity detection using regular expressions
- Two modes: masking (reversible) and redaction (permanent)
- Automatic PII restoration in responses when using masking mode
- Supports JSONPath (RFC 9535) to choose which values are masked, for example only user and tool content
- A masked JSON request is always valid JSON: only the text of string values changes, never keys, numbers or spacing
- The same value always gets the same placeholder, so prompt caching and preserved reasoning keep working
- Restores streamed tool-call arguments and thinking, and keeps each content block's text in its own block
- Streaming response support for both SSE and plain chunked bodies -- the gateway accumulates only until a PII placeholder (e.g., `[EMAIL_3fa91c0b]`) is complete, then restores and forwards

## Configuration

This policy requires only a single-level configuration where all parameters are configured in the API definition YAML.

### User Parameters (API Definition)

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `email` | boolean | No | `false` | Enables built-in EMAIL detection. At least one of `email`, `phone`, `ssn`, or `customPIIEntities` must be enabled. |
| `phone` | boolean | No | `false` | Enables built-in PHONE detection. At least one of `email`, `phone`, `ssn`, or `customPIIEntities` must be enabled. |
| `ssn` | boolean | No | `false` | Enables built-in SSN detection. At least one of `email`, `phone`, `ssn`, or `customPIIEntities` must be enabled. |
| `customPIIEntities` | `CustomPIIEntity` array | No | - | Custom PII entity definitions for detection. Each item defines a `piiEntity` name and `piiRegex` pattern. At least one item required if provided. |
| `jsonPath` | string | No | `"$.messages[-1].content"` | RFC 9535 JSONPath expression that selects the string values to mask. Use `"$"` or `""` to mask every string value in the payload. |
| `redactPII` | boolean | No | `false` | If `true`, redacts PII by replacing with "*****" (permanent, cannot be restored). If `false`, masks PII with placeholders that can be restored in responses. |

### CustomPIIEntity Configuration

Each item in the `customPIIEntities` array must contain:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `piiEntity` | string | Yes | Name/type of the PII entity (e.g., "CREDIT_CARD", "PASSPORT"). Must contain only uppercase letters and underscores. |
| `piiRegex` | string | Yes | Regular expression pattern to match the PII entity. Must be a valid Go regexp pattern. |

#### JSONPath Support

`jsonPath` is an [RFC 9535](https://www.rfc-editor.org/rfc/rfc9535) JSONPath expression. It chooses which **string values** are masked. Keys, numbers, booleans and everything outside the selection are copied to the upstream unchanged, so a masked JSON request is always valid JSON.

- `"$"` or `""` — every string value in the payload is masked. This includes the system prompt and tool descriptions. It is the same coverage as earlier releases. A payload that is not JSON is masked as one piece of text.
- `$.messages[-1].content` (default) — the content of the last message.
- `$.messages[0].content`, `$.data.content`, `$.items[0].text` — a single value.
- Many values at once, using `[*]`, filters, unions and `..`.

A selected node that is not a string (an object or an array, such as a multimodal content array) is skipped. If the path matches nothing, the request passes through unmasked. A single-value path that does not exist returns an error, as in earlier releases. An invalid expression returns an error.

##### Mask only user and tool content (Anthropic Messages)

To keep the system prompt and tool definitions exactly as the application wrote them, and mask only what users and tools supplied:

```yaml
jsonPath: "$.messages[?(@.role=='user')]..['text','content']"
```

This selects the text of every user message, including tool results, which Anthropic sends in user messages. It does not select `system`, `tools`, or assistant turns.

> **Assistant turns are outside this selection.** When a client resends the conversation, the assistant's earlier replies contain the restored original values. With the path above those reach the model unmasked. To mask them too, select assistant content as well, for example `$.messages[*]..['text','content','thinking']`, which also covers assistant text and thinking blocks.

**Note:**

Inside the `gateway/build.yaml`, ensure the policy module is added under `policies:`:

```yaml
- name: pii-masking-regex
  gomodule: github.com/wso2/gateway-controllers/policies/pii-masking-regex@v1
```

## Reference Scenarios

### Example 1: Basic PII Masking

Deploy an LLM provider that masks email addresses and phone numbers in requests and restores them in responses:

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: LlmProvider
metadata:
  name: pii-masking-provider
spec:
  displayName: PII Masking Provider
  version: v1.0
  template: openai
  context: /openai
  upstream:
    url: "https://api.openai.com/v1"
    auth:
      type: api-key
      header: Authorization
      value: Bearer <openai-apikey>
  accessControl:
    mode: deny_all
    exceptions:
      - path: /chat/completions
        methods: [POST]
      - path: /models
        methods: [GET]
      - path: /models/{modelId}
        methods: [GET]
  operationPolicies:
    - name: pii-masking-regex
      version: v1
      paths:
        - path: /chat/completions
          methods: [POST]
          params:
            email: true
            phone: true
            jsonPath: "$.messages[-1].content"
            redactPII: true
```

**Test the guardrail:**

```bash
# Request with PII (should be masked)
curl -X POST http://localhost:8080/openai/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-4",
    "messages": [
      {
        "role": "user",
        "content": "Contact me at john.doe@example.com or call +1234567890"
      }
    ]
  }'
```

 **Sample Payload after intervention from Regex PII Masking with redactPII=true**

```json
{
  "messages": [
    {
      "role": "user",
      "content": "Prepare an email with my contact information, email: *****, and website: https://example.com."
    }
  ]
}
```

### Example 2: Streaming Response PII Restoration

When using masking mode with a streaming LLM endpoint, PII placeholders sent to the upstream are automatically restored in the SSE response stream:

```yaml
  operationPolicies:
    - name: pii-masking-regex
      version: v1
      paths:
        - path: /chat/completions
          methods: [POST]
          params:
            email: true
            phone: true
            jsonPath: "$.messages[-1].content"
            redactPII: false
```

When the upstream returns an SSE streaming response, the policy detects placeholders such as `[EMAIL_3fa91c0b]` in the delta content across chunk boundaries and restores them to the original PII values. The smart boundary detection ensures placeholders split across multiple SSE events (e.g., `[`, `EMAIL`, `_`, `3fa91c0b`, `]` arriving in separate tokens) are correctly reassembled before restoration.

## How It Works

#### Request Phase

1. **Content Selection**: Selects the string values to mask using `jsonPath`, or every string value for `"$"`. JSON bodies are never parsed and re-serialized: only the selected text is rewritten in place.
2. **PII Detection**: Applies each configured `piiRegex` pattern to detect matching PII entities.
3. **Intervention**: Replaces matches with placeholders (`[ENTITY_TYPE_XXXXXXXX]`) in masking mode or with `*****` in redaction mode.
4. **Metadata Storage**: Merges placeholder-to-original mappings into request metadata when masking mode is used. Several policy instances on one route add to the same mapping instead of overwriting each other.
5. **Forwarding**: Sends the transformed payload to the upstream service.

#### Response Phase

1. **Mapping Check**: Checks whether masking metadata is available from request processing.
2. **Restoration**: If `redactPII: false`, replaces placeholders with original values in the response.
3. **Redaction Preservation**: If `redactPII: true`, no restoration is performed.
4. **Response Return**: Returns restored or redacted content to the client.

#### PII Modes

- **Masking Mode (`redactPII: false`)**: Uses placeholders such as `[EMAIL_3fa91c0b]` and original PII values are stored temporarily in request metadata for restoration. Recommended when you need to preserve data for downstream processing or response generation
- **Redaction Mode (`redactPII: true`)**: Permanently replaces detected PII with `*****` and does not restore original values. Recommended for maximum privacy protection when original values are not needed

### Streaming (SSE) Processing

When the upstream returns an SSE streaming response, each SSE event arrives as a `data:` line containing a JSON payload, for example:

```
data: {"choices":[{"delta":{"content":"token"}}]}
```

Restoration needs a *complete* placeholder: an LLM emits `[EMAIL_3fa91c0b]` as several tokens (`[`, `EMAIL`, `_3fa9`, `1c0b]`), each in its own SSE event, so a chunk cut in the middle would match nothing and deliver the masked text to the client. The gateway therefore buffers response chunks on the policy's behalf and hands them over only once a placeholder cannot still be half-emitted:

1. **Response Mode Detection**: Each buffer handed to the policy is routed as SSE or plain-body by its own shape — SSE if it carries a `data:` or `event:` line. Because the gateway only releases a buffer on an SSE event boundary, a frame that is legitimately not data-shaped (a `: keep-alive` comment, for example) always travels with the events around it rather than being judged on its own.
2. **Delta Content Extraction**: The assistant text is extracted from each SSE `data:` line using an ordered list of JSONPath expressions — `choices[0].delta.content` for OpenAI-compatible providers, `delta.text`, `delta.partial_json` (tool-call arguments) and `delta.thinking` for Anthropic, `candidates[0].content.parts[0].text` for Gemini, `contentBlockDelta.delta.text` for Bedrock Converse, and so on. The paths are tried in order and the first match wins, so no provider is special-cased.
3. **Placeholder Boundary Detection**: The policy asks the gateway to keep buffering while the assembled assistant text ends in an unclosed `[` whose trailing characters could still complete a placeholder. Because a placeholder is always an uppercase entity name followed by eight hexadecimal digits (`[EMAIL_3fa91c0b]`), any other character after the bracket — a space, lowercase prose, punctuation — proves nothing restorable is arriving, and the stream is released on the spot. Buffering stops as soon as the bracket closes, as soon as the text stops looking like a placeholder, at end of stream, or once 64 bytes have accumulated after the bracket, whichever comes first. This test is on the assembled text rather than on how many events it spans: there is no limit on the number of SSE events buffering may continue across, so a placeholder emitted one character per event is held exactly as long as one emitted whole. Buffering also continues across a partially received event, since a truncated JSON payload has no readable content.
4. **Placeholder Restoration**: When a buffer is released, the text of the events that belong to the same content block (same `index` and same kind: text, tool-call arguments or thinking) is concatenated, placeholders are restored to their original PII values, and the restored text is written back through the same JSONPath it was extracted from, into that block's first event. Text from a different content block in the same buffer is restored on its own and stays in its own event. Restored values inside tool-call arguments are JSON-escaped, because the argument text is itself JSON. Each subsequent merged event of a block is dropped as a complete block — its `event:` field line and trailing blank separator go with its `data:` line — so the stream stays well-formed for providers that label every event. Comments, `[DONE]`, and usage frames keep their original position.
5. **Redaction Mode**: When `redactPII: true`, no restoration is performed in the response phase, so the policy never asks for buffering and chunks pass straight through.
6. **Error Handling**: Since HTTP response headers are already committed when streaming begins, errors cannot be reported via HTTP status codes. If an error occurs during restoration, the chunk passes through unmodified.

**Non-SSE chunked responses**: For plain JSON responses delivered via chunked transfer encoding (e.g., `stream: false` with `Transfer-Encoding: chunked`), the body is accumulated until it parses as complete JSON, then restored and forwarded in one piece. Such a response is not incrementally consumable anyway, so buffering it costs no perceived latency, and it guarantees no placeholder is split across two flushes.

**Compressed responses**: `gzip`, `br`, `zstd` and `deflate` responses are decompressed by the gateway before this policy runs and re-compressed afterwards, so restoration works normally and the policy itself is encoding-agnostic. If an upstream answers in an encoding the gateway cannot round-trip, the response is rejected rather than forwarded uninspected, so a masked placeholder is never silently delivered because restoration did not run.

#### Processing Behavior

- Supports multiple entity patterns in one policy and processes each detected match by entity type.
- Placeholder format is `[ENTITY_TYPE_XXXXXXXX]`, where `XXXXXXXX` is 8 hexadecimal digits derived from the value. The same value always gets the same placeholder, on every request and in every turn of a conversation, whatever else is in the request.
- Every string value is processed when `jsonPath` is `"$"` or empty.

## Notes

- Common use cases include privacy protection, compliance (GDPR/CCPA/HIPAA), data minimization, secure AI processing, and audit-friendly masking workflows.
- Regular expressions use Go's regexp package (RE2 syntax).
- PII detection is case-sensitive by default. Use `(?i)` flag for case-insensitive matching.
- The `piiEntity` name must contain only uppercase letters and underscores (e.g., "EMAIL", "PHONE_NUMBER", "SSN").
- When using masking mode, the placeholder-to-original mapping is stored in request metadata and automatically used for response restoration.
- Multiple PII entities can match the same content; each match is processed according to its entity type.
- Placeholder format is `[ENTITY_TYPE_XXXXXXXX]` where XXXXXXXX is an 8-digit hexadecimal number derived from the value (e.g., `[EMAIL_3fa91c0b]`).
- When using a single-value JSONPath, if the path does not exist an error response (HTTP 500) is returned. A selected value that is not a string is skipped.
- Redaction mode is irreversible; use masking mode if you need to restore PII in responses.
- In streaming mode, `redactPII: true` disables response-phase processing entirely since there is nothing to restore. Chunks pass through without buffering overhead.
- In streaming mode, buffering continues only while the text after an unclosed `[` could still complete a placeholder, and never holds back more than 64 bytes of assistant text. Restoration does not depend on how finely the upstream tokenises a placeholder or on where chunk boundaries fall.
- The built-in `phone` and `ssn` patterns never match inside a longer run of digits, so a 13-digit timestamp or a long identifier is not cut up. A standalone phone-shaped number is still masked, including an unformatted 10-digit one such as `4155550199`. Digits alone cannot tell such a number from a phone number. To narrow detection, use `customPIIEntities` with a stricter pattern, for example one that requires separators.
- Complex regex patterns may impact performance; test thoroughly with expected content volumes.

## What changed in v1.2

- **Valid JSON, always.** With `jsonPath: "$"` the policy used to mask the raw JSON text, so an email after an escape such as `\n` produced invalid JSON, and the phone pattern rewrote numbers. It now masks only the text of string values and copies every other byte unchanged. If masking would still produce invalid JSON, the request is rejected with a gateway error instead of being forwarded.
- **Choose what is masked.** `jsonPath` accepts RFC 9535 expressions that select many values, so the system prompt and tool definitions can be left alone. `"$"` still masks every string value, as before.
- **Stable placeholders.** Placeholders are derived from the value instead of a counter. This keeps prompt caching and preserved reasoning working across requests and turns, for any combination of entity types. **The placeholder text changed** from `[EMAIL_0000]` to `[EMAIL_3fa91c0b]`; anything downstream that matches the old format needs updating.
- **Streaming restore.** Streamed tool-call arguments and thinking are restored, and each content block keeps its own text when several blocks arrive in one flush.
- **Several instances on one route** no longer overwrite each other's mapping.
- **Phone and SSN** patterns no longer match inside a longer run of digits. Everything else they matched is still masked.

## Fault reporting

From v1.1, every rejection this policy makes is also reported to the gateway as a **fault**:
a stable code and type alongside the response. A gateway that supports fault policies uses it
for the analytics event and hands it to the API's fault policies (for example `log-message`, to
log the failure). The status and body the client receives are the same as in v1.0. A gateway
without fault policy support ignores the fault, and the policy behaves exactly as v1.0.

Masking happens on the request; restoring placeholders in the response never rejects it.

| When | Status | Code | Type |
|------|--------|------|------|
| Request: the value at `jsonPath` cannot be extracted | `500` | `960000` | `mediation` |
| Request: masking the detected PII fails | `500` | `960000` | `mediation` |
| Request: masking would produce an invalid JSON body | `500` | `960000` | `mediation` |

The fault carries no `Description`. Its `Message` holds the reason the response body already
returns, for example `Error occurred during pii-masking-regex mediation: error masking PII: ...`.
