# mistral-moderation

Moderates request and/or response text with the [Mistral Moderation API](https://docs.mistral.ai/capabilities/guardrailing)
(`POST /v1/moderations`, bearer-token auth).

## How a verdict is reached

The API returns, per category, a 0-1 score and a boolean flag (Mistral's own calibrated decision).
For each category:

1. an entry in `categoryThresholds` decides: block when `score >= threshold`; a threshold of `1`
   disables the category;
2. otherwise the category is skipped if `ignoreOtherCategories` is set or the category is in
   `ignoredCategories` (default: `health`, `financial`, `law`, `pii`, which describe subject
   matter rather than harm);
3. otherwise Mistral's flag decides.

Categories are not hard-coded: `mistral-moderation-2411` and `-2603` report different sets
(2603 adds `jailbreaking` and splits dangerous/criminal), and the policy uses whatever comes back.

## Parameters

Gateway-level (config.toml keys, or per attachment): `apiKey` (required), `endpoint`
(default `https://api.mistral.ai`), `model` (default `mistral-moderation-latest`), `timeout`
(seconds, total including retries, default 10).

Under `request` and/or `response` (at least one):

| Parameter | Default | |
|---|---|---|
| `jsonPath` | `$.messages[-1].content` / `$.choices[0].message.content` | Text to moderate. Full JSONPath: `$.messages[*].content`, `$.messages[?(@.role=='user')].content`, ... Empty = the whole body |
| `categoryThresholds` | none | `{category: 0-1}` |
| `ignoreOtherCategories` | `false` | Enforce only the categories in `categoryThresholds` |
| `ignoredCategories` | `[health, financial, law, pii]` | Replaces the default list |
| `streamingJsonPath` | `$.choices[0].delta.content` | *Response only.* Text inside one SSE frame |
| `streamingTextUnitChars` | `1000` | *Response only.* Characters gathered per check while streaming; `0` or at least 100; `0` = once, at the end |
| `maxContentChars` | `100000` | Total text per payload; more is a failed check (503), never truncated |
| `blockStatusCode` | `422` | 400-599 |
| `passthroughOnError` | `false` | Let content through if the API call fails or the body is not valid JSON |
| `showAssessment` | `false` | List violated categories and scores in the error body (never the text) |

## Behaviour worth knowing

- Fails closed: an API failure returns **503** unless `passthroughOnError` is true.
- Retries up to 3 attempts on network errors, HTTP 429 and 5xx (honouring `Retry-After`, capped at
  2 s), all inside the `timeout` budget. A 401/403 or malformed reply is not retried.
- Non-2xx **upstream** responses are not moderated (the jsonPath would not resolve against an error
  body).
- **Several texts** from one payload (a wildcard over all messages) go to the API as one `input`
  array, 20 per call, concurrently; a payload may yield at most 100 texts. A violation in any text
  blocks; the report keeps the strongest score per category.
- **Streaming (SSE)** responses are held and checked in batches; see the top-level README.
- Empty or whitespace-only text, or a path that selects no text, makes no API call.
- A path that selects nothing, or nothing with text (a provider error body that arrives with
  HTTP 200, a tool-call message with `content: null`), means there is nothing to check and the
  payload passes. Only a body that is not valid JSON is treated as unreadable.
- Pin a dated model in production. Mistral notes that scores are recalibrated between versions, so
  thresholds written against one version may need revisiting on the next.
- Fault codes: `906001` hate, `906002` sexual, `906003` self-harm, `906004` violence, `906006`
  dangerous/criminal, `906008` jailbreaking (reported as prompt injection), `906101` PII, `906099`
  anything else; `960000` when the check itself failed.

## Not verified against the real service

Built from Mistral's public documentation and tested against a mock. Not confirmed with a live key:
the exact category keys of `mistral-moderation-2603` for Dangerous and Criminal (matching is by
substring, so `dangerous`, `criminal` and `dangerous_and_criminal_content` all map to `906006`),
the API's rate limits, and its maximum input size. Run one real request before relying on it.

## Not supported

`/v1/chat/moderations` (conversation-aware moderation); images and other non-text parts (skipped);
function calls inside filters (`length()`, `match()`).
