# shieldstral

Checks request and/or response text against safety rules written in plain language, using a
self-hosted [Shieldstral 1.0 3B](https://docs.mistral.ai/resources/cookbooks/mistral-moderation-shieldstral_policy_moderation)
classifier. There is no Mistral-hosted API for Shieldstral: you run it (the cookbook uses
`vllm serve mistralai/Shieldstral-1.0-3B --max-model-len 32768`) and point the gateway at it.

## How it works

A rule is a yes/no question phrased so that "yes" means a violation. For each rule the policy sends
the model exactly the prompt layout from Mistral's cookbook (fixed system prompt; user message
`<Instruct>: ...\n\n<Query>: ...\n\n<Document>: ...`), with `max_tokens: 1`, `temperature: 0`,
`logprobs: true`, `top_logprobs: 20`. The score is `P(yes) = e^zYes / (e^zYes + e^zNo)` from the first
token's logprobs (`yes`, `yes.`, `"yes"`, `'yes'` and the `no` variants). Content is blocked when a
rule's score is **above** its threshold (default 0.5; Mistral suggests 0.3 for strict, 0.7 for
permissive). Rules run in parallel, one call each, so keep the list short (maximum 10).

Differences from the cookbook's reference code, on purpose:

- If neither `yes` nor `no` appears in the top logprobs the model did not answer; that is an error
  (503), not a silent 0.5.
- The reference floors both logprobs at -10, which turns two very negative answers into exactly 0.5.
  Here only an *absent* side takes -10.
- Section markers in the moderated text (`<Query>:`, `<Document>:`, `<Instruct>:`) are rewritten to
  `[Query]:` etc., so content cannot pose as a new section of the prompt.

## Parameters

Gateway-level (config.toml keys, or per attachment): `endpoint` (required, e.g.
`http://shieldstral:8000`), `apiKey` (optional bearer token), `model` (default
`mistralai/Shieldstral-1.0-3B`), `timeout` (seconds per rule, retries included, default 10).

Under `request` and/or `response` (at least one):

| Parameter | Default | |
|---|---|---|
| `rules` | required | 1-10 of `{name, query, threshold?, instruction?}`; `name` unique, `[A-Za-z0-9._-]` |
| `jsonPath` | `$.messages[-1].content` / `$.choices[0].message.content` | Text to classify. Full JSONPath: `$.messages[*].content`, `$.messages[?(@.role=='user')].content`, ... Empty = the whole body |
| `streamingJsonPath` | `$.choices[0].delta.content` | *Response only.* Text inside one SSE frame |
| `streamingTextUnitChars` | `1000` | *Response only.* Characters gathered per check while streaming; `0` or at least 100; `0` = once, at the end |
| `instruction` | "You are a strict safety moderator reviewing potentially harmful content. Apply a low tolerance threshold." | Sent with every rule; a rule can override it |
| `maxContentChars` | `40000` | Longer text is a failed check (503), never truncated |
| `blockStatusCode` | `422` | 400-599 |
| `passthroughOnError` | `false` | Let content through if the classifier fails or the body is not valid JSON |
| `showAssessment` | `false` | Every rule with its score and threshold in the error body (never the text) |

Example rules: "Does this content contain hate speech targeting a protected group?", "Does this
content provide specific financial investment advice?", "Does this content contain personally
identifiable information such as phone numbers, addresses, or social security numbers?"

## Behaviour worth knowing

- Fails closed: a classifier failure returns **503** unless `passthroughOnError` is true. If one
  rule violates and another fails, the violation wins.
- Retries once on network errors, 429 and 5xx, inside the `timeout` budget.
- Non-2xx **upstream** responses are not classified.
- **Several texts** from one payload (a wildcard over all messages) are joined with newlines into one
  document, so each rule is still one call.
- **Streaming (SSE)** responses are held and classified in batches; see the top-level README. Every
  batch costs one call per rule, so a long reply at the default 1000-character unit is
  `rules x (length / 1000 + 1)` calls.
- A path that selects nothing, or nothing with text (a provider error body that arrives with
  HTTP 200, a tool-call message with `content: null`), means there is nothing to check and the
  payload passes. Only a body that is not valid JSON is treated as unreadable.
- Added latency is roughly one classifier call (rules run concurrently), and GPU capacity is
  consumed `rules x requests`.
- Fault code on a violation is `906099` (unsafe content); `960000` when the check itself failed.

## Not verified against the real model

Tested against a mock that returns vLLM-shaped logprobs. Not confirmed on real hardware: that your
vLLM version returns `top_logprobs` for the first token exactly as the cookbook parses it, the
model's name as your server reports it (`model`), and how scores for your own rules are
distributed, which you should check on a labelled sample before choosing thresholds.

## Not supported

Images (the model is multimodal; this policy sends text only, and image parts are skipped), multi-turn
context beyond what the path selects, chunking of long documents (over `maxContentChars` is a failed
check), and function calls inside JSONPath filters.
