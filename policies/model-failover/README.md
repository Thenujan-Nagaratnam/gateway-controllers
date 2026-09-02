# model-failover

Transparently retries a failed LLM request against an ordered fallback chain. Fully standalone
— gateway-controller has no awareness of this policy at all.

## What it does

- Selects a target chain by matching the client's own `request.body.model` against a declared
  `targets[].model`. A request for a model that isn't declared passes through completely
  untouched — no mutation, no retry.
- On a response whose status is in `statusCodes`, walks that target's `fallbacks[]` in order
  (skipping any currently-suspended entry) until one succeeds or the chain is exhausted.
- A target can also redirect its own **primary** attempt (not just its fallbacks) if the
  operation's default upstream can't serve that model at all — see "Target-level override"
  below.

## Two kinds of fallback/override, two different mechanisms

Every `target`/`fallback` entry sets at most one of `provider` or `upstreamDefinition` (target
only). Which one is set decides how the dial happens:

- **None set — reuse the primary's own backend.** The fallback just retries the same upstream
  the primary already resolved to, with a different `model` in the body. Original credential
  reused unchanged.
- **`upstreamDefinition: <name>`** (target-level only) — redirects the primary attempt via an
  in-process Envoy `UpstreamName` swap to an already-declared `spec.upstreamDefinitions` entry.
  No extra network hop; Envoy's own routing resolves the name at runtime, so this policy needs
  nothing pre-resolved.
- **`provider: <id>`** (target- or fallback-level) — the only one that crosses providers. Never
  carries its own url/auth/template. Resolved entirely at runtime via a **self-redial** — see
  below.

## The self-redial mechanism (for `provider`)

- The policy dials **this same operation's own externally-facing URL again**
  (`selfBaseURL` + the original downstream path) with an `x-provider: <id>` header set.
- From Envoy's point of view this is a genuinely fresh inbound request, so it re-runs the
  **entire policy chain** from scratch — not something this policy simulates itself.
- That only does something useful if the operator has attached a header-based provider
  selector policy (e.g. `llm-header-router`) to the same operation, reading `x-provider` and
  publishing `SharedContext.Metadata["selected_provider"]`. Without one attached, a `provider`
  reference silently reaches the operation's own default upstream, unchanged.
- Once published, the provider's own already-attached conditional policies fire for real: the
  matching translator (full bidirectional body conversion) and the upstream-auth policy
  (credential injection) — both already-shipped, general-purpose policies used for any other
  multi-provider proxy. This policy never resolves or applies either itself, and carries no
  per-vendor adapter of its own.
- **Why a self-redial and not a request-phase redirect:** the auth policy is a
  request-**header**-phase-only policy. The kernel runs every policy's header-phase hook to
  completion for the *whole* chain before any policy's body-phase hook runs at all. This policy
  can only ever decide "redirect to provider X" in body phase — it has to see the client's
  `model` field first. A signal produced in body phase is always one phase too late for a
  header-phase-only gate to see. Publishing the selection via a real header (which *is*
  available at header-phase time) sidesteps that ordering problem instead of fighting it.

## Recursion guard

- A provider self-redial re-enters the *same* operation, which still has this policy attached.
  Without a guard, the redialed request's own `OnRequestBody` would see the same unchanged
  client model and try to redirect it all over again, forever.
- Guarded by a dedicated header, `x-wso2-model-failover-redial`, set only on this policy's own
  redial and checked first in **both** `OnRequestBody` and `OnResponseHeaders`.
- Deliberately **not** the pre-existing `x-wso2-internal-loopback` header: gateway-controller's
  own loopback-marker policy stamps that one unconditionally on *every* request through an
  `additionalProviders` proxy, including a client's genuine first request. Using it as the
  guard would have silently swallowed all real traffic — found via live testing, not review.
- A client spoofing the redial header themselves just means failover doesn't apply to that one
  request — never a routing or auth bypass.
- **Why `OnResponseHeaders` needs the same guard, not just `OnRequestBody`:** if a redial's own
  response also fails, and its model happens to also be declared as its own independent
  `targets[]` entry (or a cycle of them), `OnResponseHeaders` would otherwise walk *that*
  target's own fallback chain too — a nested failover triggered by a redial, not by the
  original client request. A cyclic config (fallback A's model is target B, whose fallback's
  model is target A again) would recurse indefinitely with nothing to stop it. The guard makes
  a redial's outcome decided exactly once, by the `tryProviderRedial`/`doDial` call that
  originated it (which independently checks `statusCodes` against the raw response) — never by
  a second, nested walk from inside the redial's own response processing. Only the original,
  non-redialed request's own failure ever drives a fallback walk.

## Downstream (client-to-gateway) auth on the self-redial

- The redial carries the client's original credential (`Authorization`, `x-api-key`, etc.)
  through **unchanged** — it is never stripped.
- This matters because those same headers are also what a client uses to authenticate to the
  gateway itself. If this operation has its own downstream auth (`api-key-auth`, `jwt-auth`,
  anything), the redial needs to present a valid credential to pass that check, exactly like
  any other request would.
- This doesn't leak the client's credential to the wrong backend for a correctly-configured
  provider: the provider's own conditional upstream-auth policy runs later in this same
  request-phase chain and overwrites the credential header with the real upstream credential
  before the request ever leaves the gateway.
- One gap this doesn't cover: a provider declaring `auth: none`/`other` with nothing else
  attached to set a credential — there the client's own credential could reach that backend
  unchanged. That's the operator's own multi-provider configuration responsibility, not
  something specific to a redial.

## Path handling

- A raw dial reusing the primary's own backend appends `SharedContext.OperationPath` (the
  operation-relative path, e.g. `/chat/completions`) to the target URL — **not** the client's
  full downstream path, which includes this proxy's own context prefix (e.g.
  `/mf-poc-proxy/chat/completions`) and would be wrong on a real backend.
- A provider self-redial appends the **full downstream path** instead (via
  `Downstream.Request.Path`), since it needs Envoy to re-match the *same* operation, not some
  operation-relative fragment.

## What gateway-controller does and doesn't do

- Nothing. gateway-controller has zero special-case code for this policy — no validation, no
  resolution, no auto-attached policies. Its only involvement anywhere in the repo is the
  `filePath` build entry needed to compile the policy in at all.
- The operator is fully responsible for attaching a provider selector (e.g.
  `llm-header-router`) and the relevant translator(s) alongside `model-failover` if they want
  `provider` references to actually reach anywhere — the same way any other multi-provider
  proxy is wired up on this platform.

## Choosing `statusCodes`

- Mandatory, no default. Every example in this doc uses `[500]` for brevity, but that alone is
  a dangerously narrow assumption — real providers signal a model/capacity problem through a
  much wider, and inconsistent, set of codes.
- Researched directly against each provider's own current docs (2026-09):
  - **OpenAI**: `429` (rate limit/quota), `500`, `503` (engine overloaded).
  - **Anthropic**: `404` (unknown/stale model), `429`, `500`, `529` (overloaded —
    Anthropic-specific; not the standard `503`).
  - **AWS Bedrock**: `404` (`ResourceNotFoundException`), `408` (`ModelTimeoutException`), `424`
    (`ModelErrorException` — Bedrock-specific, HTTP's rarely-used Failed Dependency code),
    `429` (`ThrottlingException` **and** `ModelNotReadyException`), `500`, `503`. Quota-exceeded
    is `400` here (`ServiceQuotaExceededException`), not `429` — decide deliberately whether to
    include it.
  - **Azure OpenAI**: `404` (deployment not found), `429`, `500`, `503`.
  - **Google Gemini**: `404` (`NOT_FOUND`), `429` (`RESOURCE_EXHAUSTED`), `500`, `503`
    (`UNAVAILABLE`).
  - **Mistral**: `429`, `500`, `502`, `503`, `504`.
- **Why there's no built-in default.** The set that actually matters is genuinely
  provider-specific — Anthropic's `529` and Bedrock's `424` don't exist anywhere else, and
  Bedrock alone puts quota-exceeded on `400` where every other provider here uses `429`. A single
  hardcoded default would have to either omit a real provider's outage signal or be broad enough
  to start treating a plain client-caused `4xx` as a trigger for an expensive cross-provider
  fallback. Since a fallback chain commonly spans more than one provider at once, no fixed list
  is correct for every member of that chain simultaneously — only the operator configuring that
  specific chain knows which codes belong.
- **`429` deserves a deliberate decision, not a reflexive include.** It may be better served by
  backoff-and-retry against the *same* backend (respecting `Retry-After`) than by immediately
  paying for a cross-provider fallback attempt — include it only if that trade-off is the one
  you actually want.

## Suspend tracking

- Optional (`suspendDuration`), in-memory only, never shared across replicas.
- A fallback that fails is deprioritized (tried last, not dropped) for future requests to that
  same target group, for the configured duration.
- Never applies to a target's own primary attempt — only to entries in its `fallbacks[]`.

## Response short-circuiting

- A successful dial short-circuits the operation's policy chain immediately (`ImmediateResponse`)
  — any policy declared *after* `model-failover` in the same operation (analytics, PII masking,
  anything) never runs for that response. Policies declared *before* it already had their
  normal turn.
- The redial itself is unaffected by this: it's a fully independent request from Envoy's point
  of view and runs the *entire* chain from the top on its own.
