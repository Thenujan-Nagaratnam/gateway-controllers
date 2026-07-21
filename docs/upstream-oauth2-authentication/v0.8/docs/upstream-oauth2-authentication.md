---
title: "Overview"
---
# Upstream OAuth2 Authentication

## Overview

The **OAuth2** policy authenticates outbound requests to an upstream backend
using OAuth2 before they are forwarded. The gateway acts as a confidential
client: it exchanges credentials for a short-lived access token at a
configured token endpoint, then injects the token as an
`Authorization: Bearer` header on the proxied request.

This is the policy to use when an upstream — an LLM provider, an internal
service, or any backend fronted by a standard OAuth2 token endpoint — requires
a bearer token rather than a static, pre-shared API key.

The grant used is selected via `grantType`:

- [Client Credentials](https://datatracker.ietf.org/doc/html/rfc6749#section-4.4)
  (RFC 6749 §4.4) — the standard machine-to-machine grant. **Prefer this
  whenever the upstream identity provider supports it.**
- [Resource Owner Password Credentials](https://datatracker.ietf.org/doc/html/rfc6749#section-4.3)
  (RFC 6749 §4.3) — supported for bridging to legacy identity providers that
  only expose this grant. See the security note below before using it.

`grantType` is a first-class parameter specifically so further grants can be
added later without a breaking change to this policy's configuration shape.

The client ID and secret are presented to the token endpoint per
`clientAuthMethod`:

- `client_secret_basic` (default) — HTTP Basic auth, the convention RFC 6749
  recommends when the identity provider supports it.
- `client_secret_post` — `client_id`/`client_secret` sent as form fields in
  the token request body instead, for identity providers that require this.

Both values apply identically to either `grantType`.

> **Security note on the password grant:** current OAuth2 security guidance
> (RFC 6749 §4.3 itself, and the OAuth 2.0 Security Best Current Practice)
> discourages the password grant for new integrations, because it requires
> the client — the gateway, in this case — to handle the resource owner's raw
> username and password directly, rather than the identity provider
> collecting them from the user in its own trusted context. Use
> `client_credentials` whenever the identity provider supports it; reach for
> `password` only when bridging to a legacy IdP that has no other option.

## Features

- OAuth2 Client Credentials grant (RFC 6749 §4.4) against any standard token
  endpoint
- OAuth2 Resource Owner Password Credentials grant (RFC 6749 §4.3), for
  legacy identity providers — see the security note above
- `grantType` as an explicit, forward-compatible parameter selecting between
  the two
- `clientAuthMethod` selects how `clientId`/`clientSecret` are presented to
  the token endpoint — `client_secret_basic` (default, HTTP Basic auth) or
  `client_secret_post` (form fields) — applies to both grants
- **Redis-backed token cache** shared across every gateway-runtime replica,
  keyed by the oauth2 configuration itself rather than by API/route identity,
  with a per-process in-process cache in front of it for the hot path (see
  Caching below)
- Optional `params` — arbitrary extra token-request form fields (e.g.
  `scope`), forwarded verbatim for `client_credentials`
- `tokenRequestTimeout` bounds every token-endpoint HTTP call (default `10s`)
  — an unresponsive identity provider can't block a token fetch indefinitely
- `defaultTokenTTL` (default `1h`) keeps caching working even when the
  identity provider's response omits `expires_in` entirely
- Preserves any existing authentication context set by an earlier (inbound)
  auth policy

## Caching

Access tokens are cached in two tiers:

1. **In-process (local):** the last known-good token is held in memory by
   the policy instance. As long as it's still valid, `Token()` returns
   immediately — no Redis round trip, no network call.
2. **Redis (shared):** when the local cache misses (first request after
   startup, or the local token expired), the policy checks Redis before
   falling back to the token endpoint. This means:
   - Every `gateway-runtime` replica converges on the **same** token instead
     of each independently calling the identity provider.
   - A replica restart doesn't force a fresh token fetch if another replica
     already cached one.

Redis is an **optimization layered on top of the token endpoint, not a hard
dependency**. If Redis is unreachable, `systemParameters.redis.failureMode`
controls what happens:

- `open` (default): after a local in-process cache miss or expiry, fall back
  to fetching directly from the token endpoint if Redis is also unavailable
  - not on every request, since a valid in-process token is still served
  without ever consulting Redis or the token endpoint. A Redis outage costs
  you the cross-replica sharing benefit, not authentication itself.
- `closed`: treat the Redis error as a token-acquisition failure (the same
  generic `502` as any other failure below) — for deployments that want to
  guarantee a Redis-down condition is surfaced rather than silently degraded.

### Cache key: derived from the oauth2 configuration itself

Cache entries are keyed by a SHA-256 hash of the oauth2 configuration that
determines what access token the token endpoint would issue and who is
entitled to receive it — `grantType`, `tokenEndpoint`, `clientId`,
`clientAuthMethod`, `username`, `params` (`scope` and any other extra form
fields), and a SHA-256 hash of `clientSecret`/`password` (the raw secret
itself is never put into the key material — Redis key names can appear in
`MONITOR`/slowlog output). This is computed once when the policy instance is
constructed, from the already-validated configuration — not resolved from
`SharedContext` or anything else request-time, and not scoped by API or
route identity at all.

This has two deliberate consequences:

- **Two different APIs with byte-identical `oauth2` config share one cached
  token.** If two `LlmProvider`s (or an `LlmProxy`'s primary provider and one
  of its `additionalProviders` entries) configure the exact same
  `tokenEndpoint`/`clientId`/`clientSecret`/..., they are the same caller as
  far as the identity provider is concerned, so sharing is correct and saves
  a redundant token-endpoint call.
- **Any change to the oauth2 configuration produces a different key.**
  Rotating `clientSecret` or `password`, or changing `grantType`,
  `clientAuthMethod`, `tokenEndpoint`, or `params` (including `scope`), all
  change the hash. The old entry isn't actively deleted, but the new
  configuration never looks it up again — it simply ages out via its own
  TTL. A configuration change is therefore guaranteed to fetch a fresh token
  under the new configuration rather than reuse one minted under the old
  one, whether or not the two configurations happen to be attached to the
  same API or route.

An earlier design keyed the cache by API/route identity (`apiId`, itself
falling back to `SharedContext.APIName:APIVersion` and finally the route's
own name) instead of by configuration. That had a real gap: since two
different oauth2 configs can be attached to the very same API — a proxy's
primary provider and an `additionalProviders` entry, in particular — keying
by API/route identity alone let one config's legitimately-cached token be
served to a request that presented entirely different (including outright
wrong) credentials, as long as it landed on the same API/route. Deriving the
key from the configuration itself instead closes that gap and, as a side
effect, means every configuration change is automatically cache-safe with no
separate invalidation step required.

The Redis TTL on each entry is derived from the token's own `expires_in` when
the identity provider returns one — see "When the identity provider omits
`expires_in`" below for what happens when it doesn't.

### When the identity provider omits `expires_in`

Some identity providers don't return `expires_in` at all. `golang.org/x/oauth2`
leaves the token's expiry as the zero value in that case, and treats a
zero-value expiry as always-already-expired — without a fallback, this would
mean *neither* cache tier ever considers the token cacheable, silently
forcing a fresh token fetch on every single request. `defaultTokenTTL`
(default `1h`) is applied only in this specific case, as a fallback estimate
for how long the token is likely valid — it has no effect when the identity
provider does return `expires_in`, which is authoritative and always takes
precedence. Because it's only an estimate, not a fact reported by the
identity provider, `defaultTokenTTL` is also what bounds how long a cached
token can be reused after the real, unreported expiry has already passed:
set it conservatively for any identity provider that omits `expires_in`,
since setting it too high risks the cache serving a token the identity
provider itself would already reject.

## Configuration

### User Parameters (API Definition)

Business configuration — including credential material — is set per-API in
the API definition, the same as every other policy parameter.

| Parameter | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `grantType` | string | No | `client_credentials` | `client_credentials` or `password`. See the security note above before using `password`. |
| `tokenEndpoint` | string | Yes | | URL of the OAuth2 token endpoint this policy calls to obtain an access token. |
| `clientId` | string | Yes | | OAuth2 client ID used to authenticate to the token endpoint. |
| `clientSecret` | string | Yes | | OAuth2 client secret paired with `clientId`. |
| `clientAuthMethod` | string | No | `client_secret_basic` | `client_secret_basic` (HTTP Basic auth) or `client_secret_post` (form fields). Applies to both grants. |
| `username` | string | Only when `grantType` is `password` | | Resource owner username. Unused for `client_credentials`. |
| `password` | string | Only when `grantType` is `password` | | Resource owner password, paired with `username`. Unused for `client_credentials`. |
| `params` | object (string map) | No | | Optional extra form fields sent verbatim to the token endpoint, merged into the request body alongside `grant_type` and the grant's own fields. Only applies when `grantType` is `client_credentials` — the password grant's request body is fixed. The primary use is `scope` (e.g. `params: {scope: "read write"}`), but also covers IdP-specific fields such as `resource`, `audience`, or `tenant`. |
| `tokenRequestTimeout` | string (Go duration) | No | `10s` | Maximum time to wait for a single token-endpoint HTTP call. Applies to both grants. |
| `defaultTokenTTL` | string (Go duration) | No | `1h` | Fallback token lifetime used only when the token endpoint's response omits `expires_in` — see "When the identity provider omits `expires_in`" above. Applies to both grants. |

> **Security note:** Because credential material is set directly on the API's
> own policy configuration (rather than resolved from operator-controlled
> gateway configuration), access to API definitions containing this policy
> should be restricted accordingly. This applies with extra weight to
> `password`, since it is an end user's own credential, not a
> service-to-service secret.

### System Parameters (Gateway/Operator-Level)

Unlike the user parameters above, `systemParameters.redis.*` are
operator/gateway-level settings, not something an individual API publisher
sets per API — resolve them once for the whole gateway via
`config.policy_configurations.upstream_oauth2_v1.redis.*` in the gateway's own
configuration (the same mechanism the `advanced-ratelimit` policy uses for
its own Redis settings). Every field below has a default, so omitting the
whole `redis` block is always valid — the policy just runs with a local
Redis on `localhost:6379` and no auth, or degrades to no shared cache at all
if that's unreachable (per `failureMode`).

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `redis.host` | string | `localhost` | Redis host name or IP address. |
| `redis.port` | integer | `6379` | Redis server port. |
| `redis.username` | string | *(none)* | Optional Redis ACL username. |
| `redis.password` | string | *(none)* | Optional Redis authentication password. |
| `redis.db` | integer | `0` | Redis logical database index. |
| `redis.keyPrefix` | string | `upstream-oauth2:token:v1:` | Prefix applied to every cached-token key. |
| `redis.failureMode` | string | `open` | `open` or `closed` — see Caching above. |
| `redis.connectionTimeout` | string (Go duration) | `5s` | Redis dial timeout. |
| `redis.readTimeout` | string (Go duration) | `3s` | Redis read timeout. |
| `redis.writeTimeout` | string (Go duration) | `3s` | Redis write timeout. |
| `redis.poolSize` | integer | `0` (go-redis default: 10 × GOMAXPROCS) | Connection pool size for the shared client. |

**Note:**

Inside the `gateway/build.yaml`, ensure the policy module is added under `policies:`:

```yaml
- name: oauth2
  gomodule: github.com/wso2/gateway-controllers/policies/upstream-oauth2-authentication@v0
```

## How It Works

1. **Header phase** – Injecting a bearer token needs no request body
   inspection, so this policy processes the request-header phase only; the
   request body is never buffered by this policy.
2. The policy checks its in-process cache, then Redis, then (only on a
   double miss) calls the token endpoint using the configured `grantType`,
   presenting `clientId`/`clientSecret` per `clientAuthMethod` — see Caching
   above for the full fallback order, cache-key scope, and `failureMode`
   behavior.
   - For `client_credentials`, a fresh fetch is a standard `client_credentials`
     token request, with any `params` merged into the request body.
   - For `password`, a fresh fetch re-presents `username`/`password` — this
     policy always re-authenticates with the resource owner's credentials
     rather than relying on a `refresh_token`, since not every identity
     provider issues one for this grant. `params` has no effect on this
     grant.
3. The resulting `Authorization: Bearer <token>` header is set on the request
   before it is forwarded upstream.
4. If the token cannot be obtained (network failure, invalid credentials, or
   a malformed token-endpoint response), the request is short-circuited with
   `502 Bad Gateway` — this reflects a gateway-to-backend authentication
   failure, not an inbound-client authentication rejection.

## Reference Scenarios

### Example 1: Azure OpenAI via an Entra ID App Registration

```yaml
apiVersion: gateway.api-platform.wso2.com/v1alpha1
kind: LlmProvider
metadata:
  name: azure-openai-gpt4
spec:
  displayName: Azure-OpenAI-GPT4
  upstream:
    main:
      url: https://my-resource.openai.azure.com
  policies:
    - name: oauth2
      version: v0
      params:
        tokenEndpoint: https://login.microsoftonline.com/<tenant-id>/oauth2/v2.0/token
        clientId: <app-registration-client-id>
        clientSecret: <app-registration-client-secret>
        params:
          scope: https://cognitiveservices.azure.com/.default
```

### Example 2: A Self-Hosted Model Server Behind an OAuth2 Proxy

```yaml
  policies:
    - name: oauth2
      version: v0
      params:
        tokenEndpoint: https://auth.internal.example.com/oauth2/token
        clientId: gateway-llm-client
        clientSecret: s3cr3t-value
        params:
          scope: llm.invoke
```

### Example 3: Explicit `grantType`

`grantType` defaults to `client_credentials` when omitted, so Examples 1 and 2
are equivalent to setting it explicitly:

```yaml
  policies:
    - name: oauth2
      version: v0
      params:
        grantType: client_credentials
        tokenEndpoint: https://auth.internal.example.com/oauth2/token
        clientId: gateway-llm-client
        clientSecret: s3cr3t-value
```

### Example 4: Resource Owner Password Credentials (legacy IdP bridging)

```yaml
  policies:
    - name: oauth2
      version: v0
      params:
        grantType: password
        tokenEndpoint: https://legacy-idp.example.com/oauth2/token
        clientId: gateway-llm-client
        clientSecret: s3cr3t-value
        username: service-account-user
        password: s3cr3t-service-account-password
```

### Example 5: An identity provider requiring `client_secret_post`

```yaml
  policies:
    - name: oauth2
      version: v0
      params:
        tokenEndpoint: https://idp.example.com/oauth2/token
        clientId: gateway-llm-client
        clientSecret: s3cr3t-value
        clientAuthMethod: client_secret_post
```

### Example 6: Pointing the shared token cache at a specific Redis instance

Set once at the gateway level (not per-API) via `config.toml` or Helm values:

```toml
[policy_configurations.upstream_oauth2_v1.redis]
host = "redis.internal.example.com"
port = 6379
password = "..."
failure_mode = "open"
```

## Error Responses

All error responses are returned as JSON with `Content-Type: application/json`.

| Scenario | Status | Message |
| --- | --- | --- |
| Token endpoint unreachable or returned an error (e.g. `invalid_client`, `invalid_grant`) | 502 | `failed to authenticate request to upstream service` |
| Token endpoint response missing an access token | 502 | `failed to authenticate request to upstream service` |
| Redis unreachable and `redis.failureMode` is `closed` | 502 | `failed to authenticate request to upstream service` |
| `grantType` set to an unimplemented value | Rejected at policy load (configuration error), not a runtime response | `'grantType' must be one of "client_credentials", "password"` |
| `clientAuthMethod` set to an unrecognized value | Rejected at policy load (configuration error) | `'clientAuthMethod' must be one of "client_secret_basic", "client_secret_post"` |
| `grantType: password` set without `username` or `password` | Rejected at policy load (configuration error) | `'username' parameter is required` / `'password' parameter is required` |

**Example error body:**

```json
{
  "error": "Bad Gateway",
  "message": "failed to authenticate request to upstream service"
}
```

## Security Considerations

- **Prefer `client_credentials` over `password`** – see the security note at
  the top of this document. Use `password` only when bridging to a legacy
  identity provider that does not support `client_credentials`.
- **`client_secret_basic` is the default and recommended `clientAuthMethod`**
  – switch to `client_secret_post` only when the identity provider requires
  it; sending credentials as Basic-auth header bytes is marginally preferable
  to sending them as form-body plaintext, though both travel over the same
  TLS connection.
- **Cached tokens are bearer credentials** – a valid access token cached in
  Redis grants the same access the token itself does. Restrict network
  access to the Redis instance (`redis.host`/`redis.port`) the same way you
  would restrict access to the token endpoint itself, and prefer
  `redis.password`/`redis.username` (Redis ACLs) in any shared or
  multi-tenant Redis deployment. Cache entries expire with the token's own
  TTL — there is no separate, longer-lived retention.
- **Credential storage** – Credential material configured on this policy
  (including `clientSecret` and, for the password grant, the resource
  owner's `username`/`password`) is stored as part of the API's own
  configuration. Restrict access to API definitions and control-plane
  storage accordingly. Reference a stored secret instead of a literal value
  via `{{ secret "handle" }}` for any sensitive field, including values
  nested inside `params`.
- **HTTPS only** – Ensure both the token endpoint and the upstream backend
  URL use HTTPS. Redis traffic itself is not encrypted by this policy - run
  it on a trusted network segment (e.g. the same private network as
  gateway-runtime), consistent with how `advanced-ratelimit` expects its
  Redis to be reachable.
- **Secret rotation** – Rotating `clientSecret` (or, for the password grant,
  `password`) is a normal policy-params update; it does not retroactively
  invalidate a token already issued under the old credential, nor any
  matching cached entry (the identity provider's own token TTL governs
  that), so no separate rotation mechanism is required.

## Gateway Module Reference

```yaml
- name: oauth2
  gomodule: github.com/wso2/gateway-controllers/policies/upstream-oauth2-authentication@v0
```
