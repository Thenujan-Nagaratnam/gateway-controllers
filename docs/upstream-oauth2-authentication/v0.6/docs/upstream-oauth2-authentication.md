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

The client ID and secret are always presented to the token endpoint via HTTP
Basic auth (`client_secret_basic`) — the convention RFC 6749 recommends when
the identity provider supports it.

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
- Client authentication to the token endpoint always uses `client_secret_basic`
  (HTTP Basic auth) — the identity provider must accept this convention
- **Redis-backed token cache** shared across every gateway-runtime replica,
  cached per API (not per resource/route), with a per-process in-process
  cache in front of it for the hot path (see Caching below)
- Optional scope
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

- `open` (default): fall back to fetching directly from the token endpoint
  on every request. A Redis outage costs you the cross-replica sharing
  benefit, not authentication itself.
- `closed`: treat the Redis error as a token-acquisition failure (the same
  generic `502` as any other failure below) — for deployments that want to
  guarantee a Redis-down condition is surfaced rather than silently degraded.

### Cache key: scoped per API, not per resource/route

Cache entries are keyed **per API** (`<keyPrefix><apiId>`), not per
route/resource. This is deliberate: `oauth2` config lives on `upstream.auth`,
one value for the whole API — every resource an `LlmProvider`/`LlmProxy`
exposes (`/chat/completions`, `/embeddings`, ...) is configured with the
exact same `tokenEndpoint`/`clientId`/`clientSecret`, so they should all
share the exact same cached token rather than each independently fetching
and caching its own. Keying by route as well would mint one redundant token
(and one redundant token-endpoint call) per resource instead of one per API.

`grantType` is intentionally **not** part of the key: there is exactly one
`grantType` per API's `oauth2` config, so it can never disambiguate two
entries for the same API. Even in the edge case of a live redeploy changing
`grantType`, reusing a still-valid cached token from the old grant is
harmless — the token itself doesn't carry or care which grant produced it.

`apiId` is resolved at request time from `SharedContext.APIId` (falling back
to `SharedContext.APIName:APIVersion`, and finally to the route's own name if
even those are unavailable) — not from anything passed into the policy at
construction time, since the control plane's `PolicyChainConfig` doesn't
carry a stable API identifier at that point. The key is resolved once, from
the first request a policy instance handles, and stays fixed after that.

The Redis TTL on each entry is derived from the token's own `expires_in` —
the cache never outlives the token it holds.

## Configuration

### User Parameters (API Definition)

Business configuration — including credential material — is set per-API in
the API definition, the same as every other policy parameter.

| Parameter         | Type   | Required                               | Default                | Description                                                                                    |
| ----------------- | ------ | -------------------------------------- | ---------------------- | ---------------------------------------------------------------------------------------------- |
| `grantType`     | string | No                                     | `client_credentials` | `client_credentials` or `password`. See the security note above before using `password`. |
| `tokenEndpoint` | string | Yes                                    |                        | URL of the OAuth2 token endpoint this policy calls to obtain an access token.                  |
| `clientId`      | string | Yes                                    |                        | OAuth2 client ID used to authenticate to the token endpoint.                                   |
| `clientSecret`  | string | Yes                                    |                        | OAuth2 client secret paired with`clientId`.                                                  |
| `username`      | string | Only when`grantType` is `password` |                        | Resource owner username. Unused for`client_credentials`.                                     |
| `password`      | string | Only when`grantType` is `password` |                        | Resource owner password, paired with`username`. Unused for `client_credentials`.           |
| `scope`         | string | No                                     |                        | Optional space-separated list of scopes requested from the token endpoint.                     |

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
`config.policy_configurations.oauth2_v1.redis.*` in the gateway's own
configuration (the same mechanism the `advanced-ratelimit` policy uses for
its own Redis settings). Every field below has a default, so omitting the
whole `redis` block is always valid — the policy just runs with a local
Redis on `localhost:6379` and no auth, or degrades to no shared cache at all
if that's unreachable (per `failureMode`).

| Parameter                   | Type                 | Default                                    | Description                                  |
| --------------------------- | -------------------- | ------------------------------------------ | -------------------------------------------- |
| `redis.host`              | string               | `localhost`                              | Redis host name or IP address.               |
| `redis.port`              | integer              | `6379`                                   | Redis server port.                           |
| `redis.username`          | string               | *(none)*                                 | Optional Redis ACL username.                 |
| `redis.password`          | string               | *(none)*                                 | Optional Redis authentication password.      |
| `redis.db`                | integer              | `0`                                      | Redis logical database index.                |
| `redis.keyPrefix`         | string               | `oauth2:token:v1:`                       | Prefix applied to every cached-token key.    |
| `redis.failureMode`       | string               | `open`                                   | `open` or `closed` — see Caching above. |
| `redis.connectionTimeout` | string (Go duration) | `5s`                                     | Redis dial timeout.                          |
| `redis.readTimeout`       | string (Go duration) | `3s`                                     | Redis read timeout.                          |
| `redis.writeTimeout`      | string (Go duration) | `3s`                                     | Redis write timeout.                         |
| `redis.poolSize`          | integer              | `0` (go-redis default: 10 × GOMAXPROCS) | Connection pool size for the shared client.  |

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
   presenting `clientId`/`clientSecret` as HTTP Basic auth — see Caching
   above for the full fallback order, cache-key scope, and `failureMode`
   behavior.
   - For `client_credentials`, a fresh fetch is a standard `client_credentials`
     token request.
   - For `password`, a fresh fetch re-presents `username`/`password` — this
     policy always re-authenticates with the resource owner's credentials
     rather than relying on a `refresh_token`, since not every identity
     provider issues one for this grant.
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

### Example 5: Pointing the shared token cache at a specific Redis instance

Set once at the gateway level (not per-API) via `config.toml` or Helm values:

```toml
[policy_configurations.oauth2_v1.redis]
host = "redis.internal.example.com"
port = 6379
password = "..."
failure_mode = "open"
```

## Error Responses

All error responses are returned as JSON with `Content-Type: application/json`.

| Scenario                                                                                    | Status                                                                | Message                                                                     |
| ------------------------------------------------------------------------------------------- | --------------------------------------------------------------------- | --------------------------------------------------------------------------- |
| Token endpoint unreachable or returned an error (e.g.`invalid_client`, `invalid_grant`) | 502                                                                   | `failed to authenticate request to upstream service`                      |
| Token endpoint response missing an access token                                             | 502                                                                   | `failed to authenticate request to upstream service`                      |
| Redis unreachable and`redis.failureMode` is `closed`                                    | 502                                                                   | `failed to authenticate request to upstream service`                      |
| `grantType` set to an unimplemented value                                                 | Rejected at policy load (configuration error), not a runtime response | `'grantType' must be one of "client_credentials", "password"`             |
| `grantType: password` set without `username` or `password`                            | Rejected at policy load (configuration error)                         | `'username' parameter is required` / `'password' parameter is required` |

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
- **`client_secret_basic` only** – the identity provider must accept HTTP
  Basic auth on the token request. An identity provider that only accepts
  `client_secret_post` (form-encoded client credentials) is not currently
  supported by this policy.
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
  storage accordingly.
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
