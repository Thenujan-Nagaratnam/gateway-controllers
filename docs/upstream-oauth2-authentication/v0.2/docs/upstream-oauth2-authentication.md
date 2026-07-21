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
- Configurable client authentication method: `client_secret_basic` (HTTP
  Basic auth on the token request) or `client_secret_post` (form-encoded
  body) — required, with no default, since identity providers disagree on
  convention (for example, Azure AD requires `client_secret_post`)
- Automatic in-process caching and refresh of the access token ahead of
  expiry — no token endpoint call on every request
- Optional scope
- Preserves any existing authentication context set by an earlier (inbound)
  auth policy

## Configuration

### User Parameters (API Definition)

All configuration for this policy — including credential material — is set
per-API in the API definition. There are no system/config.toml-level
parameters.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `grantType` | string | No | `client_credentials` | `client_credentials` or `password`. See the security note above before using `password`. |
| `tokenEndpoint` | string | Yes | | URL of the OAuth2 token endpoint this policy calls to obtain an access token. |
| `clientId` | string | Yes | | OAuth2 client ID used to authenticate to the token endpoint. |
| `clientSecret` | string | Yes | | OAuth2 client secret paired with `clientId`. |
| `username` | string | Only when `grantType` is `password` | | Resource owner username. Unused for `client_credentials`. |
| `password` | string | Only when `grantType` is `password` | | Resource owner password, paired with `username`. Unused for `client_credentials`. |
| `scope` | string | No | | Optional space-separated list of scopes requested from the token endpoint. |
| `clientAuthMethod` | string | Yes | | `client_secret_basic` or `client_secret_post`. No default — see Features above. |

> **Security note:** Because credential material is set directly on the API's
> own policy configuration (rather than resolved from operator-controlled
> gateway configuration), access to API definitions containing this policy
> should be restricted accordingly. This applies with extra weight to
> `password`, since it is an end user's own credential, not a
> service-to-service secret.

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
2. The policy retrieves the current access token from a token source built
   once when the policy is instantiated, based on the configured `grantType`.
   If a cached token is still valid, it is reused with no network call.
   - For `client_credentials`, an expired/missing token triggers a fresh
     `client_credentials` request using `clientId`/`clientSecret` presented
     per `clientAuthMethod`.
   - For `password`, an expired/missing token triggers a fresh `password`
     grant request re-presenting `username`/`password` (and
     `clientId`/`clientSecret` per `clientAuthMethod`) — this policy always
     re-authenticates with the resource owner's credentials rather than
     relying on a `refresh_token`, since not every identity provider issues
     one for this grant.
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
        clientAuthMethod: client_secret_post
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
        clientAuthMethod: client_secret_basic
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
        clientAuthMethod: client_secret_basic
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
        clientAuthMethod: client_secret_basic
```

## Error Responses

All error responses are returned as JSON with `Content-Type: application/json`.

| Scenario | Status | Message |
|----------|--------|---------|
| Token endpoint unreachable or returned an error (e.g. `invalid_client`, `invalid_grant`) | 502 | `failed to authenticate request to upstream service` |
| Token endpoint response missing an access token | 502 | `failed to authenticate request to upstream service` |
| `grantType` set to an unimplemented value | Rejected at policy load (configuration error), not a runtime response | `'grantType' must be one of "client_credentials", "password"` |
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
- **No silent client-auth-method default** – `clientAuthMethod` must be set
  explicitly. Guessing wrong fails at request time against the token
  endpoint instead of at configuration time.
- **Credential storage** – Credential material configured on this policy
  (including `clientSecret` and, for the password grant, the resource
  owner's `username`/`password`) is stored as part of the API's own
  configuration. Restrict access to API definitions and control-plane
  storage accordingly.
- **HTTPS only** – Ensure both the token endpoint and the upstream backend
  URL use HTTPS.
- **Secret rotation** – Rotating `clientSecret` (or, for the password grant,
  `password`) is a normal policy-params update; it does not retroactively
  invalidate a token already issued under the old credential (the identity
  provider's own token TTL governs that), so no separate rotation mechanism
  is required.

## Gateway Module Reference

```yaml
- name: oauth2
  gomodule: github.com/wso2/gateway-controllers/policies/upstream-oauth2-authentication@v0
```
