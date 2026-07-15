---
title: "Overview"
---
# OAuth2 Authentication

## Overview

The **OAuth2 Authentication** policy authenticates outbound requests to an
upstream backend using the
[OAuth2 Client Credentials grant](https://datatracker.ietf.org/doc/html/rfc6749#section-4.4)
before they are forwarded. The gateway acts as a confidential client: it
exchanges a client ID and secret for a short-lived access token at a
configured token endpoint, then injects the token as an
`Authorization: Bearer` header on the proxied request.

This is the policy to use when an upstream — an LLM provider, an internal
service, or any backend fronted by a standard OAuth2 token endpoint — requires
a bearer token obtained via client credentials rather than a static, pre-shared
API key.

## Features

- OAuth2 Client Credentials grant (RFC 6749 §4.4) against any standard token
  endpoint
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
| `tokenEndpoint` | string | Yes | | URL of the OAuth2 token endpoint this policy calls to obtain an access token. |
| `clientId` | string | Yes | | OAuth2 client ID used to authenticate to the token endpoint. |
| `clientSecret` | string | Yes | | OAuth2 client secret paired with `clientId`. |
| `scope` | string | No | | Optional space-separated list of scopes requested from the token endpoint. |
| `clientAuthMethod` | string | Yes | | `client_secret_basic` or `client_secret_post`. No default — see Features above. |

> **Security note:** Because credential material is set directly on the API's
> own policy configuration (rather than resolved from operator-controlled
> gateway configuration), access to API definitions containing this policy
> should be restricted accordingly.

**Note:**

Inside the `gateway/build.yaml`, ensure the policy module is added under `policies:`:

```yaml
- name: oauth2-authentication
  gomodule: github.com/wso2/gateway-controllers/policies/oauth2-authentication@v0
```

## How It Works

1. **Header phase** – Injecting a bearer token needs no request body
   inspection, so this policy processes the request-header phase only; the
   request body is never buffered by this policy.
2. The policy retrieves the current access token from a token source built
   once when the policy is instantiated. If a cached token is still valid, it
   is reused with no network call. If it is missing or expired, the policy
   calls the configured `tokenEndpoint` with the `client_credentials` grant,
   using `clientId`/`clientSecret` presented per `clientAuthMethod`, and
   caches the result.
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
    - name: oauth2-authentication
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
    - name: oauth2-authentication
      version: v0
      params:
        tokenEndpoint: https://auth.internal.example.com/oauth2/token
        clientId: gateway-llm-client
        clientSecret: s3cr3t-value
        scope: llm.invoke
        clientAuthMethod: client_secret_basic
```

## Error Responses

All error responses are returned as JSON with `Content-Type: application/json`.

| Scenario | Status | Message |
|----------|--------|---------|
| Token endpoint unreachable or returned an error (e.g. `invalid_client`) | 502 | `failed to authenticate request to upstream service` |
| Token endpoint response missing an access token | 502 | `failed to authenticate request to upstream service` |

**Example error body:**
```json
{
  "error": "Bad Gateway",
  "message": "failed to authenticate request to upstream service"
}
```

## Security Considerations

- **No silent client-auth-method default** – `clientAuthMethod` must be set
  explicitly. Guessing wrong fails at request time against the token
  endpoint instead of at configuration time.
- **Credential storage** – Credential material configured on this policy is
  stored as part of the API's own configuration. Restrict access to API
  definitions and control-plane storage accordingly.
- **HTTPS only** – Ensure both the token endpoint and the upstream backend
  URL use HTTPS.
- **Secret rotation** – Rotating `clientSecret` is a normal policy-params
  update; it does not retroactively invalidate a token already issued under
  the old secret (the identity provider's own token TTL governs that), so no
  separate rotation mechanism is required.

## Gateway Module Reference

```yaml
- name: oauth2-authentication
  gomodule: github.com/wso2/gateway-controllers/policies/oauth2-authentication@v0
```
