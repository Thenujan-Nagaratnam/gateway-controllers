---
title: "Overview"
---
# Azure Managed Identity

## Overview

The **azure-managed-identity** policy authenticates outbound requests to an
Azure-hosted backend using a **User-Assigned Managed Identity (UMI)** before
they are forwarded. Unlike the [`oauth2`](../../oauth2/v0.4/docs/oauth2.md)
policy, there is no `clientSecret` to configure at all: the gateway asks the
Azure platform's **Instance Metadata Service (IMDS)**,
`http://169.254.169.254/metadata/identity/oauth2/token`, for a token on the
identity's behalf, and Azure authenticates that identity internally.

The resulting access token is still an ordinary **Microsoft Entra ID (Azure
AD) token** - same issuer, same shape as one obtained via a regular App
Registration's `client_credentials` grant. Only the *method of obtaining it*
differs: no secret is presented over the wire by this policy at all, because
there isn't one to present.

> **This only works when `gateway-runtime` is actually running on Azure
> compute** - a VM, App Service instance, or AKS node - that has the target
> user-assigned identity attached. `169.254.169.254` is a link-local address
> only reachable from inside Azure's own virtualization host; there is no
> way to make this policy work from any other environment (on-prem, another
> cloud, or local development) against the real endpoint. Use
> `systemParameters.imdsEndpoint` to point at a mock IMDS server for local
> testing - see `gateway/dev-policies/azure-managed-identity/TESTING.md`.

This policy covers the **classic IMDS mechanism only** (node/VM-level
managed identity). [Azure AD Workload Identity](https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation)
(Kubernetes service-account/OIDC federation) is a different mechanism and is
not implemented here.

## Features

- User-Assigned Managed Identity authentication via Azure IMDS - no client
  secret ever configured or stored
- **Redis-backed token cache** shared across every gateway-runtime replica,
  with a per-process in-process cache in front of it for the hot path -
  identical design to the `oauth2` policy's own cache (see that policy's
  docs for the full rationale)
- Cache keyed by API/route **and** by `clientId`/`resource`, so a config
  change that swaps identity or target resource can never keep serving a
  stale token minted under the old configuration
- Fails closed (generic `502`, no detail leaked) on any IMDS or Redis
  failure, consistent with every other outbound-auth policy in this catalog

## Configuration

### User Parameters (API Definition)

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `clientId` | string | Yes | Client ID of the user-assigned managed identity to use. Always sent explicitly to IMDS - if the compute resource has more than one identity attached, an ambiguous request (no `clientId`) is rejected by IMDS itself. |
| `resource` | string | Yes | The audience (App ID URI) the token should be valid for - e.g. `https://cognitiveservices.azure.com/` for Azure OpenAI/Cognitive Services, `https://management.azure.com/` for ARM. Becomes the token's `aud` claim; the wrong value here produces a token the backend will reject, not an error from this policy. |

Attach it via the generic `policies` list (this policy is not exposed
through the typed `upstream.auth` field, matching how `aws-authentication`
is attached today):

```yaml
policies:
  - name: azure-managed-identity
    version: v0
    paths:
      - path: /chat/completions
        methods: [POST]
        params:
          clientId: <user-assigned identity client id>
          resource: https://cognitiveservices.azure.com/
```

> Note the `params` sit under a `paths` entry (`path`/`methods`/`params`),
> not directly on the policy - that's the `LLMPolicy`/`LLMPolicyPath` schema
> shape for the generic policies list, unlike `oauth2`'s typed
> `upstream.auth` field where params sit directly under `auth`.

### System Parameters (Gateway/Operator-Level)

Like the `oauth2` policy's Redis settings, these are operator/gateway-level
settings, not something an individual API publisher sets - resolve them once
for the whole gateway via
`config.policy_configurations.azure_managed_identity_v1.*`.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `imdsEndpoint` | string | `http://169.254.169.254/metadata/identity/oauth2/token` | Overrides the IMDS URL. **Never** set this from anything an API publisher controls - see Security Considerations below. Local/CI testing only. |
| `requestTimeout` | string (Go duration) | `2s` | Timeout for the IMDS HTTP call. Kept short so a misconfigured non-Azure deployment fails fast rather than hanging. |
| `redis.host` | string | `localhost` | Redis host name or IP address. |
| `redis.port` | integer | `6379` | Redis server port. |
| `redis.username` | string | *(none)* | Optional Redis ACL username. |
| `redis.password` | string | *(none)* | Optional Redis authentication password. |
| `redis.db` | integer | `0` | Redis logical database index. |
| `redis.keyPrefix` | string | `azure-managed-identity:token:v1:` | Prefix applied to every cached-token key. |
| `redis.failureMode` | string | `open` | `open` falls back to fetching directly from IMDS if Redis is unreachable; `closed` treats a Redis error as a token-acquisition failure. |
| `redis.connectionTimeout` | string (Go duration) | `5s` | Redis dial timeout. |
| `redis.readTimeout` | string (Go duration) | `3s` | Redis read timeout. |
| `redis.writeTimeout` | string (Go duration) | `3s` | Redis write timeout. |
| `redis.poolSize` | integer | `0` (go-redis default) | Connection pool size for the shared client. |

**Note:**

Inside the `gateway/build.yaml`, ensure the policy module is added under `policies:`:

```yaml
- name: azure-managed-identity
  gomodule: github.com/wso2/gateway-controllers/policies/azure-managed-identity@v0
```

## How It Works

1. **Header phase** – Injecting a bearer token needs no request body
   inspection, so this policy processes the request-header phase only.
2. The policy checks its in-process cache, then Redis, then (only on a
   double miss) calls IMDS: `GET <imdsEndpoint>?api-version=2018-02-01&resource=<resource>&client_id=<clientId>`
   with header `Metadata: true`. Azure's platform authenticates the
   identity and returns a token - no secret is presented by this policy at
   any point.
3. The resulting `Authorization: Bearer <token>` header is set on the
   request before it is forwarded upstream.
4. If the token cannot be obtained (IMDS unreachable - e.g. this policy is
   misconfigured on non-Azure compute, the identity isn't attached, the
   `resource`/`clientId` don't match anything, or Redis is down with
   `failureMode: closed`), the request is short-circuited with `502 Bad
   Gateway`.

## Reference Scenario: Azure OpenAI from an AKS Node with a UMI Attached

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: LlmProvider
metadata:
  name: azure-openai-via-umi
spec:
  displayName: Azure OpenAI (User-Assigned Managed Identity)
  version: v1.0
  template: openai
  context: /azure-openai-umi/latest
  upstream:
    url: https://my-resource.openai.azure.com
  policies:
    - name: azure-managed-identity
      version: v0
      paths:
        - path: /chat/completions
          methods: [POST]
          params:
            clientId: 11111111-1111-1111-1111-111111111111
            resource: https://cognitiveservices.azure.com/
  accessControl:
    mode: deny_all
    exceptions:
      - path: /chat/completions
        methods: [POST]
```

## Error Responses

All error responses are returned as JSON with `Content-Type: application/json`.

| Scenario | Status | Message |
|----------|--------|---------|
| IMDS unreachable (not running on Azure compute, or the metadata endpoint is genuinely down) | 502 | `failed to authenticate request to upstream service` |
| No identity matching `clientId` attached to the compute resource | 502 | `failed to authenticate request to upstream service` |
| IMDS response missing `access_token` | 502 | `failed to authenticate request to upstream service` |
| Redis unreachable and `redis.failureMode` is `closed` | 502 | `failed to authenticate request to upstream service` |
| `clientId` or `resource` omitted at registration | Rejected at policy load (configuration error), not a runtime response | `'clientId' parameter is required` / `'resource' parameter is required` |

**Example error body:**
```json
{
  "error": "Bad Gateway",
  "message": "failed to authenticate request to upstream service"
}
```

## Security Considerations

- **No secret to leak, by design** - this is the main security advantage
  over `oauth2`'s `client_credentials` grant: there is no `clientSecret`
  stored anywhere in this policy's configuration, so there is nothing to
  rotate or leak from the control plane's own storage.
- **`imdsEndpoint` must never be user-controllable.** It is deliberately a
  *system* parameter, not something reachable via the same API surface that
  configures `clientId`/`resource`. Accepting an operator-uncontrolled value
  here would let a malicious or careless API definition redirect where the
  gateway sends its IMDS token requests - and therefore where a freshly
  minted, live access token ends up. Only override it for local/CI testing
  against a mock IMDS server.
- **Cached tokens are bearer credentials**, same caveat as `oauth2`'s cache:
  restrict network access to the Redis instance the same way you'd restrict
  access to IMDS itself. Cache entries expire with the token's own
  lifetime - no separate, longer-lived retention.
- **`resource` determines the token's audience.** Requesting the wrong
  `resource` doesn't fail at this policy - it produces a validly-signed
  token that the actual backend will reject, since the `aud` claim won't
  match what that backend expects.
- **Identity assignment is the real access-control boundary.** Whatever
  Azure RBAC roles are granted to the user-assigned identity determine what
  it can do - this policy has no visibility into or control over that; it
  only obtains whatever token IMDS is willing to issue for the identity
  actually attached to the compute resource.

## Gateway Module Reference

```yaml
- name: azure-managed-identity
  gomodule: github.com/wso2/gateway-controllers/policies/azure-managed-identity@v0
```
