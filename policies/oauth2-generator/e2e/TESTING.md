# Testing the `oauth2` policy end to end

This doc walks through building the gateway with the `oauth2` dev policy
included, standing up three small mock servers (plus an optional Redis
instance), registering an AI API that uses the policy for outbound auth, and
driving every flow the policy needs to handle correctly — happy path, token
caching (both the in-process cache and the shared Redis cache), token
refresh on expiry, header/credential customization, token-endpoint
resilience (proxy, TLS, retry), and all failure modes.

Nothing here talks to a real OAuth2 provider or a real LLM. Everything is
local and mocked, so this is safe to run repeatedly and offline.

> **One-command version:** once the gateway stack is up (Parts B/C below),
> `./run-e2e.sh` in this directory starts all three mocks and runs every flow
> in `postman/oauth2.postman_collection.json` via newman, reporting a single
> pass/fail for the whole suite. The manual steps below are for driving
> individual flows by hand or debugging a specific one.

## Architecture

```
                        curl (you)
                            │
                            │  1. admin API: register LlmProvider
                            │     (port 9090, gateway-controller)
                            │
                            │  2. data-plane traffic: POST /oauth2-test/chat/completions
                            │     (port 8443, gateway-runtime / Envoy)
                            ▼
                 ┌─────────────────────────┐
                 │   gateway-runtime        │
                 │  (Envoy + policy-engine, │
                 │   oauth2 policy compiled │
                 │   in via dev-policies/)  │
                 └───────────┬─────────────┘
                    (a)       │        (b)
           token fetch/cache  │        forward request with
           (only on miss/     │        <headerName>: <valuePrefix> <credential>
            expiry), via      │
            proxyURL if set   │                    ▼
                    ▼         │      ┌───────────────────────────┐
       ┌─────────────────────┐│      │   mock-ai-backend          │
       │  mock-oauth2-idp     ││      │   :9602 (host)              │
       │  :9601 (host)        ││      │   echoes back the           │
       │  client_credentials  ││      │   Authorization header it   │
       │  and password grants ││      │   actually received, in an  │
       │  TTL, failure         ││      │   OpenAI-chat-completions   │
       │  injection, optional  ││      │   shaped response           │
       │  TLS                  ││      └───────────────────────────┘
       └──────────▲──────────┘│
                  │ (only when proxyURL is set)
       ┌──────────┴──────────┐│
       │ mock-forward-proxy   ││
       │ :9603 (host)         ││
       │ proves proxyURL was  ││
       │ actually used        ││
       └─────────────────────┘│
                               ▼
                 gateway-controller (port 9090, admin API)
```

The three mock servers run natively on your host (`go run`, no Docker), and
the gateway containers reach them via `host.docker.internal` (works out of
the box with Docker Desktop / Rancher Desktop / Colima on macOS).

## Prerequisites

- Go (matching the version in `gateway/gateway-runtime/policy-engine/go.mod`)
- Docker + Docker Compose
- `curl`, and optionally `jq` for prettier output
- `openssl` and `lsof`, only if you're running `run-e2e.sh` (which exercises `tlsCaCertPath`/`tlsInsecureSkipVerify`, Part E.27) - `lsof` is used to force-restart the TLS mock instance on every run, since its cert file is regenerated every run but a live process wouldn't otherwise pick that up
- The `oauth2-generator` dev policy already in place at `gateway/dev-policies/oauth2-generator/`
  with a corresponding `filePath` entry in `gateway/build.yaml` (already done
  as part of this policy's development — see `gateway/dev-policies/README.md`
  if you need to redo this from scratch).

## Part A — Start the three mocks

Each mock is a standalone Go module with no third-party dependencies. Run
each in its own terminal (or background them):

```bash
cd gateway/dev-policies/oauth2-generator/e2e/mocks/mock-oauth2-idp
GOWORK=off go run .
# mock-oauth2-idp listening on :9601 (valid client: test-client / test-secret)
```

```bash
cd gateway/dev-policies/oauth2-generator/e2e/mocks/mock-ai-backend
GOWORK=off go run .
# mock-ai-backend listening on :9602
```

```bash
cd gateway/dev-policies/oauth2-generator/e2e/mocks/mock-forward-proxy
GOWORK=off go run .
# mock-forward-proxy listening on :9603 - only needed for the proxyURL flow (E.26)
```

`GOWORK=off` is needed because these mock modules are intentionally not
listed in the repo's root `go.work` (they're throwaway test tooling, not part
of the product build graph) — without it, Go tries to resolve them through
the workspace and fails with "outside module roots".

Sanity check all three are up:

```bash
curl -s http://localhost:9601/healthz   # -> ok
curl -s http://localhost:9602/healthz   # -> ok
curl -s http://localhost:9603/healthz   # -> ok
```

### mock-oauth2-idp reference

| Endpoint | Purpose |
| --- | --- |
| `POST /oauth2/token` | `client_credentials` and `password` grants. Accepts **both** `client_secret_basic` (HTTP Basic auth) and `client_secret_post` (`client_id`/`client_secret` form fields) — the policy's `clientAuthMethod` param selects between them. Optional `ttl` form field (or query param) overrides the token's `expires_in` (seconds, default 300). Optional `delayMs` form field (or query param) artificially delays the response — use this to test `tokenRequestTimeout` (E.12). Optional `omitExpiresIn=true` drops `expires_in` from the response entirely — use this to test `defaultTokenTTL` (E.13). Optional `failFirstN` fails that many otherwise-valid requests with a transient `500` before letting one through — use this to test `tokenRequestMaxRetries` (E.25). Optional `scope` form field is echoed back. Every non-standard request header (anything besides `Authorization`/`Content-Type`/`Content-Length`/`Accept-Encoding`/`User-Agent`/`Host`) is captured and returned via `/debug/stats` — use this to test `tokenRequestHeaders` (E.24). |
| `GET /debug/stats` | Every token request received so far: timestamp, `clientId`, `authStyle` (`basic`/`post`), `scope`, `outcome`, the issued token (if any), and any captured non-standard `headers`. **This is how you prove caching/refresh behavior** — count how many gateway-visible requests translated into how many `/oauth2/token` calls. |
| `POST /debug/reset` | Clears the history (and the `failFirstN` counter) — call this between test flows below so counts don't carry over. |

Built-in clients:

| `clientId` | `clientSecret` | Behavior |
| --- | --- | --- |
| `test-client` | `test-secret` | Issues a valid token (200 OK) |
| `broken-client` | *(any)* | Always `500` — simulates the IdP being down |
| `malformed-client` | *(any)* | `200 OK` but the body is missing `access_token` |
| anything else | *(any)* | `400 {"error":"invalid_client"}` |

Set `TLS_CERT_FILE`/`TLS_KEY_FILE` (both required together) to run this mock
over HTTPS instead of plain HTTP — needed only for E.27 (`tlsCaCertPath`/
`tlsInsecureSkipVerify`), which have no effect against a plain-HTTP token
endpoint.

### mock-ai-backend reference

| Endpoint | Purpose |
| --- | --- |
| `POST /chat/completions` (or any path/method) | Returns an OpenAI-chat-completions-shaped response whose `choices[0].message.content` literally says `received Authorization: "<value>"` — so a plain curl through the gateway shows you the injected credential directly. Note: this always reports the literal `Authorization` header regardless of `headerName` — for a custom `headerName` (E.23), use `/debug/last-request` instead to see the actual header that arrived. |
| `GET /debug/last-request` | Full headers + body of the most recent request it received — use this for scripted assertions, e.g. `curl .../debug/last-request \| jq -r '.headers["X-Api-Token"][0]'`. |
| `POST /debug/force-status?code=401` | Makes the **next request only** (any path/method) return that status instead of the normal 200 - simulates the upstream rejecting an already-cached bearer token, to test `tokenPurgeStatusCodes` (E.16/E.17). Consumed on use - the request after that one gets the normal 200 behavior again. |
| `POST /debug/reset` | Clears the last-request record and any pending forced status - call this between test flows. |

### mock-forward-proxy reference

A minimal HTTP forward proxy — used only for E.26 (`proxyURL`). It forwards
absolute-URI HTTP requests (what the policy's token-endpoint call produces
when `proxyURL` is set) and, for completeness, tunnels `CONNECT` requests for
an HTTPS target too, though nothing in this suite exercises that path.

| Endpoint | Purpose |
| --- | --- |
| *(forward proxy)* | Point `proxyURL` at `http://host.docker.internal:9603` and this mock relays the token-endpoint call to its real target. |
| `GET /debug/stats` | Every request this mock has actually proxied — `proxiedRequestCount` and a `history` of target/method/time. **This is the proof that `proxyURL` was actually used**: if it's still `0` after a chat-completions call, the token-endpoint call reached `mock-oauth2-idp` directly instead of through the proxy. |
| `POST /debug/reset` | Clears the history. |

## Part B — Build the gateway with the policy included

```bash
cd gateway
make build   # builds gateway-runtime, gateway-builder, gateway-controller images
```

This is a normal `make build` — the only thing specific to this policy is
that `gateway/build.yaml` already has:

```yaml
  - name: oauth2-generator
    filePath: ./dev-policies/oauth2-generator
```

which `gateway-runtime`'s Dockerfile picks up automatically via its
`--build-context dev-policies=../dev-policies` build context. You can
confirm the policy made it into the built image afterwards:

```bash
docker run --rm --entrypoint cat ghcr.io/wso2/api-platform/gateway-runtime:latest /app/build-manifest.yaml | grep -A2 '^\s*- name: oauth2-generator$'
```

## Part C — Run the gateway stack

Use the top-level `gateway/docker-compose.yaml` — it's the plain local-dev
stack (no IT-suite dependencies like `mock-platform-api`), and `make build`
(Part B) already tagged your locally-built images as
`ghcr.io/wso2/api-platform/{gateway-controller,gateway-runtime}:$(cat gateway/VERSION)`,
which is exactly the tag this compose file references — so `docker compose up` here uses your local build, not anything pulled from a registry (verify
with `docker image inspect ... --format '{{.Created}}'` if you want to be
sure it's today's build, not a stale local image from a previous pull).

```bash
cd gateway
docker compose up -d gateway-controller gateway-runtime sample-backend redis
```

`redis` now starts by default with a plain `docker compose up` — no profile
flag needed. `gateway/configs/config.toml` already points the oauth2 policy's
token cache at this service
(`[policy_configurations.oauth2_generator_v1.redis]`, `host = "redis"`). If you
omit `redis` from the service list (or stop it), the stack still works
identically - the policy just falls back to fetching a fresh token on every
cache miss instead of sharing one via Redis (see E.10 below). The
`redis-override-test` instance (Part covering `advanced-ratelimit`'s
precedence test) remains opt-in behind `--profile redis`.

Wait for both to be up, then confirm — **note the ports**: this compose file
maps gateway-controller's admin API to host port **9094**, not 9092 (that's
a different compose file's port; don't mix the two up):

```bash
curl -s http://localhost:9094/api/admin/v1/health   # gateway-controller admin -> {"status":"healthy",...}
curl -sk https://localhost:8443/                    # gateway-runtime (Envoy) — a 404 is fine here, it just means no route is registered yet
```

> `host.docker.internal` (used by the mocks in Part D below) resolves
> automatically on Docker Desktop / Rancher Desktop / Colima on macOS — no
> extra config needed for `gateway-runtime`, even though only
> `gateway-controller` has an explicit `extra_hosts` entry in this compose
> file. On plain Docker Engine (Linux), add
> `extra_hosts: ["host.docker.internal:host-gateway"]` to the
> `gateway-runtime` service too, or run the mocks in containers on
> `gateway-network` instead and reference them by service name.

## Part D — Register the AI API with outbound OAuth2 security

This is the core of what we're testing: an `LlmProvider` whose upstream
requires OAuth2, attached via the generic policy-reference shape on
`upstream.auth` — `type: oauth2` plus a `policyParams` bucket (the same
shape `type: api-key` and `type: other` also use; see the design doc for the
full rationale). No separate `policies` list entry is needed - the
`oauth2-generator` policy is attached under the hood, the same way
`set-headers` is attached for `api-key`.

The gateway-controller management API's base path is `/api/management/v1`
(not `v0.9` — an earlier revision of this doc had that wrong).

```bash
curl -X POST http://localhost:9090/api/management/v1/llm-providers \
  -H "Content-Type: application/yaml" \
  -H "Authorization: Basic YWRtaW46YWRtaW4=" \
  --data-binary @- <<'EOF'
apiVersion: gateway.api-platform.wso2.com/v1
kind: LlmProvider
metadata:
  name: oauth2-test-basic
spec:
  displayName: OAuth2 Test
  version: v1.0
  template: openai
  context: /oauth2-test-basic/latest
  upstream:
    url: http://host.docker.internal:9602
    auth:
      type: oauth2
      policyParams:
        tokenEndpoint: http://host.docker.internal:9601/oauth2/token
        clientId: test-client
        clientSecret: test-secret
  accessControl:
    mode: deny_all
    exceptions:
      - path: /chat/completions
        methods: [POST]
EOF
```

Should return `201 Created`. If it fails with a validation error, re-check
`gateway-controller`'s logs — a typo in `tokenEndpoint`/`clientId`
will only surface once you send real traffic. Note that POSTing the same
`metadata.name` a second time does **not** redeploy it — it returns `400`
with `configuration already exists`; delete it first (Part F) if you need to
re-register with changed spec fields.

`grantType` is optional and defaults to `client_credentials` (you can add
`grantType: client_credentials` explicitly under `policyParams`; it's
accepted and forwarded to the policy the same way). `clientAuthMethod`
defaults to `client_secret_basic` — see E.11 for `client_secret_post`.

## Part E — Test flows

Reset the IdP's history before each flow so request counts aren't polluted
by earlier ones:

```bash
curl -s -X POST http://localhost:9601/debug/reset
```

### E.1 — Happy path

```bash
curl -sk -X POST https://localhost:8443/oauth2-test-basic/latest/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}' | jq .
```

**Expect:** `200 OK`, and `choices[0].message.content` reads
`received Authorization: "Bearer mock-token-1-issued-..."`.

Confirm the IdP was actually called with Basic auth:

```bash
curl -s http://localhost:9601/debug/stats | jq '.history[-1]'
# authStyle should be "basic", outcome "issued"
```

### E.2 — Token caching (no repeated IdP calls within TTL)

```bash
curl -s -X POST http://localhost:9601/debug/reset

for i in 1 2 3 4 5; do
  curl -sk -X POST https://localhost:8443/oauth2-test-basic/latest/chat/completions \
    -H "Content-Type: application/json" \
    -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}' \
    | jq -r '.choices[0].message.content'
done

curl -s http://localhost:9601/debug/stats | jq '.tokenRequestCount'
```

**Expect:** all 5 responses embed the **same** `mock-token-N-issued-...`
value, and `tokenRequestCount` is **1** — proving the policy reused the
cached token instead of hitting the IdP on every request.

### E.3 — Token expiry and refresh

This requires a provider configured with a short TTL. Register a second one:

```bash
curl -X POST http://localhost:9090/api/management/v1/llm-providers \
  -H "Content-Type: application/yaml" \
  -H "Authorization: Basic YWRtaW46YWRtaW4=" \
  --data-binary @- <<'EOF'
apiVersion: gateway.api-platform.wso2.com/v1
kind: LlmProvider
metadata:
  name: oauth2-test-shortttl
spec:
  displayName: OAuth2 Test (short TTL, for refresh testing)
  version: v1.0
  template: openai
  context: /oauth2-test-shortttl/latest
  upstream:
    url: http://host.docker.internal:9602
    auth:
      type: oauth2
      policyParams:
        tokenEndpoint: "http://host.docker.internal:9601/oauth2/token?ttl=2"
        clientId: test-client
        clientSecret: test-secret
  accessControl:
    mode: deny_all
    exceptions:
      - path: /chat/completions
        methods: [POST]
EOF
```

The `?ttl=2` query parameter on `tokenEndpoint` is read by the mock via
`r.FormValue`, which checks both the URL query string and the POST body —
this is the practical way to force a short TTL through a real OAuth2 client
library, since such libraries generally don't expose a way to inject an
arbitrary extra body field per grant request.

```bash
curl -s -X POST http://localhost:9601/debug/reset

curl -sk -X POST https://localhost:8443/oauth2-test-shortttl/latest/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}' \
  | jq -r '.choices[0].message.content'   # note the token value

sleep 3   # let the 2-second token expire

curl -sk -X POST https://localhost:8443/oauth2-test-shortttl/latest/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}' \
  | jq -r '.choices[0].message.content'   # token value should differ

curl -s http://localhost:9601/debug/stats | jq '.tokenRequestCount'
# -> at least 2 (one fetch, one refresh) - not exactly 2: tokenRequestMaxRetries
#    (default 2) can transparently retry a transient failure on either fetch,
#    adding to this count without indicating a real caching/refresh bug. What
#    actually matters here is that it's not stuck at 1 (still reusing the
#    expired token).
```

Note the 2-second TTL is deliberately shorter than the policy's own
`expiryBuffer` (default 30s - see E.32 below), which is what actually governs
freshness now, at every cache layer and the token source's own reuse
decision (it replaces `golang.org/x/oauth2`'s hardcoded 10s
`defaultExpiryDelta` entirely - that library default is never consulted).
A token this short-lived is already considered stale from the moment it's
minted, not just after 2 real seconds. That's fine for what this test needs
(one fetch, then a later distinct fetch) - it just means this TTL is too
short to also demonstrate within-TTL reuse (see E.2 for that, with the
mock's default 300s TTL).

### E.4 — Invalid client credentials → 502, no leaked detail

```bash
curl -X POST http://localhost:9090/api/management/v1/llm-providers \
  -H "Content-Type: application/yaml" \
  -H "Authorization: Basic YWRtaW46YWRtaW4=" \
  --data-binary @- <<'EOF'
apiVersion: gateway.api-platform.wso2.com/v1
kind: LlmProvider
metadata:
  name: oauth2-test-badsecret
spec:
  displayName: OAuth2 Test (wrong client secret)
  version: v1.0
  template: openai
  context: /oauth2-test-badsecret/latest
  upstream:
    url: http://host.docker.internal:9602
    auth:
      type: oauth2
      policyParams:
        tokenEndpoint: http://host.docker.internal:9601/oauth2/token
        clientId: test-client
        clientSecret: totally-wrong-secret
  accessControl:
    mode: deny_all
    exceptions:
      - path: /chat/completions
        methods: [POST]
EOF

curl -sk -o - -w "\nHTTP %{http_code}\n" -X POST \
  https://localhost:8443/oauth2-test-badsecret/latest/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}'
```

**Expect:** `HTTP 502` and body
`{"error":"Bad Gateway","message":"failed to authenticate request to upstream service"}`
— the underlying `invalid_client` detail from the IdP must **not** appear in
the response (only in the gateway's own logs).

### E.5 — Token endpoint unreachable → 502

```bash
curl -X POST http://localhost:9090/api/management/v1/llm-providers \
  -H "Content-Type: application/yaml" \
  -H "Authorization: Basic YWRtaW46YWRtaW4=" \
  --data-binary @- <<'EOF'
apiVersion: gateway.api-platform.wso2.com/v1
kind: LlmProvider
metadata:
  name: oauth2-test-unreachable
spec:
  displayName: OAuth2 Test (token endpoint unreachable)
  version: v1.0
  template: openai
  context: /oauth2-test-unreachable/latest
  upstream:
    url: http://host.docker.internal:9602
    auth:
      type: oauth2
      policyParams:
        # Port 9999 has nothing listening on it — a genuine connection
        # failure, distinct from a 4xx/5xx from a reachable IdP.
        tokenEndpoint: http://host.docker.internal:9999/oauth2/token
        clientId: test-client
        clientSecret: test-secret
  accessControl:
    mode: deny_all
    exceptions:
      - path: /chat/completions
        methods: [POST]
EOF

curl -sk -o - -w "\nHTTP %{http_code}\n" -X POST \
  https://localhost:8443/oauth2-test-unreachable/latest/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}'
```

**Expect:** the same generic `502` shape as E.4.

### E.6 — Malformed IdP response → 502

```bash
curl -X POST http://localhost:9090/api/management/v1/llm-providers \
  -H "Content-Type: application/yaml" \
  -H "Authorization: Basic YWRtaW46YWRtaW4=" \
  --data-binary @- <<'EOF'
apiVersion: gateway.api-platform.wso2.com/v1
kind: LlmProvider
metadata:
  name: oauth2-test-malformed
spec:
  displayName: OAuth2 Test (malformed IdP response)
  version: v1.0
  template: openai
  context: /oauth2-test-malformed/latest
  upstream:
    url: http://host.docker.internal:9602
    auth:
      type: oauth2
      policyParams:
        tokenEndpoint: http://host.docker.internal:9601/oauth2/token
        clientId: malformed-client
        clientSecret: whatever
  accessControl:
    mode: deny_all
    exceptions:
      - path: /chat/completions
        methods: [POST]
EOF

curl -sk -o - -w "\nHTTP %{http_code}\n" -X POST \
  https://localhost:8443/oauth2-test-malformed/latest/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}'
```

**Expect:** the same generic `502` shape — the mock returns `200 OK` with no
`access_token`, proving the policy doesn't crash or forward an empty
`Authorization: Bearer` header when the IdP's response is broken.

### E.7 — Confirm the header via the backend's own record (belt-and-suspenders)

For any of the successful flows above, you can also check the backend's own
view of what it received, independent of what the gateway echoed back:

```bash
curl -s http://localhost:9602/debug/last-request | jq '.headers.Authorization'
```

### E.8 — Unsupported `grantType`: registration succeeds, the route then fails

`grantType` exists so further grants can be added without a breaking schema
change, but only `client_credentials` and `password` are implemented today.
Unlike the old typed-field CRD, **gateway-controller does not validate
`policyParams`'s contents at all** — that's deliberate (see the design doc):
validation is the resolved policy's own responsibility, not the gateway's.
So registering an unrecognized `grantType` (e.g. `authorization_code`)
**succeeds** (`201`):

```bash
curl -s -o - -w "\nHTTP %{http_code}\n" -X POST http://localhost:9090/api/management/v1/llm-providers \
  -H "Content-Type: application/yaml" \
  -H "Authorization: Basic YWRtaW46YWRtaW4=" \
  --data-binary @- <<'EOF'
apiVersion: gateway.api-platform.wso2.com/v1
kind: LlmProvider
metadata:
  name: oauth2-test-badgrant
spec:
  displayName: OAuth2 Test (unsupported grant type)
  version: v1.0
  template: openai
  context: /oauth2-test-badgrant/latest
  upstream:
    url: http://host.docker.internal:9602
    auth:
      type: oauth2
      policyParams:
        grantType: authorization_code
        tokenEndpoint: http://host.docker.internal:9601/oauth2/token
        clientId: test-client
        clientSecret: test-secret
  accessControl:
    mode: deny_all
    exceptions:
      - path: /chat/completions
        methods: [POST]
EOF
```

**Expect:** `201 Created`.

The actual rejection happens later, asynchronously: gateway-controller
pushes this route to `gateway-runtime` via xDS, `policy-engine` calls
`oauth2-generator`'s `GetPolicy`, which rejects the invalid `grantType`.
Empirically (confirmed consistently across repeated runs, not a
propagation-timing flake) the route then never becomes reachable at all:

```bash
curl -sk -o - -w "\nHTTP %{http_code}\n" -X POST \
  https://localhost:8443/oauth2-test-badgrant/latest/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}'
```

**Expect:** `404 Not Found` - the same as an unregistered path. (The exact
internal mechanism for why this surfaces as a 404 rather than a 502/500
hasn't been traced to a specific line of gateway-controller/policy-engine
code; only the reliably-reproduced client-visible behavior is asserted
here.)

### E.9 — Resource Owner Password Credentials grant (`grantType: password`)

> **Security note:** the password grant (RFC 6749 §4.3) is supported for
> bridging to legacy identity providers only — it requires the gateway to
> handle the resource owner's raw username/password directly. Prefer
> `client_credentials` (E.1–E.8 above) whenever the upstream identity
> provider supports it.

The mock IdP accepts `username=resource-owner`/`password=hunter2` by default
(override via the `RESOURCE_OWNER_USERNAME`/`RESOURCE_OWNER_PASSWORD` env
vars when starting `mock-oauth2-idp`), in addition to the same
`clientId`/`clientSecret` checks as the `client_credentials` examples above.

```bash
curl -X POST http://localhost:9090/api/management/v1/llm-providers \
  -H "Content-Type: application/yaml" \
  -H "Authorization: Basic YWRtaW46YWRtaW4=" \
  --data-binary @- <<'EOF'
apiVersion: gateway.api-platform.wso2.com/v1
kind: LlmProvider
metadata:
  name: oauth2-test-password
spec:
  displayName: OAuth2 Test (password grant)
  version: v1.0
  template: openai
  context: /oauth2-test-password/latest
  upstream:
    url: http://host.docker.internal:9602
    auth:
      type: oauth2
      policyParams:
        grantType: password
        tokenEndpoint: http://host.docker.internal:9601/oauth2/token
        clientId: test-client
        clientSecret: test-secret
        username: resource-owner
        password: hunter2
  accessControl:
    mode: deny_all
    exceptions:
      - path: /chat/completions
        methods: [POST]
EOF
```

```bash
curl -s -X POST http://localhost:9601/debug/reset

curl -sk -X POST https://localhost:8443/oauth2-test-password/latest/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}' | jq .

curl -s http://localhost:9601/debug/stats | jq '.history[-1]'
```

**Expect:** `200 OK`, the same injected-bearer-token content shape as E.1.

For a failure case, register a second provider with a wrong `password`
(e.g. `wrong-password`) — the mock IdP rejects mismatched resource-owner
credentials with `400 invalid_grant`, and the policy should turn that into
the same generic `502` shape as E.4 (never leaking `invalid_grant` to the
caller).

### E.10 — Redis-backed token cache

Requires the stack to have been started with `--profile redis` (Part C), and
the provider configured with `cacheStrategy: redis`:

```bash
curl -X POST http://localhost:9090/api/management/v1/llm-providers \
  -H "Content-Type: application/yaml" \
  -H "Authorization: Basic YWRtaW46YWRtaW4=" \
  --data-binary @- <<'EOF'
apiVersion: gateway.api-platform.wso2.com/v1
kind: LlmProvider
metadata:
  name: oauth2-test-rediscache
spec:
  displayName: OAuth2 Test (Redis-backed cache)
  version: v1.0
  template: openai
  context: /oauth2-test-rediscache/latest
  upstream:
    url: http://host.docker.internal:9602
    auth:
      type: oauth2
      policyParams:
        tokenEndpoint: http://host.docker.internal:9601/oauth2/token
        clientId: test-client
        clientSecret: test-secret
        cacheStrategy: redis
  accessControl:
    mode: deny_all
    exceptions:
      - path: /chat/completions
        methods: [POST]
EOF
```

This proves the token the policy obtained actually lives in Redis, not just
in the gateway-runtime process's own memory.

```bash
curl -s -X POST http://localhost:9601/debug/reset

curl -sk -X POST https://localhost:8443/oauth2-test-rediscache/latest/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}' \
  | jq -r '.choices[0].message.content'

# Ask Redis directly for the cached entry - the key is
# <keyPrefix><apiId>, scoped to the API (not the individual route/resource),
# since oauth2 config lives on upstream.auth - one value for the whole API,
# shared by every resource it exposes. keyPrefix defaults to
# "oauth2-generator:token:v1:", so scanning for that prefix finds it without knowing
# the exact apiId up front.
docker run --rm --network gateway_gateway-network redis:7-alpine \
  redis-cli -h redis KEYS 'oauth2-generator:token:v1:*'

docker run --rm --network gateway_gateway-network redis:7-alpine \
  redis-cli -h redis GET '<the key from above>'
# -> {"access_token":"mock-token-...","token_type":"Bearer","expiry":"..."}

docker run --rm --network gateway_gateway-network redis:7-alpine \
  redis-cli -h redis TTL '<the key from above>'
# -> a positive number of seconds, close to (but not exceeding) the mock
#    IdP's default 300s expires_in
```

**Expect:** the key exists, its value is a JSON-encoded token matching what
the mock IdP just issued, and its TTL is positive and roughly matches the
token's remaining lifetime.

To see the fallback behavior when Redis is unreachable, stop the `redis`
service and repeat the chat-completions request — it should still succeed
(same `200 OK`, fresh token each time since there's no cache to hit),
proving the `failureMode: open` default degrades gracefully rather than
breaking authentication:

```bash
docker compose stop redis
curl -sk -X POST https://localhost:8443/oauth2-test-rediscache/latest/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}' | jq .
docker compose start redis   # bring it back for any further testing
```

Note that `cacheStrategy` is a regular `policyParams` field (a per-API
choice), while the Redis *connection* settings
(`systemParameters.redis.*`/`config.policy_configurations.oauth2_generator_v1.redis.*`)
are operator/gateway-level, resolved once for the whole gateway.

### E.11 — `client_secret_post` client authentication

`clientAuthMethod` defaults to `client_secret_basic` (all the flows above use
it implicitly). Set it to `client_secret_post` to have `clientId`/
`clientSecret` sent as form fields in the token request body instead of an
HTTP Basic header:

```bash
curl -X POST http://localhost:9090/api/management/v1/llm-providers \
  -H "Content-Type: application/yaml" \
  -H "Authorization: Basic YWRtaW46YWRtaW4=" \
  --data-binary @- <<'EOF'
apiVersion: gateway.api-platform.wso2.com/v1
kind: LlmProvider
metadata:
  name: oauth2-test-clientauthpost
spec:
  displayName: OAuth2 Test (client_secret_post)
  version: v1.0
  template: openai
  context: /oauth2-test-clientauthpost/latest
  upstream:
    url: http://host.docker.internal:9602
    auth:
      type: oauth2
      policyParams:
        tokenEndpoint: http://host.docker.internal:9601/oauth2/token
        clientId: test-client
        clientSecret: test-secret
        clientAuthMethod: client_secret_post
  accessControl:
    mode: deny_all
    exceptions:
      - path: /chat/completions
        methods: [POST]
EOF
```

```bash
curl -s -X POST http://localhost:9601/debug/reset

curl -sk -X POST https://localhost:8443/oauth2-test-clientauthpost/latest/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}' | jq .

curl -s http://localhost:9601/debug/stats | jq '.history[-1]'
```

**Expect:** `200 OK` on the chat-completions call, and
`.history[-1].authStyle` reads `"post"` (not `"basic"`) — proving the client
credentials actually arrived as form fields, not a Basic auth header.

### E.12 — `tokenRequestTimeout` bounds a hung token endpoint

Without this, an unresponsive identity provider would block a token fetch
indefinitely (`golang.org/x/oauth2` falls back to `http.DefaultClient`,
which has no timeout at all). Point the token endpoint at the mock's
`delayMs` param to simulate a slow IdP, and set a much smaller
`tokenRequestTimeout`:

```bash
curl -X POST http://localhost:9090/api/management/v1/llm-providers \
  -H "Content-Type: application/yaml" \
  -H "Authorization: Basic YWRtaW46YWRtaW4=" \
  --data-binary @- <<'EOF'
apiVersion: gateway.api-platform.wso2.com/v1
kind: LlmProvider
metadata:
  name: oauth2-test-timeout
spec:
  displayName: OAuth2 Test (tokenRequestTimeout)
  version: v1.0
  template: openai
  context: /oauth2-test-timeout/latest
  upstream:
    url: http://host.docker.internal:9602
    auth:
      type: oauth2
      policyParams:
        tokenEndpoint: "http://host.docker.internal:9601/oauth2/token?delayMs=3000"
        clientId: test-client
        clientSecret: test-secret
        tokenRequestTimeout: "500ms"
  accessControl:
    mode: deny_all
    exceptions:
      - path: /chat/completions
        methods: [POST]
EOF
```

```bash
time curl -sk -X POST https://localhost:8443/oauth2-test-timeout/latest/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}'
```

**Expect:** `502 Bad Gateway` (`failed to authenticate request to upstream
service`) in well under 3 seconds — the 500ms `tokenRequestTimeout` aborts
the request long before the IdP's simulated 3-second delay completes.

### E.13 — `defaultTokenTTL` fallback when the IdP omits `expires_in`

Without this, an IdP response missing `expires_in` would leave the token's
expiry at the zero value, which `golang.org/x/oauth2`'s `Token.Valid()`
always treats as already-expired — silently disabling caching entirely (a
fresh token fetch on every single request, with no visible error).

```bash
curl -X POST http://localhost:9090/api/management/v1/llm-providers \
  -H "Content-Type: application/yaml" \
  -H "Authorization: Basic YWRtaW46YWRtaW4=" \
  --data-binary @- <<'EOF'
apiVersion: gateway.api-platform.wso2.com/v1
kind: LlmProvider
metadata:
  name: oauth2-test-defaultttl
spec:
  displayName: OAuth2 Test (defaultTokenTTL)
  version: v1.0
  template: openai
  context: /oauth2-test-defaultttl/latest
  upstream:
    url: http://host.docker.internal:9602
    auth:
      type: oauth2
      policyParams:
        tokenEndpoint: http://host.docker.internal:9601/oauth2/token
        clientId: test-client
        clientSecret: test-secret
        defaultTokenTTL: "20s"
        tokenRequestParams:
          omitExpiresIn: "true"
  accessControl:
    mode: deny_all
    exceptions:
      - path: /chat/completions
        methods: [POST]
EOF
```

```bash
curl -s -X POST http://localhost:9601/debug/reset

for i in 1 2 3; do
  curl -sk -X POST https://localhost:8443/oauth2-test-defaultttl/latest/chat/completions \
    -H "Content-Type: application/json" \
    -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}' \
    -o /dev/null -w "req $i: %{http_code}\n"
done

curl -s http://localhost:9601/debug/stats | jq '.tokenRequestCount'
```

**Expect:** all three requests return `200`, and `tokenRequestCount` is `1`
— even though the IdP never sent `expires_in`, the 20s `defaultTokenTTL`
fallback made the token cacheable, so requests 2 and 3 were served from
cache rather than each re-fetching from the IdP.

### E.14 — Shared cache across two APIs with identical oauth2 config (requires `--profile redis`)

Cross-API sharing only ever works through the Redis tier - the in-process
tier is per-route (each `GetPolicy()` call gets its own fresh cache), never
shared across different APIs no matter how identical their config is. So
this needs `oauth2-test-rediscache`/`-clone` (both `cacheStrategy: redis`),
not `oauth2-test-basic`/`-clone` (deliberately memory-only, so E.1/E.2 can
test that default). Register `oauth2-test-rediscache-clone` with the exact
same `policyParams` as `oauth2-test-rediscache` (E.10) — the Redis cache key
is derived from the oauth2 config itself, not the API identity, so two
unrelated APIs with byte-identical config share one cached token:

```bash
curl -s -X POST http://localhost:9601/debug/reset

curl -sk -X POST https://localhost:8443/oauth2-test-rediscache/latest/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}' -o /dev/null

curl -sk -X POST https://localhost:8443/oauth2-test-rediscache-clone/latest/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}' -o /dev/null

curl -s http://localhost:9601/debug/stats | jq '.tokenRequestCount'
```

**Expect:** `tokenRequestCount` is `1` — the second API's request reused the
first's cached token instead of minting its own.

### E.15 — `tokenRequestParams.scope` reaches the token endpoint for the password grant

`tokenRequestParams` is otherwise `client_credentials`-only (the password
grant's underlying library helper has no `EndpointParams`-style hook), but
`scope` specifically is mapped to `Config.Scopes` for the password grant too
- the one extension point `PasswordCredentialsToken` actually has.

```bash
curl -X POST http://localhost:9090/api/management/v1/llm-providers \
  -H "Content-Type: application/yaml" \
  -H "Authorization: Basic YWRtaW46YWRtaW4=" \
  --data-binary @- <<'EOF'
apiVersion: gateway.api-platform.wso2.com/v1
kind: LlmProvider
metadata:
  name: oauth2-test-password-scope
spec:
  displayName: OAuth2 Test (password grant, custom scope)
  version: v1.0
  template: openai
  context: /oauth2-test-password-scope/latest
  upstream:
    url: http://host.docker.internal:9602
    auth:
      type: oauth2
      policyParams:
        grantType: password
        tokenEndpoint: http://host.docker.internal:9601/oauth2/token
        clientId: test-client
        clientSecret: test-secret
        username: resource-owner
        password: hunter2
        tokenRequestParams:
          scope: "read write"
  accessControl:
    mode: deny_all
    exceptions:
      - path: /chat/completions
        methods: [POST]
EOF
```

```bash
curl -s -X POST http://localhost:9601/debug/reset

curl -sk -X POST https://localhost:8443/oauth2-test-password-scope/latest/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}' \
  -o /dev/null -w "req: %{http_code}\n"

curl -s http://localhost:9601/debug/stats | jq '.history[0].scope'
```

**Expect:** `200`, and `.history[0].scope` is `"read write"`.

### E.16 — Purge the cached token on an upstream 401 (`tokenPurgeStatusCodes`)

Simulates the upstream backend rejecting an already-cached bearer token
(e.g. revoked out-of-band at the identity provider). The policy's
`OnResponseHeaders` purges both cache tiers when the upstream responds with
a status in `tokenPurgeStatusCodes` (default `[401]`).

**Updated behavior (self-retry):** `oauth2-generator` no longer declares
`x-wso2-retry-trigger` - gateway-controller builds no Envoy
`RouteAction.RetryPolicy` from this policy alone. Instead, `OnResponseHeaders`
does the whole job itself: on a status in `tokenPurgeStatusCodes` it purges
the cached token, fetches a fresh one, reconstructs the backend URL the
original request was sent to, and makes its own direct HTTP call to the
backend with the fresh token - replacing the failed response with that call's
response via `ImmediateResponse`. This is a policy-engine-side HTTP call, not
an Envoy-level retry - it never touches Envoy's router/cluster or
`x-envoy-attempt-count` for this policy. The externally observable result is
the same as before: the client only ever sees a clean `200` within that one
request, not a passthrough `401` followed by a second request. See also E.34.
This replaces the still-older behavior from before `x-wso2-retry-trigger`
existed at all, where the triggering request surfaced the raw `401` and only
the *next* client request was guaranteed a fresh token.

```bash
curl -X POST http://localhost:9090/api/management/v1/llm-providers \
  -H "Content-Type: application/yaml" \
  -H "Authorization: Basic YWRtaW46YWRtaW4=" \
  --data-binary @- <<'EOF'
apiVersion: gateway.api-platform.wso2.com/v1
kind: LlmProvider
metadata:
  name: oauth2-test-purge
spec:
  displayName: OAuth2 Test (purge on upstream 401, default)
  version: v1.0
  template: openai
  context: /oauth2-test-purge/latest
  upstream:
    url: http://host.docker.internal:9602
    auth:
      type: oauth2
      policyParams:
        tokenEndpoint: http://host.docker.internal:9601/oauth2/token
        clientId: test-client
        clientSecret: test-secret
        tokenPurgeStatusCodes: [401]
        tokenRequestParams:
          testId: purge-401-default
  accessControl:
    mode: deny_all
    exceptions:
      - path: /chat/completions
        methods: [POST]
EOF
```

```bash
curl -s -X POST http://localhost:9601/debug/reset
curl -s -X POST http://localhost:9602/debug/reset

# Prime the cache with a real token.
curl -sk -X POST https://localhost:8443/oauth2-test-purge/latest/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}' \
  -o /dev/null -w "prime: %{http_code}\n"
curl -s http://localhost:9601/debug/stats | jq '.tokenRequestCount'   # expect 1

# Make mock-ai-backend reject the NEXT request only.
curl -s -X POST "http://localhost:9602/debug/force-status?code=401"

# OnResponseHeaders sees the forced 401, purges the cached token, fetches a
# fresh one, and calls mock-ai-backend directly itself with it - replacing
# the failed response with that call's response. The CLIENT only ever sees
# the final 200 - not the intermediate 401 - all within this one request.
curl -sk -X POST https://localhost:8443/oauth2-test-purge/latest/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}' \
  -o /dev/null -w "after force-401 (now 200, not 401): %{http_code}\n"
curl -s http://localhost:9601/debug/stats | jq '.tokenRequestCount'   # expect 2 already, right after this one request

# mock-ai-backend is back to normal; the token fetched by the retry above is
# already cached, so this reuses it rather than fetching yet another one.
curl -sk -X POST https://localhost:8443/oauth2-test-purge/latest/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}' \
  -o /dev/null -w "post-purge: %{http_code}\n"
curl -s http://localhost:9601/debug/stats | jq '.tokenRequestCount'   # still 2
```

**Expect:** `prime`, `after force-401`, and `post-purge` are all `200` -
the forced 401 is no longer visible to the client at all. `tokenRequestCount`
is `1` after priming, and already `2` immediately after the single
`after force-401` request (the automatic retry's own fresh fetch) - if it
were still `1` there, the retry attempt reused the purged token instead of
genuinely fetching a fresh one. It stays `2` after `post-purge`, proving the
retry's own freshly-fetched token was actually cached.

### E.17 — `tokenPurgeStatusCodes: []` disables purging entirely

Same flow as E.16, but against a provider that explicitly sets an empty
list - proves a publisher can opt out, and that `OnResponseHeaders` doesn't
purge (or, per `Mode()`, even run) when there's nothing to purge on.

**Confirmed unchanged (self-retry):** an empty `tokenPurgeStatusCodes` means
`OnResponseHeaders`'s self-retry logic is never reached for any status
(`Mode()` skips response-header processing entirely when it's empty - see
`TestOnResponseHeaders_DisabledWhenPurgeStatusCodesEmpty`). `oauth2-generator`
contributes no `RouteAction.RetryPolicy` for this route either way (it never
did once `x-wso2-retry-trigger` was removed - see E.16). The forced `401`
still passes straight through to the client exactly as before, and the cache
is untouched.

```bash
curl -X POST http://localhost:9090/api/management/v1/llm-providers \
  -H "Content-Type: application/yaml" \
  -H "Authorization: Basic YWRtaW46YWRtaW4=" \
  --data-binary @- <<'EOF'
apiVersion: gateway.api-platform.wso2.com/v1
kind: LlmProvider
metadata:
  name: oauth2-test-purge-disabled
spec:
  displayName: OAuth2 Test (purge explicitly disabled)
  version: v1.0
  template: openai
  context: /oauth2-test-purge-disabled/latest
  upstream:
    url: http://host.docker.internal:9602
    auth:
      type: oauth2
      policyParams:
        tokenEndpoint: http://host.docker.internal:9601/oauth2/token
        clientId: test-client
        clientSecret: test-secret
        tokenPurgeStatusCodes: []
        tokenRequestParams:
          testId: purge-disabled
  accessControl:
    mode: deny_all
    exceptions:
      - path: /chat/completions
        methods: [POST]
EOF
```

```bash
curl -s -X POST http://localhost:9601/debug/reset
curl -s -X POST http://localhost:9602/debug/reset

curl -sk -X POST https://localhost:8443/oauth2-test-purge-disabled/latest/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}' \
  -o /dev/null -w "prime: %{http_code}\n"
curl -s http://localhost:9601/debug/stats | jq '.tokenRequestCount'   # expect 1

curl -s -X POST "http://localhost:9602/debug/force-status?code=401"

curl -sk -X POST https://localhost:8443/oauth2-test-purge-disabled/latest/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}' \
  -o /dev/null -w "after force-401: %{http_code}\n"

curl -sk -X POST https://localhost:8443/oauth2-test-purge-disabled/latest/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}' \
  -o /dev/null -w "after (should still be cached): %{http_code}\n"
curl -s http://localhost:9601/debug/stats | jq '.tokenRequestCount'   # expect still 1
```

**Expect:** `tokenRequestCount` stays `1` throughout, even after the forced
`401` - if it becomes `2`, disabling `tokenPurgeStatusCodes`
(set to `[]`) failed to actually disable it.

### E.18–E.21 — LlmProxy and Mcp integration

These four flows aren't narrated here in full — they're maintained directly
as requests in `postman/oauth2.postman_collection.json` (folders "01b" and
"01c" for registration, then the E.18–E.21 folders for the flows
themselves), since they're mostly about *where* `upstream.auth` lives on
each resource kind rather than new `oauth2-generator` behavior:

- **E.18** — `LlmProxy` with `oauth2` on `provider.auth`.
- **E.19** — an `LlmProxy` provider that itself has its own `LlmProvider`-level
  `upstream.auth` (a "hop 2" auth, fired via the proxy's own loopback to that
  provider) — proves the provider's own auth still fires correctly when
  reached through a proxy rather than directly.
- **E.20** — both hops authenticate independently (`LlmProxy.provider.auth`
  *and* the target `LlmProvider`'s own `upstream.auth`) — proves neither
  auth's cached token or config leaks into the other's.
- **E.21** — `Mcp`'s `upstream.auth` (`MCPProxyConfigData`), same shape as
  `LlmProvider`/`LlmProxy`.

Run these via Postman/newman, or open the collection to read the exact
requests if you want to drive them by hand.

### E.22 — `bearerToken` (directly supplied token, no token endpoint)

For backends behind a long-lived or static credential rather than a full
OAuth2 client-credentials integration - no token endpoint call, no grant, no
caching:

```bash
curl -X POST http://localhost:9090/api/management/v1/llm-providers \
  -H "Content-Type: application/yaml" \
  -H "Authorization: Basic YWRtaW46YWRtaW4=" \
  --data-binary @- <<'EOF'
apiVersion: gateway.api-platform.wso2.com/v1
kind: LlmProvider
metadata:
  name: oauth2-test-bearertoken
spec:
  displayName: OAuth2 Test (directly supplied token)
  version: v1.0
  template: openai
  context: /oauth2-test-bearertoken/latest
  upstream:
    url: http://host.docker.internal:9602
    auth:
      type: oauth2
      policyParams:
        bearerToken: static-pat-abc123
  accessControl:
    mode: deny_all
    exceptions:
      - path: /chat/completions
        methods: [POST]
EOF
```

```bash
curl -s -X POST http://localhost:9601/debug/reset

curl -sk -X POST https://localhost:8443/oauth2-test-bearertoken/latest/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}' \
  | jq -r '.choices[0].message.content'

curl -s http://localhost:9601/debug/stats | jq '.tokenRequestCount'
```

**Expect:** `content` reads `received Authorization: "Bearer static-pat-abc123"`
on every request (the literal configured value, never rotated), and
`tokenRequestCount` stays `0` - the IdP is never called at all for this path.

### E.23 — `headerName` / `valuePrefix` customization

For a backend that expects a raw token in a custom header, no scheme prefix.
Combine with `bearerToken` (E.22) for the simplest possible check, since
there's no caching/IdP interaction to control for:

```bash
curl -X POST http://localhost:9090/api/management/v1/llm-providers \
  -H "Content-Type: application/yaml" \
  -H "Authorization: Basic YWRtaW46YWRtaW4=" \
  --data-binary @- <<'EOF'
apiVersion: gateway.api-platform.wso2.com/v1
kind: LlmProvider
metadata:
  name: oauth2-test-customheader
spec:
  displayName: OAuth2 Test (custom header, no scheme prefix)
  version: v1.0
  template: openai
  context: /oauth2-test-customheader/latest
  upstream:
    url: http://host.docker.internal:9602
    auth:
      type: oauth2
      policyParams:
        bearerToken: raw-api-key-xyz789
        headerName: X-Api-Token
        valuePrefix: ""
  accessControl:
    mode: deny_all
    exceptions:
      - path: /chat/completions
        methods: [POST]
EOF
```

```bash
curl -sk -X POST https://localhost:8443/oauth2-test-customheader/latest/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}' -o /dev/null

curl -s http://localhost:9602/debug/last-request | jq '.headers["X-Api-Token"][0]'
curl -s http://localhost:9602/debug/last-request | jq '.headers.Authorization'
```

**Expect:** `.headers["X-Api-Token"][0]` is exactly `raw-api-key-xyz789` (no
`Bearer ` prefix), and `.headers.Authorization` is absent/null - the
credential went into the custom header only, not the default one too.

### E.24 — `tokenRequestHeaders` reach the token endpoint

For identity providers that require an extra header alongside the standard
OAuth2 grant (e.g. a subscription/API key header):

```bash
curl -X POST http://localhost:9090/api/management/v1/llm-providers \
  -H "Content-Type: application/yaml" \
  -H "Authorization: Basic YWRtaW46YWRtaW4=" \
  --data-binary @- <<'EOF'
apiVersion: gateway.api-platform.wso2.com/v1
kind: LlmProvider
metadata:
  name: oauth2-test-tokenreqheaders
spec:
  displayName: OAuth2 Test (tokenRequestHeaders)
  version: v1.0
  template: openai
  context: /oauth2-test-tokenreqheaders/latest
  upstream:
    url: http://host.docker.internal:9602
    auth:
      type: oauth2
      policyParams:
        tokenEndpoint: http://host.docker.internal:9601/oauth2/token
        clientId: test-client
        clientSecret: test-secret
        tokenRequestHeaders:
          Ocp-Apim-Subscription-Key: test-subscription-key
  accessControl:
    mode: deny_all
    exceptions:
      - path: /chat/completions
        methods: [POST]
EOF
```

```bash
curl -s -X POST http://localhost:9601/debug/reset

curl -sk -X POST https://localhost:8443/oauth2-test-tokenreqheaders/latest/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}' -o /dev/null

curl -s http://localhost:9601/debug/stats | jq '.history[0].headers'
```

**Expect:** `.history[0].headers` includes
`"Ocp-Apim-Subscription-Key": "test-subscription-key"` - the mock IdP
actually received it. Also worth confirming `Authorization`/`Content-Type`
can't be overridden this way — repeat with
`tokenRequestHeaders: {Authorization: "hijacked"}` and confirm
`.history[0].authStyle` is still `"basic"` (the real client credentials, not
the injected header) and the request still succeeds.

### E.25 — `tokenRequestMaxRetries` retries a transient token-endpoint failure

`failFirstN` on the mock fails that many otherwise-valid requests with a
transient `500` before letting one through - set it below
`tokenRequestMaxRetries` to prove the policy retries and ultimately
succeeds, and confirm the IdP saw more than one request for a single
gateway-visible call:

```bash
curl -X POST http://localhost:9090/api/management/v1/llm-providers \
  -H "Content-Type: application/yaml" \
  -H "Authorization: Basic YWRtaW46YWRtaW4=" \
  --data-binary @- <<'EOF'
apiVersion: gateway.api-platform.wso2.com/v1
kind: LlmProvider
metadata:
  name: oauth2-test-retries
spec:
  displayName: OAuth2 Test (tokenRequestMaxRetries)
  version: v1.0
  template: openai
  context: /oauth2-test-retries/latest
  upstream:
    url: http://host.docker.internal:9602
    auth:
      type: oauth2
      policyParams:
        tokenEndpoint: "http://host.docker.internal:9601/oauth2/token?failFirstN=2"
        clientId: test-client
        clientSecret: test-secret
        tokenRequestMaxRetries: 3
  accessControl:
    mode: deny_all
    exceptions:
      - path: /chat/completions
        methods: [POST]
EOF
```

```bash
curl -s -X POST http://localhost:9601/debug/reset

curl -sk -o - -w "\nHTTP %{http_code}\n" -X POST \
  https://localhost:8443/oauth2-test-retries/latest/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}'

curl -s http://localhost:9601/debug/stats | jq '[.history[].outcome]'
```

**Expect:** `200 OK` on the chat-completions call (the retries are invisible
to the caller), and `.history[].outcome` shows
`["forced_failure", "forced_failure", "issued"]` - three IdP calls for one
gateway-visible request, the first two failing transiently and the third
succeeding.

To see retries exhausted instead, set `failFirstN` higher than
`tokenRequestMaxRetries` (e.g. `failFirstN=5` against the same
`tokenRequestMaxRetries: 3`) - expect the generic `502` shape, and
`.history[].outcome` all `"forced_failure"` with no `"issued"` at all.
A rejected credential (4xx, e.g. E.4's wrong secret) must never retry
regardless of this setting - confirm `tokenRequestCount`/history length for
E.4 is still `1` even with a `tokenRequestMaxRetries` set.

### E.26 — `proxyURL` — token-endpoint call actually routes through the proxy

This is the one flow that needs `mock-forward-proxy` (Part A). The
assertion is deliberately two-sided: `mock-forward-proxy`'s stats must show
the proxied request, **and** the request must still reach `mock-oauth2-idp`
through it — if `proxyURL` were silently ignored, the IdP would still get
the request directly, but the proxy's own stats would stay at `0`.

```bash
curl -X POST http://localhost:9090/api/management/v1/llm-providers \
  -H "Content-Type: application/yaml" \
  -H "Authorization: Basic YWRtaW46YWRtaW4=" \
  --data-binary @- <<'EOF'
apiVersion: gateway.api-platform.wso2.com/v1
kind: LlmProvider
metadata:
  name: oauth2-test-proxyurl
spec:
  displayName: OAuth2 Test (proxyURL)
  version: v1.0
  template: openai
  context: /oauth2-test-proxyurl/latest
  upstream:
    url: http://host.docker.internal:9602
    auth:
      type: oauth2
      policyParams:
        tokenEndpoint: http://host.docker.internal:9601/oauth2/token
        clientId: test-client
        clientSecret: test-secret
        proxyURL: http://host.docker.internal:9603
  accessControl:
    mode: deny_all
    exceptions:
      - path: /chat/completions
        methods: [POST]
EOF
```

```bash
curl -s -X POST http://localhost:9601/debug/reset
curl -s -X POST http://localhost:9603/debug/reset

curl -sk -o - -w "\nHTTP %{http_code}\n" -X POST \
  https://localhost:8443/oauth2-test-proxyurl/latest/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}'

echo "--- mock-forward-proxy stats (must be non-zero) ---"
curl -s http://localhost:9603/debug/stats | jq .

echo "--- mock-oauth2-idp stats (should show the same request arrived) ---"
curl -s http://localhost:9601/debug/stats | jq '.tokenRequestCount'
```

**Expect:** `200 OK`; `mock-forward-proxy`'s `proxiedRequestCount` is `1` and
its `history[0].target` is `http://host.docker.internal:9601/oauth2/token`;
`mock-oauth2-idp`'s `tokenRequestCount` is also `1`. If the proxy's count
were `0` while the IdP's is `1`, `proxyURL` was silently bypassed - exactly
the regression this test exists to catch (the same Go footgun class as an
`http.Transport` built without `Proxy` set alongside a custom `TLSClientConfig`,
see the design doc).

As a negative control, repeat without `proxyURL` set at all (e.g. against
`oauth2-test-basic` from E.1) and confirm `mock-forward-proxy`'s stats stay
at `0` - proving the proxy is never touched unless explicitly configured.

### E.27 — `tlsCaCertPath` / `tlsInsecureSkipVerify`

Automated by `run-e2e.sh`: it runs a *second*, TLS-enabled `mock-oauth2-idp`
instance (`TLS_IDP_ADDR`, `:9611` by default) concurrently with the main
plain-HTTP one, rather than switching the same instance between HTTP/HTTPS -
every other flow keeps using plain HTTP unaffected. It also (re)generates a
short-lived self-signed cert (`mock-idp-ca.crt`/`mock-idp-ca.key`, written
into `mocks/mock-oauth2-idp/` - test-only, regenerate-anytime artifacts
already covered by this tree's `.gitignore`) on every run, before starting
that instance. `gateway-runtime` reads `tlsCaCertPath` from inside its own
container - `gateway/docker-compose.yaml` bind-mounts that same directory
read-only at `/etc/gateway/certs`, live (not a snapshot), so the cert becomes
visible there the moment it's generated, regardless of start order. **If your
`gateway-runtime` container predates that mount being added, recreate it**
(`docker compose up -d gateway-runtime` after a `docker compose down` on just
that service, or a full `down`/`up`) - a stale container won't see the mount.

Three providers exercise this (see the Postman collection's `E.27` folder for
the exact registrations): `oauth2-test-tlscacert` (`tlsCaCertPath` pointing at
the mounted CA cert - expect `200 OK`), `oauth2-test-tlsinsecure`
(`tlsInsecureSkipVerify: true` instead, no `tlsCaCertPath` - also `200 OK`,
proving verification was actually skipped rather than coincidentally
passing), and `oauth2-test-tlsuntrusted` (neither set, as a negative control -
expect the generic `502` shape, since Go's default HTTP client rejects a
self-signed cert it doesn't trust). Only ever use `tlsInsecureSkipVerify` in
this kind of local/throwaway test setup, never against a real identity
provider.

To drive this by hand instead of via `run-e2e.sh` (e.g. testing from the
Postman GUI): generate the cert with the same `openssl req` command
`generate_tls_idp_cert()` in `run-e2e.sh` uses, start a second
`mock-oauth2-idp` process with `TLS_CERT_FILE`/`TLS_KEY_FILE` pointed at it on
a free port, and register the three providers above with `tokenEndpoint`
pointed at that port instead of `:9611`.

### E.32 — `expiryBuffer` forces a refresh before actual token expiry

E.3 (above) proves a cached token gets refreshed once it's actually expired.
This proves the stronger, proactive claim `expiryBuffer` exists for:
refreshing *ahead of* actual expiry, so a request is never forwarded
upstream with a credential that's about to expire mid-flight.

`oauth2-test-expirybuffer` sets `tokenEndpoint: ...?ttl=12` (a real 12s
token lifetime) together with `expiryBuffer: "8s"` - so the token is only
genuinely "fresh" for the first `12 - 8 = 4` seconds of its life. Automated
by `run-e2e.sh` as two separate newman invocations (`E.32a`/`E.32b`) with a
real `sleep 6` in between - a genuine wall-clock gap is required here, since
newman's own inter-request overhead alone isn't a reliable substitute (see
the comment at that `sleep 6` in `run-e2e.sh`).

To drive this by hand:

```bash
curl -s -X POST http://localhost:9601/debug/reset

curl -sk -X POST https://localhost:8443/oauth2-test-expirybuffer/latest/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}' \
  | jq -r '.choices[0].message.content'   # note the mock-token-N value

curl -s http://localhost:9601/debug/stats | jq '.tokenRequestCount'   # -> 1

sleep 6   # past the 4s fresh window, well short of the 12s actual expiry

curl -sk -X POST https://localhost:8443/oauth2-test-expirybuffer/latest/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}' \
  | jq -r '.choices[0].message.content'   # different mock-token-N value

curl -s http://localhost:9601/debug/stats | jq '.tokenRequestCount'   # -> 2
```

**Expect:** the second `tokenRequestCount` reads `2`, and the second response
carries a different `mock-token-N` value - even though the *first* token,
per its own real 12s TTL, would not actually have expired yet at the 6s
mark. That's the whole point: `expiryBuffer` decides this, not the token's
literal expiry.

### E.34 — Self-retry with a fresh token (no `resilience.retry`, no `x-wso2-retry-trigger`)

Not narrated here in full - maintained directly as requests in
`postman/oauth2.postman_collection.json` (folder `E.34`). `oauth2-test-retry-refresh`
is registered with **no `resilience.retry` block at all**, and
`oauth2-generator` no longer declares `x-wso2-retry-trigger` - no Envoy
`RouteAction.RetryPolicy` exists for this route because of `oauth2-generator`
at all. The flow revokes a live token at the IdP, then sends a **single**
client request and confirms it gets a clean `200` (not a `401`) -
`OnResponseHeaders` sees the `401`, purges the revoked token, fetches a
genuinely fresh, non-revoked one, and calls the backend directly itself with
it, replacing the response via `ImmediateResponse`. No Envoy-level retry is
involved.

### E.35 — Combined: `oauth2-generator` + `model-failover`

`oauth2-test-mf-combined` is registered with **all three** of: `upstream.auth:
{type: oauth2}` (default `tokenPurgeStatusCodes: [401]`), a `model-failover`
policy (retry-source, `statusCodes: [500]`), and an explicit
`resilience.retry: {statusCodes: [503]}` block. `oauth2-generator` itself
contributes nothing to `RouteAction.RetryPolicy` - it self-retries directly
against the backend instead (see E.34) - so the merged policy's `500`+`503`
now comes from `model-failover`'s retry-source and the operator's
`resilience.retry` composing via `MergeRetryConditions`, not from
oauth2-generator's (removed) trigger.

**`resilience.retry` deliberately uses `503`, not `401` - empirically
confirmed necessary, not a style choice.** An earlier version of this test
gave `resilience.retry` the same code oauth2-generator's own
`tokenPurgeStatusCodes` watches (`401`), and it failed consistently, not
intermittently. Root cause: once `401` is in the route's *merged* Envoy
`RouteAction.RetryPolicy`, Envoy's own native retry can resolve a `401` by
dispatching to the next aggregate-cluster priority target *before*
`oauth2-generator`'s downstream/listener-scoped response-phase `ext_proc`
logic - which is what actually does the token purge+refetch - ever sees the
failure. That `ext_proc` response phase only observes the *final* response
after Envoy's own retry loop has already completed. If that Envoy-level
retry happens to land on a target that returns `200` regardless of the
(still-revoked) token's validity, the client sees a clean `200` with no fresh
token ever fetched - the self-retry purge/refetch simply never runs. This is
a genuine precedence gotcha for combining `resilience.retry` with a policy's
own response-phase self-retry mechanism on the *same* status code - pick a
disjoint code, as this test now does, rather than relying on `ext_proc`
response-phase logic to run before Envoy's own retry decision for an
overlapping code.

Not narrated here in full - maintained directly as requests in
`postman/oauth2.postman_collection.json` (folders `E.35a`/`E.35b`, run as two
separate newman invocations with a real `sleep` >= `suspendDuration` between
them - see below for why). Confirmed live:

- Registration succeeds (`201`) - an explicit `resilience.retry` alongside
  `model-failover` on the same operation is no longer rejected at all; it
  composes (see `model-failover`'s own `09b`/`09c` folders for the
  authoritative proof of this underlying mechanism).
- gateway-controller's `MergeRetryConditions` merges both into **exactly one**
  Envoy `RouteAction.RetryPolicy`, whose `retriable_status_codes` contains
  both `500` (model-failover's retry-source) and `503` (the operator's
  `resilience.retry`) -
  confirmed via `GET {{envoyAdminUrl}}/config_dump?resource=dynamic_route_configs`.
- `oauth2-generator`'s own self-retry (revoke a cached token, expect a clean
  single-request `200`) still works on this merged-policy route - **with one
  important, empirically-confirmed caveat**: the retry attempt is NOT
  guaranteed to land back on the same target that failed. Because this route
  also has `model-failover`'s aggregate-cluster dispatch attached, Envoy's
  retry (`retry_priority: previous_priorities`) can advance to the *next*
  target in model-failover's chain (the fallback) instead of retrying the
  same host - exactly as it would for one of model-failover's own triggering
  codes. `oauth2-generator`'s credential injection still fires correctly on
  whichever attempt actually goes out; the test asserts that behavior rather
  than assuming a specific target.
- `model-failover`'s own trigger (a forced `500`) still retries via its
  fallback target group correctly on the exact same route, with the model
  field rewritten and oauth2's credential injection still applying to
  whichever target actually gets dialed.

**Why E.35a/E.35b are two separate folders, not one:** empirically confirmed
that E.35a's own retry (triggered by oauth2's 401, not one of
model-failover's own configured codes) still causes model-failover to record
a suspend on whichever target received the failed attempt - model-failover's
retry dispatch is keyed off Envoy's `X-Envoy-Attempt-Count` alone, with no
way to tell *why* a given retry attempt is happening. Running E.35b's
force-500-on-primary check immediately after E.35a, in the same folder, was
observed to silently skip primary (still suspended from E.35a) and land on
fallback instead, failing an assertion that primary was ever dialed. Splitting
into two folders with a real `sleep` >= `suspendDuration` (10s) between them -
the same pattern `run-e2e.sh` already uses for E.32a/E.32b - avoids this. This
is a genuine, worth-knowing cross-policy interaction, not a test bug: an
Envoy-level retry dispatched through model-failover's target-priority
mechanism affects its suspend bookkeeping regardless of which policy's
trigger actually caused that retry. Also empirically confirmed: model-failover's
suspend state is keyed independently of the LlmProvider's own lifecycle - it
outlives a delete+recreate of the same route/upstream-definition pairing, so
rapid manual delete/register cycles during debugging can inherit
still-active suspend state from an earlier iteration.

## Part F — Cleanup

```bash
cd gateway
docker compose down

# Ctrl-C all three `go run` mock processes, or:
pkill -f mock-oauth2-idp
pkill -f mock-ai-backend
pkill -f mock-forward-proxy
```

If you don't want to keep the test `LlmProvider`s around, delete them via the
same admin API:

```bash
for name in oauth2-test-basic oauth2-test-shortttl \
            oauth2-test-badsecret oauth2-test-unreachable oauth2-test-malformed \
            oauth2-test-badgrant oauth2-test-password oauth2-test-password-wrong \
            oauth2-test-clientauthpost oauth2-test-timeout oauth2-test-defaultttl \
            oauth2-test-purge oauth2-test-purge-disabled oauth2-test-password-scope \
            oauth2-test-rediscache oauth2-test-rediscache-clone oauth2-test-bearertoken \
            oauth2-test-customheader oauth2-test-tokenreqheaders oauth2-test-retries \
            oauth2-test-proxyurl oauth2-test-purge-custom oauth2-test-redis-failopen \
            oauth2-test-redis-failclosed oauth2-test-customheader-prefix \
            oauth2-test-tlscacert oauth2-test-tlsinsecure oauth2-test-tlsuntrusted \
            oauth2-test-expirybuffer oauth2-test-retry-refresh oauth2-test-mf-combined; do
  curl -X DELETE "http://localhost:9090/api/management/v1/llm-providers/$name" \
    -H "Authorization: Basic YWRtaW46YWRtaW4="
done
```

or just `docker compose down -v` to wipe the controller's persisted state
entirely.
