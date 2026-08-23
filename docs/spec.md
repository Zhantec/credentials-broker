# credentials-broker — v1 spec

## Purpose

Agents/services talk to the broker over HTTP by target name (`github`,
`stripe`, ...). The broker resolves the target's real credential from
Infisical and proxies the request to the target on the caller's behalf,
injecting either a static secret (**proxy** mode) or a short-lived OAuth2
access token it fetches and caches on the caller's behalf (**oauth**
mode). The caller never sees the underlying secret or client credentials.

## Non-goals (v1)

- Database access (query execution, connection brokering). Scoping a
  target's blast radius — e.g. giving an agent a database that only
  needs OAuth-fronted API access no direct SQL surface at all — sits
  with whoever provisions the target's credential, not with broker code.
- mTLS / non-API-key caller auth
- Secret rotation handling beyond a cache TTL
- Multi-tenant / per-request audit UI (structured logs are enough for v1)

## Components

- **Go HTTP service**, single binary, runs as a Docker container
  (deployed via Portainer).
- **Store**: embedded SQLite database (path via `DB_PATH` env var,
  default `credentials-broker.db`), holding targets and callers.
  Managed at runtime through the admin HTTP API below — no file to
  mount or SCP.
- **Admin API**: `/admin/targets` and `/admin/callers`
  (create/list/delete), gated by a single bootstrap `ADMIN_API_KEY` env
  var. The broker fails to start if it's unset.
- **Infisical client**: Universal Auth (`INFISICAL_CLIENT_ID` /
  `INFISICAL_CLIENT_SECRET` env vars), fetches secrets per target and
  caches them in memory with a TTL.

## Admin API

All `/admin/*` routes require `Authorization: Bearer <ADMIN_API_KEY>`.

```bash
curl -X POST http://localhost:8080/admin/targets \
  -H "Authorization: Bearer $ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "stripe",
    "mode": "proxy",
    "base_url": "https://api.stripe.com",
    "infisical_workspace_id": "ws-123",
    "infisical_environment": "prod",
    "infisical_secret": "/prod/stripe/api_key"
  }'
# inject_header/inject_prefix are optional, defaulting to
# "Authorization"/"Bearer ".

curl -X POST http://localhost:8080/admin/callers \
  -H "Authorization: Bearer $ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"targets": ["stripe"]}'
# targets is optional; omitted/empty means the caller may use every
# target currently registered on this broker (dynamic all-access).
# The response's "key" field is the caller's bearer token for
# /proxy/* — it is generated here and never shown again.
```

`GET /admin/targets`, `GET /admin/callers`, `DELETE /admin/targets/{name}`,
and `DELETE /admin/callers/{id}` round out create/list/delete for both
resources. There is no update or get-by-id endpoint.

## Request flow

1. Caller sends `Authorization: Bearer <api-key>` with the request.
2. Broker looks up the key in the store.
   - Missing/unknown key → `401`.
   - Key doesn't list the requested target → `403`.
   - Target name not registered → `404`.
3. Broker resolves the secret for that target (cache, else fetch from
   Infisical; `502` if Infisical is unreachable).
4. Both modes serve `/proxy/{target}/*`: forward the request to
   `base_url + remaining path`, injecting a credential into
   `inject_header` (with `inject_prefix`), stream the upstream response
   back verbatim. `502` if the upstream target is unreachable. The mode
   determines where the injected value comes from:
   - **proxy**: the resolved Infisical secret, used as-is.
   - **oauth**: the resolved Infisical secret is a client-credentials
     blob (`client_id`, `client_secret`, `token_url`, optional `scope`).
     The broker exchanges it for an access token via the OAuth2
     `client_credentials` grant (RFC 6749 §4.4), caches the token until
     shortly before it expires, and injects the token. `502` if the
     token endpoint is unreachable or rejects the credentials.
5. Secret material — static secrets, client credentials, and issued
   access tokens — is never included in response bodies, error bodies,
   or log lines. Logs record: caller key (or a stable hash of it),
   target name, and outcome — never the resolved credential.

## Testing

- Table-driven tests for: key→target authorization, target lookup,
  Infisical response caching/TTL.
- One `httptest`-based smoke test for proxy mode (fake upstream server,
  assert the injected header + forwarded body/path).
- One smoke test for oauth mode (fake token endpoint + fake upstream) —
  assert the token is fetched once, cached within TTL, refetched after
  expiry, and injected as the header value.
- No testcontainers, no fixture frameworks — plain `net/http/httptest`
  and Go's standard `testing` package.

## Open questions for later (not blocking v1)

- Whether the oauth token cache needs to be shared/persisted across
  broker replicas, or per-instance in-memory caching (current
  implementation) is fine given each replica just refetches on a cache
  miss.
