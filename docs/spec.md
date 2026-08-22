# credentials-broker — v1 spec

## Purpose

Agents/services talk to the broker over HTTP by target name (`postgres`,
`stripe`, ...). The broker resolves the target's real credential from
Infisical and either proxies the request (injecting auth) or executes it
on the caller's behalf (e.g. running a SQL query). The caller never sees
the underlying secret.

## Non-goals (v1)

- Query-level authorization or SQL parsing/allow-listing. If a target
  needs read-only access, that's enforced by provisioning a read-only
  Infisical credential (e.g. a Postgres role with only `SELECT` grants)
  for that target — not by broker logic. The broker executes whatever
  the caller sends, using whatever privileges the configured credential
  has. Responsibility for scoping a target's blast radius sits with
  whoever configures that target, not with broker code.
- Execute mode beyond Postgres (other DB engines, message queues, etc.)
- mTLS / non-API-key caller auth
- Secret rotation handling beyond a cache TTL
- Multi-tenant / per-request audit UI (structured logs are enough for v1)

## Components

- **Go HTTP service**, single binary, runs as a Docker container
  (deployed via Portainer).
- **Config file**: static YAML, mounted into the container (path via
  `CONFIG_PATH` env var, default `/etc/credentials-broker/config.yaml`).
- **Infisical client**: Universal Auth (`INFISICAL_CLIENT_ID` /
  `INFISICAL_CLIENT_SECRET` env vars), fetches secrets per target and
  caches them in memory with a TTL.

## Config format

```yaml
callers:
  - key: "sk_agent_abcdef..."       # bearer token the caller presents
    targets: ["postgres", "stripe"]  # target names this key may use

targets:
  - name: postgres
    mode: execute
    driver: postgres
    infisical_secret: "/prod/postgres/dsn"   # full DSN, or broken into fields — TBD at implementation

  - name: stripe
    mode: proxy
    base_url: "https://api.stripe.com"
    infisical_secret: "/prod/stripe/api_key"
    inject_header: "Authorization"
    inject_prefix: "Bearer "
```

## Request flow

1. Caller sends `Authorization: Bearer <api-key>` with the request.
2. Broker looks up the key in config.
   - Missing/unknown key → `401`.
   - Key doesn't list the requested target → `403`.
   - Target name not in config → `404`.
3. Broker resolves the secret for that target (cache, else fetch from
   Infisical; `502` if Infisical is unreachable).
4. Dispatch by mode:
   - **proxy** (`POST/GET /proxy/{target}/*`): forward the request to
     `base_url + remaining path`, injecting the secret into
     `inject_header` (with `inject_prefix`), stream the upstream
     response back verbatim. `502` if the upstream target is
     unreachable.
   - **execute** (`POST /execute/{target}`): body is
     `{"query": "..."}`. Broker opens a connection using the resolved
     DSN and runs the query as-is, returns rows as JSON
     (`{"columns": [...], "rows": [[...], ...]}`). `500` with a
     generic message on query error — the raw driver error is logged
     server-side only (it can leak schema/DSN details).
5. Secret material is never included in response bodies, error bodies,
   or log lines. Logs record: caller key (or a stable hash of it),
   target name, mode, and outcome — never the resolved secret.

## Testing

- Table-driven tests for: key→target authorization, target lookup,
  Infisical response caching/TTL.
- One `httptest`-based smoke test for proxy mode (fake upstream server,
  assert the injected header + forwarded body/path).
- One smoke test for execute mode against a local Postgres (or a
  minimal fake driver if that's not available in CI) — assert query
  results round-trip and a bad query returns a generic `500` without
  leaking driver internals.
- No testcontainers, no fixture frameworks — plain `net/http/httptest`
  and Go's standard `testing` package.

## Open questions for later (not blocking v1)

- Exact shape of the Postgres DSN in Infisical: one string vs.
  host/port/user/pass/db as separate fields. Decide at implementation
  time based on what's actually easiest to rotate in Infisical.
- Whether `execute` mode needs a query timeout / row limit to avoid a
  caller accidentally hammering the DB. Worth a default timeout even in
  v1 — cheap to add, cheap to regret not having.
