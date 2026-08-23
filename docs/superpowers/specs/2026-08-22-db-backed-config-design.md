# DB-Backed Configuration Design

## Purpose

Replace the static per-sidecar `config.yaml` file with an embedded SQLite
database managed through a new admin HTTP API. Today, adding or changing a
target or caller means editing YAML and SCP-ing it to every sidecar
deployment. After this change, targets and callers are created, listed, and
deleted via HTTP requests against the broker itself, authenticated with a
single bootstrap `ADMIN_API_KEY`.

## Non-Goals

- **Multi-tenancy across projects.** One broker instance still serves one
  app/project, with access to that project's Infisical secrets only. A
  target's Infisical `workspace_id`/`environment` fields let a single
  broker span multiple Infisical *projects*, but this is not
  cross-application multi-tenancy — see "Multi-project Infisical support"
  below.
- **Admin key rotation, scoped admin roles, or an update/get-by-id admin
  endpoint.** Admin operations are create/list/delete only.
- **A UI/dashboard.** Admin API only.
- **Automatic provisioning of caller keys into calling containers.** How a
  caller application obtains and stores its key (env var, secret mount,
  etc.) is a deployment concern outside the broker's scope.

## Data Model

Three SQLite tables, created if missing on startup:

```sql
CREATE TABLE targets (
	name                   TEXT PRIMARY KEY,
	mode                   TEXT NOT NULL,   -- "proxy" | "oauth"
	base_url               TEXT NOT NULL,
	infisical_workspace_id TEXT NOT NULL,
	infisical_environment  TEXT NOT NULL,
	infisical_secret       TEXT NOT NULL,   -- e.g. "/prod/stripe/api_key"
	inject_header          TEXT NOT NULL,   -- defaults to "Authorization"
	inject_prefix          TEXT NOT NULL    -- defaults to "Bearer "
);

CREATE TABLE callers (
	id       INTEGER PRIMARY KEY AUTOINCREMENT,
	key_hash TEXT NOT NULL UNIQUE            -- SHA-256 hex of the raw key
);

CREATE TABLE caller_targets (
	caller_id   INTEGER NOT NULL REFERENCES callers(id) ON DELETE CASCADE,
	target_name TEXT NOT NULL REFERENCES targets(name) ON DELETE CASCADE,
	PRIMARY KEY (caller_id, target_name)
);
```

A caller with zero rows in `caller_targets` has **dynamic all-access**: it
may use every target currently registered on the broker, including ones
added after the caller was created. A caller with one or more rows is
scoped to exactly those targets. This mirrors the current default
behavior (every caller in `config.example.yaml` lists explicit targets,
but the common case for a single-project sidecar is "this app's agents can
reach everything this broker is allowed to reach").

Raw caller keys are **never stored**. `CreateCaller` generates a random
key, returns it exactly once in the API response, and persists only its
SHA-256 hash. This matches how the admin key itself works today (broker
never sees anyone else's copy) and limits blast radius if the SQLite file
is ever exfiltrated.

## Admin API

All `/admin/*` routes require `Authorization: Bearer <ADMIN_API_KEY>`,
checked with `crypto/subtle.ConstantTimeCompare`. The broker fails to
start if `ADMIN_API_KEY` is unset or empty (fail-closed).

### Targets

- `POST /admin/targets` — create. Body:
  ```json
  {
    "name": "stripe",
    "mode": "proxy",
    "base_url": "https://api.stripe.com",
    "infisical_workspace_id": "ws-123",
    "infisical_environment": "prod",
    "infisical_secret": "/prod/stripe/api_key",
    "inject_header": "Authorization",
    "inject_prefix": "Bearer "
  }
  ```
  `inject_header`/`inject_prefix` are optional; when omitted they default
  to `"Authorization"`/`"Bearer "` before validation runs. If present but
  empty, `inject_header` is rejected (a target must inject somewhere);
  `inject_prefix` may be empty (some APIs take a bare token). Returns
  `201` with the created target, `409` if `name` already exists, `400` on
  a missing/invalid required field.
- `GET /admin/targets` — list. Returns `{"targets": [...]}`.
- `DELETE /admin/targets/{name}` — delete. `204` on success, `404` if not
  found.

### Callers

- `POST /admin/callers` — create. Body:
  ```json
  { "targets": ["stripe", "github"] }
  ```
  `targets` is optional; omitted or `[]` means dynamic all-access. Returns
  `201`:
  ```json
  { "id": 1, "key": "sk_live_<64 hex chars>", "targets": ["stripe", "github"] }
  ```
  This is the only response that ever contains the raw key.
- `GET /admin/callers` — list. Returns
  `{"callers": [{"id": 1, "targets": ["stripe","github"]}, {"id": 2, "targets": []}]}`
  (never keys).
- `DELETE /admin/callers/{id}` — delete. `204` on success, `404` if not
  found.

## Auth Model

Two independent credential tiers, per the broker's existing
`ADMIN_API_KEY`-vs-caller-key split:

- **Control plane** — `ADMIN_API_KEY`, an env var set once at deploy time
  (the same way it reaches the broker sidecar as any other bootstrap
  secret reaches any container). Grants full create/list/delete over
  targets and callers. Not stored in the database.
- **Data plane** — per-caller keys, created via the admin API, hashed at
  rest, scoped to zero or more targets. Used on `/proxy/{target}/...`
  exactly as today (`Authorization: Bearer <key>`).

`internal/authz.Check` keeps its existing auth-before-target-existence
ordering (look up the caller first, so an invalid key can't be used to
probe which target names exist) and gains all-access semantics: if the
matched caller has no scoped targets, any registered target is `Allowed`.

## Multi-Project Infisical Support

`workspace_id`/`environment` move from global config fields to per-target
fields, so one broker can proxy targets whose secrets live in different
Infisical projects — the broker's Infisical *credentials*
(`INFISICAL_CLIENT_ID`/`INFISICAL_CLIENT_SECRET`) still apply account-wide
via Universal Auth, but the project/environment used for a given secret
lookup is now supplied per-call. This ripples through
`SecretResolver.GetSecret` (in `internal/secrets`, `internal/oauth`, and
`internal/proxy`), which gains `workspaceID, environment` as its first two
parameters.

A human-readable "project name" was considered as a replacement for the
raw Infisical `workspace_id`, but Infisical's actual REST API
(`GET /api/v3/secrets/raw/{name}?...&workspaceId=...`) requires the
literal project ID — there's no name-based lookup to build on — so this
was not adopted.

## Testing Approach

Table-driven Go tests throughout, consistent with the existing codebase
(`docs/spec.md`'s established philosophy: no mocking frameworks, no
testcontainers). `internal/store` tests run against a real
`modernc.org/sqlite` database opened at `:memory:`. `internal/authz` and
`internal/server` tests build a temporary store the same way, replacing
today's in-memory `*config.Config` fixtures.

## Migration Notes

`internal/config` (the YAML loader) is deleted once nothing imports it.
`config.example.yaml` is removed. `README.md`, `docs/spec.md`, and the
`Makefile`'s `docker-run` target are updated to describe `DB_PATH` +
`ADMIN_API_KEY` instead of `CONFIG_PATH`.
