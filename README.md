# credentials-broker

A blackbox credentials broker for AI agents. Callers authenticate to the broker
with an API key that lists the targets they may use; the broker resolves each
target's real credential from [Infisical](https://infisical.com), holds it
itself, and acts on the caller's behalf by proxying an HTTP request to an
upstream API with the resolved credential injected as a header — either a
static secret (**proxy** mode) or a short-lived access token the broker
exchanges for via OAuth2 client_credentials (**oauth** mode). The caller
never sees the underlying secret.

See [`docs/spec.md`](docs/spec.md) for the full spec.

## Configuration

Targets and caller keys live in a SQLite database, managed at runtime
through the [admin API](#admin-api) below — there's no file to edit or
mount.

| Environment variable | Required | Default |
| --- | --- | --- |
| `DB_PATH` | no | `credentials-broker.db` |
| `ADMIN_API_KEY` | yes | — |
| `PORT` | no | `8080` |
| `INFISICAL_BASE_URL` | yes | — |
| `INFISICAL_CLIENT_ID` | yes | — |
| `INFISICAL_CLIENT_SECRET` | yes | — |

The broker fails to start if `ADMIN_API_KEY` is unset.

## Routes

Every request carries `Authorization: Bearer <caller-api-key>`.

- `/proxy/{target}/{rest...}` — forwards method, path, query and body to the
  target's `base_url`, injecting the resolved credential into the configured
  header, and streams the upstream response back. Serves both `proxy` and
  `oauth` mode targets; which credential gets injected depends on the
  target's configured mode.

Unknown key → `401`, key not permitted for the target → `403`, unknown target
(or one whose mode has no handler) → `404`.

## Admin API

All `/admin/*` routes require `Authorization: Bearer <ADMIN_API_KEY>`.

- `POST /admin/targets` — create a target.
- `GET /admin/targets` — list targets.
- `DELETE /admin/targets/{name}` — delete a target.
- `POST /admin/callers` — create a caller; the response's `key` field is
  the caller's bearer token for `/proxy/*` and is generated here and
  never shown again.
- `GET /admin/callers` — list callers (without their keys).
- `DELETE /admin/callers/{id}` — delete a caller.

There is no update or get-by-id endpoint.

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
```

## Development

```sh
make run     # go run ./cmd/broker, needs DB_PATH/ADMIN_API_KEY/INFISICAL_* set
make test    # go test ./...
make lint    # golangci-lint run
make format  # gofmt + goimports
make build   # build a local ./bin/broker binary
make docker-build  # docker build -t credentials-broker:dev .
make docker-run    # run the built image, DB stored in ./data
```

`make run` needs `ADMIN_API_KEY`, `INFISICAL_BASE_URL`, `INFISICAL_CLIENT_ID`,
and `INFISICAL_CLIENT_SECRET` set in the environment.

## Running

```sh
make docker-build
ADMIN_API_KEY=... \
  INFISICAL_BASE_URL=https://app.infisical.com \
  INFISICAL_CLIENT_ID=... \
  INFISICAL_CLIENT_SECRET=... \
  make docker-run
```

## License

Apache 2.0 — see [LICENSE](LICENSE).
