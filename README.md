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

Targets and caller keys live in a YAML file — see
[`config.example.yaml`](config.example.yaml).

| Environment variable | Required | Default |
| --- | --- | --- |
| `CONFIG_PATH` | no | `/etc/credentials-broker/config.yaml` |
| `PORT` | no | `8080` |
| `INFISICAL_BASE_URL` | yes | — |
| `INFISICAL_CLIENT_ID` | yes | — |
| `INFISICAL_CLIENT_SECRET` | yes | — |

## Routes

Every request carries `Authorization: Bearer <caller-api-key>`.

- `/proxy/{target}/{rest...}` — forwards method, path, query and body to the
  target's `base_url`, injecting the resolved credential into the configured
  header, and streams the upstream response back. Serves both `proxy` and
  `oauth` mode targets; which credential gets injected depends on the
  target's configured mode.

Unknown key → `401`, key not permitted for the target → `403`, unknown target
(or one whose mode has no handler) → `404`.

## Development

```sh
make run     # go run ./cmd/broker against config.example.yaml
make test    # go test ./...
make lint    # golangci-lint run
make format  # gofmt + goimports
make build   # build a local ./bin/broker binary
make docker-build  # docker build -t credentials-broker:dev .
make docker-run    # run the built image, config.example.yaml mounted in
```

`make run` still needs `INFISICAL_BASE_URL`, `INFISICAL_CLIENT_ID`, and
`INFISICAL_CLIENT_SECRET` set in the environment.

## Running

```sh
make docker-build
INFISICAL_BASE_URL=https://app.infisical.com \
  INFISICAL_CLIENT_ID=... \
  INFISICAL_CLIENT_SECRET=... \
  make docker-run
```

## License

Apache 2.0 — see [LICENSE](LICENSE).
