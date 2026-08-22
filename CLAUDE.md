# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```sh
make build   # go build -o bin/broker ./cmd/broker
make run     # go run ./cmd/broker (needs INFISICAL_* env vars, see below)
make test    # go test ./...
make lint    # golangci-lint run
make format  # gofmt -w . && goimports -w .
```

Single test: `go test ./internal/proxy/... -run TestServe_PathTraversalCannotEscapeBasePath -v`

Required env vars for `make run`: `INFISICAL_BASE_URL`, `INFISICAL_CLIENT_ID`, `INFISICAL_CLIENT_SECRET`. `CONFIG_PATH` defaults to `/etc/credentials-broker/config.yaml`; point it at `config.example.yaml` for local runs. `PORT` defaults to `8080`.

## Architecture

credentials-broker is a blackbox credentials proxy: callers hold a broker API key, never the real upstream credential. One route, `/proxy/{target}/{rest...}`, forwards a request to a named target's upstream API, injecting the resolved credential into a configured header.

Request path (`cmd/broker/main.go` wires it all up):

1. `internal/server` — `server.New` registers the single mux route through `withAuthz`, which resolves the caller key and target name, calls `internal/authz.Check`, and logs a hashed caller ID (`internal/reqctx`) into the request context before dispatching.
2. `internal/authz.Check` looks up the caller by key and the target by name in `internal/config.Config` (loaded from YAML, see `config.example.yaml`) and returns one of `Allowed` / `Unauthenticated` / `Forbidden` / `TargetNotFound`.
3. Dispatch is by `target.Mode` via a `map[string]server.DispatchFunc` built in `main.go` — currently `"proxy"` and `"oauth"`, both served by the same `proxy.Serve` handler but with a different `SecretResolver`:
   - **proxy mode** (`internal/secrets`): resolves the target's Infisical secret directly and injects it as-is (`inject_header` / `inject_prefix` from config).
   - **oauth mode** (`internal/oauth`): resolves an Infisical secret holding `{client_id, client_secret, token_url, scope}` JSON, exchanges it for a short-lived access token via OAuth2 client_credentials, caches the token until near expiry, and injects `Authorization: Bearer <token>`.
4. `internal/proxy.Serve` does the actual forwarding: parses `target.BaseURL`, `path.Clean`s the wildcard `rest` path to prevent traversal escaping the base path, forwards method/query/body, and streams the upstream response back verbatim. The caller's own `Authorization` header is never forwarded upstream.

Both `secrets.Client` (`internal/secrets`, talks to Infisical) and `oauth.Client` (`internal/oauth`, wraps a `SecretResolver`) implement the same `SecretResolver` interface consumed by `proxy.Serve`, which is why one `Serve` closure handles both modes.

Full spec: [`docs/spec.md`](docs/spec.md).
