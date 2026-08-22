# credentials-broker

A blackbox credentials broker for AI agents. Agents and services talk to the
broker over HTTP by target name (e.g. `postgres`, `stripe`) and a reason; the
broker resolves the target against [Infisical](https://infisical.com), holds
the real credential itself, and either proxies the request (injecting auth
headers) or executes it on the caller's behalf (e.g. running a SQL query) —
the caller never sees the underlying secret.

Runs as a Docker container, deployed via Portainer.

**Status:** design phase — see `docs/` for the spec once it lands.

## License

Apache 2.0 — see [LICENSE](LICENSE).
