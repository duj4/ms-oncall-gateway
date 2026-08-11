# ms-oncall-gateway

MS OnCall Gateway is an independently running notification-delivery component.
The current implementation is a safe HTTP intake skeleton: it validates and
type-decodes Core webhook requests but has no durable queue or provider.

## Build and run

Go 1.25 or newer is required.

```sh
GOTOOLCHAIN=local GOFLAGS=-mod=readonly go build ./cmd/ms-oncall-gateway
GOTOOLCHAIN=local GOFLAGS=-mod=readonly go run ./cmd/ms-oncall-gateway
```

Gateway requires its own PostgreSQL database and database identity before it
starts the HTTP listener. The application automatically initializes and
upgrades its versioned schema at startup. `MS_ONCALL_GATEWAY_DATABASE_URL`
accepts one PostgreSQL host or a pgx-compatible multi-host URI. It must use
`sslmode=verify-full`; Gateway forces `target_session_attrs=read-write` when it
is absent and rejects conflicting values.

```text
postgresql://<gateway_user>@<pg_same_dc_1>:5432,<pg_same_dc_2>:5432,<pg_dr_dc>:5432/<gateway_database>?target_session_attrs=read-write&connect_timeout=<seconds>&sslmode=verify-full
```

`MS_ONCALL_GATEWAY_DATABASE_STARTUP_TIMEOUT` optionally bounds connection,
migration-lock, inspection, and migration startup work. It defaults to `2m`
and cannot exceed `10m`. PostgreSQL `connect_timeout` defaults to five seconds
when absent and cannot exceed 30 seconds.

`MS_ONCALL_GATEWAY_LISTEN_ADDR` controls the listen address after database
preparation succeeds. It defaults to `127.0.0.1:8080`, a loopback-only
development default rather than a production port or deployment
recommendation.

```sh
MS_ONCALL_GATEWAY_DATABASE_URL='<approved PostgreSQL multi-host URI>' \
  MS_ONCALL_GATEWAY_LISTEN_ADDR=127.0.0.1:8081 \
  GOTOOLCHAIN=local GOFLAGS=-mod=readonly \
  go run ./cmd/ms-oncall-gateway
```

See [PostgreSQL operations](docs/postgresql-operations.md) for the DB team and
Gateway ownership boundary, automatic migration behavior, multi-instance
HA/DR limitations, mTLS requirements, and read-only inspection SQL.

## HTTP endpoints

- `POST /v1/goalert/contact-method/{opaque_token}` strictly validates the
  documented Core payload, content type, 256 KiB body limit, and canonical
  UUID `Idempotency-Key`.
- `GET /healthz` reports process liveness.
- `GET /metrics` exposes a bounded-label Prometheus request counter.

The runtime intentionally connects the intake handler to an unavailable sink.
Every otherwise-valid webhook therefore returns `503 Service Unavailable` with
`Retry-After`; it never returns a false success while durable acceptance is
missing. Tests inject an accepting sink to exercise the future `202 Accepted`
handoff contract.

The PostgreSQL schema and automatic migration foundation is implemented, but
the HTTP sink does not read or write the foundation table. Delivery workers,
retry policy, providers, callbacks, Core ACK/Resolve calls, HTTP authentication,
destination resolution, event encryption, and production deployment
configuration are not implemented. The loopback default must not be treated as
a substitute for the future authentication and HTTP TLS design.
