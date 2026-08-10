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

`MS_ONCALL_GATEWAY_LISTEN_ADDR` controls the listen address. It defaults to
`127.0.0.1:8080`, a loopback-only development default rather than a production
port or deployment recommendation.

```sh
MS_ONCALL_GATEWAY_LISTEN_ADDR=127.0.0.1:8081 \
  GOTOOLCHAIN=local GOFLAGS=-mod=readonly \
  go run ./cmd/ms-oncall-gateway
```

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

PostgreSQL persistence, migrations, delivery workers, retry policy, providers,
callbacks, Core ACK/Resolve calls, TLS termination, authentication, and
production deployment configuration are not implemented. The loopback default
must not be treated as a substitute for the future authentication and TLS
design.
