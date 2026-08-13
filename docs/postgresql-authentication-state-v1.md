# PostgreSQL Authentication State Repositories V1

Status: Accepted by the project-owner merge of Gateway PR #10, merge commit
`1e22c4058350dc4889235772017547082bb01556`.

This checkpoint implements only the PostgreSQL-backed dependencies required by
the accepted transport-independent Authentication V1 service:

- `securitystate.AudienceBindingStore`;
- `securitystate.CredentialRegistry`;
- `securitystate.PrincipalRegistry`; and
- `securitystate.ReplayReservationStore`.

It uses the accepted version-2 schema without changing either published
migration. The existing one-logical-`pgxpool`, read-write-primary, multi-host and
verified-TLS behavior remains the connection boundary.

## Read repositories

Realm binding performs a fresh singleton query for every request. Exactly one
true singleton row must contain one canonical non-zero `GatewayAudienceID`;
missing, repeated, malformed or uncertain state fails closed and is not cached.

Credential lookup is parameterized by the locally configured audience and the
public canonical UUIDv4 credential ID. The credential row is the primary query
record and its slot and principal are left joined. This distinction preserves a
deterministic credential absence while treating a missing or inconsistent
relationship as server-side integrity failure. The repository scans every
lifecycle timestamp and reconstructs `Principal`, `CredentialSlot`, then
`Credential` through the existing domain constructors. It never reads an
Authentication secret.

Only confirmed global absence of the public credential row returns
`ErrCredentialNotFound`. An existing record with the wrong audience, an invalid
relationship or lifecycle, a missing derived principal, and every uncertain
repository result fail closed as server-side unavailable or integrity errors.

Principal lookup is parameterized by audience and principal ID and reconstructs
the domain record through `NewPrincipal`. Disabled and
`gateway_intake_v1_authorized=false` records are returned normally for the
Authentication service to classify. A missing principal derived from a verified
credential is an integrity failure, not caller authorization failure.

## Replay reservation

One parameterized PostgreSQL statement inserts:

```text
(credential_record_id, exact decoded 16-byte nonce, now, now + 5 minutes)
```

It uses `ON CONFLICT ON CONSTRAINT
authentication_replay_reservations_pkey DO NOTHING RETURNING`. A confirmed row
is `ReplayReserved`; confirmed no row is `ReplayDuplicate`. The repository uses
the exact clock snapshot passed by Authentication V1 and never substitutes a
database default.

An acquire failure or ordinary confirmed SQL failure is unavailable. A network,
EOF, timeout or cancellation interruption after the write begins makes the
result unknown. The connection is hijacked and closed rather than returned to
the pool, and the repository never retries, replays or compensates the insert.
Cancellation and deadline remain recognizable to the Authentication service,
which retains its existing cancellation priority.

## Errors, tests and deferred scope

All returned errors have bounded, content-free classifications. PostgreSQL
driver text, SQL, DSN, host, database account, certificate paths, audience,
credential, principal, record identifiers and nonce bytes never enter errors,
logs, metrics or traces. The repository emits no logs, metrics or traces.

Ordinary unit and race tests use narrow fake connection/query seams. The
single-instance integration test is opt-in, validates the existing dedicated
database/mTLS/read-write guard, and owns and cleans only fixed test records. It
does not validate failover. The HA/DR integration test retains a separate opt-in
environment and skip reason.

Opaque Destination Token Resolver V1 was separately accepted in Gateway PR
#11, merge commit `cbd5164db2f99c4cc856836288be22afb88bd440`. It reuses this
repository foundation's single logical read-write pool and the accepted
destination/token tables, but does not modify these four Authentication State
repository interfaces or their error classifications. Destination Token
Lifecycle Transaction Foundation V1 is in review over the same published
schema.

The privileged Core token-only operation, cross-repository rotation
coordination, production Authentication and verifier-key sources, HTTP
authentication and resolution composition, status mapping, replay cleanup,
runtime wiring and `202 Accepted` remain unimplemented. Runtime remains
deliberately wired to `UnavailableSink`, and otherwise-valid webhooks continue
to receive `503 Service Unavailable`.
