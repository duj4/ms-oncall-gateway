# Gateway PostgreSQL operations

This document defines the ownership and startup boundary for the Gateway-owned
PostgreSQL database. Values in angle brackets are placeholders, not deployment
defaults.

## Ownership boundary

The DB team owns:

- the PostgreSQL instance or logical HA/DR cluster;
- one independent Gateway database and one independently scoped Gateway
  database identity;
- database-level permissions, PostgreSQL replication and node health;
- primary selection, promotion, demotion, fencing, quorum and split-brain
  prevention;
- backup, restore, monitoring, engine upgrades, RPO and RTO.

The Gateway application owns only objects inside its database:

- Gateway tables, indexes and constraints;
- forward-only, versioned migration files shipped inside the binary;
- automatic first-start initialization and startup upgrades;
- migration version and checksum validation;
- failure before the HTTP listener starts when the schema cannot be proved
  current.

The DB team supplies an empty database and an account with the DDL and DML
permissions required by its normal policy inside that database. The project
does not require separate migration and runtime accounts. Gateway does not
create a PostgreSQL instance, database, role or user, change grants, or access
Core or another application's database. The DB team does not manually select
or execute migration SQL during an ordinary Gateway release, and the project
owner does not need to hold a routine DDL administration account.

PostgreSQL engine versions and Gateway application schema versions are
independent. Engine upgrade planning remains with the DB team; application
migrations must not be used as a replacement for backup, restore, replication,
or an engine upgrade procedure.

## Connection configuration

Gateway reads one project-specific setting:

```text
MS_ONCALL_GATEWAY_DATABASE_URL=postgresql://<gateway_user>@<pg_same_dc_1>:5432,<pg_same_dc_2>:5432,<pg_dr_dc>:5432/<gateway_database>?target_session_attrs=read-write&connect_timeout=<seconds>&sslmode=verify-full
```

The URI may contain one host for development or multiple hosts belonging to
the same logical Gateway PostgreSQL HA/DR cluster. It represents one database
and creates one logical `pgxpool`; it is not one DSN or pool per node. Address
order is attempt priority, so the DB team may put same-DC nodes before a DR-DC
node. Gateway delegates fallback and read-write validation to pgx, preserves
the parser's primary and fallback configurations, and connects to the first
candidate that accepts write transactions.

`target_session_attrs=read-write` is mandatory. Gateway adds the equivalent
pgx validation when the parameter is absent and rejects `any`, `read-only`,
`standby`, `prefer-standby`, `primary`, and other conflicting values. A node
that accepts TCP/TLS connections but is a standby does not make Gateway ready.
If the first node is unavailable or read-only, pgx tries later addresses. If no
candidate is writable, Gateway fails before opening its HTTP listener.

`connect_timeout` is bounded to at most 30 seconds per pgx connection process;
an omitted value uses five seconds. The optional
`MS_ONCALL_GATEWAY_DATABASE_STARTUP_TIMEOUT` bounds the complete connection,
lock and migration startup stage, defaults to two minutes, and cannot exceed
ten minutes.

Gateway requires `sslmode=verify-full`. For multi-host mTLS, every configured
FQDN must be present in the matching server certificate SAN, or the DB team
must supply a service name compatible with its certificate standard. pgx
builds the TLS server name for the primary and every fallback. Gateway does not
rewrite host, port, TLS configuration or fallbacks independently, does not
lower TLS verification, and never logs database URLs, addresses, user names,
passwords, certificate paths, certificate contents or private keys.

## Automatic schema lifecycle

The startup order is:

```text
parse one- or multi-host configuration
  -> connect to a read-write node through one pgxpool
  -> acquire the Gateway migration advisory lock on one dedicated connection
  -> inspect and apply pending migrations
  -> prove the application schema current
  -> start the existing HTTP server with UnavailableSink
```

Migration files are embedded in the binary and use contiguous six-digit
versions. Each pending migration runs in its own PostgreSQL transaction. Its
DDL and the version/checksum record commit or roll back together. Applied files
are immutable; a later release adds a new forward migration rather than editing
an old one. Runtime startup never performs down migration, skips a version,
repairs metadata, changes a stored checksum, or continues after an invalid or
ahead schema.

The session advisory lock uses the stable application-specific bigint value
represented in source as hexadecimal `0x4d534f4e43414c4c` (`MSONCALL`). The same
dedicated connection holds the lock across initial inspection, every pending
migration and final inspection. Lock waiting is bounded by the startup context.
If acquisition or release cannot be confirmed, startup fails and the
connection is destroyed rather than returned to the pool with a possible lock.

Non-sensitive log events distinguish:

- `database_connecting`;
- `database_connected_read_write`;
- `database_schema_inspected` with bounded status and numeric version;
- `database_migration_starting` and `database_migration_applied` with numeric
  application schema version;
- `database_schema_current`;
- `gateway_failed` with reason `database_migration_interrupted` when a bounded
  transaction cleanup, connection loss, cancellation, deadline, or commit
  outcome cannot be confirmed;
- `gateway_failed` with a bounded reason code.

No SQL body or connection value is included in these events.

Application schema version 2 is the additive Security State Foundation V1.
It creates the realm binding, Core principal and credential metadata, replay
reservations, destinations and keyed token-verifier metadata. It changes no
version-1 table or row, seeds no realm or security identity, and stores no
Authentication secret, raw destination token or token-verifier key material.
`000001_initial_schema.sql` remains immutable.

Rollback cleanup uses the earlier of the startup/migration deadline and a
finite local timeout. A failed or unconfirmed rollback marks the migration
connection unsafe: it is removed from the pool, closed with a bounded context,
and the startup fails with `database_migration_interrupted`. Gateway does not
retry or replay that migration transaction. Ordinary PostgreSQL SQL, DDL,
permission, and constraint errors remain the separate bounded migration-failed
category.

## HA, failover and cross-DC DR boundary

All configured instances must expose replicas of the same logical Gateway
database. Gateway maintains one logical copy of its tables and migration
metadata; PostgreSQL replication carries that state to cluster nodes. Gateway
does not perform application-level dual writes, fan-out writes, read/write
splitting, standby reads, topology discovery, replication, promotion,
demotion, fencing or cluster management.

After PostgreSQL promotion completes, new pgx connections re-evaluate the
configured addresses and `read-write` condition. Existing connections and
transactions do not move transparently to a new primary. A connection break
during migration causes that Gateway startup to fail. It does not replay an
unknown transaction on another node. A later top-level execution or restart
creates/selects a new connection, reacquires the advisory lock, reruns the
inspector against the new primary, and proceeds only when the replicated schema
is classified as `current` or can be advanced normally.

The advisory lock protects concurrent Gateway migrations only inside the
currently connected writable database. It cannot coordinate two incorrectly
fenced, divergent writable primaries. Preventing split brain and defining
cross-DC replication, promotion, RPO, RTO and switchover procedures remain PG
team responsibilities. Multi-host client fallback does not promise zero
downtime, transparent transaction migration, automatic business-transaction
replay or zero-data-loss DR.

## Backup, restore and inspection

A database dump/restore must preserve Gateway tables, data, and
`gateway_schema_migrations` rows together. After restore, Gateway validates the
version sequence and checksums and applies only migrations that are genuinely
missing. Re-running the initial migration is not a backup, restore or engine
upgrade procedure. Future destructive or high-risk migrations require separate
review and coordination with the DB team; the initial migration is additive.

Version-2 backup and restore must preserve the security realm, principal,
credential, replay, destination and token metadata together with both migration
rows. Authentication HMAC secrets, destination-verifier keys and Payload
Protection AES keys are external and are not recoverable from the database
backup. Before restored instances serve traffic, operators must prove that the
local `GatewayAudienceID` equals the restored singleton binding and that every
required external key version is available. A wrong realm or missing key fails
closed. Instances in one logical HA/DR realm share that audience; a restored
clone intended as another realm must not reuse the metadata as active state.

The DB team may use these read-only checks from an already authenticated
session connected to `<gateway_database>`:

```sql
SELECT migration_version, migration_checksum, applied_at
FROM gateway_schema_migrations
ORDER BY migration_version;

SELECT to_regclass('gateway_schema_migrations') AS migration_metadata_table;
SELECT to_regclass('durable_acceptances') AS durable_acceptance_foundation;

SELECT gateway_audience_id, created_at
FROM gateway_security_realm;

SELECT enabled, gateway_intake_v1_authorized, count(*)
FROM core_principals
GROUP BY enabled, gateway_intake_v1_authorized
ORDER BY enabled, gateway_intake_v1_authorized;

SELECT credential_state, count(*)
FROM core_authentication_credentials
GROUP BY credential_state
ORDER BY credential_state;

SELECT count(*) AS replay_reservations,
       min(expires_at) AS earliest_expiry,
       max(expires_at) AS latest_expiry
FROM authentication_replay_reservations;

SELECT destination_state, count(*)
FROM gateway_destinations
GROUP BY destination_state
ORDER BY destination_state;

SELECT token_state, count(*)
FROM gateway_destination_tokens
GROUP BY token_state
ORDER BY token_state;
```

Do not place connection strings or credentials in inspection output or support
logs.

## Integration-test isolation

PostgreSQL integration tests run only when both a dedicated enable flag and a
separate, explicitly authorized, disposable test database setting are supplied.
Before a mutation, the harness validates `sslmode=verify-full`,
`target_session_attrs=read-write`, certificate-file accessibility, private-key
permissions, the current database identity, a writable primary, TLS, and a
non-empty client certificate DN. It then uses only the embedded migration runner
and the Gateway application tables. Durable-acceptance test cleanup is limited
to `TRUNCATE durable_acceptances`; it does not create or drop a database, schema,
role, extension, replication object, or server setting.

HA/DR tests have separate enable and multi-host settings. A passing
single-instance version-1-to-version-2 migration test is not failover, fencing,
RPO, RTO or cross-DC validation. Ordinary tests never
read the production database setting and never operate on the Core database.

## Durable acceptance persistence checkpoint

The `internal/durable` service and PostgreSQL repository persist records that
have already been authenticated, resolved, canonicalized, and protected by
future upstream layers. They are deliberately not wired to the HTTP runtime.
The running Gateway continues to use `UnavailableSink`, and a persisted
`durable_acceptances` row is not yet a complete delivery job. Therefore this
checkpoint does not permit `202 Accepted` or conflict mapping at HTTP intake.

Each top-level store call generates one UUIDv4 receipt candidate in the
application, acquires one connection from the existing logical read-write pool,
and opens one read-write, read-committed transaction. The repository executes a
parameterized insert with `ON CONFLICT ON CONSTRAINT
durable_acceptances_delivery_identity_unique DO NOTHING RETURNING receipt_id`.
A returned receipt becomes `AcceptedNew` only after a confirmed commit. A
conflict performs a separate select in the same transaction and commits before
the domain service opens the protected digest and compares its literal SHA-256
value in constant time. Matching format version and digest return the stored
receipt as `AcceptedDuplicate`; a mismatch returns `IdentityConflict` without a
receipt or mutation.

There is no transaction retry or replay. A receipt primary-key collision is an
ordinary store failure. An interrupted insert, unconfirmed rollback, or
unconfirmed commit is an outcome-unknown failure and destroys the connection
instead of returning it to the pool. A later top-level request may inspect the
same durable identity in a new transaction; it must not replay the previous
transaction. Missing or retired protection keys and protected digests that
cannot be opened fail closed as an unreadable stored record.

Store errors expose only fixed classifications. Logs and metric labels must not
contain principals, destinations, delivery identities, receipts, protected
bytes, literal digests, key IDs, connection settings, certificate paths, or SQL.
The checkpoint supplies only the digest-opening interface seam and test fakes;
production encryption, key injection, rotation, retention, update, deletion,
workers, providers, and HTTP wiring remain unimplemented.

## Authentication state repositories

PostgreSQL Authentication State Repositories V1 was accepted by the
project-owner merge of Gateway PR #10, merge commit
`1e22c4058350dc4889235772017547082bb01556`. It implements only the accepted
security-state interfaces for realm binding, credential lookup, principal
lookup and shared replay reservation. Every read uses the existing single
logical read-write pool and reconstructs domain values through their public
constructors. A credential query begins with the public credential row and uses
left joins so a broken principal or slot relationship cannot be reported as a
caller-visible unknown credential. Principal disabled and intake-authorization
flags remain separate normal record fields.

Replay reservation is one parameterized insert on the exact
`(credential_record_id, nonce_bytes)` primary key. It stores the exact decoded
16-byte nonce and the Authentication service's one clock snapshot as
`reserved_at`, with `expires_at` exactly five minutes later. A confirmed insert
is reserved and a confirmed named-key conflict is duplicate. A connection
interruption after the write begins or an unconfirmed result is outcome unknown:
the connection is destroyed and the transaction is never replayed. A later
top-level request makes its own decision.

Only a confirmed absence of the globally unique public credential record is
`ErrCredentialNotFound`. An audience mismatch, broken relationship, missing
derived principal, malformed record or repository failure is a fixed
unavailable/integrity classification. Cancellation remains recognizable, and
unconfirmed replay completion is outcome unknown. These classifications contain
no SQL, driver text, connection setting, identifier or nonce. Ordinary unit
tests use fakes and no database.
The single-instance PostgreSQL integration test is separately opt-in and is not
HA/DR evidence; the multi-instance HA/DR test retains its independent switch.

## Opaque destination-token resolution

Opaque Destination Token Resolver V1 is in review. For each request it obtains
all one or two explicitly configured verifier keys, computes the fixed
domain-separated HMAC-SHA-256 candidates in memory, and performs one bounded
parameterized indexed lookup per candidate. SQL receives only the local
audience, configured key ID and computed verifier, never the raw token.

The token query starts from `gateway_destination_tokens` and left joins
`gateway_destinations`. The resolver reconstructs both rows through public
security-state constructors, confirms every audience, ID, key-ID and verifier
relationship, compares verifiers in constant time and applies the caller's one
clock snapshot. Confirmed absence and every unusable lifecycle state share
`ErrDestinationNotFound`. Missing keys, malformed or cross-bound rows, multiple
matches and repository uncertainty fail closed as fixed server-side errors.
Interrupted connections are destroyed; confirmed ordinary read failures release
the connection. There is no cache, retry, replay, compensation query, log,
metric or trace.

This repository and resolver scope does not implement Authentication secrets,
token creation or rotation, privileged Core mutation, production verifier-key
sources, HTTP composition or runtime wiring. The running binary continues to
use `UnavailableSink`, so otherwise-valid webhook requests remain
`503 Service Unavailable`; `202 Accepted` remains prohibited.
