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
- `gateway_failed` with a bounded reason code.

No SQL body or connection value is included in these events.

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

The DB team may use these read-only checks from an already authenticated
session connected to `<gateway_database>`:

```sql
SELECT migration_version, migration_checksum, applied_at
FROM gateway_schema_migrations
ORDER BY migration_version;

SELECT to_regclass('gateway_schema_migrations') AS migration_metadata_table;
SELECT to_regclass('durable_acceptances') AS durable_acceptance_foundation;
```

Do not place connection strings or credentials in inspection output or support
logs.

## Integration-test isolation

PostgreSQL integration tests run only when both a dedicated enable flag and a
separate test database setting are supplied. They create and remove only a
randomly named schema inside that explicitly authorized test database. HA/DR
tests have separate enable and multi-host settings. Ordinary tests never read
the production database setting and never operate on the Core database.
