# Gateway Security State Foundation V1

Status: In review. This checkpoint implements only the first implementation
step authorized after the project-owner merge of Security Boundary V1 in
Gateway PR #7, merge commit
`9be58c84c705fe2d47a0d03437b6bd5634016c4e`.

This checkpoint does not implement Authentication V1, token resolution,
credential or token administration, Core signing, HTTP status mapping, or
runtime wiring.

## Scope and evidence

Security Boundary V1 fixes HMAC-SHA-256 request authentication, a local
`GatewayAudienceID`, shared replay reservations keyed by credential record and
decoded nonce, and keyed opaque-token verification. Existing migration
`000001_initial_schema.sql` contains only migration metadata and durable
acceptance. It is immutable. Runtime `cmd/ms-oncall-gateway/main.go` still
constructs `httpapi.UnavailableSink`, so otherwise-valid requests remain
`503 Service Unavailable`.

This checkpoint adds:

- additive forward migration `000002_security_state_v1.sql`;
- pure domain value types, static record validation and narrow interfaces in
  `internal/securitystate`;
- unit and opt-in migration integration coverage; and
- operator inspection and backup/restore guidance.

It adds no repository, HMAC, resolver, credential or token administration,
Core operation, secret source, HTTP adapter or runtime connection.

## Forward migration 1 to 2

The existing migration runner applies version 2 in one PostgreSQL transaction
and records its fixed checksum in `gateway_schema_migrations`. The SQL contains
no `BEGIN`, `COMMIT`, down migration, drift-masking `IF NOT EXISTS`, database,
schema, role, extension, function, trigger, grant, seed row or generated UUID.
It neither alters `000001` objects nor references `durable_acceptances`.

All internal UUIDs are supplied by a future application or privileged
administrative operation. Migration 2 creates no realm row. Startup may prove
the schema current, but future security runtime must fail closed until exactly
one configured realm binding exists and matches local configuration.

## Tables and relationships

| Table | Purpose | Primary binding |
| --- | --- | --- |
| `gateway_security_realm` | One logical security realm | One true singleton key and one unique, non-zero audience UUID |
| `core_principals` | Immutable Core identities and explicit intake authorization | Audience plus principal UUID |
| `core_credential_slots` | Rotation position for one Core node or equivalent deployment identity | Audience plus principal plus slot UUID |
| `core_authentication_credentials` | Public credential metadata and lifecycle | Audience, principal and slot; no HMAC secret |
| `authentication_replay_reservations` | Five-minute attempt-nonce reservation | Credential record UUID plus exact 16-byte nonce |
| `gateway_destinations` | Stable internal routing identity and enabled state | Audience plus destination UUID |
| `gateway_destination_tokens` | Keyed token verifier and bounded lifecycle | Audience plus destination, verifier-key ID and verifier |

Every cross-entity relationship includes the same audience where applicable.
A principal references the singleton realm. A credential slot references an
audience-bound principal. A credential references an audience/principal/slot
tuple. A token references an audience-bound destination. This prevents a row
from silently joining metadata from another logical realm.

No foreign key is added from these tables to `durable_acceptances`; existing
durable tests and their current principal/destination string representation are
unchanged.

## Realm and audience binding

`GatewayAudienceID` is a canonical lowercase hyphenated non-zero UUID. Dev,
QA, UAT and production use distinct values. HA and DR instances in the same
logical security realm share one value. The migration stores only the binding
schema and never chooses or seeds an instance value.

Backup or metadata copied under another local audience does not become valid.
Future repositories must compare their local configured audience with the
singleton row and every credential, principal, destination and token lookup.
Missing, duplicate or mismatched realm state fails closed.

## Principals and intake authorization

`core_principals.enabled` and
`core_principals.gateway_intake_v1_authorized` are independent, explicit
booleans. There is no caller-controlled scope string and no principal supplied
by an HTTP header. A future authorizer permits intake only when the verified
credential supplies the stored principal and both flags allow it.

The domain `Principal` value mirrors this rule with an audience-bound,
content-free authorization check. It does not authenticate a request or load a
database row.

## Credential slots and lifecycle

A credential slot is an internal UUID bound to one audience and principal. It
stores no hostname, IP address, certificate subject or secret. Partial unique
indexes allow at most one `active` and one `retiring` credential per slot.

Credential states are `disabled`, `active`, `retiring` and `revoked`.
Expiration is derived from `expires_at`, never represented as a restorable
state. Each record has a public canonical UUIDv4 `credential_id`, immutable
internal record UUID, `not_before`, mandatory expiry and lifecycle timestamps.
The lifetime from `not_before` through `expires_at` is at most 90 days. A
retiring overlap is greater than zero and at most 24 hours. At the exact expiry
or overlap deadline, the credential is no longer usable.

The database contains no Authentication HMAC secret, encrypted secret,
certificate or external secret value. A future `AuthenticationSecretSource`
loads the Authentication-specific secret outside PostgreSQL by the approved
public `CredentialID`; the database-private record ID remains the replay
reservation namespace. A future repository must supply coherent application
timestamps for credential creation and state change rather than mixing an
application `not_before` value with a later database-generated creation time.

## Replay reservation

Authentication replay uniqueness is exactly:

```text
(credential_record_id, nonce_bytes)
```

`nonce_bytes` is the strict decoded 16-byte value. `reserved_at` and
`expires_at` have an exact five-minute difference, and an expiry index supports
future bounded cleanup. Credential rotation never changes an existing record
ID namespace or reservation. There is no nonce hash, replay digest, replay key,
replay key ID or fourth cryptographic key domain.

This checkpoint defines only the `ReplayReservationStore` interface and typed
reserved/duplicate dispositions. It does not reserve, delete or clean a nonce.
Unavailable and ambiguous outcomes remain distinct fixed fail-closed errors.

## Destinations and opaque-token lifecycle

A destination is an audience-bound immutable UUID with `enabled` or `disabled`
state. It stores no phone, email, provider credential, Core alert ID or raw
opaque token.

A destination-token record stores exactly a 32-byte keyed verifier, a bounded
verifier-key ID, lifecycle timestamps, mandatory expiry, staged cleanup
deadline and retiring overlap deadline. The raw `mso1_` token is never stored.
Its domain form validates `mso1_` plus 43 canonical unpadded base64url
characters that decode to exactly 32 bytes; validation creates no real token
and performs no random generation.

States are `staged`, `active`, `retiring` and `revoked`; expiration is derived.
Lifetime is at most 90 days from creation, staged cleanup is at most 24 hours
from creation, and retiring overlap is at most 24 hours from the confirmed
transition time. Exact expiry, cleanup and overlap deadlines are exclusive for
usability.

Stable partial unique indexes enforce at most one row in each of the staged,
active and retiring states per destination. They do not by themselves prevent
the combined active/retiring/staged set from representing a prohibited third
usable or pending token. A future repository must lock the destination row and
check and transition the complete state set in one transaction. That
repository and the rotation/rollback/reconciliation coordinator are not in
this checkpoint and must not use instance-local cache.

## Raw material and three key domains

Exactly three cryptographic key domains exist:

1. Authentication HMAC secrets;
2. Opaque Destination Token verifier keys; and
3. Payload Protection AES keys.

Authentication secrets and destination-verifier keys have separate Go types
and interfaces from each other and from `protection.Key`. The security-state
tables store neither key material nor Authentication secrets. They store only
the bounded verifier-key identifier required to select an external historical
verifier key.

Secret, nonce, raw token, verifier, verifier-key material and key-ID value types
defensively copy mutable bytes. Their default `%v`, `%+v` and `%#v` formatting
is fixed to `[redacted]`. Raw token and secret types expose no `String`,
`GoString`, text-marshalling or JSON-marshalling method. Explicit byte access
returns a fixed value or a copy.

Go does not guarantee physical erasure of sensitive values from memory; this
checkpoint makes no such claim.

## Domain-only interfaces

`internal/securitystate` depends only on the Go standard library and defines:

- `AudienceBindingStore`;
- `CredentialRegistry`;
- `AuthenticationSecretSource`;
- `PrincipalRegistry`;
- `ReplayReservationStore`;
- `DestinationResolver`; and
- `DestinationVerifierKeySource`.

Every interface accepts `context.Context` and strong domain values. None
accepts HTTP headers, URLs, JSON, `httpapi.Delivery`, `intake.Request`, pgx or
SQL types. The raw opaque token exists only at the resolver boundary. A
resolver returns only a stable `DestinationID`, never an email, telephone or
provider address. Fixed sentinel errors discard identifiers, raw material and
dependency text.

Static record constructors validate single-row invariants and audience
relationships already present in memory. They do not implement cross-row
state transitions or replace transactional PostgreSQL enforcement.

## Logging, HA/DR and backup/restore

Errors, logs, metrics and traces must not contain the audience, principal,
credential, slot, nonce, destination, token, verifier, key ID, secret, DSN,
host, account, certificate path or database error. This package emits no logs,
metrics, I/O, SQL or network calls.

Security metadata and migration rows belong in the same database backup.
Authentication secrets, destination-verifier keys and Payload Protection AES
keys remain external and are not recovered from that backup. Before serving,
all instances in the restored logical realm must have the same expected
audience and required external key versions. A missing key or different realm
fails closed.

The existing one-logical-pool, read-write-primary, mTLS and multi-host behavior
is unchanged. A single-instance migration integration test is not HA/DR,
failover, fencing, RPO or RTO validation.

## Integration isolation and runtime boundary

Ordinary tests leave all PostgreSQL integration variables unset and connect to
no database. The existing opt-in migration test can advance a dedicated
version-1 database to version 2, verify exactly one metadata row per version,
prove repeated current inspection does not rewrite timestamps, check all seven
tables and confirm the migration seeded no security row. The separate HA/DR
test retains its own enable condition.

Runtime remains on `UnavailableSink`; legal webhooks still receive `503` with
`Retry-After`. Schema currency, a domain value or a test fake is not request
authentication, destination resolution or durable HTTP acceptance.

## Deferred implementation order

Separate project-owner authorization remains required to:

1. implement the narrow Core Gateway-target signer and privileged token-only
   Contact Method rotation operation;
2. implement Gateway Authentication V1, the PostgreSQL registries and shared
   replay reservation, and opaque-token resolution without runtime wiring;
3. compose those adapters with the existing acceptance pipeline and test all
   HTTP failure and concurrency boundaries;
4. choose and wire production secret sources; and
5. replace `UnavailableSink` only after every prerequisite is accepted.
