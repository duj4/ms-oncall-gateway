# Gateway Opaque Destination Token Resolver V1

Status: Accepted by the project-owner merge of Gateway PR #11, merge commit
`cbd5164db2f99c4cc856836288be22afb88bd440`.

This checkpoint implements the existing transport-independent
`securitystate.DestinationResolver` over the accepted Security State V1 schema.
It resolves a validated opaque token to one stable internal `DestinationID` and
returns no address, provider, raw token, verifier or key metadata to downstream
layers.

The PostgreSQL Authentication State Repositories V1 dependency was accepted by
the project-owner merge of Gateway PR #10, merge commit
`1e22c4058350dc4889235772017547082bb01556`. This resolver reuses the same
single logical read-write `pgxpool`; it adds no migration and changes no
published schema.

## Verifier and bounded keyring

For each explicitly configured verifier key, the resolver calculates
HMAC-SHA-256 over exactly:

```text
ASCII "MS_ONCALL_GATEWAY_DESTINATION_TOKEN_V1"
0x00
canonical GatewayAudienceID ASCII bytes
0x00
32 raw token bytes
```

The configured key-ID list contains one active key and, optionally, one
retiring or historical key. It must contain at least one and no more than two
valid, distinct IDs and is defensively copied at construction. IDs never come
from the request or database discovery. Every call reloads every configured key
through `DestinationVerifierKeySource`; the resolver retains no key material or
state cache.

Authentication HMAC secrets, destination-verifier keys and Payload Protection
AES keys remain three separate key domains. A verifier key is never substituted
with either other key type. The complete configured key set is evaluated even
when an earlier key produces a match. If any required key is missing, malformed
or unavailable, the entire resolution fails closed rather than returning a
partial success.

## Indexed lookup and domain reconstruction

Each candidate query is parameterized by only the locally expected audience,
configured key ID and computed 32-byte verifier. The raw token is never a SQL
parameter or stored value. The query starts from `gateway_destination_tokens`,
uses its unique `(gateway_audience_id, verifier_key_id, token_verifier)` access
path, and left joins `gateway_destinations` so a missing or wrongly bound
destination cannot be confused with token absence.

For every row, the resolver scans all identifiers, states and lifecycle
timestamps. It reconstructs `securitystate.Destination` and
`securitystate.DestinationToken` through their public constructors, confirms the
expected audience, token-to-destination IDs, configured key ID and stored
verifier, and compares the stored and computed verifier in constant time.

One `Resolve` call uses the caller-supplied clock snapshot for all lifecycle
checks. Only an enabled destination with an active token, or a retiring token
strictly before its overlap deadline, resolves. Activation is inclusive;
expiry and retirement deadlines are exclusive. Staged, revoked and expired
tokens never resolve.

The resolver performs fresh key-source and PostgreSQL reads on every call. It
does not cache destination, token, key, revocation or lifecycle state. Two
instances connected to the same logical read-write database therefore observe
the same persisted state subject to normal PostgreSQL visibility.

## Fail-closed errors and connection handling

Confirmed absence, a disabled destination, a staged or revoked token, expiry,
and an elapsed retiring overlap all return the same fixed
`securitystate.ErrDestinationNotFound`. This preserves one generic future
caller behavior and does not create a token-existence oracle.

Repository unavailability and record-integrity failures have separate fixed,
content-free server-side classifications. They include acquire, query or scan
failure; nil dependencies or rows; invalid configuration; unavailable keys;
malformed or cross-bound records; verifier or key-ID mismatch; and multiple
matches across the configured key set. None is downgraded to not-found.
Cancellation and deadline remain recognizable and take priority. Connection
interruptions destroy the acquired connection; confirmed ordinary failures
release it. The resolver performs no retry, replay, compensation query, log,
metric or trace.

Errors and diagnostics contain no audience, destination, token, verifier, key
ID or material, database setting, account, certificate path, SQL or dependency
text.

## Test and runtime boundary

Unit coverage uses narrow fake key-source, connection and row seams. It covers
the hard-coded cross-implementation verifier vector, bounded keyring behavior,
active and retiring lifecycle boundaries, generic not-found states, full record
reconstruction, constant-time confirmation, multi-match integrity failure,
connection handling, cancellation, redaction, no cache and concurrent use.

The single-instance PostgreSQL integration test is separately opt-in, reuses
the existing dedicated database, verified mTLS and read-write-primary guard,
and owns and removes only its fixed test realm, destination and token rows in
dependency order. When disabled it uses the repository's existing exact skip
reason. It is not HA/DR, failover, fencing, RPO or RTO evidence.

The separately authorized Destination Token Lifecycle Transaction Foundation V1
checkpoint is in review. It adds transaction-scoped creation and lifecycle
primitives but does not change this resolver's read behavior.

The accepted resolver does not implement the privileged Core mutation, the
cross-repository rotation coordinator, a production key source, HTTP
authentication/resolution composition, status mapping, runtime wiring, replay
cleanup, provider work or `202 Accepted`. Gateway runtime remains deliberately
wired to `UnavailableSink`; otherwise-valid webhooks continue to receive
`503 Service Unavailable`.
