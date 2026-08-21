# Gateway Destination Token Lifecycle Transaction Foundation V1

Status: Accepted by the project-owner merge of Gateway PR #12, merge commit
`09bd3bbe84dcca72a7221454e62777a4e29e20c2`.

The project owner accepted Opaque Destination Token Resolver V1 by merging
Gateway PR #11 at merge commit
`cbd5164db2f99c4cc856836288be22afb88bd440`. This checkpoint adds the narrow,
transport-independent transaction boundary that creates and changes the
existing destination-token records. It uses the published Security State V1
schema without changing either migration.

This is a persistence and domain foundation, not an end-to-end rotation
workflow. It does not change a Core Contact Method URL, coordinate a
cross-repository rotation, expose an HTTP or administrative operation, or wire
the Gateway runtime.

## Operations

The lifecycle service exposes eight distinct operations. They are not combined
behind optional token arguments or a generic state mutation:

1. `CreateStagedToken` creates only an initial-provisioning candidate when no
   live or pending token exists.
2. `CreateRotationStagedToken` creates a rotation candidate only while the
   exact expected active record remains authoritative under the destination
   lock. It also rejects generated raw material equal to the supplied current
   raw token before verifier lookup or persistence. Both create operations
   return the new raw token exactly once and only after insert commit is
   confirmed.
3. `ActivateInitialToken` promotes one exact unexpired staged record when there
   is no active or retiring record.
4. `ActivateRotation` atomically promotes one exact staged record and moves one
   exact old active record to retiring with a fixed overlap deadline. A
   confirmed result returns a redacted activation receipt containing the exact
   immutable activation time and deadline supplied to that committed repository
   command; every error returns a zero receipt.
5. `AbortStagedToken` revokes one exact staged record without changing any
   active token.
6. `RollbackRotation` revokes the exact new active record and restores the exact
   old retiring record strictly before its overlap deadline.
7. `FinalizeRotation` revokes the exact old retiring record. The typed
   `verified-and-drained` reason may complete before the deadline; the typed
   `deadline-elapsed` reason is valid only at or after the deadline.
8. `InspectLifecycleState` returns a bounded, typed, authoritative snapshot for
   future reconciliation. It contains record identities, states and deadlines,
   but no raw token, verifier, key material or destination address.

Every operation validates the local audience and destination relation and
reconstructs persisted state through the existing security-state domain
constructors. Missing, malformed, cross-bound, expired-but-still-live, or
otherwise ambiguous state fails closed. No operation treats a stale state or a
wrong record ID as idempotent success.

## Policy, token and verifier boundary

The service receives an injected clock, random source, token-record-ID
generator, active destination-verifier key source, lifecycle durations, and a
narrow transaction repository. Token lifetime is positive and at most 90 days;
staged cleanup and retiring overlap are positive and at most 24 hours. Token
lifetime must also be strictly longer than retiring overlap. Invalid
configuration fails before a dependency is used.

One top-level operation reads the clock once. Each create operation also
generates one record ID and reads exactly 32 fresh random bytes once. The raw
value has the canonical `mso1_` plus unpadded base64url form. Its verifier
reuses the accepted Resolver V1 domain-separated HMAC-SHA-256 algorithm and the
currently active verifier key. Rotation creation compares the generated and
current fixed-size raw values in constant time before key lookup. This prevents
the same raw token from being inserted under a new verifier key during key
rollover, even though its verifier would differ. Neither raw value is passed to
the repository, database, formatter or diagnostic; persistence receives only
the generated verifier and key ID.

Random failure, short read, record-ID failure, key failure, transaction failure,
or an unconfirmed commit returns no partial result and no raw token. There is no
retry, fallback randomness, regenerated record, replayed transaction, or
recoverable token storage. Returned one-time material is defensively copied and
formats as `[redacted]`.

## PostgreSQL serialization and transitions

Every mutation acquires one connection, starts one explicit read-write
transaction, and locks the exact destination row with `SELECT ... FOR UPDATE`.
The destination row is the cross-instance serialization point. While holding
that lock, the repository reads the complete staged, active and retiring set,
reconstructs and validates it, applies an expected-state insert or update,
checks the exact affected-row count, and commits explicitly.

Partial unique indexes remain a final database defense; they are not used as a
substitute for the destination lock and complete-state validation. A mutation
never silently ignores an expired record that is still stored in a staged,
active or retiring state. At most one staged, one active and one retiring row
may be represented, and the service refuses any transition that would create a
third live or pending token.

Initial creation is deliberately rejected once an active record exists.
Rotation creation carries the participant's expected active record identity;
the repository validates that identity against the complete state while it
holds the same destination lock used for the insert. Therefore a concurrent
active-token transition either produces a pre-insert conflict or leaves an
outcome-unknown record identity that is still bound to the exact active record
used by its reconciliation handle.

Token validity starts when the staged token is created, not when it is
activated. Initial activation is one staged-to-active update. Rotation
activation updates the old active row to retiring and the new staged row to
active in the same transaction, but only when both token expiry timestamps are
strictly later than the complete overlap deadline. Expiry at the exact deadline
is insufficient because token validity is exclusive at expiry. Failure is a
precondition conflict checked after the locked state is reconstructed and
before any mutation or commit; the transaction is rolled back, and the overlap
deadline is never recalculated to fit either token. Before dispatch, the
lifecycle service canonicalizes the activation timestamp and derived deadline
once to PostgreSQL's microsecond timestamp precision. Those exact canonical
values are used by both the repository command and the redacted activation
receipt, so the receipt can never be later than the persisted value because of
sub-microsecond truncation. It releases that receipt only after the repository
confirms the activation; an error or outcome-unknown result carries neither
activation metadata nor token material.
Rollback and finalization require the exact current pair; duplicate, stale and
mismatched transitions fail closed.

Inspection uses one repeatable-read, read-only transaction and the same
complete-state reconstruction rules. It distinguishes unprovisioned, staged
initial, active, active plus staged rotation candidate, and new-active plus
old-retiring overlap. Expired or malformed live state requires reconciliation
and never returns a partially trusted snapshot.

## Transaction uncertainty and errors

Errors use fixed, content-free, unwrapped lifecycle classifications for invalid
input or configuration, precondition conflict, reconciliation-required stored
state, repository unavailability, transaction outcome unknown, cancellation and
deadline. They contain no audience, destination, token, verifier, key ID or key
material, record ID, SQL, database configuration, account or certificate data.
This layer emits no log, metric or trace containing those values.

Any failure, including an interruption after an execution was attempted, may
return the applicable unavailable, conflict or integrity classification only
when rollback is confirmed and therefore proves that no mutation committed.
Once a mutation may have reached PostgreSQL and rollback is not confirmed, or
when a commit acknowledgement is ambiguous, the result is transaction outcome
unknown. The specific pgx result that conclusively reports COMMIT completed as
ROLLBACK is fixed unavailable, not outcome unknown. An unsafe connection is
destroyed, the transaction is never replayed, no compensation is attempted,
and either create operation returns no raw token. For an outcome-unknown insert
it retains only the already-generated record identity so an authorized
coordinator can construct an exact reconciliation handle. A joined or otherwise
mixed mutation error remains outcome-unknown even if the caller is concurrently
canceled or reaches its deadline. Read-only/pre-mutation mixed failures remain
unavailable; cancellation or deadline is recognized from a non-empty dependency
error only when it is the strict single cause. A later caller must use
authoritative inspection and a separately authorized reconciliation workflow.

## Test and runtime boundary

Unit tests cover policy bounds, exact token entropy and verifier behavior,
every lifecycle transition and deadline boundary, malformed and cross-bound
state, affected-row and transaction failures, bounded cleanup, content-free
diagnostics, and race-safe use. Concurrency tests use independent repository
instances and prove that the destination lock serializes competing stage,
activation, rollback and finalization operations without producing a third
live or pending token.

The single-instance PostgreSQL integration test is separately opt-in. It may
operate only on fixed test-owned realm, destination and token records after the
existing mTLS, database-identity and read-write-primary guard succeeds. Cleanup
uses a separate bounded context, deletes test-owned token rows before the
destination and realm, and verifies zero remaining test rows. It is not HA/DR,
failover, fencing, RPO or RTO evidence.

When that dedicated environment is not configured, the integration test is
skipped before opening a database connection. This checkpoint's transaction-
interruption evidence comes from the bounded unit-test seam; it does not claim
that a real PostgreSQL interruption or failover was injected.

The Core Gateway token-only URL compare-and-swap operation was separately
accepted in Core PR #3. The Gateway/Core rotation coordinator is now a separate
in-review checkpoint. Operational HTTP or administrative transport, production
verifier-key source, automated cleanup or rotation scheduler,
Authentication/resolution composition, provider delivery and runtime wiring
remain unimplemented. Gateway continues to use `UnavailableSink`;
otherwise-valid webhooks continue to receive `503 Service Unavailable`, never
`202 Accepted`.
