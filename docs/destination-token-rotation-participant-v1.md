# Gateway Destination Token Rotation Participant V1

Status: In review

The project owner accepted the Opaque Destination Token Resolver V1 in Gateway
PR #11 at merge commit `cbd5164db2f99c4cc856836288be22afb88bd440`
and the Destination Token Lifecycle Transaction Foundation V1 in Gateway PR
#12 at merge commit `09bd3bbe84dcca72a7221454e62777a4e29e20c2`.
This checkpoint composes those accepted foundations into the Gateway side of a
cross-repository destination-token rotation. It changes no schema, migration,
HTTP endpoint or production runtime wiring.

## Participant boundary

`securitystate.DestinationTokenRotationParticipant` is a narrow,
transport-independent service. Its request binds one trusted Gateway audience,
one destination and the current opaque token. Its attempt and handle bind the
same audience and destination to one exact new-active/old-retiring record pair.
Each confirmed attempt also carries the immutable activation timestamp and
retirement deadline from the lifecycle activation receipt. Requests, receipts,
attempts, handles,
observations, the service and its configuration format only as `[redacted]`.
The public accessors are `ActivatedAt` and `RetirementDeadline`; both are
non-zero only on a confirmed attempt. Every failed handle-only attempt carries
zero values for both and no one-time token.

Token identity is a closed, cross-coordinator contract: `New` is numeric value
`1`, `Old` is `2`, and `Neither` is `3`. Zero and every other value are invalid
and force reconciliation.

`BeginRotation` always performs this order:

1. validate the complete request and caller cancellation;
2. resolve the current token through the accepted verifier/key/repository path
   and require the requested destination;
3. inspect authoritative lifecycle state and require exactly one active token;
4. create one staged token through the rotation-only seam, binding the insert
   under the destination lock to the exact active record from step 3 and
   rejecting generated raw material equal to the current raw token before any
   verifier or repository call;
5. activate the staged record against the authoritative old-active record and
   receive the exact deadline receipt only after that commit is confirmed; and
6. return the one-time new token and those immutable timestamps only while the
   confirmed overlap window is still open.

The participant does not accept an old record ID from the caller. The new
one-time token is defensively copied and is absent from every failed result.
Neither timestamp is caller-provided or recomputed by the participant: both
are the values supplied to the confirmed lifecycle repository command. A zero,
malformed or already elapsed receipt turns the post-activation result into
handle-only reconciliation and suppresses the new token.
After a possibly committed create or activation, or an unconfirmed staged
abort, the failed result contains only a redacted exact-pair handle for
explicit reconciliation. The lifecycle create seam retains the generated
record identity on an outcome-unknown insert, but never the generated token.
The expected-active check and insert share one locked transaction, so any
possibly committed record identity in that handle is bound to the exact old
record in the same handle rather than to a stale pre-lock inspection.

## Failure and compensation rules

There is no retry, replay, token regeneration or speculative compensation.
A staged record is aborted at most once, and only when activation has
conclusively reported that it did not commit. The abort uses a fresh,
cancellation-detached context with a fixed finite timeout; it does not reuse an
expired caller deadline. Only a confirmed abort permits the original fixed
failure classification to be returned.

An activation outcome-unknown result, an unrecognized or joined dependency
error after activation was attempted, or any abort failure returns fixed
reconciliation-required. It never returns the one-time token. A create result
whose commit is not confirmed is never activated. If inspection later proves
the exact new record is staged beside the stable old active record, that
prepared/no-activation state remains reconciliation-required: the participant
does not retry activation or automatically abort it. Joined and mixed errors
are not downgraded to a caller-safe conflict, cancellation or deadline merely
because the caller context changed concurrently. A non-empty dependency error
is classified solely from one strict, unambiguous cause chain.

## Authoritative observation

The public reconciliation read is one `ObserveRotation(handle,
candidateToken)` operation. It first maps the candidate token to the exact new
record, exact old record or neither through the existing bounded verifier
keyring and indexed resolver query. It then reads the latest attempt state, so
a future transport cannot reorder identity and state as two independent public
operations.

The attempt-specific PostgreSQL inspection uses one repeatable-read, read-only
transaction. In that snapshot it reads both the complete non-revoked lifecycle
set and the two handle-selected records, including revoked records. The bounded
result contains lifecycle states, timestamps and the retirement deadline, but
no raw token, verifier or key metadata. An active-pair observation also carries
`ObservedAt`, the same Gateway clock snapshot supplied to identity and attempt
inspection, plus the authoritative retirement deadline. Rolled-back and
completed observations carry zero `ObservedAt` and zero deadline.

The observation recognizes only:

- the exact new-active/old-retiring pair;
- an exact rollback proven by the revoked new record and restored old-active
  record, including an abort-before-activation terminal. The old row may retain
  a state-change timestamp from an earlier rollback, but that stable change
  must not be later than this candidate's creation, which in turn must not be
  later than its abort; or
- exact completion proven by the active new record and revoked old record with
  retained retirement history.

A live-state-only read cannot claim a terminal result. Missing counterparts,
another live record, mismatched binding or history, a disabled destination, an
expired new-active token, a future timestamp, or malformed state fails closed.
The pair and completion proofs require the recorded deadline to be strictly
before both token expiries. Rollback rejects any retirement history on the new
record. An activated rollback additionally requires the exact new revocation
and old restoration timestamp to match, the revocation to precede the new-token
expiry, and the activation-to-revocation interval to be strictly below the
maximum 24-hour overlap. Completion revalidates both complete record histories.
Every activated state—live pair, rollback or completion—also proves that the
new record was created no earlier than the old record's activation and that the
new activation occurred strictly before its staged-cleanup deadline. Equality
with or passage beyond that cleanup deadline is malformed history.
Successful rollback clears the old row's recorded retirement timestamps, so a
terminal snapshot cannot compare its revocation time directly with that
attempt's erased deadline. It does not treat a sub-24-hour interval as proof of
that comparison. Terminal recognition relies on the accepted lifecycle
repository being the sole serialized writer: while holding the destination
lock, it rejects rollback at or after the recorded deadline before issuing
either mutation. The interval and expiry predicates are additional corruption
guards. A writer which bypasses that repository violates the V1 contract.
At or after the retirement deadline, the generic lifecycle snapshot normally
has reconciliation-required status because the old token is no longer usable.
The participant recognizes that state as the exact pair only when every other
pair, binding, expiry and history invariant remains valid.

## Exact rollback and deadline finalization

Rollback and finalization each re-read the exact attempt before mutation and
then call the accepted lifecycle primitive with the handle's exact pair. A
stale, mismatched or repeated handle is never idempotent success. Rollback is
permitted only strictly before the authoritative retirement deadline.

V1 finalization accepts no caller-provided drain boolean and exposes no early
verified-and-drained path. It requires the exact pair at or after its recorded
deadline and always calls lifecycle finalization with the fixed
`deadline-elapsed` reason. A scheduler, cleanup worker and durable-delivery
drain proof remain outside this checkpoint.

## Runtime and validation boundary

Unit and race coverage fixes the begin/abort/outcome matrix, joined-error plus
concurrent cancellation/deadline behavior, redaction and defensive result
copying, exact observation terminal proofs, identity of active, retiring,
revoked and expired records, deadline finalization, stale and repeat rejection,
and concurrent begin behavior. PostgreSQL seam tests prove the
bounded resolver query contains no raw token and the attempt inspection reads
live and exact terminal records in one read-only snapshot.

No production participant is wired by this checkpoint. Gateway still uses
`UnavailableSink`; otherwise-valid webhook requests still receive `503 Service
Unavailable`, never `202 Accepted`. Core coordination, operational transport,
Authentication/resolver HTTP composition, production verifier-key injection,
delivery and provider behavior remain separately authorized work.
