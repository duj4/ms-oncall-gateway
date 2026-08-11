# Gateway Acceptance Pipeline V1

## Boundary

The MS OnCall notification path is Grafana to MS OnCall Core, then the Core
Webhook Contact Method to MS OnCall Gateway, and finally to notification
providers. Gateway does not ingest raw Grafana alerts and does not own on-call
scheduling, escalation policies, or alert lifecycle state.

Acceptance Pipeline V1 is an internal application-service boundary for input
that has already been authenticated and resolved. Its inputs are an immutable
Core principal identifier, an internal destination identifier, the Core
delivery identity, and a validated typed webhook event. The raw opaque routing
token, authentication credentials, provider credentials, destination address,
HTTP request, and HTTP headers never enter this pipeline.

Authentication, authorization, destination resolution, and the opaque-token
lifecycle are intentionally not implemented here.

## Exact processing order

For every top-level call, the service performs these steps once and in order:

1. Validate the service, dependencies, context, request, and required fields.
2. Require a lower-case canonical hyphenated delivery UUID and parse it without
   generating a fallback identity.
3. Canonicalize the known typed event with Canonical Event Format V1.
4. Recheck cancellation.
5. Protect the canonical bytes and literal digest with Payload Protection V1.
6. Verify that the protected acceptance carries the exact principal,
   destination, parsed delivery identity, canonical format version, and literal
   equivalence digest, and that both protected values and the key identifier are
   present.
7. Recheck cancellation.
8. Ask the durable store to accept the protected value.
9. Validate the durable result before returning it by value.

The service never sends unprotected canonical data to the durable store and
does not modify the request, event, metadata map, canonical value, protected
value, or dependency result.

## Durable result invariants

- `AcceptedNew` has a non-zero durable receipt.
- `AcceptedDuplicate` returns the non-zero stable receipt already associated
  with the logical delivery.
- `IdentityConflict` has a zero receipt.
- Unknown dispositions, missing receipts, and conflict results carrying a
  receipt fail closed.

Any error discards every partial result, receipt, or protected value. Invalid
pipeline input and pipeline-detected cancellation use fixed errors. Known safe
canonicalization, protection, and durable-store errors retain their sentinel
classification; unknown dependency errors collapse to fixed safe failures.
Dependency errors are never wrapped. This layer emits no logs, metrics, or
traces, so it cannot expose principals, destinations, delivery identities,
events, canonical bytes or digests, ciphertext, nonces, key identifiers, raw
tokens, or dependency details.

## Current runtime status

This foundation is not wired to the HTTP handler or `main`. The runtime still
uses `UnavailableSink`, and otherwise-valid webhooks still receive
`503 Service Unavailable`. A future HTTP adapter may return `202 Accepted` only
after this pipeline proves a new durable commit or an equivalent existing
durable record. Conflict-to-`409` mapping is also deferred.

Production authentication, authorization, destination resolution and token
rotation/revocation, a production key source, Vault/KMS/HSM integration,
workers, retries, providers, callbacks, and retention remain unimplemented.
Gateway must not read or modify the MS OnCall Core database.
