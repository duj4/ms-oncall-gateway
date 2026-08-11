# Payload Protection V1

Payload Protection V1 is the boundary between a validated Canonical Event
Format V1 value and `durable.PreparedAcceptance`. It protects both the exact
canonical event bytes and their literal SHA-256 equivalence digest before a
durable repository receives them. It is not connected to the HTTP runtime or
to production key configuration in this checkpoint.

## Cryptographic parameters

- Algorithm: AES-256-GCM from the Go standard library.
- Key size: 32 bytes.
- Nonce size: 12 bytes.
- Authentication tag size: 16 bytes, included in the ciphertext returned by
  GCM.
- Event and digest protection use the same active key ID for one preparation.
- Event and digest protection use independently generated nonces. Repeated
  nonces within one preparation are rejected without retry or fallback.
- The canonical event bytes and the literal 32-byte SHA-256 digest are sealed
  separately. A digest of ciphertext is not an equivalence digest.

The literal digest remains in `PreparedAcceptance` only for the current
in-memory duplicate comparison. It must not be persisted or logged in literal
form.

## Authenticated additional data

V1 constructs deterministic binary authenticated additional data in this
exact order:

```text
ASCII "MS_ONCALL_GATEWAY_PAYLOAD_PROTECTION"
0x00
payload protection format version: uint64, big-endian
purpose: one byte
canonical event format version: uint64, big-endian
delivery identity: 16 raw bytes
core principal ID: uint32 big-endian byte length, then UTF-8 bytes
destination ID: uint32 big-endian byte length, then UTF-8 bytes
encryption key ID: uint32 big-endian byte length, then UTF-8 bytes
```

Purpose values are fixed:

- `0x01`: canonical event
- `0x02`: canonical digest

Length prefixes make variable-width fields unambiguous. The AAD is neither
stored inside ciphertext nor written to logs. Authentication binds the
protected value to the protection version, purpose, canonical format version,
delivery identity, principal, destination, and key ID. Changing any bound
field causes opening to fail closed.

Payload Protection V1 is not separately versioned in the current database
schema. The algorithm, AAD bytes and field order, nonce rules, and purpose
values therefore cannot be changed silently. A future format must first add a
persisted version-selection mechanism or an explicit migration.

## Key and rotation boundary

New preparation asks a `KeySource` for one active key. Historical protected
digests are opened by their stored key ID through `KeyByID`. Rotation may
change the active key while retaining older keys for reads. A missing or
retired historical key, an unexpected returned key ID, or an authentication
failure all produce the same fail-closed protected-digest error.

This checkpoint supplies only the key-source interface and test-only in-memory
implementations. It does not load keys from environment variables or files and
does not implement Vault, KMS, HSM, caching, refresh, scheduling, persistence,
or production rotation. There is no plaintext or no-op production key source.

Key construction and all protected-value boundaries defensively copy mutable
byte slices. Go does not provide a guarantee that key or plaintext bytes are
physically cleared from memory.

## Failure and logging boundary

Provider, randomness, cipher, and authentication details are reduced to fixed
safe errors. Errors, logs, and metric labels must not contain principal or
destination identifiers, delivery or receipt identities, key identifiers or
material, canonical bytes, literal digests, ciphertext, nonces, AAD, provider
errors, connection details, or certificate information. Preparation returns a
zero result unless every protection and durable-value construction step
succeeds.

## Current scope

The service prepares durable-domain values and implements the protected digest
opener used by durable duplicate detection. It is not wired into `main`, the
HTTP receiver, or PostgreSQL runtime construction. The runtime deliberately
continues to use `UnavailableSink`, so an otherwise valid webhook remains
`503 Service Unavailable` and cannot return `202 Accepted`.

Authentication, opaque destination resolution, production encryption-key
configuration, worker delivery, retries, providers, callbacks, and HTTP
`202`/`409` mapping remain outside this checkpoint.
