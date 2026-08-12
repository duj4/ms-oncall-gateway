# Core to Gateway Security Boundary V1

Status: Proposed in this PR. Merge by the project owner after formal review records approval as Security Boundary V1.

Creating or publishing this Draft PR is not approval. Only a project-owner merge
after formal review approves the exact Authentication V1 and Opaque Destination
Token V1 decisions in this document. No behavior described here is implemented
by this documentation change.

## Scope and fixed architecture

The request path remains:

```text
Grafana -> MS OnCall Core -> MS OnCall Gateway -> notification providers
```

Core owns alerts, schedules, escalation and the persisted
`outgoing_messages.id`. Gateway owns intake security, destination resolution,
durable acceptance and future provider delivery. Gateway never reads Core
database tables. The opaque destination token selects a Gateway destination; it
is not Core authentication, a delivery identity or a destination address.

This decision covers only the future Core-to-Gateway authentication and opaque
destination-token boundary. It does not implement authentication, resolution,
runtime wiring, an HTTP status change, a key source, a schema migration, a
worker, a provider or a callback.

## Confirmed implementation evidence

### Gateway

- `internal/httpapi/handler.go` (`Handler.handleWebhook`) currently extracts the
  raw path token, validates `Idempotency-Key`, reads a body bounded to 262,144
  bytes, decodes the typed event and passes all three values to `Sink.Enqueue`.
  It has no authentication or destination lookup.
- `internal/httpapi/types.go` (`Delivery`) currently contains the raw `Token`,
  delivery `Identity` and typed `Event`. `UnavailableSink.Enqueue` is the safe
  default.
- `internal/intake/service.go` (`Request` and `Service.Accept`) deliberately
  starts after authentication and resolution. It requires trusted
  `CorePrincipalID` and `DestinationID` and accepts no raw token, credential,
  request or header.
- `internal/protection/key.go` defines the Payload Protection `KeySource`, and
  `internal/protection/service.go` uses that key only for AES-256-GCM event and
  digest protection. Authentication credentials and token-verifier keys must
  use separate types, sources, material and key-ID namespaces.
- `internal/durable/store.go` and `internal/postgres/migrations/000001_initial_schema.sql`
  bind durable identity to `core_principal_id`, `destination_id` and
  `core_delivery_identity`. Migration `000001` contains no principal,
  authentication credential, replay nonce, destination or token-verifier
  registry.
- `cmd/ms-oncall-gateway/main.go` (`serveHTTP`) still constructs
  `httpapi.UnavailableSink`. An otherwise-valid request therefore remains
  `503 Service Unavailable`; the acceptance pipeline is not wired into the
  runtime.

### Core and pristine GoAlert v0.34.1

- `notification/webhook/nfydest.go` (`Sender.TypeInfo`) defines one generic
  Webhook Contact Method field, `webhook_url`. It defines no custom header,
  authorization credential, signing key or client-certificate field.
- `gadb/dest.go` (`DestV1`) stores destination arguments as strings, and
  `migrate/schema.sql` stores the contact-method destination in
  `user_contact_methods.dest` as JSONB. `user/contactmethod/store.go`
  (`Store.Create` and `Store.Update`) persists the destination and does not
  permit it to be changed after creation.
- `notification/webhook/sender.go` (`Sender.SendMessage`) reads the complete URL
  from `webhook_url`, serializes the body, creates an HTTP `POST`, sets only
  `Content-Type` and `Idempotency-Key`, and applies a three-second request
  timeout. It has no `Authorization`, request signature or client-certificate
  behavior.
- `app/app.go` (`NewApp`) creates one `http.Client` around the default transport.
  `app/startup.go` passes that same client to the webhook sender; `app/inittwilio.go`,
  `app/initslack.go` and `app/initstores.go` also use it. All Webhook Contact
  Methods use the single registered webhook sender. Authentication material
  therefore must not be installed by mutating this shared client or sent to
  every generic webhook target.
- `config/config.go` currently gives `Webhook` only `Enable` and `AllowedURLs`.
  `config/store.go` encrypts the dynamic configuration with the existing Core
  configuration keyring, while `app/cmd.go` supports process configuration from
  `GOALERT_` environment variables. No dedicated Core-to-Gateway production
  authentication secret source currently exists.
- `engine/message/db.go` (`DB.sendMessage`) gives a send operation five seconds,
  while the webhook sender applies its existing three-second child timeout.
  Temporary attempts and persisted retries preserve the same
  `outgoing_messages.id`; `notification/webhook/sender.go` sends it as
  `Idempotency-Key`.
- Comparing the fork to pristine GoAlert v0.34.1 commit
  `0918387e38650aaddd6a923d445ee992f64d6ab6` shows fork changes only for stable
  delivery identity, machine-readable `AlertState`, transport correctness and
  destination redaction in the relevant paths. The Webhook Contact Method
  model, shared client construction and absence of Core authentication are
  unchanged from pristine v0.34.1.

## Security capabilities are distinct

These controls are complementary and must not be substituted for one another:

| Control | Purpose |
| --- | --- |
| Authentication replay protection | Reject a captured HTTP attempt that is resent with the same authentication nonce |
| Durable idempotency | Make a legitimate Core retry of one logical `outgoing_messages` row return the existing receipt instead of creating a second acceptance |
| Payload conflict detection | Reject reuse of one durable identity for different canonical event content |
| Destination routing secrecy | Make the path token unguessable and keep the actual provider destination out of the URL |
| Payload-at-rest protection | Protect canonical event bytes and their literal digest in the Gateway database |

Authentication replay protection uses a fresh attempt nonce. Durable
idempotency intentionally reuses `Idempotency-Key`. These requirements do not
conflict.

## Threat model

| Threat | Required response |
| --- | --- |
| Unauthenticated caller reaches Gateway | Fail before destination lookup, JSON decoding or intake |
| Opaque token is guessed, leaked or captured from an access log | Token remains only a routing capability; a valid Core signature is still required; logs suppress the full path |
| Authentication credential leaks | Credential can be disabled or revoked independently; short overlap and expiry bound exposure |
| Token-verifier database leaks | No raw token is present; a separate keyed verifier prevents verification without its external key |
| Captured HTTP request is replayed | Timestamp window plus an atomic shared nonce reservation rejects the repeated attempt |
| Core legitimately retries one delivery | A fresh authentication nonce is signed while the same `Idempotency-Key` is retained; durable idempotency returns the stable receipt |
| Credential or token rotates during traffic | Old and new records overlap only within explicit limits; shared database state gives all Gateway instances one decision |
| Principal is disabled | A valid credential cannot authorize intake; return generic `403` |
| Destination is disabled | Resolve only after authentication; return generic `404` without an existence oracle |
| Gateway instances observe stale revocation state | Do not use instance-local authorization or token-status caches; query the logical read-write database for each request |
| TLS terminator or reverse proxy is misconfigured | HMAC remains end-to-end; never trust a caller-controlled principal header; fail closed if exact bytes are transformed |
| Principal header is forged | Ignore it; derive principal only from the verified credential registry record |
| Body, URL, header or token reaches a log | Log only route templates, bounded result codes and non-sensitive counts; redact request targets and security material at every hop |
| Core or Gateway clock is skewed | Permit only the defined signed-timestamp window and monitor clock synchronization; outside the window is authentication failure |
| Gateway database leaks | Authentication secrets, raw destination tokens and token-verifier keys are absent; protected event data remains AES-GCM ciphertext |
| One key is reused for another purpose | Reject deployment: authentication, replay hashing, token verification and payload protection use disjoint key domains |

## Core authentication option matrix

| Option | Current-Core change and processing | Principal, rotation and replay | Operations, HA/DR and decision |
| --- | --- | --- | --- |
| Gateway directly verifies a Core client certificate | Requires a Gateway-only TLS client configuration. The current client is shared by webhook, Slack, Twilio and UIK, and all webhook targets share one sender, so mutating it is prohibited. | Principal could map from a certificate fingerprint; rotation can overlap certificates. TLS prevents passive capture but does not provide application nonce replay detection. | Strong transport identity but complicated target scoping, certificate provisioning and TLS-handshake failures that often cannot return contract HTTP errors. Not selected for V1. |
| Trusted reverse proxy terminates mTLS and passes verified identity | Small Core change if certificates already exist, but Gateway must trust one proxy-only identity channel and reject direct access. | Principal depends on proxy configuration. A forged forwarded header is fatal unless the proxy strips it and the Gateway port is unreachable. | Adds proxy fencing, HA and cross-DC synchronization requirements. It may be defense in depth, but is not the V1 identity source. |
| Narrow bearer credential over verified TLS | Core adds one header and Gateway performs a lookup. | Principal maps from the token. Rotation is simple, but every captured request remains replayable until expiry or revocation. | Lowest code cost but highest credential/header log impact and no request integrity beyond TLS. Not selected. |
| HMAC-signed request over verified TLS | Core signs the exact already-serialized bytes and adds three authentication headers. Gateway must boundedly buffer the body before authentication. | Credential ID maps to principal. A timestamp and random nonce provide attempt replay protection; legitimate retries sign again with the same delivery identity. | End-to-end across a proxy, intake-only scope, deterministic testing and no client-certificate mutation. Requires clock discipline, a shared nonce store and production secret sources. **Selected for Authentication V1.** |
| HMAC plus mTLS | Includes the HMAC behavior and an independent certificate boundary. | Strong layered control with two independent rotations. | Higher deployment and incident complexity. May be added later as defense in depth, but is not required or accepted as a V1 fallback. |

Authentication V1 has one mechanism: HMAC-SHA-256 request signing over verified
TLS. There is no bearer, mTLS-identity or proxy-header fallback. A deployment
may additionally require mTLS, but HMAC verification and principal derivation
remain mandatory and authoritative.

## Authentication V1

### Credentials and TLS

- Every credential consists of a non-secret canonical lower-case UUIDv4
  `credential_id` and exactly 32 CSPRNG bytes of HMAC secret material.
- Core obtains the pair from a dedicated external process secret source. It is
  not stored in a contact-method URL or destination argument and is not the
  Core data-encryption key.
- Gateway stores credential metadata and its mapping to one immutable internal
  `CorePrincipalID`. HMAC secret material is obtained by credential ID from a
  dedicated external production secret source, never from the request or the
  destination-token table.
- Selecting and implementing the concrete Core and Gateway production secret
  providers is a prerequisite to runtime implementation. This decision fixes
  the interfaces and security semantics, not a vendor such as Vault, KMS or an
  environment-file format.
- TLS 1.2 or newer with verified server certificate chain and hostname is
  mandatory; TLS 1.3 is preferred. `InsecureSkipVerify`, plaintext HTTP and a
  certificate-verification downgrade are prohibited.
- If a reverse proxy terminates TLS, Core verifies that proxy endpoint and the
  proxy-to-Gateway hop must be authenticated and integrity protected. The proxy
  must preserve the exact method, canonical path, signed headers and body bytes.
  It is not trusted to assert `CorePrincipalID`.

### Exact request authentication

Core sends exactly one of each header:

```text
Authorization: MSOnCall-HMAC-SHA256 Credential=<credential_id>, Signature=<signature>
X-MS-OnCall-Timestamp: <unix-seconds>
X-MS-OnCall-Nonce: <nonce>
```

- `credential_id` is the canonical UUID described above.
- `unix-seconds` is canonical unsigned base-10 Unix time with no leading zero.
- `nonce` is unpadded base64url encoding of 16 fresh CSPRNG bytes, exactly 22
  characters. It is generated once for each HTTP attempt and is never reused.
- `signature` is unpadded base64url encoding of the 32-byte HMAC-SHA-256 result,
  exactly 43 characters.

The HMAC input is UTF-8/ASCII bytes with a single LF between fields and no
trailing LF:

```text
MS_ONCALL_GATEWAY_REQUEST_V1
POST
/v1/goalert/contact-method/mso1_<token-body>
<credential_id>
<canonical Idempotency-Key UUID>
<unix-seconds>
<nonce>
<lower-case hex SHA-256 of the exact raw request body bytes>
```

The canonical path contains only the literal ASCII prefix and canonical token;
percent-encoded or otherwise equivalent spellings are invalid. The query string
is empty. Gateway reconstructs these bytes from its validated transport values,
looks up the active credential by ID, computes HMAC-SHA-256 and compares the
32-byte MAC with `crypto/subtle.ConstantTimeCompare` semantics. It never signs
decoded JSON or re-encoded body content.

### Principal and authorization

- Successful signature verification identifies a credential registry record.
  That record, not the credential ID itself, supplies the immutable
  `CorePrincipalID`.
- Multiple Core nodes may have distinct credential IDs and secrets mapped to
  the same logical `CorePrincipalID`. This preserves durable identity if another
  Core node retries the same persisted outgoing message.
- A principal record must be enabled and carry only the explicit
  `gateway.intake.v1` authorization. A caller-provided principal header, URL
  field or JSON value is ignored and must never reach `intake.Request`.
- Missing or malformed authentication headers, unknown/disabled/expired/revoked
  credentials, invalid signatures, timestamps outside the permitted window,
  malformed nonces and repeated nonces produce the same generic `401` response.
- A cryptographically valid active credential for a known principal that is
  disabled or lacks `gateway.intake.v1` produces generic `403`.
- An unavailable credential secret source or replay store is a server-side
  fail-closed `503`; it is not misreported as invalid caller authentication.

### Replay and rotation

- Gateway accepts a signed timestamp only when it is within 60 seconds of its
  current time, inclusive.
- After the signature is valid, Gateway atomically reserves the pair
  `(credential_id, nonce)` in the shared logical read-write PostgreSQL database.
  A uniqueness conflict is authentication replay and returns generic `401`.
  Reservations are retained for five minutes, longer than the accepted clock
  window. An unavailable or ambiguous reservation returns `503`.
- The nonce store is shared by all Gateway instances and is not an in-memory
  cache. Clock synchronization and skew alerts are production prerequisites.
- A normal Core retry keeps the same `Idempotency-Key` but generates a fresh
  timestamp, nonce and signature. Authentication replay protection therefore
  does not replace or break durable idempotency.
- Each Core node credential slot may have one active and one retiring
  credential. Rotation overlap is at most 24 hours. The new secret is staged on
  every required Gateway instance before its metadata record is enabled; Core
  then switches to it, and the old credential is revoked or expires by the end
  of the overlap.
- Every credential has `not_before` and `expires_at`; a credential lifetime may
  not exceed 90 days. Revocation and principal disablement take effect from the
  shared database on the next request.
- Credential IDs, principal IDs, signatures, nonces and authentication errors
  are absent from application/access logs and metric labels. Audit records use
  a server-generated request ID and fixed action/result codes only.

### Minimum future code seams

Core needs a Gateway-target-scoped signer injected into the webhook sender. It
must match an exact configured HTTPS Gateway origin and canonical intake path,
sign the already serialized body, add the three headers, and fail before
`Client.Do` if configuration, randomness or signing fails. It must not mutate
the shared `http.Client`, change JSON, change `Idempotency-Key`, change the
three-second timeout or send the credential to non-Gateway webhook targets.

Gateway needs narrow HTTP-adapter dependencies for credential lookup/signature
verification, principal authorization, replay reservation and destination
resolution. Only their verified `CorePrincipalID` and resolved `DestinationID`
enter `intake.Request`. Domain, protection, durable and PostgreSQL repository
interfaces remain free of HTTP headers and raw tokens.

## Opaque destination-token option matrix

| Storage model | Database-leak behavior and rotation | Decision |
| --- | --- | --- |
| Raw token in plaintext | Database disclosure immediately grants routing capability; backups contain live tokens. | Rejected. |
| Plain cryptographic hash | A 256-bit token resists guessing, but there is no independent verifier-key boundary or controlled verifier-key retirement. | Rejected for V1 defense in depth. |
| Keyed HMAC verifier | Database stores only a keyed, domain-separated verifier and key ID. Raw token is not recoverable; verifier-key rotation is explicit. | **Selected for Opaque Destination Token V1.** |
| Reversible encrypted token | Gateway can recover raw tokens even though lookup never requires it; compromise of the encryption key reveals every token. | Rejected. |
| Self-contained signed token | Claims become URL-visible and revocation/disablement requires extra state or broad key rotation; it does not simplify destination lifecycle. | Rejected. |

## Opaque Destination Token V1

### Format and verifier

- The token is destination lookup material only. It does not authenticate Core,
  identify an HTTP attempt or encode a telephone number, email address,
  provider, tenant or destination ID.
- Creation reads exactly 32 bytes from a CSPRNG, providing 256 bits of entropy.
- The canonical wire format is lowercase prefix `mso1_` followed by the 43
  characters of unpadded RFC 4648 base64url encoding of those 32 bytes. Padding,
  percent encoding, alternate alphabets, non-canonical length and unknown
  prefixes are invalid.
- The complete token is shown exactly once at creation for secure installation
  in the Core Webhook Contact Method URL. Gateway never persists or returns the
  raw token after creation.
- The verifier is HMAC-SHA-256 under a dedicated 32-byte-or-longer CSPRNG
  token-verifier key over these bytes:

  ```text
  ASCII "MS_ONCALL_GATEWAY_DESTINATION_TOKEN_V1"
  0x00
  32 raw token bytes
  ```

- The row stores the 32-byte verifier and its non-secret verifier-key ID.
  Lookup computes candidate verifiers for the bounded active/historical
  verifier keyring, performs indexed lookup by key ID and verifier, then
  confirms equality in constant time before returning the stable internal
  `DestinationID`.
- Token-verifier key material and key IDs are in a different type, source and
  namespace from Authentication V1 credentials, authentication replay hashing
  and Payload Protection V1 AES keys. One value may never serve two purposes.

### Lifecycle

- A destination has one immutable Gateway-generated UUID `DestinationID` and an
  independent enabled/disabled state. Tokens never change that ID.
- A token record is `active`, `retiring`, `revoked` or expired. Only active and
  unexpired retiring records resolve, and only when the destination is enabled.
- Every token has a mandatory expiry no more than 90 days after creation. A
  destination may have at most two usable tokens: one active and one retiring.
- Rotation creates and displays a new token once, marks the prior token
  retiring, and caps overlap at 24 hours. A third usable token is rejected.
  Revocation is immediate and does not wait for overlap expiry.
- New tokens use the active verifier key. Historical verifier keys remain
  available only until every associated token is expired or revoked. Because
  Gateway does not retain raw tokens, verifier-key rotation requires token
  reissue; it cannot silently re-HMAC an existing token.
- The usable verifier keyring is bounded to one active and one retiring key.
  Another verifier-key rotation cannot begin until every token under the older
  retiring key is expired or revoked and that key has been removed.
- Unknown, disabled, revoked and expired tokens have one external behavior:
  after successful Core authentication and authorization, return generic
  `404` with no token-existence distinction. They never call `intake.Accept`.
- Token status and destination status are read from the shared logical
  read-write database on every resolution. Instance-local caches must not delay
  rotation, revocation or disablement.

### Secrecy, backup and downstream boundaries

- Raw tokens, full request paths and complete request targets are absent from
  application, access, audit and proxy logs. Metric labels contain neither raw
  nor hashed tokens. A safe audit event contains only a request ID and fixed
  result code.
- A token-verifier database disclosure does not disclose raw tokens and does
  not permit verification without the external verifier key. Compromise of the
  verifier key and database together requires rotation of that key and reissue
  of every affected token.
- Backups contain token state and keyed verifiers, not raw tokens. HA/DR restore
  must restore matching external verifier-key versions before serving traffic;
  a missing key fails closed. If raw tokens are lost at Core, Gateway cannot
  recover them and new tokens must be issued.
- Raw tokens remain in the HTTP adapter and resolver only. They never enter
  `intake.Request`, durable acceptance, protected event data, provider jobs or
  delivery identity. Gateway resolves a configured internal destination; it
  never infers a phone number or email address from token bytes.

## Exact future HTTP processing order

Authentication V1 signs the body, so bounded raw-body acquisition necessarily
precedes signature verification. The exact order is:

1. Complete verified TLS. Reject TLS below 1.2, an invalid server/peer boundary
   or plaintext before application processing. A TLS-handshake failure may have
   no HTTP response.
2. Validate the route template, exact `POST` method, empty query, canonical
   unescaped token syntax, media type, identity content encoding, required
   single-value header cardinality and canonical `Idempotency-Key`. Enforce
   header and server timeouts. Do not resolve the token.
3. Reject a declared or streamed body over 262,144 bytes. Read at most 262,145
   raw bytes into a request-scoped buffer. Before authentication, do not decode
   JSON, resolve a destination, call intake or log body/header/path values.
4. Parse the three authentication headers, validate their canonical syntax,
   check credential metadata and secret availability, reconstruct the exact
   signing input, verify HMAC in constant time, validate the timestamp and
   atomically reserve the nonce. Deterministically invalid authentication is
   `401`; unavailable or ambiguous server-side dependencies are `503`.
5. Derive `CorePrincipalID` from the verified credential record and require the
   enabled principal's `gateway.intake.v1` authorization. Failure is `403`.
6. Resolve the raw token to one enabled, unexpired internal `DestinationID` by
   keyed verifier. Unknown, disabled, revoked or expired is generic `404`.
7. Decode and strictly validate the already buffered JSON into a typed event.
   Structural or supported-event field failure is `400`; an unsupported string
   event type remains `422`.
8. Drop references to authentication headers, the raw body and raw token as
   soon as their adapter work is complete. Go does not guarantee physical
   memory zeroization, so no such guarantee is claimed.
9. Call `intake.Service.Accept` with only the verified `CorePrincipalID`,
   resolved `DestinationID`, unchanged delivery identity and typed event.
10. Map `AcceptedNew` to `202` with `duplicate:false`, `AcceptedDuplicate` to
    `202` with `duplicate:true`, and `IdentityConflict` to `409`. Durable
    unavailable, cancellation with no confirmed acceptance, or outcome unknown
    is `503`; an unexpected safe internal failure is `500`.

No path returns `202` until a new durable commit is confirmed or an equivalent
existing durable record is proven. Authentication success, nonce reservation,
token resolution, canonicalization, encryption or starting a transaction is
not durable acceptance.

## Multi-instance, HA/DR and key separation

- Credential metadata, principal authorization, replay reservations,
  destination state and token state use the same logical read-write PostgreSQL
  primary selection already required by the Gateway foundation. No stale
  standby or per-instance in-memory state may authorize a request.
- Authentication and token-resolution database failure returns `503` before
  intake. Primary failover starts a new top-level request; no authentication,
  nonce reservation or acceptance transaction is replayed internally.
- Every Gateway instance must have the same active/historical authentication
  and token-verifier key versions before shared metadata enables them. Missing
  key material fails closed. Database backup/restore and external secret-source
  recovery are one coordinated runbook.
- Authentication HMAC secrets, authentication replay-hash keys, destination
  token-verifier keys and Payload Protection AES keys use distinct random
  material, access policies, rotation schedules, key IDs and audit scopes.

## Logging and observability

Application, access, reverse-proxy, audit and trace outputs must not contain:

- full paths or request targets;
- raw or hashed opaque tokens;
- `Authorization`, credential ID, signature, nonce or principal ID;
- `Idempotency-Key` or delivery identity;
- request bodies, body digests, event fields or verification codes;
- internal destination IDs, verifier values or any security-key ID/material.

Safe fields are route templates, HTTP status, fixed bounded reason code, body
byte count, duration, validated event type after authentication and a random
Gateway request ID. None of the sensitive or unbounded values above may become
a metric label.

## Schema and implementation implications

The published `000001_initial_schema.sql` remains immutable. A future forward
migration is required before runtime wiring to hold, at minimum, principal and
intake authorization state, credential metadata, replay reservations,
destinations, token lifecycle state, keyed verifiers and verifier-key IDs.
Authentication and verifier secret material remains outside those tables.

Recommended implementation order after separate owner authorization is:

1. add the forward security-state migration plus domain-only credential,
   principal, replay and destination resolver interfaces and tests;
2. implement the Core Gateway-target matcher and HMAC signer with exact-byte,
   clock, nonce, rotation and redaction tests;
3. implement Gateway Authentication V1, shared replay reservation and Opaque
   Destination Token V1 resolution without runtime wiring;
4. compose the verified adapter with the existing acceptance pipeline and add
   full HTTP/concurrency/failure tests;
5. wire production key sources and runtime only after the owner accepts all
   prior checkpoints. Preserve `UnavailableSink/503` until then.

## Required tests for future implementation

- hard-coded HMAC signing vectors for the complete canonical request;
- header cardinality and syntax, exact raw-body binding and constant-time MAC
  comparison;
- timestamp boundaries, clock skew, fresh nonces, replay uniqueness across two
  Gateway instances and ordinary retry with stable `Idempotency-Key`;
- credential unknown/disabled/expired/revoked, principal disabled and
  intake-scope denial with exact `401`/`403` behavior;
- secret-source and replay-store outage/ambiguity producing fail-closed `503`;
- target-scoped Core signing proving non-Gateway webhooks receive no credential;
- token format/entropy, one-time return, keyed verifier golden vectors,
  constant-time confirmation and raw-token absence from persistence;
- token creation, two-token maximum, 24-hour overlap, expiry, immediate
  revocation, destination disablement and generic `404` without an oracle;
- verifier-key rotation and historical lookup, missing-key fail closed,
  database backup/restore mismatch and multi-instance state consistency;
- processing-order tests proving no JSON decode, resolution, intake or sensitive
  logging before authentication;
- `AcceptedNew`, `AcceptedDuplicate`, `IdentityConflict`, durable unavailable
  and outcome-unknown mappings, while never returning unverified `202`;
- test/race/vet/build plus opt-in PostgreSQL concurrency tests. A single-instance
  test must not be described as HA/DR failover validation.

## Rejected shortcuts

- treating possession of the opaque token or `Idempotency-Key` as Core
  authentication;
- trusting a caller-controlled principal header;
- attaching a client certificate or bearer credential to the existing shared
  Core HTTP client or every generic webhook;
- signing decoded/re-encoded JSON instead of exact bytes;
- using in-memory nonce or revocation state in a multi-instance deployment;
- storing raw destination tokens or using reversible token storage;
- using a token, body hash, alert ID, timestamp or nonce as delivery identity;
- reusing authentication, replay, token-verifier or payload-protection keys;
- returning `202` before durable acceptance is confirmed.

## Remaining owner decisions

Merging this decision approves the protocol choices above, but does not select
or authorize implementation of:

1. the concrete production secret-source provider and operational custody for
   Core HMAC secrets, Gateway HMAC secrets, replay hashing, token-verifier keys
   and Payload Protection keys;
2. the administrative API/CLI and operator authorization used to create,
   rotate, revoke and audit principals, credentials, destinations and tokens;
3. the deployment TLS termination topology and whether mTLS is additionally
   required as defense in depth;
4. support schemas and fixtures for `AlertBundle` or
   `ScheduleOnCallUsers`, which remain outside the MVP contract;
5. authorization to create the forward security-state migration, change Core,
   implement the Gateway adapter or replace `UnavailableSink`.

Until each implementation checkpoint is separately approved, runtime remains
unchanged and otherwise-valid requests continue to receive `503 Service
Unavailable`.
