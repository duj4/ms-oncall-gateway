# Core to Gateway Security Boundary V1

Status: Approved as Security Boundary V1 by the project-owner merge of Gateway
PR #7, merge commit `9be58c84c705fe2d47a0d03437b6bd5634016c4e`.

The additive migration and domain-only seams in
[Security State Foundation V1](security-state-foundation-v1.md) were accepted
in Gateway PR #8, merge commit
`ea4673537b75074ce8a2d4de8aec56d4a4fccc42`. The strict Core target matcher and
HMAC signer foundation was accepted in Core PR #2, merge commit
`d73e7a357f9d75a8b9c0aa7851107e860faed9d7`, but production runtime injects no
real audience, credential or secret. The transport-independent Gateway
Authentication V1 foundation was accepted in Gateway PR #9, merge commit
`4e74094fd89273b7132bad49f734ad222feb1a8a`. PostgreSQL audience, credential,
principal and replay repositories are a separate in-review checkpoint.
Resolution, token rotation, HTTP composition, production secret sources and
runtime wiring remain unimplemented and require separate owner authorization.

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

This decision covers the future Core-to-Gateway authentication and opaque
destination-token boundary. Its approved schema/domain checkpoint does not
implement authentication, resolution, runtime wiring, an HTTP status change, a
key source, a worker, a provider or a callback.

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
  from `webhook_url`, serializes the body, creates an HTTP `POST`, sets
  `Content-Type` and `Idempotency-Key`, and applies a three-second request
  timeout. The separately accepted optional signer can add the exact three
  Authentication V1 headers only for a strict Gateway target. Production
  startup does not inject that signer or any real credential.
- `app/app.go` (`NewApp`) creates one `http.Client` around the default transport.
  `app/startup.go` passes that same client to the webhook sender through
  `NewSender`, not `NewSenderWithGatewaySigner`; `app/inittwilio.go`,
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
- `user/contactmethod/store.go` (`Store.Update`) explicitly rejects any normal
  update that changes `DestV1`; the generated update query changes only name,
  disabled and status fields. Token rotation therefore cannot use the existing
  Contact Method update path or pretend destination mutation is already
  supported.
- `engine/statusmgr/queries.sql` (`StatusMgrSendUserMsg`) and
  `engine/verifymanager/db.go` (`DB.insertMessages`) enqueue a
  `contact_method_id`, not a destination snapshot. `MessageMgrGetPending` in
  `engine/message/queries.sql` and its generated `gadb/queries.sql.go` method
  join that ID to the current
  `user_contact_methods.dest`, and `engine/message.DB.currentQueue` loads that
  current destination when a persisted message is selected.
- `engine/message.DB.sendMessage` and `Message.Base` then copy the loaded
  destination into one in-memory send cycle. Its immediate temporary retries
  reuse that snapshot. A later durable retry is reset to pending and passes
  through `currentQueue` again, so it reads the then-current Contact Method
  destination. This split proves that token rotation needs a bounded old-token
  overlap even after Core atomically changes the stored destination.
- Comparing the fork to pristine GoAlert v0.34.1 commit
  `0918387e38650aaddd6a923d445ee992f64d6ab6` shows fork changes only for stable
  delivery identity, machine-readable `AlertState`, transport correctness and
  destination redaction plus the optional strict Gateway matcher/HMAC signer
  foundation in the relevant paths. The Webhook Contact Method model and shared
  client construction remain unchanged, and production runtime still supplies
  no real Authentication credential.

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
| Credential or token metadata is copied to another deployment realm | Bind request signatures and destination-token verifiers to the configured `GatewayAudienceID`; a different realm fails authentication or resolution |
| Token rotation partially fails while sends continue | Permit only the two-token bounded state machine and the privileged Core compare-and-swap operation; fail closed on ambiguous state and never create a third usable token |
| One key is reused for another purpose | Reject deployment: authentication, token verification and payload protection use exactly three disjoint key domains |

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

- Each logical Gateway realm has one deployment-configured `GatewayAudienceID`.
  It is a canonical lowercase hyphenated non-zero UUID. Development, QA, UAT
  and production use different values; HA and DR instances for the same logical
  realm use the same value.
- `GatewayAudienceID` is local configuration on both signer and verifier. It is
  never taken from an HTTP header, `Host`, `Forwarded`, the URL path or JSON.
  Credential metadata and the destination-token registry are both bound to the
  audience. Copying either record to another realm does not make it usable.
- Every credential consists of a non-secret canonical lower-case UUIDv4
  `credential_id` and exactly 32 CSPRNG bytes of HMAC secret material.
- Core obtains the pair from a dedicated external process secret source. It is
  not stored in a contact-method URL or destination argument and is not the
  Core data-encryption key.
- Gateway stores credential metadata and its mapping to one immutable internal
  `CorePrincipalID` and exactly one `GatewayAudienceID`. HMAC secret material is
  obtained by credential ID from a dedicated external production secret source,
  never from the request or the destination-token table. A credential whose
  recorded audience differs from the verifier's local audience is unusable.
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
<canonical GatewayAudienceID UUID>
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
is empty. Core signs its configured audience and Gateway reconstructs the input
with its own configured audience. Gateway requires that local audience to match
the credential record, looks up the active credential by ID, computes
HMAC-SHA-256 and compares the 32-byte MAC with
`crypto/subtle.ConstantTimeCompare` semantics. It never signs decoded JSON or
re-encoded body content. A missing, zero, non-canonical or wrong audience fails
closed without accepting a caller-supplied replacement.

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
  `(credential_record_id, nonce_bytes)` in the shared logical read-write
  PostgreSQL database. `nonce_bytes` is the strict decoded 16-byte nonce, not
  its encoded spelling. A uniqueness conflict is authentication replay and
  returns generic `401`. Reservations are retained for five minutes, longer
  than the accepted clock window. An unavailable or ambiguous reservation
  returns `503`.
- The replay reservation has no independent cryptographic key, digest or key
  rotation. Credential rotation does not rewrite, delete or change existing
  nonce reservations; the internal credential record ID remains their stable
  namespace until the five-minute retention period ends.
- A nonce is public uniqueness input, not an authentication secret. It is still
  sensitive correlation material and never enters a log, metric label, trace,
  audit message or returned error.
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

Core now has an accepted optional Gateway-target-scoped signer seam in
`NewSenderWithGatewaySigner`. It matches an exact configured HTTPS Gateway
origin and canonical intake path, signs its configured `GatewayAudienceID` with
the already serialized body, adds the three headers, and fails before
`Client.Do` if configuration, randomness or signing fails. It does not mutate
the shared `http.Client`, change JSON, change `Idempotency-Key`, change the
three-second timeout or send the credential to non-Gateway webhook targets.
Production startup intentionally continues to use `NewSender` without a real
audience, credential or secret source.

Core also needs the separate privileged Gateway-specific Contact Method
token-rotation operation defined below. The normal `Store.Update` path remains
destination-immutable. The operation is a narrow compare-and-swap of only the
canonical token segment for an already identified Gateway `builtin-webhook`; it
preserves the Contact Method UUID and every relationship keyed by that UUID.

Gateway needs narrow HTTP-adapter dependencies for local audience validation,
credential lookup/signature verification, principal authorization, replay
reservation and destination resolution. Only their verified `CorePrincipalID`
and resolved `DestinationID` enter `intake.Request`. Domain, protection, durable
and PostgreSQL repository interfaces remain free of HTTP headers and raw tokens.

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
  canonical GatewayAudienceID ASCII bytes
  0x00
  32 raw token bytes
  ```

- The row stores the 32-byte verifier and its non-secret verifier-key ID.
  Its metadata is bound to the same canonical `GatewayAudienceID` used to
  calculate the verifier. A resolver uses only its local configured audience;
  it never accepts an audience from the request.
  Lookup computes candidate verifiers for the bounded active/historical
  verifier keyring, performs indexed lookup by key ID and verifier, then
  confirms equality in constant time before returning the stable internal
  `DestinationID`.
- Token-verifier key material and key IDs are in a different type, source and
  namespace from Authentication V1 credentials and Payload Protection V1 AES
  keys. These are the only three cryptographic key domains in this decision;
  one value may never serve two purposes.

### Lifecycle

- A destination has one immutable Gateway-generated UUID `DestinationID` and an
  independent enabled/disabled state. Tokens never change that ID.
- A token record is `staged`, `active`, `retiring`, `revoked` or expired. A
  staged token has a persisted verifier but never resolves. Only active and
  unexpired retiring records resolve, and only when the destination is enabled.
- Every token has a mandatory expiry no more than 90 days after creation. A
  destination may have at most one staged token and two usable tokens: one
  active and one retiring.
- Rotation creates and displays a new token once, marks the prior token
  retiring, and caps overlap at 24 hours. A third usable token is rejected.
  Revocation is immediate and does not wait for overlap expiry.
- A staged token gets an immutable cleanup deadline no later than 24 hours from
  creation. Abort before activation revokes it; reaching the deadline expires
  it. Creating another staged token is prohibited until the prior staged record
  is confirmed revoked or expired. Losing its one-time raw value never makes it
  resolvable and is recovered only by revoking or expiring that record.
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

### Privileged Core token-rotation operation

Normal `contactmethod.Store.Update` remains destination-immutable. Future token
rotation requires one separate admin/system-only Core operation scoped solely to
an identified `builtin-webhook` Contact Method already targeting Gateway. The
operation preserves the Contact Method UUID, owner, notification rules,
escalation references, disabled state and status-update setting. It may replace
only the canonical `mso1_` token segment after both old and new destinations pass
the strict Gateway-target matcher: exact HTTPS scheme, host, effective port and
canonical `/v1/goalert/contact-method/{opaque_token}` route template, with empty
userinfo, query and fragment. Every non-token URL component must be present in
the same canonical form in both values; only the token segment may differ. It
cannot add URL credentials, change origin, route, delivery identity or any other
destination field. Tokens and complete URLs are never logged or returned in
errors. The operation does not change `outgoing_messages.id` or any delivery
identity. Gateway still never reads Core database tables.

The future rotation coordinator must implement exactly this bounded sequence:

1. Gateway creates one new `staged` token under the same destination, persists
   its verifier and immutable cleanup deadline, and returns the raw token once
   to the authorized coordinator. It does not resolve. No prior staged token or
   retiring token may exist, and no third usable token may already exist.
2. In one Gateway transaction, require that exact unexpired staged record and
   one old active record, promote the new token to `active`, mark the old token
   `retiring` and consume the staged state.
3. As part of that same transaction, give the old token one overlap deadline no
   later than 24 hours from the transaction's confirmed activation time. The
   deadline is immutable and cannot be extended by retry or rollback. The staged
   cleanup deadline does not reduce this post-activation drain interval. If the
   transaction is confirmed not committed, the old token remains active and the
   new token remains non-resolving until confirmed revocation or its staged
   cleanup deadline.
4. The coordinator validates both complete URLs in memory with the strict
   matcher and retains the exact old value only in its bounded rotation context;
   neither value enters logs, errors or audit fields. The privileged Core
   operation then atomically compare-and-swaps the identified
   Contact Method destination from the exact old canonical value to the exact
   new canonical value. A mismatch or ambiguous commit fails closed; normal
   `Store.Update` is not used.
5. Core sends a newly signed verification request through that same Contact
   Method. The request uses the unchanged persisted delivery-ID rules and the
   new token; Gateway verifies the configured audience, signature and token.
6. Until that verification succeeds, retain both old and new token records. An
   already-loaded send cycle and its immediate retries may still use the old
   snapshot; queued or later durable retries reload the current Core destination
   and use the new token. After verification, allow the old token only for drain
   of attempts already holding the old snapshot and revoke it as soon as drain
   is confirmed.
7. At the fixed overlap deadline Gateway expires the old token unconditionally.
   Failure to prove drain cannot extend overlap or create another usable token.
8. Rollback is exact and bounded. An abort before step 2 atomically revokes the
   staged token and leaves the old token active. Before the overlap deadline, if
   step 4 fails before the Core write is sent or Core proves no write occurred,
   Gateway atomically revokes the new token and restores the old token to
   `active`. If Core confirms the new value but step 5 fails, the coordinator
   uses the same privileged compare-and-swap operation to restore the exact old
   value, verifies the old signed path, then atomically revokes the new token and
   restores the old token to `active`.
9. Every create, activation and rollback transition enforces at most one staged
   token and never more than one active plus one retiring token. A third usable
   token is rejected rather than used for recovery.
10. If the Gateway activation transaction, Core destination mutation or
    rollback outcome is ambiguous, do not replay the mutation, revoke either
    potentially referenced token, extend a deadline or create a third token.
    Block further rotation, keep at most the existing old/new pair only until
    the original deadline, return a fixed fail-closed result and require
    privileged reconciliation. Reconciliation first inspects the authoritative
    Gateway token states and deadlines, then reads the current Contact Method by
    UUID; it accepts only the exact old or new canonical value and resumes the
    matching branch above. Any other value is a hard failure. This is bounded
    safety, not a claim of automatic recovery.

The future Core test surface must cover queued messages, a send already loaded
before rotation, immediate retry, later durable retry, concurrent send and
rotation, staged tokens never resolving, interruption before activation,
staged-token cleanup, atomic activation/retirement, old/new token overlap, Core
update failure, verification failure, successful rollback, ambiguous rollback,
expiry, revocation, and every partial failure boundary above, including
immediate revoke before the deadline. No test may infer safety merely from
updating a newly created Contact Method.

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
  a missing key fails closed. The restored realm must retain its original
  `GatewayAudienceID`; restoring the records into a differently identified realm
  does not make credentials or tokens usable. If raw tokens are lost at Core,
  Gateway cannot recover them and new tokens must be issued.
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
   validate the local configured `GatewayAudienceID`, require the credential
   record's audience to match it, check secret availability, reconstruct the
   exact signing input with that local audience, verify HMAC in constant time,
   validate the timestamp and atomically reserve the strict decoded 16-byte
   nonce by credential record ID. Deterministically invalid authentication is
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
- All instances in one logical HA/DR realm use the same canonical
  `GatewayAudienceID`. Development, QA, UAT, production and any restored clone
  intended as a separate realm must use different IDs. Credential and token
  metadata cannot be reused across those boundaries; backup/restore must not
  silently change or duplicate the realm identity.
- Authentication and token-resolution database failure returns `503` before
  intake. Primary failover starts a new top-level request; no authentication,
  nonce reservation or acceptance transaction is replayed internally.
- Every Gateway instance must have the same active/historical authentication
  and token-verifier key versions before shared metadata enables them. Missing
  key material fails closed. Database backup/restore and external secret-source
  recovery are one coordinated runbook.
- Authentication HMAC secrets, destination token-verifier keys and Payload
  Protection AES keys use distinct random material, access policies, rotation
  schedules, key IDs and audit scopes. Replay reservation uses only database
  uniqueness over credential record ID and decoded nonce bytes and introduces
  no fourth cryptographic key domain.

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

The published `000001_initial_schema.sql` remains immutable. The separately
authorized additive `000002_security_state_v1.sql` checkpoint now supplies the
local realm audience binding, principal and intake authorization state,
credential metadata, five-minute `(credential_record_id, nonce_bytes)` replay
reservations, destinations, token lifecycle state, keyed verifiers and
verifier-key IDs. Authentication and verifier secret material remains outside
those tables. The migration and `internal/securitystate` interfaces implement
no repository, HMAC, resolver, administration or runtime behavior.

Implementation checkpoint status and remaining order are:

1. the Security State Foundation migration and domain seams are accepted in
   Gateway PR #8;
2. the strict Core matcher/HMAC signer foundation is accepted in Core PR #2,
   while privileged token rotation and production credential injection remain
   unimplemented;
3. the transport-independent Gateway Authentication V1 foundation is accepted
   in Gateway PR #9;
4. PostgreSQL audience, credential, principal and shared replay repositories
   are in review, while Opaque Destination Token V1 resolution still requires
   separate owner authorization;
5. HTTP composition, production secret sources and runtime wiring follow only
   after prior checkpoints are accepted. Preserve `UnavailableSink/503` until
   then.

## Required tests for future implementation

- hard-coded HMAC signing vectors for the complete canonical request, including
  the canonical `GatewayAudienceID` field;
- header cardinality and syntax, exact raw-body binding and constant-time MAC
  comparison;
- timestamp boundaries, clock skew, fresh nonces, replay uniqueness across two
  Gateway instances and ordinary retry with stable `Idempotency-Key`;
- credential unknown/disabled/expired/revoked, principal disabled and
  intake-scope denial with exact `401`/`403` behavior;
- secret-source and replay-store outage/ambiguity producing fail-closed `503`;
- strict replay uniqueness by credential record ID and decoded 16-byte nonce,
  including credential rotation with unchanged five-minute reservations and no
  additional cryptographic key;
- target-scoped Core signing proving non-Gateway webhooks receive no credential;
- audience tests for correct, wrong, zero and non-canonical values, cross-realm
  credential/token copies, same-realm HA/DR and restore under a different realm;
- token format/entropy, one-time return, keyed verifier golden vectors,
  constant-time confirmation and raw-token absence from persistence;
- token creation, one non-resolving staged-token maximum, staged abort/expiry,
  atomic staged activation plus old-token retirement, two-usable-token maximum,
  24-hour overlap, expiry, immediate revocation, destination disablement and
  generic `404` without an oracle;
- privileged Core token rotation covering queued and already-loaded messages,
  immediate and durable retry, concurrent sends, exact old/new URL matching,
  userinfo/query/fragment rejection, activation-relative overlap boundaries,
  update and verification failure, confirmed and ambiguous rollback, overlap
  expiry, revocation and every partial failure without a third usable token;
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
- adding an unnecessary cryptographic key to database nonce uniqueness;
- reusing authentication, token-verifier or payload-protection keys;
- returning `202` before durable acceptance is confirmed.

## Remaining owner decisions

Merging this decision approves the protocol choices above, but does not select
or authorize implementation of:

1. the concrete production secret-source provider and operational custody for
   Core HMAC secrets, Gateway HMAC secrets, token-verifier keys and Payload
   Protection keys;
2. the administrative API/CLI and operator authorization used to create,
   rotate, revoke and audit principals, credentials, destinations and tokens;
3. the deployment TLS termination topology and whether mTLS is additionally
   required as defense in depth;
4. support schemas and fixtures for `AlertBundle` or
   `ScheduleOnCallUsers`, which remain outside the MVP contract;
5. authorization to configure and bind a unique audience per logical realm,
   inject real Core signer credentials, add the narrow privileged Core
   token-only rotation operation, implement the Gateway repositories and
   adapter, or replace `UnavailableSink`. The accepted foundations do not
   authorize any of those actions.

Until each implementation checkpoint is separately approved, runtime remains
unchanged and otherwise-valid requests continue to receive `503 Service
Unavailable`.
