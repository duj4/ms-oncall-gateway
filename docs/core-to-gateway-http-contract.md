# Core to Gateway HTTP intake contract

Status: Draft contract for the MS OnCall Gateway MVP.

The proposed [Core to Gateway Security Boundary V1](core-to-gateway-security-boundary-v1.md)
selects one exact Authentication V1 and Opaque Destination Token V1. The
proposal is not approved by Draft PR creation; project-owner merge after formal
review records approval. Neither security mechanism is implemented in the
current runtime.

Upstream baseline: GoAlert v0.34.1 at commit
`0918387e38650aaddd6a923d445ee992f64d6ab6`. This contract also documents
owner-approved additive MS OnCall wire extensions to that baseline.

This document defines the Core-to-Gateway intake boundary. It does not define
provider delivery, provider callbacks, Core alert actions, or the Gateway
persistence schema. The words MUST, MUST NOT, SHOULD, and MAY are normative.

## Confirmed source and PoC basis

The v0.34.1 wire shape is confirmed from:

- `notification/webhook/sender.go`, which constructs the event-specific
  payload structs, marshals them with Go's `encoding/json`, sends `POST`, and
  sets `Content-Type: application/json`;
- `engine/sendmessage.go`, which supplies alert data, the six-digit
  verification code, and the rendered alert-log entry;
- `alert/alert.go` and `alert/metadata.go`, which define the current Core
  limits for alert content and metadata;
- `web/src/app/documentation/sections/Webhooks.md` and
  `test/smoke/webhook_test.go`, which provide documentation and smoke-test
  corroboration.

The completed PoC confirmed end-to-end receipt of `Verification`, `Alert`,
acknowledgement `AlertStatus`, and closure `AlertStatus` notifications.
The fixtures are structurally faithful, sanitized examples; they are not
copies of production requests or logs.

The Go structs have no JSON tags. Field names on the wire are therefore the
case-sensitive exported Go field names shown below.

## Request target and transport

| Property | Contract |
| --- | --- |
| Method | `POST` only |
| Path | `/v1/goalert/contact-method/{opaque_token}` |
| Transport | HTTPS with certificate verification; plaintext HTTP is not a production option |
| Media type | `application/json`; an optional `charset=utf-8` parameter is accepted |
| Content encoding | Absent or `identity`; compressed request bodies are rejected |
| Maximum body | 262,144 raw bytes (256 KiB), enforced while reading as well as against `Content-Length` |
| Query string | Must be empty; destinations and credentials are never query parameters |
| Delivery identity | Exactly one `Idempotency-Key` header containing the canonical UUID from Core's persisted `outgoing_messages.id` |

The 256 KiB limit covers the v0.34.1 alert limits (1,024 Unicode code points
for summary, 6,144 for details, and 32 KiB of metadata key/value bytes) plus
JSON escaping and envelope overhead. A body of exactly 262,144 bytes is
allowed; the next byte makes the request too large.

`opaque_token` selects a pre-provisioned Gateway contact destination. It is a
single path segment and MUST NOT contain an email address, telephone number,
provider credential, or other clear-text destination. It is routing material,
not sufficient request authentication.

The security-boundary proposal gives the token the canonical form `mso1_`
followed by unpadded base64url encoding of 32 CSPRNG bytes and stores only a
separately keyed HMAC-SHA-256 verifier. That format and lifecycle become
normative only if the project owner merges the decision PR after formal review.

Core v0.34.1 has a three-second webhook request timeout. Gateway intake MUST
not wait for provider delivery. This timeout is a compatibility constraint,
not permission to acknowledge an event before durable acceptance.

`Idempotency-Key` identifies one logical Core delivery, not one HTTP attempt.
Core MUST reuse the same value for every attempt and durable retry of one
`outgoing_messages` row. Core MUST fail the send before invoking its HTTP
client when the delivery identity is missing; it MUST NOT generate a fallback
UUID or substitute an alert ID, destination token, payload hash, timestamp, or
attempt-specific value.

## JSON parsing rules

The request body MUST be one UTF-8 JSON object.

- Field names and event type values are case-sensitive.
- Duplicate object member names, unknown top-level fields, a byte-order mark,
  trailing non-whitespace data, and multiple JSON values are invalid.
- Every field listed as required MUST be present. `null` is not a substitute
  for a required string, integer, or object.
- Strings and numbers are not coerced into one another.
- Numeric identifiers MUST be JSON integers, not floating-point or exponent
  forms.
- Validation occurs before a delivery job is inserted.
- The Gateway MUST NOT use `AppName`, `AlertID`, `ServiceID`, `Summary`,
  `Meta`, or `LogEntry` as authentication or delivery identity.
- Delivery identity is carried only in `Idempotency-Key`; it MUST NOT be added
  to the JSON object. The `AlertState` extension does not change that
  header-only delivery-identity rule.

Unknown top-level fields are rejected deliberately. A new Core field requires
an explicit v1 contract update and receiver coverage rather than being silently
discarded.

## Common fields

| Field | Required | Validation |
| --- | --- | --- |
| `AppName` | Yes | String containing 1-32 printable ASCII bytes. It is display data and may differ from `GoAlert`. |
| `Type` | Yes | String exactly equal to one supported event name below. |

## Supported event payloads

### Verification

Required fields: `AppName`, `Type`, and `Code`.

| Field | Validation |
| --- | --- |
| `Type` | Exactly `Verification` |
| `Code` | String matching `^[0-9]{6}$` |

`Code` is sensitive one-time verification data. It MUST be encrypted or
otherwise protected according to the future persistence design and MUST
always be redacted from logs, metrics, traces, and error responses.

### Test

Required fields: `AppName` and `Type`.

`Type` is exactly `Test`. No other top-level field is accepted.

### Alert

All fields in this table are required, including an empty `Details` string or
empty `Meta` object.

| Field | Validation |
| --- | --- |
| `Type` | Exactly `Alert` |
| `AlertID` | Positive JSON integer no greater than 9,223,372,036,854,775,807 |
| `Summary` | String of at most 1,024 Unicode code points |
| `Details` | String of at most 6,144 Unicode code points |
| `ServiceID` | Canonical hyphenated UUID string |
| `ServiceName` | 2-64 printable ASCII characters; begins with a letter; contains only letters, digits, spaces, hyphens, underscores, or apostrophes; does not end in a space |
| `Meta` | JSON object whose keys and values are strings; keys are 1-255 printable ASCII bytes; the sum of UTF-8 byte lengths of all keys and values is at most 32,768 |

An empty `Summary` is accepted for v0.34.1 compatibility even though useful
alerts should have a summary. `Meta` values and alert text are untrusted
display data and MUST NOT be interpreted as credentials, routing directives,
or template code.

### AlertStatus

Required fields: `AppName`, `Type`, `AlertID`, `LogEntry`, and `AlertState`.

| Field | Validation |
| --- | --- |
| `Type` | Exactly `AlertStatus` |
| `AlertID` | Positive JSON integer no greater than 9,223,372,036,854,775,807 |
| `LogEntry` | Non-empty valid Unicode string; the overall request-size limit is the upper bound |
| `AlertState` | Case-sensitive JSON string exactly equal to `Unacknowledged`, `Acknowledged`, or `Closed` |

`AlertState` is an owner-approved additive MS OnCall extension to the pristine
GoAlert v0.34.1 field set. Current MS OnCall Core derives it directly from the
internal `NewAlertState`; the internal integer enum and the name
`NewAlertState` are not serialized. `ServiceID`, `Summary`, and `Details`
remain absent from this payload.

Gateway MUST treat `LogEntry` as opaque display text. It MUST NOT infer an ACK
or Closed state by parsing English words. Acknowledgement and closure business
logic MUST use `AlertState` only. A missing or `null` `AlertState`, a JSON
number, incorrect capitalization, or any unknown string does not satisfy this
contract. `Unacknowledged` preserves the existing escalation status-notification
behavior.

## Unsupported and unknown events

The v1 MVP event allowlist is `Verification`, `Test`, `Alert`, and
`AlertStatus`.

Core v0.34.1 also contains sender branches for `AlertBundle` and
`ScheduleOnCallUsers`. They are known but outside this MVP contract. Those
types, an empty `Type`, and every unknown type receive
`422 Unprocessable Content` with error code `unsupported_event_type`.
They MUST NOT create a delivery job. Support can be added only with an explicit
contract and fixture update.

## Authentication boundary

Core-to-Gateway authentication is independent of the opaque destination token.
The linked Security Boundary V1 proposes exactly one mechanism:
HMAC-SHA-256 signing of the exact request over verified TLS, using a scoped
credential ID, signed timestamp and fresh attempt nonce. It has no bearer,
client-certificate-identity or trusted-principal-header fallback. The HMAC
proposal becomes normative only when the project owner merges the decision PR;
it is not implemented by this contract update.

Regardless of the selected mechanism:

- the authenticated principal MUST identify MS OnCall Core and be authorized
  only for Gateway intake;
- credentials MUST be sent in a header or established by mutually
  authenticated TLS, never in the URL or JSON body;
- TLS peer and server certificates MUST be verified;
- an unknown or disabled destination MUST not be accepted merely because a
  caller knows the path token;
- authentication material, raw path tokens, and complete request targets MUST
  be redacted from application and reverse-proxy logs;
- a production receiver MUST NOT be declared ready until the selected
  authentication mechanism is configured.

Under the proposal, Gateway derives immutable `CorePrincipalID` only from an
active verified credential registry record. It never accepts that value from a
normal request header, URL or JSON body. The signature covers the method,
canonical path, credential ID, `Idempotency-Key`, timestamp, nonce and SHA-256
of the exact raw body bytes. A 60-second timestamp window plus an atomic
five-minute shared nonce reservation provides authentication replay protection;
normal Core retries keep `Idempotency-Key` but use a fresh timestamp, nonce and
signature. Authentication, token-verifier and Payload Protection key domains
remain strictly separate.

## Delivery identity and idempotency

### Owner-approved wire binding

The project owner approved `Idempotency-Key` as the delivery-identity header.
Its value is the existing persisted `outgoing_messages.id`, serialized as the
canonical hyphenated UUID string.

Core propagates the value without replacement through the existing internal
message envelope: the queue reads `outgoing_messages.id` into
`engine/message.Message.ID`, `Message.Base()` copies it into
`nfymsg.Base.ID`, and `msg.MsgID()` exposes it to the webhook sender. The
sender sets that exact value as `Idempotency-Key`.

- Every HTTP attempt for one logical outgoing message uses the same key.
- Different `outgoing_messages` rows use different keys because `id` is the
  row's UUID primary key.
- A missing or empty key is invalid and MUST NOT be sent by Core or accepted
  by Gateway.
- No component may generate a fallback key or derive one from `AlertID`, the
  opaque destination token, the JSON body, a payload hash, a timestamp, or an
  individual HTTP attempt.
- The key is correlation and deduplication data, not authentication.
- The JSON payload is byte-for-byte independent of the delivery identity; the
  five v0.34.1 JSON fixtures do not gain a delivery-ID field.

`AlertID`, the destination token, and a hash of the body are not safe
substitutes:

- one alert legitimately produces multiple deliveries;
- one destination receives unrelated events;
- two intentional messages may have identical bodies;
- retrying after a lost response is indistinguishable from a new request.

The body hash MUST be used only as a conflict fingerprint after a stable
delivery identity is available, never as the identity itself.

### Idempotency model

Gateway acceptance uses a durable uniqueness key composed of:

1. the authenticated Core principal;
2. the resolved internal destination ID; and
3. the Core delivery identity, unchanged across retries of one
   `outgoing_messages` row.

In the same transaction as job creation, Gateway stores that key and a SHA-256
digest of the validated, canonical typed event.

- A new key and payload creates one durable job.
- A repeated key with the same digest creates no additional job and returns
  `202` with the original Gateway receipt ID and `duplicate: true`.
- A repeated key with a different digest creates no job and returns
  `409 Conflict` with error code `delivery_identity_conflict`.
- The Gateway-generated receipt ID identifies the durable Gateway job. It does
  not replace the Core delivery identity.

Gateway MUST reject an absent, empty, malformed, or repeated
`Idempotency-Key`; it MUST NOT silently invent a random ID or use body-hash
deduplication as a fallback.

## Reliable acceptance and `202 Accepted`

Gateway may return `202 Accepted` only after all of the following are true:

1. transport, authentication, and authorization checks succeeded;
2. the opaque token resolved to an enabled internal destination;
3. the complete body was read within the limit and the typed event validated;
4. the durable acceptance transaction committed the job, routing reference,
   delivery identity, and payload digest; or
5. a committed record proved that the same delivery identity and payload had
   already been accepted.

An in-memory queue, goroutine/channel handoff, log line, temporary file, or
started-but-uncommitted database transaction is not reliable acceptance.
Provider delivery is asynchronous and is not required before returning
`202`.

If durable state is unavailable, commit outcome is unknown, or the operation
cannot finish safely, Gateway returns an error. It MUST NOT return `202`.
After an ambiguous response, a Core retry is safe only when the stable delivery
identity model is in effect.

## HTTP response semantics

Successful acceptance uses `Content-Type: application/json`:

```json
{
  "receipt_id": "opaque-gateway-receipt",
  "status": "accepted",
  "duplicate": false
}
```

`receipt_id` is an opaque Gateway value. A duplicate acceptance returns the
same receipt with `duplicate: true`. No success condition returns `200` or
`204`.

Gateway-generated errors use `Content-Type: application/problem+json` and a
stable machine-readable `code`. Error text MUST NOT echo credentials, tokens,
destinations, verification codes, or event field values.

```json
{
  "type": "about:blank",
  "title": "Invalid request",
  "status": 400,
  "code": "invalid_request",
  "request_id": "opaque-correlation-value"
}
```

| Status | Meaning |
| --- | --- |
| `202 Accepted` | A new job is durably committed, or an identical delivery identity was already durably accepted |
| `400 Bad Request` | Missing, empty, malformed, or repeated `Idempotency-Key`; malformed/ambiguous JSON; invalid field type or value; missing/extra field; duplicate JSON key; non-empty query string; or trailing data |
| `401 Unauthorized` | Core authentication is missing or deterministically invalid, including an unknown/disabled/expired/revoked credential, invalid signature, invalid timestamp/nonce, or authentication replay |
| `403 Forbidden` | A valid credential maps to a disabled principal or a principal without intake authorization |
| `404 Not Found` | The authenticated request names an unknown or disabled opaque destination; response remains generic |
| `405 Method Not Allowed` | Method is not `POST`; include `Allow: POST` |
| `409 Conflict` | One stable delivery identity is reused with a different canonical payload |
| `413 Content Too Large` | Body exceeds 262,144 raw bytes |
| `415 Unsupported Media Type` | Media type or content encoding is unsupported |
| `422 Unprocessable Content` | `Type` is not on the supported-event allowlist |
| `429 Too Many Requests` | Admission control rejected the request; include `Retry-After` when known |
| `500 Internal Server Error` | Unexpected failure before reliable acceptance |
| `503 Service Unavailable` | Durable acceptance is unavailable or cannot be confirmed; include `Retry-After` when known |

The accepted Core transport-correctness checkpoint treats every non-2xx
response as a send failure and feeds the error into Core's existing retry
path. The three-second sender timeout and existing retry/backoff behavior are
unchanged.

## Sensitive data and logging

The request body is not safe to log. In particular:

- `Code` is secret verification data;
- `Summary`, `Details`, `Meta`, and `LogEntry` may contain operational
  details, personal data, URLs, or source-system labels;
- the opaque path token is sensitive routing material;
- authentication and cookie headers are credentials;
- the delivery identity is correlation data and SHOULD be logged only as a
  one-way digest or short non-reversible reference.

Application, access, trace, and audit logs MUST NOT record raw bodies, raw
tokens, complete request URLs, authorization headers, destinations, or
provider credentials. Safe structured fields include a Gateway request ID,
Gateway receipt ID, validated event type, body byte count, response status,
duration, duplicate flag, stable error code, and an internal or irreversibly
hashed destination reference.

Validation errors identify field names and error codes, not rejected values.
Metrics use bounded labels and MUST NOT use alert IDs, service IDs, tokens,
destinations, summaries, or log entries as labels.

## Decision required

The project owner must decide the following before the affected behavior is
implemented:

The `Idempotency-Key: <outgoing_messages.id>` delivery-identity binding and
the prohibition on no-ID sends are approved and are no longer decision items.

1. **Security Boundary V1 owner decision.** The linked decision proposal
   uniquely selects HMAC-signed requests over verified TLS and a 256-bit opaque
   token backed by a separate keyed HMAC verifier. Draft publication is not
   approval. Project-owner merge after formal review approves those exact
   choices; until then the opaque token remains insufficient authentication and
   both mechanisms remain unimplemented.
2. **Additional Core event types.** Confirm that `AlertBundle` and
   `ScheduleOnCallUsers` remain rejected for the Gateway MVP, or approve
   schemas and fixtures for them.
3. **Implementation prerequisites after decision approval.** Select concrete
   production secret sources and separately authorize the forward security
   migration, Core signer, Gateway authenticator/resolver and final runtime
   wiring. No implementation is authorized by merging documentation alone.

The machine-readable `AlertState` field and its three case-sensitive values
are owner-approved and are no longer a decision item. Until the remaining
decisions are recorded, they remain contract blockers rather than implicit
implementation defaults.
