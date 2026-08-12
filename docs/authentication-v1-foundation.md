# Gateway Authentication V1 Foundation

Status: In review

This checkpoint implements only the transport-independent Authentication V1
domain service approved by the project owner. The protocol source is
[Core to Gateway Security Boundary V1](core-to-gateway-security-boundary-v1.md).
The matching Core signer foundation was accepted in Core PR #2, merge commit
`d73e7a357f9d75a8b9c0aa7851107e860faed9d7`. Production Core runtime still
injects no real audience, credential or Authentication secret.

## Boundary

`internal/authentication` accepts an in-memory request value containing only:

- the method and canonical path;
- the canonical delivery identity;
- value collections for `Authorization`, `X-MS-OnCall-Timestamp` and
  `X-MS-OnCall-Nonce`; and
- the exact raw request body bytes.

The constructor defensively copies the three header collections and body. The
request has no caller-controlled audience, principal or destination. Its
formatted representation is always `[redacted]`. A successful result exposes
only the trusted `securitystate.CorePrincipalID` derived from the verified
credential record, and its formatted representation is also redacted.

The package has no dependency on HTTP, JSON decoding, intake, payload
protection, PostgreSQL, logging, metrics, tracing or network packages. It uses
only the existing security-state interfaces and the durable delivery-identity
value parser.

## Exact request verification

The service requires method `POST` and the literal path:

```text
/v1/goalert/contact-method/mso1_<43-character canonical unpadded base64url body>
```

The token body must decode to exactly 32 bytes. A complete URL, userinfo,
query, fragment, percent encoding, alternate alphabet, padding, duplicate
slash, dot segment, suffix or case variation is invalid. The delivery identity
must be a canonical lowercase, hyphenated, non-zero UUID.

Each of the three Authentication headers must have exactly one non-empty value
without surrounding whitespace or CR/LF. Authorization syntax is exact:

```text
MSOnCall-HMAC-SHA256 Credential=<canonical lowercase RFC 4122 UUIDv4>, Signature=<43-character canonical unpadded base64url MAC>
```

No equivalent whitespace, quoting, padding, extra parameter, alternate scheme
or fallback identity is accepted. The timestamp is unsigned base-10 Unix
seconds with no sign, whitespace, decimal, exponent, overflow or leading zero
except the value `0`. The nonce is canonical unpadded base64url, 22 characters,
and decodes to exactly 16 bytes.

## HMAC and time boundary

The HMAC-SHA-256 input is byte-for-byte:

```text
MS_ONCALL_GATEWAY_REQUEST_V1
<configured canonical GatewayAudienceID UUID>
POST
<validated canonical path>
<credential_id>
<canonical delivery identity UUID>
<original canonical Unix-seconds value>
<original canonical nonce>
<lowercase hexadecimal SHA-256 of the exact raw body bytes>
```

Fields have one LF between them and no trailing LF. The service uses the local
configured audience, never a caller-supplied audience. It does not decode or
re-encode the body. The 32-byte MAC is decoded and compared in constant time.
Only after a valid MAC does the service enforce the inclusive 60-second window:
`abs(nowUnix-signedUnix) <= 60`.

## State and authorization order

After local syntax validation, the service reads its injected clock exactly
once and then performs these narrow calls in order:

1. read the current realm binding and require an exact configured-audience
   match;
2. look up the credential by configured audience and public credential ID;
3. require matching IDs and audience plus an active or retiring credential
   usable at that clock snapshot;
4. obtain the independent 32-byte Authentication secret by configured audience
   and public credential ID;
5. verify the exact HMAC and then the timestamp window;
6. reserve the decoded nonce under the credential's internal record ID using
   the same clock snapshot; and
7. only after `ReplayReserved`, load the principal derived from the credential
   and require matching ID/audience, enabled state and `gateway.intake.v1`.

`ReplayDuplicate` is an authentication failure. Replay unavailability,
ambiguous outcome or an illegal disposition fails closed as unavailable. A
forbidden principal is evaluated only after successful reservation. Context is
checked between dependency calls. The service caches no audience, credential,
principal, revocation or replay result.

## Safe errors

Failures use only these fixed content-free categories:

- `authentication configuration invalid`;
- `authentication request invalid`;
- `authentication failed`;
- `authentication forbidden`;
- `authentication unavailable`; and
- `authentication canceled`.

Dependency errors are never wrapped. Errors and formatting do not expose an
audience, path, token, credential, principal, delivery identity, timestamp,
nonce, signature, secret, body, digest or data-source detail. The package emits
no log, trace or metric.

## Verification and deferred work

Unit coverage includes the hard-coded test-only Core/Gateway golden vector,
strict parsing and cardinality, credential lifecycle boundaries, exact raw-body
binding, inclusive timestamp boundaries, replay/principal ordering, concurrent
duplicate reservation, defensive copies and redaction. Ordinary validation
leaves all PostgreSQL integration variables unset and accesses no database.

This checkpoint does not implement an HTTP adapter or status mapping,
PostgreSQL security-state repository, opaque-token resolver, production secret
provider, credential or token administration, rotation, runtime composition or
wiring. Gateway runtime remains `UnavailableSink`; otherwise-valid webhooks
still receive `503 Service Unavailable`. Every later stage requires separate
project-owner authorization.
