# Canonical Event Format V1

Canonical Event Format V1 is the deterministic representation of a validated,
typed Core webhook event between HTTP transport validation and future payload
protection. It is not wired into the runtime or durable-acceptance store yet.

## Output

Canonicalization returns:

- format version `1`;
- one compact UTF-8 JSON object with no BOM, surrounding whitespace, or trailing
  newline;
- the literal SHA-256 digest of those exact JSON bytes.

The byte slice is immutable at the API boundary: callers receive a defensive
copy. The digest is returned by value. Canonical bytes and their digest are
sensitive event material and must not be logged or used as metric labels.

## Event shapes and field order

The `Type` value is selected from the known concrete Go event type and is never
taken from a free-form field.

| Event | Fixed field order |
| --- | --- |
| `TestEvent` | `AppName`, `Type` |
| `VerificationEvent` | `AppName`, `Type`, `Code` |
| `AlertEvent` | `AppName`, `Type`, `AlertID`, `Summary`, `Details`, `ServiceID`, `ServiceName`, `Meta` |
| `AlertStatusEvent` | `AppName`, `Type`, `AlertID`, `LogEntry`, `AlertState` |

`Meta` is required for `AlertEvent`, including when it is empty. Its keys are
sorted in ascending ASCII order and an empty non-nil map is encoded as `{}`.
Canonicalization never modifies the input map.

## String and Unicode rules

V1 defines its string encoding directly. Quotes and reverse solidus use the
two-character JSON escapes. Backspace, form feed, newline, carriage return, and
tab use their short JSON escapes; other U+0000 through U+001F characters use
lowercase `\u00xx`. The HTML-sensitive characters `<`, `>`, and `&` are encoded
as `\u003c`, `\u003e`, and `\u0026`; U+2028 and U+2029 are encoded as
`\u2028` and `\u2029`. Other valid Unicode remains literal UTF-8. These rules
do not depend on a JSON library's map ordering or future escaping choices.

No Unicode normalization is performed. Canonically equivalent but byte-distinct
NFC and NFD strings therefore remain distinct events. Literal Unicode and a
valid JSON escape that the strict HTTP decoder resolves to the same Go string
produce identical canonical bytes.

## Fail-closed boundary

Nil events, typed-nil events, unsupported `Event` implementations, nil `Meta`,
non-ASCII `Meta` keys, and invalid UTF-8 fail with the fixed
`ErrCanonicalEvent` sentinel. Errors do not wrap or disclose event content.

V1 bytes are immutable once stored. Any future change to field order, field
presence, number formatting, string escaping, Unicode treatment, or `Meta`
ordering requires a new canonical format version; it must not silently alter
V1.

## Deferred integration

This foundation does not implement payload encryption, authentication,
destination resolution, durable sink wiring, workers, providers, callbacks, or
HTTP `202`/`409` behavior. Runtime remains on `UnavailableSink` and returns
`503 Service Unavailable` for otherwise-valid webhook requests.
