# Sanitized GoAlert v0.34.1 webhook fixtures

These JSON files model the payload emitted by MS OnCall Core's GoAlert
v0.34.1 baseline at commit
`0918387e38650aaddd6a923d445ee992f64d6ab6`.

## Fixture set

| File | Event | Proven PoC scenario |
| --- | --- | --- |
| `verification.json` | `Verification` | Webhook contact-method verification |
| `alert.json` | `Alert` | Initial alert notification |
| `alert-status-acknowledged.json` | `AlertStatus` | Alert acknowledged in the Core web UI |
| `alert-status-closed.json` | `AlertStatus` | Alert closed after the source alert resolved |
| `test.json` | `Test` | Source-supported event added for contract coverage; not one of the four PoC categories |

## Provenance

The exact field sets and casing come from
`ms-oncall/notification/webhook/sender.go`. Event construction is confirmed
by `ms-oncall/engine/sendmessage.go`; alert limits and metadata shape come
from `ms-oncall/alert/alert.go` and `ms-oncall/alert/metadata.go`.
GoAlert's webhook documentation and smoke test corroborate the payload shape.

The PoC evidence in `PROJECT_CONTEXT.md` confirms that the first four
scenarios traversed the tested Core-to-PrometheusAlert-to-email path. No raw
PoC request capture was available or read for this task. These are therefore
source-derived, scenario-matched fixtures rather than byte-for-byte production
captures.

The two status fixtures intentionally have the same field set. Core v0.34.1
does not serialize its internal `NewAlertState`; only the rendered
`LogEntry` distinguishes the scenarios. Consumers must not parse that text
to infer state.

## Sanitization

- Application, service, user, host, alert, and metadata values are synthetic.
- The UUID and alert number are generated fixture identifiers with no mapping
  to a deployed Core database.
- `fixture-host.invalid` uses the reserved `.invalid` domain.
- The verification code is a conventional synthetic six-digit value.
- No email address, telephone number, contact token, API key, access token,
  password, provider credential, certificate, private key, or production
  connection string is present.
- No destination is represented in the payload because GoAlert v0.34.1 sends
  the webhook destination in the request URL, not in these JSON fields.

Fixture-only provenance is documented here rather than by adding non-contract
properties to the JSON objects.
