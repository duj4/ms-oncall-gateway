package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	testToken    = "fixture-routing-token"
	testIdentity = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
)

type recordingSink struct {
	mu         sync.Mutex
	deliveries []Delivery
	acceptance Acceptance
	err        error
}

func (s *recordingSink) Enqueue(_ context.Context, delivery Delivery) (Acceptance, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deliveries = append(s.deliveries, delivery)
	return s.acceptance, s.err
}

func (s *recordingSink) snapshot() []Delivery {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Delivery(nil), s.deliveries...)
}

func acceptingSink() *recordingSink {
	return &recordingSink{acceptance: Acceptance{ReceiptID: "gateway-receipt"}}
}

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile("../../testdata/goalert/v0.34.1/" + name)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return data
}

func webhookRequest(method string, body []byte) *http.Request {
	req := httptest.NewRequest(method, webhookPathPrefix+testToken, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(idempotencyKeyHeader, testIdentity)
	return req
}

func alertRequestBody(summary, details, meta string) []byte {
	return []byte(fmt.Sprintf(
		`{"AppName":"MS OnCall","Type":"Alert","AlertID":7,"Summary":%s,"Details":%s,"ServiceID":"11111111-2222-4333-8444-555555555555","ServiceName":"Fixture Service","Meta":%s}`,
		summary,
		details,
		meta,
	))
}

func perform(handler http.Handler, req *http.Request) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	return recorder
}

func TestReceiverFixturesWithRealHTTPServer(t *testing.T) {
	tests := []struct {
		name     string
		fixture  string
		expected Event
	}{
		{
			name:    "test",
			fixture: "test.json",
			expected: TestEvent{
				AppName: "MS OnCall Fixture",
			},
		},
		{
			name:    "verification",
			fixture: "verification.json",
			expected: VerificationEvent{
				AppName: "MS OnCall Fixture",
				Code:    "123456",
			},
		},
		{
			name:    "alert",
			fixture: "alert.json",
			expected: AlertEvent{
				AppName:     "MS OnCall Fixture",
				AlertID:     4242,
				Summary:     "Synthetic CPU saturation alert",
				Details:     "**Synthetic alert details**\n\n- instance: `fixture-host.invalid:9100`\n- value: `95`",
				ServiceID:   "11111111-2222-4333-8444-555555555555",
				ServiceName: "Fixture Service",
				Meta: map[string]string{
					"environment":    "fixture",
					"fixture_origin": "sanitized-goalert-v0.34.1",
				},
			},
		},
		{
			name:    "acknowledged",
			fixture: "alert-status-acknowledged.json",
			expected: AlertStatusEvent{
				AppName:    "MS OnCall Fixture",
				AlertID:    4242,
				LogEntry:   "Acknowledged by Fixture User (Web)",
				AlertState: AlertStateAcknowledged,
			},
		},
		{
			name:    "closed",
			fixture: "alert-status-closed.json",
			expected: AlertStatusEvent{
				AppName:    "MS OnCall Fixture",
				AlertID:    4242,
				LogEntry:   "Closed via Fixture Grafana integration (Grafana)",
				AlertState: AlertStateClosed,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sink := acceptingSink()
			server := httptest.NewServer(NewHandler(sink, nil))
			defer server.Close()

			req, err := http.NewRequest(http.MethodPost, server.URL+webhookPathPrefix+testToken, bytes.NewReader(fixture(t, test.fixture)))
			if err != nil {
				t.Fatalf("create request: %v", err)
			}
			req.Header.Set("Content-Type", "application/json; charset=utf-8")
			req.Header.Set(idempotencyKeyHeader, testIdentity)

			response, err := server.Client().Do(req)
			if err != nil {
				t.Fatalf("send request: %v", err)
			}
			defer response.Body.Close()
			if response.StatusCode != http.StatusAccepted {
				body, _ := io.ReadAll(response.Body)
				t.Fatalf("status = %d, want 202; body=%s", response.StatusCode, body)
			}

			deliveries := sink.snapshot()
			if len(deliveries) != 1 {
				t.Fatalf("sink calls = %d, want 1", len(deliveries))
			}
			if deliveries[0].Token != testToken {
				t.Errorf("token = %q, want %q", deliveries[0].Token, testToken)
			}
			if deliveries[0].Identity != testIdentity {
				t.Errorf("identity = %q, want exact header value", deliveries[0].Identity)
			}
			if !reflect.DeepEqual(deliveries[0].Event, test.expected) {
				t.Errorf("event = %#v, want %#v", deliveries[0].Event, test.expected)
			}
		})
	}
}

func TestAlertStatusUsesAlertStateOnly(t *testing.T) {
	tests := []struct {
		name     string
		state    AlertState
		logEntry string
	}{
		{name: "unacknowledged with misleading close text", state: AlertStateUnacknowledged, logEntry: "Closed and acknowledged in display text"},
		{name: "acknowledged with localized close text", state: AlertStateAcknowledged, logEntry: "警报已经关闭"},
		{name: "closed with misleading acknowledgement text", state: AlertStateClosed, logEntry: "Acknowledged by someone"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sink := acceptingSink()
			body := []byte(fmt.Sprintf(`{"AppName":"MS OnCall","Type":"AlertStatus","AlertID":7,"LogEntry":%q,"AlertState":%q}`,
				test.logEntry, test.state))
			response := perform(NewHandler(sink, nil), webhookRequest(http.MethodPost, body))
			if response.Code != http.StatusAccepted {
				t.Fatalf("status = %d, want 202; body=%s", response.Code, response.Body.String())
			}
			delivery := sink.snapshot()[0]
			event, ok := delivery.Event.(AlertStatusEvent)
			if !ok {
				t.Fatalf("event type = %T, want AlertStatusEvent", delivery.Event)
			}
			if event.AlertState != test.state {
				t.Errorf("state = %q, want %q", event.AlertState, test.state)
			}
			if event.LogEntry != test.logEntry {
				t.Errorf("LogEntry changed: got %q", event.LogEntry)
			}
		})
	}
}

func TestInvalidAlertStateDoesNotCallSink(t *testing.T) {
	tests := []struct {
		name  string
		field string
	}{
		{name: "missing", field: ""},
		{name: "null", field: `,"AlertState":null`},
		{name: "number", field: `,"AlertState":2`},
		{name: "wrong case", field: `,"AlertState":"acknowledged"`},
		{name: "unknown", field: `,"AlertState":"Silenced"`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sink := acceptingSink()
			body := []byte(`{"AppName":"MS OnCall","Type":"AlertStatus","AlertID":7,"LogEntry":"display text"` + test.field + `}`)
			response := perform(NewHandler(sink, nil), webhookRequest(http.MethodPost, body))
			if response.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400", response.Code)
			}
			if calls := len(sink.snapshot()); calls != 0 {
				t.Errorf("sink calls = %d, want 0", calls)
			}
		})
	}
}

func TestMetaValuesMustBeStrings(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{name: "null", value: `null`},
		{name: "number", value: `42`},
		{name: "boolean", value: `true`},
		{name: "array", value: `[]`},
		{name: "object", value: `{}`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sink := acceptingSink()
			body := alertRequestBody(`"summary"`, `"details"`, `{"key":`+test.value+`}`)
			response := perform(NewHandler(sink, nil), webhookRequest(http.MethodPost, body))
			if response.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400; body=%s", response.Code, response.Body.String())
			}
			if calls := len(sink.snapshot()); calls != 0 {
				t.Errorf("sink calls = %d, want 0", calls)
			}
		})
	}

	sink := acceptingSink()
	body := alertRequestBody(`"summary"`, `"details"`, `{"key":""}`)
	response := perform(NewHandler(sink, nil), webhookRequest(http.MethodPost, body))
	if response.Code != http.StatusAccepted {
		t.Fatalf("empty string status = %d, want 202; body=%s", response.Code, response.Body.String())
	}
	delivery := sink.snapshot()[0]
	event, ok := delivery.Event.(AlertEvent)
	if !ok {
		t.Fatalf("event type = %T, want AlertEvent", delivery.Event)
	}
	if value, ok := event.Meta["key"]; !ok || value != "" {
		t.Errorf("Meta key = (%q, %t), want present empty string", value, ok)
	}
}

func TestLossyUnicodeEscapesDoNotCallSink(t *testing.T) {
	surrogates := []struct {
		name  string
		value string
	}{
		{name: "lone high surrogate", value: `"\uD800"`},
		{name: "lone low surrogate", value: `"\uDC00"`},
	}
	fields := []struct {
		name string
		body func(string) []byte
	}{
		{
			name: "Summary",
			body: func(value string) []byte {
				return alertRequestBody(value, `"details"`, `{}`)
			},
		},
		{
			name: "Details",
			body: func(value string) []byte {
				return alertRequestBody(`"summary"`, value, `{}`)
			},
		},
		{
			name: "Meta value",
			body: func(value string) []byte {
				return alertRequestBody(`"summary"`, `"details"`, `{"key":`+value+`}`)
			},
		},
		{
			name: "LogEntry",
			body: func(value string) []byte {
				return []byte(`{"AppName":"MS OnCall","Type":"AlertStatus","AlertID":7,"LogEntry":` + value + `,"AlertState":"Acknowledged"}`)
			},
		},
	}

	for _, field := range fields {
		for _, surrogate := range surrogates {
			t.Run(field.name+"/"+surrogate.name, func(t *testing.T) {
				sink := acceptingSink()
				response := perform(NewHandler(sink, nil), webhookRequest(http.MethodPost, field.body(surrogate.value)))
				if response.Code != http.StatusBadRequest {
					t.Errorf("status = %d, want 400; body=%s", response.Code, response.Body.String())
				}
				if calls := len(sink.snapshot()); calls != 0 {
					t.Errorf("sink calls = %d, want 0", calls)
				}
			})
		}
	}
}

func TestValidSurrogatePairsArePreserved(t *testing.T) {
	const escapedEmoji = `"\uD83D\uDE00"`

	alertSink := acceptingSink()
	alertBody := alertRequestBody(escapedEmoji, escapedEmoji, `{"key":`+escapedEmoji+`}`)
	response := perform(NewHandler(alertSink, nil), webhookRequest(http.MethodPost, alertBody))
	if response.Code != http.StatusAccepted {
		t.Fatalf("Alert status = %d, want 202; body=%s", response.Code, response.Body.String())
	}
	alertEvent, ok := alertSink.snapshot()[0].Event.(AlertEvent)
	if !ok {
		t.Fatalf("event type = %T, want AlertEvent", alertSink.snapshot()[0].Event)
	}
	if alertEvent.Summary != "😀" || alertEvent.Details != "😀" || alertEvent.Meta["key"] != "😀" {
		t.Errorf("valid surrogate pair changed: %#v", alertEvent)
	}

	statusSink := acceptingSink()
	statusBody := []byte(`{"AppName":"MS OnCall","Type":"AlertStatus","AlertID":7,"LogEntry":` + escapedEmoji + `,"AlertState":"Closed"}`)
	response = perform(NewHandler(statusSink, nil), webhookRequest(http.MethodPost, statusBody))
	if response.Code != http.StatusAccepted {
		t.Fatalf("AlertStatus status = %d, want 202; body=%s", response.Code, response.Body.String())
	}
	statusEvent, ok := statusSink.snapshot()[0].Event.(AlertStatusEvent)
	if !ok {
		t.Fatalf("event type = %T, want AlertStatusEvent", statusSink.snapshot()[0].Event)
	}
	if statusEvent.LogEntry != "😀" {
		t.Errorf("LogEntry = %q, want emoji", statusEvent.LogEntry)
	}
}

func TestDecodeJSONStringRejectsUnpairedSurrogates(t *testing.T) {
	for _, raw := range []string{`"\uD800"`, `"\uDC00"`, `"\uD800\u0041"`} {
		if _, err := decodeJSONString([]byte(raw)); !errors.Is(err, errInvalidEvent) {
			t.Errorf("decodeJSONString(%s) error = %v, want invalid event", raw, err)
		}
	}

	value, err := decodeJSONString([]byte(`"\uD83D\uDE00"`))
	if err != nil || value != "😀" {
		t.Errorf("valid pair = (%q, %v), want emoji", value, err)
	}
	literal, err := decodeJSONString([]byte(`"\\uD800"`))
	if err != nil || literal != `\uD800` {
		t.Errorf("escaped literal = (%q, %v), want literal backslash-u", literal, err)
	}
}

func TestIdempotencyKeyValidationAndOpaqueHandoff(t *testing.T) {
	validBody := fixture(t, "test.json")
	tests := []struct {
		name    string
		headers []string
	}{
		{name: "missing"},
		{name: "empty", headers: []string{""}},
		{name: "non UUID", headers: []string{"opaque-but-not-a-uuid"}},
		{name: "unhyphenated", headers: []string{"aaaaaaaabbbb4ccc8dddeeeeeeeeeeee"}},
		{name: "uppercase", headers: []string{"AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE"}},
		{name: "duplicate", headers: []string{testIdentity, "11111111-2222-4333-8444-555555555555"}},
		{name: "comma-separated multi-value", headers: []string{testIdentity + ", 11111111-2222-4333-8444-555555555555"}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sink := acceptingSink()
			req := httptest.NewRequest(http.MethodPost, webhookPathPrefix+testToken, bytes.NewReader(validBody))
			req.Header.Set("Content-Type", "application/json")
			for _, value := range test.headers {
				req.Header.Add(idempotencyKeyHeader, value)
			}
			response := perform(NewHandler(sink, nil), req)
			if response.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400", response.Code)
			}
			if calls := len(sink.snapshot()); calls != 0 {
				t.Errorf("sink calls = %d, want 0", calls)
			}
		})
	}

	sink := acceptingSink()
	response := perform(NewHandler(sink, nil), webhookRequest(http.MethodPost, validBody))
	if response.Code != http.StatusAccepted {
		t.Fatalf("valid key status = %d, want 202", response.Code)
	}
	if got := sink.snapshot()[0].Identity; got != testIdentity {
		t.Errorf("identity = %q, want %q", got, testIdentity)
	}
}

func TestInvalidRequests(t *testing.T) {
	validBody := fixture(t, "test.json")
	tests := []struct {
		name       string
		request    func() *http.Request
		wantStatus int
		wantAllow  string
	}{
		{
			name: "wrong method",
			request: func() *http.Request {
				return webhookRequest(http.MethodGet, validBody)
			},
			wantStatus: http.StatusMethodNotAllowed,
			wantAllow:  http.MethodPost,
		},
		{
			name: "invalid path",
			request: func() *http.Request {
				return httptest.NewRequest(http.MethodPost, "/v1/goalert/contact-method/", bytes.NewReader(validBody))
			},
			wantStatus: http.StatusNotFound,
		},
		{
			name: "extra path segment",
			request: func() *http.Request {
				return httptest.NewRequest(http.MethodPost, webhookPathPrefix+testToken+"/extra", bytes.NewReader(validBody))
			},
			wantStatus: http.StatusNotFound,
		},
		{
			name: "wrong content type",
			request: func() *http.Request {
				req := webhookRequest(http.MethodPost, validBody)
				req.Header.Set("Content-Type", "text/plain")
				return req
			},
			wantStatus: http.StatusUnsupportedMediaType,
		},
		{
			name: "unsupported charset",
			request: func() *http.Request {
				req := webhookRequest(http.MethodPost, validBody)
				req.Header.Set("Content-Type", "application/json; charset=iso-8859-1")
				return req
			},
			wantStatus: http.StatusUnsupportedMediaType,
		},
		{
			name: "compressed body",
			request: func() *http.Request {
				req := webhookRequest(http.MethodPost, validBody)
				req.Header.Set("Content-Encoding", "gzip")
				return req
			},
			wantStatus: http.StatusUnsupportedMediaType,
		},
		{
			name: "query string",
			request: func() *http.Request {
				req := webhookRequest(http.MethodPost, validBody)
				req.URL.RawQuery = "destination=secret"
				return req
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "malformed JSON",
			request: func() *http.Request {
				return webhookRequest(http.MethodPost, []byte(`{"AppName":`))
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "trailing JSON",
			request: func() *http.Request {
				return webhookRequest(http.MethodPost, append(append([]byte(nil), validBody...), []byte(` {}`)...))
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "unknown field",
			request: func() *http.Request {
				return webhookRequest(http.MethodPost, []byte(`{"AppName":"MS OnCall","Type":"Test","Unexpected":true}`))
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "duplicate field",
			request: func() *http.Request {
				return webhookRequest(http.MethodPost, []byte(`{"AppName":"MS OnCall","Type":"Test","Type":"Test"}`))
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "missing Type",
			request: func() *http.Request {
				return webhookRequest(http.MethodPost, []byte(`{"AppName":"MS OnCall"}`))
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "null Type",
			request: func() *http.Request {
				return webhookRequest(http.MethodPost, []byte(`{"AppName":"MS OnCall","Type":null}`))
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "numeric Type",
			request: func() *http.Request {
				return webhookRequest(http.MethodPost, []byte(`{"AppName":"MS OnCall","Type":1}`))
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "unknown string Type",
			request: func() *http.Request {
				return webhookRequest(http.MethodPost, []byte(`{"AppName":"MS OnCall","Type":"FutureEvent"}`))
			},
			wantStatus: http.StatusUnprocessableEntity,
		},
		{
			name: "known unsupported string Type",
			request: func() *http.Request {
				return webhookRequest(http.MethodPost, []byte(`{"AppName":"MS OnCall","Type":"AlertBundle"}`))
			},
			wantStatus: http.StatusUnprocessableEntity,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sink := acceptingSink()
			response := perform(NewHandler(sink, nil), test.request())
			if response.Code != test.wantStatus {
				t.Errorf("status = %d, want %d; body=%s", response.Code, test.wantStatus, response.Body.String())
			}
			if response.Header().Get("Allow") != test.wantAllow {
				t.Errorf("Allow = %q, want %q", response.Header().Get("Allow"), test.wantAllow)
			}
			if calls := len(sink.snapshot()); calls != 0 {
				t.Errorf("sink calls = %d, want 0", calls)
			}
		})
	}
}

func TestBodySizeBoundary(t *testing.T) {
	base := fixture(t, "test.json")
	if len(base) >= MaxBodyBytes {
		t.Fatal("test fixture unexpectedly exceeds body limit")
	}
	atLimit := append(append([]byte(nil), base...), bytes.Repeat([]byte(" "), MaxBodyBytes-len(base))...)
	overLimit := append(append([]byte(nil), atLimit...), ' ')

	tests := []struct {
		name                 string
		body                 []byte
		unknownContentLength bool
		wantStatus           int
		wantCalls            int
	}{
		{name: "exactly 256 KiB", body: atLimit, wantStatus: http.StatusAccepted, wantCalls: 1},
		{name: "over 256 KiB", body: overLimit, wantStatus: http.StatusRequestEntityTooLarge, wantCalls: 0},
		{name: "streamed over 256 KiB", body: overLimit, unknownContentLength: true, wantStatus: http.StatusRequestEntityTooLarge, wantCalls: 0},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sink := acceptingSink()
			request := webhookRequest(http.MethodPost, test.body)
			if test.unknownContentLength {
				request.ContentLength = -1
			}
			response := perform(NewHandler(sink, nil), request)
			if response.Code != test.wantStatus {
				t.Errorf("status = %d, want %d", response.Code, test.wantStatus)
			}
			if calls := len(sink.snapshot()); calls != test.wantCalls {
				t.Errorf("sink calls = %d, want %d", calls, test.wantCalls)
			}
		})
	}
}

func TestAcceptingSinkResponse(t *testing.T) {
	sink := &recordingSink{acceptance: Acceptance{ReceiptID: "receipt-42", Duplicate: true}}
	response := perform(NewHandler(sink, nil), webhookRequest(http.MethodPost, fixture(t, "test.json")))
	if response.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", response.Code)
	}
	if got := response.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}
	var result struct {
		ReceiptID string `json:"receipt_id"`
		Status    string `json:"status"`
		Duplicate bool   `json:"duplicate"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if result.ReceiptID != "receipt-42" || result.Status != "accepted" || !result.Duplicate {
		t.Errorf("response = %#v", result)
	}
}

func TestUnavailableRuntimeNeverReturnsSuccess(t *testing.T) {
	response := perform(NewHandler(UnavailableSink{}, nil), webhookRequest(http.MethodPost, fixture(t, "test.json")))
	if response.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", response.Code)
	}
	if got := response.Header().Get("Retry-After"); got == "" {
		t.Error("Retry-After is missing")
	}
}

func TestSinkFailureReturnsGenericError(t *testing.T) {
	sink := &recordingSink{err: errors.New("database details must stay private")}
	response := perform(NewHandler(sink, nil), webhookRequest(http.MethodPost, fixture(t, "test.json")))
	if response.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", response.Code)
	}
	if strings.Contains(response.Body.String(), "database details") {
		t.Error("response leaked sink error")
	}
}

func TestHealthAndMetrics(t *testing.T) {
	handler := NewHandler(UnavailableSink{}, nil)

	health := perform(handler, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if health.Code != http.StatusOK || health.Body.String() != "ok\n" {
		t.Errorf("health response = (%d, %q), want (200, ok)", health.Code, health.Body.String())
	}
	healthPost := perform(handler, httptest.NewRequest(http.MethodPost, "/healthz", nil))
	if healthPost.Code != http.StatusMethodNotAllowed || healthPost.Header().Get("Allow") != http.MethodGet {
		t.Errorf("health POST = (%d, Allow %q)", healthPost.Code, healthPost.Header().Get("Allow"))
	}
	ready := perform(handler, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if ready.Code != http.StatusNotFound {
		t.Errorf("ready status = %d, want 404", ready.Code)
	}
	metrics := perform(handler, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if metrics.Code != http.StatusOK {
		t.Fatalf("metrics status = %d, want 200", metrics.Code)
	}
	if !strings.Contains(metrics.Body.String(), "ms_oncall_gateway_http_requests_total") {
		t.Errorf("metrics body missing request counter: %s", metrics.Body.String())
	}
	if strings.Contains(metrics.Body.String(), testToken) || strings.Contains(metrics.Body.String(), testIdentity) {
		t.Error("metrics leaked routing token or delivery identity")
	}
}

func TestSensitiveValuesAreRedacted(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	handler := NewHandler(UnavailableSink{}, logger)
	sensitiveToken := "secret-routing-token"
	sensitiveIdentity := "12345678-1234-4234-8234-123456789abc"
	body := []byte(`{"AppName":"Sensitive App","Type":"Verification","Code":"987654"}`)
	req := httptest.NewRequest(http.MethodPost, webhookPathPrefix+sensitiveToken, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(idempotencyKeyHeader, sensitiveIdentity)
	req.Header.Set("Authorization", "Bearer private-credential")
	response := perform(handler, req)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("valid request status = %d, want 503", response.Code)
	}
	queryRequest := webhookRequest(http.MethodPost, body)
	queryRequest.URL.RawQuery = "destination=hidden@example.invalid"
	queryResponse := perform(handler, queryRequest)
	metrics := perform(handler, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	combined := response.Body.String() + queryResponse.Body.String() + logs.String() + metrics.Body.String()
	for _, secret := range []string{
		sensitiveToken,
		sensitiveIdentity,
		"Sensitive App",
		"987654",
		"hidden@example.invalid",
		"private-credential",
		string(body),
	} {
		if strings.Contains(combined, secret) {
			t.Errorf("output leaked sensitive value %q", secret)
		}
	}
}

func TestConcurrentHandlerAndMetricsAccess(t *testing.T) {
	sink := acceptingSink()
	handler := NewHandler(sink, nil)
	body := fixture(t, "test.json")
	const requestCount = 64

	var waitGroup sync.WaitGroup
	waitGroup.Add(requestCount * 2)
	for i := 0; i < requestCount; i++ {
		go func() {
			defer waitGroup.Done()
			response := perform(handler, webhookRequest(http.MethodPost, body))
			if response.Code != http.StatusAccepted {
				t.Errorf("webhook status = %d, want 202", response.Code)
			}
		}()
		go func() {
			defer waitGroup.Done()
			response := perform(handler, httptest.NewRequest(http.MethodGet, "/metrics", nil))
			if response.Code != http.StatusOK {
				t.Errorf("metrics status = %d, want 200", response.Code)
			}
		}()
	}
	waitGroup.Wait()
	if calls := len(sink.snapshot()); calls != requestCount {
		t.Errorf("sink calls = %d, want %d", calls, requestCount)
	}
}

func TestServerConfiguration(t *testing.T) {
	server := NewServer("127.0.0.1:0", NewHandler(UnavailableSink{}, nil))
	if server.Addr != "127.0.0.1:0" {
		t.Errorf("address = %q", server.Addr)
	}
	if server.ReadHeaderTimeout <= 0 || server.ReadTimeout <= 0 || server.WriteTimeout <= 0 || server.IdleTimeout <= 0 {
		t.Error("server timeouts must all be positive")
	}
	if server.MaxHeaderBytes <= 0 {
		t.Error("server header-size limit must be positive")
	}
	if DefaultListenAddress != "127.0.0.1:8080" {
		t.Errorf("default address = %q", DefaultListenAddress)
	}
	if MaxBodyBytes != 256*1024 {
		t.Errorf("body limit = %d, want 262144", MaxBodyBytes)
	}
}

func TestProblemResponsesHaveStableBoundedShape(t *testing.T) {
	response := perform(NewHandler(UnavailableSink{}, nil), webhookRequest(http.MethodPost, []byte(`not-json`)))
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", response.Code)
	}
	if got := response.Header().Get("Content-Type"); got != "application/problem+json" {
		t.Errorf("Content-Type = %q", got)
	}
	var problem map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &problem); err != nil {
		t.Fatalf("decode problem response: %v", err)
	}
	if len(problem) != 4 || problem["code"] != "invalid_request" {
		t.Errorf("problem = %#v", problem)
	}
}

func TestMetricsOutputIsDeterministic(t *testing.T) {
	metrics := newRequestMetrics()
	metrics.increment("webhook", "unavailable")
	metrics.increment("health", "ok")
	first := metrics.render()
	second := metrics.render()
	if first != second {
		t.Error("metrics output changed without counter updates")
	}
	if !strings.Contains(first, `route="health",result="ok"`) || !strings.Contains(first, `route="webhook",result="unavailable"`) {
		t.Errorf("unexpected metrics output: %s", first)
	}
}

func TestServerTimeoutsAreFinite(t *testing.T) {
	server := NewServer(DefaultListenAddress, NewHandler(UnavailableSink{}, nil))
	for name, value := range map[string]time.Duration{
		"read header": server.ReadHeaderTimeout,
		"read":        server.ReadTimeout,
		"write":       server.WriteTimeout,
		"idle":        server.IdleTimeout,
	} {
		if value <= 0 || value > time.Minute {
			t.Errorf("%s timeout = %s, want >0 and <=1m", name, value)
		}
	}
}
