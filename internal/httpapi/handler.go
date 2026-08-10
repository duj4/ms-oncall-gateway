package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"strings"
	"time"
)

const (
	DefaultListenAddress = "127.0.0.1:8080"
	MaxBodyBytes         = 262144
	idempotencyKeyHeader = "Idempotency-Key"
	webhookPathPrefix    = "/v1/goalert/contact-method/"
)

type Handler struct {
	sink    Sink
	logger  *slog.Logger
	metrics *requestMetrics
}

func NewHandler(sink Sink, logger *slog.Logger) *Handler {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Handler{
		sink:    sink,
		logger:  logger,
		metrics: newRequestMetrics(),
	}
}

func NewServer(address string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              address,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    32 << 10,
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/healthz":
		h.handleHealth(w, r)
		return
	case "/metrics":
		h.handleMetrics(w, r)
		return
	}

	token, ok := webhookToken(r.URL.Path)
	if !ok {
		h.problem(w, "not_found", "not_found", http.StatusNotFound, "")
		return
	}
	h.handleWebhook(w, r, token)
}

func webhookToken(path string) (string, bool) {
	if !strings.HasPrefix(path, webhookPathPrefix) {
		return "", false
	}
	token := strings.TrimPrefix(path, webhookPathPrefix)
	if token == "" || strings.Contains(token, "/") {
		return "", false
	}
	return token, true
}

func (h *Handler) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		h.problem(w, "health", "method_not_allowed", http.StatusMethodNotAllowed, "")
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, "ok\n")
	h.record("health", "ok", http.StatusOK, "")
}

func (h *Handler) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		h.problem(w, "metrics", "method_not_allowed", http.StatusMethodNotAllowed, "")
		return
	}
	h.record("metrics", "ok", http.StatusOK, "")
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, h.metrics.render())
}

func (h *Handler) handleWebhook(w http.ResponseWriter, r *http.Request, token string) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		h.problem(w, "webhook", "method_not_allowed", http.StatusMethodNotAllowed, "")
		return
	}
	if r.URL.RawQuery != "" {
		h.problem(w, "webhook", "invalid_request", http.StatusBadRequest, "")
		return
	}
	if !validContentEncoding(r.Header.Values("Content-Encoding")) || !validContentType(r.Header.Values("Content-Type")) {
		h.problem(w, "webhook", "unsupported_media_type", http.StatusUnsupportedMediaType, "")
		return
	}

	identities := r.Header.Values(idempotencyKeyHeader)
	if len(identities) != 1 || !validCanonicalUUID(identities[0]) {
		h.problem(w, "webhook", "invalid_request", http.StatusBadRequest, "")
		return
	}
	identity := identities[0]

	if r.ContentLength > MaxBodyBytes {
		h.problem(w, "webhook", "request_too_large", http.StatusRequestEntityTooLarge, "")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxBodyBytes+1))
	if err != nil {
		h.problem(w, "webhook", "invalid_request", http.StatusBadRequest, "")
		return
	}
	if len(body) > MaxBodyBytes {
		h.problem(w, "webhook", "request_too_large", http.StatusRequestEntityTooLarge, "")
		return
	}

	event, err := decodeEvent(body)
	if errors.Is(err, errUnsupportedEvent) {
		h.problem(w, "webhook", "unsupported_event_type", http.StatusUnprocessableEntity, "")
		return
	}
	if err != nil {
		h.problem(w, "webhook", "invalid_request", http.StatusBadRequest, "")
		return
	}

	eventType := string(event.Kind())
	if h.sink == nil {
		h.problem(w, "webhook", "internal_error", http.StatusInternalServerError, eventType)
		return
	}
	acceptance, err := h.sink.Enqueue(r.Context(), Delivery{
		Token:    token,
		Identity: identity,
		Event:    event,
	})
	if errors.Is(err, ErrSinkUnavailable) {
		w.Header().Set("Retry-After", "30")
		h.problem(w, "webhook", "unavailable", http.StatusServiceUnavailable, eventType)
		return
	}
	if err != nil || acceptance.ReceiptID == "" {
		h.problem(w, "webhook", "internal_error", http.StatusInternalServerError, eventType)
		return
	}

	response := struct {
		ReceiptID string `json:"receipt_id"`
		Status    string `json:"status"`
		Duplicate bool   `json:"duplicate"`
	}{
		ReceiptID: acceptance.ReceiptID,
		Status:    "accepted",
		Duplicate: acceptance.Duplicate,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(response)
	h.record("webhook", "accepted", http.StatusAccepted, eventType)
}

func validContentEncoding(values []string) bool {
	return len(values) == 0 || (len(values) == 1 && strings.EqualFold(values[0], "identity"))
}

func validContentType(values []string) bool {
	if len(values) != 1 {
		return false
	}
	mediaType, params, err := mime.ParseMediaType(values[0])
	if err != nil || !strings.EqualFold(mediaType, "application/json") {
		return false
	}
	if len(params) == 0 {
		return true
	}
	charset, ok := params["charset"]
	return len(params) == 1 && ok && strings.EqualFold(charset, "utf-8")
}

func (h *Handler) problem(w http.ResponseWriter, route, result string, status int, eventType string) {
	response := struct {
		Type   string `json:"type"`
		Title  string `json:"title"`
		Status int    `json:"status"`
		Code   string `json:"code"`
	}{
		Type:   "about:blank",
		Title:  "Request rejected",
		Status: status,
		Code:   result,
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(response)
	h.record(route, result, status, eventType)
}

func (h *Handler) record(route, result string, status int, eventType string) {
	h.metrics.increment(route, result)
	attributes := []any{
		"route", route,
		"result", result,
		"status", status,
	}
	if eventType != "" {
		attributes = append(attributes, "event_type", eventType)
	}
	h.logger.Info("http_request", attributes...)
}
