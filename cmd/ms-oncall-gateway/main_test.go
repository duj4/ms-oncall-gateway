package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/duj4/ms-oncall-gateway/internal/httpapi"
	"github.com/duj4/ms-oncall-gateway/internal/postgres"
	"github.com/jackc/pgx/v5/pgxpool"
)

type mainTestPool struct {
	closed bool
}

func (*mainTestPool) Ping(context.Context) error { return nil }
func (*mainTestPool) Acquire(context.Context) (*pgxpool.Conn, error) {
	return nil, errors.New("not used")
}
func (p *mainTestPool) Close() { p.closed = true }

func testEnvironment(values map[string]string) func(string) string {
	return func(name string) string { return values[name] }
}

func TestRunFailsClosedBeforeListener(t *testing.T) {
	tests := []struct {
		name        string
		databaseURL string
		prepareErr  error
	}{
		{name: "missing database configuration", prepareErr: &postgres.SafeError{Kind: postgres.ErrConfigMissing, Operation: "configuration"}},
		{name: "database connection failure", databaseURL: "configured", prepareErr: &postgres.SafeError{Kind: postgres.ErrConnect, Operation: "connection"}},
		{name: "schema ahead", databaseURL: "configured", prepareErr: &postgres.SafeError{Kind: postgres.ErrSchemaAhead, Operation: "schema compatibility"}},
		{name: "schema invalid", databaseURL: "configured", prepareErr: &postgres.SafeError{Kind: postgres.ErrSchemaInvalid, Operation: "schema compatibility"}},
		{name: "migration interrupted", databaseURL: "configured", prepareErr: &postgres.SafeError{Kind: postgres.ErrMigrationInterrupted, Operation: "transaction cleanup"}},
		{name: "migration failure", databaseURL: "configured", prepareErr: &postgres.SafeError{Kind: postgres.ErrMigration, Operation: "migration execution"}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			prepareCalls := 0
			serveCalls := 0
			err := run(
				context.Background(),
				slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)),
				testEnvironment(map[string]string{postgres.DatabaseURLEnv: test.databaseURL}),
				func(context.Context, string, *slog.Logger) (postgres.Pool, error) {
					prepareCalls++
					return nil, test.prepareErr
				},
				func(context.Context, string, *slog.Logger) error {
					serveCalls++
					return nil
				},
			)
			if err == nil {
				t.Fatal("run succeeded, want failure")
			}
			if prepareCalls != 1 || serveCalls != 0 {
				t.Errorf("prepare calls = %d, serve calls = %d", prepareCalls, serveCalls)
			}
		})
	}
}

func TestRunStartsOnlyAfterSchemaPreparationAndKeepsUnavailableSink(t *testing.T) {
	var order []string
	pool := &mainTestPool{}
	err := run(
		context.Background(),
		slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)),
		testEnvironment(map[string]string{
			postgres.DatabaseURLEnv:         "configured",
			"MS_ONCALL_GATEWAY_LISTEN_ADDR": "127.0.0.1:0",
		}),
		func(context.Context, string, *slog.Logger) (postgres.Pool, error) {
			order = append(order, "database_current")
			return pool, nil
		},
		func(_ context.Context, address string, logger *slog.Logger) error {
			order = append(order, "listener")
			if address != "127.0.0.1:0" {
				t.Errorf("address = %q", address)
			}
			handler := httpapi.NewHandler(httpapi.UnavailableSink{}, logger)
			request := httptest.NewRequest(http.MethodPost, "/v1/goalert/contact-method/placeholder-token", strings.NewReader(`{"AppName":"MS OnCall","Type":"Test"}`))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Idempotency-Key", "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusServiceUnavailable {
				t.Errorf("runtime status = %d, want 503", response.Code)
			}
			if response.Code == http.StatusAccepted {
				t.Error("runtime returned prohibited 202")
			}
			return nil
		},
	)
	if err != nil {
		t.Fatalf("run returned error: %v", err)
	}
	if len(order) != 2 || order[0] != "database_current" || order[1] != "listener" {
		t.Errorf("startup order = %v", order)
	}
	if !pool.closed {
		t.Error("database pool was not closed")
	}
}

func TestFailureReasonIsBoundedAndRedacted(t *testing.T) {
	tests := []struct {
		err  error
		want string
	}{
		{err: &postgres.SafeError{Kind: postgres.ErrConfigMissing, Operation: "configuration"}, want: "database_configuration_missing"},
		{err: &postgres.SafeError{Kind: postgres.ErrConfigInvalid, Operation: "configuration"}, want: "database_configuration_invalid"},
		{err: &postgres.SafeError{Kind: postgres.ErrConnect, Operation: "connection"}, want: "database_unavailable"},
		{err: &postgres.SafeError{Kind: postgres.ErrMigrationLock, Operation: "lock"}, want: "database_migration_lock_failed"},
		{err: &postgres.SafeError{Kind: postgres.ErrSchemaAhead, Operation: "schema"}, want: "database_schema_ahead"},
		{err: &postgres.SafeError{Kind: postgres.ErrSchemaInvalid, Operation: "schema"}, want: "database_schema_invalid"},
		{err: &postgres.SafeError{Kind: postgres.ErrSchemaQuery, Operation: "schema"}, want: "database_schema_query_failed"},
		{err: &postgres.SafeError{Kind: postgres.ErrMigrationInterrupted, Operation: "private host and credential details"}, want: "database_migration_interrupted"},
		{err: &postgres.SafeError{Kind: postgres.ErrMigration, Operation: "migration"}, want: "database_migration_failed"},
		{err: errors.New("private host and credential details"), want: "runtime_failed"},
	}
	for _, test := range tests {
		if got := failureReason(test.err); got != test.want {
			t.Errorf("failureReason(%v) = %q, want %q", test.err, got, test.want)
		}
		if strings.Contains(failureReason(test.err), "private") {
			t.Error("failure reason leaked sensitive details")
		}
	}
}
