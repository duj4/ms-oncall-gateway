package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/duj4/ms-oncall-gateway/internal/httpapi"
	"github.com/duj4/ms-oncall-gateway/internal/postgres"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	shutdownSignal, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(shutdownSignal, logger, os.Getenv, postgres.Prepare, serveHTTP); err != nil {
		logger.Error("gateway_failed", "reason", failureReason(err))
		os.Exit(1)
	}
}

type prepareDatabaseFunc func(context.Context, string, *slog.Logger) (postgres.Pool, error)
type serveHTTPFunc func(context.Context, string, *slog.Logger) error

func run(
	ctx context.Context,
	logger *slog.Logger,
	getenv func(string) string,
	prepare prepareDatabaseFunc,
	serve serveHTTPFunc,
) error {
	databaseURL := getenv(postgres.DatabaseURLEnv)
	startupTimeout, err := postgres.ParseStartupTimeout(getenv(postgres.DatabaseStartupTimeoutEnv))
	if err != nil {
		return err
	}
	startupCtx, cancel := context.WithTimeout(ctx, startupTimeout)
	database, err := prepare(startupCtx, databaseURL, logger)
	cancel()
	if err != nil {
		return err
	}
	defer database.Close()

	address := getenv("MS_ONCALL_GATEWAY_LISTEN_ADDR")
	if address == "" {
		address = httpapi.DefaultListenAddress
	}
	return serve(ctx, address, logger)
}

func serveHTTP(ctx context.Context, address string, logger *slog.Logger) error {
	handler := httpapi.NewHandler(httpapi.UnavailableSink{}, logger)
	server := httpapi.NewServer(address, handler)

	serverError := make(chan error, 1)
	go func() {
		logger.Info("server_starting")
		serverError <- server.ListenAndServe()
	}()

	select {
	case err := <-serverError:
		if !errors.Is(err, http.ErrServerClosed) {
			return errors.New("http server failed")
		}
		return nil
	case <-ctx.Done():
		logger.Info("server_stopping")
		shutdownContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownContext); err != nil {
			return errors.New("http server shutdown failed")
		}
		if err := <-serverError; !errors.Is(err, http.ErrServerClosed) {
			return errors.New("http server failed")
		}
		return nil
	}
}

func failureReason(err error) string {
	switch {
	case errors.Is(err, postgres.ErrConfigMissing):
		return "database_configuration_missing"
	case errors.Is(err, postgres.ErrConfigInvalid):
		return "database_configuration_invalid"
	case errors.Is(err, postgres.ErrConnect):
		return "database_unavailable"
	case errors.Is(err, postgres.ErrMigrationLock):
		return "database_migration_lock_failed"
	case errors.Is(err, postgres.ErrSchemaAhead):
		return "database_schema_ahead"
	case errors.Is(err, postgres.ErrSchemaInvalid):
		return "database_schema_invalid"
	case errors.Is(err, postgres.ErrSchemaQuery):
		return "database_schema_query_failed"
	case errors.Is(err, postgres.ErrMigration):
		return "database_migration_failed"
	default:
		return "runtime_failed"
	}
}
