package postgres

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"
)

var (
	ErrConfigMissing = errors.New("database configuration missing")
	ErrConfigInvalid = errors.New("database configuration invalid")
	ErrConnect       = errors.New("database connection unavailable")
	ErrSchemaQuery   = errors.New("database schema query failed")
	ErrMigrationLock = errors.New("database migration lock failed")
	ErrMigration     = errors.New("database migration failed")
	// ErrMigrationInterrupted is intentionally more specific than
	// ErrMigration, so callers can fail closed on an unknown execution result.
	ErrMigrationInterrupted           = fmt.Errorf("%w: interrupted", ErrMigration)
	ErrSchemaAhead                    = errors.New("database schema is ahead")
	ErrSchemaInvalid                  = errors.New("database schema is invalid")
	ErrAuthenticationStateUnavailable = errors.New("database authentication state unavailable")
	ErrAuthenticationStateIntegrity   = errors.New("database authentication state invalid")
)

// SafeError deliberately retains only bounded, non-sensitive diagnostic data.
// PostgreSQL driver errors are not exposed because they can contain connection
// parameters, host names, user names, or certificate paths.
type SafeError struct {
	Kind      error
	Operation string
}

func (e *SafeError) Error() string {
	return "postgres " + e.Operation + " failed"
}

func (e *SafeError) Unwrap() error {
	return e.Kind
}

func safeError(kind error, operation string) error {
	return &SafeError{Kind: kind, Operation: operation}
}

func migrationFailure(err error, operation string) error {
	if isMigrationInterruption(err) {
		return safeError(ErrMigrationInterrupted, operation)
	}
	return safeError(ErrMigration, operation)
}

func isMigrationInterruption(err error) bool {
	return isConnectionInterruption(err)
}

func isConnectionInterruption(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, io.ErrClosedPipe) || errors.Is(err, net.ErrClosed) ||
		pgconn.Timeout(err) {
		return true
	}

	var postgresError *pgconn.PgError
	if errors.As(err, &postgresError) {
		// SQLSTATE class 08 and server shutdown/crash states indicate a broken
		// session. 40003 explicitly means statement completion is unknown.
		// Ordinary SQL, DDL, permission, and constraint errors do not.
		return strings.HasPrefix(postgresError.Code, "08") ||
			postgresError.Code == "40003" ||
			postgresError.Code == "57P01" ||
			postgresError.Code == "57P02" ||
			postgresError.Code == "57P03" ||
			postgresError.Code == "57P04" ||
			postgresError.Code == "57P05"
	}

	var connectError *pgconn.ConnectError
	if errors.As(err, &connectError) {
		return true
	}
	var networkError net.Error
	return errors.As(err, &networkError)
}
