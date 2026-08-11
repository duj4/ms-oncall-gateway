package postgres

import "errors"

var (
	ErrConfigMissing = errors.New("database configuration missing")
	ErrConfigInvalid = errors.New("database configuration invalid")
	ErrConnect       = errors.New("database connection unavailable")
	ErrSchemaQuery   = errors.New("database schema query failed")
	ErrMigrationLock = errors.New("database migration lock failed")
	ErrMigration     = errors.New("database migration failed")
	ErrSchemaAhead   = errors.New("database schema is ahead")
	ErrSchemaInvalid = errors.New("database schema is invalid")
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
