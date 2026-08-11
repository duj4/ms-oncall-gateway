package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	migrationAdvisoryLockKey int64 = 0x4d534f4e43414c4c // ASCII "MSONCALL"
	lockCleanupTimeout             = 5 * time.Second
	migrationRollbackTimeout       = 5 * time.Second
)

type PGBackend struct {
	pool Pool
}

func NewPGBackend(pool Pool) *PGBackend {
	return &PGBackend{pool: pool}
}

func (b *PGBackend) WithMigrationLock(ctx context.Context, run func(MigrationSession) error) error {
	connection, err := b.pool.Acquire(ctx)
	if err != nil {
		return safeError(ErrMigrationLock, "lock connection")
	}

	if _, err := connection.Exec(ctx, "select pg_advisory_lock($1)", migrationAdvisoryLockKey); err != nil {
		destroyPoolConnection(connection)
		return safeError(ErrMigrationLock, "lock acquisition")
	}

	runErr := run(&pgSession{connection: connection})
	return finishMigrationConnection(
		runErr,
		func(cleanupCtx context.Context) (bool, error) {
			var unlocked bool
			err := connection.QueryRow(cleanupCtx, "select pg_advisory_unlock($1)", migrationAdvisoryLockKey).Scan(&unlocked)
			return unlocked, err
		},
		connection.Release,
		func() { destroyPoolConnection(connection) },
	)
}

func finishMigrationConnection(
	runErr error,
	unlock func(context.Context) (bool, error),
	release func(),
	destroy func(),
) error {
	// An interrupted migration, including an unconfirmed rollback, makes the
	// connection unsafe to reuse. Hijacking it also guarantees that a
	// session-level advisory lock cannot return to the pool.
	if errors.Is(runErr, ErrMigrationInterrupted) {
		destroy()
		return runErr
	}

	cleanupCtx, cancel := context.WithTimeout(context.Background(), lockCleanupTimeout)
	defer cancel()
	unlocked, unlockErr := unlock(cleanupCtx)
	if unlockErr != nil || !unlocked {
		destroy()
		if runErr != nil {
			return runErr
		}
		return safeError(ErrMigrationLock, "lock release")
	}
	release()
	return runErr
}

func destroyPoolConnection(connection *pgxpool.Conn) {
	ctx, cancel := context.WithTimeout(context.Background(), lockCleanupTimeout)
	defer cancel()
	underlying := connection.Hijack()
	_ = underlying.Close(ctx)
}

type pgSession struct {
	connection *pgxpool.Conn
}

func (s *pgSession) Inspect(ctx context.Context, migrations []Migration) (Inspection, error) {
	return NewInspector(&pgMetadataSource{queryer: s.connection}, migrations).Inspect(ctx)
}

func (s *pgSession) Apply(ctx context.Context, migration Migration) error {
	return applyMigration(ctx, migration, func(ctx context.Context) (migrationTransaction, error) {
		return s.connection.Begin(ctx)
	})
}

type migrationTransaction interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	Commit(context.Context) error
	Rollback(context.Context) error
}

func applyMigration(
	ctx context.Context,
	migration Migration,
	begin func(context.Context) (migrationTransaction, error),
) error {
	return applyMigrationWithRollbackTimeout(ctx, migration, migrationRollbackTimeout, begin)
}

func applyMigrationWithRollbackTimeout(
	ctx context.Context,
	migration Migration,
	rollbackTimeout time.Duration,
	begin func(context.Context) (migrationTransaction, error),
) (resultErr error) {
	transaction, err := begin(ctx)
	if err != nil {
		return migrationFailure(err, "transaction begin")
	}
	transactionOpen := true
	defer func() {
		if !transactionOpen {
			return
		}
		rollbackCtx, cancel := boundedCleanupContext(ctx, rollbackTimeout)
		rollbackErr := transaction.Rollback(rollbackCtx)
		cancel()
		if rollbackErr != nil && !errors.Is(rollbackErr, pgx.ErrTxClosed) {
			// The transaction state cannot be confirmed. Replace the original
			// failure with a safe interruption classification so the owning
			// migration connection is destroyed rather than pooled.
			resultErr = safeError(ErrMigrationInterrupted, "transaction cleanup")
		}
	}()

	if _, err := transaction.Exec(ctx, migration.SQL, pgx.QueryExecModeSimpleProtocol); err != nil {
		return migrationFailure(err, "migration execution")
	}
	if _, err := transaction.Exec(ctx, `
		insert into gateway_schema_migrations (migration_version, migration_checksum)
		values ($1, $2)
	`, migration.Version, migration.Checksum); err != nil {
		return migrationFailure(err, "migration record")
	}
	if err := transaction.Commit(ctx); err != nil {
		return migrationFailure(err, "transaction commit")
	}
	transactionOpen = false
	return nil
}

func boundedCleanupContext(parent context.Context, limit time.Duration) (context.Context, context.CancelFunc) {
	deadline := time.Now().Add(limit)
	if parentDeadline, ok := parent.Deadline(); ok && parentDeadline.Before(deadline) {
		deadline = parentDeadline
	}
	// Preserve values but deliberately detach cancellation: cleanup remains
	// possible after an early cancel while retaining the earlier of the parent
	// deadline and the finite local cap.
	return context.WithDeadline(context.WithoutCancel(parent), deadline)
}

type pgQueryer interface {
	QueryRow(context.Context, string, ...any) pgx.Row
	Query(context.Context, string, ...any) (pgx.Rows, error)
}

type pgMetadataSource struct {
	queryer pgQueryer
}

func (s *pgMetadataSource) Snapshot(ctx context.Context) (MetadataSnapshot, error) {
	var exists bool
	if err := s.queryer.QueryRow(ctx, "select to_regclass('gateway_schema_migrations') is not null").Scan(&exists); err != nil {
		return MetadataSnapshot{}, err
	}
	if !exists {
		return MetadataSnapshot{TableExists: false}, nil
	}

	complete, err := s.metadataColumnsComplete(ctx)
	if err != nil {
		return MetadataSnapshot{}, err
	}
	if !complete {
		return MetadataSnapshot{TableExists: true, Complete: false}, nil
	}

	rows, err := s.queryer.Query(ctx, `
		select migration_version, migration_checksum, applied_at
		from gateway_schema_migrations
		order by migration_version
	`)
	if err != nil {
		return MetadataSnapshot{}, err
	}
	defer rows.Close()

	var applied []AppliedMigration
	for rows.Next() {
		var record AppliedMigration
		if err := rows.Scan(&record.Version, &record.Checksum, &record.AppliedAt); err != nil {
			return MetadataSnapshot{TableExists: true, Complete: false}, nil
		}
		applied = append(applied, record)
	}
	if err := rows.Err(); err != nil {
		return MetadataSnapshot{}, err
	}
	return MetadataSnapshot{TableExists: true, Complete: true, Applied: applied}, nil
}

func (s *pgMetadataSource) metadataColumnsComplete(ctx context.Context) (bool, error) {
	rows, err := s.queryer.Query(ctx, `
		select column_name, data_type, is_nullable
		from information_schema.columns
		where table_schema = current_schema()
		  and table_name = 'gateway_schema_migrations'
	`)
	if err != nil {
		return false, err
	}
	defer rows.Close()

	expected := map[string]string{
		"migration_version":  "bigint",
		"migration_checksum": "text",
		"applied_at":         "timestamp with time zone",
	}
	seen := make(map[string]bool, len(expected))
	for rows.Next() {
		var name, dataType, nullable string
		if err := rows.Scan(&name, &dataType, &nullable); err != nil {
			return false, nil
		}
		if requiredType, ok := expected[name]; ok && dataType == requiredType && nullable == "NO" {
			seen[name] = true
		}
	}
	if err := rows.Err(); err != nil {
		return false, err
	}
	for name := range expected {
		if !seen[name] {
			return false, nil
		}
	}
	return true, nil
}
