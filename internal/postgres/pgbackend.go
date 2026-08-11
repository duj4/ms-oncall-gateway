package postgres

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	migrationAdvisoryLockKey int64 = 0x4d534f4e43414c4c // ASCII "MSONCALL"
	lockCleanupTimeout             = 5 * time.Second
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
	cleanupCtx, cancel := context.WithTimeout(context.Background(), lockCleanupTimeout)
	defer cancel()
	var unlocked bool
	unlockErr := connection.QueryRow(cleanupCtx, "select pg_advisory_unlock($1)", migrationAdvisoryLockKey).Scan(&unlocked)
	if unlockErr != nil || !unlocked {
		destroyPoolConnection(connection)
		if runErr != nil {
			return runErr
		}
		return safeError(ErrMigrationLock, "lock release")
	}
	connection.Release()
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
	transaction, err := begin(ctx)
	if err != nil {
		return safeError(ErrMigration, "transaction begin")
	}
	defer func() { _ = transaction.Rollback(context.Background()) }()

	if _, err := transaction.Exec(ctx, migration.SQL, pgx.QueryExecModeSimpleProtocol); err != nil {
		return safeError(ErrMigration, "migration execution")
	}
	if _, err := transaction.Exec(ctx, `
		insert into gateway_schema_migrations (migration_version, migration_checksum)
		values ($1, $2)
	`, migration.Version, migration.Checksum); err != nil {
		return safeError(ErrMigration, "migration record")
	}
	if err := transaction.Commit(ctx); err != nil {
		return safeError(ErrMigration, "transaction commit")
	}
	return nil
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
