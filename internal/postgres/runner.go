package postgres

import (
	"context"
	"io"
	"log/slog"
)

type MigrationSession interface {
	Inspect(context.Context, []Migration) (Inspection, error)
	Apply(context.Context, Migration) error
}

type MigrationLocker interface {
	WithMigrationLock(context.Context, func(MigrationSession) error) error
}

type Runner struct {
	locker     MigrationLocker
	migrations []Migration
	logger     *slog.Logger
}

func NewRunner(locker MigrationLocker, migrations []Migration, logger *slog.Logger) *Runner {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Runner{locker: locker, migrations: append([]Migration(nil), migrations...), logger: logger}
}

func (r *Runner) Run(ctx context.Context) error {
	return r.locker.WithMigrationLock(ctx, func(session MigrationSession) error {
		inspection, err := session.Inspect(ctx, r.migrations)
		if err != nil {
			return err
		}
		r.logger.Info("database_schema_inspected", "status", inspection.Status, "version", inspection.CurrentVersion)

		switch inspection.Status {
		case SchemaAhead:
			return safeError(ErrSchemaAhead, "schema compatibility")
		case SchemaInvalid:
			return safeError(ErrSchemaInvalid, "schema compatibility")
		case SchemaQueryError:
			return safeError(ErrSchemaQuery, "schema inspection")
		case SchemaCurrent, SchemaBehind, SchemaUninitialized:
		default:
			return safeError(ErrSchemaInvalid, "schema compatibility")
		}

		for inspection.CurrentVersion < int64(len(r.migrations)) {
			next := r.migrations[inspection.CurrentVersion]
			r.logger.Info("database_migration_starting", "version", next.Version)
			if err := session.Apply(ctx, next); err != nil {
				return err
			}
			r.logger.Info("database_migration_applied", "version", next.Version)

			inspection, err = session.Inspect(ctx, r.migrations)
			if err != nil {
				return err
			}
			if inspection.CurrentVersion != next.Version || (inspection.Status != SchemaBehind && inspection.Status != SchemaCurrent) {
				return safeError(ErrSchemaInvalid, "post-migration verification")
			}
		}

		finalInspection, err := session.Inspect(ctx, r.migrations)
		if err != nil {
			return err
		}
		if finalInspection.Status != SchemaCurrent || finalInspection.CurrentVersion != int64(len(r.migrations)) {
			return safeError(ErrSchemaInvalid, "final schema verification")
		}
		r.logger.Info("database_schema_current", "version", finalInspection.CurrentVersion)
		return nil
	})
}
