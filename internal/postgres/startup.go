package postgres

import (
	"context"
	"log/slog"
)

func Prepare(ctx context.Context, databaseURL string, logger *slog.Logger) (Pool, error) {
	config, err := ParsePoolConfig(databaseURL)
	if err != nil {
		return nil, err
	}
	if logger != nil {
		logger.Info("database_connecting")
	}
	pool, err := Open(ctx, config)
	if err != nil {
		return nil, err
	}
	if logger != nil {
		logger.Info("database_connected_read_write")
	}

	runner := NewRunner(NewPGBackend(pool), EmbeddedMigrations(), logger)
	if err := runner.Run(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return pool, nil
}
