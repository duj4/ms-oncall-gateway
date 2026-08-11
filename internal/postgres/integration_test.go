package postgres

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	postgresIntegrationEnableEnv = "MS_ONCALL_GATEWAY_TEST_POSTGRES_ENABLE"
	postgresIntegrationURLEnv    = "MS_ONCALL_GATEWAY_TEST_DATABASE_URL"
	haIntegrationEnableEnv       = "MS_ONCALL_GATEWAY_TEST_HA_ENABLE"
	haIntegrationURLEnv          = "MS_ONCALL_GATEWAY_TEST_HA_DATABASE_URL"
)

func TestPostgresMigrationIntegration(t *testing.T) {
	if os.Getenv(postgresIntegrationEnableEnv) != "1" {
		t.Skip("因未配置专用 PostgreSQL 测试数据库而跳过")
	}
	databaseURL := os.Getenv(postgresIntegrationURLEnv)
	if databaseURL == "" {
		t.Fatal("专用 PostgreSQL 测试已启用，但测试数据库配置缺失")
	}

	t.Run("first initialization and repeated no-op", func(t *testing.T) {
		withTestSchema(t, databaseURL, func(ctx context.Context, pool *pgxpool.Pool) {
			runner := NewRunner(NewPGBackend(pool), EmbeddedMigrations(), nil)
			if err := runner.Run(ctx); err != nil {
				t.Fatalf("first migration run: %v", err)
			}
			var firstApplied time.Time
			if err := pool.QueryRow(ctx, "select applied_at from gateway_schema_migrations where migration_version = 1").Scan(&firstApplied); err != nil {
				t.Fatal("read first migration metadata")
			}
			if err := runner.Run(ctx); err != nil {
				t.Fatalf("repeated migration run: %v", err)
			}
			var secondApplied time.Time
			if err := pool.QueryRow(ctx, "select applied_at from gateway_schema_migrations where migration_version = 1").Scan(&secondApplied); err != nil {
				t.Fatal("read repeated migration metadata")
			}
			if !firstApplied.Equal(secondApplied) {
				t.Error("current schema was unexpectedly rewritten")
			}
		})
	})

	t.Run("legal forward upgrade", func(t *testing.T) {
		withTestSchema(t, databaseURL, func(ctx context.Context, pool *pgxpool.Pool) {
			first := EmbeddedMigrations()
			if err := NewRunner(NewPGBackend(pool), first, nil).Run(ctx); err != nil {
				t.Fatalf("initial migration: %v", err)
			}
			second := testMigration(2, "000002_integration_upgrade.sql", "alter table durable_acceptances add column integration_marker text")
			if err := NewRunner(NewPGBackend(pool), append(first, second), nil).Run(ctx); err != nil {
				t.Fatalf("forward migration: %v", err)
			}
			var version int64
			if err := pool.QueryRow(ctx, "select max(migration_version) from gateway_schema_migrations").Scan(&version); err != nil || version != 2 {
				t.Errorf("schema version = %d, error = %v", version, err)
			}
		})
	})

	t.Run("concurrent runners serialize", func(t *testing.T) {
		withTestSchema(t, databaseURL, func(ctx context.Context, pool *pgxpool.Pool) {
			var wait sync.WaitGroup
			errorsFound := make(chan error, 2)
			wait.Add(2)
			for range 2 {
				go func() {
					defer wait.Done()
					errorsFound <- NewRunner(NewPGBackend(pool), EmbeddedMigrations(), nil).Run(ctx)
				}()
			}
			wait.Wait()
			close(errorsFound)
			for err := range errorsFound {
				if err != nil {
					t.Errorf("concurrent runner: %v", err)
				}
			}
			var count int
			if err := pool.QueryRow(ctx, "select count(*) from gateway_schema_migrations").Scan(&count); err != nil || count != 1 {
				t.Errorf("migration record count = %d, error = %v", count, err)
			}
		})
	})

	t.Run("failed migration rolls back", func(t *testing.T) {
		withTestSchema(t, databaseURL, func(ctx context.Context, pool *pgxpool.Pool) {
			first := EmbeddedMigrations()
			if err := NewRunner(NewPGBackend(pool), first, nil).Run(ctx); err != nil {
				t.Fatalf("initial migration: %v", err)
			}
			failed := testMigration(2, "000002_integration_failure.sql", "create table rollback_probe (id bigint); select 1 / 0")
			err := NewRunner(NewPGBackend(pool), append(first, failed), nil).Run(ctx)
			if !errors.Is(err, ErrMigration) {
				t.Fatalf("failure = %v, want ErrMigration", err)
			}
			var version int64
			if err := pool.QueryRow(ctx, "select max(migration_version) from gateway_schema_migrations").Scan(&version); err != nil || version != 1 {
				t.Errorf("schema version after failure = %d, error = %v", version, err)
			}
			var probeExists bool
			if err := pool.QueryRow(ctx, "select to_regclass('rollback_probe') is not null").Scan(&probeExists); err != nil || probeExists {
				t.Errorf("rollback probe exists = %t, error = %v", probeExists, err)
			}
		})
	})
}

func TestPostgresMultiInstanceHAIntegration(t *testing.T) {
	if os.Getenv(haIntegrationEnableEnv) != "1" {
		t.Skip("因未配置专用 PostgreSQL multi-instance HA/DR 测试集群而跳过")
	}
	databaseURL := os.Getenv(haIntegrationURLEnv)
	if databaseURL == "" {
		t.Fatal("专用 PostgreSQL HA/DR 测试已启用，但 multi-host 测试配置缺失")
	}
	config, err := ParsePoolConfig(databaseURL)
	if err != nil {
		t.Fatalf("解析专用 HA/DR 测试配置失败: %v", err)
	}
	if len(config.ConnConfig.Fallbacks) == 0 {
		t.Fatal("HA/DR 测试配置必须包含多个 instance")
	}
	withTestSchema(t, databaseURL, func(ctx context.Context, pool *pgxpool.Pool) {
		if err := NewRunner(NewPGBackend(pool), EmbeddedMigrations(), nil).Run(ctx); err != nil {
			t.Fatalf("HA/DR logical pool migration: %v", err)
		}
	})
}

func withTestSchema(t *testing.T, databaseURL string, run func(context.Context, *pgxpool.Pool)) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	baseConfig, err := ParsePoolConfig(databaseURL)
	if err != nil {
		t.Fatalf("解析专用测试数据库配置失败: %v", err)
	}
	basePool, err := pgxpool.NewWithConfig(ctx, baseConfig)
	if err != nil {
		t.Fatal("连接专用测试数据库失败")
	}
	if err := basePool.Ping(ctx); err != nil {
		basePool.Close()
		t.Fatal("专用测试数据库不可用")
	}

	schema := randomTestSchema(t)
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := basePool.Exec(ctx, "create schema "+identifier); err != nil {
		basePool.Close()
		t.Fatal("创建隔离测试 schema 失败")
	}
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		_, _ = basePool.Exec(cleanupCtx, "drop schema "+identifier+" cascade")
		basePool.Close()
	}()

	testConfig := baseConfig.Copy()
	testConfig.ConnConfig.RuntimeParams["search_path"] = schema
	testPool, err := pgxpool.NewWithConfig(ctx, testConfig)
	if err != nil {
		t.Fatal("创建隔离测试连接池失败")
	}
	defer testPool.Close()
	if err := testPool.Ping(ctx); err != nil {
		t.Fatal("隔离测试 schema 不可用")
	}
	run(ctx, testPool)
}

func randomTestSchema(t *testing.T) string {
	t.Helper()
	random := make([]byte, 8)
	if _, err := rand.Read(random); err != nil {
		t.Fatal("生成测试 schema 标识失败")
	}
	return "gateway_migration_test_" + hex.EncodeToString(random)
}

func testMigration(version int64, name, sql string) Migration {
	digest := sha256.Sum256([]byte(sql))
	return Migration{Version: version, Name: name, SQL: sql, Checksum: hex.EncodeToString(digest[:])}
}
