package postgres

import (
	"context"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

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

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool := openIntegrationPool(t, ctx, databaseURL)
	defer pool.Close()
	verifyIntegrationSession(t, ctx, pool, databaseURL)

	runner := NewRunner(NewPGBackend(pool), EmbeddedMigrations(), nil)
	if err := runner.Run(ctx); err != nil {
		t.Fatalf("首次 schema preparation 失败: %v", err)
	}
	var firstApplied time.Time
	if err := pool.QueryRow(ctx, "select applied_at from gateway_schema_migrations where migration_version = 1").Scan(&firstApplied); err != nil {
		t.Fatal("读取 migration metadata 失败")
	}
	if err := runner.Run(ctx); err != nil {
		t.Fatalf("重复 schema preparation 失败: %v", err)
	}
	var secondApplied time.Time
	if err := pool.QueryRow(ctx, "select applied_at from gateway_schema_migrations where migration_version = 1").Scan(&secondApplied); err != nil {
		t.Fatal("读取重复 migration metadata 失败")
	}
	if !firstApplied.Equal(secondApplied) {
		t.Fatal("current schema 被意外重写")
	}

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
			t.Errorf("并发 current-schema inspection 失败: %v", err)
		}
	}
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

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool := openIntegrationPool(t, ctx, databaseURL)
	defer pool.Close()
	verifyIntegrationSession(t, ctx, pool, databaseURL)
	if err := NewRunner(NewPGBackend(pool), EmbeddedMigrations(), nil).Run(ctx); err != nil {
		t.Fatalf("HA/DR logical pool migration: %v", err)
	}
}

func openIntegrationPool(t *testing.T, ctx context.Context, databaseURL string) *pgxpool.Pool {
	t.Helper()
	validateIntegrationTarget(t, databaseURL)
	config, err := ParsePoolConfig(databaseURL)
	if err != nil {
		t.Fatalf("解析专用测试数据库配置失败: %v", err)
	}
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal("连接专用测试数据库失败")
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		t.Fatal("专用测试数据库不可用")
	}
	return pool
}

func validateIntegrationTarget(t *testing.T, databaseURL string) {
	t.Helper()
	parsed, err := url.Parse(databaseURL)
	if err != nil || parsed.Scheme != "postgresql" || parsed.Host == "" || parsed.User == nil || parsed.User.Username() == "" {
		t.Fatal("专用 PostgreSQL 测试 URL 不满足安全策略")
	}
	if strings.TrimPrefix(parsed.Path, "/") == "" {
		t.Fatal("专用 PostgreSQL 测试 database 缺失")
	}
	query := parsed.Query()
	if query.Get("sslmode") != requiredSSLMode || query.Get("target_session_attrs") != requiredTargetSessionAttrs {
		t.Fatal("专用 PostgreSQL 测试必须使用 verify-full 和 read-write target")
	}
	for _, parameter := range []string{"sslrootcert", "sslcert", "sslkey"} {
		values, ok := query[parameter]
		if !ok || len(values) != 1 || !filepath.IsAbs(values[0]) {
			t.Fatal("专用 PostgreSQL 测试证书路径配置无效")
		}
		if _, err := os.Stat(values[0]); err != nil {
			t.Fatal("专用 PostgreSQL 测试证书文件不可读")
		}
	}
	keyInfo, err := os.Stat(query.Get("sslkey"))
	if err != nil || keyInfo.Mode().Perm()&0o077 != 0 {
		t.Fatal("专用 PostgreSQL 测试私钥权限不安全")
	}
}

func verifyIntegrationSession(t *testing.T, ctx context.Context, pool *pgxpool.Pool, databaseURL string) {
	t.Helper()
	parsed, err := url.Parse(databaseURL)
	if err != nil {
		t.Fatal("专用 PostgreSQL 测试 URL 无法复核")
	}
	expectedDatabase := strings.TrimPrefix(parsed.Path, "/")
	expectedUser := parsed.User.Username()
	var (
		currentUser     string
		currentDatabase string
		inRecovery      bool
		secureSession   bool
	)
	if err := pool.QueryRow(ctx, `
		select
			current_user,
			current_database(),
			pg_is_in_recovery(),
			coalesce((
				select ssl and client_dn is not null
				from pg_stat_ssl
				where pid = pg_backend_pid()
			), false)
	`).Scan(&currentUser, &currentDatabase, &inRecovery, &secureSession); err != nil {
		t.Fatal("专用 PostgreSQL session 安全检查失败")
	}
	if currentUser != expectedUser || currentDatabase != expectedDatabase || inRecovery || !secureSession {
		t.Fatal("专用 PostgreSQL session 不满足 user/database/read-write/mTLS 策略")
	}
}
