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

	migrations := EmbeddedMigrations()
	if len(migrations) != 2 {
		t.Fatal("embedded migration count 不满足 version 2 integration 前置条件")
	}
	currentVersion := integrationSchemaVersion(t, ctx, pool)
	if currentVersion == 0 {
		if err := NewRunner(NewPGBackend(pool), migrations[:1], nil).Run(ctx); err != nil {
			t.Fatalf("version 1 schema preparation 失败: %v", err)
		}
		currentVersion = 1
	}
	if currentVersion != 1 && currentVersion != 2 {
		t.Fatal("专用 PostgreSQL 测试 schema 不是 version 1 或 version 2")
	}

	before := integrationMigrationTimes(t, ctx, pool)
	if currentVersion == 1 {
		for _, table := range securityStateTables {
			if integrationTableExists(t, ctx, pool, table) {
				t.Fatal("version 1 baseline 意外包含 security-state table")
			}
		}
	}

	runner := NewRunner(NewPGBackend(pool), migrations, nil)
	if err := runner.Run(ctx); err != nil {
		t.Fatalf("version 1 到 version 2 forward schema preparation 失败: %v", err)
	}
	afterForward := integrationMigrationTimes(t, ctx, pool)
	if len(afterForward) != 2 {
		t.Fatalf("migration metadata row count = %d, want 2", len(afterForward))
	}
	if firstApplied, ok := before[1]; !ok || !firstApplied.Equal(afterForward[1]) {
		t.Fatal("version 1 migration metadata 被 forward migration 改写")
	}
	if currentVersion == 2 {
		if secondApplied, ok := before[2]; !ok || !secondApplied.Equal(afterForward[2]) {
			t.Fatal("existing version 2 migration metadata 被重写")
		}
	}

	rowCounts := integrationSecurityStateRowCounts(t, ctx, pool)
	for _, table := range securityStateTables {
		if !integrationTableExists(t, ctx, pool, table) {
			t.Fatal("security-state table 缺失")
		}
		if count := rowCounts[table]; count != 0 {
			t.Fatalf("security-state migration seeded row count = %d, want 0", count)
		}
	}
	if integrationSensitiveColumnExists(t, ctx, pool) {
		t.Fatal("security-state schema 包含 raw-token 或 authentication-secret column")
	}

	if err := runner.Run(ctx); err != nil {
		t.Fatalf("重复 version 2 schema preparation 失败: %v", err)
	}
	afterRepeat := integrationMigrationTimes(t, ctx, pool)
	if len(afterRepeat) != 2 || !afterRepeat[1].Equal(afterForward[1]) || !afterRepeat[2].Equal(afterForward[2]) {
		t.Fatal("current version 2 schema metadata 被意外重写")
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

var securityStateTables = []string{
	"gateway_security_realm",
	"core_principals",
	"core_credential_slots",
	"core_authentication_credentials",
	"authentication_replay_reservations",
	"gateway_destinations",
	"gateway_destination_tokens",
}

func integrationSchemaVersion(t *testing.T, ctx context.Context, pool *pgxpool.Pool) int64 {
	t.Helper()
	var tableName *string
	if err := pool.QueryRow(ctx, "select to_regclass('gateway_schema_migrations')::text").Scan(&tableName); err != nil {
		t.Fatal("读取 migration metadata table 状态失败")
	}
	if tableName == nil {
		return 0
	}
	var version int64
	if err := pool.QueryRow(ctx, "select coalesce(max(migration_version), 0) from gateway_schema_migrations").Scan(&version); err != nil {
		t.Fatal("读取 application schema version 失败")
	}
	return version
}

func integrationMigrationTimes(t *testing.T, ctx context.Context, pool *pgxpool.Pool) map[int64]time.Time {
	t.Helper()
	rows, err := pool.Query(ctx, "select migration_version, applied_at from gateway_schema_migrations order by migration_version")
	if err != nil {
		t.Fatal("读取 migration metadata rows 失败")
	}
	defer rows.Close()
	result := make(map[int64]time.Time)
	for rows.Next() {
		var version int64
		var appliedAt time.Time
		if err := rows.Scan(&version, &appliedAt); err != nil {
			t.Fatal("读取 migration metadata row 失败")
		}
		result[version] = appliedAt
	}
	if rows.Err() != nil {
		t.Fatal("遍历 migration metadata rows 失败")
	}
	return result
}

func integrationTableExists(t *testing.T, ctx context.Context, pool *pgxpool.Pool, table string) bool {
	t.Helper()
	var exists bool
	if err := pool.QueryRow(ctx, "select to_regclass($1) is not null", table).Scan(&exists); err != nil {
		t.Fatal("检查 application table 失败")
	}
	return exists
}

func integrationSecurityStateRowCounts(t *testing.T, ctx context.Context, pool *pgxpool.Pool) map[string]int64 {
	t.Helper()
	rows, err := pool.Query(ctx, `
		select 'gateway_security_realm', count(*) from gateway_security_realm
		union all select 'core_principals', count(*) from core_principals
		union all select 'core_credential_slots', count(*) from core_credential_slots
		union all select 'core_authentication_credentials', count(*) from core_authentication_credentials
		union all select 'authentication_replay_reservations', count(*) from authentication_replay_reservations
		union all select 'gateway_destinations', count(*) from gateway_destinations
		union all select 'gateway_destination_tokens', count(*) from gateway_destination_tokens
	`)
	if err != nil {
		t.Fatal("读取 security-state table row counts 失败")
	}
	defer rows.Close()
	result := make(map[string]int64)
	for rows.Next() {
		var table string
		var count int64
		if err := rows.Scan(&table, &count); err != nil {
			t.Fatal("读取 security-state table row count 失败")
		}
		result[table] = count
	}
	if rows.Err() != nil || len(result) != len(securityStateTables) {
		t.Fatal("security-state table row count result 不完整")
	}
	return result
}

func integrationSensitiveColumnExists(t *testing.T, ctx context.Context, pool *pgxpool.Pool) bool {
	t.Helper()
	var exists bool
	if err := pool.QueryRow(ctx, `
		select exists (
			select 1
			from information_schema.columns
			where table_schema = current_schema()
			  and table_name = any($1)
			  and lower(column_name) = any($2)
		)
	`, securityStateTables, []string{"raw_token", "authentication_secret", "hmac_secret"}).Scan(&exists); err != nil {
		t.Fatal("检查 security-state sensitive columns 失败")
	}
	return exists
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
