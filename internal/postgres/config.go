package postgres

import (
	"context"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	DatabaseURLEnv             = "MS_ONCALL_GATEWAY_DATABASE_URL"
	DatabaseStartupTimeoutEnv  = "MS_ONCALL_GATEWAY_DATABASE_STARTUP_TIMEOUT"
	DefaultConnectTimeout      = 5 * time.Second
	MaximumConnectTimeout      = 30 * time.Second
	DefaultStartupTimeout      = 2 * time.Minute
	MaximumStartupTimeout      = 10 * time.Minute
	requiredTargetSessionAttrs = "read-write"
	requiredSSLMode            = "verify-full"
)

// ParsePoolConfig delegates PostgreSQL and multi-host parsing to pgx. It only
// enforces Gateway-specific write-target, TLS, and timeout policy afterward.
func ParsePoolConfig(databaseURL string) (*pgxpool.Config, error) {
	if strings.TrimSpace(databaseURL) == "" {
		return nil, safeError(ErrConfigMissing, "configuration")
	}

	parsedURL, err := url.Parse(databaseURL)
	if err != nil || (parsedURL.Scheme != "postgres" && parsedURL.Scheme != "postgresql") || parsedURL.Host == "" {
		return nil, safeError(ErrConfigInvalid, "configuration")
	}
	query, err := url.ParseQuery(parsedURL.RawQuery)
	if err != nil {
		return nil, safeError(ErrConfigInvalid, "configuration")
	}
	if values, ok := query["target_session_attrs"]; ok && (len(values) != 1 || values[0] != requiredTargetSessionAttrs) {
		return nil, safeError(ErrConfigInvalid, "configuration")
	}
	if values := query["sslmode"]; len(values) != 1 || values[0] != requiredSSLMode {
		return nil, safeError(ErrConfigInvalid, "configuration")
	}

	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, safeError(ErrConfigInvalid, "configuration")
	}

	// Missing target_session_attrs defaults to "any" in libpq/pgx. Gateway is
	// write-only, so override that default without changing host/TLS fallbacks.
	config.ConnConfig.ValidateConnect = pgconn.ValidateConnectTargetSessionAttrsReadWrite
	if config.ConnConfig.ConnectTimeout == 0 {
		config.ConnConfig.ConnectTimeout = DefaultConnectTimeout
		dialer := &net.Dialer{Timeout: DefaultConnectTimeout}
		config.ConnConfig.DialFunc = dialer.DialContext
	}
	if config.ConnConfig.ConnectTimeout < 0 || config.ConnConfig.ConnectTimeout > MaximumConnectTimeout {
		return nil, safeError(ErrConfigInvalid, "configuration")
	}

	return config, nil
}

func ParseStartupTimeout(value string) (time.Duration, error) {
	if strings.TrimSpace(value) == "" {
		return DefaultStartupTimeout, nil
	}
	timeout, err := time.ParseDuration(value)
	if err != nil || timeout <= 0 || timeout > MaximumStartupTimeout {
		return 0, safeError(ErrConfigInvalid, "startup timeout")
	}
	return timeout, nil
}

type Pool interface {
	Ping(context.Context) error
	Acquire(context.Context) (*pgxpool.Conn, error)
	Close()
}

type poolFactory func(context.Context, *pgxpool.Config) (Pool, error)

func Open(ctx context.Context, config *pgxpool.Config) (Pool, error) {
	return openWithFactory(ctx, config, func(ctx context.Context, config *pgxpool.Config) (Pool, error) {
		return pgxpool.NewWithConfig(ctx, config)
	})
}

func openWithFactory(ctx context.Context, config *pgxpool.Config, factory poolFactory) (Pool, error) {
	pool, err := factory(ctx, config)
	if err != nil {
		return nil, safeError(ErrConnect, "connection")
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, safeError(ErrConnect, "connection")
	}
	return pool, nil
}
