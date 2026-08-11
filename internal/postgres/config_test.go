package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestParsePoolConfigSingleAndMultiHost(t *testing.T) {
	tests := []struct {
		name          string
		databaseURL   string
		primaryHost   string
		primaryPort   uint16
		fallbackHosts []string
		fallbackPorts []uint16
		timeout       time.Duration
	}{
		{
			name: "single host missing target attrs is forced read-write",
			databaseURL: "postgresql://gateway_user@pg-primary.invalid:5432/gateway_database" +
				"?sslmode=verify-full",
			primaryHost: "pg-primary.invalid", primaryPort: 5432, timeout: DefaultConnectTimeout,
		},
		{
			name: "multi host preserves configured order and explicit read-write",
			databaseURL: "postgresql://gateway_user@pg-one.invalid:5432,pg-two.invalid:5433,pg-three.invalid:5434/gateway_database" +
				"?sslmode=verify-full&target_session_attrs=read-write&connect_timeout=7",
			primaryHost: "pg-one.invalid", primaryPort: 5432,
			fallbackHosts: []string{"pg-two.invalid", "pg-three.invalid"},
			fallbackPorts: []uint16{5433, 5434}, timeout: 7 * time.Second,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config, err := ParsePoolConfig(test.databaseURL)
			if err != nil {
				t.Fatalf("ParsePoolConfig returned error: %v", err)
			}
			if config.ConnConfig.Host != test.primaryHost || config.ConnConfig.Port != test.primaryPort {
				t.Errorf("primary = %s:%d, want %s:%d", config.ConnConfig.Host, config.ConnConfig.Port, test.primaryHost, test.primaryPort)
			}
			if config.ConnConfig.User != "gateway_user" || config.ConnConfig.Database != "gateway_database" {
				t.Errorf("user/database semantics were not preserved")
			}
			if config.ConnConfig.ValidateConnect == nil {
				t.Fatal("read-write validation is missing")
			}
			if config.ConnConfig.ConnectTimeout != test.timeout || config.ConnConfig.ConnectTimeout > MaximumConnectTimeout {
				t.Errorf("connect timeout = %s", config.ConnConfig.ConnectTimeout)
			}
			if len(config.ConnConfig.Fallbacks) != len(test.fallbackHosts) {
				t.Fatalf("fallback count = %d, want %d", len(config.ConnConfig.Fallbacks), len(test.fallbackHosts))
			}
			if config.ConnConfig.TLSConfig == nil || config.ConnConfig.TLSConfig.ServerName != test.primaryHost {
				t.Errorf("primary TLS server name was not bound to the primary host")
			}
			for index, fallback := range config.ConnConfig.Fallbacks {
				if fallback.Host != test.fallbackHosts[index] || fallback.Port != test.fallbackPorts[index] {
					t.Errorf("fallback %d order changed", index)
				}
				if fallback.TLSConfig == nil || fallback.TLSConfig.ServerName != test.fallbackHosts[index] {
					t.Errorf("fallback %d TLS server name was not bound to its host", index)
				}
			}
		})
	}
}

func TestParsePoolConfigRejectsUnsafeTargetSessionAttrs(t *testing.T) {
	for _, value := range []string{"any", "read-only", "standby", "prefer-standby", "primary"} {
		t.Run(value, func(t *testing.T) {
			databaseURL := "postgresql://gateway_user@pg.invalid/gateway_database?sslmode=verify-full&target_session_attrs=" + value
			if _, err := ParsePoolConfig(databaseURL); !errors.Is(err, ErrConfigInvalid) {
				t.Errorf("error = %v, want ErrConfigInvalid", err)
			}
		})
	}
}

func TestParsePoolConfigRejectsInvalidOrUnboundedConfigurationWithoutLeaks(t *testing.T) {
	tests := []string{
		"not-a-postgresql-uri",
		"postgresql://gateway_user@pg.invalid/gateway_database",
		"postgresql://gateway_user@pg.invalid/gateway_database?sslmode=disable",
		"postgresql://gateway_user@pg.invalid/gateway_database?sslmode=verify-full&connect_timeout=31",
		"postgresql://private_user:private_password@private-node.invalid/gateway_database?sslmode=verify-full&target_session_attrs=any",
	}
	for _, databaseURL := range tests {
		_, err := ParsePoolConfig(databaseURL)
		if err == nil {
			t.Fatal("ParsePoolConfig succeeded for invalid configuration")
		}
		for _, sensitive := range []string{"private_user", "private_password", "private-node.invalid", databaseURL} {
			if strings.Contains(err.Error(), sensitive) {
				t.Errorf("error leaked sensitive configuration data")
			}
		}
	}
}

func TestParseStartupTimeout(t *testing.T) {
	if timeout, err := ParseStartupTimeout(""); err != nil || timeout != DefaultStartupTimeout {
		t.Errorf("default = (%s, %v)", timeout, err)
	}
	if timeout, err := ParseStartupTimeout("45s"); err != nil || timeout != 45*time.Second {
		t.Errorf("explicit = (%s, %v)", timeout, err)
	}
	for _, invalid := range []string{"0s", "-1s", "11m", "invalid"} {
		if _, err := ParseStartupTimeout(invalid); !errors.Is(err, ErrConfigInvalid) {
			t.Errorf("ParseStartupTimeout(%q) error = %v", invalid, err)
		}
	}
}

type fakePool struct {
	pingErr error
	closed  bool
}

func (p *fakePool) Ping(context.Context) error { return p.pingErr }
func (p *fakePool) Acquire(context.Context) (*pgxpool.Conn, error) {
	return nil, errors.New("not used")
}
func (p *fakePool) Close() { p.closed = true }

func TestOpenCreatesOneLogicalPoolAndFailsClosed(t *testing.T) {
	config, err := ParsePoolConfig("postgresql://gateway_user@pg-one.invalid,pg-two.invalid/gateway_database?sslmode=verify-full")
	if err != nil {
		t.Fatal(err)
	}
	created := 0
	pool := &fakePool{}
	opened, err := openWithFactory(context.Background(), config, func(context.Context, *pgxpool.Config) (Pool, error) {
		created++
		return pool, nil
	})
	if err != nil || opened != pool || created != 1 {
		t.Errorf("open = (%T, %v), pool creations = %d", opened, err, created)
	}

	failing := &fakePool{pingErr: errors.New("node details")}
	_, err = openWithFactory(context.Background(), config, func(context.Context, *pgxpool.Config) (Pool, error) {
		return failing, nil
	})
	if !errors.Is(err, ErrConnect) || !failing.closed {
		t.Errorf("failure = %v, closed = %t", err, failing.closed)
	}
	if strings.Contains(err.Error(), "node details") {
		t.Error("connection error leaked driver details")
	}
}
