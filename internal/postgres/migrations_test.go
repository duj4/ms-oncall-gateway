package postgres

import (
	"strings"
	"testing"
	"testing/fstest"
)

func TestEmbeddedMigrationLayoutAndInitialSchema(t *testing.T) {
	migrations := EmbeddedMigrations()
	if len(migrations) != 1 {
		t.Fatalf("migration count = %d, want 1", len(migrations))
	}
	migration := migrations[0]
	if migration.Version != 1 || migration.Name != "000001_initial_schema.sql" {
		t.Errorf("migration identity = (%d, %q)", migration.Version, migration.Name)
	}
	if migration.Checksum != "2a71c7da93990ec43dfb0ff1cf0a778fc7f1a4a12dac606cbcd8d2c232ae7165" {
		t.Errorf("migration checksum = %q", migration.Checksum)
	}

	lower := strings.ToLower(migration.SQL)
	for _, required := range []string{
		"create table gateway_schema_migrations",
		"migration_version bigint primary key",
		"migration_checksum text not null",
		"create table durable_acceptances",
		"receipt_id uuid primary key",
		"core_principal_id text not null",
		"destination_id text not null",
		"core_delivery_identity uuid not null",
		"canonical_event_ciphertext bytea not null",
		"canonical_event_digest_ciphertext bytea not null",
		"encryption_key_id text not null",
		"unique (core_principal_id, destination_id, core_delivery_identity)",
	} {
		if !strings.Contains(lower, required) {
			t.Errorf("initial migration missing %q", required)
		}
	}
	for _, prohibited := range []string{
		"create database", "create role", "create user", "alter role", "grant ", "revoke ",
		"create extension", "begin;", "commit;", "opaque_token", "verification.code",
		"password", "sslcert", "sslkey", "provider", "worker", "attempt", "callback", "down migration",
	} {
		if strings.Contains(lower, prohibited) {
			t.Errorf("initial migration contains prohibited term %q", prohibited)
		}
	}
	if strings.Contains(lower, "receipt_id uuid default") {
		t.Error("receipt ID must not have a database-generated default")
	}
}

func TestMigrationSequenceRejectsDuplicatesGapsAndInvalidNames(t *testing.T) {
	for _, test := range []struct {
		name  string
		files fstest.MapFS
	}{
		{name: "gap", files: fstest.MapFS{"migrations/000002_gap.sql": {Data: []byte("select 1")}}},
		{name: "invalid name", files: fstest.MapFS{"migrations/initial.sql": {Data: []byte("select 1")}}},
		{name: "empty", files: fstest.MapFS{"migrations/000001_empty.sql": {Data: nil}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := loadMigrations(test.files); err == nil {
				t.Fatal("loadMigrations succeeded, want error")
			}
		})
	}
}
