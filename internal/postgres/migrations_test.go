package postgres

import (
	"regexp"
	"strings"
	"testing"
	"testing/fstest"
)

func TestEmbeddedMigrationLayoutAndSchemas(t *testing.T) {
	migrations := EmbeddedMigrations()
	if len(migrations) != 2 {
		t.Fatalf("migration count = %d, want 2", len(migrations))
	}
	for index, expected := range []struct {
		version  int64
		name     string
		checksum string
	}{
		{version: 1, name: "000001_initial_schema.sql", checksum: "2a71c7da93990ec43dfb0ff1cf0a778fc7f1a4a12dac606cbcd8d2c232ae7165"},
		{version: 2, name: "000002_security_state_v1.sql", checksum: "b336ccd2453400949f54454d8509c3f2559b93f740125e7c2f8762bc9fd0fcab"},
	} {
		migration := migrations[index]
		if migration.Version != expected.version || migration.Name != expected.name || migration.Checksum != expected.checksum {
			t.Errorf("migration %d identity or checksum mismatch", expected.version)
		}
	}

	lower := strings.ToLower(migrations[0].SQL)
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

	securitySQL := strings.ToLower(migrations[1].SQL)
	normalized := strings.Join(strings.Fields(securitySQL), " ")
	for _, required := range []string{
		"create table gateway_security_realm",
		"create table core_principals",
		"create table core_credential_slots",
		"create table core_authentication_credentials",
		"create table authentication_replay_reservations",
		"create table gateway_destinations",
		"create table gateway_destination_tokens",
		"constraint gateway_security_realm_singleton",
		"constraint gateway_security_realm_audience_nonzero",
		"constraint core_principals_audience_fk",
		"constraint core_credential_slots_principal_fk",
		"foreign key (gateway_audience_id, core_principal_id)",
		"constraint core_authentication_credentials_slot_fk",
		"foreign key (gateway_audience_id, core_principal_id, credential_slot_id)",
		"create unique index core_authentication_credentials_one_active_per_slot",
		"where credential_state = 'active'",
		"create unique index core_authentication_credentials_one_retiring_per_slot",
		"where credential_state = 'retiring'",
		"constraint authentication_replay_reservations_pkey primary key (credential_record_id, nonce_bytes)",
		"check (octet_length(nonce_bytes) = 16)",
		"check (expires_at = reserved_at + interval '5 minutes')",
		"create index authentication_replay_reservations_expiry",
		"constraint gateway_destinations_audience_fk",
		"constraint gateway_destination_tokens_destination_fk",
		"foreign key (gateway_audience_id, destination_id)",
		"check (octet_length(token_verifier) = 32)",
		"unique (gateway_audience_id, verifier_key_id, token_verifier)",
		"create unique index gateway_destination_tokens_one_staged_per_destination",
		"where token_state = 'staged'",
		"create unique index gateway_destination_tokens_one_active_per_destination",
		"where token_state = 'active'",
		"create unique index gateway_destination_tokens_one_retiring_per_destination",
		"where token_state = 'retiring'",
		"expires_at <= not_before + interval '90 days'",
		"retirement_overlap_deadline <= retirement_started_at + interval '24 hours'",
		"expires_at <= created_at + interval '90 days'",
		"staged_cleanup_deadline <= created_at + interval '24 hours'",
	} {
		if !strings.Contains(normalized, required) {
			t.Errorf("security migration missing required schema fragment %q", required)
		}
	}
	for _, state := range []string{"'disabled'", "'active'", "'retiring'", "'revoked'", "'staged'"} {
		if !strings.Contains(normalized, state) {
			t.Errorf("security migration missing lifecycle state %q", state)
		}
	}
	if count := len(regexp.MustCompile(`(?m)^create table `).FindAllString(securitySQL, -1)); count != 7 {
		t.Errorf("security migration table count = %d, want 7", count)
	}
	for _, prohibited := range []string{
		"create database", "create schema", "create role", "create user", "alter role",
		"grant ", "revoke ", "create extension", "create function", "create trigger",
		"begin;", "commit;", "down migration", "if not exists", "on delete cascade",
		"gen_random_uuid", "uuid_generate", "alter table", "durable_acceptances",
		"raw_token", "authentication_secret", "hmac_secret", "provider_address",
		"phone_number", "email_address", "certificate", "password",
	} {
		if strings.Contains(securitySQL, prohibited) {
			t.Errorf("security migration contains prohibited term %q", prohibited)
		}
	}
	if regexp.MustCompile(`(?is)check\s*\([^;]*current_timestamp`).MatchString(securitySQL) {
		t.Error("security migration uses current_timestamp in a CHECK constraint")
	}
	if regexp.MustCompile(`(?i)\buuid\s+default\b`).MatchString(securitySQL) {
		t.Error("security migration contains a database-generated UUID default")
	}
	credentialTable := regexp.MustCompile(`(?s)create table core_authentication_credentials \((.*?)\n\);`).FindStringSubmatch(securitySQL)
	if len(credentialTable) != 2 || strings.Contains(credentialTable[1], "created_at timestamp with time zone not null default") || strings.Contains(credentialTable[1], "state_changed_at timestamp with time zone not null default") {
		t.Error("credential lifecycle timestamps must use one explicit application time source")
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
