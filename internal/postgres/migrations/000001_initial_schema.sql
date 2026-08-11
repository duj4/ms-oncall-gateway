CREATE TABLE gateway_schema_migrations (
    migration_version bigint PRIMARY KEY,
    migration_checksum text NOT NULL,
    applied_at timestamp with time zone NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT gateway_schema_migrations_version_positive
        CHECK (migration_version > 0),
    CONSTRAINT gateway_schema_migrations_checksum_sha256
        CHECK (
            length(migration_checksum) = 64
            AND migration_checksum ~ '^[0-9a-f]{64}$'
        )
);

CREATE TABLE durable_acceptances (
    receipt_id uuid PRIMARY KEY,
    core_principal_id text NOT NULL,
    destination_id text NOT NULL,
    core_delivery_identity uuid NOT NULL,
    canonical_event_format_version bigint NOT NULL,
    canonical_event_ciphertext bytea NOT NULL,
    canonical_event_nonce bytea NOT NULL,
    canonical_event_digest_ciphertext bytea NOT NULL,
    canonical_event_digest_nonce bytea NOT NULL,
    encryption_key_id text NOT NULL,
    created_at timestamp with time zone NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT durable_acceptances_core_principal_present
        CHECK (length(core_principal_id) > 0),
    CONSTRAINT durable_acceptances_destination_present
        CHECK (length(destination_id) > 0),
    CONSTRAINT durable_acceptances_event_format_positive
        CHECK (canonical_event_format_version > 0),
    CONSTRAINT durable_acceptances_event_ciphertext_present
        CHECK (octet_length(canonical_event_ciphertext) > 0),
    CONSTRAINT durable_acceptances_event_nonce_present
        CHECK (octet_length(canonical_event_nonce) > 0),
    CONSTRAINT durable_acceptances_digest_ciphertext_present
        CHECK (octet_length(canonical_event_digest_ciphertext) > 0),
    CONSTRAINT durable_acceptances_digest_nonce_present
        CHECK (octet_length(canonical_event_digest_nonce) > 0),
    CONSTRAINT durable_acceptances_encryption_key_present
        CHECK (length(encryption_key_id) > 0),
    CONSTRAINT durable_acceptances_delivery_identity_unique
        UNIQUE (core_principal_id, destination_id, core_delivery_identity)
);
