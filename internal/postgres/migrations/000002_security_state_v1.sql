CREATE TABLE gateway_security_realm (
    singleton_key boolean PRIMARY KEY DEFAULT true,
    gateway_audience_id uuid NOT NULL UNIQUE,
    created_at timestamp with time zone NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT gateway_security_realm_singleton
        CHECK (singleton_key),
    CONSTRAINT gateway_security_realm_audience_nonzero
        CHECK (gateway_audience_id <> '00000000-0000-0000-0000-000000000000'::uuid)
);

CREATE TABLE core_principals (
    core_principal_id uuid PRIMARY KEY,
    gateway_audience_id uuid NOT NULL,
    enabled boolean NOT NULL,
    gateway_intake_v1_authorized boolean NOT NULL,
    created_at timestamp with time zone NOT NULL DEFAULT CURRENT_TIMESTAMP,
    state_changed_at timestamp with time zone NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT core_principals_id_nonzero
        CHECK (core_principal_id <> '00000000-0000-0000-0000-000000000000'::uuid),
    CONSTRAINT core_principals_state_time_order
        CHECK (state_changed_at >= created_at),
    CONSTRAINT core_principals_audience_fk
        FOREIGN KEY (gateway_audience_id)
        REFERENCES gateway_security_realm (gateway_audience_id),
    CONSTRAINT core_principals_audience_id_unique
        UNIQUE (gateway_audience_id, core_principal_id)
);

CREATE TABLE core_credential_slots (
    credential_slot_id uuid PRIMARY KEY,
    gateway_audience_id uuid NOT NULL,
    core_principal_id uuid NOT NULL,
    created_at timestamp with time zone NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT core_credential_slots_id_nonzero
        CHECK (credential_slot_id <> '00000000-0000-0000-0000-000000000000'::uuid),
    CONSTRAINT core_credential_slots_principal_fk
        FOREIGN KEY (gateway_audience_id, core_principal_id)
        REFERENCES core_principals (gateway_audience_id, core_principal_id),
    CONSTRAINT core_credential_slots_audience_principal_id_unique
        UNIQUE (gateway_audience_id, core_principal_id, credential_slot_id)
);

CREATE TABLE core_authentication_credentials (
    credential_record_id uuid PRIMARY KEY,
    credential_id uuid NOT NULL UNIQUE,
    credential_slot_id uuid NOT NULL,
    gateway_audience_id uuid NOT NULL,
    core_principal_id uuid NOT NULL,
    credential_state text NOT NULL,
    not_before timestamp with time zone NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    activated_at timestamp with time zone,
    retirement_started_at timestamp with time zone,
    retirement_overlap_deadline timestamp with time zone,
    revoked_at timestamp with time zone,
    created_at timestamp with time zone NOT NULL,
    state_changed_at timestamp with time zone NOT NULL,
    CONSTRAINT core_authentication_credentials_record_id_nonzero
        CHECK (credential_record_id <> '00000000-0000-0000-0000-000000000000'::uuid),
    CONSTRAINT core_authentication_credentials_public_id_v4
        CHECK (credential_id::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
    CONSTRAINT core_authentication_credentials_state
        CHECK (credential_state IN ('disabled', 'active', 'retiring', 'revoked')),
    CONSTRAINT core_authentication_credentials_lifetime
        CHECK (
            created_at <= not_before
            AND not_before < expires_at
            AND expires_at <= not_before + INTERVAL '90 days'
        ),
    CONSTRAINT core_authentication_credentials_state_time_order
        CHECK (
            state_changed_at >= created_at
            AND (activated_at IS NULL OR activated_at >= created_at)
            AND (retirement_started_at IS NULL OR (activated_at IS NOT NULL AND retirement_started_at >= activated_at))
            AND (revoked_at IS NULL OR revoked_at >= created_at)
        ),
    CONSTRAINT core_authentication_credentials_retirement_bound
        CHECK (
            (retirement_started_at IS NULL AND retirement_overlap_deadline IS NULL)
            OR (
                retirement_started_at IS NOT NULL
                AND retirement_overlap_deadline > retirement_started_at
                AND retirement_overlap_deadline <= retirement_started_at + INTERVAL '24 hours'
            )
        ),
    CONSTRAINT core_authentication_credentials_state_fields
        CHECK (
            (credential_state = 'disabled' AND revoked_at IS NULL)
            OR (
                credential_state = 'active'
                AND activated_at IS NOT NULL
                AND retirement_started_at IS NULL
                AND retirement_overlap_deadline IS NULL
                AND revoked_at IS NULL
            )
            OR (
                credential_state = 'retiring'
                AND activated_at IS NOT NULL
                AND retirement_started_at IS NOT NULL
                AND retirement_overlap_deadline IS NOT NULL
                AND revoked_at IS NULL
            )
            OR (credential_state = 'revoked' AND revoked_at IS NOT NULL)
        ),
    CONSTRAINT core_authentication_credentials_slot_fk
        FOREIGN KEY (gateway_audience_id, core_principal_id, credential_slot_id)
        REFERENCES core_credential_slots (gateway_audience_id, core_principal_id, credential_slot_id)
);

CREATE UNIQUE INDEX core_authentication_credentials_one_active_per_slot
    ON core_authentication_credentials (credential_slot_id)
    WHERE credential_state = 'active';

CREATE UNIQUE INDEX core_authentication_credentials_one_retiring_per_slot
    ON core_authentication_credentials (credential_slot_id)
    WHERE credential_state = 'retiring';

CREATE TABLE authentication_replay_reservations (
    credential_record_id uuid NOT NULL,
    nonce_bytes bytea NOT NULL,
    reserved_at timestamp with time zone NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at timestamp with time zone NOT NULL DEFAULT (CURRENT_TIMESTAMP + INTERVAL '5 minutes'),
    CONSTRAINT authentication_replay_reservations_nonce_size
        CHECK (octet_length(nonce_bytes) = 16),
    CONSTRAINT authentication_replay_reservations_retention
        CHECK (expires_at = reserved_at + INTERVAL '5 minutes'),
    CONSTRAINT authentication_replay_reservations_credential_fk
        FOREIGN KEY (credential_record_id)
        REFERENCES core_authentication_credentials (credential_record_id),
    CONSTRAINT authentication_replay_reservations_pkey
        PRIMARY KEY (credential_record_id, nonce_bytes)
);

CREATE INDEX authentication_replay_reservations_expiry
    ON authentication_replay_reservations (expires_at);

CREATE TABLE gateway_destinations (
    destination_id uuid PRIMARY KEY,
    gateway_audience_id uuid NOT NULL,
    destination_state text NOT NULL,
    created_at timestamp with time zone NOT NULL DEFAULT CURRENT_TIMESTAMP,
    state_changed_at timestamp with time zone NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT gateway_destinations_id_nonzero
        CHECK (destination_id <> '00000000-0000-0000-0000-000000000000'::uuid),
    CONSTRAINT gateway_destinations_state
        CHECK (destination_state IN ('enabled', 'disabled')),
    CONSTRAINT gateway_destinations_state_time_order
        CHECK (state_changed_at >= created_at),
    CONSTRAINT gateway_destinations_audience_fk
        FOREIGN KEY (gateway_audience_id)
        REFERENCES gateway_security_realm (gateway_audience_id),
    CONSTRAINT gateway_destinations_audience_id_unique
        UNIQUE (gateway_audience_id, destination_id)
);

CREATE TABLE gateway_destination_tokens (
    destination_token_record_id uuid PRIMARY KEY,
    gateway_audience_id uuid NOT NULL,
    destination_id uuid NOT NULL,
    token_verifier bytea NOT NULL,
    verifier_key_id character varying(128) NOT NULL,
    token_state text NOT NULL,
    created_at timestamp with time zone NOT NULL DEFAULT CURRENT_TIMESTAMP,
    activated_at timestamp with time zone,
    retirement_started_at timestamp with time zone,
    revoked_at timestamp with time zone,
    expires_at timestamp with time zone NOT NULL,
    staged_cleanup_deadline timestamp with time zone NOT NULL,
    retirement_overlap_deadline timestamp with time zone,
    state_changed_at timestamp with time zone NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT gateway_destination_tokens_record_id_nonzero
        CHECK (destination_token_record_id <> '00000000-0000-0000-0000-000000000000'::uuid),
    CONSTRAINT gateway_destination_tokens_verifier_size
        CHECK (octet_length(token_verifier) = 32),
    CONSTRAINT gateway_destination_tokens_key_id_present
        CHECK (octet_length(verifier_key_id) > 0),
    CONSTRAINT gateway_destination_tokens_state
        CHECK (token_state IN ('staged', 'active', 'retiring', 'revoked')),
    CONSTRAINT gateway_destination_tokens_lifetime
        CHECK (created_at < expires_at AND expires_at <= created_at + INTERVAL '90 days'),
    CONSTRAINT gateway_destination_tokens_staged_cleanup_bound
        CHECK (
            staged_cleanup_deadline > created_at
            AND staged_cleanup_deadline <= created_at + INTERVAL '24 hours'
        ),
    CONSTRAINT gateway_destination_tokens_state_time_order
        CHECK (
            state_changed_at >= created_at
            AND (activated_at IS NULL OR activated_at >= created_at)
            AND (retirement_started_at IS NULL OR (activated_at IS NOT NULL AND retirement_started_at >= activated_at))
            AND (revoked_at IS NULL OR revoked_at >= created_at)
        ),
    CONSTRAINT gateway_destination_tokens_retirement_bound
        CHECK (
            (retirement_started_at IS NULL AND retirement_overlap_deadline IS NULL)
            OR (
                retirement_started_at IS NOT NULL
                AND retirement_overlap_deadline > retirement_started_at
                AND retirement_overlap_deadline <= retirement_started_at + INTERVAL '24 hours'
            )
        ),
    CONSTRAINT gateway_destination_tokens_state_fields
        CHECK (
            (
                token_state = 'staged'
                AND activated_at IS NULL
                AND retirement_started_at IS NULL
                AND retirement_overlap_deadline IS NULL
                AND revoked_at IS NULL
            )
            OR (
                token_state = 'active'
                AND activated_at IS NOT NULL
                AND retirement_started_at IS NULL
                AND retirement_overlap_deadline IS NULL
                AND revoked_at IS NULL
            )
            OR (
                token_state = 'retiring'
                AND activated_at IS NOT NULL
                AND retirement_started_at IS NOT NULL
                AND retirement_overlap_deadline IS NOT NULL
                AND revoked_at IS NULL
            )
            OR (token_state = 'revoked' AND revoked_at IS NOT NULL)
        ),
    CONSTRAINT gateway_destination_tokens_destination_fk
        FOREIGN KEY (gateway_audience_id, destination_id)
        REFERENCES gateway_destinations (gateway_audience_id, destination_id),
    CONSTRAINT gateway_destination_tokens_verifier_unique
        UNIQUE (gateway_audience_id, verifier_key_id, token_verifier)
);

CREATE UNIQUE INDEX gateway_destination_tokens_one_staged_per_destination
    ON gateway_destination_tokens (destination_id)
    WHERE token_state = 'staged';

CREATE UNIQUE INDEX gateway_destination_tokens_one_active_per_destination
    ON gateway_destination_tokens (destination_id)
    WHERE token_state = 'active';

CREATE UNIQUE INDEX gateway_destination_tokens_one_retiring_per_destination
    ON gateway_destination_tokens (destination_id)
    WHERE token_state = 'retiring';
