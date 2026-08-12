package postgres

import (
	"context"
	"errors"
	"reflect"
	"time"

	"github.com/duj4/ms-oncall-gateway/internal/securitystate"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

const replayReservationLifetime = 5 * time.Minute

const selectBoundAudienceSQL = `
	select
		count(*),
		coalesce(min(gateway_audience_id::text), ''),
		coalesce(bool_and(singleton_key), false)
	from gateway_security_realm
`

const selectCredentialSQL = `
	select
		count(*) over (),
		credential.gateway_audience_id = $1,
		credential.credential_record_id::text,
		credential.credential_id::text,
		credential.credential_slot_id::text,
		credential.gateway_audience_id::text,
		credential.core_principal_id::text,
		credential.credential_state,
		credential.not_before,
		credential.expires_at,
		credential.activated_at,
		credential.retirement_started_at,
		credential.retirement_overlap_deadline,
		credential.revoked_at,
		credential.created_at,
		credential.state_changed_at,
		slot.credential_slot_id::text,
		slot.gateway_audience_id::text,
		slot.core_principal_id::text,
		slot.created_at,
		principal.core_principal_id::text,
		principal.gateway_audience_id::text,
		principal.enabled,
		principal.gateway_intake_v1_authorized,
		principal.created_at,
		principal.state_changed_at
	from core_authentication_credentials credential
	left join core_credential_slots slot
		on slot.credential_slot_id = credential.credential_slot_id
	left join core_principals principal
		on principal.core_principal_id = credential.core_principal_id
	where credential.credential_id = $2
`

const selectPrincipalSQL = `
	select
		count(*) over (),
		core_principal_id::text,
		gateway_audience_id::text,
		enabled,
		gateway_intake_v1_authorized,
		created_at,
		state_changed_at
	from core_principals
	where gateway_audience_id = $1
	  and core_principal_id = $2
`

const insertReplayReservationSQL = `
	insert into authentication_replay_reservations (
		credential_record_id,
		nonce_bytes,
		reserved_at,
		expires_at
	)
	values ($1, $2, $3, $4)
	on conflict on constraint authentication_replay_reservations_pkey
	do nothing
	returning true
`

type authenticationStateConnection interface {
	QueryRow(context.Context, string, ...any) pgx.Row
	Release()
	Destroy()
}

type AuthenticationStateRepository struct {
	acquire func(context.Context) (authenticationStateConnection, error)
}

var (
	_ securitystate.AudienceBindingStore   = (*AuthenticationStateRepository)(nil)
	_ securitystate.CredentialRegistry     = (*AuthenticationStateRepository)(nil)
	_ securitystate.PrincipalRegistry      = (*AuthenticationStateRepository)(nil)
	_ securitystate.ReplayReservationStore = (*AuthenticationStateRepository)(nil)
)

func NewAuthenticationStateRepository(pool Pool) *AuthenticationStateRepository {
	if nilInterface(pool) {
		return &AuthenticationStateRepository{}
	}
	return newAuthenticationStateRepository(func(ctx context.Context) (authenticationStateConnection, error) {
		connection, err := pool.Acquire(ctx)
		if err != nil {
			if connection != nil {
				destroyPoolConnection(connection)
			}
			return nil, err
		}
		if connection == nil {
			return nil, ErrAuthenticationStateUnavailable
		}
		return &pgAuthenticationStateConnection{connection: connection}, nil
	})
}

func newAuthenticationStateRepository(acquire func(context.Context) (authenticationStateConnection, error)) *AuthenticationStateRepository {
	return &AuthenticationStateRepository{acquire: acquire}
}

type pgAuthenticationStateConnection struct {
	connection *pgxpool.Conn
}

func (connection *pgAuthenticationStateConnection) QueryRow(ctx context.Context, sql string, arguments ...any) pgx.Row {
	return connection.connection.QueryRow(ctx, sql, arguments...)
}

func (connection *pgAuthenticationStateConnection) Release() {
	connection.connection.Release()
}

func (connection *pgAuthenticationStateConnection) Destroy() {
	destroyPoolConnection(connection.connection)
}

func (repository *AuthenticationStateRepository) BoundAudience(ctx context.Context) (securitystate.GatewayAudienceID, error) {
	connection, finish, err := repository.readConnection(ctx, "security realm connection")
	if err != nil {
		return securitystate.GatewayAudienceID{}, err
	}

	var (
		count        int64
		audienceText string
		singleton    bool
	)
	row := connection.QueryRow(ctx, selectBoundAudienceSQL)
	if nilInterface(row) {
		finish(true)
		return securitystate.GatewayAudienceID{}, safeError(ErrAuthenticationStateUnavailable, "security realm query")
	}
	err = row.Scan(&count, &audienceText, &singleton)
	if err != nil {
		finish(isConnectionInterruption(err))
		return securitystate.GatewayAudienceID{}, repositoryReadError(ctx, err, "security realm query")
	}
	finish(false)
	if count != 1 || !singleton {
		return securitystate.GatewayAudienceID{}, securitystate.ErrAudienceUnavailable
	}
	audience, parseErr := securitystate.ParseGatewayAudienceID(audienceText)
	if parseErr != nil || audience.IsZero() || audience.String() != audienceText {
		return securitystate.GatewayAudienceID{}, securitystate.ErrAudienceUnavailable
	}
	return audience, nil
}

func (repository *AuthenticationStateRepository) Credential(
	ctx context.Context,
	expectedAudience securitystate.GatewayAudienceID,
	expectedPublicID securitystate.CredentialID,
) (securitystate.Credential, error) {
	parsedPublicID, publicIDErr := securitystate.ParseCredentialID(expectedPublicID.String())
	if expectedAudience.IsZero() || expectedPublicID.IsZero() || publicIDErr != nil || parsedPublicID != expectedPublicID {
		return securitystate.Credential{}, safeError(ErrAuthenticationStateIntegrity, "authentication credential input")
	}
	connection, finish, err := repository.readConnection(ctx, "authentication credential connection")
	if err != nil {
		return securitystate.Credential{}, err
	}

	record := credentialRecord{}
	row := connection.QueryRow(
		ctx,
		selectCredentialSQL,
		expectedAudience.String(),
		expectedPublicID.String(),
	)
	if nilInterface(row) {
		finish(true)
		return securitystate.Credential{}, safeError(ErrAuthenticationStateUnavailable, "authentication credential query")
	}
	err = row.Scan(record.destinations()...)
	if cancellation := contextSentinel(ctx, err); cancellation != nil {
		finish(isConnectionInterruption(err))
		return securitystate.Credential{}, safeError(cancellation, "authentication credential query")
	}
	if err == pgx.ErrNoRows {
		finish(false)
		return securitystate.Credential{}, securitystate.ErrCredentialNotFound
	}
	if err != nil {
		finish(isConnectionInterruption(err))
		return securitystate.Credential{}, repositoryReadError(ctx, err, "authentication credential query")
	}
	finish(false)

	credential, recordErr := record.credential(expectedAudience, expectedPublicID)
	if recordErr != nil {
		return securitystate.Credential{}, safeError(ErrAuthenticationStateIntegrity, "authentication credential record")
	}
	return credential, nil
}

func (repository *AuthenticationStateRepository) Principal(
	ctx context.Context,
	expectedAudience securitystate.GatewayAudienceID,
	expectedPrincipalID securitystate.CorePrincipalID,
) (securitystate.Principal, error) {
	if expectedAudience.IsZero() || expectedPrincipalID.IsZero() {
		return securitystate.Principal{}, safeError(ErrAuthenticationStateIntegrity, "core principal input")
	}
	connection, finish, err := repository.readConnection(ctx, "core principal connection")
	if err != nil {
		return securitystate.Principal{}, err
	}

	var (
		count            int64
		principalText    string
		audienceText     string
		enabled          bool
		intakeAuthorized bool
		createdAt        time.Time
		stateChangedAt   time.Time
	)
	row := connection.QueryRow(
		ctx,
		selectPrincipalSQL,
		expectedAudience.String(),
		expectedPrincipalID.String(),
	)
	if nilInterface(row) {
		finish(true)
		return securitystate.Principal{}, safeError(ErrAuthenticationStateUnavailable, "core principal query")
	}
	err = row.Scan(
		&count,
		&principalText,
		&audienceText,
		&enabled,
		&intakeAuthorized,
		&createdAt,
		&stateChangedAt,
	)
	if err != nil {
		if cancellation := contextSentinel(ctx, err); cancellation != nil {
			finish(isConnectionInterruption(err))
			return securitystate.Principal{}, safeError(cancellation, "core principal query")
		}
		finish(isConnectionInterruption(err))
		if err == pgx.ErrNoRows {
			return securitystate.Principal{}, safeError(ErrAuthenticationStateIntegrity, "core principal record")
		}
		return securitystate.Principal{}, repositoryReadError(ctx, err, "core principal query")
	}
	finish(false)

	principalID, principalErr := securitystate.ParseCorePrincipalID(principalText)
	audience, audienceErr := securitystate.ParseGatewayAudienceID(audienceText)
	if count != 1 || principalErr != nil || audienceErr != nil ||
		principalID != expectedPrincipalID || audience != expectedAudience {
		return securitystate.Principal{}, safeError(ErrAuthenticationStateIntegrity, "core principal record")
	}
	principal, constructErr := securitystate.NewPrincipal(
		audience,
		principalID,
		enabled,
		intakeAuthorized,
		createdAt,
		stateChangedAt,
	)
	if constructErr != nil {
		return securitystate.Principal{}, safeError(ErrAuthenticationStateIntegrity, "core principal record")
	}
	return principal, nil
}

func (repository *AuthenticationStateRepository) Reserve(
	ctx context.Context,
	recordID securitystate.CredentialRecordID,
	nonce securitystate.ReplayNonce,
	now time.Time,
) (securitystate.ReplayReservationDisposition, error) {
	if repository == nil || repository.acquire == nil || nilInterface(ctx) || recordID.IsZero() || now.IsZero() {
		return 0, securitystate.ErrReplayUnavailable
	}
	if cancellation := contextSentinel(ctx, nil); cancellation != nil {
		return 0, safeError(cancellation, "replay reservation canceled")
	}
	expiresAt := now.Add(replayReservationLifetime)
	if !expiresAt.After(now) {
		return 0, securitystate.ErrReplayUnavailable
	}

	connection, err := repository.acquire(ctx)
	if err != nil {
		if !nilInterface(connection) {
			connection.Destroy()
		}
		if cancellation := contextSentinel(ctx, err); cancellation != nil {
			return 0, safeError(cancellation, "replay reservation connection")
		}
		return 0, securitystate.ErrReplayUnavailable
	}
	if nilInterface(connection) {
		return 0, securitystate.ErrReplayUnavailable
	}

	nonceBytes := nonce.Bytes()
	var inserted bool
	row := connection.QueryRow(
		ctx,
		insertReplayReservationSQL,
		recordID.String(),
		append([]byte(nil), nonceBytes[:]...),
		now,
		expiresAt,
	)
	if nilInterface(row) {
		connection.Destroy()
		return 0, newReplayOutcomeUnknownError(nil)
	}
	err = row.Scan(&inserted)
	if err == nil && inserted {
		connection.Release()
		return securitystate.ReplayReserved, nil
	}
	if isConnectionInterruption(err) || contextSentinel(ctx, err) != nil {
		connection.Destroy()
		return 0, newReplayOutcomeUnknownError(contextSentinel(ctx, err))
	}
	if err == pgx.ErrNoRows {
		connection.Release()
		return securitystate.ReplayDuplicate, nil
	}
	if singleCausePostgresError(err) {
		connection.Release()
		return 0, securitystate.ErrReplayUnavailable
	}
	connection.Destroy()
	return 0, newReplayOutcomeUnknownError(nil)
}

func (repository *AuthenticationStateRepository) readConnection(
	ctx context.Context,
	operation string,
) (authenticationStateConnection, func(bool), error) {
	if repository == nil || repository.acquire == nil || nilInterface(ctx) {
		return nil, nil, safeError(ErrAuthenticationStateUnavailable, operation)
	}
	if cancellation := contextSentinel(ctx, nil); cancellation != nil {
		return nil, nil, safeError(cancellation, operation)
	}
	connection, err := repository.acquire(ctx)
	if err != nil {
		if !nilInterface(connection) {
			connection.Destroy()
		}
		if cancellation := contextSentinel(ctx, err); cancellation != nil {
			return nil, nil, safeError(cancellation, operation)
		}
		return nil, nil, safeError(ErrAuthenticationStateUnavailable, operation)
	}
	if nilInterface(connection) {
		return nil, nil, safeError(ErrAuthenticationStateUnavailable, operation)
	}
	finished := false
	finish := func(destroy bool) {
		if finished {
			return
		}
		finished = true
		if destroy {
			connection.Destroy()
			return
		}
		connection.Release()
	}
	return connection, finish, nil
}

func repositoryReadError(ctx context.Context, err error, operation string) error {
	if cancellation := contextSentinel(ctx, err); cancellation != nil {
		return safeError(cancellation, operation)
	}
	return safeError(ErrAuthenticationStateUnavailable, operation)
}

func contextSentinel(ctx context.Context, err error) error {
	if errors.Is(err, context.Canceled) || (!nilInterface(ctx) && errors.Is(ctx.Err(), context.Canceled)) {
		return context.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) || (!nilInterface(ctx) && errors.Is(ctx.Err(), context.DeadlineExceeded)) {
		return context.DeadlineExceeded
	}
	return nil
}

func singleCausePostgresError(err error) bool {
	for current, depth := err, 0; current != nil && depth < 64; depth++ {
		if nilInterface(current) {
			return false
		}
		if _, ambiguous := current.(interface{ Unwrap() []error }); ambiguous {
			return false
		}
		if _, ok := current.(*pgconn.PgError); ok {
			return true
		}
		current = errors.Unwrap(current)
	}
	return false
}

type replayOutcomeUnknownError struct {
	cancellation error
}

func newReplayOutcomeUnknownError(cancellation error) error {
	if !errors.Is(cancellation, context.Canceled) && !errors.Is(cancellation, context.DeadlineExceeded) {
		cancellation = nil
	}
	return replayOutcomeUnknownError{cancellation: cancellation}
}

func (replayOutcomeUnknownError) Error() string {
	return securitystate.ErrReplayOutcomeUnknown.Error()
}

func (err replayOutcomeUnknownError) Is(target error) bool {
	return target == securitystate.ErrReplayOutcomeUnknown || (err.cancellation != nil && target == err.cancellation)
}

type credentialRecord struct {
	count                     int64
	audienceMatches           bool
	recordText                string
	publicText                string
	credentialSlotText        string
	credentialAudienceText    string
	credentialPrincipalText   string
	stateText                 string
	notBefore                 time.Time
	expiresAt                 time.Time
	activatedAt               pgtype.Timestamptz
	retirementStartedAt       pgtype.Timestamptz
	retirementDeadline        pgtype.Timestamptz
	revokedAt                 pgtype.Timestamptz
	createdAt                 time.Time
	stateChangedAt            time.Time
	slotText                  pgtype.Text
	slotAudienceText          pgtype.Text
	slotPrincipalText         pgtype.Text
	slotCreatedAt             pgtype.Timestamptz
	principalText             pgtype.Text
	principalAudienceText     pgtype.Text
	principalEnabled          pgtype.Bool
	principalIntakeAuthorized pgtype.Bool
	principalCreatedAt        pgtype.Timestamptz
	principalStateChangedAt   pgtype.Timestamptz
}

func (record *credentialRecord) destinations() []any {
	return []any{
		&record.count,
		&record.audienceMatches,
		&record.recordText,
		&record.publicText,
		&record.credentialSlotText,
		&record.credentialAudienceText,
		&record.credentialPrincipalText,
		&record.stateText,
		&record.notBefore,
		&record.expiresAt,
		&record.activatedAt,
		&record.retirementStartedAt,
		&record.retirementDeadline,
		&record.revokedAt,
		&record.createdAt,
		&record.stateChangedAt,
		&record.slotText,
		&record.slotAudienceText,
		&record.slotPrincipalText,
		&record.slotCreatedAt,
		&record.principalText,
		&record.principalAudienceText,
		&record.principalEnabled,
		&record.principalIntakeAuthorized,
		&record.principalCreatedAt,
		&record.principalStateChangedAt,
	}
}

func (record credentialRecord) credential(
	expectedAudience securitystate.GatewayAudienceID,
	expectedPublicID securitystate.CredentialID,
) (securitystate.Credential, error) {
	if record.count != 1 || !record.audienceMatches ||
		!record.slotText.Valid || !record.slotAudienceText.Valid || !record.slotPrincipalText.Valid || !finiteTimestamp(record.slotCreatedAt) ||
		!record.principalText.Valid || !record.principalAudienceText.Valid || !record.principalEnabled.Valid || !record.principalIntakeAuthorized.Valid ||
		!finiteTimestamp(record.principalCreatedAt) || !finiteTimestamp(record.principalStateChangedAt) {
		return securitystate.Credential{}, ErrAuthenticationStateIntegrity
	}

	recordID, recordErr := securitystate.ParseCredentialRecordID(record.recordText)
	publicID, publicErr := securitystate.ParseCredentialID(record.publicText)
	credentialSlotID, credentialSlotErr := securitystate.ParseCredentialSlotID(record.credentialSlotText)
	credentialAudience, credentialAudienceErr := securitystate.ParseGatewayAudienceID(record.credentialAudienceText)
	credentialPrincipalID, credentialPrincipalErr := securitystate.ParseCorePrincipalID(record.credentialPrincipalText)
	slotID, slotErr := securitystate.ParseCredentialSlotID(record.slotText.String)
	slotAudience, slotAudienceErr := securitystate.ParseGatewayAudienceID(record.slotAudienceText.String)
	slotPrincipalID, slotPrincipalErr := securitystate.ParseCorePrincipalID(record.slotPrincipalText.String)
	principalID, principalErr := securitystate.ParseCorePrincipalID(record.principalText.String)
	principalAudience, principalAudienceErr := securitystate.ParseGatewayAudienceID(record.principalAudienceText.String)
	if recordErr != nil || publicErr != nil || credentialSlotErr != nil || credentialAudienceErr != nil || credentialPrincipalErr != nil ||
		slotErr != nil || slotAudienceErr != nil || slotPrincipalErr != nil || principalErr != nil || principalAudienceErr != nil ||
		publicID != expectedPublicID || credentialAudience != expectedAudience || credentialSlotID != slotID ||
		credentialPrincipalID != slotPrincipalID || credentialPrincipalID != principalID ||
		slotAudience != credentialAudience || principalAudience != credentialAudience {
		return securitystate.Credential{}, ErrAuthenticationStateIntegrity
	}

	principal, err := securitystate.NewPrincipal(
		principalAudience,
		principalID,
		record.principalEnabled.Bool,
		record.principalIntakeAuthorized.Bool,
		record.principalCreatedAt.Time,
		record.principalStateChangedAt.Time,
	)
	if err != nil {
		return securitystate.Credential{}, ErrAuthenticationStateIntegrity
	}
	slot, err := securitystate.NewCredentialSlot(
		slotAudience,
		principal,
		slotID,
		record.slotCreatedAt.Time,
	)
	if err != nil {
		return securitystate.Credential{}, ErrAuthenticationStateIntegrity
	}
	state, err := credentialState(record.stateText)
	if err != nil {
		return securitystate.Credential{}, ErrAuthenticationStateIntegrity
	}
	activatedAt, err := optionalFiniteTime(record.activatedAt)
	if err != nil {
		return securitystate.Credential{}, ErrAuthenticationStateIntegrity
	}
	retirementStartedAt, err := optionalFiniteTime(record.retirementStartedAt)
	if err != nil {
		return securitystate.Credential{}, ErrAuthenticationStateIntegrity
	}
	retirementDeadline, err := optionalFiniteTime(record.retirementDeadline)
	if err != nil {
		return securitystate.Credential{}, ErrAuthenticationStateIntegrity
	}
	revokedAt, err := optionalFiniteTime(record.revokedAt)
	if err != nil {
		return securitystate.Credential{}, ErrAuthenticationStateIntegrity
	}
	return securitystate.NewCredential(securitystate.CredentialSpec{
		AudienceID:          credentialAudience,
		Principal:           principal,
		Slot:                slot,
		RecordID:            recordID,
		PublicID:            publicID,
		State:               state,
		NotBefore:           record.notBefore,
		ExpiresAt:           record.expiresAt,
		ActivatedAt:         activatedAt,
		RetirementStartedAt: retirementStartedAt,
		RetirementDeadline:  retirementDeadline,
		RevokedAt:           revokedAt,
		CreatedAt:           record.createdAt,
		StateChangedAt:      record.stateChangedAt,
	})
}

func credentialState(value string) (securitystate.CredentialState, error) {
	switch value {
	case "disabled":
		return securitystate.CredentialDisabled, nil
	case "active":
		return securitystate.CredentialActive, nil
	case "retiring":
		return securitystate.CredentialRetiring, nil
	case "revoked":
		return securitystate.CredentialRevoked, nil
	default:
		return 0, ErrAuthenticationStateIntegrity
	}
}

func optionalFiniteTime(value pgtype.Timestamptz) (time.Time, error) {
	if !value.Valid {
		return time.Time{}, nil
	}
	if value.InfinityModifier != pgtype.Finite || value.Time.IsZero() {
		return time.Time{}, ErrAuthenticationStateIntegrity
	}
	return value.Time, nil
}

func finiteTimestamp(value pgtype.Timestamptz) bool {
	return value.Valid && value.InfinityModifier == pgtype.Finite && !value.Time.IsZero()
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
