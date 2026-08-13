package postgres

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"time"

	"github.com/duj4/ms-oncall-gateway/internal/securitystate"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

const selectDestinationTokenSQL = `
	select
		count(*) over (),
		token.destination_token_record_id::text,
		token.gateway_audience_id::text,
		token.destination_id::text,
		token.token_verifier,
		token.verifier_key_id,
		token.token_state,
		token.created_at,
		token.activated_at,
		token.retirement_started_at,
		token.revoked_at,
		token.expires_at,
		token.staged_cleanup_deadline,
		token.retirement_overlap_deadline,
		token.state_changed_at,
		destination.destination_id::text,
		destination.gateway_audience_id::text,
		destination.destination_state,
		destination.created_at,
		destination.state_changed_at
	from gateway_destination_tokens token
	left join gateway_destinations destination
		on destination.destination_id = token.destination_id
	where token.gateway_audience_id = $1
	  and token.verifier_key_id = $2
	  and token.token_verifier = $3
`

type destinationResolverConnection interface {
	QueryRow(context.Context, string, ...any) pgx.Row
	Release()
	Destroy()
}

type OpaqueDestinationResolver struct {
	acquire   func(context.Context) (destinationResolverConnection, error)
	keySource securitystate.DestinationVerifierKeySource
	keyIDs    []securitystate.DestinationVerifierKeyID
}

var _ securitystate.DestinationResolver = (*OpaqueDestinationResolver)(nil)

func NewOpaqueDestinationResolver(
	pool Pool,
	keySource securitystate.DestinationVerifierKeySource,
	keyIDs []securitystate.DestinationVerifierKeyID,
) (*OpaqueDestinationResolver, error) {
	if nilInterface(pool) {
		return nil, safeError(ErrDestinationResolverIntegrity, "destination resolver configuration")
	}
	return newOpaqueDestinationResolver(func(ctx context.Context) (destinationResolverConnection, error) {
		connection, err := pool.Acquire(ctx)
		if err != nil {
			if connection != nil {
				destroyPoolConnection(connection)
			}
			return nil, err
		}
		if connection == nil {
			return nil, ErrDestinationResolverUnavailable
		}
		return &pgDestinationResolverConnection{connection: connection}, nil
	}, keySource, keyIDs)
}

func newOpaqueDestinationResolver(
	acquire func(context.Context) (destinationResolverConnection, error),
	keySource securitystate.DestinationVerifierKeySource,
	keyIDs []securitystate.DestinationVerifierKeyID,
) (*OpaqueDestinationResolver, error) {
	if acquire == nil || nilInterface(keySource) || len(keyIDs) < 1 || len(keyIDs) > 2 {
		return nil, safeError(ErrDestinationResolverIntegrity, "destination resolver configuration")
	}

	configured := make([]securitystate.DestinationVerifierKeyID, len(keyIDs))
	for index, keyID := range keyIDs {
		parsed, err := securitystate.NewDestinationVerifierKeyID(keyID.Value())
		if err != nil || parsed != keyID {
			return nil, safeError(ErrDestinationResolverIntegrity, "destination resolver configuration")
		}
		for prior := range index {
			if configured[prior] == keyID {
				return nil, safeError(ErrDestinationResolverIntegrity, "destination resolver configuration")
			}
		}
		configured[index] = keyID
	}

	return &OpaqueDestinationResolver{
		acquire:   acquire,
		keySource: keySource,
		keyIDs:    configured,
	}, nil
}

type pgDestinationResolverConnection struct {
	connection *pgxpool.Conn
}

func (connection *pgDestinationResolverConnection) QueryRow(ctx context.Context, sql string, arguments ...any) pgx.Row {
	return connection.connection.QueryRow(ctx, sql, arguments...)
}

func (connection *pgDestinationResolverConnection) Release() {
	connection.connection.Release()
}

func (connection *pgDestinationResolverConnection) Destroy() {
	destroyPoolConnection(connection.connection)
}

func (OpaqueDestinationResolver) Format(state fmt.State, verb rune) {
	_, _ = state.Write([]byte("[redacted]"))
}

func (resolver *OpaqueDestinationResolver) Resolve(
	ctx context.Context,
	expectedAudience securitystate.GatewayAudienceID,
	rawToken securitystate.OpaqueDestinationToken,
	now time.Time,
) (securitystate.DestinationID, error) {
	if resolver == nil || resolver.acquire == nil || nilInterface(resolver.keySource) ||
		len(resolver.keyIDs) < 1 || len(resolver.keyIDs) > 2 || nilInterface(ctx) ||
		expectedAudience.IsZero() || now.IsZero() {
		return securitystate.DestinationID{}, safeError(ErrDestinationResolverIntegrity, "destination resolution input")
	}
	parsedAudience, audienceErr := securitystate.ParseGatewayAudienceID(expectedAudience.String())
	if audienceErr != nil || parsedAudience != expectedAudience {
		return securitystate.DestinationID{}, safeError(ErrDestinationResolverIntegrity, "destination resolution input")
	}
	if cancellation := contextSentinel(ctx, nil); cancellation != nil {
		return securitystate.DestinationID{}, safeError(cancellation, "destination resolution canceled")
	}

	candidates, err := resolver.verifierCandidates(ctx, expectedAudience, rawToken)
	if err != nil {
		return securitystate.DestinationID{}, err
	}

	connection, err := resolver.acquire(ctx)
	if err != nil {
		if !nilInterface(connection) {
			connection.Destroy()
		}
		if cancellation := contextSentinel(ctx, err); cancellation != nil {
			return securitystate.DestinationID{}, safeError(cancellation, "destination resolution connection")
		}
		return securitystate.DestinationID{}, safeError(ErrDestinationResolverUnavailable, "destination resolution connection")
	}
	if nilInterface(connection) {
		return securitystate.DestinationID{}, safeError(ErrDestinationResolverUnavailable, "destination resolution connection")
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

	matches := make([]securitystate.DestinationToken, 0, len(candidates))
	integrityFailure := false
	for _, candidate := range candidates {
		if cancellation := contextSentinel(ctx, nil); cancellation != nil {
			finish(true)
			return securitystate.DestinationID{}, safeError(cancellation, "destination token query")
		}

		candidateVerifier := candidate.verifier.Bytes()
		record := destinationTokenRecord{}
		row := connection.QueryRow(
			ctx,
			selectDestinationTokenSQL,
			expectedAudience.String(),
			candidate.keyID.Value(),
			append([]byte(nil), candidateVerifier[:]...),
		)
		if nilInterface(row) {
			finish(true)
			return securitystate.DestinationID{}, safeError(ErrDestinationResolverUnavailable, "destination token query")
		}
		err = row.Scan(record.destinations()...)
		if cancellation := contextSentinel(ctx, err); cancellation != nil {
			finish(true)
			return securitystate.DestinationID{}, safeError(cancellation, "destination token query")
		}
		if err == pgx.ErrNoRows {
			continue
		}
		if err != nil {
			finish(isConnectionInterruption(err))
			return securitystate.DestinationID{}, safeError(ErrDestinationResolverUnavailable, "destination token query")
		}

		token, recordErr := record.token(expectedAudience, candidate)
		if recordErr != nil {
			integrityFailure = true
			continue
		}
		matches = append(matches, token)
	}

	if cancellation := contextSentinel(ctx, nil); cancellation != nil {
		finish(true)
		return securitystate.DestinationID{}, safeError(cancellation, "destination token query")
	}
	finish(false)
	if integrityFailure || len(matches) > 1 {
		return securitystate.DestinationID{}, safeError(ErrDestinationResolverIntegrity, "destination token record")
	}
	if len(matches) == 0 || !matches[0].UsableAt(now) {
		return securitystate.DestinationID{}, securitystate.ErrDestinationNotFound
	}
	return matches[0].DestinationID(), nil
}

type destinationVerifierCandidate struct {
	keyID    securitystate.DestinationVerifierKeyID
	verifier securitystate.TokenVerifier
}

func (resolver *OpaqueDestinationResolver) verifierCandidates(
	ctx context.Context,
	audience securitystate.GatewayAudienceID,
	rawToken securitystate.OpaqueDestinationToken,
) ([]destinationVerifierCandidate, error) {
	candidates := make([]destinationVerifierCandidate, 0, len(resolver.keyIDs))
	unavailable := false
	for _, keyID := range resolver.keyIDs {
		key, err := resolver.keySource.DestinationVerifierKey(ctx, audience, keyID)
		if cancellation := contextSentinel(ctx, err); cancellation != nil {
			return nil, safeError(cancellation, "destination verifier key")
		}
		if err != nil {
			unavailable = true
			continue
		}
		keyBytes := key.Bytes()
		if len(keyBytes) < sha256.Size {
			unavailable = true
			continue
		}
		verifier, verifierErr := securitystate.ComputeDestinationTokenVerifier(audience, rawToken, key)
		if verifierErr != nil {
			unavailable = true
			continue
		}
		candidates = append(candidates, destinationVerifierCandidate{keyID: keyID, verifier: verifier})
	}
	if unavailable || len(candidates) != len(resolver.keyIDs) {
		return nil, safeError(ErrDestinationResolverUnavailable, "destination verifier key")
	}
	return candidates, nil
}

// computeDestinationTokenVerifier remains as the package-local test seam used
// by the accepted Resolver V1 golden vector. The algorithm lives only in the
// securitystate package so resolver and lifecycle creation cannot drift.
func computeDestinationTokenVerifier(
	audience securitystate.GatewayAudienceID,
	rawToken securitystate.OpaqueDestinationToken,
	keyBytes []byte,
) (securitystate.TokenVerifier, error) {
	key, err := securitystate.NewDestinationVerifierKey(keyBytes)
	if err != nil {
		return securitystate.TokenVerifier{}, ErrDestinationResolverIntegrity
	}
	return securitystate.ComputeDestinationTokenVerifier(audience, rawToken, key)
}

type destinationTokenRecord struct {
	count                     int64
	recordText                string
	audienceText              string
	destinationText           string
	verifierBytes             []byte
	keyIDText                 string
	stateText                 string
	createdAt                 pgtype.Timestamptz
	activatedAt               pgtype.Timestamptz
	retirementStartedAt       pgtype.Timestamptz
	revokedAt                 pgtype.Timestamptz
	expiresAt                 pgtype.Timestamptz
	stagedCleanupDeadline     pgtype.Timestamptz
	retirementDeadline        pgtype.Timestamptz
	stateChangedAt            pgtype.Timestamptz
	destinationRecordText     pgtype.Text
	destinationAudienceText   pgtype.Text
	destinationStateText      pgtype.Text
	destinationCreatedAt      pgtype.Timestamptz
	destinationStateChangedAt pgtype.Timestamptz
}

func (record *destinationTokenRecord) destinations() []any {
	return []any{
		&record.count,
		&record.recordText,
		&record.audienceText,
		&record.destinationText,
		&record.verifierBytes,
		&record.keyIDText,
		&record.stateText,
		&record.createdAt,
		&record.activatedAt,
		&record.retirementStartedAt,
		&record.revokedAt,
		&record.expiresAt,
		&record.stagedCleanupDeadline,
		&record.retirementDeadline,
		&record.stateChangedAt,
		&record.destinationRecordText,
		&record.destinationAudienceText,
		&record.destinationStateText,
		&record.destinationCreatedAt,
		&record.destinationStateChangedAt,
	}
}

func (record destinationTokenRecord) token(
	expectedAudience securitystate.GatewayAudienceID,
	candidate destinationVerifierCandidate,
) (securitystate.DestinationToken, error) {
	if record.count != 1 || !finiteTimestamp(record.createdAt) || !finiteTimestamp(record.expiresAt) ||
		!finiteTimestamp(record.stagedCleanupDeadline) || !finiteTimestamp(record.stateChangedAt) ||
		!record.destinationRecordText.Valid || !record.destinationAudienceText.Valid ||
		!record.destinationStateText.Valid || !finiteTimestamp(record.destinationCreatedAt) ||
		!finiteTimestamp(record.destinationStateChangedAt) {
		return securitystate.DestinationToken{}, ErrDestinationResolverIntegrity
	}

	recordID, recordErr := securitystate.ParseDestinationTokenRecordID(record.recordText)
	audience, audienceErr := securitystate.ParseGatewayAudienceID(record.audienceText)
	destinationID, destinationErr := securitystate.ParseDestinationID(record.destinationText)
	storedVerifier, verifierErr := securitystate.NewTokenVerifier(record.verifierBytes)
	storedKeyID, keyIDErr := securitystate.NewDestinationVerifierKeyID(record.keyIDText)
	destinationRecordID, destinationRecordErr := securitystate.ParseDestinationID(record.destinationRecordText.String)
	destinationAudience, destinationAudienceErr := securitystate.ParseGatewayAudienceID(record.destinationAudienceText.String)
	if recordErr != nil || audienceErr != nil || destinationErr != nil || verifierErr != nil || keyIDErr != nil ||
		destinationRecordErr != nil || destinationAudienceErr != nil || audience != expectedAudience ||
		destinationID != destinationRecordID || destinationAudience != audience || storedKeyID != candidate.keyID {
		return securitystate.DestinationToken{}, ErrDestinationResolverIntegrity
	}
	storedVerifierBytes := storedVerifier.Bytes()
	candidateVerifierBytes := candidate.verifier.Bytes()
	if subtle.ConstantTimeCompare(storedVerifierBytes[:], candidateVerifierBytes[:]) != 1 {
		return securitystate.DestinationToken{}, ErrDestinationResolverIntegrity
	}

	destinationState, stateErr := destinationState(record.destinationStateText.String)
	if stateErr != nil {
		return securitystate.DestinationToken{}, ErrDestinationResolverIntegrity
	}
	destination, constructErr := securitystate.NewDestination(
		destinationAudience,
		destinationRecordID,
		destinationState,
		record.destinationCreatedAt.Time,
		record.destinationStateChangedAt.Time,
	)
	if constructErr != nil {
		return securitystate.DestinationToken{}, ErrDestinationResolverIntegrity
	}
	tokenState, stateErr := destinationTokenState(record.stateText)
	if stateErr != nil {
		return securitystate.DestinationToken{}, ErrDestinationResolverIntegrity
	}
	activatedAt, timeErr := optionalFiniteTime(record.activatedAt)
	if timeErr != nil {
		return securitystate.DestinationToken{}, ErrDestinationResolverIntegrity
	}
	retirementStartedAt, timeErr := optionalFiniteTime(record.retirementStartedAt)
	if timeErr != nil {
		return securitystate.DestinationToken{}, ErrDestinationResolverIntegrity
	}
	revokedAt, timeErr := optionalFiniteTime(record.revokedAt)
	if timeErr != nil {
		return securitystate.DestinationToken{}, ErrDestinationResolverIntegrity
	}
	retirementDeadline, timeErr := optionalFiniteTime(record.retirementDeadline)
	if timeErr != nil {
		return securitystate.DestinationToken{}, ErrDestinationResolverIntegrity
	}
	return securitystate.NewDestinationToken(securitystate.DestinationTokenSpec{
		AudienceID:            audience,
		Destination:           destination,
		RecordID:              recordID,
		Verifier:              storedVerifier,
		VerifierKeyID:         storedKeyID,
		State:                 tokenState,
		CreatedAt:             record.createdAt.Time,
		ActivatedAt:           activatedAt,
		RetirementStartedAt:   retirementStartedAt,
		RevokedAt:             revokedAt,
		ExpiresAt:             record.expiresAt.Time,
		StagedCleanupDeadline: record.stagedCleanupDeadline.Time,
		RetirementDeadline:    retirementDeadline,
		StateChangedAt:        record.stateChangedAt.Time,
	})
}

func destinationState(value string) (securitystate.DestinationState, error) {
	switch value {
	case "enabled":
		return securitystate.DestinationEnabled, nil
	case "disabled":
		return securitystate.DestinationDisabled, nil
	default:
		return 0, ErrDestinationResolverIntegrity
	}
}

func destinationTokenState(value string) (securitystate.DestinationTokenState, error) {
	switch value {
	case "staged":
		return securitystate.DestinationTokenStaged, nil
	case "active":
		return securitystate.DestinationTokenActive, nil
	case "retiring":
		return securitystate.DestinationTokenRetiring, nil
	case "revoked":
		return securitystate.DestinationTokenRevoked, nil
	default:
		return 0, ErrDestinationResolverIntegrity
	}
}
