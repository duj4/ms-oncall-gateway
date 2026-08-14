package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/duj4/ms-oncall-gateway/internal/securitystate"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

const destinationTokenLifecycleRollbackTimeout = 5 * time.Second

const lockLifecycleDestinationSQL = `
	select
		destination_id::text,
		gateway_audience_id::text,
		destination_state,
		created_at,
		state_changed_at
	from gateway_destinations
	where destination_id = $1
	for update
`

const inspectLifecycleDestinationSQL = `
	select
		destination_id::text,
		gateway_audience_id::text,
		destination_state,
		created_at,
		state_changed_at
	from gateway_destinations
	where destination_id = $1
`

const lockLifecycleTokensSQL = `
	select
		destination_token_record_id::text,
		gateway_audience_id::text,
		destination_id::text,
		token_verifier,
		verifier_key_id,
		token_state,
		created_at,
		activated_at,
		retirement_started_at,
		revoked_at,
		expires_at,
		staged_cleanup_deadline,
		retirement_overlap_deadline,
		state_changed_at
	from gateway_destination_tokens
	where destination_id = $1
	  and token_state is distinct from 'revoked'
	order by token_state, destination_token_record_id
	limit 4
	for update
`

const inspectLifecycleTokensSQL = `
	select
		destination_token_record_id::text,
		gateway_audience_id::text,
		destination_id::text,
		token_verifier,
		verifier_key_id,
		token_state,
		created_at,
		activated_at,
		retirement_started_at,
		revoked_at,
		expires_at,
		staged_cleanup_deadline,
		retirement_overlap_deadline,
		state_changed_at
	from gateway_destination_tokens
	where destination_id = $1
	  and token_state is distinct from 'revoked'
	order by token_state, destination_token_record_id
	limit 4
`

const insertLifecycleStagedTokenSQL = `
	insert into gateway_destination_tokens (
		destination_token_record_id,
		gateway_audience_id,
		destination_id,
		token_verifier,
		verifier_key_id,
		token_state,
		created_at,
		expires_at,
		staged_cleanup_deadline,
		state_changed_at
	)
	values ($1, $2, $3, $4, $5, 'staged', $6, $7, $8, $6)
`

const activateInitialLifecycleTokenSQL = `
	update gateway_destination_tokens
	set token_state = 'active',
		activated_at = $5,
		state_changed_at = $5
	where gateway_audience_id = $1
	  and destination_id = $2
	  and destination_token_record_id = $3
	  and token_state = 'staged'
	  and state_changed_at = $4
`

const retireLifecycleTokenSQL = `
	update gateway_destination_tokens
	set token_state = 'retiring',
		retirement_started_at = $5,
		retirement_overlap_deadline = $6,
		state_changed_at = $5
	where gateway_audience_id = $1
	  and destination_id = $2
	  and destination_token_record_id = $3
	  and token_state = 'active'
	  and state_changed_at = $4
`

const activateRotationLifecycleTokenSQL = `
	update gateway_destination_tokens
	set token_state = 'active',
		activated_at = $5,
		state_changed_at = $5
	where gateway_audience_id = $1
	  and destination_id = $2
	  and destination_token_record_id = $3
	  and token_state = 'staged'
	  and state_changed_at = $4
`

const revokeStagedLifecycleTokenSQL = `
	update gateway_destination_tokens
	set token_state = 'revoked',
		revoked_at = $5,
		state_changed_at = $5
	where gateway_audience_id = $1
	  and destination_id = $2
	  and destination_token_record_id = $3
	  and token_state = 'staged'
	  and state_changed_at = $4
`

const revokeActiveLifecycleTokenSQL = `
	update gateway_destination_tokens
	set token_state = 'revoked',
		revoked_at = $5,
		state_changed_at = $5
	where gateway_audience_id = $1
	  and destination_id = $2
	  and destination_token_record_id = $3
	  and token_state = 'active'
	  and state_changed_at = $4
`

const restoreRetiringLifecycleTokenSQL = `
	update gateway_destination_tokens
	set token_state = 'active',
		retirement_started_at = null,
		retirement_overlap_deadline = null,
		state_changed_at = $5
	where gateway_audience_id = $1
	  and destination_id = $2
	  and destination_token_record_id = $3
	  and token_state = 'retiring'
	  and state_changed_at = $4
`

const revokeRetiringLifecycleTokenSQL = `
	update gateway_destination_tokens
	set token_state = 'revoked',
		revoked_at = $5,
		state_changed_at = $5
	where gateway_audience_id = $1
	  and destination_id = $2
	  and destination_token_record_id = $3
	  and token_state = 'retiring'
	  and state_changed_at = $4
`

type destinationTokenLifecycleRows interface {
	Close()
	Err() error
	Next() bool
	Scan(...any) error
}

type destinationTokenLifecycleTransaction interface {
	QueryRow(context.Context, string, ...any) pgx.Row
	Query(context.Context, string, ...any) (destinationTokenLifecycleRows, error)
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	Commit(context.Context) error
	Rollback(context.Context) error
}

type destinationTokenLifecycleConnection interface {
	Begin(context.Context, pgx.TxOptions) (destinationTokenLifecycleTransaction, error)
	Release()
	Destroy()
}

type DestinationTokenLifecycleRepository struct {
	acquire         func(context.Context) (destinationTokenLifecycleConnection, error)
	rollbackTimeout time.Duration
}

var _ securitystate.DestinationTokenLifecycleRepository = (*DestinationTokenLifecycleRepository)(nil)

func NewDestinationTokenLifecycleRepository(pool Pool) *DestinationTokenLifecycleRepository {
	if nilInterface(pool) {
		return &DestinationTokenLifecycleRepository{}
	}
	return newDestinationTokenLifecycleRepository(func(ctx context.Context) (destinationTokenLifecycleConnection, error) {
		connection, err := pool.Acquire(ctx)
		if err != nil {
			if connection != nil {
				destroyPoolConnection(connection)
			}
			return nil, err
		}
		if connection == nil {
			return nil, securitystate.ErrDestinationLifecycleUnavailable
		}
		return &pgDestinationTokenLifecycleConnection{connection: connection}, nil
	})
}

func newDestinationTokenLifecycleRepository(
	acquire func(context.Context) (destinationTokenLifecycleConnection, error),
) *DestinationTokenLifecycleRepository {
	return &DestinationTokenLifecycleRepository{
		acquire:         acquire,
		rollbackTimeout: destinationTokenLifecycleRollbackTimeout,
	}
}

type pgDestinationTokenLifecycleConnection struct {
	connection *pgxpool.Conn
}

func (connection *pgDestinationTokenLifecycleConnection) Begin(
	ctx context.Context,
	options pgx.TxOptions,
) (destinationTokenLifecycleTransaction, error) {
	transaction, err := connection.connection.BeginTx(ctx, options)
	if err != nil {
		return nil, err
	}
	return &pgDestinationTokenLifecycleTransaction{transaction: transaction}, nil
}

func (connection *pgDestinationTokenLifecycleConnection) Release() {
	connection.connection.Release()
}

func (connection *pgDestinationTokenLifecycleConnection) Destroy() {
	destroyPoolConnection(connection.connection)
}

type pgDestinationTokenLifecycleTransaction struct {
	transaction pgx.Tx
}

func (transaction *pgDestinationTokenLifecycleTransaction) QueryRow(
	ctx context.Context,
	sql string,
	arguments ...any,
) pgx.Row {
	return transaction.transaction.QueryRow(ctx, sql, arguments...)
}

func (transaction *pgDestinationTokenLifecycleTransaction) Query(
	ctx context.Context,
	sql string,
	arguments ...any,
) (destinationTokenLifecycleRows, error) {
	return transaction.transaction.Query(ctx, sql, arguments...)
}

func (transaction *pgDestinationTokenLifecycleTransaction) Exec(
	ctx context.Context,
	sql string,
	arguments ...any,
) (pgconn.CommandTag, error) {
	return transaction.transaction.Exec(ctx, sql, arguments...)
}

func (transaction *pgDestinationTokenLifecycleTransaction) Commit(ctx context.Context) error {
	return transaction.transaction.Commit(ctx)
}

func (transaction *pgDestinationTokenLifecycleTransaction) Rollback(ctx context.Context) error {
	return transaction.transaction.Rollback(ctx)
}

type lifecycleLockedState struct {
	destination securitystate.Destination
	snapshot    securitystate.DestinationLifecycleSnapshot
}

type lifecycleMutation func(
	context.Context,
	destinationTokenLifecycleTransaction,
	lifecycleLockedState,
	*bool,
) error

func (repository *DestinationTokenLifecycleRepository) CreateStagedToken(
	ctx context.Context,
	candidate securitystate.StagedTokenCandidate,
	now time.Time,
) error {
	validated, err := securitystate.NewStagedTokenCandidate(
		candidate.AudienceID(),
		candidate.DestinationID(),
		candidate.RecordID(),
		candidate.Verifier(),
		candidate.VerifierKeyID(),
		candidate.CreatedAt(),
		candidate.ExpiresAt(),
		candidate.StagedCleanupDeadline(),
	)
	if err != nil || validated.RecordID() != candidate.RecordID() || now.IsZero() ||
		!candidate.CreatedAt().Equal(now) {
		return lifecycleRepositoryError(securitystate.ErrDestinationLifecycleInvalid, "staged token input")
	}
	return repository.runLifecycleMutation(
		ctx,
		candidate.AudienceID(),
		candidate.DestinationID(),
		now,
		func(
			ctx context.Context,
			transaction destinationTokenLifecycleTransaction,
			state lifecycleLockedState,
			mutationSent *bool,
		) error {
			if !state.destination.Enabled() {
				return securitystate.ErrDestinationLifecycleReconciliation
			}
			switch state.snapshot.Status() {
			case securitystate.LifecycleUnprovisioned, securitystate.LifecycleActive:
			case securitystate.LifecycleReconciliationRequired:
				return securitystate.ErrDestinationLifecycleReconciliation
			default:
				return securitystate.ErrDestinationLifecycleConflict
			}
			verifier := candidate.Verifier().Bytes()
			*mutationSent = true
			tag, execErr := transaction.Exec(
				ctx,
				insertLifecycleStagedTokenSQL,
				candidate.RecordID().String(),
				candidate.AudienceID().String(),
				candidate.DestinationID().String(),
				append([]byte(nil), verifier[:]...),
				candidate.VerifierKeyID().Value(),
				candidate.CreatedAt(),
				candidate.ExpiresAt(),
				candidate.StagedCleanupDeadline(),
			)
			if execErr != nil {
				return lifecycleMutationError(execErr)
			}
			return lifecycleRowsAffected(tag)
		},
	)
}

func (repository *DestinationTokenLifecycleRepository) ActivateInitialToken(
	ctx context.Context,
	audience securitystate.GatewayAudienceID,
	destination securitystate.DestinationID,
	stagedID securitystate.DestinationTokenRecordID,
	now time.Time,
) error {
	if stagedID.IsZero() {
		return lifecycleRepositoryError(securitystate.ErrDestinationLifecycleInvalid, "initial activation input")
	}
	return repository.runLifecycleMutation(ctx, audience, destination, now, func(
		ctx context.Context,
		transaction destinationTokenLifecycleTransaction,
		state lifecycleLockedState,
		mutationSent *bool,
	) error {
		staged, present := state.snapshot.Staged()
		if state.snapshot.Status() == securitystate.LifecycleReconciliationRequired {
			return securitystate.ErrDestinationLifecycleReconciliation
		}
		if state.snapshot.Status() != securitystate.LifecycleStagedInitial || !present || staged.RecordID() != stagedID {
			return securitystate.ErrDestinationLifecycleConflict
		}
		*mutationSent = true
		tag, err := transaction.Exec(ctx, activateInitialLifecycleTokenSQL,
			audience.String(), destination.String(), stagedID.String(), staged.StateChangedAt(), now)
		if err != nil {
			return lifecycleMutationError(err)
		}
		return lifecycleRowsAffected(tag)
	})
}

func (repository *DestinationTokenLifecycleRepository) ActivateRotation(
	ctx context.Context,
	command securitystate.ActivateRotationCommand,
) error {
	audience := command.AudienceID
	destination := command.DestinationID
	stagedID := command.StagedRecordID
	oldActiveID := command.OldActiveRecordID
	now := command.Now
	overlapDeadline := command.OverlapDeadline
	if stagedID.IsZero() || oldActiveID.IsZero() || stagedID == oldActiveID ||
		!overlapDeadline.After(now) || overlapDeadline.Sub(now) > securitystate.MaximumRetiringOverlapDuration {
		return lifecycleRepositoryError(securitystate.ErrDestinationLifecycleInvalid, "rotation activation input")
	}
	return repository.runLifecycleMutation(ctx, audience, destination, now, func(
		ctx context.Context,
		transaction destinationTokenLifecycleTransaction,
		state lifecycleLockedState,
		mutationSent *bool,
	) error {
		if state.snapshot.Status() == securitystate.LifecycleReconciliationRequired {
			return securitystate.ErrDestinationLifecycleReconciliation
		}
		staged, hasStaged := state.snapshot.Staged()
		active, hasActive := state.snapshot.Active()
		if state.snapshot.Status() != securitystate.LifecycleActiveWithStaged || !hasStaged || !hasActive ||
			staged.RecordID() != stagedID || active.RecordID() != oldActiveID {
			return securitystate.ErrDestinationLifecycleConflict
		}
		if !overlapDeadline.Before(staged.ExpiresAt()) || !overlapDeadline.Before(active.ExpiresAt()) {
			return securitystate.ErrDestinationLifecycleConflict
		}

		// Retire the old row first so the existing partial active-token index
		// permits the staged row to become active in the same transaction.
		*mutationSent = true
		tag, err := transaction.Exec(ctx, retireLifecycleTokenSQL,
			audience.String(), destination.String(), oldActiveID.String(), active.StateChangedAt(), now, overlapDeadline)
		if err != nil {
			return lifecycleMutationError(err)
		}
		if err := lifecycleRowsAffected(tag); err != nil {
			return err
		}
		tag, err = transaction.Exec(ctx, activateRotationLifecycleTokenSQL,
			audience.String(), destination.String(), stagedID.String(), staged.StateChangedAt(), now)
		if err != nil {
			return lifecycleMutationError(err)
		}
		return lifecycleRowsAffected(tag)
	})
}

func (repository *DestinationTokenLifecycleRepository) AbortStagedToken(
	ctx context.Context,
	audience securitystate.GatewayAudienceID,
	destination securitystate.DestinationID,
	stagedID securitystate.DestinationTokenRecordID,
	now time.Time,
) error {
	if stagedID.IsZero() {
		return lifecycleRepositoryError(securitystate.ErrDestinationLifecycleInvalid, "staged abort input")
	}
	return repository.runLifecycleMutation(ctx, audience, destination, now, func(
		ctx context.Context,
		transaction destinationTokenLifecycleTransaction,
		state lifecycleLockedState,
		mutationSent *bool,
	) error {
		staged, hasStaged := state.snapshot.Staged()
		_, hasRetiring := state.snapshot.Retiring()
		if !hasStaged || hasRetiring || staged.RecordID() != stagedID {
			return securitystate.ErrDestinationLifecycleConflict
		}
		if err := lifecycleStagedAbortAllowed(state, staged, now); err != nil {
			return err
		}
		*mutationSent = true
		tag, err := transaction.Exec(ctx, revokeStagedLifecycleTokenSQL,
			audience.String(), destination.String(), stagedID.String(), staged.StateChangedAt(), now)
		if err != nil {
			return lifecycleMutationError(err)
		}
		return lifecycleRowsAffected(tag)
	})
}

func (repository *DestinationTokenLifecycleRepository) RollbackRotation(
	ctx context.Context,
	command securitystate.RollbackRotationCommand,
) error {
	audience := command.AudienceID
	destination := command.DestinationID
	newActiveID := command.NewActiveRecordID
	oldRetiringID := command.OldRetiringRecordID
	now := command.Now
	if newActiveID.IsZero() || oldRetiringID.IsZero() || newActiveID == oldRetiringID {
		return lifecycleRepositoryError(securitystate.ErrDestinationLifecycleInvalid, "rotation rollback input")
	}
	return repository.runLifecycleMutation(ctx, audience, destination, now, func(
		ctx context.Context,
		transaction destinationTokenLifecycleTransaction,
		state lifecycleLockedState,
		mutationSent *bool,
	) error {
		active, retiring, err := lifecycleRotationPair(state, newActiveID, oldRetiringID, now, false)
		if err != nil {
			return err
		}
		if !now.Before(retiring.RetirementDeadline()) {
			return securitystate.ErrDestinationLifecycleConflict
		}

		// Revoke the new row first to free the partial active-token index.
		*mutationSent = true
		tag, execErr := transaction.Exec(ctx, revokeActiveLifecycleTokenSQL,
			audience.String(), destination.String(), newActiveID.String(), active.StateChangedAt(), now)
		if execErr != nil {
			return lifecycleMutationError(execErr)
		}
		if err := lifecycleRowsAffected(tag); err != nil {
			return err
		}
		tag, execErr = transaction.Exec(ctx, restoreRetiringLifecycleTokenSQL,
			audience.String(), destination.String(), oldRetiringID.String(), retiring.StateChangedAt(), now)
		if execErr != nil {
			return lifecycleMutationError(execErr)
		}
		return lifecycleRowsAffected(tag)
	})
}

func (repository *DestinationTokenLifecycleRepository) FinalizeRotation(
	ctx context.Context,
	command securitystate.FinalizeRotationCommand,
) error {
	audience := command.AudienceID
	destination := command.DestinationID
	newActiveID := command.NewActiveRecordID
	oldRetiringID := command.OldRetiringRecordID
	reason := command.Reason
	now := command.Now
	if newActiveID.IsZero() || oldRetiringID.IsZero() || newActiveID == oldRetiringID || !reason.Valid() {
		return lifecycleRepositoryError(securitystate.ErrDestinationLifecycleInvalid, "rotation finalization input")
	}
	return repository.runLifecycleMutation(ctx, audience, destination, now, func(
		ctx context.Context,
		transaction destinationTokenLifecycleTransaction,
		state lifecycleLockedState,
		mutationSent *bool,
	) error {
		_, retiring, err := lifecycleRotationPair(state, newActiveID, oldRetiringID, now, true)
		if err != nil {
			return err
		}
		if reason == securitystate.RotationDeadlineElapsed && now.Before(retiring.RetirementDeadline()) {
			return securitystate.ErrDestinationLifecycleConflict
		}
		*mutationSent = true
		tag, execErr := transaction.Exec(ctx, revokeRetiringLifecycleTokenSQL,
			audience.String(), destination.String(), oldRetiringID.String(), retiring.StateChangedAt(), now)
		if execErr != nil {
			return lifecycleMutationError(execErr)
		}
		return lifecycleRowsAffected(tag)
	})
}

func (repository *DestinationTokenLifecycleRepository) InspectLifecycleState(
	ctx context.Context,
	audience securitystate.GatewayAudienceID,
	destination securitystate.DestinationID,
	now time.Time,
) (result securitystate.DestinationLifecycleSnapshot, resultErr error) {
	if err := validateLifecycleRepositoryInput(repository, ctx, audience, destination, now); err != nil {
		return securitystate.DestinationLifecycleSnapshot{}, err
	}
	connection, err := repository.acquire(ctx)
	if err != nil {
		if !nilInterface(connection) {
			connection.Destroy()
		}
		return securitystate.DestinationLifecycleSnapshot{}, lifecycleConnectionError(ctx, err, "lifecycle inspection connection")
	}
	if nilInterface(connection) {
		return securitystate.DestinationLifecycleSnapshot{}, lifecycleRepositoryError(
			securitystate.ErrDestinationLifecycleUnavailable,
			"lifecycle inspection connection",
		)
	}
	release := true
	defer func() {
		if release {
			connection.Release()
		}
	}()

	transaction, err := connection.Begin(ctx, pgx.TxOptions{
		IsoLevel:   pgx.RepeatableRead,
		AccessMode: pgx.ReadOnly,
	})
	if err != nil || nilInterface(transaction) {
		if isConnectionInterruption(err) || nilInterface(transaction) {
			connection.Destroy()
			release = false
		}
		return securitystate.DestinationLifecycleSnapshot{}, lifecycleConnectionError(ctx, err, "lifecycle inspection begin")
	}
	transactionOpen := true
	defer func() {
		if !transactionOpen {
			return
		}
		rollbackCtx, cancel := boundedCleanupContext(ctx, repository.rollbackTimeout)
		rollbackErr := transaction.Rollback(rollbackCtx)
		cancel()
		transactionOpen = false
		if rollbackErr != nil {
			connection.Destroy()
			release = false
			result = securitystate.DestinationLifecycleSnapshot{}
			resultErr = lifecycleRepositoryError(
				securitystate.ErrDestinationLifecycleUnavailable,
				"lifecycle inspection cleanup",
			)
		}
	}()

	state, err := loadDestinationLifecycleState(ctx, transaction, audience, destination, now, false)
	if err != nil {
		return securitystate.DestinationLifecycleSnapshot{}, lifecycleRollbackRead(
			ctx, repository, connection, transaction, &transactionOpen, &release, err,
		)
	}
	if err := transaction.Commit(ctx); err != nil {
		transactionOpen = false
		connection.Destroy()
		release = false
		return securitystate.DestinationLifecycleSnapshot{}, lifecycleConnectionError(
			ctx,
			err,
			"lifecycle inspection commit",
		)
	}
	transactionOpen = false
	return state.snapshot, nil
}

func (repository *DestinationTokenLifecycleRepository) runLifecycleMutation(
	ctx context.Context,
	audience securitystate.GatewayAudienceID,
	destination securitystate.DestinationID,
	now time.Time,
	mutation lifecycleMutation,
) (resultErr error) {
	if err := validateLifecycleRepositoryInput(repository, ctx, audience, destination, now); err != nil || mutation == nil {
		if err != nil {
			return err
		}
		return lifecycleRepositoryError(securitystate.ErrDestinationLifecycleInvalid, "lifecycle mutation input")
	}
	connection, err := repository.acquire(ctx)
	if err != nil {
		if !nilInterface(connection) {
			connection.Destroy()
		}
		return lifecycleConnectionError(ctx, err, "lifecycle mutation connection")
	}
	if nilInterface(connection) {
		return lifecycleRepositoryError(securitystate.ErrDestinationLifecycleUnavailable, "lifecycle mutation connection")
	}
	release := true
	defer func() {
		if release {
			connection.Release()
		}
	}()

	transaction, err := connection.Begin(ctx, pgx.TxOptions{
		IsoLevel:   pgx.ReadCommitted,
		AccessMode: pgx.ReadWrite,
	})
	if err != nil || nilInterface(transaction) {
		if isConnectionInterruption(err) || nilInterface(transaction) {
			connection.Destroy()
			release = false
		}
		return lifecycleConnectionError(ctx, err, "lifecycle mutation begin")
	}
	transactionOpen := true
	defer func() {
		if !transactionOpen {
			return
		}
		rollbackCtx, cancel := boundedCleanupContext(ctx, repository.rollbackTimeout)
		rollbackErr := transaction.Rollback(rollbackCtx)
		cancel()
		transactionOpen = false
		if rollbackErr != nil {
			connection.Destroy()
			release = false
			resultErr = lifecycleRepositoryError(
				securitystate.ErrDestinationLifecycleOutcomeUnknown,
				"lifecycle mutation cleanup",
			)
		}
	}()

	state, err := loadDestinationLifecycleState(ctx, transaction, audience, destination, now, true)
	if err != nil {
		return repository.rollbackLifecycleMutation(
			ctx, connection, transaction, &transactionOpen, &release, err,
		)
	}
	mutationSent := false
	if err := mutation(ctx, transaction, state, &mutationSent); err != nil {
		return repository.rollbackLifecycleMutation(
			ctx, connection, transaction, &transactionOpen, &release, err,
		)
	}
	if !mutationSent {
		return repository.rollbackLifecycleMutation(
			ctx,
			connection,
			transaction,
			&transactionOpen,
			&release,
			securitystate.ErrDestinationLifecycleReconciliation,
		)
	}
	if err := transaction.Commit(ctx); err != nil {
		transactionOpen = false
		if err == pgx.ErrTxCommitRollback {
			// PostgreSQL conclusively completed COMMIT as ROLLBACK. No mutation
			// committed, so this specific pgx sentinel is unavailable rather
			// than outcome-unknown and the healthy connection may be released.
			return lifecycleRepositoryError(
				securitystate.ErrDestinationLifecycleUnavailable,
				"lifecycle mutation commit",
			)
		}
		connection.Destroy()
		release = false
		return lifecycleRepositoryError(
			securitystate.ErrDestinationLifecycleOutcomeUnknown,
			"lifecycle mutation commit",
		)
	}
	transactionOpen = false
	return nil
}

func (repository *DestinationTokenLifecycleRepository) rollbackLifecycleMutation(
	ctx context.Context,
	connection destinationTokenLifecycleConnection,
	transaction destinationTokenLifecycleTransaction,
	transactionOpen *bool,
	release *bool,
	cause error,
) error {
	rollbackCtx, cancel := boundedCleanupContext(ctx, repository.rollbackTimeout)
	rollbackErr := transaction.Rollback(rollbackCtx)
	cancel()
	*transactionOpen = false
	if rollbackErr != nil {
		connection.Destroy()
		*release = false
		return lifecycleRepositoryError(
			securitystate.ErrDestinationLifecycleOutcomeUnknown,
			"lifecycle mutation rollback",
		)
	}
	if lifecycleErrorRequiresDestroy(cause) || isConnectionInterruption(cause) {
		connection.Destroy()
		*release = false
	}
	if errors.Is(cause, securitystate.ErrDestinationLifecycleCanceled) {
		return lifecycleRepositoryError(securitystate.ErrDestinationLifecycleCanceled, "lifecycle mutation canceled")
	}
	if errors.Is(cause, securitystate.ErrDestinationLifecycleDeadline) {
		return lifecycleRepositoryError(securitystate.ErrDestinationLifecycleDeadline, "lifecycle mutation canceled")
	}
	if cancellation := lifecycleRepositoryCancellation(ctx, cause); cancellation != nil {
		return lifecycleRepositoryError(cancellation, "lifecycle mutation canceled")
	}
	for _, kind := range []error{
		securitystate.ErrDestinationLifecycleInvalid,
		securitystate.ErrDestinationLifecycleConflict,
		securitystate.ErrDestinationLifecycleReconciliation,
		securitystate.ErrDestinationLifecycleUnavailable,
	} {
		if errors.Is(cause, kind) {
			return lifecycleRepositoryError(kind, "lifecycle mutation")
		}
	}
	return lifecycleRepositoryError(securitystate.ErrDestinationLifecycleUnavailable, "lifecycle mutation")
}

func lifecycleRollbackRead(
	ctx context.Context,
	repository *DestinationTokenLifecycleRepository,
	connection destinationTokenLifecycleConnection,
	transaction destinationTokenLifecycleTransaction,
	transactionOpen *bool,
	release *bool,
	cause error,
) error {
	rollbackCtx, cancel := boundedCleanupContext(ctx, repository.rollbackTimeout)
	rollbackErr := transaction.Rollback(rollbackCtx)
	cancel()
	*transactionOpen = false
	if rollbackErr != nil {
		connection.Destroy()
		*release = false
		return lifecycleRepositoryError(securitystate.ErrDestinationLifecycleUnavailable, "lifecycle inspection rollback")
	}
	if lifecycleErrorRequiresDestroy(cause) || isConnectionInterruption(cause) {
		connection.Destroy()
		*release = false
	}
	if errors.Is(cause, securitystate.ErrDestinationLifecycleCanceled) {
		return lifecycleRepositoryError(securitystate.ErrDestinationLifecycleCanceled, "lifecycle inspection canceled")
	}
	if errors.Is(cause, securitystate.ErrDestinationLifecycleDeadline) {
		return lifecycleRepositoryError(securitystate.ErrDestinationLifecycleDeadline, "lifecycle inspection canceled")
	}
	if cancellation := lifecycleRepositoryCancellation(ctx, cause); cancellation != nil {
		return lifecycleRepositoryError(cancellation, "lifecycle inspection canceled")
	}
	for _, kind := range []error{
		securitystate.ErrDestinationLifecycleConflict,
		securitystate.ErrDestinationLifecycleReconciliation,
		securitystate.ErrDestinationLifecycleUnavailable,
	} {
		if errors.Is(cause, kind) {
			return lifecycleRepositoryError(kind, "lifecycle inspection")
		}
	}
	return lifecycleRepositoryError(securitystate.ErrDestinationLifecycleUnavailable, "lifecycle inspection")
}

func loadDestinationLifecycleState(
	ctx context.Context,
	transaction destinationTokenLifecycleTransaction,
	expectedAudience securitystate.GatewayAudienceID,
	expectedDestination securitystate.DestinationID,
	now time.Time,
	lock bool,
) (lifecycleLockedState, error) {
	destinationSQL := inspectLifecycleDestinationSQL
	tokensSQL := inspectLifecycleTokensSQL
	if lock {
		destinationSQL = lockLifecycleDestinationSQL
		tokensSQL = lockLifecycleTokensSQL
	}

	record := lifecycleDestinationRecord{}
	row := transaction.QueryRow(ctx, destinationSQL, expectedDestination.String())
	if nilInterface(row) {
		return lifecycleLockedState{}, lifecycleInternalError{
			kind:    securitystate.ErrDestinationLifecycleUnavailable,
			destroy: true,
		}
	}
	err := row.Scan(record.destinations()...)
	if err == pgx.ErrNoRows {
		return lifecycleLockedState{}, securitystate.ErrDestinationLifecycleConflict
	}
	if err != nil {
		return lifecycleLockedState{}, lifecycleReadError(ctx, err)
	}
	destination, err := record.destination(expectedAudience, expectedDestination, now)
	if err != nil {
		return lifecycleLockedState{}, securitystate.ErrDestinationLifecycleReconciliation
	}

	rows, err := transaction.Query(ctx, tokensSQL, expectedDestination.String())
	if err != nil {
		return lifecycleLockedState{}, lifecycleReadError(ctx, err)
	}
	if nilInterface(rows) {
		return lifecycleLockedState{}, lifecycleInternalError{
			kind:    securitystate.ErrDestinationLifecycleUnavailable,
			destroy: true,
		}
	}
	defer rows.Close()

	tokens := make([]securitystate.DestinationToken, 0, 3)
	for rows.Next() {
		if len(tokens) == 3 {
			return lifecycleLockedState{}, securitystate.ErrDestinationLifecycleReconciliation
		}
		tokenRecord := lifecycleTokenRecord{}
		if err := rows.Scan(tokenRecord.destinations()...); err != nil {
			if isConnectionInterruption(err) || lifecycleRepositoryCancellation(ctx, err) != nil {
				return lifecycleLockedState{}, lifecycleReadError(ctx, err)
			}
			return lifecycleLockedState{}, securitystate.ErrDestinationLifecycleReconciliation
		}
		token, err := tokenRecord.token(expectedAudience, destination)
		if err != nil {
			return lifecycleLockedState{}, securitystate.ErrDestinationLifecycleReconciliation
		}
		tokens = append(tokens, token)
	}
	if err := rows.Err(); err != nil {
		return lifecycleLockedState{}, lifecycleReadError(ctx, err)
	}
	snapshot, err := securitystate.NewDestinationLifecycleSnapshot(destination, tokens, now)
	if err != nil {
		return lifecycleLockedState{}, securitystate.ErrDestinationLifecycleReconciliation
	}
	return lifecycleLockedState{destination: destination, snapshot: snapshot}, nil
}

type lifecycleDestinationRecord struct {
	destinationText string
	audienceText    string
	stateText       string
	createdAt       pgtype.Timestamptz
	stateChangedAt  pgtype.Timestamptz
}

func (record *lifecycleDestinationRecord) destinations() []any {
	return []any{
		&record.destinationText,
		&record.audienceText,
		&record.stateText,
		&record.createdAt,
		&record.stateChangedAt,
	}
}

func (record lifecycleDestinationRecord) destination(
	expectedAudience securitystate.GatewayAudienceID,
	expectedDestination securitystate.DestinationID,
	now time.Time,
) (securitystate.Destination, error) {
	if !finiteTimestamp(record.createdAt) || !finiteTimestamp(record.stateChangedAt) {
		return securitystate.Destination{}, securitystate.ErrDestinationLifecycleReconciliation
	}
	if record.createdAt.Time.After(now) || record.stateChangedAt.Time.After(now) {
		return securitystate.Destination{}, securitystate.ErrDestinationLifecycleReconciliation
	}
	destination, destinationErr := securitystate.ParseDestinationID(record.destinationText)
	audience, audienceErr := securitystate.ParseGatewayAudienceID(record.audienceText)
	state, stateErr := destinationState(record.stateText)
	if destinationErr != nil || audienceErr != nil || stateErr != nil ||
		destination != expectedDestination || audience != expectedAudience {
		return securitystate.Destination{}, securitystate.ErrDestinationLifecycleReconciliation
	}
	value, err := securitystate.NewDestination(
		audience,
		destination,
		state,
		record.createdAt.Time,
		record.stateChangedAt.Time,
	)
	if err != nil {
		return securitystate.Destination{}, securitystate.ErrDestinationLifecycleReconciliation
	}
	return value, nil
}

type lifecycleTokenRecord struct {
	recordText            string
	audienceText          string
	destinationText       string
	verifierBytes         []byte
	keyIDText             string
	stateText             string
	createdAt             pgtype.Timestamptz
	activatedAt           pgtype.Timestamptz
	retirementStartedAt   pgtype.Timestamptz
	revokedAt             pgtype.Timestamptz
	expiresAt             pgtype.Timestamptz
	stagedCleanupDeadline pgtype.Timestamptz
	retirementDeadline    pgtype.Timestamptz
	stateChangedAt        pgtype.Timestamptz
}

func (record *lifecycleTokenRecord) destinations() []any {
	return []any{
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
	}
}

func (record lifecycleTokenRecord) token(
	expectedAudience securitystate.GatewayAudienceID,
	destination securitystate.Destination,
) (securitystate.DestinationToken, error) {
	if !finiteTimestamp(record.createdAt) || !finiteTimestamp(record.expiresAt) ||
		!finiteTimestamp(record.stagedCleanupDeadline) || !finiteTimestamp(record.stateChangedAt) {
		return securitystate.DestinationToken{}, securitystate.ErrDestinationLifecycleReconciliation
	}
	recordID, recordErr := securitystate.ParseDestinationTokenRecordID(record.recordText)
	audience, audienceErr := securitystate.ParseGatewayAudienceID(record.audienceText)
	destinationID, destinationErr := securitystate.ParseDestinationID(record.destinationText)
	verifier, verifierErr := securitystate.NewTokenVerifier(record.verifierBytes)
	keyID, keyIDErr := securitystate.NewDestinationVerifierKeyID(record.keyIDText)
	state, stateErr := destinationTokenState(record.stateText)
	activatedAt, activatedErr := optionalFiniteTime(record.activatedAt)
	retirementStartedAt, retirementStartedErr := optionalFiniteTime(record.retirementStartedAt)
	revokedAt, revokedErr := optionalFiniteTime(record.revokedAt)
	retirementDeadline, retirementDeadlineErr := optionalFiniteTime(record.retirementDeadline)
	if recordErr != nil || audienceErr != nil || destinationErr != nil || verifierErr != nil || keyIDErr != nil ||
		stateErr != nil || activatedErr != nil || retirementStartedErr != nil || revokedErr != nil ||
		retirementDeadlineErr != nil || audience != expectedAudience || destinationID != destination.ID() ||
		destination.AudienceID() != audience {
		return securitystate.DestinationToken{}, securitystate.ErrDestinationLifecycleReconciliation
	}
	value, err := securitystate.NewDestinationToken(securitystate.DestinationTokenSpec{
		AudienceID:            audience,
		Destination:           destination,
		RecordID:              recordID,
		Verifier:              verifier,
		VerifierKeyID:         keyID,
		State:                 state,
		CreatedAt:             record.createdAt.Time,
		ActivatedAt:           activatedAt,
		RetirementStartedAt:   retirementStartedAt,
		RevokedAt:             revokedAt,
		ExpiresAt:             record.expiresAt.Time,
		StagedCleanupDeadline: record.stagedCleanupDeadline.Time,
		RetirementDeadline:    retirementDeadline,
		StateChangedAt:        record.stateChangedAt.Time,
	})
	if err != nil {
		return securitystate.DestinationToken{}, securitystate.ErrDestinationLifecycleReconciliation
	}
	return value, nil
}

func lifecycleRotationPair(
	state lifecycleLockedState,
	newActiveID securitystate.DestinationTokenRecordID,
	oldRetiringID securitystate.DestinationTokenRecordID,
	now time.Time,
	allowRetiringStale bool,
) (securitystate.LifecycleTokenView, securitystate.LifecycleTokenView, error) {
	active, hasActive := state.snapshot.Active()
	retiring, hasRetiring := state.snapshot.Retiring()
	_, hasStaged := state.snapshot.Staged()
	if !hasActive || !hasRetiring || hasStaged || active.RecordID() != newActiveID ||
		retiring.RecordID() != oldRetiringID {
		return securitystate.LifecycleTokenView{}, securitystate.LifecycleTokenView{},
			securitystate.ErrDestinationLifecycleConflict
	}
	if !state.destination.Enabled() || !now.Before(active.ExpiresAt()) ||
		active.ActivatedAt().After(now) || active.StateChangedAt().After(now) ||
		retiring.ActivatedAt().After(now) || retiring.RetirementStartedAt().After(now) ||
		retiring.StateChangedAt().After(now) ||
		!active.ActivatedAt().Equal(active.StateChangedAt()) ||
		!active.ActivatedAt().Equal(retiring.RetirementStartedAt()) ||
		!retiring.RetirementStartedAt().Equal(retiring.StateChangedAt()) ||
		retiring.RetirementDeadline().IsZero() {
		return securitystate.LifecycleTokenView{}, securitystate.LifecycleTokenView{},
			securitystate.ErrDestinationLifecycleReconciliation
	}
	if !allowRetiringStale && !now.Before(retiring.ExpiresAt()) {
		return securitystate.LifecycleTokenView{}, securitystate.LifecycleTokenView{},
			securitystate.ErrDestinationLifecycleReconciliation
	}
	return active, retiring, nil
}

func lifecycleStagedAbortAllowed(
	state lifecycleLockedState,
	staged securitystate.LifecycleTokenView,
	now time.Time,
) error {
	switch state.snapshot.Status() {
	case securitystate.LifecycleStagedInitial, securitystate.LifecycleActiveWithStaged:
		return nil
	case securitystate.LifecycleReconciliationRequired:
	default:
		return securitystate.ErrDestinationLifecycleConflict
	}

	// Abort is the exact cleanup primitive for a staged row whose own token or
	// cleanup deadline has elapsed. It must not use that narrow exception to
	// conceal a disabled destination, a future-dated row, or a stale active row.
	if !state.destination.Enabled() || staged.StateChangedAt().After(now) ||
		(now.Before(staged.ExpiresAt()) && now.Before(staged.StagedCleanupDeadline())) {
		return securitystate.ErrDestinationLifecycleReconciliation
	}
	active, hasActive := state.snapshot.Active()
	if !hasActive {
		return nil
	}
	if active.ActivatedAt().After(now) || active.StateChangedAt().After(now) || !now.Before(active.ExpiresAt()) {
		return securitystate.ErrDestinationLifecycleReconciliation
	}
	return nil
}

func lifecycleRowsAffected(tag pgconn.CommandTag) error {
	switch tag.RowsAffected() {
	case 1:
		return nil
	case 0:
		return securitystate.ErrDestinationLifecycleConflict
	default:
		return securitystate.ErrDestinationLifecycleReconciliation
	}
}

func lifecycleMutationError(err error) error {
	if cancellation := lifecycleRepositoryCancellation(nil, err); cancellation != nil {
		return lifecycleInternalError{kind: cancellation, destroy: isConnectionInterruption(err)}
	}
	if isConnectionInterruption(err) {
		return lifecycleInternalError{kind: securitystate.ErrDestinationLifecycleUnavailable, destroy: true}
	}
	if name := lifecycleConstraintName(err); name != "" {
		switch name {
		case "gateway_destination_tokens_one_staged_per_destination",
			"gateway_destination_tokens_one_active_per_destination",
			"gateway_destination_tokens_one_retiring_per_destination":
			return securitystate.ErrDestinationLifecycleConflict
		default:
			return securitystate.ErrDestinationLifecycleUnavailable
		}
	}
	return securitystate.ErrDestinationLifecycleUnavailable
}

type lifecycleInternalError struct {
	kind    error
	destroy bool
}

func (err lifecycleInternalError) Error() string {
	return "destination token lifecycle operation failed"
}

func (err lifecycleInternalError) Is(target error) bool { return target == err.kind }

func lifecycleReadError(ctx context.Context, err error) error {
	if cancellation := lifecycleRepositoryCancellation(ctx, err); cancellation != nil {
		return lifecycleInternalError{kind: cancellation, destroy: isConnectionInterruption(err)}
	}
	return lifecycleInternalError{
		kind:    securitystate.ErrDestinationLifecycleUnavailable,
		destroy: isConnectionInterruption(err),
	}
}

func lifecycleErrorRequiresDestroy(err error) bool {
	var internal lifecycleInternalError
	return errors.As(err, &internal) && internal.destroy
}

func lifecycleConstraintName(err error) string {
	if !singleCausePostgresError(err) {
		return ""
	}
	var postgresError *pgconn.PgError
	if errors.As(err, &postgresError) && postgresError.Code == "23505" {
		return postgresError.ConstraintName
	}
	return ""
}

func validateLifecycleRepositoryInput(
	repository *DestinationTokenLifecycleRepository,
	ctx context.Context,
	audience securitystate.GatewayAudienceID,
	destination securitystate.DestinationID,
	now time.Time,
) error {
	if repository == nil || repository.acquire == nil || repository.rollbackTimeout <= 0 || nilInterface(ctx) ||
		audience.IsZero() || destination.IsZero() || now.IsZero() {
		return lifecycleRepositoryError(securitystate.ErrDestinationLifecycleInvalid, "lifecycle repository input")
	}
	if cancellation := lifecycleRepositoryCancellation(ctx, nil); cancellation != nil {
		return lifecycleRepositoryError(cancellation, "lifecycle repository canceled")
	}
	return nil
}

func lifecycleConnectionError(ctx context.Context, err error, operation string) error {
	if cancellation := lifecycleRepositoryCancellation(ctx, err); cancellation != nil {
		return lifecycleRepositoryError(cancellation, operation)
	}
	return lifecycleRepositoryError(securitystate.ErrDestinationLifecycleUnavailable, operation)
}

func lifecycleRepositoryCancellation(ctx context.Context, err error) error {
	if errors.Is(err, context.Canceled) || (!nilInterface(ctx) && errors.Is(ctx.Err(), context.Canceled)) {
		return securitystate.ErrDestinationLifecycleCanceled
	}
	if errors.Is(err, context.DeadlineExceeded) || (!nilInterface(ctx) && errors.Is(ctx.Err(), context.DeadlineExceeded)) {
		return securitystate.ErrDestinationLifecycleDeadline
	}
	return nil
}

func lifecycleRepositoryError(kind error, operation string) error {
	return safeError(kind, operation)
}
