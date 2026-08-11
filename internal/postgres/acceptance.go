package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/duj4/ms-oncall-gateway/internal/durable"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	acceptanceRollbackTimeout = 5 * time.Second
	identityConstraintName    = "durable_acceptances_delivery_identity_unique"
	receiptConstraintName     = "durable_acceptances_pkey"
)

const insertAcceptanceSQL = `
	insert into durable_acceptances (
		receipt_id,
		core_principal_id,
		destination_id,
		core_delivery_identity,
		canonical_event_format_version,
		canonical_event_ciphertext,
		canonical_event_nonce,
		canonical_event_digest_ciphertext,
		canonical_event_digest_nonce,
		encryption_key_id
	)
	values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	on conflict on constraint durable_acceptances_delivery_identity_unique
	do nothing
	returning receipt_id::text
`

const selectAcceptanceSQL = `
	select
		receipt_id::text,
		canonical_event_format_version,
		canonical_event_digest_ciphertext,
		canonical_event_digest_nonce,
		encryption_key_id
	from durable_acceptances
	where core_principal_id = $1
	  and destination_id = $2
	  and core_delivery_identity = $3
`

type acceptanceTransaction interface {
	QueryRow(context.Context, string, ...any) pgx.Row
	Commit(context.Context) error
	Rollback(context.Context) error
}

type acceptanceConnection interface {
	Begin(context.Context, pgx.TxOptions) (acceptanceTransaction, error)
	Release()
	Destroy()
}

type AcceptanceRepository struct {
	acquire         func(context.Context) (acceptanceConnection, error)
	rollbackTimeout time.Duration
}

func NewAcceptanceRepository(pool Pool) *AcceptanceRepository {
	return newAcceptanceRepository(func(ctx context.Context) (acceptanceConnection, error) {
		connection, err := pool.Acquire(ctx)
		if err != nil {
			return nil, err
		}
		return &pgAcceptanceConnection{connection: connection}, nil
	})
}

func newAcceptanceRepository(acquire func(context.Context) (acceptanceConnection, error)) *AcceptanceRepository {
	return &AcceptanceRepository{acquire: acquire, rollbackTimeout: acceptanceRollbackTimeout}
}

type pgAcceptanceConnection struct {
	connection *pgxpool.Conn
}

func (connection *pgAcceptanceConnection) Begin(ctx context.Context, options pgx.TxOptions) (acceptanceTransaction, error) {
	return connection.connection.BeginTx(ctx, options)
}

func (connection *pgAcceptanceConnection) Release() {
	connection.connection.Release()
}

func (connection *pgAcceptanceConnection) Destroy() {
	destroyPoolConnection(connection.connection)
}

func (repository *AcceptanceRepository) InsertOrLoad(ctx context.Context, candidate durable.Candidate) (durable.PersistenceResult, error) {
	if repository == nil || repository.acquire == nil {
		return durable.PersistenceResult{}, safeError(durable.ErrStoreFailure, "durable acceptance configuration")
	}
	connection, err := repository.acquire(ctx)
	if err != nil {
		if contextFailure(ctx, err) {
			return durable.PersistenceResult{}, safeError(durable.ErrStoreCanceled, "durable acceptance connection")
		}
		return durable.PersistenceResult{}, safeError(durable.ErrStoreUnavailable, "durable acceptance connection")
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
	if err != nil {
		if isConnectionInterruption(err) {
			connection.Destroy()
			release = false
			if contextFailure(ctx, err) {
				return durable.PersistenceResult{}, safeError(durable.ErrStoreCanceled, "durable acceptance begin")
			}
			return durable.PersistenceResult{}, safeError(durable.ErrStoreUnavailable, "durable acceptance begin")
		}
		return durable.PersistenceResult{}, safeError(durable.ErrStoreFailure, "durable acceptance begin")
	}
	transactionOpen := true
	rollback := func(kind error, destroy bool, operation string) (durable.PersistenceResult, error) {
		rollbackCtx, cancel := boundedCleanupContext(ctx, repository.rollbackTimeout)
		rollbackErr := transaction.Rollback(rollbackCtx)
		cancel()
		transactionOpen = false
		if rollbackErr != nil && !errors.Is(rollbackErr, pgx.ErrTxClosed) {
			connection.Destroy()
			release = false
			return durable.PersistenceResult{}, safeError(durable.ErrStoreOutcomeUnknown, "durable acceptance cleanup")
		}
		if destroy {
			connection.Destroy()
			release = false
		}
		return durable.PersistenceResult{}, safeError(kind, operation)
	}
	defer func() {
		if transactionOpen {
			rollbackCtx, cancel := boundedCleanupContext(ctx, repository.rollbackTimeout)
			_ = transaction.Rollback(rollbackCtx)
			cancel()
		}
	}()

	acceptance := candidate.Acceptance
	event := acceptance.CanonicalEvent()
	protectedDigest := acceptance.ProtectedDigest()
	var insertedReceipt string
	err = transaction.QueryRow(
		ctx,
		insertAcceptanceSQL,
		candidate.ReceiptID.String(),
		acceptance.CorePrincipalID(),
		acceptance.DestinationID(),
		acceptance.DeliveryIdentity().String(),
		acceptance.FormatVersion(),
		event.Ciphertext(),
		event.Nonce(),
		protectedDigest.Ciphertext(),
		protectedDigest.Nonce(),
		acceptance.EncryptionKeyID(),
	).Scan(&insertedReceipt)
	if err == nil {
		persistedReceipt, parseErr := durable.ParseReceiptID(insertedReceipt)
		if parseErr != nil || persistedReceipt != candidate.ReceiptID {
			return rollback(durable.ErrStoreFailure, false, "durable acceptance insert result")
		}
		if commitErr := transaction.Commit(ctx); commitErr != nil {
			transactionOpen = false
			connection.Destroy()
			release = false
			return durable.PersistenceResult{}, safeError(durable.ErrStoreOutcomeUnknown, "durable acceptance commit")
		}
		transactionOpen = false
		return durable.PersistenceResult{
			Inserted: true,
			Stored: durable.StoredAcceptance{
				ReceiptID: candidate.ReceiptID,
			},
		}, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		if contextFailure(ctx, err) {
			return rollback(durable.ErrStoreCanceled, false, "durable acceptance insert")
		}
		if isConnectionInterruption(err) {
			return rollback(durable.ErrStoreOutcomeUnknown, true, "durable acceptance insert")
		}
		return rollback(durable.ErrStoreFailure, false, "durable acceptance insert")
	}

	var (
		storedReceiptString string
		storedVersion       int64
		storedCiphertext    []byte
		storedNonce         []byte
		storedKeyID         string
	)
	err = transaction.QueryRow(
		ctx,
		selectAcceptanceSQL,
		acceptance.CorePrincipalID(),
		acceptance.DestinationID(),
		acceptance.DeliveryIdentity().String(),
	).Scan(
		&storedReceiptString,
		&storedVersion,
		&storedCiphertext,
		&storedNonce,
		&storedKeyID,
	)
	if err != nil {
		if contextFailure(ctx, err) {
			return rollback(durable.ErrStoreCanceled, false, "durable acceptance lookup")
		}
		if isConnectionInterruption(err) {
			return rollback(durable.ErrStoreUnavailable, true, "durable acceptance lookup")
		}
		return rollback(durable.ErrStoreFailure, false, "durable acceptance lookup")
	}
	storedReceipt, parseErr := durable.ParseReceiptID(storedReceiptString)
	storedDigest, protectedErr := durable.NewProtectedValue(storedCiphertext, storedNonce)
	if parseErr != nil || protectedErr != nil || storedVersion <= 0 || storedKeyID == "" {
		return rollback(durable.ErrStoredRecordUnreadable, false, "durable acceptance stored record")
	}
	if commitErr := transaction.Commit(ctx); commitErr != nil {
		transactionOpen = false
		connection.Destroy()
		release = false
		return durable.PersistenceResult{}, safeError(durable.ErrStoreOutcomeUnknown, "durable acceptance commit")
	}
	transactionOpen = false
	return durable.PersistenceResult{
		Stored: durable.StoredAcceptance{
			ReceiptID:       storedReceipt,
			FormatVersion:   storedVersion,
			ProtectedDigest: storedDigest,
			EncryptionKeyID: storedKeyID,
		},
	}, nil
}

func contextFailure(ctx context.Context, err error) bool {
	return errors.Is(err, context.Canceled) ||
		errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(ctx.Err(), context.Canceled) ||
		errors.Is(ctx.Err(), context.DeadlineExceeded)
}

func constraintName(err error) string {
	var postgresError *pgconn.PgError
	if errors.As(err, &postgresError) && postgresError.Code == "23505" {
		return postgresError.ConstraintName
	}
	return ""
}
