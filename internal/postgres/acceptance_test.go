package postgres

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/duj4/ms-oncall-gateway/internal/durable"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type acceptanceRowResult struct {
	values []any
	err    error
}

type fakeAcceptanceRow struct {
	result acceptanceRowResult
}

func (row fakeAcceptanceRow) Scan(destinations ...any) error {
	if row.result.err != nil {
		return row.result.err
	}
	if len(destinations) != len(row.result.values) {
		return errors.New("unexpected scan arity")
	}
	for index, value := range row.result.values {
		switch destination := destinations[index].(type) {
		case *string:
			*destination = value.(string)
		case *int64:
			*destination = value.(int64)
		case *[]byte:
			*destination = append((*destination)[:0], value.([]byte)...)
		default:
			return errors.New("unsupported scan destination")
		}
	}
	return nil
}

type acceptanceQuery struct {
	sql  string
	args []any
}

type fakeAcceptanceTransaction struct {
	rows             []acceptanceRowResult
	queries          []acceptanceQuery
	commitErr        error
	commitCalls      int
	rollbackErr      error
	rollbackWait     bool
	rollbackCalls    int
	rollbackDeadline time.Time
	rollbackBounded  bool
}

func (transaction *fakeAcceptanceTransaction) QueryRow(_ context.Context, sql string, args ...any) pgx.Row {
	transaction.queries = append(transaction.queries, acceptanceQuery{sql: sql, args: append([]any(nil), args...)})
	index := len(transaction.queries) - 1
	if index >= len(transaction.rows) {
		return fakeAcceptanceRow{result: acceptanceRowResult{err: errors.New("unexpected query")}}
	}
	return fakeAcceptanceRow{result: transaction.rows[index]}
}

func (transaction *fakeAcceptanceTransaction) Commit(context.Context) error {
	transaction.commitCalls++
	return transaction.commitErr
}

func (transaction *fakeAcceptanceTransaction) Rollback(ctx context.Context) error {
	transaction.rollbackCalls++
	transaction.rollbackDeadline, transaction.rollbackBounded = ctx.Deadline()
	if transaction.rollbackWait {
		<-ctx.Done()
		return ctx.Err()
	}
	return transaction.rollbackErr
}

type fakeAcceptanceConnection struct {
	transaction  acceptanceTransaction
	beginErr     error
	beginCalls   int
	beginOptions []pgx.TxOptions
	releaseCalls int
	destroyCalls int
}

func (connection *fakeAcceptanceConnection) Begin(_ context.Context, options pgx.TxOptions) (acceptanceTransaction, error) {
	connection.beginCalls++
	connection.beginOptions = append(connection.beginOptions, options)
	return connection.transaction, connection.beginErr
}

func (connection *fakeAcceptanceConnection) Release() { connection.releaseCalls++ }
func (connection *fakeAcceptanceConnection) Destroy() { connection.destroyCalls++ }

func acceptanceTestReceipt(seed byte) durable.ReceiptID {
	var receipt durable.ReceiptID
	for index := range receipt {
		receipt[index] = seed + byte(index)
	}
	return receipt
}

func acceptanceTestIdentity(seed byte) durable.DeliveryIdentity {
	var identity durable.DeliveryIdentity
	for index := range identity {
		identity[index] = seed + byte(index)
	}
	return identity
}

func acceptanceTestCandidate(t *testing.T) durable.Candidate {
	t.Helper()
	event, err := durable.NewProtectedValue([]byte("event-ciphertext"), []byte("event-nonce"))
	if err != nil {
		t.Fatal(err)
	}
	digest, err := durable.NewProtectedValue([]byte("digest-ciphertext"), []byte("digest-nonce"))
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := durable.NewPreparedAcceptance(
		"principal-value",
		"destination-value",
		acceptanceTestIdentity(2),
		3,
		event,
		digest,
		"key-value",
		durable.CanonicalDigest{1},
	)
	if err != nil {
		t.Fatal(err)
	}
	return durable.Candidate{ReceiptID: acceptanceTestReceipt(10), Acceptance: prepared}
}

func repositoryWithTransaction(transaction *fakeAcceptanceTransaction) (*AcceptanceRepository, *fakeAcceptanceConnection, *int) {
	connection := &fakeAcceptanceConnection{transaction: transaction}
	acquireCalls := 0
	repository := newAcceptanceRepository(func(context.Context) (acceptanceConnection, error) {
		acquireCalls++
		return connection, nil
	})
	return repository, connection, &acquireCalls
}

func TestAcceptanceRepositoryInsertCommitsNewRecord(t *testing.T) {
	candidate := acceptanceTestCandidate(t)
	transaction := &fakeAcceptanceTransaction{rows: []acceptanceRowResult{{values: []any{candidate.ReceiptID.String()}}}}
	repository, connection, acquireCalls := repositoryWithTransaction(transaction)

	result, err := repository.InsertOrLoad(context.Background(), candidate)
	if err != nil {
		t.Fatalf("InsertOrLoad: %v", err)
	}
	if !result.Inserted || result.Stored.ReceiptID != candidate.ReceiptID {
		t.Errorf("result = %+v, want inserted candidate receipt", result)
	}
	if *acquireCalls != 1 || connection.beginCalls != 1 || len(transaction.queries) != 1 || transaction.commitCalls != 1 {
		t.Errorf("calls acquire/begin/query/commit = %d/%d/%d/%d", *acquireCalls, connection.beginCalls, len(transaction.queries), transaction.commitCalls)
	}
	if connection.releaseCalls != 1 || connection.destroyCalls != 0 || transaction.rollbackCalls != 0 {
		t.Errorf("cleanup release/destroy/rollback = %d/%d/%d", connection.releaseCalls, connection.destroyCalls, transaction.rollbackCalls)
	}
	options := connection.beginOptions[0]
	if options.IsoLevel != pgx.ReadCommitted || options.AccessMode != pgx.ReadWrite {
		t.Errorf("transaction options = %+v, want read committed/read write", options)
	}
	query := transaction.queries[0]
	if !strings.Contains(query.sql, "on conflict on constraint "+identityConstraintName) ||
		!strings.Contains(query.sql, "do nothing") ||
		!strings.Contains(query.sql, "returning receipt_id") {
		t.Errorf("insert SQL does not use the named identity constraint: %q", query.sql)
	}
	if len(query.args) != 10 || query.args[0] != candidate.ReceiptID.String() || query.args[3] != candidate.Acceptance.DeliveryIdentity().String() {
		t.Errorf("insert arguments do not carry the candidate and delivery identity")
	}
}

func TestAcceptanceRepositoryNoRowsPerformsIndependentSelectAndReturnsStableRecord(t *testing.T) {
	candidate := acceptanceTestCandidate(t)
	existingReceipt := acceptanceTestReceipt(30)
	transaction := &fakeAcceptanceTransaction{rows: []acceptanceRowResult{
		{err: pgx.ErrNoRows},
		{values: []any{existingReceipt.String(), int64(3), []byte("stored-ciphertext"), []byte("stored-nonce"), "stored-key"}},
	}}
	repository, connection, _ := repositoryWithTransaction(transaction)

	result, err := repository.InsertOrLoad(context.Background(), candidate)
	if err != nil {
		t.Fatalf("InsertOrLoad: %v", err)
	}
	if result.Inserted || result.Stored.ReceiptID != existingReceipt || result.Stored.FormatVersion != 3 || result.Stored.EncryptionKeyID != "stored-key" {
		t.Errorf("stored result = %+v", result)
	}
	if len(transaction.queries) != 2 || !strings.Contains(transaction.queries[1].sql, "from durable_acceptances") {
		t.Fatalf("queries = %d, want INSERT then separate SELECT", len(transaction.queries))
	}
	if transaction.queries[0].sql == transaction.queries[1].sql {
		t.Error("collision lookup reused the INSERT statement instead of a separate SELECT")
	}
	if transaction.commitCalls != 1 || connection.releaseCalls != 1 || connection.destroyCalls != 0 {
		t.Errorf("commit/release/destroy = %d/%d/%d", transaction.commitCalls, connection.releaseCalls, connection.destroyCalls)
	}
}

func TestAcceptanceRepositoryDistinguishesIdentityConflictFromReceiptCollision(t *testing.T) {
	candidate := acceptanceTestCandidate(t)
	identityCollision := &fakeAcceptanceTransaction{rows: []acceptanceRowResult{
		{err: pgx.ErrNoRows},
		{values: []any{acceptanceTestReceipt(40).String(), int64(3), []byte("ciphertext"), []byte("nonce"), "key"}},
	}}
	repository, _, _ := repositoryWithTransaction(identityCollision)
	if _, err := repository.InsertOrLoad(context.Background(), candidate); err != nil {
		t.Fatalf("identity collision lookup failed: %v", err)
	}

	receiptCollisionError := &pgconn.PgError{Code: "23505", ConstraintName: receiptConstraintName, Message: "private receipt collision detail"}
	receiptCollision := &fakeAcceptanceTransaction{rows: []acceptanceRowResult{{err: receiptCollisionError}}}
	repository, connection, acquireCalls := repositoryWithTransaction(receiptCollision)
	_, err := repository.InsertOrLoad(context.Background(), candidate)
	if !errors.Is(err, durable.ErrStoreFailure) || strings.Contains(err.Error(), "private") {
		t.Fatalf("receipt collision error = %v, want redacted store failure", err)
	}
	if constraintName(receiptCollisionError) != receiptConstraintName {
		t.Error("receipt primary-key collision was not structurally identified")
	}
	if *acquireCalls != 1 || len(receiptCollision.queries) != 1 || connection.releaseCalls != 1 || connection.destroyCalls != 0 {
		t.Errorf("receipt collision was retried or destroyed unexpectedly")
	}
}

func TestAcceptanceRepositoryFailureClassificationCleanupAndNoReplay(t *testing.T) {
	privateText := "principal destination delivery receipt ciphertext nonce digest key DSN host username certificate SQL"
	candidate := acceptanceTestCandidate(t)
	tests := []struct {
		name        string
		ctx         func() (context.Context, context.CancelFunc)
		acquireErr  error
		beginErr    error
		rows        []acceptanceRowResult
		commitErr   error
		rollbackErr error
		want        error
		wantDestroy bool
		wantRelease bool
	}{
		{name: "acquire unavailable", acquireErr: &net.OpError{Op: "dial", Net: "tcp", Err: io.EOF}, want: durable.ErrStoreUnavailable},
		{name: "begin unavailable", beginErr: &net.OpError{Op: "read", Net: "tcp", Err: io.EOF}, want: durable.ErrStoreUnavailable, wantDestroy: true},
		{name: "ordinary insert failure", rows: []acceptanceRowResult{{err: &pgconn.PgError{Code: "42501", Message: privateText}}}, want: durable.ErrStoreFailure, wantRelease: true},
		{name: "insert interruption", rows: []acceptanceRowResult{{err: &net.OpError{Op: "read", Net: "tcp", Err: io.EOF}}}, want: durable.ErrStoreOutcomeUnknown, wantDestroy: true},
		{name: "lookup interruption", rows: []acceptanceRowResult{{err: pgx.ErrNoRows}, {err: &net.OpError{Op: "read", Net: "tcp", Err: io.EOF}}}, want: durable.ErrStoreUnavailable, wantDestroy: true},
		{name: "commit unknown", rows: []acceptanceRowResult{{values: []any{candidate.ReceiptID.String()}}}, commitErr: &net.OpError{Op: "write", Net: "tcp", Err: io.EOF}, want: durable.ErrStoreOutcomeUnknown, wantDestroy: true},
		{name: "rollback unknown", rows: []acceptanceRowResult{{err: &pgconn.PgError{Code: "42501", Message: privateText}}}, rollbackErr: errors.New(privateText), want: durable.ErrStoreOutcomeUnknown, wantDestroy: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			transaction := &fakeAcceptanceTransaction{rows: test.rows, commitErr: test.commitErr, rollbackErr: test.rollbackErr}
			connection := &fakeAcceptanceConnection{transaction: transaction, beginErr: test.beginErr}
			acquireCalls := 0
			repository := newAcceptanceRepository(func(context.Context) (acceptanceConnection, error) {
				acquireCalls++
				if test.acquireErr != nil {
					return nil, test.acquireErr
				}
				return connection, nil
			})
			_, err := repository.InsertOrLoad(ctx, candidate)
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
			if strings.Contains(err.Error(), privateText) || strings.Contains(err.Error(), "principal") {
				t.Fatalf("error leaked sensitive details: %v", err)
			}
			if acquireCalls != 1 || connection.beginCalls > 1 || len(transaction.queries) > len(test.rows) {
				t.Errorf("operation was retried: acquire/begin/query = %d/%d/%d", acquireCalls, connection.beginCalls, len(transaction.queries))
			}
			if (connection.destroyCalls == 1) != test.wantDestroy {
				t.Errorf("destroy calls = %d, want destroy %t", connection.destroyCalls, test.wantDestroy)
			}
			if (connection.releaseCalls == 1) != test.wantRelease {
				t.Errorf("release calls = %d, want release %t", connection.releaseCalls, test.wantRelease)
			}
		})
	}
}

func TestAcceptanceRepositoryCancellationAndRollbackAreBounded(t *testing.T) {
	candidate := acceptanceTestCandidate(t)

	t.Run("canceled request with confirmed rollback", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		transaction := &fakeAcceptanceTransaction{rows: []acceptanceRowResult{{err: context.Canceled}}}
		repository, connection, _ := repositoryWithTransaction(transaction)
		cancel()
		_, err := repository.InsertOrLoad(ctx, candidate)
		if !errors.Is(err, durable.ErrStoreCanceled) {
			t.Fatalf("error = %v, want ErrStoreCanceled", err)
		}
		if transaction.rollbackCalls != 1 || !transaction.rollbackBounded {
			t.Errorf("rollback calls/bounded = %d/%t", transaction.rollbackCalls, transaction.rollbackBounded)
		}
		if connection.releaseCalls != 1 || connection.destroyCalls != 0 {
			t.Errorf("release/destroy = %d/%d", connection.releaseCalls, connection.destroyCalls)
		}
	})

	t.Run("parent deadline is rollback upper bound", func(t *testing.T) {
		deadline := time.Now().Add(time.Second)
		ctx, cancel := context.WithDeadline(context.Background(), deadline)
		defer cancel()
		transaction := &fakeAcceptanceTransaction{rows: []acceptanceRowResult{{err: &pgconn.PgError{Code: "42501"}}}}
		repository, _, _ := repositoryWithTransaction(transaction)
		_, _ = repository.InsertOrLoad(ctx, candidate)
		if !transaction.rollbackBounded || transaction.rollbackDeadline.After(deadline) {
			t.Errorf("rollback deadline = %s, parent = %s", transaction.rollbackDeadline, deadline)
		}
	})

	t.Run("rollback timeout becomes unknown and destroys connection", func(t *testing.T) {
		transaction := &fakeAcceptanceTransaction{
			rows:         []acceptanceRowResult{{err: &pgconn.PgError{Code: "42501"}}},
			rollbackWait: true,
		}
		repository, connection, _ := repositoryWithTransaction(transaction)
		repository.rollbackTimeout = 10 * time.Millisecond
		started := time.Now()
		_, err := repository.InsertOrLoad(context.Background(), candidate)
		if time.Since(started) > time.Second {
			t.Fatal("rollback did not return within its local bound")
		}
		if !errors.Is(err, durable.ErrStoreOutcomeUnknown) || connection.destroyCalls != 1 || connection.releaseCalls != 0 {
			t.Errorf("error/destroy/release = %v/%d/%d", err, connection.destroyCalls, connection.releaseCalls)
		}
	})
}
