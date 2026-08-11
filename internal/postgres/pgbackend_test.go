package postgres

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

type fakeMigrationTransaction struct {
	statements    []string
	failStatement int
	execErrors    map[int]error
	commitErr     error
	rollbackErr   error
	rollbackWait  bool
	rollbackCalls int
	rollbackLimit time.Time
	rollbackBound bool
	committed     bool
	rolledBack    bool
}

func (t *fakeMigrationTransaction) Exec(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
	t.statements = append(t.statements, sql)
	if err := t.execErrors[len(t.statements)]; err != nil {
		return pgconn.CommandTag{}, err
	}
	if len(t.statements) == t.failStatement {
		return pgconn.CommandTag{}, errors.New("private SQL failure details")
	}
	return pgconn.NewCommandTag("OK"), nil
}

func (t *fakeMigrationTransaction) Commit(context.Context) error {
	if t.commitErr != nil {
		return t.commitErr
	}
	t.committed = true
	return nil
}

func (t *fakeMigrationTransaction) Rollback(ctx context.Context) error {
	t.rollbackCalls++
	t.rollbackLimit, t.rollbackBound = ctx.Deadline()
	if t.rollbackWait {
		<-ctx.Done()
		return ctx.Err()
	}
	t.rolledBack = true
	return t.rollbackErr
}

func TestApplyMigrationCommitsDDLAndMetadataAtomically(t *testing.T) {
	migration := Migration{Version: 1, SQL: "create table foundation (id bigint)", Checksum: strings.Repeat("a", 64)}
	transaction := &fakeMigrationTransaction{}
	err := applyMigration(context.Background(), migration, func(context.Context) (migrationTransaction, error) {
		return transaction, nil
	})
	if err != nil {
		t.Fatalf("applyMigration returned error: %v", err)
	}
	if len(transaction.statements) != 2 {
		t.Fatalf("statement count = %d, want DDL and metadata record", len(transaction.statements))
	}
	if transaction.statements[0] != migration.SQL || !strings.Contains(transaction.statements[1], "insert into gateway_schema_migrations") {
		t.Errorf("statement order did not keep DDL before metadata record")
	}
	if !transaction.committed {
		t.Error("transaction was not committed")
	}
}

func TestApplyMigrationRollsBackAndRedactsEveryFailureStage(t *testing.T) {
	tests := []struct {
		name      string
		beginErr  error
		failExec  int
		commitErr error
	}{
		{name: "begin", beginErr: errors.New("private begin details")},
		{name: "DDL", failExec: 1},
		{name: "metadata", failExec: 2},
		{name: "commit", commitErr: errors.New("private commit details")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			transaction := &fakeMigrationTransaction{failStatement: test.failExec, commitErr: test.commitErr}
			err := applyMigration(context.Background(), Migration{Version: 1, SQL: "select 1", Checksum: strings.Repeat("a", 64)}, func(context.Context) (migrationTransaction, error) {
				if test.beginErr != nil {
					return nil, test.beginErr
				}
				return transaction, nil
			})
			if !errors.Is(err, ErrMigration) {
				t.Fatalf("error = %v, want ErrMigration", err)
			}
			if strings.Contains(err.Error(), "private") {
				t.Error("migration error leaked driver details")
			}
			if test.beginErr == nil && !transaction.rolledBack {
				t.Error("rollback was not attempted")
			}
			if transaction.committed {
				t.Error("failed migration reported committed")
			}
		})
	}
}

func TestApplyMigrationRollbackContextIsBounded(t *testing.T) {
	migration := Migration{Version: 1, SQL: "select sensitive migration payload", Checksum: strings.Repeat("a", 64)}

	t.Run("local bound without parent deadline", func(t *testing.T) {
		transaction := &fakeMigrationTransaction{failStatement: 1}
		started := time.Now()
		err := applyMigration(context.Background(), migration, func(context.Context) (migrationTransaction, error) {
			return transaction, nil
		})
		if !errors.Is(err, ErrMigration) || errors.Is(err, ErrMigrationInterrupted) {
			t.Fatalf("error = %v, want ordinary migration failure", err)
		}
		if !transaction.rollbackBound {
			t.Fatal("rollback context has no deadline")
		}
		if transaction.rollbackLimit.After(started.Add(migrationRollbackTimeout + 100*time.Millisecond)) {
			t.Errorf("rollback deadline = %s, exceeds local bound", transaction.rollbackLimit)
		}
	})

	t.Run("parent deadline remains the upper bound", func(t *testing.T) {
		parentDeadline := time.Now().Add(200 * time.Millisecond)
		ctx, cancel := context.WithDeadline(context.Background(), parentDeadline)
		defer cancel()
		transaction := &fakeMigrationTransaction{failStatement: 1}
		_ = applyMigration(ctx, migration, func(context.Context) (migrationTransaction, error) {
			return transaction, nil
		})
		if !transaction.rollbackBound || transaction.rollbackLimit.After(parentDeadline) {
			t.Errorf("rollback deadline = %s, parent deadline = %s", transaction.rollbackLimit, parentDeadline)
		}
	})
}

func TestApplyMigrationCanceledParentRollbackReturnsWithinLocalBound(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	transaction := &fakeMigrationTransaction{failStatement: 1, rollbackWait: true}
	started := time.Now()
	err := applyMigrationWithRollbackTimeout(
		ctx,
		Migration{Version: 1, SQL: "select 1", Checksum: strings.Repeat("a", 64)},
		20*time.Millisecond,
		func(context.Context) (migrationTransaction, error) { return transaction, nil },
	)
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("bounded rollback took %s", elapsed)
	}
	if !errors.Is(err, ErrMigrationInterrupted) {
		t.Fatalf("error = %v, want ErrMigrationInterrupted", err)
	}
	if transaction.rollbackCalls != 1 || !transaction.rollbackBound {
		t.Errorf("rollback calls = %d, bounded = %t", transaction.rollbackCalls, transaction.rollbackBound)
	}
}

func TestApplyMigrationClassifiesInterruptionsWithoutSensitiveDetails(t *testing.T) {
	privateText := "private-host.invalid private_user private_certificate_path sensitive SQL body"
	tests := []struct {
		name       string
		beginErr   error
		execErrors map[int]error
		commitErr  error
		want       error
	}{
		{name: "context cancellation", beginErr: fmtWrap(privateText, context.Canceled), want: ErrMigrationInterrupted},
		{name: "context deadline", execErrors: map[int]error{1: fmtWrap(privateText, context.DeadlineExceeded)}, want: ErrMigrationInterrupted},
		{name: "connection loss", execErrors: map[int]error{1: &net.OpError{Op: "read", Net: "tcp", Err: io.EOF}}, want: ErrMigrationInterrupted},
		{name: "connection SQLSTATE", execErrors: map[int]error{1: &pgconn.PgError{Code: "08006", Message: privateText}}, want: ErrMigrationInterrupted},
		{name: "ordinary PostgreSQL permission error", execErrors: map[int]error{1: &pgconn.PgError{Code: "42501", Message: privateText}}, want: ErrMigration},
		{name: "commit interruption", commitErr: fmtWrap(privateText, context.DeadlineExceeded), want: ErrMigrationInterrupted},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			transaction := &fakeMigrationTransaction{execErrors: test.execErrors, commitErr: test.commitErr}
			beginCalls := 0
			err := applyMigration(context.Background(), Migration{Version: 1, SQL: privateText, Checksum: strings.Repeat("a", 64)}, func(context.Context) (migrationTransaction, error) {
				beginCalls++
				if test.beginErr != nil {
					return nil, test.beginErr
				}
				return transaction, nil
			})
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
			if test.want == ErrMigration && errors.Is(err, ErrMigrationInterrupted) {
				t.Fatalf("ordinary PostgreSQL error classified as interrupted: %v", err)
			}
			if strings.Contains(err.Error(), privateText) || strings.Contains(err.Error(), "private-host") {
				t.Error("migration error leaked driver or SQL details")
			}
			if beginCalls != 1 {
				t.Errorf("begin calls = %d, want no retry", beginCalls)
			}
		})
	}
}

func TestRollbackFailureDestroysConnectionWithoutUnlockOrRelease(t *testing.T) {
	privateText := "private rollback driver details"
	transaction := &fakeMigrationTransaction{failStatement: 1, rollbackErr: errors.New(privateText)}
	runErr := applyMigration(context.Background(), Migration{Version: 1, SQL: "select 1", Checksum: strings.Repeat("a", 64)}, func(context.Context) (migrationTransaction, error) {
		return transaction, nil
	})
	if !errors.Is(runErr, ErrMigrationInterrupted) || strings.Contains(runErr.Error(), privateText) {
		t.Fatalf("rollback failure = %v", runErr)
	}

	unlockCalls, releaseCalls, destroyCalls := 0, 0, 0
	err := finishMigrationConnection(
		runErr,
		func(context.Context) (bool, error) { unlockCalls++; return true, nil },
		func() { releaseCalls++ },
		func() { destroyCalls++ },
	)
	if !errors.Is(err, ErrMigrationInterrupted) {
		t.Fatalf("finish error = %v", err)
	}
	if unlockCalls != 0 || releaseCalls != 0 || destroyCalls != 1 {
		t.Errorf("cleanup calls unlock/release/destroy = %d/%d/%d", unlockCalls, releaseCalls, destroyCalls)
	}
}

func fmtWrap(text string, err error) error {
	return &testWrappedError{text: text, err: err}
}

type testWrappedError struct {
	text string
	err  error
}

func (e *testWrappedError) Error() string { return e.text }
func (e *testWrappedError) Unwrap() error { return e.err }

func TestMigrationAdvisoryLockKeyIsStable(t *testing.T) {
	const expected int64 = 0x4d534f4e43414c4c
	if migrationAdvisoryLockKey != expected {
		t.Errorf("migration lock key = %x, want %x", migrationAdvisoryLockKey, expected)
	}
}
