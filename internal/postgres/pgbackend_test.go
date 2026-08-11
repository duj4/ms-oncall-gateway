package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

type fakeMigrationTransaction struct {
	statements    []string
	failStatement int
	commitErr     error
	committed     bool
	rolledBack    bool
}

func (t *fakeMigrationTransaction) Exec(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
	t.statements = append(t.statements, sql)
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

func (t *fakeMigrationTransaction) Rollback(context.Context) error {
	t.rolledBack = true
	return nil
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

func TestMigrationAdvisoryLockKeyIsStable(t *testing.T) {
	const expected int64 = 0x4d534f4e43414c4c
	if migrationAdvisoryLockKey != expected {
		t.Errorf("migration lock key = %x, want %x", migrationAdvisoryLockKey, expected)
	}
}
