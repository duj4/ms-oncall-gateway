package postgres

import (
	"context"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/duj4/ms-oncall-gateway/internal/securitystate"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
)

const (
	lifecyclePGTestAudience    = "11111111-2222-3333-8444-555555555555"
	lifecyclePGTestDestination = "66666666-7777-8888-8999-aaaaaaaaaaaa"
	lifecyclePGTestRecordOne   = "88888888-9999-aaaa-8bbb-cccccccccccc"
	lifecyclePGTestRecordTwo   = "99999999-aaaa-bbbb-8ccc-dddddddddddd"
	lifecyclePGTestKeyID       = "lifecycle-postgres-test-key"
	lifecyclePGPrivateMarker   = "lifecycle-postgres-private-marker"
)

var lifecyclePGNow = time.Date(2031, time.February, 3, 4, 5, 6, 0, time.UTC)

type lifecyclePGRow struct {
	values []any
	err    error
}

type lifecyclePGTypedNilRow struct{}

func (*lifecyclePGTypedNilRow) Scan(...any) error {
	panic("typed-nil lifecycle row must not be scanned")
}

func (row lifecyclePGRow) Scan(destinations ...any) error {
	if row.err != nil {
		return row.err
	}
	if len(destinations) != len(row.values) {
		return errors.New("lifecycle fake row arity mismatch")
	}
	for index, value := range row.values {
		destination := reflect.ValueOf(destinations[index])
		if destination.Kind() != reflect.Pointer || destination.IsNil() {
			return errors.New("lifecycle fake row destination invalid")
		}
		reflected := reflect.ValueOf(value)
		if !reflected.IsValid() || !reflected.Type().AssignableTo(destination.Elem().Type()) {
			return errors.New("lifecycle fake row value invalid")
		}
		destination.Elem().Set(reflected)
	}
	return nil
}

type lifecyclePGRows struct {
	values [][]any
	err    error
	index  int
	closed bool
}

type lifecyclePGTypedNilRows struct{}

func (*lifecyclePGTypedNilRows) Close()     {}
func (*lifecyclePGTypedNilRows) Err() error { return nil }
func (*lifecyclePGTypedNilRows) Next() bool { return false }
func (*lifecyclePGTypedNilRows) Scan(...any) error {
	panic("typed-nil lifecycle rows must not be scanned")
}

func (rows *lifecyclePGRows) Close()     { rows.closed = true }
func (rows *lifecyclePGRows) Err() error { return rows.err }
func (rows *lifecyclePGRows) Next() bool { return rows.index < len(rows.values) }
func (rows *lifecyclePGRows) Scan(destinations ...any) error {
	if rows.index >= len(rows.values) {
		return errors.New("lifecycle fake rows exhausted")
	}
	err := (lifecyclePGRow{values: rows.values[rows.index]}).Scan(destinations...)
	rows.index++
	return err
}

type lifecyclePGCall struct {
	kind string
	sql  string
	args []any
}

type lifecyclePGTransaction struct {
	destinationRow pgx.Row
	tokenRows      destinationTokenLifecycleRows
	queryErr       error
	execTags       []pgconn.CommandTag
	execErrors     []error
	commitErr      error
	rollbackErr    error
	rollbackWait   bool
	calls          []lifecyclePGCall
	commitCalls    int
	rollbackCalls  int
	rollbackBound  bool
}

func (transaction *lifecyclePGTransaction) QueryRow(_ context.Context, sql string, args ...any) pgx.Row {
	transaction.calls = append(transaction.calls, lifecyclePGCall{kind: "query-row", sql: sql, args: append([]any(nil), args...)})
	return transaction.destinationRow
}

func (transaction *lifecyclePGTransaction) Query(_ context.Context, sql string, args ...any) (destinationTokenLifecycleRows, error) {
	transaction.calls = append(transaction.calls, lifecyclePGCall{kind: "query", sql: sql, args: append([]any(nil), args...)})
	return transaction.tokenRows, transaction.queryErr
}

func (transaction *lifecyclePGTransaction) Exec(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	transaction.calls = append(transaction.calls, lifecyclePGCall{kind: "exec", sql: sql, args: append([]any(nil), args...)})
	index := 0
	for _, call := range transaction.calls {
		if call.kind == "exec" {
			index++
		}
	}
	index--
	var tag pgconn.CommandTag
	if index < len(transaction.execTags) {
		tag = transaction.execTags[index]
	} else {
		tag = pgconn.NewCommandTag("UPDATE 1")
	}
	if index < len(transaction.execErrors) {
		return tag, transaction.execErrors[index]
	}
	return tag, nil
}

func (transaction *lifecyclePGTransaction) Commit(context.Context) error {
	transaction.calls = append(transaction.calls, lifecyclePGCall{kind: "commit"})
	transaction.commitCalls++
	return transaction.commitErr
}

func (transaction *lifecyclePGTransaction) Rollback(ctx context.Context) error {
	transaction.calls = append(transaction.calls, lifecyclePGCall{kind: "rollback"})
	transaction.rollbackCalls++
	_, transaction.rollbackBound = ctx.Deadline()
	if transaction.rollbackWait {
		<-ctx.Done()
		return ctx.Err()
	}
	return transaction.rollbackErr
}

type lifecyclePGConnection struct {
	transaction destinationTokenLifecycleTransaction
	beginErr    error
	beginCalls  int
	options     []pgx.TxOptions
	releases    int
	destroys    int
}

func (connection *lifecyclePGConnection) Begin(_ context.Context, options pgx.TxOptions) (destinationTokenLifecycleTransaction, error) {
	connection.beginCalls++
	connection.options = append(connection.options, options)
	return connection.transaction, connection.beginErr
}
func (connection *lifecyclePGConnection) Release() { connection.releases++ }
func (connection *lifecyclePGConnection) Destroy() { connection.destroys++ }

func lifecyclePGRepository(transaction *lifecyclePGTransaction) (*DestinationTokenLifecycleRepository, *lifecyclePGConnection, *int) {
	connection := &lifecyclePGConnection{transaction: transaction}
	acquires := 0
	repository := newDestinationTokenLifecycleRepository(func(context.Context) (destinationTokenLifecycleConnection, error) {
		acquires++
		return connection, nil
	})
	return repository, connection, &acquires
}

func lifecyclePGAudience(t *testing.T) securitystate.GatewayAudienceID {
	t.Helper()
	value, err := securitystate.ParseGatewayAudienceID(lifecyclePGTestAudience)
	if err != nil {
		t.Fatal("lifecycle postgres audience setup failed")
	}
	return value
}

func lifecyclePGDestination(t *testing.T) securitystate.DestinationID {
	t.Helper()
	value, err := securitystate.ParseDestinationID(lifecyclePGTestDestination)
	if err != nil {
		t.Fatal("lifecycle postgres destination setup failed")
	}
	return value
}

func lifecyclePGRecord(t *testing.T, value string) securitystate.DestinationTokenRecordID {
	t.Helper()
	record, err := securitystate.ParseDestinationTokenRecordID(value)
	if err != nil {
		t.Fatal("lifecycle postgres record setup failed")
	}
	return record
}

func lifecyclePGDestinationValues() []any {
	createdAt := lifecyclePGNow.Add(-time.Hour)
	return []any{
		lifecyclePGTestDestination, lifecyclePGTestAudience, "enabled",
		pgtype.Timestamptz{Time: createdAt, Valid: true},
		pgtype.Timestamptz{Time: createdAt, Valid: true},
	}
}

func lifecyclePGTokenValues(record, state string, stateChanged time.Time) []any {
	createdAt := lifecyclePGNow.Add(-10 * time.Minute)
	activated := pgtype.Timestamptz{}
	retirementStarted := pgtype.Timestamptz{}
	retirementDeadline := pgtype.Timestamptz{}
	switch state {
	case "active":
		activated = pgtype.Timestamptz{Time: stateChanged, Valid: true}
	case "retiring":
		activated = pgtype.Timestamptz{Time: stateChanged.Add(-time.Minute), Valid: true}
		retirementStarted = pgtype.Timestamptz{Time: stateChanged, Valid: true}
		retirementDeadline = pgtype.Timestamptz{Time: lifecyclePGNow.Add(6 * time.Hour), Valid: true}
	}
	return []any{
		record, lifecyclePGTestAudience, lifecyclePGTestDestination, make([]byte, 32), lifecyclePGTestKeyID,
		state, pgtype.Timestamptz{Time: createdAt, Valid: true}, activated, retirementStarted,
		pgtype.Timestamptz{}, pgtype.Timestamptz{Time: lifecyclePGNow.Add(48 * time.Hour), Valid: true},
		pgtype.Timestamptz{Time: lifecyclePGNow.Add(12 * time.Hour), Valid: true}, retirementDeadline,
		pgtype.Timestamptz{Time: stateChanged, Valid: true},
	}
}

func lifecyclePGTransactionFor(tokens ...[]any) *lifecyclePGTransaction {
	return &lifecyclePGTransaction{
		destinationRow: lifecyclePGRow{values: lifecyclePGDestinationValues()},
		tokenRows:      &lifecyclePGRows{values: tokens},
	}
}

func lifecyclePGCandidate(t *testing.T) securitystate.StagedTokenCandidate {
	t.Helper()
	verifier, err := securitystate.NewTokenVerifier(make([]byte, 32))
	if err != nil {
		t.Fatal("lifecycle postgres verifier setup failed")
	}
	keyID, err := securitystate.NewDestinationVerifierKeyID(lifecyclePGTestKeyID)
	if err != nil {
		t.Fatal("lifecycle postgres key setup failed")
	}
	candidate, err := securitystate.NewStagedTokenCandidate(
		lifecyclePGAudience(t), lifecyclePGDestination(t), lifecyclePGRecord(t, lifecyclePGTestRecordOne),
		verifier, keyID, lifecyclePGNow, lifecyclePGNow.Add(48*time.Hour), lifecyclePGNow.Add(12*time.Hour),
	)
	if err != nil {
		t.Fatal("lifecycle postgres candidate setup failed")
	}
	return candidate
}

func assertLifecyclePGSafe(t *testing.T, err, want, private error) {
	t.Helper()
	if err == nil || !errors.Is(err, want) {
		t.Fatal("lifecycle postgres error classification mismatch")
	}
	for _, forbidden := range []string{lifecyclePGPrivateMarker, lifecyclePGTestAudience, lifecyclePGTestDestination, lifecyclePGTestRecordOne, lifecyclePGTestRecordTwo, lifecyclePGTestKeyID} {
		if strings.Contains(err.Error(), forbidden) {
			t.Fatal("lifecycle postgres error exposed protected content")
		}
	}
	if private != nil && errors.Is(err, private) {
		t.Fatal("lifecycle postgres error exposed dependency chain")
	}
}

func TestDestinationTokenLifecycleCreateLocksBeforeInsert(t *testing.T) {
	transaction := lifecyclePGTransactionFor()
	repository, connection, acquires := lifecyclePGRepository(transaction)
	candidate := lifecyclePGCandidate(t)

	if err := repository.CreateStagedToken(context.Background(), candidate, lifecyclePGNow); err != nil {
		t.Fatal("lifecycle postgres staged insert failed")
	}
	if *acquires != 1 || connection.beginCalls != 1 || connection.releases != 1 || connection.destroys != 0 || transaction.commitCalls != 1 || transaction.rollbackCalls != 0 {
		t.Fatal("lifecycle postgres staged transaction lifecycle mismatch")
	}
	if options := connection.options[0]; options.AccessMode != pgx.ReadWrite || options.IsoLevel != pgx.ReadCommitted {
		t.Fatal("lifecycle mutation did not use read-write read-committed transaction")
	}
	if len(transaction.calls) != 4 || transaction.calls[0].sql != lockLifecycleDestinationSQL || transaction.calls[1].sql != lockLifecycleTokensSQL || transaction.calls[2].sql != insertLifecycleStagedTokenSQL || transaction.calls[3].kind != "commit" {
		t.Fatal("lifecycle staged insert did not lock destination and complete state first")
	}
	if len(transaction.calls[0].args) != 1 || transaction.calls[0].args[0] != lifecyclePGTestDestination || len(transaction.calls[1].args) != 1 || transaction.calls[1].args[0] != lifecyclePGTestDestination {
		t.Fatal("lifecycle lock SQL arguments mismatch")
	}
	insert := transaction.calls[2]
	if len(insert.args) != 8 || insert.args[0] != lifecyclePGTestRecordOne || insert.args[1] != lifecyclePGTestAudience || insert.args[2] != lifecyclePGTestDestination {
		t.Fatal("lifecycle staged insert arguments mismatch")
	}
	for _, argument := range insert.args {
		if text, ok := argument.(string); ok && strings.HasPrefix(text, "mso1_") {
			t.Fatal("raw lifecycle token reached SQL")
		}
	}
}

func TestDestinationTokenLifecycleRejectsDisabledDestination(t *testing.T) {
	transaction := lifecyclePGTransactionFor()
	values := lifecyclePGDestinationValues()
	values[2] = "disabled"
	transaction.destinationRow = lifecyclePGRow{values: values}
	repository, connection, _ := lifecyclePGRepository(transaction)
	err := repository.CreateStagedToken(context.Background(), lifecyclePGCandidate(t), lifecyclePGNow)
	assertLifecyclePGSafe(t, err, securitystate.ErrDestinationLifecycleReconciliation, nil)
	if transaction.commitCalls != 0 || transaction.rollbackCalls != 1 || connection.releases != 1 || connection.destroys != 0 {
		t.Fatal("disabled destination lifecycle transaction boundary mismatch")
	}
	for _, call := range transaction.calls {
		if call.kind == "exec" {
			t.Fatal("disabled destination lifecycle request mutated state")
		}
	}
}

func TestDestinationTokenLifecycleRejectsFutureDestinationState(t *testing.T) {
	transaction := lifecyclePGTransactionFor()
	values := lifecyclePGDestinationValues()
	values[4] = pgtype.Timestamptz{Time: lifecyclePGNow.Add(time.Second), Valid: true}
	transaction.destinationRow = lifecyclePGRow{values: values}
	repository, _, _ := lifecyclePGRepository(transaction)
	err := repository.CreateStagedToken(context.Background(), lifecyclePGCandidate(t), lifecyclePGNow)
	assertLifecyclePGSafe(t, err, securitystate.ErrDestinationLifecycleReconciliation, nil)
	for _, call := range transaction.calls {
		if call.kind == "exec" {
			t.Fatal("future destination state allowed lifecycle mutation")
		}
	}
}

func TestDestinationTokenLifecycleTransitionSQLAndDeadlineBoundaries(t *testing.T) {
	audience := lifecyclePGAudience(t)
	destination := lifecyclePGDestination(t)
	first := lifecyclePGRecord(t, lifecyclePGTestRecordOne)
	second := lifecyclePGRecord(t, lifecyclePGTestRecordTwo)

	tests := []struct {
		name       string
		tokens     [][]any
		invoke     func(*DestinationTokenLifecycleRepository) error
		statements []string
	}{
		{name: "initial", tokens: [][]any{lifecyclePGTokenValues(lifecyclePGTestRecordOne, "staged", lifecyclePGNow.Add(-time.Minute))}, invoke: func(repository *DestinationTokenLifecycleRepository) error {
			return repository.ActivateInitialToken(context.Background(), audience, destination, first, lifecyclePGNow)
		}, statements: []string{activateInitialLifecycleTokenSQL}},
		{name: "activate rotation", tokens: [][]any{
			lifecyclePGTokenValues(lifecyclePGTestRecordOne, "active", lifecyclePGNow.Add(-2*time.Minute)),
			lifecyclePGTokenValues(lifecyclePGTestRecordTwo, "staged", lifecyclePGNow.Add(-time.Minute)),
		}, invoke: func(repository *DestinationTokenLifecycleRepository) error {
			return repository.ActivateRotation(context.Background(), securitystate.ActivateRotationCommand{AudienceID: audience, DestinationID: destination, StagedRecordID: second, OldActiveRecordID: first, Now: lifecyclePGNow, OverlapDeadline: lifecyclePGNow.Add(6 * time.Hour)})
		}, statements: []string{retireLifecycleTokenSQL, activateRotationLifecycleTokenSQL}},
		{name: "abort", tokens: [][]any{lifecyclePGTokenValues(lifecyclePGTestRecordOne, "staged", lifecyclePGNow.Add(-time.Minute))}, invoke: func(repository *DestinationTokenLifecycleRepository) error {
			return repository.AbortStagedToken(context.Background(), audience, destination, first, lifecyclePGNow)
		}, statements: []string{revokeStagedLifecycleTokenSQL}},
		{name: "rollback", tokens: [][]any{
			lifecyclePGTokenValues(lifecyclePGTestRecordTwo, "active", lifecyclePGNow.Add(-time.Minute)),
			lifecyclePGTokenValues(lifecyclePGTestRecordOne, "retiring", lifecyclePGNow.Add(-time.Minute)),
		}, invoke: func(repository *DestinationTokenLifecycleRepository) error {
			return repository.RollbackRotation(context.Background(), securitystate.RollbackRotationCommand{AudienceID: audience, DestinationID: destination, NewActiveRecordID: second, OldRetiringRecordID: first, Now: lifecyclePGNow})
		}, statements: []string{revokeActiveLifecycleTokenSQL, restoreRetiringLifecycleTokenSQL}},
		{name: "finalize verified", tokens: [][]any{
			lifecyclePGTokenValues(lifecyclePGTestRecordTwo, "active", lifecyclePGNow.Add(-time.Minute)),
			lifecyclePGTokenValues(lifecyclePGTestRecordOne, "retiring", lifecyclePGNow.Add(-time.Minute)),
		}, invoke: func(repository *DestinationTokenLifecycleRepository) error {
			return repository.FinalizeRotation(context.Background(), securitystate.FinalizeRotationCommand{AudienceID: audience, DestinationID: destination, NewActiveRecordID: second, OldRetiringRecordID: first, Reason: securitystate.RotationVerifiedAndDrained, Now: lifecyclePGNow})
		}, statements: []string{revokeRetiringLifecycleTokenSQL}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			transaction := lifecyclePGTransactionFor(test.tokens...)
			repository, connection, _ := lifecyclePGRepository(transaction)
			if err := test.invoke(repository); err != nil {
				t.Fatal("lifecycle transition failed")
			}
			var actual []string
			for _, call := range transaction.calls {
				if call.kind == "exec" {
					actual = append(actual, call.sql)
				}
			}
			if !reflect.DeepEqual(actual, test.statements) || transaction.commitCalls != 1 || connection.releases != 1 || connection.destroys != 0 {
				t.Fatal("lifecycle transition SQL or cleanup mismatch")
			}
		})
	}

	deadlineTokens := [][]any{
		lifecyclePGTokenValues(lifecyclePGTestRecordTwo, "active", lifecyclePGNow.Add(-time.Minute)),
		lifecyclePGTokenValues(lifecyclePGTestRecordOne, "retiring", lifecyclePGNow.Add(-time.Minute)),
	}
	for _, test := range []struct {
		name   string
		now    time.Time
		reason securitystate.RotationCompletionReason
		want   error
	}{
		{name: "rollback at deadline", now: lifecyclePGNow.Add(6 * time.Hour), want: securitystate.ErrDestinationLifecycleConflict},
		{name: "deadline finalize before", now: lifecyclePGNow, reason: securitystate.RotationDeadlineElapsed, want: securitystate.ErrDestinationLifecycleConflict},
		{name: "deadline finalize exact", now: lifecyclePGNow.Add(6 * time.Hour), reason: securitystate.RotationDeadlineElapsed},
	} {
		t.Run(test.name, func(t *testing.T) {
			transaction := lifecyclePGTransactionFor(deadlineTokens...)
			repository, _, _ := lifecyclePGRepository(transaction)
			var err error
			if test.reason.Valid() {
				err = repository.FinalizeRotation(context.Background(), securitystate.FinalizeRotationCommand{AudienceID: audience, DestinationID: destination, NewActiveRecordID: second, OldRetiringRecordID: first, Reason: test.reason, Now: test.now})
			} else {
				err = repository.RollbackRotation(context.Background(), securitystate.RollbackRotationCommand{AudienceID: audience, DestinationID: destination, NewActiveRecordID: second, OldRetiringRecordID: first, Now: test.now})
			}
			if test.want == nil && err != nil || test.want != nil && !errors.Is(err, test.want) {
				t.Fatal("lifecycle deadline boundary mismatch")
			}
		})
	}
}

func TestDestinationTokenLifecycleInspectionUsesConsistentReadAndNoMutation(t *testing.T) {
	transaction := lifecyclePGTransactionFor(lifecyclePGTokenValues(lifecyclePGTestRecordOne, "active", lifecyclePGNow.Add(-time.Minute)))
	repository, connection, _ := lifecyclePGRepository(transaction)
	snapshot, err := repository.InspectLifecycleState(context.Background(), lifecyclePGAudience(t), lifecyclePGDestination(t), lifecyclePGNow)
	if err != nil || snapshot.Status() != securitystate.LifecycleActive || snapshot.AudienceID() != lifecyclePGAudience(t) || snapshot.DestinationID() != lifecyclePGDestination(t) {
		t.Fatal("lifecycle postgres inspection result mismatch")
	}
	if options := connection.options[0]; options.AccessMode != pgx.ReadOnly || options.IsoLevel != pgx.RepeatableRead {
		t.Fatal("lifecycle inspection did not use repeatable-read read-only transaction")
	}
	if len(transaction.calls) != 3 || transaction.calls[0].sql != inspectLifecycleDestinationSQL || transaction.calls[1].sql != inspectLifecycleTokensSQL || transaction.calls[2].kind != "commit" {
		t.Fatal("lifecycle inspection query sequence mismatch")
	}
	for _, call := range transaction.calls {
		if call.kind == "exec" {
			t.Fatal("lifecycle inspection performed a mutation")
		}
	}
}

func TestDestinationTokenLifecycleRejectsUnknownAndNullTokenStates(t *testing.T) {
	if !strings.Contains(strings.ToLower(lockLifecycleTokensSQL), "token_state is distinct from 'revoked'") ||
		!strings.Contains(strings.ToLower(inspectLifecycleTokensSQL), "token_state is distinct from 'revoked'") {
		t.Fatal("lifecycle token queries could silently exclude corrupt non-revoked states")
	}
	for _, test := range []struct {
		name   string
		mutate func([]any)
	}{
		{name: "unknown", mutate: func(values []any) { values[5] = "unknown" }},
		{name: "null", mutate: func(values []any) { values[5] = nil }},
	} {
		t.Run(test.name, func(t *testing.T) {
			values := lifecyclePGTokenValues(lifecyclePGTestRecordOne, "staged", lifecyclePGNow.Add(-time.Minute))
			test.mutate(values)
			transaction := lifecyclePGTransactionFor(values)
			repository, _, _ := lifecyclePGRepository(transaction)
			err := repository.CreateStagedToken(context.Background(), lifecyclePGCandidate(t), lifecyclePGNow)
			if !errors.Is(err, securitystate.ErrDestinationLifecycleReconciliation) || transaction.commitCalls != 0 {
				t.Fatal("corrupt non-revoked lifecycle state was not reconciled")
			}
		})
	}
}

func TestDestinationTokenLifecycleRejectsRotationHistoryMismatch(t *testing.T) {
	active := lifecyclePGTokenValues(lifecyclePGTestRecordTwo, "active", lifecyclePGNow.Add(-time.Minute))
	active[7] = pgtype.Timestamptz{Time: lifecyclePGNow.Add(-2 * time.Minute), Valid: true}
	retiring := lifecyclePGTokenValues(lifecyclePGTestRecordOne, "retiring", lifecyclePGNow.Add(-time.Minute))
	transaction := lifecyclePGTransactionFor(active, retiring)
	repository, _, _ := lifecyclePGRepository(transaction)
	err := repository.FinalizeRotation(context.Background(), securitystate.FinalizeRotationCommand{
		AudienceID: lifecyclePGAudience(t), DestinationID: lifecyclePGDestination(t),
		NewActiveRecordID:   lifecyclePGRecord(t, lifecyclePGTestRecordTwo),
		OldRetiringRecordID: lifecyclePGRecord(t, lifecyclePGTestRecordOne),
		Reason:              securitystate.RotationVerifiedAndDrained, Now: lifecyclePGNow,
	})
	if !errors.Is(err, securitystate.ErrDestinationLifecycleReconciliation) || transaction.commitCalls != 0 {
		t.Fatal("corrupt rotation state-change history reached mutation")
	}
}

func TestDestinationTokenLifecycleRejectsDisabledAndFutureDestination(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func([]any)
	}{
		{name: "disabled", mutate: func(values []any) { values[2] = "disabled" }},
		{name: "future created", mutate: func(values []any) {
			values[3] = pgtype.Timestamptz{Time: lifecyclePGNow.Add(time.Minute), Valid: true}
			values[4] = pgtype.Timestamptz{Time: lifecyclePGNow.Add(time.Minute), Valid: true}
		}},
		{name: "future state change", mutate: func(values []any) {
			values[4] = pgtype.Timestamptz{Time: lifecyclePGNow.Add(time.Minute), Valid: true}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			transaction := lifecyclePGTransactionFor()
			values := lifecyclePGDestinationValues()
			test.mutate(values)
			transaction.destinationRow = lifecyclePGRow{values: values}
			repository, _, _ := lifecyclePGRepository(transaction)
			err := repository.CreateStagedToken(context.Background(), lifecyclePGCandidate(t), lifecyclePGNow)
			if !errors.Is(err, securitystate.ErrDestinationLifecycleReconciliation) || transaction.commitCalls != 0 {
				t.Fatal("unsafe lifecycle destination state reached mutation")
			}
		})
	}
}

func TestDestinationTokenLifecycleAbortAllowsOnlyTargetStaleState(t *testing.T) {
	audience := lifecyclePGAudience(t)
	destination := lifecyclePGDestination(t)
	stagedID := lifecyclePGRecord(t, lifecyclePGTestRecordOne)

	staleStaged := lifecyclePGTokenValues(lifecyclePGTestRecordOne, "staged", lifecyclePGNow.Add(-time.Minute))
	staleStaged[10] = pgtype.Timestamptz{Time: lifecyclePGNow, Valid: true}
	staleStaged[11] = pgtype.Timestamptz{Time: lifecyclePGNow, Valid: true}
	transaction := lifecyclePGTransactionFor(staleStaged)
	repository, _, _ := lifecyclePGRepository(transaction)
	if err := repository.AbortStagedToken(context.Background(), audience, destination, stagedID, lifecyclePGNow); err != nil || transaction.commitCalls != 1 {
		t.Fatal("expired target staged token could not be explicitly aborted")
	}

	active := lifecyclePGTokenValues(lifecyclePGTestRecordTwo, "active", lifecyclePGNow.Add(-time.Minute))
	active[10] = pgtype.Timestamptz{Time: lifecyclePGNow, Valid: true}
	transaction = lifecyclePGTransactionFor(staleStaged, active)
	repository, _, _ = lifecyclePGRepository(transaction)
	err := repository.AbortStagedToken(context.Background(), audience, destination, stagedID, lifecyclePGNow)
	if !errors.Is(err, securitystate.ErrDestinationLifecycleReconciliation) || transaction.commitCalls != 0 {
		t.Fatal("staged abort concealed stale non-target active state")
	}

	transaction = lifecyclePGTransactionFor(staleStaged)
	disabled := lifecyclePGDestinationValues()
	disabled[2] = "disabled"
	transaction.destinationRow = lifecyclePGRow{values: disabled}
	repository, _, _ = lifecyclePGRepository(transaction)
	err = repository.AbortStagedToken(context.Background(), audience, destination, stagedID, lifecyclePGNow)
	if !errors.Is(err, securitystate.ErrDestinationLifecycleReconciliation) {
		t.Fatal("staged abort concealed disabled destination")
	}
}

func TestDestinationTokenLifecycleFinalizeAllowsExpiredOldRetiring(t *testing.T) {
	active := lifecyclePGTokenValues(lifecyclePGTestRecordTwo, "active", lifecyclePGNow.Add(-time.Minute))
	retiring := lifecyclePGTokenValues(lifecyclePGTestRecordOne, "retiring", lifecyclePGNow.Add(-time.Minute))
	retiring[10] = pgtype.Timestamptz{Time: lifecyclePGNow, Valid: true}
	transaction := lifecyclePGTransactionFor(active, retiring)
	repository, _, _ := lifecyclePGRepository(transaction)
	err := repository.FinalizeRotation(context.Background(), securitystate.FinalizeRotationCommand{
		AudienceID: lifecyclePGAudience(t), DestinationID: lifecyclePGDestination(t),
		NewActiveRecordID:   lifecyclePGRecord(t, lifecyclePGTestRecordTwo),
		OldRetiringRecordID: lifecyclePGRecord(t, lifecyclePGTestRecordOne),
		Reason:              securitystate.RotationVerifiedAndDrained, Now: lifecyclePGNow,
	})
	if err != nil || transaction.commitCalls != 1 {
		t.Fatal("expired old retiring token could not be explicitly finalized")
	}
}

func TestDestinationTokenLifecycleFailureClassificationAndCleanup(t *testing.T) {
	private := errors.New(lifecyclePGPrivateMarker)
	candidate := lifecyclePGCandidate(t)

	tests := []struct {
		name          string
		configure     func(*lifecyclePGTransaction)
		want          error
		destroy       bool
		outcome       bool
		rollbackBound bool
	}{
		{name: "state query", configure: func(transaction *lifecyclePGTransaction) { transaction.queryErr = private }, want: securitystate.ErrDestinationLifecycleUnavailable, rollbackBound: true},
		{name: "insert ordinary", configure: func(transaction *lifecyclePGTransaction) { transaction.execErrors = []error{private} }, want: securitystate.ErrDestinationLifecycleUnavailable, rollbackBound: true},
		{name: "insert interrupted", configure: func(transaction *lifecyclePGTransaction) { transaction.execErrors = []error{io.EOF} }, want: securitystate.ErrDestinationLifecycleUnavailable, destroy: true, rollbackBound: true},
		{name: "rows zero", configure: func(transaction *lifecyclePGTransaction) {
			transaction.execTags = []pgconn.CommandTag{pgconn.NewCommandTag("INSERT 0")}
		}, want: securitystate.ErrDestinationLifecycleConflict, rollbackBound: true},
		{name: "rows multiple", configure: func(transaction *lifecyclePGTransaction) {
			transaction.execTags = []pgconn.CommandTag{pgconn.NewCommandTag("INSERT 2")}
		}, want: securitystate.ErrDestinationLifecycleReconciliation, rollbackBound: true},
		{name: "commit confirmed rollback", configure: func(transaction *lifecyclePGTransaction) {
			transaction.commitErr = pgx.ErrTxCommitRollback
		}, want: securitystate.ErrDestinationLifecycleUnavailable},
		{name: "commit unknown", configure: func(transaction *lifecyclePGTransaction) { transaction.commitErr = io.EOF }, want: securitystate.ErrDestinationLifecycleOutcomeUnknown, destroy: true, outcome: true},
		{name: "rollback unknown", configure: func(transaction *lifecyclePGTransaction) {
			transaction.execErrors = []error{private}
			transaction.rollbackErr = io.EOF
		}, want: securitystate.ErrDestinationLifecycleOutcomeUnknown, destroy: true, outcome: true, rollbackBound: true},
		{name: "rollback already closed is unknown", configure: func(transaction *lifecyclePGTransaction) {
			transaction.execErrors = []error{private}
			transaction.rollbackErr = pgx.ErrTxClosed
		}, want: securitystate.ErrDestinationLifecycleOutcomeUnknown, destroy: true, outcome: true, rollbackBound: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			transaction := lifecyclePGTransactionFor()
			test.configure(transaction)
			repository, connection, _ := lifecyclePGRepository(transaction)
			err := repository.CreateStagedToken(context.Background(), candidate, lifecyclePGNow)
			assertLifecyclePGSafe(t, err, test.want, private)
			if (connection.destroys == 1) != test.destroy || (connection.releases == 1) == test.destroy {
				t.Fatal("lifecycle failure connection disposition mismatch")
			}
			if test.rollbackBound && !transaction.rollbackBound {
				t.Fatal("lifecycle rollback did not use a bounded context")
			}
			if test.outcome && transaction.commitCalls > 1 {
				t.Fatal("lifecycle unknown outcome replayed a transaction")
			}
		})
	}
}

func TestDestinationTokenLifecycleInterruptedMutationUsesConfirmedRollbackClassification(t *testing.T) {
	for _, test := range []struct {
		name      string
		execError error
		want      error
	}{
		{name: "connection interruption", execError: io.EOF, want: securitystate.ErrDestinationLifecycleUnavailable},
		{name: "canceled mutation", execError: context.Canceled, want: securitystate.ErrDestinationLifecycleCanceled},
		{name: "deadline mutation", execError: context.DeadlineExceeded, want: securitystate.ErrDestinationLifecycleDeadline},
	} {
		t.Run(test.name, func(t *testing.T) {
			transaction := lifecyclePGTransactionFor()
			transaction.execErrors = []error{test.execError}
			repository, connection, _ := lifecyclePGRepository(transaction)
			err := repository.CreateStagedToken(context.Background(), lifecyclePGCandidate(t), lifecyclePGNow)
			if !errors.Is(err, test.want) || errors.Is(err, securitystate.ErrDestinationLifecycleOutcomeUnknown) || transaction.rollbackCalls != 1 || !transaction.rollbackBound || connection.destroys != 1 || connection.releases != 0 {
				t.Fatal("confirmed rollback after interrupted mutation had unsafe classification")
			}
		})
	}
}

func TestDestinationTokenLifecycleReadFaultMatrix(t *testing.T) {
	private := errors.New(lifecyclePGPrivateMarker)
	candidate := lifecyclePGCandidate(t)

	for _, test := range []struct {
		name    string
		setup   func(*lifecyclePGTransaction, *lifecyclePGConnection)
		want    error
		destroy bool
	}{
		{name: "destination lock scan", setup: func(transaction *lifecyclePGTransaction, _ *lifecyclePGConnection) {
			transaction.destinationRow = lifecyclePGRow{err: private}
		}, want: securitystate.ErrDestinationLifecycleUnavailable},
		{name: "typed nil destination row", setup: func(transaction *lifecyclePGTransaction, _ *lifecyclePGConnection) {
			var row *lifecyclePGTypedNilRow
			transaction.destinationRow = row
		}, want: securitystate.ErrDestinationLifecycleUnavailable, destroy: true},
		{name: "token scan", setup: func(transaction *lifecyclePGTransaction, _ *lifecyclePGConnection) {
			transaction.tokenRows = &lifecyclePGRows{values: [][]any{{"wrong-arity"}}}
		}, want: securitystate.ErrDestinationLifecycleReconciliation},
		{name: "token rows error", setup: func(transaction *lifecyclePGTransaction, _ *lifecyclePGConnection) {
			transaction.tokenRows = &lifecyclePGRows{err: private}
		}, want: securitystate.ErrDestinationLifecycleUnavailable},
		{name: "typed nil token rows", setup: func(transaction *lifecyclePGTransaction, _ *lifecyclePGConnection) {
			var rows *lifecyclePGTypedNilRows
			transaction.tokenRows = rows
		}, want: securitystate.ErrDestinationLifecycleUnavailable, destroy: true},
		{name: "begin interruption", setup: func(_ *lifecyclePGTransaction, connection *lifecyclePGConnection) {
			connection.beginErr = io.EOF
		}, want: securitystate.ErrDestinationLifecycleUnavailable, destroy: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			transaction := lifecyclePGTransactionFor()
			repository, connection, _ := lifecyclePGRepository(transaction)
			test.setup(transaction, connection)
			err := repository.CreateStagedToken(context.Background(), candidate, lifecyclePGNow)
			assertLifecyclePGSafe(t, err, test.want, private)
			if (connection.destroys == 1) != test.destroy || (connection.releases == 1) == test.destroy {
				t.Fatal("lifecycle read fault connection disposition mismatch")
			}
		})
	}

	transaction := lifecyclePGTransactionFor(lifecyclePGTokenValues(lifecyclePGTestRecordOne, "active", lifecyclePGNow.Add(-time.Minute)))
	transaction.commitErr = io.EOF
	repository, connection, _ := lifecyclePGRepository(transaction)
	_, err := repository.InspectLifecycleState(context.Background(), lifecyclePGAudience(t), lifecyclePGDestination(t), lifecyclePGNow)
	assertLifecyclePGSafe(t, err, securitystate.ErrDestinationLifecycleUnavailable, nil)
	if connection.destroys != 1 || connection.releases != 0 || transaction.commitCalls != 1 {
		t.Fatal("interrupted lifecycle inspection commit reused its connection")
	}

	transaction = lifecyclePGTransactionFor()
	transaction.queryErr = private
	transaction.rollbackErr = pgx.ErrTxClosed
	repository, connection, _ = lifecyclePGRepository(transaction)
	_, err = repository.InspectLifecycleState(context.Background(), lifecyclePGAudience(t), lifecyclePGDestination(t), lifecyclePGNow)
	assertLifecyclePGSafe(t, err, securitystate.ErrDestinationLifecycleUnavailable, private)
	if connection.destroys != 1 || connection.releases != 0 || transaction.rollbackCalls != 1 || !transaction.rollbackBound {
		t.Fatal("unconfirmed lifecycle inspection rollback reused its connection")
	}
}

func TestDestinationTokenLifecycleErrTxClosedMutationRollbackIsOutcomeUnknown(t *testing.T) {
	transaction := lifecyclePGTransactionFor()
	transaction.execErrors = []error{errors.New(lifecyclePGPrivateMarker)}
	transaction.rollbackErr = pgx.ErrTxClosed
	repository, connection, _ := lifecyclePGRepository(transaction)
	err := repository.CreateStagedToken(context.Background(), lifecyclePGCandidate(t), lifecyclePGNow)
	assertLifecyclePGSafe(t, err, securitystate.ErrDestinationLifecycleOutcomeUnknown, nil)
	if connection.destroys != 1 || connection.releases != 0 || transaction.rollbackCalls != 1 || !transaction.rollbackBound || transaction.commitCalls != 0 {
		t.Fatal("unconfirmed lifecycle mutation rollback was treated as retryable")
	}
}

func TestDestinationTokenLifecycleAcquireBeginCancellationAndConstraintSafety(t *testing.T) {
	private := errors.New(lifecyclePGPrivateMarker)
	candidate := lifecyclePGCandidate(t)

	repository := newDestinationTokenLifecycleRepository(func(context.Context) (destinationTokenLifecycleConnection, error) { return nil, private })
	err := repository.CreateStagedToken(context.Background(), candidate, lifecyclePGNow)
	assertLifecyclePGSafe(t, err, securitystate.ErrDestinationLifecycleUnavailable, private)

	connection := &lifecyclePGConnection{transaction: lifecyclePGTransactionFor(), beginErr: private}
	repository = newDestinationTokenLifecycleRepository(func(context.Context) (destinationTokenLifecycleConnection, error) { return connection, nil })
	err = repository.CreateStagedToken(context.Background(), candidate, lifecyclePGNow)
	assertLifecyclePGSafe(t, err, securitystate.ErrDestinationLifecycleUnavailable, private)
	if connection.releases != 1 || connection.destroys != 0 {
		t.Fatal("ordinary lifecycle begin failure connection disposition mismatch")
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	transaction := lifecyclePGTransactionFor()
	repository, connection, _ = lifecyclePGRepository(transaction)
	err = repository.CreateStagedToken(canceled, candidate, lifecyclePGNow)
	assertLifecyclePGSafe(t, err, securitystate.ErrDestinationLifecycleCanceled, nil)
	if connection.beginCalls != 0 {
		t.Fatal("pre-canceled lifecycle request began a transaction")
	}

	for _, constraint := range []struct {
		name string
		want error
	}{
		{name: "gateway_destination_tokens_one_staged_per_destination", want: securitystate.ErrDestinationLifecycleConflict},
		{name: "gateway_destination_tokens_pkey", want: securitystate.ErrDestinationLifecycleUnavailable},
	} {
		transaction := lifecyclePGTransactionFor()
		transaction.execErrors = []error{&pgconn.PgError{Code: "23505", ConstraintName: constraint.name, Detail: lifecyclePGPrivateMarker}}
		repository, _, _ := lifecyclePGRepository(transaction)
		err := repository.CreateStagedToken(context.Background(), candidate, lifecyclePGNow)
		assertLifecyclePGSafe(t, err, constraint.want, private)
	}

	joined := errors.Join(
		&pgconn.PgError{Code: "23505", ConstraintName: "gateway_destination_tokens_one_staged_per_destination"},
		private,
	)
	transaction = lifecyclePGTransactionFor()
	transaction.execErrors = []error{joined}
	repository, _, _ = lifecyclePGRepository(transaction)
	err = repository.CreateStagedToken(context.Background(), candidate, lifecyclePGNow)
	assertLifecyclePGSafe(t, err, securitystate.ErrDestinationLifecycleUnavailable, private)
}

func TestDestinationTokenLifecycleSQLScopeAndNoForbiddenBehavior(t *testing.T) {
	for name, statement := range map[string]string{
		"destination lock":  lockLifecycleDestinationSQL,
		"token lock":        lockLifecycleTokensSQL,
		"insert":            insertLifecycleStagedTokenSQL,
		"activate initial":  activateInitialLifecycleTokenSQL,
		"retire":            retireLifecycleTokenSQL,
		"activate rotation": activateRotationLifecycleTokenSQL,
		"abort":             revokeStagedLifecycleTokenSQL,
		"revoke active":     revokeActiveLifecycleTokenSQL,
		"restore retiring":  restoreRetiringLifecycleTokenSQL,
		"finalize":          revokeRetiringLifecycleTokenSQL,
	} {
		t.Run(name, func(t *testing.T) {
			lower := strings.ToLower(statement)
			for _, forbidden := range []string{"mso1_", " update gateway_destinations", "delete ", "on conflict do update", "pg_advisory", "credential", "provider"} {
				if strings.Contains(lower, forbidden) {
					t.Fatal("lifecycle SQL exceeded approved scope")
				}
			}
			if strings.Contains(name, "lock") && !strings.Contains(lower, "for update") {
				t.Fatal("lifecycle mutation state query lacks row lock")
			}
		})
	}
	for _, statement := range []string{lockLifecycleTokensSQL, inspectLifecycleTokensSQL} {
		lower := strings.ToLower(statement)
		if !strings.Contains(lower, "is distinct from 'revoked'") || strings.Contains(lower, "in ('staged', 'active', 'retiring')") {
			t.Fatal("lifecycle state query could conceal malformed non-revoked rows")
		}
	}
	if fmt.Sprintf("%v", lifecycleInternalError{kind: securitystate.ErrDestinationLifecycleUnavailable}) != "destination token lifecycle operation failed" {
		t.Fatal("lifecycle internal error diagnostic changed")
	}
}
