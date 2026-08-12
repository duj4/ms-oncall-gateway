package postgres

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/duj4/ms-oncall-gateway/internal/securitystate"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	authStateTestAudience  = "11111111-2222-3333-8444-555555555555"
	authStateTestPrincipal = "22222222-3333-4444-8555-666666666666"
	authStateTestSlot      = "33333333-4444-5555-8666-777777777777"
	authStateTestRecord    = "44444444-5555-6666-8777-888888888888"
	authStateTestPublic    = "55555555-6666-4777-8888-999999999999"
	authStatePrivateMarker = "test-only-private-dependency-marker"
)

var authStateTestTime = time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)

type authenticationStateQuery struct {
	sql  string
	args []any
}

type fakeAuthenticationStateRow struct {
	values []any
	err    error
}

type typedNilAuthenticationStateRow struct{}

func (*typedNilAuthenticationStateRow) Scan(...any) error {
	panic("typed-nil authentication-state row must not be scanned")
}

func (row fakeAuthenticationStateRow) Scan(destinations ...any) error {
	if row.err != nil {
		return row.err
	}
	if len(destinations) != len(row.values) {
		return errors.New("fake authentication-state scan mismatch")
	}
	for index := range destinations {
		destination := reflect.ValueOf(destinations[index])
		if destination.Kind() != reflect.Pointer || destination.IsNil() {
			return errors.New("fake authentication-state scan destination invalid")
		}
		value := reflect.ValueOf(row.values[index])
		if !value.IsValid() || !value.Type().AssignableTo(destination.Elem().Type()) {
			return errors.New("fake authentication-state scan value invalid")
		}
		destination.Elem().Set(value)
	}
	return nil
}

type fakeAuthenticationStateConnection struct {
	rows         []fakeAuthenticationStateRow
	queries      []authenticationStateQuery
	releaseCalls int
	destroyCalls int
}

func (connection *fakeAuthenticationStateConnection) QueryRow(_ context.Context, sql string, args ...any) pgx.Row {
	connection.queries = append(connection.queries, authenticationStateQuery{sql: sql, args: append([]any(nil), args...)})
	index := len(connection.queries) - 1
	if index >= len(connection.rows) {
		return fakeAuthenticationStateRow{err: errors.New("fake authentication-state query missing")}
	}
	return connection.rows[index]
}

func (connection *fakeAuthenticationStateConnection) Release() { connection.releaseCalls++ }
func (connection *fakeAuthenticationStateConnection) Destroy() { connection.destroyCalls++ }

type typedNilAuthenticationStatePool struct{}

func (*typedNilAuthenticationStatePool) Ping(context.Context) error { return nil }
func (*typedNilAuthenticationStatePool) Acquire(context.Context) (*pgxpool.Conn, error) {
	return nil, nil
}
func (*typedNilAuthenticationStatePool) Close() {}

type typedNilAuthenticationStateContext struct{}

func (*typedNilAuthenticationStateContext) Deadline() (time.Time, bool) { return time.Time{}, false }
func (*typedNilAuthenticationStateContext) Done() <-chan struct{}       { return nil }
func (*typedNilAuthenticationStateContext) Err() error                  { return nil }
func (*typedNilAuthenticationStateContext) Value(any) any               { return nil }

func authenticationStateRepositoryWithRows(rows ...fakeAuthenticationStateRow) (*AuthenticationStateRepository, *fakeAuthenticationStateConnection, *int) {
	connection := &fakeAuthenticationStateConnection{rows: rows}
	acquireCalls := 0
	repository := newAuthenticationStateRepository(func(context.Context) (authenticationStateConnection, error) {
		acquireCalls++
		return connection, nil
	})
	return repository, connection, &acquireCalls
}

func mustAuthenticationStateAudience(t *testing.T) securitystate.GatewayAudienceID {
	t.Helper()
	value, err := securitystate.ParseGatewayAudienceID(authStateTestAudience)
	if err != nil {
		t.Fatal("test audience setup failed")
	}
	return value
}

func mustAuthenticationStatePrincipal(t *testing.T) securitystate.CorePrincipalID {
	t.Helper()
	value, err := securitystate.ParseCorePrincipalID(authStateTestPrincipal)
	if err != nil {
		t.Fatal("test principal setup failed")
	}
	return value
}

func mustAuthenticationStatePublicCredential(t *testing.T) securitystate.CredentialID {
	t.Helper()
	value, err := securitystate.ParseCredentialID(authStateTestPublic)
	if err != nil {
		t.Fatal("test public credential setup failed")
	}
	return value
}

func mustAuthenticationStateRecord(t *testing.T) securitystate.CredentialRecordID {
	t.Helper()
	value, err := securitystate.ParseCredentialRecordID(authStateTestRecord)
	if err != nil {
		t.Fatal("test credential record setup failed")
	}
	return value
}

func mustAuthenticationStateNonce(t *testing.T, seed byte) securitystate.ReplayNonce {
	t.Helper()
	var raw [16]byte
	for index := range raw {
		raw[index] = seed + byte(index)
	}
	value, err := securitystate.ParseReplayNonce(base64.RawURLEncoding.EncodeToString(raw[:]))
	if err != nil {
		t.Fatal("test replay nonce setup failed")
	}
	return value
}

func validCredentialRow(state string) []any {
	createdAt := authStateTestTime
	notBefore := createdAt.Add(time.Hour)
	expiresAt := createdAt.Add(48 * time.Hour)
	stateChangedAt := createdAt
	activatedAt := pgtype.Timestamptz{}
	retirementStartedAt := pgtype.Timestamptz{}
	retirementDeadline := pgtype.Timestamptz{}
	revokedAt := pgtype.Timestamptz{}
	switch state {
	case "active":
		stateChangedAt = createdAt.Add(30 * time.Minute)
		activatedAt = pgtype.Timestamptz{Time: stateChangedAt, Valid: true}
	case "retiring":
		activatedAt = pgtype.Timestamptz{Time: createdAt.Add(30 * time.Minute), Valid: true}
		retirementStartedAt = pgtype.Timestamptz{Time: createdAt.Add(2 * time.Hour), Valid: true}
		retirementDeadline = pgtype.Timestamptz{Time: createdAt.Add(3 * time.Hour), Valid: true}
		stateChangedAt = retirementStartedAt.Time
	case "revoked":
		revokedAt = pgtype.Timestamptz{Time: createdAt.Add(2 * time.Hour), Valid: true}
		stateChangedAt = revokedAt.Time
	}
	return []any{
		int64(1), true,
		authStateTestRecord, authStateTestPublic, authStateTestSlot, authStateTestAudience, authStateTestPrincipal,
		state, notBefore, expiresAt, activatedAt, retirementStartedAt, retirementDeadline, revokedAt, createdAt, stateChangedAt,
		pgtype.Text{String: authStateTestSlot, Valid: true},
		pgtype.Text{String: authStateTestAudience, Valid: true},
		pgtype.Text{String: authStateTestPrincipal, Valid: true},
		pgtype.Timestamptz{Time: createdAt, Valid: true},
		pgtype.Text{String: authStateTestPrincipal, Valid: true},
		pgtype.Text{String: authStateTestAudience, Valid: true},
		pgtype.Bool{Bool: true, Valid: true},
		pgtype.Bool{Bool: true, Valid: true},
		pgtype.Timestamptz{Time: createdAt, Valid: true},
		pgtype.Timestamptz{Time: stateChangedAt, Valid: true},
	}
}

func assertAuthenticationStateSafeError(t *testing.T, err error, want error, private error) {
	t.Helper()
	if err == nil || !errors.Is(err, want) {
		t.Fatal("authentication-state error classification mismatch")
	}
	for _, forbidden := range []string{
		authStatePrivateMarker,
		authStateTestAudience,
		authStateTestPrincipal,
		authStateTestSlot,
		authStateTestRecord,
		authStateTestPublic,
		"FBUWFxgZGhscHR4fICEiIw",
	} {
		if strings.Contains(err.Error(), forbidden) {
			t.Fatal("authentication-state error exposed request detail")
		}
	}
	if private != nil && errors.Is(err, private) {
		t.Fatal("authentication-state error exposed dependency detail")
	}
}

func TestAuthenticationStateBoundAudience(t *testing.T) {
	t.Run("unique realm", func(t *testing.T) {
		repository, connection, acquireCalls := authenticationStateRepositoryWithRows(fakeAuthenticationStateRow{values: []any{int64(1), authStateTestAudience, true}})
		audience, err := repository.BoundAudience(context.Background())
		if err != nil || audience != mustAuthenticationStateAudience(t) {
			t.Fatal("unique realm was not returned")
		}
		if *acquireCalls != 1 || len(connection.queries) != 1 || connection.releaseCalls != 1 || connection.destroyCalls != 0 {
			t.Fatal("unique realm query lifecycle mismatch")
		}
		if connection.queries[0].sql != selectBoundAudienceSQL || len(connection.queries[0].args) != 0 {
			t.Fatal("unique realm query scope mismatch")
		}
	})

	for _, test := range []struct {
		name      string
		values    []any
		rowErr    error
		want      error
		destroyed bool
	}{
		{name: "missing", values: []any{int64(0), "", false}, want: securitystate.ErrAudienceUnavailable},
		{name: "duplicate", values: []any{int64(2), authStateTestAudience, true}, want: securitystate.ErrAudienceUnavailable},
		{name: "singleton invalid", values: []any{int64(1), authStateTestAudience, false}, want: securitystate.ErrAudienceUnavailable},
		{name: "malformed", values: []any{int64(1), "not-a-uuid", true}, want: securitystate.ErrAudienceUnavailable},
		{name: "zero", values: []any{int64(1), "00000000-0000-0000-0000-000000000000", true}, want: securitystate.ErrAudienceUnavailable},
		{name: "scan failure", rowErr: errors.New(authStatePrivateMarker), want: ErrAuthenticationStateUnavailable},
		{name: "connection interruption", rowErr: io.EOF, want: ErrAuthenticationStateUnavailable, destroyed: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			private := test.rowErr
			repository, connection, _ := authenticationStateRepositoryWithRows(fakeAuthenticationStateRow{values: test.values, err: test.rowErr})
			_, err := repository.BoundAudience(context.Background())
			assertAuthenticationStateSafeError(t, err, test.want, private)
			if (connection.destroyCalls == 1) != test.destroyed || (connection.releaseCalls == 1) == test.destroyed {
				t.Fatal("realm failure connection lifecycle mismatch")
			}
		})
	}
}

func TestAuthenticationStateBoundAudienceFailuresAndCancellation(t *testing.T) {
	private := errors.New(authStatePrivateMarker)
	repository := newAuthenticationStateRepository(func(context.Context) (authenticationStateConnection, error) {
		return nil, private
	})
	_, err := repository.BoundAudience(context.Background())
	assertAuthenticationStateSafeError(t, err, ErrAuthenticationStateUnavailable, private)

	for _, sentinel := range []error{context.Canceled, context.DeadlineExceeded} {
		repository, connection, _ := authenticationStateRepositoryWithRows(fakeAuthenticationStateRow{err: sentinel})
		_, err := repository.BoundAudience(context.Background())
		assertAuthenticationStateSafeError(t, err, sentinel, nil)
		if connection.destroyCalls != 1 || connection.releaseCalls != 0 {
			t.Fatal("canceled realm query did not destroy connection")
		}
	}

	var nilConnection *fakeAuthenticationStateConnection
	repository = newAuthenticationStateRepository(func(context.Context) (authenticationStateConnection, error) {
		return nilConnection, nil
	})
	_, err = repository.BoundAudience(context.Background())
	assertAuthenticationStateSafeError(t, err, ErrAuthenticationStateUnavailable, nil)

	var nilPool *typedNilAuthenticationStatePool
	repository = NewAuthenticationStateRepository(nilPool)
	_, err = repository.BoundAudience(context.Background())
	assertAuthenticationStateSafeError(t, err, ErrAuthenticationStateUnavailable, nil)

	var nilContext *typedNilAuthenticationStateContext
	_, err = repository.BoundAudience(nilContext)
	assertAuthenticationStateSafeError(t, err, ErrAuthenticationStateUnavailable, nil)

	var nilRepository *AuthenticationStateRepository
	_, err = nilRepository.BoundAudience(context.Background())
	assertAuthenticationStateSafeError(t, err, ErrAuthenticationStateUnavailable, nil)
}

func TestAuthenticationStateBoundAudienceDoesNotCache(t *testing.T) {
	connection := &fakeAuthenticationStateConnection{rows: []fakeAuthenticationStateRow{
		{values: []any{int64(1), authStateTestAudience, true}},
		{values: []any{int64(1), authStateTestAudience, true}},
	}}
	acquireCalls := 0
	repository := newAuthenticationStateRepository(func(context.Context) (authenticationStateConnection, error) {
		acquireCalls++
		return connection, nil
	})
	for range 2 {
		if _, err := repository.BoundAudience(context.Background()); err != nil {
			t.Fatal("realm repeat lookup failed")
		}
	}
	if acquireCalls != 2 || len(connection.queries) != 2 || connection.releaseCalls != 2 {
		t.Fatal("realm lookup was cached")
	}
}

func TestAuthenticationStateCredentialReconstructsAllLifecycleStates(t *testing.T) {
	states := []struct {
		name string
		text string
		want securitystate.CredentialState
	}{
		{name: "disabled", text: "disabled", want: securitystate.CredentialDisabled},
		{name: "active", text: "active", want: securitystate.CredentialActive},
		{name: "retiring", text: "retiring", want: securitystate.CredentialRetiring},
		{name: "revoked", text: "revoked", want: securitystate.CredentialRevoked},
	}
	for _, test := range states {
		t.Run(test.name, func(t *testing.T) {
			repository, connection, acquireCalls := authenticationStateRepositoryWithRows(fakeAuthenticationStateRow{values: validCredentialRow(test.text)})
			credential, err := repository.Credential(context.Background(), mustAuthenticationStateAudience(t), mustAuthenticationStatePublicCredential(t))
			if err != nil || credential.State() != test.want || credential.AudienceID() != mustAuthenticationStateAudience(t) ||
				credential.PrincipalID() != mustAuthenticationStatePrincipal(t) || credential.RecordID() != mustAuthenticationStateRecord(t) ||
				credential.PublicID() != mustAuthenticationStatePublicCredential(t) || credential.SlotID().String() != authStateTestSlot {
				t.Fatal("credential lifecycle record was not reconstructed")
			}
			usableBeforeDeadline := credential.UsableAt(authStateTestTime.Add(150 * time.Minute))
			usableAtDeadline := credential.UsableAt(authStateTestTime.Add(3 * time.Hour))
			switch test.want {
			case securitystate.CredentialActive:
				if !usableBeforeDeadline || !usableAtDeadline {
					t.Fatal("active credential lifecycle was not reconstructed")
				}
			case securitystate.CredentialRetiring:
				if !usableBeforeDeadline || usableAtDeadline {
					t.Fatal("retiring credential lifecycle was not reconstructed")
				}
			default:
				if usableBeforeDeadline || usableAtDeadline {
					t.Fatal("inactive credential lifecycle was not reconstructed")
				}
			}
			if *acquireCalls != 1 || connection.releaseCalls != 1 || connection.destroyCalls != 0 || len(connection.queries) != 1 {
				t.Fatal("credential query lifecycle mismatch")
			}
			query := connection.queries[0]
			if query.sql != selectCredentialSQL || len(query.args) != 2 || query.args[0] != authStateTestAudience || query.args[1] != authStateTestPublic {
				t.Fatal("credential query scope or parameter order mismatch")
			}
			for _, required := range []string{
				"credential.gateway_audience_id = $1",
				"where credential.credential_id = $2",
			} {
				if !strings.Contains(query.sql, required) {
					t.Fatal("credential query relationship scope mismatch")
				}
			}
			if strings.Contains(strings.ToLower(query.sql), "secret") {
				t.Fatal("credential query requested authentication secret material")
			}
		})
	}
}

func TestAuthenticationStateCredentialNotFoundAndDamagedRecords(t *testing.T) {
	t.Run("not found", func(t *testing.T) {
		repository, connection, _ := authenticationStateRepositoryWithRows(fakeAuthenticationStateRow{err: pgx.ErrNoRows})
		_, err := repository.Credential(context.Background(), mustAuthenticationStateAudience(t), mustAuthenticationStatePublicCredential(t))
		if !errors.Is(err, securitystate.ErrCredentialNotFound) || connection.releaseCalls != 1 || connection.destroyCalls != 0 {
			t.Fatal("credential absence classification mismatch")
		}
	})

	t.Run("ambiguous not found", func(t *testing.T) {
		private := errors.New(authStatePrivateMarker)
		repository, connection, _ := authenticationStateRepositoryWithRows(fakeAuthenticationStateRow{err: errors.Join(pgx.ErrNoRows, private)})
		_, err := repository.Credential(context.Background(), mustAuthenticationStateAudience(t), mustAuthenticationStatePublicCredential(t))
		assertAuthenticationStateSafeError(t, err, ErrAuthenticationStateUnavailable, private)
		if errors.Is(err, securitystate.ErrCredentialNotFound) || connection.releaseCalls != 1 || connection.destroyCalls != 0 {
			t.Fatal("ambiguous credential absence was misclassified")
		}
	})

	for _, test := range []struct {
		name   string
		mutate func([]any)
	}{
		{name: "duplicate", mutate: func(values []any) { values[0] = int64(2) }},
		{name: "audience mismatch flag", mutate: func(values []any) { values[1] = false }},
		{name: "malformed record", mutate: func(values []any) { values[2] = "not-a-uuid" }},
		{name: "non-v4 public ID", mutate: func(values []any) { values[3] = "55555555-6666-1777-8888-999999999999" }},
		{name: "invalid state", mutate: func(values []any) { values[7] = "unknown" }},
		{name: "slot mismatch", mutate: func(values []any) {
			values[16] = pgtype.Text{String: "aaaaaaaa-bbbb-cccc-8ddd-eeeeeeeeeeee", Valid: true}
		}},
		{name: "principal mismatch", mutate: func(values []any) {
			values[20] = pgtype.Text{String: "aaaaaaaa-bbbb-cccc-8ddd-eeeeeeeeeeee", Valid: true}
		}},
		{name: "missing slot join", mutate: func(values []any) { values[16] = pgtype.Text{} }},
		{name: "invalid active lifecycle", mutate: func(values []any) { values[10] = pgtype.Timestamptz{} }},
		{name: "retiring missing start", mutate: func(values []any) { values[11] = pgtype.Timestamptz{} }},
		{name: "retiring missing deadline", mutate: func(values []any) { values[12] = pgtype.Timestamptz{} }},
		{name: "revoked missing revoked at", mutate: func(values []any) { values[13] = pgtype.Timestamptz{} }},
		{name: "disabled unexpected revoked at", mutate: func(values []any) {
			values[13] = pgtype.Timestamptz{Time: authStateTestTime.Add(time.Hour), Valid: true}
		}},
		{name: "infinite lifecycle timestamp", mutate: func(values []any) {
			values[10] = pgtype.Timestamptz{InfinityModifier: pgtype.Infinity, Valid: true}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			state := "active"
			switch test.name {
			case "retiring missing start", "retiring missing deadline":
				state = "retiring"
			case "revoked missing revoked at":
				state = "revoked"
			case "disabled unexpected revoked at":
				state = "disabled"
			}
			values := validCredentialRow(state)
			test.mutate(values)
			repository, connection, _ := authenticationStateRepositoryWithRows(fakeAuthenticationStateRow{values: values})
			_, err := repository.Credential(context.Background(), mustAuthenticationStateAudience(t), mustAuthenticationStatePublicCredential(t))
			assertAuthenticationStateSafeError(t, err, ErrAuthenticationStateIntegrity, nil)
			if errors.Is(err, securitystate.ErrCredentialNotFound) || connection.releaseCalls != 1 || connection.destroyCalls != 0 {
				t.Fatal("damaged credential was misclassified")
			}
		})
	}
}

func TestAuthenticationStateCredentialRepositoryFailuresAreSafe(t *testing.T) {
	private := errors.New(authStatePrivateMarker)
	for _, test := range []struct {
		name      string
		err       error
		destroyed bool
	}{
		{name: "ordinary query", err: private},
		{name: "connection query", err: io.EOF, destroyed: true},
		{name: "canceled query", err: context.Canceled, destroyed: true},
		{name: "deadline query", err: context.DeadlineExceeded, destroyed: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			repository, connection, _ := authenticationStateRepositoryWithRows(fakeAuthenticationStateRow{err: test.err})
			_, err := repository.Credential(context.Background(), mustAuthenticationStateAudience(t), mustAuthenticationStatePublicCredential(t))
			want := ErrAuthenticationStateUnavailable
			if errors.Is(test.err, context.Canceled) || errors.Is(test.err, context.DeadlineExceeded) {
				want = test.err
			}
			assertAuthenticationStateSafeError(t, err, want, private)
			if errors.Is(err, securitystate.ErrCredentialNotFound) || (connection.destroyCalls == 1) != test.destroyed {
				t.Fatal("credential repository failure classification mismatch")
			}
		})
	}
}

func TestAuthenticationStateReadRepositoriesRejectInvalidConfigurationAndInputs(t *testing.T) {
	var nilRepository *AuthenticationStateRepository
	_, err := nilRepository.Credential(context.Background(), mustAuthenticationStateAudience(t), mustAuthenticationStatePublicCredential(t))
	assertAuthenticationStateSafeError(t, err, ErrAuthenticationStateUnavailable, nil)
	_, err = nilRepository.Principal(context.Background(), mustAuthenticationStateAudience(t), mustAuthenticationStatePrincipal(t))
	assertAuthenticationStateSafeError(t, err, ErrAuthenticationStateUnavailable, nil)

	repository, _, acquireCalls := authenticationStateRepositoryWithRows()
	_, err = repository.Credential(context.Background(), securitystate.GatewayAudienceID{}, mustAuthenticationStatePublicCredential(t))
	assertAuthenticationStateSafeError(t, err, ErrAuthenticationStateIntegrity, nil)
	_, err = repository.Principal(context.Background(), mustAuthenticationStateAudience(t), securitystate.CorePrincipalID{})
	assertAuthenticationStateSafeError(t, err, ErrAuthenticationStateIntegrity, nil)
	if *acquireCalls != 0 {
		t.Fatal("invalid read input reached the database seam")
	}

	var nilContext *typedNilAuthenticationStateContext
	_, err = repository.Credential(nilContext, mustAuthenticationStateAudience(t), mustAuthenticationStatePublicCredential(t))
	assertAuthenticationStateSafeError(t, err, ErrAuthenticationStateUnavailable, nil)
	_, err = repository.Principal(nilContext, mustAuthenticationStateAudience(t), mustAuthenticationStatePrincipal(t))
	assertAuthenticationStateSafeError(t, err, ErrAuthenticationStateUnavailable, nil)

	invalidPublicID := mustAuthenticationStatePublicCredential(t)
	invalidPublicID[6] = invalidPublicID[6]&0x0f | 0x10
	_, err = repository.Credential(context.Background(), mustAuthenticationStateAudience(t), invalidPublicID)
	assertAuthenticationStateSafeError(t, err, ErrAuthenticationStateIntegrity, nil)
}

func principalRow(enabled, authorized bool) []any {
	return []any{int64(1), authStateTestPrincipal, authStateTestAudience, enabled, authorized, authStateTestTime, authStateTestTime.Add(time.Minute)}
}

func TestAuthenticationStatePrincipalStates(t *testing.T) {
	for _, test := range []struct {
		name       string
		enabled    bool
		authorized bool
	}{
		{name: "enabled authorized", enabled: true, authorized: true},
		{name: "disabled", enabled: false, authorized: true},
		{name: "unauthorized", enabled: true, authorized: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			repository, connection, _ := authenticationStateRepositoryWithRows(fakeAuthenticationStateRow{values: principalRow(test.enabled, test.authorized)})
			principal, err := repository.Principal(context.Background(), mustAuthenticationStateAudience(t), mustAuthenticationStatePrincipal(t))
			if err != nil || principal.Enabled() != test.enabled || principal.IntakeAuthorized() != test.authorized {
				t.Fatal("principal state was not reconstructed")
			}
			query := connection.queries[0]
			if query.sql != selectPrincipalSQL || len(query.args) != 2 || query.args[0] != authStateTestAudience || query.args[1] != authStateTestPrincipal || connection.releaseCalls != 1 {
				t.Fatal("principal query scope or lifecycle mismatch")
			}
		})
	}
}

func TestAuthenticationStatePrincipalMissingDamagedAndRepositoryFailures(t *testing.T) {
	private := errors.New(authStatePrivateMarker)
	tests := []struct {
		name      string
		values    []any
		rowErr    error
		want      error
		destroyed bool
	}{
		{name: "missing", rowErr: pgx.ErrNoRows, want: ErrAuthenticationStateIntegrity},
		{name: "duplicate", values: func() []any { values := principalRow(true, true); values[0] = int64(2); return values }(), want: ErrAuthenticationStateIntegrity},
		{name: "malformed", values: func() []any { values := principalRow(true, true); values[1] = "not-a-uuid"; return values }(), want: ErrAuthenticationStateIntegrity},
		{name: "principal mismatch", values: func() []any {
			values := principalRow(true, true)
			values[1] = "aaaaaaaa-bbbb-cccc-8ddd-eeeeeeeeeeee"
			return values
		}(), want: ErrAuthenticationStateIntegrity},
		{name: "audience mismatch", values: func() []any {
			values := principalRow(true, true)
			values[2] = "aaaaaaaa-bbbb-cccc-8ddd-eeeeeeeeeeee"
			return values
		}(), want: ErrAuthenticationStateIntegrity},
		{name: "invalid timestamps", values: func() []any {
			values := principalRow(true, true)
			values[6] = authStateTestTime.Add(-time.Minute)
			return values
		}(), want: ErrAuthenticationStateIntegrity},
		{name: "repository failure", rowErr: private, want: ErrAuthenticationStateUnavailable},
		{name: "connection interruption", rowErr: io.EOF, want: ErrAuthenticationStateUnavailable, destroyed: true},
		{name: "canceled query", rowErr: context.Canceled, want: context.Canceled, destroyed: true},
		{name: "deadline query", rowErr: context.DeadlineExceeded, want: context.DeadlineExceeded, destroyed: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repository, connection, _ := authenticationStateRepositoryWithRows(fakeAuthenticationStateRow{values: test.values, err: test.rowErr})
			_, err := repository.Principal(context.Background(), mustAuthenticationStateAudience(t), mustAuthenticationStatePrincipal(t))
			assertAuthenticationStateSafeError(t, err, test.want, private)
			if errors.Is(err, securitystate.ErrPrincipalNotAuthorized) || (connection.destroyCalls == 1) != test.destroyed {
				t.Fatal("principal failure was misclassified")
			}
		})
	}
}

func TestAuthenticationStateReplayReservationResultsAndExactArguments(t *testing.T) {
	recordID := mustAuthenticationStateRecord(t)
	nonce := mustAuthenticationStateNonce(t, 1)
	now := authStateTestTime.Add(17 * time.Second)

	for _, test := range []struct {
		name string
		row  fakeAuthenticationStateRow
		want securitystate.ReplayReservationDisposition
	}{
		{name: "reserved", row: fakeAuthenticationStateRow{values: []any{true}}, want: securitystate.ReplayReserved},
		{name: "duplicate", row: fakeAuthenticationStateRow{err: pgx.ErrNoRows}, want: securitystate.ReplayDuplicate},
	} {
		t.Run(test.name, func(t *testing.T) {
			repository, connection, acquireCalls := authenticationStateRepositoryWithRows(test.row)
			disposition, err := repository.Reserve(context.Background(), recordID, nonce, now)
			if err != nil || disposition != test.want {
				t.Fatal("replay reservation disposition mismatch")
			}
			if *acquireCalls != 1 || len(connection.queries) != 1 || connection.releaseCalls != 1 || connection.destroyCalls != 0 {
				t.Fatal("replay reservation query lifecycle mismatch")
			}
			query := connection.queries[0]
			if query.sql != insertReplayReservationSQL || len(query.args) != 4 || query.args[0] != authStateTestRecord || query.args[2] != now || query.args[3] != now.Add(5*time.Minute) {
				t.Fatal("replay reservation SQL or clock arguments mismatch")
			}
			nonceArgument, ok := query.args[1].([]byte)
			expectedNonce := nonce.Bytes()
			if !ok || len(nonceArgument) != len(expectedNonce) || !reflect.DeepEqual(nonceArgument, expectedNonce[:]) {
				t.Fatal("replay reservation nonce argument mismatch")
			}
			if !strings.Contains(query.sql, "on conflict on constraint authentication_replay_reservations_pkey") || !strings.Contains(query.sql, "returning true") {
				t.Fatal("replay reservation is not an atomic named-constraint insert")
			}
		})
	}
}

func TestAuthenticationStateReplayFailuresDestroyOrReleaseWithoutRetry(t *testing.T) {
	private := errors.New(authStatePrivateMarker)
	recordID := mustAuthenticationStateRecord(t)
	nonce := mustAuthenticationStateNonce(t, 20)
	tests := []struct {
		name        string
		row         fakeAuthenticationStateRow
		want        error
		wantDestroy bool
		wantRelease bool
	}{
		{name: "ordinary SQL", row: fakeAuthenticationStateRow{err: &pgconn.PgError{Code: "42501", Message: authStatePrivateMarker}}, want: securitystate.ErrReplayUnavailable, wantRelease: true},
		{name: "connection interruption", row: fakeAuthenticationStateRow{err: io.EOF}, want: securitystate.ErrReplayOutcomeUnknown, wantDestroy: true},
		{name: "deadline during write", row: fakeAuthenticationStateRow{err: context.DeadlineExceeded}, want: securitystate.ErrReplayOutcomeUnknown, wantDestroy: true},
		{name: "statement completion unknown", row: fakeAuthenticationStateRow{err: &pgconn.PgError{Code: "40003", Message: authStatePrivateMarker}}, want: securitystate.ErrReplayOutcomeUnknown, wantDestroy: true},
		{name: "database dropped session", row: fakeAuthenticationStateRow{err: &pgconn.PgError{Code: "57P04", Message: authStatePrivateMarker}}, want: securitystate.ErrReplayOutcomeUnknown, wantDestroy: true},
		{name: "idle session timeout", row: fakeAuthenticationStateRow{err: &pgconn.PgError{Code: "57P05", Message: authStatePrivateMarker}}, want: securitystate.ErrReplayOutcomeUnknown, wantDestroy: true},
		{name: "ambiguous duplicate", row: fakeAuthenticationStateRow{err: errors.Join(pgx.ErrNoRows, private)}, want: securitystate.ErrReplayOutcomeUnknown, wantDestroy: true},
		{name: "unconfirmed false", row: fakeAuthenticationStateRow{values: []any{false}}, want: securitystate.ErrReplayOutcomeUnknown, wantDestroy: true},
		{name: "unclassified post-send failure", row: fakeAuthenticationStateRow{err: private}, want: securitystate.ErrReplayOutcomeUnknown, wantDestroy: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repository, connection, acquireCalls := authenticationStateRepositoryWithRows(test.row)
			disposition, err := repository.Reserve(context.Background(), recordID, nonce, authStateTestTime)
			if disposition != 0 {
				t.Fatal("replay failure returned a disposition")
			}
			assertAuthenticationStateSafeError(t, err, test.want, private)
			if *acquireCalls != 1 || len(connection.queries) != 1 || connection.destroyCalls != boolCount(test.wantDestroy) || connection.releaseCalls != boolCount(test.wantRelease) {
				t.Fatal("replay failure lifecycle or retry count mismatch")
			}
		})
	}
}

func TestAuthenticationStateDependencyBoundaryDestroysAmbiguousResources(t *testing.T) {
	private := errors.New(authStatePrivateMarker)
	connection := &fakeAuthenticationStateConnection{}
	repository := newAuthenticationStateRepository(func(context.Context) (authenticationStateConnection, error) {
		return connection, private
	})
	_, err := repository.BoundAudience(context.Background())
	assertAuthenticationStateSafeError(t, err, ErrAuthenticationStateUnavailable, private)
	if connection.destroyCalls != 1 || connection.releaseCalls != 0 {
		t.Fatal("ambiguous acquired connection was not destroyed")
	}

	var nilRow *typedNilAuthenticationStateRow
	connection = &fakeAuthenticationStateConnection{}
	repository = newAuthenticationStateRepository(func(context.Context) (authenticationStateConnection, error) {
		return &rowOverrideAuthenticationStateConnection{
			fakeAuthenticationStateConnection: connection,
			row:                               nilRow,
		}, nil
	})
	_, err = repository.BoundAudience(context.Background())
	assertAuthenticationStateSafeError(t, err, ErrAuthenticationStateUnavailable, nil)
	if connection.destroyCalls != 1 || connection.releaseCalls != 0 {
		t.Fatal("typed-nil row connection was not destroyed")
	}

	connection = &fakeAuthenticationStateConnection{}
	repository = newAuthenticationStateRepository(func(context.Context) (authenticationStateConnection, error) {
		return connection, private
	})
	_, err = repository.Reserve(
		context.Background(),
		mustAuthenticationStateRecord(t),
		mustAuthenticationStateNonce(t, 60),
		authStateTestTime,
	)
	assertAuthenticationStateSafeError(t, err, securitystate.ErrReplayUnavailable, private)
	if connection.destroyCalls != 1 || connection.releaseCalls != 0 {
		t.Fatal("ambiguous replay connection was not destroyed")
	}
}

type rowOverrideAuthenticationStateConnection struct {
	*fakeAuthenticationStateConnection
	row pgx.Row
}

func (connection *rowOverrideAuthenticationStateConnection) QueryRow(context.Context, string, ...any) pgx.Row {
	return connection.row
}

func TestAuthenticationStateReplayAcquireCancellationAndInvalidConfiguration(t *testing.T) {
	private := errors.New(authStatePrivateMarker)
	recordID := mustAuthenticationStateRecord(t)
	nonce := mustAuthenticationStateNonce(t, 40)

	for _, test := range []struct {
		name string
		err  error
		want error
	}{
		{name: "acquire failure", err: private, want: securitystate.ErrReplayUnavailable},
		{name: "acquire canceled", err: context.Canceled, want: context.Canceled},
		{name: "acquire deadline", err: context.DeadlineExceeded, want: context.DeadlineExceeded},
	} {
		t.Run(test.name, func(t *testing.T) {
			acquireCalls := 0
			repository := newAuthenticationStateRepository(func(context.Context) (authenticationStateConnection, error) {
				acquireCalls++
				return nil, test.err
			})
			_, err := repository.Reserve(context.Background(), recordID, nonce, authStateTestTime)
			assertAuthenticationStateSafeError(t, err, test.want, private)
			if acquireCalls != 1 {
				t.Fatal("replay acquire was retried")
			}
		})
	}

	var nilConnection *fakeAuthenticationStateConnection
	repository := newAuthenticationStateRepository(func(context.Context) (authenticationStateConnection, error) {
		return nilConnection, nil
	})
	_, err := repository.Reserve(context.Background(), recordID, nonce, authStateTestTime)
	assertAuthenticationStateSafeError(t, err, securitystate.ErrReplayUnavailable, nil)

	var nilPool *typedNilAuthenticationStatePool
	repository = NewAuthenticationStateRepository(nilPool)
	_, err = repository.Reserve(context.Background(), recordID, nonce, authStateTestTime)
	assertAuthenticationStateSafeError(t, err, securitystate.ErrReplayUnavailable, nil)

	var nilRepository *AuthenticationStateRepository
	_, err = nilRepository.Reserve(context.Background(), recordID, nonce, authStateTestTime)
	assertAuthenticationStateSafeError(t, err, securitystate.ErrReplayUnavailable, nil)

	_, err = repository.Reserve(context.Background(), securitystate.CredentialRecordID{}, nonce, authStateTestTime)
	assertAuthenticationStateSafeError(t, err, securitystate.ErrReplayUnavailable, nil)
	_, err = repository.Reserve(context.Background(), recordID, nonce, time.Time{})
	assertAuthenticationStateSafeError(t, err, securitystate.ErrReplayUnavailable, nil)

	var nilContext *typedNilAuthenticationStateContext
	_, err = repository.Reserve(nilContext, recordID, nonce, authStateTestTime)
	assertAuthenticationStateSafeError(t, err, securitystate.ErrReplayUnavailable, nil)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	acquireCalls := 0
	repository = newAuthenticationStateRepository(func(context.Context) (authenticationStateConnection, error) {
		acquireCalls++
		return nil, nil
	})
	_, err = repository.Reserve(ctx, recordID, nonce, authStateTestTime)
	assertAuthenticationStateSafeError(t, err, context.Canceled, nil)
	if acquireCalls != 0 {
		t.Fatal("pre-canceled replay request reached the database seam")
	}
}

func TestAuthenticationStateReplayIdentityDimensionsRemainIndependent(t *testing.T) {
	firstRecord := mustAuthenticationStateRecord(t)
	secondRecord, err := securitystate.ParseCredentialRecordID("66666666-7777-8888-8999-aaaaaaaaaaaa")
	if err != nil {
		t.Fatal("test credential record setup failed")
	}
	firstNonce := mustAuthenticationStateNonce(t, 70)
	secondNonce := mustAuthenticationStateNonce(t, 90)
	connection := &fakeAuthenticationStateConnection{rows: []fakeAuthenticationStateRow{
		{values: []any{true}},
		{values: []any{true}},
		{values: []any{true}},
	}}
	repository := newAuthenticationStateRepository(func(context.Context) (authenticationStateConnection, error) {
		return connection, nil
	})

	for _, request := range []struct {
		record securitystate.CredentialRecordID
		nonce  securitystate.ReplayNonce
	}{
		{record: firstRecord, nonce: firstNonce},
		{record: secondRecord, nonce: firstNonce},
		{record: firstRecord, nonce: secondNonce},
	} {
		disposition, reserveErr := repository.Reserve(context.Background(), request.record, request.nonce, authStateTestTime)
		if reserveErr != nil || disposition != securitystate.ReplayReserved {
			t.Fatal("independent replay identity was not reserved")
		}
	}
	if len(connection.queries) != 3 || connection.releaseCalls != 3 || connection.destroyCalls != 0 {
		t.Fatal("independent replay identity lifecycle mismatch")
	}
	if connection.queries[0].args[0] == connection.queries[1].args[0] ||
		reflect.DeepEqual(connection.queries[0].args[1], connection.queries[2].args[1]) {
		t.Fatal("replay identity dimensions were not independently parameterized")
	}
}

func boolCount(value bool) int {
	if value {
		return 1
	}
	return 0
}
