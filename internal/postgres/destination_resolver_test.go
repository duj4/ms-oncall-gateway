package postgres

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/duj4/ms-oncall-gateway/internal/securitystate"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	resolverTestOnlyAudience          = "11111111-2222-3333-8444-555555555555"
	resolverTestOnlySecondAudience    = "22222222-3333-4444-8555-666666666666"
	resolverTestOnlyDestination       = "66666666-7777-8888-8999-aaaaaaaaaaaa"
	resolverTestOnlySecondDestination = "77777777-8888-9999-8aaa-bbbbbbbbbbbb"
	resolverTestOnlyRecord            = "88888888-9999-aaaa-8bbb-cccccccccccc"
	resolverTestOnlySecondRecord      = "99999999-aaaa-bbbb-8ccc-dddddddddddd"
	resolverTestOnlyActiveKeyID       = "active-test-only-key"
	resolverTestOnlyHistoricalKeyID   = "historical-test-only-key"
	resolverTestOnlyPrivateMarker     = "resolver-test-only-private-marker"
	resolverTestOnlyTokenText         = "mso1_AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
)

var resolverTestOnlyNow = time.Date(2030, time.January, 2, 12, 0, 0, 0, time.UTC)

type destinationResolverQuery struct {
	sql  string
	args []any
}

type fakeDestinationResolverRow struct {
	values []any
	err    error
}

func (row fakeDestinationResolverRow) Scan(destinations ...any) error {
	if row.err != nil {
		return row.err
	}
	if len(destinations) != len(row.values) {
		return errors.New("fake destination resolver scan mismatch")
	}
	for index := range destinations {
		destination := reflect.ValueOf(destinations[index])
		if destination.Kind() != reflect.Pointer || destination.IsNil() {
			return errors.New("fake destination resolver scan destination invalid")
		}
		value := reflect.ValueOf(row.values[index])
		if !value.IsValid() || !value.Type().AssignableTo(destination.Elem().Type()) {
			return errors.New("fake destination resolver scan value invalid")
		}
		destination.Elem().Set(value)
	}
	return nil
}

type typedNilDestinationResolverRow struct{}

func (*typedNilDestinationResolverRow) Scan(...any) error {
	panic("typed-nil destination resolver row must not be scanned")
}

type fakeDestinationResolverConnection struct {
	rows         []pgx.Row
	queries      []destinationResolverQuery
	releaseCalls int
	destroyCalls int
}

func (connection *fakeDestinationResolverConnection) QueryRow(_ context.Context, sql string, args ...any) pgx.Row {
	connection.queries = append(connection.queries, destinationResolverQuery{
		sql:  sql,
		args: append([]any(nil), args...),
	})
	index := len(connection.queries) - 1
	if index >= len(connection.rows) {
		return fakeDestinationResolverRow{err: errors.New("fake destination resolver query missing")}
	}
	return connection.rows[index]
}

func (connection *fakeDestinationResolverConnection) Release() { connection.releaseCalls++ }
func (connection *fakeDestinationResolverConnection) Destroy() { connection.destroyCalls++ }

type destinationResolverRowOverrideConnection struct {
	*fakeDestinationResolverConnection
	row pgx.Row
}

func (connection *destinationResolverRowOverrideConnection) QueryRow(context.Context, string, ...any) pgx.Row {
	return connection.row
}

type destinationResolverKeyResponse struct {
	key securitystate.DestinationVerifierKey
	err error
}

type destinationResolverKeyCall struct {
	audience securitystate.GatewayAudienceID
	keyID    securitystate.DestinationVerifierKeyID
}

type fakeDestinationResolverKeySource struct {
	mu        sync.Mutex
	responses map[string]destinationResolverKeyResponse
	calls     []destinationResolverKeyCall
}

func (source *fakeDestinationResolverKeySource) DestinationVerifierKey(
	_ context.Context,
	audience securitystate.GatewayAudienceID,
	keyID securitystate.DestinationVerifierKeyID,
) (securitystate.DestinationVerifierKey, error) {
	source.mu.Lock()
	defer source.mu.Unlock()
	source.calls = append(source.calls, destinationResolverKeyCall{audience: audience, keyID: keyID})
	response, ok := source.responses[keyID.Value()]
	if !ok {
		return securitystate.DestinationVerifierKey{}, securitystate.ErrVerifierKeyUnavailable
	}
	return response.key, response.err
}

func (source *fakeDestinationResolverKeySource) callSnapshot() []destinationResolverKeyCall {
	source.mu.Lock()
	defer source.mu.Unlock()
	return append([]destinationResolverKeyCall(nil), source.calls...)
}

type typedNilDestinationResolverKeySource struct{}

func (*typedNilDestinationResolverKeySource) DestinationVerifierKey(
	context.Context,
	securitystate.GatewayAudienceID,
	securitystate.DestinationVerifierKeyID,
) (securitystate.DestinationVerifierKey, error) {
	return securitystate.DestinationVerifierKey{}, nil
}

type typedNilDestinationResolverPool struct{}

func (*typedNilDestinationResolverPool) Ping(context.Context) error { return nil }
func (*typedNilDestinationResolverPool) Acquire(context.Context) (*pgxpool.Conn, error) {
	return nil, nil
}
func (*typedNilDestinationResolverPool) Close() {}

type typedNilDestinationResolverContext struct{}

func (*typedNilDestinationResolverContext) Deadline() (time.Time, bool) { return time.Time{}, false }
func (*typedNilDestinationResolverContext) Done() <-chan struct{}       { return nil }
func (*typedNilDestinationResolverContext) Err() error                  { return nil }
func (*typedNilDestinationResolverContext) Value(any) any               { return nil }

func TestDestinationResolverVerifierGoldenVector(t *testing.T) {
	audience := mustDestinationResolverAudience(t)
	token := mustDestinationResolverToken(t)
	keyMaterial := make([]byte, 32)
	for index := range keyMaterial {
		keyMaterial[index] = byte(index)
	}

	verifier, err := computeDestinationTokenVerifier(audience, token, keyMaterial)
	if err != nil {
		t.Fatal("test-only verifier golden vector was rejected")
	}
	expected, err := hex.DecodeString("89090ee7ca4101838432e2efaee10d35355d6361e0c41a0776ec9d67c2470640")
	if err != nil {
		t.Fatal("test-only verifier golden expectation is invalid")
	}
	actual := verifier.Bytes()
	if !reflect.DeepEqual(actual[:], expected) {
		t.Fatal("test-only verifier golden vector mismatch")
	}
	secondAudience := mustDestinationResolverSecondAudience(t)
	secondVerifier, err := computeDestinationTokenVerifier(secondAudience, token, keyMaterial)
	if err != nil || secondVerifier == verifier {
		t.Fatal("destination verifier did not bind the expected audience")
	}

	zeroAudience, err := computeDestinationTokenVerifier(securitystate.GatewayAudienceID{}, token, keyMaterial)
	if err == nil || !zeroAudience.IsZero() {
		t.Fatal("zero audience produced a verifier")
	}
	shortKey, err := computeDestinationTokenVerifier(audience, token, keyMaterial[:31])
	if err == nil || !shortKey.IsZero() {
		t.Fatal("short verifier key produced a verifier")
	}
}

func TestDestinationResolverConfigurationAndDefensiveCopy(t *testing.T) {
	activeID := mustDestinationResolverKeyID(t, resolverTestOnlyActiveKeyID)
	historicalID := mustDestinationResolverKeyID(t, resolverTestOnlyHistoricalKeyID)
	source := newDestinationResolverKeySource(t)
	private := errors.New(resolverTestOnlyPrivateMarker)

	for _, test := range []struct {
		name   string
		build  func() (*OpaqueDestinationResolver, error)
		wanted error
	}{
		{name: "nil acquire", build: func() (*OpaqueDestinationResolver, error) {
			return newOpaqueDestinationResolver(nil, source, []securitystate.DestinationVerifierKeyID{activeID})
		}, wanted: ErrDestinationResolverIntegrity},
		{name: "nil source", build: func() (*OpaqueDestinationResolver, error) {
			return newOpaqueDestinationResolver(func(context.Context) (destinationResolverConnection, error) { return nil, private }, nil, []securitystate.DestinationVerifierKeyID{activeID})
		}, wanted: ErrDestinationResolverIntegrity},
		{name: "empty keyring", build: func() (*OpaqueDestinationResolver, error) {
			return newOpaqueDestinationResolver(func(context.Context) (destinationResolverConnection, error) { return nil, private }, source, nil)
		}, wanted: ErrDestinationResolverIntegrity},
		{name: "too many keys", build: func() (*OpaqueDestinationResolver, error) {
			return newOpaqueDestinationResolver(func(context.Context) (destinationResolverConnection, error) { return nil, private }, source, []securitystate.DestinationVerifierKeyID{activeID, historicalID, mustDestinationResolverKeyID(t, "third-test-only-key")})
		}, wanted: ErrDestinationResolverIntegrity},
		{name: "duplicate keys", build: func() (*OpaqueDestinationResolver, error) {
			return newOpaqueDestinationResolver(func(context.Context) (destinationResolverConnection, error) { return nil, private }, source, []securitystate.DestinationVerifierKeyID{activeID, activeID})
		}, wanted: ErrDestinationResolverIntegrity},
		{name: "zero key", build: func() (*OpaqueDestinationResolver, error) {
			return newOpaqueDestinationResolver(func(context.Context) (destinationResolverConnection, error) { return nil, private }, source, []securitystate.DestinationVerifierKeyID{{}})
		}, wanted: ErrDestinationResolverIntegrity},
	} {
		t.Run(test.name, func(t *testing.T) {
			resolver, err := test.build()
			if resolver != nil || !errors.Is(err, test.wanted) || errors.Is(err, private) || strings.Contains(err.Error(), resolverTestOnlyPrivateMarker) {
				t.Fatal("invalid resolver configuration was not safely rejected")
			}
		})
	}

	var typedNilSource *typedNilDestinationResolverKeySource
	resolver, err := newOpaqueDestinationResolver(
		func(context.Context) (destinationResolverConnection, error) { return nil, private },
		typedNilSource,
		[]securitystate.DestinationVerifierKeyID{activeID},
	)
	if resolver != nil || !errors.Is(err, ErrDestinationResolverIntegrity) {
		t.Fatal("typed-nil key source was accepted")
	}
	var typedNilPool *typedNilDestinationResolverPool
	resolver, err = NewOpaqueDestinationResolver(typedNilPool, source, []securitystate.DestinationVerifierKeyID{activeID})
	if resolver != nil || !errors.Is(err, ErrDestinationResolverIntegrity) {
		t.Fatal("typed-nil pool was accepted")
	}

	keyIDs := []securitystate.DestinationVerifierKeyID{activeID}
	row := validDestinationResolverRow(t, activeID, mustDestinationResolverKey(t, 0), securitystate.DestinationTokenActive, securitystate.DestinationEnabled)
	resolver, connection, _ := destinationResolverWithRows(t, source, keyIDs, row)
	keyIDs[0] = historicalID
	destination, resolveErr := resolver.Resolve(context.Background(), mustDestinationResolverAudience(t), mustDestinationResolverToken(t), resolverTestOnlyNow)
	if resolveErr != nil || destination != mustDestinationResolverDestination(t) || connection.releaseCalls != 1 {
		t.Fatal("resolver keyring defensive copy failed")
	}
	calls := source.callSnapshot()
	if len(calls) != 1 || calls[0].keyID != activeID || calls[0].audience != mustDestinationResolverAudience(t) {
		t.Fatal("resolver keyring changed with caller slice")
	}
	for _, formatted := range []string{
		fmt.Sprintf("%v", resolver),
		fmt.Sprintf("%+v", resolver),
		fmt.Sprintf("%#v", resolver),
		fmt.Sprintf("%v", *resolver),
		fmt.Sprintf("%+v", *resolver),
		fmt.Sprintf("%#v", *resolver),
	} {
		if formatted != "[redacted]" {
			t.Fatal("resolver formatting exposed internal state")
		}
	}
}

func TestDestinationResolverLifecycleAndUniformNotFound(t *testing.T) {
	activeID := mustDestinationResolverKeyID(t, resolverTestOnlyActiveKeyID)
	key := mustDestinationResolverKey(t, 0)
	sourceFactory := func() *fakeDestinationResolverKeySource {
		return destinationResolverKeySource(map[string]destinationResolverKeyResponse{
			activeID.Value(): {key: key},
		})
	}

	t.Run("active", func(t *testing.T) {
		resolver, connection, _ := destinationResolverWithRows(
			t,
			sourceFactory(),
			[]securitystate.DestinationVerifierKeyID{activeID},
			validDestinationResolverRow(t, activeID, key, securitystate.DestinationTokenActive, securitystate.DestinationEnabled),
		)
		destination, err := resolver.Resolve(context.Background(), mustDestinationResolverAudience(t), mustDestinationResolverToken(t), resolverTestOnlyNow)
		if err != nil || destination != mustDestinationResolverDestination(t) || connection.releaseCalls != 1 || connection.destroyCalls != 0 {
			t.Fatal("active destination token did not resolve")
		}
	})

	retiringRow := validDestinationResolverRow(t, activeID, key, securitystate.DestinationTokenRetiring, securitystate.DestinationEnabled)
	retirementDeadline := retiringRow.values[13].(pgtype.Timestamptz).Time
	for _, test := range []struct {
		name   string
		now    time.Time
		wantOK bool
	}{
		{name: "before retirement deadline", now: retirementDeadline.Add(-time.Nanosecond), wantOK: true},
		{name: "at retirement deadline", now: retirementDeadline},
		{name: "after retirement deadline", now: retirementDeadline.Add(time.Nanosecond)},
	} {
		t.Run(test.name, func(t *testing.T) {
			resolver, _, _ := destinationResolverWithRows(t, sourceFactory(), []securitystate.DestinationVerifierKeyID{activeID}, retiringRow)
			destination, err := resolver.Resolve(context.Background(), mustDestinationResolverAudience(t), mustDestinationResolverToken(t), test.now)
			if test.wantOK {
				if err != nil || destination != mustDestinationResolverDestination(t) {
					t.Fatal("retiring token was not usable before its deadline")
				}
				return
			}
			assertDestinationResolverNotFound(t, destination, err)
		})
	}

	for _, test := range []struct {
		name             string
		tokenState       securitystate.DestinationTokenState
		destinationState securitystate.DestinationState
		mutate           func(*fakeDestinationResolverRow)
	}{
		{name: "staged", tokenState: securitystate.DestinationTokenStaged, destinationState: securitystate.DestinationEnabled},
		{name: "revoked", tokenState: securitystate.DestinationTokenRevoked, destinationState: securitystate.DestinationEnabled},
		{name: "expired", tokenState: securitystate.DestinationTokenActive, destinationState: securitystate.DestinationEnabled, mutate: func(row *fakeDestinationResolverRow) {
			row.values[11] = pgtype.Timestamptz{Time: resolverTestOnlyNow, Valid: true}
		}},
		{name: "disabled destination", tokenState: securitystate.DestinationTokenActive, destinationState: securitystate.DestinationDisabled},
	} {
		t.Run(test.name, func(t *testing.T) {
			row := validDestinationResolverRow(t, activeID, key, test.tokenState, test.destinationState)
			if test.mutate != nil {
				test.mutate(&row)
			}
			resolver, connection, _ := destinationResolverWithRows(t, sourceFactory(), []securitystate.DestinationVerifierKeyID{activeID}, row)
			destination, err := resolver.Resolve(context.Background(), mustDestinationResolverAudience(t), mustDestinationResolverToken(t), resolverTestOnlyNow)
			assertDestinationResolverNotFound(t, destination, err)
			if connection.releaseCalls != 1 || connection.destroyCalls != 0 {
				t.Fatal("unusable token did not release its read connection")
			}
		})
	}

	t.Run("unknown token", func(t *testing.T) {
		resolver, connection, _ := destinationResolverWithRows(t, sourceFactory(), []securitystate.DestinationVerifierKeyID{activeID}, fakeDestinationResolverRow{err: pgx.ErrNoRows})
		destination, err := resolver.Resolve(context.Background(), mustDestinationResolverAudience(t), mustDestinationResolverToken(t), resolverTestOnlyNow)
		assertDestinationResolverNotFound(t, destination, err)
		if connection.releaseCalls != 1 || connection.destroyCalls != 0 {
			t.Fatal("unknown token did not release its read connection")
		}
	})

	t.Run("wrong audience token", func(t *testing.T) {
		source := sourceFactory()
		resolver, connection, _ := destinationResolverWithRows(t, source, []securitystate.DestinationVerifierKeyID{activeID}, fakeDestinationResolverRow{err: pgx.ErrNoRows})
		expectedAudience := mustDestinationResolverSecondAudience(t)
		destination, err := resolver.Resolve(context.Background(), expectedAudience, mustDestinationResolverToken(t), resolverTestOnlyNow)
		assertDestinationResolverNotFound(t, destination, err)
		calls := source.callSnapshot()
		if len(calls) != 1 || calls[0].audience != expectedAudience || len(connection.queries) != 1 || connection.queries[0].args[0] != expectedAudience.String() {
			t.Fatal("wrong-audience lookup did not remain scoped to the expected audience")
		}
		queriedVerifier, ok := connection.queries[0].args[2].([]byte)
		storedAudienceVerifier := mustDestinationResolverVerifier(t, activeID, key).Bytes()
		if !ok || subtle.ConstantTimeCompare(queriedVerifier, storedAudienceVerifier[:]) == 1 {
			t.Fatal("wrong-audience lookup reused the stored audience verifier")
		}
		if connection.releaseCalls != 1 || connection.destroyCalls != 0 {
			t.Fatal("wrong-audience token did not release its read connection")
		}
	})
}

func TestDestinationResolverEvaluatesCompleteKeyringAndRejectsMultipleMatches(t *testing.T) {
	activeID := mustDestinationResolverKeyID(t, resolverTestOnlyActiveKeyID)
	historicalID := mustDestinationResolverKeyID(t, resolverTestOnlyHistoricalKeyID)
	activeKey := mustDestinationResolverKey(t, 0)
	historicalKey := mustDestinationResolverKey(t, 64)
	keyResponses := map[string]destinationResolverKeyResponse{
		activeID.Value():     {key: activeKey},
		historicalID.Value(): {key: historicalKey},
	}

	for _, test := range []struct {
		name string
		ids  []securitystate.DestinationVerifierKeyID
		rows func() []pgx.Row
	}{
		{name: "active first", ids: []securitystate.DestinationVerifierKeyID{activeID, historicalID}, rows: func() []pgx.Row {
			return []pgx.Row{
				validDestinationResolverRow(t, activeID, activeKey, securitystate.DestinationTokenActive, securitystate.DestinationEnabled),
				fakeDestinationResolverRow{err: pgx.ErrNoRows},
			}
		}},
		{name: "active second", ids: []securitystate.DestinationVerifierKeyID{historicalID, activeID}, rows: func() []pgx.Row {
			return []pgx.Row{
				fakeDestinationResolverRow{err: pgx.ErrNoRows},
				validDestinationResolverRow(t, activeID, activeKey, securitystate.DestinationTokenActive, securitystate.DestinationEnabled),
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			source := destinationResolverKeySource(keyResponses)
			resolver, connection, _ := destinationResolverWithRows(t, source, test.ids, test.rows()...)
			destination, err := resolver.Resolve(context.Background(), mustDestinationResolverAudience(t), mustDestinationResolverToken(t), resolverTestOnlyNow)
			if err != nil || destination != mustDestinationResolverDestination(t) || len(connection.queries) != 2 || connection.releaseCalls != 1 {
				t.Fatal("bounded keyring order changed resolution")
			}
			calls := source.callSnapshot()
			if len(calls) != 2 || calls[0].keyID != test.ids[0] || calls[1].keyID != test.ids[1] {
				t.Fatal("configured keyring was not evaluated completely")
			}
		})
	}

	t.Run("unavailable key prevents partial success", func(t *testing.T) {
		private := errors.New(resolverTestOnlyPrivateMarker)
		source := destinationResolverKeySource(map[string]destinationResolverKeyResponse{
			activeID.Value():     {key: activeKey},
			historicalID.Value(): {err: private},
		})
		acquireCalls := 0
		resolver, err := newOpaqueDestinationResolver(func(context.Context) (destinationResolverConnection, error) {
			acquireCalls++
			return nil, private
		}, source, []securitystate.DestinationVerifierKeyID{activeID, historicalID})
		if err != nil {
			t.Fatal("partial-key resolver fixture construction failed")
		}
		destination, resolveErr := resolver.Resolve(context.Background(), mustDestinationResolverAudience(t), mustDestinationResolverToken(t), resolverTestOnlyNow)
		assertDestinationResolverSafeError(t, destination, resolveErr, ErrDestinationResolverUnavailable, private)
		if acquireCalls != 0 || len(source.callSnapshot()) != 2 {
			t.Fatal("partial keyring reached PostgreSQL or skipped a key")
		}
	})

	t.Run("zero key prevents partial success", func(t *testing.T) {
		source := destinationResolverKeySource(map[string]destinationResolverKeyResponse{
			activeID.Value():     {key: activeKey},
			historicalID.Value(): {},
		})
		acquireCalls := 0
		resolver, err := newOpaqueDestinationResolver(func(context.Context) (destinationResolverConnection, error) {
			acquireCalls++
			return nil, nil
		}, source, []securitystate.DestinationVerifierKeyID{activeID, historicalID})
		if err != nil {
			t.Fatal("zero-key resolver fixture construction failed")
		}
		destination, resolveErr := resolver.Resolve(context.Background(), mustDestinationResolverAudience(t), mustDestinationResolverToken(t), resolverTestOnlyNow)
		assertDestinationResolverSafeError(t, destination, resolveErr, ErrDestinationResolverUnavailable, nil)
		if acquireCalls != 0 || len(source.callSnapshot()) != 2 {
			t.Fatal("invalid keyring reached PostgreSQL or skipped a key")
		}
	})

	t.Run("two matches", func(t *testing.T) {
		second := validDestinationResolverRow(t, historicalID, historicalKey, securitystate.DestinationTokenRetiring, securitystate.DestinationEnabled)
		second.values[1] = resolverTestOnlySecondRecord
		resolver, connection, _ := destinationResolverWithRows(
			t,
			destinationResolverKeySource(keyResponses),
			[]securitystate.DestinationVerifierKeyID{activeID, historicalID},
			validDestinationResolverRow(t, activeID, activeKey, securitystate.DestinationTokenActive, securitystate.DestinationEnabled),
			second,
		)
		destination, err := resolver.Resolve(context.Background(), mustDestinationResolverAudience(t), mustDestinationResolverToken(t), resolverTestOnlyNow)
		assertDestinationResolverSafeError(t, destination, err, ErrDestinationResolverIntegrity, nil)
		if len(connection.queries) != 2 || connection.releaseCalls != 1 || connection.destroyCalls != 0 {
			t.Fatal("multiple-match keyring lifecycle mismatch")
		}
	})

	t.Run("unusable plus usable is ambiguous", func(t *testing.T) {
		second := validDestinationResolverRow(t, historicalID, historicalKey, securitystate.DestinationTokenActive, securitystate.DestinationEnabled)
		second.values[1] = resolverTestOnlySecondRecord
		resolver, _, _ := destinationResolverWithRows(
			t,
			destinationResolverKeySource(keyResponses),
			[]securitystate.DestinationVerifierKeyID{activeID, historicalID},
			validDestinationResolverRow(t, activeID, activeKey, securitystate.DestinationTokenRevoked, securitystate.DestinationEnabled),
			second,
		)
		destination, err := resolver.Resolve(context.Background(), mustDestinationResolverAudience(t), mustDestinationResolverToken(t), resolverTestOnlyNow)
		assertDestinationResolverSafeError(t, destination, err, ErrDestinationResolverIntegrity, nil)
	})
}

func TestDestinationResolverSQLIsBoundedAndNeverReceivesRawToken(t *testing.T) {
	activeID := mustDestinationResolverKeyID(t, resolverTestOnlyActiveKeyID)
	key := mustDestinationResolverKey(t, 17)
	source := destinationResolverKeySource(map[string]destinationResolverKeyResponse{activeID.Value(): {key: key}})
	row := validDestinationResolverRow(t, activeID, key, securitystate.DestinationTokenActive, securitystate.DestinationEnabled)
	resolver, connection, _ := destinationResolverWithRows(t, source, []securitystate.DestinationVerifierKeyID{activeID}, row)

	destination, err := resolver.Resolve(context.Background(), mustDestinationResolverAudience(t), mustDestinationResolverToken(t), resolverTestOnlyNow)
	if err != nil || destination != mustDestinationResolverDestination(t) || len(connection.queries) != 1 {
		t.Fatal("SQL boundary fixture did not resolve")
	}
	query := connection.queries[0]
	if query.sql != selectDestinationTokenSQL || len(query.args) != 3 ||
		query.args[0] != resolverTestOnlyAudience || query.args[1] != resolverTestOnlyActiveKeyID {
		t.Fatal("destination resolver SQL or indexed arguments mismatch")
	}
	if !strings.Contains(query.sql, "from gateway_destination_tokens token") ||
		!strings.Contains(query.sql, "left join gateway_destinations destination") ||
		!strings.Contains(query.sql, "token.gateway_audience_id = $1") ||
		!strings.Contains(query.sql, "token.verifier_key_id = $2") ||
		!strings.Contains(query.sql, "token.token_verifier = $3") ||
		strings.Contains(query.sql, resolverTestOnlyTokenText) {
		t.Fatal("destination resolver query is not a bounded parameterized lookup")
	}
	verifierArgument, ok := query.args[2].([]byte)
	expectedVerifier := mustDestinationResolverVerifier(t, activeID, key).Bytes()
	if !ok || len(verifierArgument) != len(expectedVerifier) || !reflect.DeepEqual(verifierArgument, expectedVerifier[:]) {
		t.Fatal("destination resolver verifier query argument mismatch")
	}
	rawBytes := mustDestinationResolverToken(t).Bytes()
	for _, argument := range query.args {
		if text, ok := argument.(string); ok && text == resolverTestOnlyTokenText {
			t.Fatal("raw destination token text reached SQL arguments")
		}
		if value, ok := argument.([]byte); ok && reflect.DeepEqual(value, rawBytes[:]) {
			t.Fatal("raw destination token bytes reached SQL arguments")
		}
	}
}

func TestDestinationResolverRejectsCorruptedRecords(t *testing.T) {
	activeID := mustDestinationResolverKeyID(t, resolverTestOnlyActiveKeyID)
	key := mustDestinationResolverKey(t, 0)
	private := errors.New(resolverTestOnlyPrivateMarker)
	wrongAudience := "22222222-3333-4444-8555-666666666666"
	wrongKeyID := "wrong-test-only-key"
	wrongVerifier := make([]byte, 32)
	for index := range wrongVerifier {
		wrongVerifier[index] = byte(255 - index)
	}

	for _, test := range []struct {
		name   string
		mutate func(*fakeDestinationResolverRow)
	}{
		{name: "duplicate row count", mutate: func(row *fakeDestinationResolverRow) { row.values[0] = int64(2) }},
		{name: "malformed record ID", mutate: func(row *fakeDestinationResolverRow) { row.values[1] = "invalid" }},
		{name: "wrong token audience", mutate: func(row *fakeDestinationResolverRow) { row.values[2] = wrongAudience }},
		{name: "malformed destination ID", mutate: func(row *fakeDestinationResolverRow) { row.values[3] = "invalid" }},
		{name: "short verifier", mutate: func(row *fakeDestinationResolverRow) { row.values[4] = []byte{1} }},
		{name: "mismatched verifier", mutate: func(row *fakeDestinationResolverRow) { row.values[4] = wrongVerifier }},
		{name: "malformed verifier key ID", mutate: func(row *fakeDestinationResolverRow) { row.values[5] = "" }},
		{name: "wrong verifier key ID", mutate: func(row *fakeDestinationResolverRow) { row.values[5] = wrongKeyID }},
		{name: "invalid token state", mutate: func(row *fakeDestinationResolverRow) { row.values[6] = "unknown" }},
		{name: "missing token created time", mutate: func(row *fakeDestinationResolverRow) { row.values[7] = pgtype.Timestamptz{} }},
		{name: "infinite token created time", mutate: func(row *fakeDestinationResolverRow) {
			row.values[7] = pgtype.Timestamptz{InfinityModifier: pgtype.Infinity, Valid: true}
		}},
		{name: "infinite activation", mutate: func(row *fakeDestinationResolverRow) {
			row.values[8] = pgtype.Timestamptz{InfinityModifier: pgtype.Infinity, Valid: true}
		}},
		{name: "invalid expiry", mutate: func(row *fakeDestinationResolverRow) {
			row.values[11] = pgtype.Timestamptz{Time: resolverTestOnlyNow.Add(-3 * time.Hour), Valid: true}
		}},
		{name: "infinite expiry", mutate: func(row *fakeDestinationResolverRow) {
			row.values[11] = pgtype.Timestamptz{InfinityModifier: pgtype.Infinity, Valid: true}
		}},
		{name: "invalid staged cleanup", mutate: func(row *fakeDestinationResolverRow) { row.values[12] = pgtype.Timestamptz{} }},
		{name: "infinite staged cleanup", mutate: func(row *fakeDestinationResolverRow) {
			row.values[12] = pgtype.Timestamptz{InfinityModifier: pgtype.Infinity, Valid: true}
		}},
		{name: "reversed token state time", mutate: func(row *fakeDestinationResolverRow) {
			row.values[14] = pgtype.Timestamptz{Time: resolverTestOnlyNow.Add(-4 * time.Hour), Valid: true}
		}},
		{name: "infinite token state time", mutate: func(row *fakeDestinationResolverRow) {
			row.values[14] = pgtype.Timestamptz{InfinityModifier: pgtype.Infinity, Valid: true}
		}},
		{name: "missing destination", mutate: func(row *fakeDestinationResolverRow) { row.values[15] = pgtype.Text{} }},
		{name: "misbound destination ID", mutate: func(row *fakeDestinationResolverRow) {
			row.values[15] = pgtype.Text{String: resolverTestOnlySecondDestination, Valid: true}
		}},
		{name: "misbound destination audience", mutate: func(row *fakeDestinationResolverRow) {
			row.values[16] = pgtype.Text{String: wrongAudience, Valid: true}
		}},
		{name: "invalid destination state", mutate: func(row *fakeDestinationResolverRow) {
			row.values[17] = pgtype.Text{String: "unknown", Valid: true}
		}},
		{name: "infinite destination created time", mutate: func(row *fakeDestinationResolverRow) {
			row.values[18] = pgtype.Timestamptz{InfinityModifier: pgtype.Infinity, Valid: true}
		}},
		{name: "reversed destination state time", mutate: func(row *fakeDestinationResolverRow) {
			row.values[19] = pgtype.Timestamptz{Time: resolverTestOnlyNow.Add(-4 * time.Hour), Valid: true}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			row := validDestinationResolverRow(t, activeID, key, securitystate.DestinationTokenActive, securitystate.DestinationEnabled)
			test.mutate(&row)
			resolver, connection, _ := destinationResolverWithRows(
				t,
				destinationResolverKeySource(map[string]destinationResolverKeyResponse{activeID.Value(): {key: key}}),
				[]securitystate.DestinationVerifierKeyID{activeID},
				row,
			)
			destination, err := resolver.Resolve(context.Background(), mustDestinationResolverAudience(t), mustDestinationResolverToken(t), resolverTestOnlyNow)
			assertDestinationResolverSafeError(t, destination, err, ErrDestinationResolverIntegrity, private)
			if connection.releaseCalls != 1 || connection.destroyCalls != 0 {
				t.Fatal("corrupted read record did not release its connection")
			}
		})
	}
}

func TestDestinationResolverConnectionAndDependencyFailures(t *testing.T) {
	activeID := mustDestinationResolverKeyID(t, resolverTestOnlyActiveKeyID)
	key := mustDestinationResolverKey(t, 0)
	private := errors.New(resolverTestOnlyPrivateMarker)
	sourceFactory := func() *fakeDestinationResolverKeySource {
		return destinationResolverKeySource(map[string]destinationResolverKeyResponse{activeID.Value(): {key: key}})
	}

	for _, test := range []struct {
		name        string
		rowErr      error
		want        error
		wantRelease bool
		wantDestroy bool
	}{
		{name: "ordinary query", rowErr: private, want: ErrDestinationResolverUnavailable, wantRelease: true},
		{name: "postgres query", rowErr: &pgconn.PgError{Code: "42501", Message: resolverTestOnlyPrivateMarker}, want: ErrDestinationResolverUnavailable, wantRelease: true},
		{name: "connection interruption", rowErr: io.EOF, want: ErrDestinationResolverUnavailable, wantDestroy: true},
		{name: "deadline interruption", rowErr: context.DeadlineExceeded, want: context.DeadlineExceeded, wantDestroy: true},
		{name: "canceled interruption", rowErr: context.Canceled, want: context.Canceled, wantDestroy: true},
		{name: "ambiguous not found", rowErr: errors.Join(pgx.ErrNoRows, private), want: ErrDestinationResolverUnavailable, wantRelease: true},
		{name: "ambiguous interruption", rowErr: errors.Join(io.EOF, private), want: ErrDestinationResolverUnavailable, wantDestroy: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			resolver, connection, _ := destinationResolverWithRows(
				t,
				sourceFactory(),
				[]securitystate.DestinationVerifierKeyID{activeID},
				fakeDestinationResolverRow{err: test.rowErr},
			)
			destination, err := resolver.Resolve(context.Background(), mustDestinationResolverAudience(t), mustDestinationResolverToken(t), resolverTestOnlyNow)
			assertDestinationResolverSafeError(t, destination, err, test.want, private)
			if connection.releaseCalls != boolCount(test.wantRelease) || connection.destroyCalls != boolCount(test.wantDestroy) || len(connection.queries) != 1 {
				t.Fatal("destination query failure connection lifecycle mismatch")
			}
		})
	}

	t.Run("acquire failure", func(t *testing.T) {
		acquireCalls := 0
		resolver, err := newOpaqueDestinationResolver(func(context.Context) (destinationResolverConnection, error) {
			acquireCalls++
			return nil, private
		}, sourceFactory(), []securitystate.DestinationVerifierKeyID{activeID})
		if err != nil {
			t.Fatal("acquire-failure fixture construction failed")
		}
		destination, resolveErr := resolver.Resolve(context.Background(), mustDestinationResolverAudience(t), mustDestinationResolverToken(t), resolverTestOnlyNow)
		assertDestinationResolverSafeError(t, destination, resolveErr, ErrDestinationResolverUnavailable, private)
		if acquireCalls != 1 {
			t.Fatal("destination acquire failure was retried")
		}
	})

	t.Run("ambiguous acquired connection", func(t *testing.T) {
		connection := &fakeDestinationResolverConnection{}
		resolver, err := newOpaqueDestinationResolver(func(context.Context) (destinationResolverConnection, error) {
			return connection, private
		}, sourceFactory(), []securitystate.DestinationVerifierKeyID{activeID})
		if err != nil {
			t.Fatal("ambiguous-acquire fixture construction failed")
		}
		destination, resolveErr := resolver.Resolve(context.Background(), mustDestinationResolverAudience(t), mustDestinationResolverToken(t), resolverTestOnlyNow)
		assertDestinationResolverSafeError(t, destination, resolveErr, ErrDestinationResolverUnavailable, private)
		if connection.destroyCalls != 1 || connection.releaseCalls != 0 {
			t.Fatal("ambiguous acquired connection was not destroyed")
		}
	})

	t.Run("nil connection", func(t *testing.T) {
		var nilConnection *fakeDestinationResolverConnection
		resolver, err := newOpaqueDestinationResolver(func(context.Context) (destinationResolverConnection, error) {
			return nilConnection, nil
		}, sourceFactory(), []securitystate.DestinationVerifierKeyID{activeID})
		if err != nil {
			t.Fatal("nil-connection fixture construction failed")
		}
		destination, resolveErr := resolver.Resolve(context.Background(), mustDestinationResolverAudience(t), mustDestinationResolverToken(t), resolverTestOnlyNow)
		assertDestinationResolverSafeError(t, destination, resolveErr, ErrDestinationResolverUnavailable, nil)
	})

	t.Run("typed nil row", func(t *testing.T) {
		var nilRow *typedNilDestinationResolverRow
		base := &fakeDestinationResolverConnection{}
		resolver, err := newOpaqueDestinationResolver(func(context.Context) (destinationResolverConnection, error) {
			return &destinationResolverRowOverrideConnection{fakeDestinationResolverConnection: base, row: nilRow}, nil
		}, sourceFactory(), []securitystate.DestinationVerifierKeyID{activeID})
		if err != nil {
			t.Fatal("typed-nil-row fixture construction failed")
		}
		destination, resolveErr := resolver.Resolve(context.Background(), mustDestinationResolverAudience(t), mustDestinationResolverToken(t), resolverTestOnlyNow)
		assertDestinationResolverSafeError(t, destination, resolveErr, ErrDestinationResolverUnavailable, nil)
		if base.destroyCalls != 1 || base.releaseCalls != 0 {
			t.Fatal("typed-nil row connection was not destroyed")
		}
	})

	t.Run("key source failures", func(t *testing.T) {
		for _, sourceErr := range []error{
			private,
			errors.Join(securitystate.ErrVerifierKeyUnavailable, private),
		} {
			source := destinationResolverKeySource(map[string]destinationResolverKeyResponse{activeID.Value(): {err: sourceErr}})
			acquireCalls := 0
			resolver, err := newOpaqueDestinationResolver(func(context.Context) (destinationResolverConnection, error) {
				acquireCalls++
				return nil, nil
			}, source, []securitystate.DestinationVerifierKeyID{activeID})
			if err != nil {
				t.Fatal("key-source failure fixture construction failed")
			}
			destination, resolveErr := resolver.Resolve(context.Background(), mustDestinationResolverAudience(t), mustDestinationResolverToken(t), resolverTestOnlyNow)
			assertDestinationResolverSafeError(t, destination, resolveErr, ErrDestinationResolverUnavailable, private)
			if acquireCalls != 0 {
				t.Fatal("key-source failure reached PostgreSQL")
			}
		}
	})
}

func TestDestinationResolverCancellationAndInvalidInputsStopEarly(t *testing.T) {
	activeID := mustDestinationResolverKeyID(t, resolverTestOnlyActiveKeyID)
	key := mustDestinationResolverKey(t, 0)
	private := errors.New(resolverTestOnlyPrivateMarker)
	source := destinationResolverKeySource(map[string]destinationResolverKeyResponse{activeID.Value(): {key: key}})
	acquireCalls := 0
	resolver, err := newOpaqueDestinationResolver(func(context.Context) (destinationResolverConnection, error) {
		acquireCalls++
		return nil, private
	}, source, []securitystate.DestinationVerifierKeyID{activeID})
	if err != nil {
		t.Fatal("input-validation fixture construction failed")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	destination, resolveErr := resolver.Resolve(ctx, mustDestinationResolverAudience(t), mustDestinationResolverToken(t), resolverTestOnlyNow)
	assertDestinationResolverSafeError(t, destination, resolveErr, context.Canceled, private)
	if acquireCalls != 0 || len(source.callSnapshot()) != 0 {
		t.Fatal("pre-canceled resolution reached a dependency")
	}

	deadlineCtx, deadlineCancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer deadlineCancel()
	destination, resolveErr = resolver.Resolve(deadlineCtx, mustDestinationResolverAudience(t), mustDestinationResolverToken(t), resolverTestOnlyNow)
	assertDestinationResolverSafeError(t, destination, resolveErr, context.DeadlineExceeded, private)

	var nilContext *typedNilDestinationResolverContext
	for _, test := range []struct {
		name     string
		resolver *OpaqueDestinationResolver
		ctx      context.Context
		audience securitystate.GatewayAudienceID
		now      time.Time
	}{
		{name: "nil receiver", ctx: context.Background(), audience: mustDestinationResolverAudience(t), now: resolverTestOnlyNow},
		{name: "typed nil context", resolver: resolver, ctx: nilContext, audience: mustDestinationResolverAudience(t), now: resolverTestOnlyNow},
		{name: "zero audience", resolver: resolver, ctx: context.Background(), now: resolverTestOnlyNow},
		{name: "zero time", resolver: resolver, ctx: context.Background(), audience: mustDestinationResolverAudience(t)},
	} {
		t.Run(test.name, func(t *testing.T) {
			destination, err := test.resolver.Resolve(test.ctx, test.audience, mustDestinationResolverToken(t), test.now)
			assertDestinationResolverSafeError(t, destination, err, ErrDestinationResolverIntegrity, private)
		})
	}
	if acquireCalls != 0 || len(source.callSnapshot()) != 0 {
		t.Fatal("invalid destination resolution input reached a dependency")
	}

	t.Run("key source cancellation", func(t *testing.T) {
		for _, sourceErr := range []error{
			context.Canceled,
			errors.Join(context.DeadlineExceeded, private),
		} {
			source := destinationResolverKeySource(map[string]destinationResolverKeyResponse{activeID.Value(): {err: sourceErr}})
			resolver, err := newOpaqueDestinationResolver(func(context.Context) (destinationResolverConnection, error) {
				t.Fatal("canceled key lookup reached PostgreSQL")
				return nil, nil
			}, source, []securitystate.DestinationVerifierKeyID{activeID})
			if err != nil {
				t.Fatal("canceled-key fixture construction failed")
			}
			destination, resolveErr := resolver.Resolve(context.Background(), mustDestinationResolverAudience(t), mustDestinationResolverToken(t), resolverTestOnlyNow)
			want := context.Canceled
			if errors.Is(sourceErr, context.DeadlineExceeded) {
				want = context.DeadlineExceeded
			}
			assertDestinationResolverSafeError(t, destination, resolveErr, want, private)
		}
	})
}

func TestDestinationResolverReadsKeysAndDatabaseOnEveryCall(t *testing.T) {
	activeID := mustDestinationResolverKeyID(t, resolverTestOnlyActiveKeyID)
	key := mustDestinationResolverKey(t, 0)
	source := destinationResolverKeySource(map[string]destinationResolverKeyResponse{activeID.Value(): {key: key}})
	row := validDestinationResolverRow(t, activeID, key, securitystate.DestinationTokenActive, securitystate.DestinationEnabled)
	var acquireCalls atomic.Int64
	var released atomic.Int64
	resolver, err := newOpaqueDestinationResolver(func(context.Context) (destinationResolverConnection, error) {
		acquireCalls.Add(1)
		return &countingDestinationResolverConnection{row: row, released: &released}, nil
	}, source, []securitystate.DestinationVerifierKeyID{activeID})
	if err != nil {
		t.Fatal("no-cache resolver fixture construction failed")
	}

	for range 2 {
		destination, resolveErr := resolver.Resolve(context.Background(), mustDestinationResolverAudience(t), mustDestinationResolverToken(t), resolverTestOnlyNow)
		if resolveErr != nil || destination != mustDestinationResolverDestination(t) {
			t.Fatal("fresh destination resolution failed")
		}
	}
	if acquireCalls.Load() != 2 || released.Load() != 2 || len(source.callSnapshot()) != 2 {
		t.Fatal("destination resolver cached key or PostgreSQL state")
	}

	secondResolver, err := newOpaqueDestinationResolver(func(context.Context) (destinationResolverConnection, error) {
		acquireCalls.Add(1)
		return &countingDestinationResolverConnection{row: row, released: &released}, nil
	}, source, []securitystate.DestinationVerifierKeyID{activeID})
	if err != nil {
		t.Fatal("second resolver fixture construction failed")
	}
	destination, resolveErr := secondResolver.Resolve(context.Background(), mustDestinationResolverAudience(t), mustDestinationResolverToken(t), resolverTestOnlyNow)
	if resolveErr != nil || destination != mustDestinationResolverDestination(t) || acquireCalls.Load() != 3 || released.Load() != 3 || len(source.callSnapshot()) != 3 {
		t.Fatal("two resolver instances did not observe the same state independently")
	}
}

type countingDestinationResolverConnection struct {
	row       fakeDestinationResolverRow
	released  *atomic.Int64
	destroyed *atomic.Int64
}

func (connection *countingDestinationResolverConnection) QueryRow(context.Context, string, ...any) pgx.Row {
	return connection.row
}
func (connection *countingDestinationResolverConnection) Release() {
	if connection.released != nil {
		connection.released.Add(1)
	}
}
func (connection *countingDestinationResolverConnection) Destroy() {
	if connection.destroyed != nil {
		connection.destroyed.Add(1)
	}
}

func TestDestinationResolverConcurrentCallsAreIndependentAndRaceSafe(t *testing.T) {
	activeID := mustDestinationResolverKeyID(t, resolverTestOnlyActiveKeyID)
	key := mustDestinationResolverKey(t, 0)
	source := destinationResolverKeySource(map[string]destinationResolverKeyResponse{activeID.Value(): {key: key}})
	row := validDestinationResolverRow(t, activeID, key, securitystate.DestinationTokenActive, securitystate.DestinationEnabled)
	var acquireCalls atomic.Int64
	var releaseCalls atomic.Int64
	var destroyCalls atomic.Int64
	resolver, err := newOpaqueDestinationResolver(func(context.Context) (destinationResolverConnection, error) {
		acquireCalls.Add(1)
		return &countingDestinationResolverConnection{row: row, released: &releaseCalls, destroyed: &destroyCalls}, nil
	}, source, []securitystate.DestinationVerifierKeyID{activeID})
	if err != nil {
		t.Fatal("concurrent resolver fixture construction failed")
	}

	const callers = 32
	start := make(chan struct{})
	errorsFound := make(chan bool, callers)
	var wait sync.WaitGroup
	wait.Add(callers)
	for range callers {
		go func() {
			defer wait.Done()
			<-start
			destination, resolveErr := resolver.Resolve(context.Background(), mustDestinationResolverAudience(t), mustDestinationResolverToken(t), resolverTestOnlyNow)
			errorsFound <- resolveErr != nil || destination != mustDestinationResolverDestination(t)
		}()
	}
	close(start)
	wait.Wait()
	close(errorsFound)
	for failed := range errorsFound {
		if failed {
			t.Fatal("concurrent destination resolution failed")
		}
	}
	if acquireCalls.Load() != callers || releaseCalls.Load() != callers || destroyCalls.Load() != 0 || len(source.callSnapshot()) != callers {
		t.Fatal("concurrent destination resolution shared request state")
	}
}

func TestDestinationResolverErrorsAndSensitiveValuesAreContentFree(t *testing.T) {
	activeID := mustDestinationResolverKeyID(t, resolverTestOnlyActiveKeyID)
	private := errors.New(resolverTestOnlyPrivateMarker)
	source := destinationResolverKeySource(map[string]destinationResolverKeyResponse{activeID.Value(): {err: private}})
	resolver, err := newOpaqueDestinationResolver(func(context.Context) (destinationResolverConnection, error) {
		return nil, private
	}, source, []securitystate.DestinationVerifierKeyID{activeID})
	if err != nil {
		t.Fatal("redaction resolver fixture construction failed")
	}
	destination, resolveErr := resolver.Resolve(context.Background(), mustDestinationResolverAudience(t), mustDestinationResolverToken(t), resolverTestOnlyNow)
	assertDestinationResolverSafeError(t, destination, resolveErr, ErrDestinationResolverUnavailable, private)

	for _, sensitive := range []string{
		resolverTestOnlyPrivateMarker,
		resolverTestOnlyAudience,
		resolverTestOnlyDestination,
		resolverTestOnlyRecord,
		resolverTestOnlyActiveKeyID,
		resolverTestOnlyTokenText,
	} {
		if strings.Contains(resolveErr.Error(), sensitive) {
			t.Fatal("destination resolver error exposed sensitive state")
		}
	}
	for _, sentinel := range []error{
		ErrDestinationResolverUnavailable,
		ErrDestinationResolverIntegrity,
		securitystate.ErrDestinationNotFound,
	} {
		if sentinel == nil || strings.Contains(sentinel.Error(), resolverTestOnlyPrivateMarker) {
			t.Fatal("destination resolver sentinel is not content-free")
		}
	}
}

func destinationResolverWithRows(
	t *testing.T,
	source securitystate.DestinationVerifierKeySource,
	keyIDs []securitystate.DestinationVerifierKeyID,
	rows ...pgx.Row,
) (*OpaqueDestinationResolver, *fakeDestinationResolverConnection, *int) {
	t.Helper()
	connection := &fakeDestinationResolverConnection{rows: rows}
	acquireCalls := 0
	resolver, err := newOpaqueDestinationResolver(func(context.Context) (destinationResolverConnection, error) {
		acquireCalls++
		return connection, nil
	}, source, keyIDs)
	if err != nil {
		t.Fatal("destination resolver fixture construction failed")
	}
	return resolver, connection, &acquireCalls
}

func destinationResolverKeySource(responses map[string]destinationResolverKeyResponse) *fakeDestinationResolverKeySource {
	copyResponses := make(map[string]destinationResolverKeyResponse, len(responses))
	for key, response := range responses {
		copyResponses[key] = response
	}
	return &fakeDestinationResolverKeySource{responses: copyResponses}
}

func newDestinationResolverKeySource(t *testing.T) *fakeDestinationResolverKeySource {
	t.Helper()
	return destinationResolverKeySource(map[string]destinationResolverKeyResponse{
		resolverTestOnlyActiveKeyID:     {key: mustDestinationResolverKey(t, 0)},
		resolverTestOnlyHistoricalKeyID: {key: mustDestinationResolverKey(t, 64)},
	})
}

func validDestinationResolverRow(
	t *testing.T,
	keyID securitystate.DestinationVerifierKeyID,
	key securitystate.DestinationVerifierKey,
	tokenState securitystate.DestinationTokenState,
	destinationState securitystate.DestinationState,
) fakeDestinationResolverRow {
	t.Helper()
	createdAt := resolverTestOnlyNow.Add(-2 * time.Hour)
	activatedAt := pgtype.Timestamptz{}
	retirementStartedAt := pgtype.Timestamptz{}
	retirementDeadline := pgtype.Timestamptz{}
	revokedAt := pgtype.Timestamptz{}
	stateChangedAt := createdAt
	switch tokenState {
	case securitystate.DestinationTokenActive:
		activatedAt = pgtype.Timestamptz{Time: createdAt.Add(30 * time.Minute), Valid: true}
		stateChangedAt = activatedAt.Time
	case securitystate.DestinationTokenRetiring:
		activatedAt = pgtype.Timestamptz{Time: createdAt.Add(30 * time.Minute), Valid: true}
		retirementStartedAt = pgtype.Timestamptz{Time: createdAt.Add(time.Hour), Valid: true}
		retirementDeadline = pgtype.Timestamptz{Time: createdAt.Add(3 * time.Hour), Valid: true}
		stateChangedAt = retirementStartedAt.Time
	case securitystate.DestinationTokenRevoked:
		revokedAt = pgtype.Timestamptz{Time: createdAt.Add(time.Hour), Valid: true}
		stateChangedAt = revokedAt.Time
	}
	stateText := map[securitystate.DestinationTokenState]string{
		securitystate.DestinationTokenStaged:   "staged",
		securitystate.DestinationTokenActive:   "active",
		securitystate.DestinationTokenRetiring: "retiring",
		securitystate.DestinationTokenRevoked:  "revoked",
	}[tokenState]
	destinationStateText := map[securitystate.DestinationState]string{
		securitystate.DestinationEnabled:  "enabled",
		securitystate.DestinationDisabled: "disabled",
	}[destinationState]
	verifier := mustDestinationResolverVerifier(t, keyID, key).Bytes()
	return fakeDestinationResolverRow{values: []any{
		int64(1),
		resolverTestOnlyRecord,
		resolverTestOnlyAudience,
		resolverTestOnlyDestination,
		append([]byte(nil), verifier[:]...),
		keyID.Value(),
		stateText,
		pgtype.Timestamptz{Time: createdAt, Valid: true},
		activatedAt,
		retirementStartedAt,
		revokedAt,
		pgtype.Timestamptz{Time: createdAt.Add(30 * 24 * time.Hour), Valid: true},
		pgtype.Timestamptz{Time: createdAt.Add(24 * time.Hour), Valid: true},
		retirementDeadline,
		pgtype.Timestamptz{Time: stateChangedAt, Valid: true},
		pgtype.Text{String: resolverTestOnlyDestination, Valid: true},
		pgtype.Text{String: resolverTestOnlyAudience, Valid: true},
		pgtype.Text{String: destinationStateText, Valid: true},
		pgtype.Timestamptz{Time: createdAt, Valid: true},
		pgtype.Timestamptz{Time: createdAt, Valid: true},
	}}
}

func mustDestinationResolverAudience(t *testing.T) securitystate.GatewayAudienceID {
	t.Helper()
	value, err := securitystate.ParseGatewayAudienceID(resolverTestOnlyAudience)
	if err != nil {
		t.Fatal("test-only resolver audience fixture invalid")
	}
	return value
}

func mustDestinationResolverSecondAudience(t *testing.T) securitystate.GatewayAudienceID {
	t.Helper()
	value, err := securitystate.ParseGatewayAudienceID(resolverTestOnlySecondAudience)
	if err != nil {
		t.Fatal("second test-only resolver audience fixture invalid")
	}
	return value
}

func mustDestinationResolverDestination(t *testing.T) securitystate.DestinationID {
	t.Helper()
	value, err := securitystate.ParseDestinationID(resolverTestOnlyDestination)
	if err != nil {
		t.Fatal("test-only resolver destination fixture invalid")
	}
	return value
}

func mustDestinationResolverToken(t *testing.T) securitystate.OpaqueDestinationToken {
	t.Helper()
	value, err := securitystate.ParseOpaqueDestinationToken(resolverTestOnlyTokenText)
	if err != nil {
		t.Fatal("test-only resolver token fixture invalid")
	}
	return value
}

func mustDestinationResolverKeyID(t *testing.T, value string) securitystate.DestinationVerifierKeyID {
	t.Helper()
	keyID, err := securitystate.NewDestinationVerifierKeyID(value)
	if err != nil {
		t.Fatal("test-only resolver key identifier fixture invalid")
	}
	return keyID
}

func mustDestinationResolverKey(t *testing.T, seed byte) securitystate.DestinationVerifierKey {
	t.Helper()
	material := make([]byte, 32)
	for index := range material {
		material[index] = seed + byte(index)
	}
	key, err := securitystate.NewDestinationVerifierKey(material)
	if err != nil {
		t.Fatal("test-only resolver key fixture invalid")
	}
	material[0] ^= 0xff
	return key
}

func mustDestinationResolverVerifier(
	t *testing.T,
	_ securitystate.DestinationVerifierKeyID,
	key securitystate.DestinationVerifierKey,
) securitystate.TokenVerifier {
	t.Helper()
	verifier, err := computeDestinationTokenVerifier(mustDestinationResolverAudience(t), mustDestinationResolverToken(t), key.Bytes())
	if err != nil {
		t.Fatal("test-only resolver verifier fixture invalid")
	}
	return verifier
}

func assertDestinationResolverNotFound(t *testing.T, destination securitystate.DestinationID, err error) {
	t.Helper()
	if !destination.IsZero() || err != securitystate.ErrDestinationNotFound {
		t.Fatal("destination not-found classification mismatch")
	}
}

func assertDestinationResolverSafeError(
	t *testing.T,
	destination securitystate.DestinationID,
	err error,
	want error,
	private error,
) {
	t.Helper()
	if !destination.IsZero() || !errors.Is(err, want) {
		t.Fatal("destination resolver safe classification mismatch")
	}
	if private != nil && (errors.Is(err, private) || strings.Contains(err.Error(), resolverTestOnlyPrivateMarker)) {
		t.Fatal("destination resolver error retained private dependency state")
	}
}

func TestDestinationResolverTokenFixtureIsCanonicalAndTestOnly(t *testing.T) {
	token := mustDestinationResolverToken(t)
	bytesValue := token.Bytes()
	if base64.RawURLEncoding.EncodeToString(bytesValue[:]) != strings.TrimPrefix(resolverTestOnlyTokenText, "mso1_") {
		t.Fatal("test-only resolver token fixture is not canonical")
	}
}
