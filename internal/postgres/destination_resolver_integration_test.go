package postgres

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/duj4/ms-oncall-gateway/internal/securitystate"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	integrationDestinationAudienceText  = "61111111-1111-1111-8111-111111111111"
	integrationDestinationActiveID      = "62222222-2222-2222-8222-222222222222"
	integrationDestinationRetiringID    = "63333333-3333-3333-8333-333333333333"
	integrationDestinationRevokedID     = "64444444-4444-4444-8444-444444444444"
	integrationDestinationExpiredID     = "65555555-5555-5555-8555-555555555555"
	integrationDestinationDisabledID    = "66666666-6666-6666-8666-666666666666"
	integrationTokenActiveRecord        = "67777777-7777-7777-8777-777777777777"
	integrationTokenRetiringRecord      = "68888888-8888-8888-8888-888888888888"
	integrationTokenRevokedRecord       = "69999999-9999-9999-8999-999999999999"
	integrationTokenExpiredRecord       = "6aaaaaaa-aaaa-aaaa-8aaa-aaaaaaaaaaaa"
	integrationTokenDisabledRecord      = "6bbbbbbb-bbbb-bbbb-8bbb-bbbbbbbbbbbb"
	integrationDestinationActiveKeyID   = "integration-destination-active-key"
	integrationDestinationRetiringKeyID = "integration-destination-retiring-key"
)

var integrationDestinationBaseTime = time.Date(2026, time.January, 3, 4, 5, 6, 0, time.UTC)

type integrationDestinationKeySource struct {
	keys map[string]securitystate.DestinationVerifierKey
}

func (source integrationDestinationKeySource) DestinationVerifierKey(
	_ context.Context,
	_ securitystate.GatewayAudienceID,
	keyID securitystate.DestinationVerifierKeyID,
) (securitystate.DestinationVerifierKey, error) {
	key, ok := source.keys[keyID.Value()]
	if !ok {
		return securitystate.DestinationVerifierKey{}, securitystate.ErrVerifierKeyUnavailable
	}
	return key, nil
}

type integrationDestinationFixture struct {
	destinationID       string
	recordID            string
	token               securitystate.OpaqueDestinationToken
	keyID               securitystate.DestinationVerifierKeyID
	destinationState    string
	tokenState          string
	createdAt           time.Time
	activatedAt         any
	retirementStartedAt any
	revokedAt           any
	expiresAt           time.Time
	retirementDeadline  any
	stateChangedAt      time.Time
}

func TestOpaqueDestinationResolverPostgresIntegration(t *testing.T) {
	if os.Getenv(postgresIntegrationEnableEnv) != "1" {
		t.Skip("因未配置专用 PostgreSQL 测试数据库而跳过")
	}
	databaseURL := os.Getenv(postgresIntegrationURLEnv)
	if databaseURL == "" {
		t.Fatal("专用 PostgreSQL 测试已启用，但测试数据库配置缺失")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	pool := openIntegrationPool(t, ctx, databaseURL)
	t.Cleanup(pool.Close)

	verifyIntegrationSession(t, ctx, pool, databaseURL)
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		if !deleteIntegrationDestinationState(cleanupCtx, pool, func(message string) {
			t.Error(message)
		}) {
			t.Error("destination resolver integration final cleanup 不完整")
		}
	})

	if err := NewRunner(NewPGBackend(pool), EmbeddedMigrations(), nil).Run(ctx); err != nil {
		t.Fatal("destination resolver integration schema preparation 失败")
	}

	initialCleanupCtx, initialCleanupCancel := context.WithTimeout(ctx, 10*time.Second)
	initialCleanupOK := deleteIntegrationDestinationState(initialCleanupCtx, pool, func(message string) {
		t.Error(message)
	})
	initialCleanupCancel()
	if !initialCleanupOK {
		t.Fatal("destination resolver integration initial cleanup 失败")
	}
	assertNoForeignIntegrationRealm(t, ctx, pool)

	audience := mustIntegrationDestinationAudience(t)
	activeKeyID := mustIntegrationDestinationKeyID(t, integrationDestinationActiveKeyID)
	retiringKeyID := mustIntegrationDestinationKeyID(t, integrationDestinationRetiringKeyID)
	activeKey := mustIntegrationDestinationKey(t, 0x10)
	retiringKey := mustIntegrationDestinationKey(t, 0x80)
	keySource := integrationDestinationKeySource{keys: map[string]securitystate.DestinationVerifierKey{
		activeKeyID.Value():   activeKey,
		retiringKeyID.Value(): retiringKey,
	}}
	fixtures := integrationDestinationFixtures(t, activeKeyID, retiringKeyID)
	seedIntegrationDestinationState(t, ctx, pool, audience, keySource, fixtures)

	resolvers := []*OpaqueDestinationResolver{
		mustIntegrationDestinationResolver(t, pool, keySource, []securitystate.DestinationVerifierKeyID{activeKeyID, retiringKeyID}),
		mustIntegrationDestinationResolver(t, pool, keySource, []securitystate.DestinationVerifierKeyID{retiringKeyID, activeKeyID}),
	}
	now := integrationDestinationBaseTime.Add(12 * time.Hour)

	for _, resolver := range resolvers {
		activeID, err := resolver.Resolve(ctx, audience, fixtures[0].token, now)
		if err != nil || activeID != mustIntegrationDestinationID(t, integrationDestinationActiveID) {
			t.Fatal("destination resolver active round trip 失败")
		}
		retiringID, err := resolver.Resolve(ctx, audience, fixtures[1].token, now)
		if err != nil || retiringID != mustIntegrationDestinationID(t, integrationDestinationRetiringID) {
			t.Fatal("destination resolver retiring round trip 失败")
		}
		if _, err := resolver.Resolve(ctx, audience, fixtures[1].token, integrationDestinationBaseTime.Add(24*time.Hour)); !errors.Is(err, securitystate.ErrDestinationNotFound) {
			t.Fatal("destination resolver retiring deadline boundary 无效")
		}
		for _, fixture := range fixtures[2:] {
			if _, err := resolver.Resolve(ctx, audience, fixture.token, now); !errors.Is(err, securitystate.ErrDestinationNotFound) {
				t.Fatal("destination resolver inactive state classification 无效")
			}
		}
	}

	if countIntegrationDestinationRows(t, ctx, pool) != int64(len(fixtures)) {
		t.Fatal("destination resolver test-owned row count 无效")
	}
}

func integrationDestinationFixtures(
	t *testing.T,
	activeKeyID securitystate.DestinationVerifierKeyID,
	retiringKeyID securitystate.DestinationVerifierKeyID,
) []integrationDestinationFixture {
	t.Helper()
	createdAt := integrationDestinationBaseTime
	activatedAt := createdAt.Add(time.Minute)
	retirementStartedAt := createdAt.Add(2 * time.Minute)
	return []integrationDestinationFixture{
		{
			destinationID: integrationDestinationActiveID, recordID: integrationTokenActiveRecord,
			token: mustIntegrationDestinationToken(t, 0x20), keyID: activeKeyID,
			destinationState: "enabled", tokenState: "active", createdAt: createdAt,
			activatedAt: activatedAt, expiresAt: createdAt.Add(48 * time.Hour), stateChangedAt: activatedAt,
		},
		{
			destinationID: integrationDestinationRetiringID, recordID: integrationTokenRetiringRecord,
			token: mustIntegrationDestinationToken(t, 0x40), keyID: retiringKeyID,
			destinationState: "enabled", tokenState: "retiring", createdAt: createdAt,
			activatedAt: activatedAt, retirementStartedAt: retirementStartedAt,
			expiresAt: createdAt.Add(48 * time.Hour), retirementDeadline: createdAt.Add(24 * time.Hour), stateChangedAt: retirementStartedAt,
		},
		{
			destinationID: integrationDestinationRevokedID, recordID: integrationTokenRevokedRecord,
			token: mustIntegrationDestinationToken(t, 0x60), keyID: activeKeyID,
			destinationState: "enabled", tokenState: "revoked", createdAt: createdAt,
			revokedAt: createdAt.Add(3 * time.Minute), expiresAt: createdAt.Add(48 * time.Hour), stateChangedAt: createdAt.Add(3 * time.Minute),
		},
		{
			destinationID: integrationDestinationExpiredID, recordID: integrationTokenExpiredRecord,
			token: mustIntegrationDestinationToken(t, 0xa0), keyID: retiringKeyID,
			destinationState: "enabled", tokenState: "active", createdAt: createdAt,
			activatedAt: activatedAt, expiresAt: createdAt.Add(6 * time.Hour), stateChangedAt: activatedAt,
		},
		{
			destinationID: integrationDestinationDisabledID, recordID: integrationTokenDisabledRecord,
			token: mustIntegrationDestinationToken(t, 0xc0), keyID: activeKeyID,
			destinationState: "disabled", tokenState: "active", createdAt: createdAt,
			activatedAt: activatedAt, expiresAt: createdAt.Add(48 * time.Hour), stateChangedAt: activatedAt,
		},
	}
}

func seedIntegrationDestinationState(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	audience securitystate.GatewayAudienceID,
	keySource integrationDestinationKeySource,
	fixtures []integrationDestinationFixture,
) {
	t.Helper()
	if _, err := pool.Exec(ctx, `
		insert into gateway_security_realm (singleton_key, gateway_audience_id, created_at)
		values (true, $1, $2)
	`, audience.String(), integrationDestinationBaseTime); err != nil {
		t.Fatal("destination resolver test realm seed 失败")
	}
	for _, fixture := range fixtures {
		if _, err := pool.Exec(ctx, `
			insert into gateway_destinations (
				destination_id, gateway_audience_id, destination_state, created_at, state_changed_at
			)
			values ($1, $2, $3, $4, $5)
		`, fixture.destinationID, audience.String(), fixture.destinationState, fixture.createdAt, fixture.stateChangedAt); err != nil {
			t.Fatal("destination resolver test destination seed 失败")
		}
		key, err := keySource.DestinationVerifierKey(ctx, audience, fixture.keyID)
		if err != nil {
			t.Fatal("destination resolver test key setup 失败")
		}
		verifier := integrationDestinationVerifier(audience, fixture.token, key)
		if _, err := pool.Exec(ctx, `
			insert into gateway_destination_tokens (
				destination_token_record_id, gateway_audience_id, destination_id,
				token_verifier, verifier_key_id, token_state, created_at, activated_at,
				retirement_started_at, revoked_at, expires_at, staged_cleanup_deadline,
				retirement_overlap_deadline, state_changed_at
			)
			values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
		`,
			fixture.recordID, audience.String(), fixture.destinationID, verifier,
			fixture.keyID.Value(), fixture.tokenState, fixture.createdAt, fixture.activatedAt,
			fixture.retirementStartedAt, fixture.revokedAt, fixture.expiresAt,
			fixture.createdAt.Add(12*time.Hour), fixture.retirementDeadline, fixture.stateChangedAt,
		); err != nil {
			t.Fatal("destination resolver test token seed 失败")
		}
	}
}

func integrationDestinationVerifier(
	audience securitystate.GatewayAudienceID,
	token securitystate.OpaqueDestinationToken,
	key securitystate.DestinationVerifierKey,
) []byte {
	mac := hmac.New(sha256.New, key.Bytes())
	_, _ = mac.Write([]byte("MS_ONCALL_GATEWAY_DESTINATION_TOKEN_V1"))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(audience.String()))
	_, _ = mac.Write([]byte{0})
	raw := token.Bytes()
	_, _ = mac.Write(raw[:])
	return mac.Sum(nil)
}

func deleteIntegrationDestinationState(
	ctx context.Context,
	pool *pgxpool.Pool,
	report func(string),
) bool {
	steps := []struct {
		message   string
		statement string
	}{
		{
			message: "destination resolver token cleanup 失败",
			statement: `delete from gateway_destination_tokens where destination_token_record_id in
				($1, $2, $3, $4, $5)`,
		},
		{
			message: "destination resolver destination cleanup 失败",
			statement: `delete from gateway_destinations where destination_id in
				($1, $2, $3, $4, $5)`,
		},
	}
	arguments := []any{
		integrationTokenActiveRecord,
		integrationTokenRetiringRecord,
		integrationTokenRevokedRecord,
		integrationTokenExpiredRecord,
		integrationTokenDisabledRecord,
	}
	destinationArguments := []any{
		integrationDestinationActiveID,
		integrationDestinationRetiringID,
		integrationDestinationRevokedID,
		integrationDestinationExpiredID,
		integrationDestinationDisabledID,
	}
	ok := true
	for index, step := range steps {
		stepArguments := arguments
		if index == 1 {
			stepArguments = destinationArguments
		}
		if _, err := pool.Exec(ctx, step.statement, stepArguments...); err != nil {
			report(step.message)
			ok = false
		}
	}
	if _, err := pool.Exec(ctx,
		"delete from gateway_security_realm where gateway_audience_id = $1",
		integrationDestinationAudienceText,
	); err != nil {
		report("destination resolver realm cleanup 失败")
		ok = false
	}

	var remaining int64
	if err := pool.QueryRow(ctx, `
		select
			(select count(*) from gateway_destination_tokens where destination_token_record_id in ($1, $2, $3, $4, $5)) +
			(select count(*) from gateway_destinations where destination_id in ($6, $7, $8, $9, $10)) +
			(select count(*) from gateway_security_realm where gateway_audience_id = $11)
	`,
		integrationTokenActiveRecord,
		integrationTokenRetiringRecord,
		integrationTokenRevokedRecord,
		integrationTokenExpiredRecord,
		integrationTokenDisabledRecord,
		integrationDestinationActiveID,
		integrationDestinationRetiringID,
		integrationDestinationRevokedID,
		integrationDestinationExpiredID,
		integrationDestinationDisabledID,
		integrationDestinationAudienceText,
	).Scan(&remaining); err != nil {
		report("destination resolver cleanup verification 失败")
		ok = false
	} else if remaining != 0 {
		report("destination resolver cleanup 留有test-only记录")
		ok = false
	}
	return ok
}

func countIntegrationDestinationRows(t *testing.T, ctx context.Context, pool *pgxpool.Pool) int64 {
	t.Helper()
	var count int64
	if err := pool.QueryRow(ctx, `
		select count(*) from gateway_destination_tokens
		where gateway_audience_id = $1
	`, integrationDestinationAudienceText).Scan(&count); err != nil {
		t.Fatal("destination resolver test-owned row count 失败")
	}
	return count
}

func mustIntegrationDestinationResolver(
	t *testing.T,
	pool *pgxpool.Pool,
	keySource integrationDestinationKeySource,
	keyIDs []securitystate.DestinationVerifierKeyID,
) *OpaqueDestinationResolver {
	t.Helper()
	resolver, err := NewOpaqueDestinationResolver(pool, keySource, keyIDs)
	if err != nil {
		t.Fatal("destination resolver integration setup 失败")
	}
	return resolver
}

func mustIntegrationDestinationAudience(t *testing.T) securitystate.GatewayAudienceID {
	t.Helper()
	value, err := securitystate.ParseGatewayAudienceID(integrationDestinationAudienceText)
	if err != nil {
		t.Fatal("destination resolver test audience setup 失败")
	}
	return value
}

func mustIntegrationDestinationID(t *testing.T, value string) securitystate.DestinationID {
	t.Helper()
	parsed, err := securitystate.ParseDestinationID(value)
	if err != nil {
		t.Fatal("destination resolver test destination setup 失败")
	}
	return parsed
}

func mustIntegrationDestinationToken(t *testing.T, seed byte) securitystate.OpaqueDestinationToken {
	t.Helper()
	raw := make([]byte, 32)
	for index := range raw {
		raw[index] = seed + byte(index)
	}
	value, err := securitystate.ParseOpaqueDestinationToken("mso1_" + base64.RawURLEncoding.EncodeToString(raw))
	if err != nil {
		t.Fatal("destination resolver test token setup 失败")
	}
	return value
}

func mustIntegrationDestinationKeyID(t *testing.T, value string) securitystate.DestinationVerifierKeyID {
	t.Helper()
	keyID, err := securitystate.NewDestinationVerifierKeyID(value)
	if err != nil {
		t.Fatal("destination resolver test key ID setup 失败")
	}
	return keyID
}

func mustIntegrationDestinationKey(t *testing.T, seed byte) securitystate.DestinationVerifierKey {
	t.Helper()
	material := make([]byte, 32)
	for index := range material {
		material[index] = seed + byte(index)
	}
	key, err := securitystate.NewDestinationVerifierKey(material)
	if err != nil {
		t.Fatal("destination resolver test key setup 失败")
	}
	return key
}
