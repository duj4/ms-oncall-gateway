package postgres

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/duj4/ms-oncall-gateway/internal/securitystate"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	integrationAuthenticationAudienceText  = "11111111-1111-1111-8111-111111111111"
	integrationAuthenticationPrincipalText = "22222222-2222-2222-8222-222222222222"
	integrationAuthenticationSlotText      = "33333333-3333-3333-8333-333333333333"
	integrationAuthenticationRecordText    = "44444444-4444-4444-8444-444444444444"
	integrationAuthenticationPublicText    = "55555555-5555-4555-8555-555555555555"
	integrationAuthenticationNonceOne      = "AAAAAAAAAAAAAAAAAAAAAQ"
	integrationAuthenticationNonceTwo      = "AAAAAAAAAAAAAAAAAAAAAg"
)

var integrationAuthenticationBaseTime = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

func TestAuthenticationStatePostgresIntegration(t *testing.T) {
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
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		defer pool.Close()
		if !deleteIntegrationAuthenticationState(cleanupCtx, pool, func(message string) {
			t.Error(message)
		}) {
			t.Error("authentication-state integration final cleanup 不完整")
		}
	})

	verifyIntegrationSession(t, ctx, pool, databaseURL)
	if err := NewRunner(NewPGBackend(pool), EmbeddedMigrations(), nil).Run(ctx); err != nil {
		t.Fatal("authentication-state integration schema preparation 失败")
	}

	initialCleanupCtx, initialCleanupCancel := context.WithTimeout(ctx, 10*time.Second)
	initialCleanupOK := deleteIntegrationAuthenticationState(initialCleanupCtx, pool, func(message string) {
		t.Error(message)
	})
	initialCleanupCancel()
	if !initialCleanupOK {
		t.Fatal("authentication-state integration initial cleanup 失败")
	}
	assertNoForeignIntegrationRealm(t, ctx, pool)

	seedIntegrationAuthenticationState(t, ctx, pool)
	audience := mustIntegrationAuthenticationAudience(t)
	principalID := mustIntegrationAuthenticationPrincipal(t)
	recordID := mustIntegrationAuthenticationRecord(t)
	publicID := mustIntegrationAuthenticationPublic(t)

	repository := NewAuthenticationStateRepository(pool)
	boundAudience, err := repository.BoundAudience(ctx)
	if err != nil || boundAudience != audience {
		t.Fatal("authentication-state realm round trip 失败")
	}

	credential, err := repository.Credential(ctx, audience, publicID)
	if err != nil || credential.AudienceID() != audience || credential.PublicID() != publicID ||
		credential.RecordID() != recordID || credential.PrincipalID() != principalID ||
		credential.State() != securitystate.CredentialActive || !credential.UsableAt(integrationAuthenticationBaseTime.Add(30*time.Minute)) {
		t.Fatal("authentication-state credential round trip 失败")
	}

	principal, err := repository.Principal(ctx, audience, principalID)
	if err != nil || principal.AudienceID() != audience || principal.ID() != principalID ||
		!principal.Enabled() || !principal.IntakeAuthorized() {
		t.Fatal("authentication-state principal round trip 失败")
	}

	nonceOne := mustIntegrationAuthenticationNonce(t, integrationAuthenticationNonceOne)
	repositories := []*AuthenticationStateRepository{
		NewAuthenticationStateRepository(pool),
		NewAuthenticationStateRepository(pool),
	}
	const callers = 8
	start := make(chan struct{})
	dispositions := make(chan securitystate.ReplayReservationDisposition, callers)
	errorsFound := make(chan error, callers)
	var wait sync.WaitGroup
	wait.Add(callers)
	for index := range callers {
		currentRepository := repositories[index%len(repositories)]
		go func() {
			defer wait.Done()
			<-start
			disposition, reserveErr := currentRepository.Reserve(
				ctx,
				recordID,
				nonceOne,
				integrationAuthenticationBaseTime.Add(30*time.Minute),
			)
			dispositions <- disposition
			errorsFound <- reserveErr
		}()
	}
	close(start)
	wait.Wait()
	close(dispositions)
	close(errorsFound)

	for reserveErr := range errorsFound {
		if reserveErr != nil {
			t.Fatal("authentication-state concurrent replay reservation 失败")
		}
	}
	reservedCount := 0
	duplicateCount := 0
	for disposition := range dispositions {
		switch disposition {
		case securitystate.ReplayReserved:
			reservedCount++
		case securitystate.ReplayDuplicate:
			duplicateCount++
		default:
			t.Fatal("authentication-state concurrent replay disposition 无效")
		}
	}
	if reservedCount != 1 || duplicateCount != callers-1 {
		t.Fatal("authentication-state concurrent replay uniqueness 失败")
	}

	nonceTwo := mustIntegrationAuthenticationNonce(t, integrationAuthenticationNonceTwo)
	disposition, err := repositories[1].Reserve(
		ctx,
		recordID,
		nonceTwo,
		integrationAuthenticationBaseTime.Add(31*time.Minute),
	)
	if err != nil || disposition != securitystate.ReplayReserved {
		t.Fatal("authentication-state independent replay nonce reservation 失败")
	}
	if countIntegrationAuthenticationReplays(t, ctx, pool) != 2 {
		t.Fatal("authentication-state replay row count 无效")
	}
}

func seedIntegrationAuthenticationState(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	createdAt := integrationAuthenticationBaseTime
	if _, err := pool.Exec(ctx, `
		insert into gateway_security_realm (singleton_key, gateway_audience_id, created_at)
		values (true, $1, $2)
	`, integrationAuthenticationAudienceText, createdAt); err != nil {
		t.Fatal("authentication-state test realm seed 失败")
	}
	if _, err := pool.Exec(ctx, `
		insert into core_principals (
			core_principal_id,
			gateway_audience_id,
			enabled,
			gateway_intake_v1_authorized,
			created_at,
			state_changed_at
		)
		values ($1, $2, true, true, $3, $4)
	`,
		integrationAuthenticationPrincipalText,
		integrationAuthenticationAudienceText,
		createdAt,
		createdAt.Add(time.Minute),
	); err != nil {
		t.Fatal("authentication-state test principal seed 失败")
	}
	if _, err := pool.Exec(ctx, `
		insert into core_credential_slots (
			credential_slot_id,
			gateway_audience_id,
			core_principal_id,
			created_at
		)
		values ($1, $2, $3, $4)
	`,
		integrationAuthenticationSlotText,
		integrationAuthenticationAudienceText,
		integrationAuthenticationPrincipalText,
		createdAt.Add(2*time.Minute),
	); err != nil {
		t.Fatal("authentication-state test credential slot seed 失败")
	}
	if _, err := pool.Exec(ctx, `
		insert into core_authentication_credentials (
			credential_record_id,
			credential_id,
			credential_slot_id,
			gateway_audience_id,
			core_principal_id,
			credential_state,
			not_before,
			expires_at,
			activated_at,
			retirement_started_at,
			retirement_overlap_deadline,
			revoked_at,
			created_at,
			state_changed_at
		)
		values ($1, $2, $3, $4, $5, 'active', $6, $7, $8, null, null, null, $9, $10)
	`,
		integrationAuthenticationRecordText,
		integrationAuthenticationPublicText,
		integrationAuthenticationSlotText,
		integrationAuthenticationAudienceText,
		integrationAuthenticationPrincipalText,
		createdAt.Add(3*time.Minute),
		createdAt.Add(24*time.Hour),
		createdAt.Add(4*time.Minute),
		createdAt.Add(3*time.Minute),
		createdAt.Add(4*time.Minute),
	); err != nil {
		t.Fatal("authentication-state test credential seed 失败")
	}
}

func deleteIntegrationAuthenticationState(
	ctx context.Context,
	pool *pgxpool.Pool,
	report func(string),
) bool {
	steps := []struct {
		message   string
		statement string
		argument  string
	}{
		{
			message:   "authentication-state replay cleanup 失败",
			statement: "delete from authentication_replay_reservations where credential_record_id = $1",
			argument:  integrationAuthenticationRecordText,
		},
		{
			message:   "authentication-state credential cleanup 失败",
			statement: "delete from core_authentication_credentials where credential_record_id = $1",
			argument:  integrationAuthenticationRecordText,
		},
		{
			message:   "authentication-state credential slot cleanup 失败",
			statement: "delete from core_credential_slots where credential_slot_id = $1",
			argument:  integrationAuthenticationSlotText,
		},
		{
			message:   "authentication-state principal cleanup 失败",
			statement: "delete from core_principals where core_principal_id = $1",
			argument:  integrationAuthenticationPrincipalText,
		},
		{
			message:   "authentication-state realm cleanup 失败",
			statement: "delete from gateway_security_realm where gateway_audience_id = $1",
			argument:  integrationAuthenticationAudienceText,
		},
	}
	ok := true
	for _, step := range steps {
		if _, err := pool.Exec(ctx, step.statement, step.argument); err != nil {
			report(step.message)
			ok = false
		}
	}
	var remaining int64
	if err := pool.QueryRow(ctx, `
		select
			(select count(*) from authentication_replay_reservations where credential_record_id = $1) +
			(select count(*) from core_authentication_credentials where credential_record_id = $1) +
			(select count(*) from core_credential_slots where credential_slot_id = $2) +
			(select count(*) from core_principals where core_principal_id = $3) +
			(select count(*) from gateway_security_realm where gateway_audience_id = $4)
	`,
		integrationAuthenticationRecordText,
		integrationAuthenticationSlotText,
		integrationAuthenticationPrincipalText,
		integrationAuthenticationAudienceText,
	).Scan(&remaining); err != nil {
		report("authentication-state cleanup verification 失败")
		ok = false
	} else if remaining != 0 {
		report("authentication-state cleanup 留有test-only记录")
		ok = false
	}
	return ok
}

func assertNoForeignIntegrationRealm(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	var count int64
	if err := pool.QueryRow(ctx, "select count(*) from gateway_security_realm").Scan(&count); err != nil {
		t.Fatal("authentication-state test realm inspection 失败")
	}
	if count != 0 {
		t.Fatal("authentication-state test database 存在非test-only realm")
	}
}

func countIntegrationAuthenticationReplays(t *testing.T, ctx context.Context, pool *pgxpool.Pool) int64 {
	t.Helper()
	var count int64
	if err := pool.QueryRow(
		ctx,
		"select count(*) from authentication_replay_reservations where credential_record_id = $1",
		integrationAuthenticationRecordText,
	).Scan(&count); err != nil {
		t.Fatal("authentication-state replay count inspection 失败")
	}
	return count
}

func mustIntegrationAuthenticationAudience(t *testing.T) securitystate.GatewayAudienceID {
	t.Helper()
	value, err := securitystate.ParseGatewayAudienceID(integrationAuthenticationAudienceText)
	if err != nil {
		t.Fatal("authentication-state test audience fixture 无效")
	}
	return value
}

func mustIntegrationAuthenticationPrincipal(t *testing.T) securitystate.CorePrincipalID {
	t.Helper()
	value, err := securitystate.ParseCorePrincipalID(integrationAuthenticationPrincipalText)
	if err != nil {
		t.Fatal("authentication-state test principal fixture 无效")
	}
	return value
}

func mustIntegrationAuthenticationRecord(t *testing.T) securitystate.CredentialRecordID {
	t.Helper()
	value, err := securitystate.ParseCredentialRecordID(integrationAuthenticationRecordText)
	if err != nil {
		t.Fatal("authentication-state test credential record fixture 无效")
	}
	return value
}

func mustIntegrationAuthenticationPublic(t *testing.T) securitystate.CredentialID {
	t.Helper()
	value, err := securitystate.ParseCredentialID(integrationAuthenticationPublicText)
	if err != nil {
		t.Fatal("authentication-state test public credential fixture 无效")
	}
	return value
}

func mustIntegrationAuthenticationNonce(t *testing.T, text string) securitystate.ReplayNonce {
	t.Helper()
	value, err := securitystate.ParseReplayNonce(text)
	if err != nil {
		t.Fatal("authentication-state test replay nonce fixture 无效")
	}
	return value
}
