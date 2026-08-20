package postgres

import (
	"bytes"
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/duj4/ms-oncall-gateway/internal/securitystate"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	integrationLifecycleAudience    = "71111111-1111-1111-8111-111111111111"
	integrationLifecycleDestination = "72222222-2222-2222-8222-222222222222"
	integrationLifecycleRecordOne   = "73333333-3333-3333-8333-333333333333"
	integrationLifecycleRecordTwo   = "74444444-4444-4444-8444-444444444444"
	integrationLifecycleRecordThree = "75555555-5555-5555-8555-555555555555"
	integrationLifecycleRecordFour  = "76666666-6666-6666-8666-666666666666"
	integrationLifecycleRecordFive  = "77777777-7777-7777-8777-777777777777"
	integrationLifecycleRecordSix   = "78888888-8888-8888-8888-888888888888"
	integrationLifecycleRecordSeven = "79999999-9999-9999-8999-999999999999"
	integrationLifecycleRecordEight = "7aaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	integrationLifecycleRecordNine  = "7bbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	integrationLifecycleKeyID       = "lifecycle-integration-test-key"
)

var integrationLifecycleNow = time.Date(2032, time.March, 4, 5, 6, 7, 0, time.UTC)

type integrationLifecycleClock struct{ now time.Time }

func (clock integrationLifecycleClock) Now() time.Time { return clock.now }

type integrationLifecycleRecordGenerator struct {
	mu      sync.Mutex
	records []securitystate.DestinationTokenRecordID
}

func (generator *integrationLifecycleRecordGenerator) NewDestinationTokenRecordID(context.Context) (securitystate.DestinationTokenRecordID, error) {
	generator.mu.Lock()
	defer generator.mu.Unlock()
	if len(generator.records) == 0 {
		return securitystate.DestinationTokenRecordID{}, securitystate.ErrDestinationLifecycleUnavailable
	}
	record := generator.records[0]
	generator.records = generator.records[1:]
	return record, nil
}

type integrationLifecycleKeySource struct {
	keyID securitystate.DestinationVerifierKeyID
	key   securitystate.DestinationVerifierKey
}

func (source integrationLifecycleKeySource) DestinationVerifierKey(
	_ context.Context,
	_ securitystate.GatewayAudienceID,
	keyID securitystate.DestinationVerifierKeyID,
) (securitystate.DestinationVerifierKey, error) {
	if keyID != source.keyID {
		return securitystate.DestinationVerifierKey{}, securitystate.ErrVerifierKeyUnavailable
	}
	return source.key, nil
}

func TestDestinationTokenLifecyclePostgresIntegration(t *testing.T) {
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
	// Register pool close first. Cleanup is LIFO, so the test-owned mutation
	// cleanup registered after the verified session always runs first.
	t.Cleanup(pool.Close)
	verifyIntegrationSession(t, ctx, pool, databaseURL)
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		if !deleteIntegrationLifecycleState(cleanupCtx, pool, func(message string) { t.Error(message) }) {
			t.Error("destination lifecycle integration final cleanup 不完整")
		}
	})

	if err := NewRunner(NewPGBackend(pool), EmbeddedMigrations(), nil).Run(ctx); err != nil {
		t.Fatal("destination lifecycle integration schema preparation 失败")
	}
	initialCleanupCtx, initialCleanupCancel := context.WithTimeout(ctx, 10*time.Second)
	initialCleanupOK := deleteIntegrationLifecycleState(initialCleanupCtx, pool, func(message string) { t.Error(message) })
	initialCleanupCancel()
	if !initialCleanupOK {
		t.Fatal("destination lifecycle integration initial cleanup 失败")
	}
	assertNoForeignIntegrationRealm(t, ctx, pool)
	seedIntegrationLifecycleDestination(t, ctx, pool)

	audience := mustIntegrationLifecycleAudience(t)
	destination := mustIntegrationLifecycleDestination(t)
	keyID := mustIntegrationLifecycleKeyID(t)
	key := mustIntegrationLifecycleKey(t)
	keySource := integrationLifecycleKeySource{keyID: keyID, key: key}
	records := []securitystate.DestinationTokenRecordID{
		mustIntegrationLifecycleRecord(t, integrationLifecycleRecordOne),
		mustIntegrationLifecycleRecord(t, integrationLifecycleRecordTwo),
		mustIntegrationLifecycleRecord(t, integrationLifecycleRecordThree),
		mustIntegrationLifecycleRecord(t, integrationLifecycleRecordFour),
		mustIntegrationLifecycleRecord(t, integrationLifecycleRecordFive),
		mustIntegrationLifecycleRecord(t, integrationLifecycleRecordSix),
		mustIntegrationLifecycleRecord(t, integrationLifecycleRecordSeven),
		mustIntegrationLifecycleRecord(t, integrationLifecycleRecordEight),
		mustIntegrationLifecycleRecord(t, integrationLifecycleRecordNine),
	}
	service := mustIntegrationLifecycleService(t, pool, keySource, &integrationLifecycleRecordGenerator{records: []securitystate.DestinationTokenRecordID{records[0], records[1], records[2], records[4]}}, integrationLifecycleNow, 0x10)

	initial, err := service.CreateStagedToken(ctx, audience, destination)
	if err != nil || initial.RecordID() != records[0] || initial.Token().IsZero() {
		t.Fatal("destination lifecycle initial staged creation 失败")
	}
	initialToken := integrationLifecycleOpaqueToken(t, initial.Token())
	assertIntegrationLifecycleStatus(t, ctx, service, audience, destination, securitystate.LifecycleStagedInitial)
	concurrentIntegrationLifecycleOperation(t, []func() error{
		func() error {
			return NewDestinationTokenLifecycleRepository(pool).ActivateInitialToken(ctx, audience, destination, initial.RecordID(), integrationLifecycleNow)
		},
		func() error {
			return NewDestinationTokenLifecycleRepository(pool).ActivateInitialToken(ctx, audience, destination, initial.RecordID(), integrationLifecycleNow)
		},
	})
	assertIntegrationLifecycleResolution(t, ctx, pool, keySource, keyID, audience, initial.Token(), destination)

	rotation, err := service.CreateRotationStagedToken(
		ctx, audience, destination, initial.RecordID(), initialToken,
	)
	if err != nil || rotation.RecordID() != records[1] || rotation.Token().IsZero() {
		t.Fatal("destination lifecycle rotation staged creation 失败")
	}
	assertIntegrationLifecycleStatus(t, ctx, service, audience, destination, securitystate.LifecycleActiveWithStaged)
	activation := securitystate.ActivateRotationCommand{
		AudienceID: audience, DestinationID: destination, StagedRecordID: rotation.RecordID(),
		OldActiveRecordID: initial.RecordID(), Now: integrationLifecycleNow,
		OverlapDeadline: integrationLifecycleNow.Add(6 * time.Hour),
	}
	concurrentIntegrationLifecycleOperation(t, []func() error{
		func() error { return NewDestinationTokenLifecycleRepository(pool).ActivateRotation(ctx, activation) },
		func() error { return NewDestinationTokenLifecycleRepository(pool).ActivateRotation(ctx, activation) },
	})
	assertIntegrationLifecycleStatus(t, ctx, service, audience, destination, securitystate.LifecycleActiveWithRetiring)
	assertIntegrationLifecycleResolution(t, ctx, pool, keySource, keyID, audience, initial.Token(), destination)
	assertIntegrationLifecycleResolution(t, ctx, pool, keySource, keyID, audience, rotation.Token(), destination)
	concurrentIntegrationLifecycleOperation(t, []func() error{
		func() error {
			return NewDestinationTokenLifecycleRepository(pool).RollbackRotation(ctx, securitystate.RollbackRotationCommand{
				AudienceID: audience, DestinationID: destination, NewActiveRecordID: rotation.RecordID(),
				OldRetiringRecordID: initial.RecordID(), Now: integrationLifecycleNow,
			})
		},
		func() error {
			return NewDestinationTokenLifecycleRepository(pool).FinalizeRotation(ctx, securitystate.FinalizeRotationCommand{
				AudienceID: audience, DestinationID: destination, NewActiveRecordID: rotation.RecordID(),
				OldRetiringRecordID: initial.RecordID(), Reason: securitystate.RotationVerifiedAndDrained,
				Now: integrationLifecycleNow,
			})
		},
	})
	assertIntegrationLifecycleStatus(t, ctx, service, audience, destination, securitystate.LifecycleActive)
	currentSnapshot, err := service.InspectLifecycleState(ctx, audience, destination)
	if err != nil {
		t.Fatal("destination lifecycle current active inspection 失败")
	}
	currentActive, present := currentSnapshot.Active()
	if !present {
		t.Fatal("destination lifecycle current active record 缺失")
	}
	currentToken := initialToken
	if currentActive.RecordID() == rotation.RecordID() {
		currentToken = integrationLifecycleOpaqueToken(t, rotation.Token())
	} else if currentActive.RecordID() != initial.RecordID() {
		t.Fatal("destination lifecycle current active token identity unknown")
	}

	secondRotation, err := service.CreateRotationStagedToken(
		ctx, audience, destination, currentActive.RecordID(), currentToken,
	)
	if err != nil || secondRotation.RecordID() != records[2] {
		t.Fatal("destination lifecycle second rotation staged creation 失败")
	}
	if _, err := service.ActivateRotation(ctx, audience, destination, secondRotation.RecordID(), currentActive.RecordID()); err != nil {
		t.Fatal("destination lifecycle second rotation activation 失败")
	}
	secondRotationToken := integrationLifecycleOpaqueToken(t, secondRotation.Token())
	deadlineService := mustIntegrationLifecycleService(t, pool, keySource, &integrationLifecycleRecordGenerator{}, integrationLifecycleNow.Add(6*time.Hour), 0x40)
	concurrentFinalizeAndStageIntegrationLifecycle(
		t, ctx, pool, keySource, deadlineService, audience, destination,
		secondRotation.RecordID(), currentActive.RecordID(), secondRotationToken, records[3],
	)
	assertIntegrationLifecycleStatus(t, ctx, service, audience, destination, securitystate.LifecycleActive)

	aborted, err := service.CreateRotationStagedToken(
		ctx, audience, destination, secondRotation.RecordID(), secondRotationToken,
	)
	if err != nil || aborted.RecordID() != records[4] {
		t.Fatal("destination lifecycle abort candidate creation 失败")
	}
	if err := service.AbortStagedToken(ctx, audience, destination, aborted.RecordID()); err != nil {
		t.Fatal("destination lifecycle staged abort 失败")
	}
	assertIntegrationLifecycleStatus(t, ctx, service, audience, destination, securitystate.LifecycleActive)

	concurrentStageIntegrationLifecycle(
		t, ctx, pool, keySource, audience, destination,
		secondRotation.RecordID(), secondRotationToken, records[5:7],
	)
	concurrentRollbackAndStageIntegrationLifecycle(
		t, ctx, pool, keySource, audience, destination,
		secondRotationToken, records[7], records[8],
	)
	if countIntegrationLifecycleLiveRows(t, ctx, pool) > 2 {
		t.Fatal("destination lifecycle third-token prevention 失败")
	}
}

func concurrentIntegrationLifecycleOperation(t *testing.T, operations []func() error) {
	t.Helper()
	start := make(chan struct{})
	errorsFound := make(chan error, len(operations))
	var wait sync.WaitGroup
	wait.Add(len(operations))
	for _, operation := range operations {
		go func(current func() error) {
			defer wait.Done()
			<-start
			errorsFound <- current()
		}(operation)
	}
	close(start)
	wait.Wait()
	close(errorsFound)
	successes := 0
	conflicts := 0
	for err := range errorsFound {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, securitystate.ErrDestinationLifecycleConflict):
			conflicts++
		default:
			t.Fatal("destination lifecycle concurrent operation classification 失败")
		}
	}
	if successes != 1 || conflicts != len(operations)-1 {
		t.Fatal("destination lifecycle concurrent operation serialization 失败")
	}
}

func concurrentFinalizeAndStageIntegrationLifecycle(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	keys integrationLifecycleKeySource,
	finalizer *securitystate.DestinationTokenLifecycleService,
	audience securitystate.GatewayAudienceID,
	destination securitystate.DestinationID,
	newActive securitystate.DestinationTokenRecordID,
	oldRetiring securitystate.DestinationTokenRecordID,
	currentToken securitystate.OpaqueDestinationToken,
	stageRecord securitystate.DestinationTokenRecordID,
) {
	t.Helper()
	stageService := mustIntegrationLifecycleService(
		t, pool, keys,
		&integrationLifecycleRecordGenerator{records: []securitystate.DestinationTokenRecordID{stageRecord}},
		integrationLifecycleNow.Add(6*time.Hour), 0x60,
	)
	start := make(chan struct{})
	finalizeResult := make(chan error, 1)
	stageResult := make(chan struct {
		created securitystate.CreatedStagedToken
		err     error
	}, 1)
	go func() {
		<-start
		finalizeResult <- finalizer.FinalizeRotation(
			ctx, audience, destination, newActive, oldRetiring, securitystate.RotationDeadlineElapsed,
		)
	}()
	go func() {
		<-start
		created, err := stageService.CreateRotationStagedToken(
			ctx, audience, destination, newActive, currentToken,
		)
		stageResult <- struct {
			created securitystate.CreatedStagedToken
			err     error
		}{created: created, err: err}
	}()
	close(start)
	if err := <-finalizeResult; err != nil {
		t.Fatal("destination lifecycle concurrent finalization 失败")
	}
	staged := <-stageResult
	if staged.err != nil && !errors.Is(staged.err, securitystate.ErrDestinationLifecycleConflict) {
		t.Fatal("destination lifecycle concurrent finalize-stage classification 失败")
	}
	snapshot, err := finalizer.InspectLifecycleState(ctx, audience, destination)
	if err != nil || (snapshot.Status() != securitystate.LifecycleActive && snapshot.Status() != securitystate.LifecycleActiveWithStaged) {
		t.Fatal("destination lifecycle concurrent finalize-stage produced invalid state")
	}
	if staged.err == nil {
		if staged.created.RecordID() != stageRecord || staged.created.Token().IsZero() || snapshot.Status() != securitystate.LifecycleActiveWithStaged {
			t.Fatal("destination lifecycle concurrent stage result mismatch")
		}
		if err := stageService.AbortStagedToken(ctx, audience, destination, stageRecord); err != nil {
			t.Fatal("destination lifecycle concurrent finalize-stage cleanup transition 失败")
		}
	}
}

func mustIntegrationLifecycleService(
	t *testing.T,
	pool *pgxpool.Pool,
	keys securitystate.DestinationVerifierKeySource,
	records securitystate.DestinationTokenRecordIDGenerator,
	now time.Time,
	entropySeed byte,
) *securitystate.DestinationTokenLifecycleService {
	t.Helper()
	entropy := make([]byte, 32*8)
	for index := range entropy {
		entropy[index] = entropySeed + byte(index%251)
	}
	service, err := securitystate.NewDestinationTokenLifecycleService(securitystate.DestinationTokenLifecycleConfig{
		Clock: integrationLifecycleClock{now: now}, Random: bytes.NewReader(entropy), RecordIDs: records,
		Repository: NewDestinationTokenLifecycleRepository(pool), VerifierKeys: keys,
		ActiveVerifierKeyID: mustIntegrationLifecycleKeyID(t), TokenLifetime: 48 * time.Hour,
		StagedCleanupDuration: 12 * time.Hour, RetiringOverlap: 6 * time.Hour,
	})
	if err != nil {
		t.Fatal("destination lifecycle integration service setup 失败")
	}
	return service
}

func integrationLifecycleOpaqueToken(
	t *testing.T,
	token securitystate.OneTimeDestinationToken,
) securitystate.OpaqueDestinationToken {
	t.Helper()
	parsed, err := securitystate.ParseOpaqueDestinationToken(token.Value())
	if err != nil {
		t.Fatal("destination lifecycle integration opaque token setup failed")
	}
	return parsed
}

func concurrentStageIntegrationLifecycle(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	keys integrationLifecycleKeySource,
	audience securitystate.GatewayAudienceID,
	destination securitystate.DestinationID,
	activeRecord securitystate.DestinationTokenRecordID,
	currentToken securitystate.OpaqueDestinationToken,
	records []securitystate.DestinationTokenRecordID,
) {
	t.Helper()
	services := []*securitystate.DestinationTokenLifecycleService{
		mustIntegrationLifecycleService(t, pool, keys, &integrationLifecycleRecordGenerator{records: records[:1]}, integrationLifecycleNow.Add(time.Minute), 0x80),
		mustIntegrationLifecycleService(t, pool, keys, &integrationLifecycleRecordGenerator{records: records[1:]}, integrationLifecycleNow.Add(time.Minute), 0xc0),
	}
	start := make(chan struct{})
	results := make(chan securitystate.CreatedStagedToken, 2)
	errorsFound := make(chan error, 2)
	var wait sync.WaitGroup
	wait.Add(2)
	for _, service := range services {
		go func(current *securitystate.DestinationTokenLifecycleService) {
			defer wait.Done()
			<-start
			created, err := current.CreateRotationStagedToken(
				ctx, audience, destination, activeRecord, currentToken,
			)
			results <- created
			errorsFound <- err
		}(service)
	}
	close(start)
	wait.Wait()
	close(results)
	close(errorsFound)

	successes := 0
	conflicts := 0
	var staged securitystate.CreatedStagedToken
	for err := range errorsFound {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, securitystate.ErrDestinationLifecycleConflict):
			conflicts++
		default:
			t.Fatal("destination lifecycle concurrent stage classification 失败")
		}
	}
	for result := range results {
		if !result.Token().IsZero() {
			staged = result
		}
	}
	if successes != 1 || conflicts != 1 || staged.RecordID().IsZero() || staged.Token().IsZero() {
		t.Fatal("destination lifecycle concurrent stage serialization 失败")
	}
	if err := services[0].AbortStagedToken(ctx, audience, destination, staged.RecordID()); err != nil {
		t.Fatal("destination lifecycle concurrent stage cleanup transition 失败")
	}
}

func concurrentRollbackAndStageIntegrationLifecycle(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	keys integrationLifecycleKeySource,
	audience securitystate.GatewayAudienceID,
	destination securitystate.DestinationID,
	currentToken securitystate.OpaqueDestinationToken,
	rotationRecord securitystate.DestinationTokenRecordID,
	stageRecord securitystate.DestinationTokenRecordID,
) {
	t.Helper()
	now := integrationLifecycleNow.Add(7 * time.Hour)
	setupService := mustIntegrationLifecycleService(
		t, pool, keys,
		&integrationLifecycleRecordGenerator{records: []securitystate.DestinationTokenRecordID{rotationRecord}},
		now, 0x20,
	)
	before, err := setupService.InspectLifecycleState(ctx, audience, destination)
	if err != nil {
		t.Fatal("destination lifecycle rollback-stage setup inspection 失败")
	}
	oldActive, present := before.Active()
	if !present || before.Status() != securitystate.LifecycleActive {
		t.Fatal("destination lifecycle rollback-stage setup state 无效")
	}
	rotation, err := setupService.CreateRotationStagedToken(
		ctx, audience, destination, oldActive.RecordID(), currentToken,
	)
	if err != nil || rotation.RecordID() != rotationRecord || rotation.Token().IsZero() {
		t.Fatal("destination lifecycle rollback-stage rotation creation 失败")
	}
	if _, err := setupService.ActivateRotation(ctx, audience, destination, rotationRecord, oldActive.RecordID()); err != nil {
		t.Fatal("destination lifecycle rollback-stage rotation activation 失败")
	}

	rollbackService := mustIntegrationLifecycleService(
		t, pool, keys, &integrationLifecycleRecordGenerator{}, now, 0x30,
	)
	stageService := mustIntegrationLifecycleService(
		t, pool, keys,
		&integrationLifecycleRecordGenerator{records: []securitystate.DestinationTokenRecordID{stageRecord}},
		now, 0x50,
	)
	start := make(chan struct{})
	rollbackResult := make(chan error, 1)
	stageResult := make(chan struct {
		created securitystate.CreatedStagedToken
		err     error
	}, 1)
	go func() {
		<-start
		rollbackResult <- rollbackService.RollbackRotation(
			ctx, audience, destination, rotationRecord, oldActive.RecordID(),
		)
	}()
	go func() {
		<-start
		created, createErr := stageService.CreateRotationStagedToken(
			ctx, audience, destination, oldActive.RecordID(), currentToken,
		)
		stageResult <- struct {
			created securitystate.CreatedStagedToken
			err     error
		}{created: created, err: createErr}
	}()
	close(start)

	if err := <-rollbackResult; err != nil {
		t.Fatal("destination lifecycle concurrent rollback 失败")
	}
	staged := <-stageResult
	if staged.err != nil && !errors.Is(staged.err, securitystate.ErrDestinationLifecycleConflict) {
		t.Fatal("destination lifecycle concurrent rollback-stage classification 失败")
	}
	finalSnapshot, err := rollbackService.InspectLifecycleState(ctx, audience, destination)
	if err != nil || (finalSnapshot.Status() != securitystate.LifecycleActive && finalSnapshot.Status() != securitystate.LifecycleActiveWithStaged) {
		t.Fatal("destination lifecycle concurrent rollback-stage produced invalid state")
	}
	finalActive, activePresent := finalSnapshot.Active()
	_, retiringPresent := finalSnapshot.Retiring()
	if !activePresent || finalActive.RecordID() != oldActive.RecordID() || retiringPresent {
		t.Fatal("destination lifecycle concurrent rollback-stage active state mismatch")
	}
	liveRows := countIntegrationLifecycleLiveRows(t, ctx, pool)
	if liveRows < 1 || liveRows > 2 {
		t.Fatal("destination lifecycle concurrent rollback-stage third-token prevention 失败")
	}
	if staged.err == nil {
		stagedView, stagedPresent := finalSnapshot.Staged()
		if staged.created.RecordID() != stageRecord || staged.created.Token().IsZero() ||
			!stagedPresent || stagedView.RecordID() != stageRecord ||
			finalSnapshot.Status() != securitystate.LifecycleActiveWithStaged || liveRows != 2 {
			t.Fatal("destination lifecycle concurrent rollback-stage staged result mismatch")
		}
		if err := stageService.AbortStagedToken(ctx, audience, destination, stageRecord); err != nil {
			t.Fatal("destination lifecycle concurrent rollback-stage cleanup transition 失败")
		}
	} else if finalSnapshot.Status() != securitystate.LifecycleActive || liveRows != 1 {
		t.Fatal("destination lifecycle concurrent rollback-stage conflict result mismatch")
	}
}

func assertIntegrationLifecycleResolution(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	keys integrationLifecycleKeySource,
	keyID securitystate.DestinationVerifierKeyID,
	audience securitystate.GatewayAudienceID,
	oneTime securitystate.OneTimeDestinationToken,
	want securitystate.DestinationID,
) {
	t.Helper()
	token, err := securitystate.ParseOpaqueDestinationToken(oneTime.Value())
	if err != nil {
		t.Fatal("destination lifecycle resolver token setup 失败")
	}
	resolver, err := NewOpaqueDestinationResolver(pool, keys, []securitystate.DestinationVerifierKeyID{keyID})
	if err != nil {
		t.Fatal("destination lifecycle resolver setup 失败")
	}
	resolved, err := resolver.Resolve(ctx, audience, token, integrationLifecycleNow.Add(time.Minute))
	if err != nil || resolved != want {
		t.Fatal("destination lifecycle resolver interoperability 失败")
	}
}

func assertIntegrationLifecycleStatus(
	t *testing.T,
	ctx context.Context,
	service *securitystate.DestinationTokenLifecycleService,
	audience securitystate.GatewayAudienceID,
	destination securitystate.DestinationID,
	want securitystate.DestinationLifecycleStatus,
) {
	t.Helper()
	snapshot, err := service.InspectLifecycleState(ctx, audience, destination)
	if err != nil || snapshot.Status() != want {
		t.Fatal("destination lifecycle integration inspection mismatch")
	}
}

func seedIntegrationLifecycleDestination(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	if _, err := pool.Exec(ctx, `
		insert into gateway_security_realm (singleton_key, gateway_audience_id, created_at)
		values (true, $1, $2)
	`, integrationLifecycleAudience, integrationLifecycleNow.Add(-time.Hour)); err != nil {
		t.Fatal("destination lifecycle test realm seed 失败")
	}
	if _, err := pool.Exec(ctx, `
		insert into gateway_destinations (
			destination_id, gateway_audience_id, destination_state, created_at, state_changed_at
		) values ($1, $2, 'enabled', $3, $3)
	`, integrationLifecycleDestination, integrationLifecycleAudience, integrationLifecycleNow.Add(-time.Hour)); err != nil {
		t.Fatal("destination lifecycle test destination seed 失败")
	}
}

func deleteIntegrationLifecycleState(ctx context.Context, pool *pgxpool.Pool, report func(string)) bool {
	ok := true
	records := []any{
		integrationLifecycleRecordOne, integrationLifecycleRecordTwo, integrationLifecycleRecordThree,
		integrationLifecycleRecordFour, integrationLifecycleRecordFive, integrationLifecycleRecordSix,
		integrationLifecycleRecordSeven, integrationLifecycleRecordEight, integrationLifecycleRecordNine,
	}
	if _, err := pool.Exec(ctx, `delete from gateway_destination_tokens where destination_token_record_id in ($1,$2,$3,$4,$5,$6,$7,$8,$9)`, records...); err != nil {
		report("destination lifecycle token cleanup 失败")
		ok = false
	}
	if _, err := pool.Exec(ctx, `delete from gateway_destinations where destination_id = $1`, integrationLifecycleDestination); err != nil {
		report("destination lifecycle destination cleanup 失败")
		ok = false
	}
	if _, err := pool.Exec(ctx, `delete from gateway_security_realm where gateway_audience_id = $1`, integrationLifecycleAudience); err != nil {
		report("destination lifecycle realm cleanup 失败")
		ok = false
	}
	var remaining int64
	if err := pool.QueryRow(ctx, `
		select
			(select count(*) from gateway_destination_tokens where destination_token_record_id in ($1,$2,$3,$4,$5,$6,$7,$8,$9)) +
			(select count(*) from gateway_destinations where destination_id = $10) +
			(select count(*) from gateway_security_realm where gateway_audience_id = $11)
	`, append(records, integrationLifecycleDestination, integrationLifecycleAudience)...).Scan(&remaining); err != nil {
		report("destination lifecycle cleanup verification 失败")
		return false
	}
	if remaining != 0 {
		report("destination lifecycle cleanup verification 非零")
		ok = false
	}
	return ok
}

func countIntegrationLifecycleLiveRows(t *testing.T, ctx context.Context, pool *pgxpool.Pool) int64 {
	t.Helper()
	var count int64
	if err := pool.QueryRow(ctx, `
		select count(*) from gateway_destination_tokens
		where destination_id = $1 and token_state in ('staged','active','retiring')
	`, integrationLifecycleDestination).Scan(&count); err != nil {
		t.Fatal("destination lifecycle live-row count 失败")
	}
	return count
}

func mustIntegrationLifecycleAudience(t *testing.T) securitystate.GatewayAudienceID {
	t.Helper()
	value, err := securitystate.ParseGatewayAudienceID(integrationLifecycleAudience)
	if err != nil {
		t.Fatal("destination lifecycle integration audience setup 失败")
	}
	return value
}

func mustIntegrationLifecycleDestination(t *testing.T) securitystate.DestinationID {
	t.Helper()
	value, err := securitystate.ParseDestinationID(integrationLifecycleDestination)
	if err != nil {
		t.Fatal("destination lifecycle integration destination setup 失败")
	}
	return value
}

func mustIntegrationLifecycleRecord(t *testing.T, text string) securitystate.DestinationTokenRecordID {
	t.Helper()
	value, err := securitystate.ParseDestinationTokenRecordID(text)
	if err != nil {
		t.Fatal("destination lifecycle integration record setup 失败")
	}
	return value
}

func mustIntegrationLifecycleKeyID(t *testing.T) securitystate.DestinationVerifierKeyID {
	t.Helper()
	value, err := securitystate.NewDestinationVerifierKeyID(integrationLifecycleKeyID)
	if err != nil {
		t.Fatal("destination lifecycle integration key ID setup 失败")
	}
	return value
}

func mustIntegrationLifecycleKey(t *testing.T) securitystate.DestinationVerifierKey {
	t.Helper()
	material := make([]byte, 32)
	for index := range material {
		material[index] = byte(index)
	}
	value, err := securitystate.NewDestinationVerifierKey(material)
	if err != nil {
		t.Fatal("destination lifecycle integration key setup 失败")
	}
	return value
}
