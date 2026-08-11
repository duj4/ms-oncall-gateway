package postgres

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/duj4/ms-oncall-gateway/internal/durable"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const integrationTestKeyID = "test-only-key"

type integrationDigestOpener struct{}

func (integrationDigestOpener) OpenDigest(_ context.Context, request durable.DigestOpenRequest) (durable.CanonicalDigest, error) {
	if request.EncryptionKeyID != integrationTestKeyID || string(request.ProtectedDigest.Nonce()) != "test-only-nonce" {
		return durable.CanonicalDigest{}, errors.New("test-only protected digest unavailable")
	}
	ciphertext := request.ProtectedDigest.Ciphertext()
	if len(ciphertext) != sha256.Size {
		return durable.CanonicalDigest{}, errors.New("test-only protected digest invalid")
	}
	var digest durable.CanonicalDigest
	for index := range digest {
		digest[index] = ciphertext[index] ^ 0xa5
	}
	return digest, nil
}

func protectIntegrationDigest(t *testing.T, digest durable.CanonicalDigest) durable.ProtectedValue {
	t.Helper()
	ciphertext := make([]byte, len(digest))
	for index := range digest {
		ciphertext[index] = digest[index] ^ 0xa5
	}
	protected, err := durable.NewProtectedValue(ciphertext, []byte("test-only-nonce"))
	if err != nil {
		t.Fatal(err)
	}
	return protected
}

func integrationIdentity(t *testing.T) durable.DeliveryIdentity {
	t.Helper()
	receipt, err := (durable.UUIDv4Generator{}).NewReceiptID()
	if err != nil {
		t.Fatal("生成 test delivery identity 失败")
	}
	return durable.DeliveryIdentity(receipt)
}

func integrationPrepared(
	t *testing.T,
	principal string,
	destination string,
	identity durable.DeliveryIdentity,
	eventText string,
) durable.PreparedAcceptance {
	t.Helper()
	literalDigest := durable.CanonicalDigest(sha256.Sum256([]byte(eventText)))
	event, err := durable.NewProtectedValue([]byte("test-only-event-"+eventText), []byte("test-only-event-nonce"))
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := durable.NewPreparedAcceptance(
		principal,
		destination,
		identity,
		1,
		event,
		protectIntegrationDigest(t, literalDigest),
		integrationTestKeyID,
		literalDigest,
	)
	if err != nil {
		t.Fatal(err)
	}
	return prepared
}

func TestDurableAcceptancePostgresIntegration(t *testing.T) {
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
		if _, err := pool.Exec(cleanupCtx, "truncate table durable_acceptances"); err != nil {
			t.Error("final durable_acceptances cleanup failed")
		}
	})
	verifyIntegrationSession(t, ctx, pool, databaseURL)
	if err := NewRunner(NewPGBackend(pool), EmbeddedMigrations(), nil).Run(ctx); err != nil {
		t.Fatalf("schema preparation 失败: %v", err)
	}
	truncateDurableAcceptances(t, ctx, pool)

	newStore := func(target Pool) durable.Store {
		return durable.NewService(NewAcceptanceRepository(target), integrationDigestOpener{})
	}

	t.Run("first insert and sequential duplicate", func(t *testing.T) {
		truncateDurableAcceptances(t, ctx, pool)
		store := newStore(pool)
		prepared := integrationPrepared(t, "principal-a", "destination-a", integrationIdentity(t), "event-a")
		first, err := store.Accept(ctx, prepared)
		if err != nil || first.Disposition != durable.AcceptedNew || first.ReceiptID.IsZero() {
			t.Fatalf("first result/error = %+v/%v", first, err)
		}
		duplicate, err := store.Accept(ctx, prepared)
		if err != nil || duplicate.Disposition != durable.AcceptedDuplicate || duplicate.ReceiptID != first.ReceiptID {
			t.Fatalf("duplicate result/error = %+v/%v", duplicate, err)
		}
		if count := durableAcceptanceCount(t, ctx, pool); count != 1 {
			t.Fatalf("row count = %d, want 1", count)
		}
	})

	t.Run("concurrent identical requests", func(t *testing.T) {
		truncateDurableAcceptances(t, ctx, pool)
		store := newStore(pool)
		prepared := integrationPrepared(t, "principal-b", "destination-b", integrationIdentity(t), "event-b")
		const callers = 8
		results := make(chan durable.Result, callers)
		errorsFound := make(chan error, callers)
		var wait sync.WaitGroup
		wait.Add(callers)
		for range callers {
			go func() {
				defer wait.Done()
				result, err := store.Accept(ctx, prepared)
				results <- result
				errorsFound <- err
			}()
		}
		wait.Wait()
		close(results)
		close(errorsFound)
		for err := range errorsFound {
			if err != nil {
				t.Fatalf("concurrent identical acceptance: %v", err)
			}
		}
		var stableReceipt durable.ReceiptID
		newCount := 0
		for result := range results {
			if result.Disposition == durable.AcceptedNew {
				newCount++
			}
			if result.Disposition != durable.AcceptedNew && result.Disposition != durable.AcceptedDuplicate {
				t.Fatalf("unexpected disposition = %d", result.Disposition)
			}
			if stableReceipt.IsZero() {
				stableReceipt = result.ReceiptID
			} else if result.ReceiptID != stableReceipt {
				t.Fatal("concurrent duplicates did not return one stable receipt")
			}
		}
		if newCount != 1 || durableAcceptanceCount(t, ctx, pool) != 1 {
			t.Fatalf("new/row count = %d/%d, want 1/1", newCount, durableAcceptanceCount(t, ctx, pool))
		}
	})

	t.Run("same identity different event concurrency", func(t *testing.T) {
		truncateDurableAcceptances(t, ctx, pool)
		store := newStore(pool)
		identity := integrationIdentity(t)
		prepared := []durable.PreparedAcceptance{
			integrationPrepared(t, "principal-c", "destination-c", identity, "event-c-1"),
			integrationPrepared(t, "principal-c", "destination-c", identity, "event-c-2"),
		}
		results := make(chan durable.Result, 2)
		errorsFound := make(chan error, 2)
		var wait sync.WaitGroup
		for _, acceptance := range prepared {
			wait.Add(1)
			go func(value durable.PreparedAcceptance) {
				defer wait.Done()
				result, err := store.Accept(ctx, value)
				results <- result
				errorsFound <- err
			}(acceptance)
		}
		wait.Wait()
		close(results)
		close(errorsFound)
		for err := range errorsFound {
			if err != nil {
				t.Fatalf("concurrent conflict acceptance: %v", err)
			}
		}
		newCount, conflictCount := 0, 0
		for result := range results {
			switch result.Disposition {
			case durable.AcceptedNew:
				newCount++
			case durable.IdentityConflict:
				conflictCount++
				if !result.ReceiptID.IsZero() {
					t.Fatal("identity conflict returned a receipt")
				}
			default:
				t.Fatalf("unexpected disposition = %d", result.Disposition)
			}
		}
		if newCount != 1 || conflictCount != 1 || durableAcceptanceCount(t, ctx, pool) != 1 {
			t.Fatalf("new/conflict/row count = %d/%d/%d", newCount, conflictCount, durableAcceptanceCount(t, ctx, pool))
		}
	})

	t.Run("principal and destination isolation", func(t *testing.T) {
		truncateDurableAcceptances(t, ctx, pool)
		store := newStore(pool)
		identity := integrationIdentity(t)
		for _, prepared := range []durable.PreparedAcceptance{
			integrationPrepared(t, "principal-d-1", "destination-d-1", identity, "event-d"),
			integrationPrepared(t, "principal-d-2", "destination-d-1", identity, "event-d"),
			integrationPrepared(t, "principal-d-1", "destination-d-2", identity, "event-d"),
		} {
			result, err := store.Accept(ctx, prepared)
			if err != nil || result.Disposition != durable.AcceptedNew {
				t.Fatalf("isolated acceptance result/error = %+v/%v", result, err)
			}
		}
		if count := durableAcceptanceCount(t, ctx, pool); count != 3 {
			t.Fatalf("isolated row count = %d, want 3", count)
		}
	})

	t.Run("receipt remains stable through a new pool", func(t *testing.T) {
		truncateDurableAcceptances(t, ctx, pool)
		prepared := integrationPrepared(t, "principal-e", "destination-e", integrationIdentity(t), "event-e")
		first, err := newStore(pool).Accept(ctx, prepared)
		if err != nil || first.Disposition != durable.AcceptedNew {
			t.Fatalf("first acceptance: %+v/%v", first, err)
		}
		reconnectedPool := openIntegrationPool(t, ctx, databaseURL)
		defer reconnectedPool.Close()
		verifyIntegrationSession(t, ctx, reconnectedPool, databaseURL)
		duplicate, err := newStore(reconnectedPool).Accept(ctx, prepared)
		if err != nil || duplicate.Disposition != durable.AcceptedDuplicate || duplicate.ReceiptID != first.ReceiptID {
			t.Fatalf("reconnected duplicate: %+v/%v", duplicate, err)
		}
	})

	t.Run("rollback does not persist", func(t *testing.T) {
		truncateDurableAcceptances(t, ctx, pool)
		connection, err := pool.Acquire(ctx)
		if err != nil {
			t.Fatal("acquire rollback probe connection failed")
		}
		defer connection.Release()
		transaction, err := connection.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted, AccessMode: pgx.ReadWrite})
		if err != nil {
			t.Fatal("begin rollback probe failed")
		}
		prepared := integrationPrepared(t, "principal-f", "destination-f", integrationIdentity(t), "event-f")
		receipt, err := (durable.UUIDv4Generator{}).NewReceiptID()
		if err != nil {
			t.Fatal("generate rollback receipt failed")
		}
		if err := insertIntegrationAcceptance(ctx, transaction, receipt, prepared); err != nil {
			_ = transaction.Rollback(ctx)
			t.Fatal("insert rollback probe failed")
		}
		if err := transaction.Rollback(ctx); err != nil {
			t.Fatal("rollback probe failed")
		}
		if count := durableAcceptanceCount(t, ctx, pool); count != 0 {
			t.Fatalf("rollback row count = %d, want 0", count)
		}
	})

	t.Run("context deadline never reports acceptance", func(t *testing.T) {
		truncateDurableAcceptances(t, ctx, pool)
		identity := integrationIdentity(t)
		prepared := integrationPrepared(t, "principal-g", "destination-g", identity, "event-g")
		holder, err := pool.Acquire(ctx)
		if err != nil {
			t.Fatal("acquire deadline probe connection failed")
		}
		defer holder.Release()
		transaction, err := holder.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted, AccessMode: pgx.ReadWrite})
		if err != nil {
			t.Fatal("begin deadline probe failed")
		}
		receipt, err := (durable.UUIDv4Generator{}).NewReceiptID()
		if err != nil || insertIntegrationAcceptance(ctx, transaction, receipt, prepared) != nil {
			_ = transaction.Rollback(ctx)
			t.Fatal("prepare deadline probe failed")
		}
		deadlineCtx, deadlineCancel := context.WithTimeout(ctx, 25*time.Millisecond)
		defer deadlineCancel()
		result, acceptErr := newStore(pool).Accept(deadlineCtx, prepared)
		if acceptErr == nil || (!errors.Is(acceptErr, durable.ErrStoreCanceled) && !errors.Is(acceptErr, durable.ErrStoreOutcomeUnknown)) {
			t.Fatalf("deadline result/error = %+v/%v", result, acceptErr)
		}
		if result.Disposition != 0 || !result.ReceiptID.IsZero() {
			t.Fatalf("deadline unexpectedly reported acceptance: %+v", result)
		}
		if err := transaction.Rollback(ctx); err != nil {
			t.Fatal("deadline probe cleanup rollback failed")
		}
	})
}

func truncateDurableAcceptances(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	if _, err := pool.Exec(ctx, "truncate table durable_acceptances"); err != nil {
		t.Fatal("清理 durable_acceptances 失败")
	}
}

func durableAcceptanceCount(t *testing.T, ctx context.Context, pool *pgxpool.Pool) int {
	t.Helper()
	var count int
	if err := pool.QueryRow(ctx, "select count(*) from durable_acceptances").Scan(&count); err != nil {
		t.Fatal("读取 durable_acceptances 计数失败")
	}
	return count
}

func insertIntegrationAcceptance(ctx context.Context, transaction pgx.Tx, receipt durable.ReceiptID, prepared durable.PreparedAcceptance) error {
	event := prepared.CanonicalEvent()
	protectedDigest := prepared.ProtectedDigest()
	var returnedReceipt string
	return transaction.QueryRow(
		ctx,
		insertAcceptanceSQL,
		receipt.String(),
		prepared.CorePrincipalID(),
		prepared.DestinationID(),
		prepared.DeliveryIdentity().String(),
		prepared.FormatVersion(),
		event.Ciphertext(),
		event.Nonce(),
		protectedDigest.Ciphertext(),
		protectedDigest.Nonce(),
		prepared.EncryptionKeyID(),
	).Scan(&returnedReceipt)
}
