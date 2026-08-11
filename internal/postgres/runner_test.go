package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type fakeMigrationLocker struct {
	session     MigrationSession
	err         error
	lockCalls   int
	waitForDone bool
}

func (l *fakeMigrationLocker) WithMigrationLock(ctx context.Context, run func(MigrationSession) error) error {
	l.lockCalls++
	if l.waitForDone {
		<-ctx.Done()
		return safeError(ErrMigrationLock, "lock acquisition")
	}
	if l.err != nil {
		return l.err
	}
	return run(l.session)
}

type fakeMigrationSession struct {
	initialized bool
	applied     []AppliedMigration
	applyCalls  []int64
	failVersion int64
	failErr     error
	inspectErr  error
	inspectCall int
}

func (s *fakeMigrationSession) Inspect(_ context.Context, migrations []Migration) (Inspection, error) {
	s.inspectCall++
	if s.inspectErr != nil {
		return Inspection{Status: SchemaQueryError}, s.inspectErr
	}
	return classifySnapshot(MetadataSnapshot{
		TableExists: s.initialized,
		Complete:    s.initialized,
		Applied:     append([]AppliedMigration(nil), s.applied...),
	}, migrations), nil
}

func (s *fakeMigrationSession) Apply(_ context.Context, migration Migration) error {
	s.applyCalls = append(s.applyCalls, migration.Version)
	if migration.Version == s.failVersion {
		if s.failErr != nil {
			return s.failErr
		}
		return safeError(ErrMigration, "migration execution")
	}
	s.initialized = true
	s.applied = append(s.applied, AppliedMigration{
		Version: migration.Version, Checksum: migration.Checksum, AppliedAt: time.Unix(migration.Version, 0).UTC(),
	})
	return nil
}

func testMigrations(count int) []Migration {
	result := make([]Migration, count)
	for index := range result {
		result[index] = Migration{Version: int64(index + 1), Checksum: strings.Repeat(string(rune('a'+index)), 64)}
	}
	return result
}

func TestRunnerCurrentDoesNotApplyMigration(t *testing.T) {
	migrations := testMigrations(1)
	session := &fakeMigrationSession{initialized: true, applied: []AppliedMigration{{Version: 1, Checksum: migrations[0].Checksum, AppliedAt: time.Unix(1, 0).UTC()}}}
	locker := &fakeMigrationLocker{session: session}
	if err := NewRunner(locker, migrations, nil).Run(context.Background()); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if len(session.applyCalls) != 0 {
		t.Errorf("apply calls = %v, want none", session.applyCalls)
	}
	if session.inspectCall != 2 {
		t.Errorf("inspect calls = %d, want initial and final", session.inspectCall)
	}
}

func TestRunnerUninitializedAppliesFromOneInOrder(t *testing.T) {
	migrations := testMigrations(3)
	session := &fakeMigrationSession{}
	if err := NewRunner(&fakeMigrationLocker{session: session}, migrations, nil).Run(context.Background()); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	want := []int64{1, 2, 3}
	if len(session.applyCalls) != len(want) {
		t.Fatalf("apply calls = %v, want %v", session.applyCalls, want)
	}
	for index := range want {
		if session.applyCalls[index] != want[index] {
			t.Errorf("apply calls = %v, want %v", session.applyCalls, want)
		}
	}
}

func TestRunnerBehindAppliesOnlyMissingMigrations(t *testing.T) {
	migrations := testMigrations(3)
	session := &fakeMigrationSession{initialized: true, applied: []AppliedMigration{{Version: 1, Checksum: migrations[0].Checksum, AppliedAt: time.Unix(1, 0).UTC()}}}
	if err := NewRunner(&fakeMigrationLocker{session: session}, migrations, nil).Run(context.Background()); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if len(session.applyCalls) != 2 || session.applyCalls[0] != 2 || session.applyCalls[1] != 3 {
		t.Errorf("apply calls = %v, want [2 3]", session.applyCalls)
	}
}

func TestRunnerStopsAfterMigrationFailure(t *testing.T) {
	migrations := testMigrations(3)
	session := &fakeMigrationSession{failVersion: 2}
	err := NewRunner(&fakeMigrationLocker{session: session}, migrations, nil).Run(context.Background())
	if !errors.Is(err, ErrMigration) {
		t.Fatalf("error = %v, want ErrMigration", err)
	}
	if len(session.applyCalls) != 2 || session.applyCalls[0] != 1 || session.applyCalls[1] != 2 {
		t.Errorf("apply calls = %v, want [1 2]", session.applyCalls)
	}
	if session.inspectCall != 2 {
		t.Errorf("inspect calls = %d, want no post-failure current report", session.inspectCall)
	}
}

func TestRunnerRejectsAheadAndInvalidSchemas(t *testing.T) {
	migrations := testMigrations(1)
	now := time.Unix(1, 0).UTC()
	for _, test := range []struct {
		name    string
		applied []AppliedMigration
		want    error
	}{
		{name: "ahead", applied: []AppliedMigration{{Version: 1, Checksum: migrations[0].Checksum, AppliedAt: now}, {Version: 2, Checksum: strings.Repeat("b", 64), AppliedAt: now}}, want: ErrSchemaAhead},
		{name: "invalid", applied: []AppliedMigration{{Version: 1, Checksum: strings.Repeat("f", 64), AppliedAt: now}}, want: ErrSchemaInvalid},
	} {
		t.Run(test.name, func(t *testing.T) {
			session := &fakeMigrationSession{initialized: true, applied: test.applied}
			err := NewRunner(&fakeMigrationLocker{session: session}, migrations, nil).Run(context.Background())
			if !errors.Is(err, test.want) {
				t.Errorf("error = %v, want %v", err, test.want)
			}
			if len(session.applyCalls) != 0 {
				t.Errorf("apply calls = %v, want none", session.applyCalls)
			}
		})
	}
}

func TestRunnerMigrationLockSuccessFailureAndTimeout(t *testing.T) {
	migrations := testMigrations(1)
	session := &fakeMigrationSession{}
	success := &fakeMigrationLocker{session: session}
	if err := NewRunner(success, migrations, nil).Run(context.Background()); err != nil {
		t.Fatalf("success error: %v", err)
	}
	if success.lockCalls != 1 {
		t.Errorf("success lock calls = %d, want 1", success.lockCalls)
	}

	failure := &fakeMigrationLocker{err: safeError(ErrMigrationLock, "lock acquisition")}
	if err := NewRunner(failure, migrations, nil).Run(context.Background()); !errors.Is(err, ErrMigrationLock) {
		t.Errorf("failure error = %v, want ErrMigrationLock", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	timed := &fakeMigrationLocker{waitForDone: true}
	if err := NewRunner(timed, migrations, nil).Run(ctx); !errors.Is(err, ErrMigrationLock) {
		t.Errorf("timeout error = %v, want ErrMigrationLock", err)
	}
}

func TestRunnerAfterConnectionInterruptionReacquiresLockAndReinspects(t *testing.T) {
	migrations := testMigrations(1)
	interrupted := &fakeMigrationLocker{err: safeError(ErrMigrationLock, "migration connection")}
	if err := NewRunner(interrupted, migrations, nil).Run(context.Background()); !errors.Is(err, ErrMigrationLock) {
		t.Fatalf("interrupted run error = %v, want ErrMigrationLock", err)
	}
	if interrupted.lockCalls != 1 {
		t.Fatalf("interrupted lock calls = %d, want 1", interrupted.lockCalls)
	}

	reselectedSession := &fakeMigrationSession{}
	reselected := &fakeMigrationLocker{session: reselectedSession}
	if err := NewRunner(reselected, migrations, nil).Run(context.Background()); err != nil {
		t.Fatalf("restarted run error: %v", err)
	}
	if reselected.lockCalls != 1 {
		t.Errorf("restarted lock calls = %d, want 1", reselected.lockCalls)
	}
	if reselectedSession.inspectCall != 3 {
		t.Errorf("restarted inspect calls = %d, want initial, post-apply, and final", reselectedSession.inspectCall)
	}
	if len(reselectedSession.applyCalls) != 1 || reselectedSession.applyCalls[0] != 1 {
		t.Errorf("restarted apply calls = %v, want [1]", reselectedSession.applyCalls)
	}
}

func TestRunnerStopsAfterMigrationInterruptionWithoutReplay(t *testing.T) {
	migrations := testMigrations(2)
	session := &fakeMigrationSession{
		failVersion: 1,
		failErr:     safeError(ErrMigrationInterrupted, "transaction commit"),
	}
	err := NewRunner(&fakeMigrationLocker{session: session}, migrations, nil).Run(context.Background())
	if !errors.Is(err, ErrMigrationInterrupted) || !errors.Is(err, ErrMigration) {
		t.Fatalf("error = %v, want interrupted migration", err)
	}
	if len(session.applyCalls) != 1 || session.applyCalls[0] != 1 {
		t.Errorf("apply calls = %v, want one attempt for version 1", session.applyCalls)
	}
	if session.inspectCall != 1 {
		t.Errorf("inspect calls = %d, want no post-interruption replay or verification", session.inspectCall)
	}
}
