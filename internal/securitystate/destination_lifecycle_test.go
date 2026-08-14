package securitystate

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	lifecycleTestAudienceText    = "11111111-2222-3333-8444-555555555555"
	lifecycleTestDestinationText = "66666666-7777-8888-8999-aaaaaaaaaaaa"
	lifecycleTestRecordOneText   = "88888888-9999-aaaa-8bbb-cccccccccccc"
	lifecycleTestRecordTwoText   = "99999999-aaaa-bbbb-8ccc-dddddddddddd"
	lifecycleTestKeyIDText       = "lifecycle-test-only-key"
	lifecyclePrivateMarker       = "lifecycle-test-only-private-marker"
	lifecycleGoldenToken         = "mso1_AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
	lifecycleGoldenVerifier      = "89090ee7ca4101838432e2efaee10d35355d6361e0c41a0776ec9d67c2470640"
)

var lifecycleTestNow = time.Date(2031, time.February, 3, 4, 5, 6, 0, time.UTC)

type lifecycleTestClock struct {
	mu    sync.Mutex
	now   time.Time
	calls int
}

func (clock *lifecycleTestClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	clock.calls++
	return clock.now
}

func (clock *lifecycleTestClock) callCount() int {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.calls
}

type lifecycleTestRecordGenerator struct {
	mu      sync.Mutex
	records []DestinationTokenRecordID
	err     error
	calls   int
}

func (generator *lifecycleTestRecordGenerator) NewDestinationTokenRecordID(context.Context) (DestinationTokenRecordID, error) {
	generator.mu.Lock()
	defer generator.mu.Unlock()
	generator.calls++
	if generator.err != nil || len(generator.records) == 0 {
		return DestinationTokenRecordID{}, generator.err
	}
	record := generator.records[0]
	generator.records = generator.records[1:]
	return record, nil
}

type lifecycleTestKeySource struct {
	mu       sync.Mutex
	key      DestinationVerifierKey
	err      error
	calls    int
	audience GatewayAudienceID
	keyID    DestinationVerifierKeyID
}

func (source *lifecycleTestKeySource) DestinationVerifierKey(_ context.Context, audience GatewayAudienceID, keyID DestinationVerifierKeyID) (DestinationVerifierKey, error) {
	source.mu.Lock()
	defer source.mu.Unlock()
	source.calls++
	source.audience = audience
	source.keyID = keyID
	return source.key, source.err
}

type lifecycleRepositoryCall struct {
	operation string
	candidate StagedTokenCandidate
	audience  GatewayAudienceID
	dest      DestinationID
	first     DestinationTokenRecordID
	second    DestinationTokenRecordID
	reason    RotationCompletionReason
	now       time.Time
	deadline  time.Time
}

type lifecycleTestRepository struct {
	mu       sync.Mutex
	calls    []lifecycleRepositoryCall
	err      error
	snapshot DestinationLifecycleSnapshot
}

func (repository *lifecycleTestRepository) add(call lifecycleRepositoryCall) error {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	repository.calls = append(repository.calls, call)
	return repository.err
}

func (repository *lifecycleTestRepository) CreateStagedToken(_ context.Context, candidate StagedTokenCandidate, now time.Time) error {
	return repository.add(lifecycleRepositoryCall{operation: "create", candidate: candidate, now: now})
}

func (repository *lifecycleTestRepository) ActivateInitialToken(_ context.Context, audience GatewayAudienceID, destination DestinationID, staged DestinationTokenRecordID, now time.Time) error {
	return repository.add(lifecycleRepositoryCall{operation: "activate-initial", audience: audience, dest: destination, first: staged, now: now})
}

func (repository *lifecycleTestRepository) ActivateRotation(_ context.Context, command ActivateRotationCommand) error {
	return repository.add(lifecycleRepositoryCall{operation: "activate-rotation", audience: command.AudienceID, dest: command.DestinationID, first: command.StagedRecordID, second: command.OldActiveRecordID, now: command.Now, deadline: command.OverlapDeadline})
}

func (repository *lifecycleTestRepository) AbortStagedToken(_ context.Context, audience GatewayAudienceID, destination DestinationID, staged DestinationTokenRecordID, now time.Time) error {
	return repository.add(lifecycleRepositoryCall{operation: "abort", audience: audience, dest: destination, first: staged, now: now})
}

func (repository *lifecycleTestRepository) RollbackRotation(_ context.Context, command RollbackRotationCommand) error {
	return repository.add(lifecycleRepositoryCall{operation: "rollback", audience: command.AudienceID, dest: command.DestinationID, first: command.NewActiveRecordID, second: command.OldRetiringRecordID, now: command.Now})
}

func (repository *lifecycleTestRepository) FinalizeRotation(_ context.Context, command FinalizeRotationCommand) error {
	return repository.add(lifecycleRepositoryCall{operation: "finalize", audience: command.AudienceID, dest: command.DestinationID, first: command.NewActiveRecordID, second: command.OldRetiringRecordID, reason: command.Reason, now: command.Now})
}

func (repository *lifecycleTestRepository) InspectLifecycleState(_ context.Context, audience GatewayAudienceID, destination DestinationID, now time.Time) (DestinationLifecycleSnapshot, error) {
	err := repository.add(lifecycleRepositoryCall{operation: "inspect", audience: audience, dest: destination, now: now})
	return repository.snapshot, err
}

func (repository *lifecycleTestRepository) callSnapshot() []lifecycleRepositoryCall {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	return append([]lifecycleRepositoryCall(nil), repository.calls...)
}

type lifecycleErrorReader struct{ err error }

func (reader lifecycleErrorReader) Read([]byte) (int, error) { return 0, reader.err }

type lifecycleCountingReader struct{ calls int }

func (reader *lifecycleCountingReader) Read(buffer []byte) (int, error) {
	reader.calls++
	for index := range buffer {
		buffer[index] = byte(index)
	}
	return len(buffer), nil
}

func mustLifecycleAudience(t *testing.T) GatewayAudienceID {
	t.Helper()
	value, err := ParseGatewayAudienceID(lifecycleTestAudienceText)
	if err != nil {
		t.Fatal("lifecycle test audience setup failed")
	}
	return value
}

func mustLifecycleDestinationID(t *testing.T) DestinationID {
	t.Helper()
	value, err := ParseDestinationID(lifecycleTestDestinationText)
	if err != nil {
		t.Fatal("lifecycle test destination setup failed")
	}
	return value
}

func mustLifecycleRecordID(t *testing.T, text string) DestinationTokenRecordID {
	t.Helper()
	value, err := ParseDestinationTokenRecordID(text)
	if err != nil {
		t.Fatal("lifecycle test record setup failed")
	}
	return value
}

func mustLifecycleKeyID(t *testing.T) DestinationVerifierKeyID {
	t.Helper()
	value, err := NewDestinationVerifierKeyID(lifecycleTestKeyIDText)
	if err != nil {
		t.Fatal("lifecycle test key identifier setup failed")
	}
	return value
}

func mustLifecycleKey(t *testing.T) DestinationVerifierKey {
	t.Helper()
	material := make([]byte, 32)
	for index := range material {
		material[index] = byte(index)
	}
	value, err := NewDestinationVerifierKey(material)
	if err != nil {
		t.Fatal("lifecycle test key setup failed")
	}
	return value
}

func lifecycleEntropy(blocks int) []byte {
	result := make([]byte, blocks*32)
	for block := 0; block < blocks; block++ {
		for index := 0; index < 32; index++ {
			result[block*32+index] = byte(block + index)
		}
	}
	return result
}

func newLifecycleTestService(t *testing.T, repository *lifecycleTestRepository, random io.Reader, generator DestinationTokenRecordIDGenerator) (*DestinationTokenLifecycleService, *lifecycleTestClock, *lifecycleTestKeySource) {
	t.Helper()
	clock := &lifecycleTestClock{now: lifecycleTestNow}
	keys := &lifecycleTestKeySource{key: mustLifecycleKey(t)}
	service, err := NewDestinationTokenLifecycleService(DestinationTokenLifecycleConfig{
		Clock: clock, Random: random, RecordIDs: generator, Repository: repository,
		VerifierKeys: keys, ActiveVerifierKeyID: mustLifecycleKeyID(t),
		TokenLifetime: 48 * time.Hour, StagedCleanupDuration: 12 * time.Hour,
		RetiringOverlap: 6 * time.Hour,
	})
	if err != nil {
		t.Fatal("lifecycle test service setup failed")
	}
	return service, clock, keys
}

func TestDestinationLifecycleConfigurationBounds(t *testing.T) {
	repository := &lifecycleTestRepository{}
	clock := &lifecycleTestClock{now: lifecycleTestNow}
	generator := &lifecycleTestRecordGenerator{records: []DestinationTokenRecordID{mustLifecycleRecordID(t, lifecycleTestRecordOneText)}}
	keySource := &lifecycleTestKeySource{key: mustLifecycleKey(t)}
	valid := DestinationTokenLifecycleConfig{
		Clock: clock, Random: bytes.NewReader(lifecycleEntropy(1)), RecordIDs: generator,
		Repository: repository, VerifierKeys: keySource, ActiveVerifierKeyID: mustLifecycleKeyID(t),
		TokenLifetime:         MaximumDestinationTokenLifetime,
		StagedCleanupDuration: MaximumStagedCleanupDuration,
		RetiringOverlap:       MaximumRetiringOverlapDuration,
	}
	if service, err := NewDestinationTokenLifecycleService(valid); err != nil || service == nil {
		t.Fatal("maximum lifecycle policy bounds were rejected")
	}

	invalid := []DestinationTokenLifecycleConfig{
		{},
		func() DestinationTokenLifecycleConfig { value := valid; value.Clock = nil; return value }(),
		func() DestinationTokenLifecycleConfig { value := valid; value.Random = nil; return value }(),
		func() DestinationTokenLifecycleConfig { value := valid; value.RecordIDs = nil; return value }(),
		func() DestinationTokenLifecycleConfig { value := valid; value.Repository = nil; return value }(),
		func() DestinationTokenLifecycleConfig { value := valid; value.VerifierKeys = nil; return value }(),
		func() DestinationTokenLifecycleConfig {
			value := valid
			value.ActiveVerifierKeyID = DestinationVerifierKeyID{}
			return value
		}(),
		func() DestinationTokenLifecycleConfig { value := valid; value.TokenLifetime = 0; return value }(),
		func() DestinationTokenLifecycleConfig {
			value := valid
			value.TokenLifetime = MaximumDestinationTokenLifetime + time.Nanosecond
			return value
		}(),
		func() DestinationTokenLifecycleConfig {
			value := valid
			value.StagedCleanupDuration = MaximumStagedCleanupDuration + time.Nanosecond
			return value
		}(),
		func() DestinationTokenLifecycleConfig {
			value := valid
			value.RetiringOverlap = MaximumRetiringOverlapDuration + time.Nanosecond
			return value
		}(),
	}
	for range invalid {
		configuration := invalid[0]
		invalid = invalid[1:]
		service, err := NewDestinationTokenLifecycleService(configuration)
		if service != nil || !errors.Is(err, ErrDestinationLifecycleInvalid) {
			t.Fatal("invalid lifecycle configuration was accepted")
		}
	}
}

func TestDestinationLifecycleTokenLifetimeExceedsRetiringOverlap(t *testing.T) {
	for _, test := range []struct {
		name     string
		lifetime time.Duration
		valid    bool
	}{
		{name: "shorter", lifetime: 6*time.Hour - time.Nanosecond},
		{name: "equal", lifetime: 6 * time.Hour},
		{name: "strictly longer", lifetime: 6*time.Hour + time.Nanosecond, valid: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			repository := &lifecycleTestRepository{}
			clock := &lifecycleTestClock{now: lifecycleTestNow}
			random := &lifecycleCountingReader{}
			generator := &lifecycleTestRecordGenerator{records: []DestinationTokenRecordID{
				mustLifecycleRecordID(t, lifecycleTestRecordOneText),
			}}
			keySource := &lifecycleTestKeySource{key: mustLifecycleKey(t)}
			service, err := NewDestinationTokenLifecycleService(DestinationTokenLifecycleConfig{
				Clock: clock, Random: random, RecordIDs: generator, Repository: repository,
				VerifierKeys: keySource, ActiveVerifierKeyID: mustLifecycleKeyID(t),
				TokenLifetime: test.lifetime, StagedCleanupDuration: time.Hour,
				RetiringOverlap: 6 * time.Hour,
			})
			if test.valid {
				if err != nil || service == nil {
					t.Fatal("strictly longer lifecycle token lifetime was rejected")
				}
			} else if service != nil || err != ErrDestinationLifecycleInvalid {
				t.Fatal("unsafe lifecycle token lifetime was accepted")
			}
			if clock.callCount() != 0 || random.calls != 0 || generator.calls != 0 ||
				keySource.calls != 0 || len(repository.callSnapshot()) != 0 {
				t.Fatal("lifecycle configuration validation invoked a dependency")
			}
		})
	}
}

func TestDestinationLifecycleUUIDv4Generator(t *testing.T) {
	input := make([]byte, 32)
	for index := range input {
		input[index] = byte(index)
	}
	generator := NewUUIDv4DestinationTokenRecordIDGenerator(bytes.NewReader(input))
	first, err := generator.NewDestinationTokenRecordID(context.Background())
	if err != nil || first.IsZero() {
		t.Fatal("UUIDv4 lifecycle record generation failed")
	}
	firstBytes := [16]byte(first)
	if firstBytes[6]>>4 != 4 || firstBytes[8]>>6 != 2 {
		t.Fatal("lifecycle record does not have UUIDv4 version and RFC variant")
	}
	second, err := generator.NewDestinationTokenRecordID(context.Background())
	if err != nil || second.IsZero() || second == first {
		t.Fatal("lifecycle record generator reused a value")
	}
	failed, err := NewUUIDv4DestinationTokenRecordIDGenerator(lifecycleErrorReader{err: errors.New(lifecyclePrivateMarker)}).NewDestinationTokenRecordID(context.Background())
	if !errors.Is(err, ErrDestinationLifecycleUnavailable) || !failed.IsZero() || strings.Contains(err.Error(), lifecyclePrivateMarker) {
		t.Fatal("lifecycle record randomness failure was not safely classified")
	}
}

func TestDestinationLifecycleCreateGoldenAndOneTimeReturn(t *testing.T) {
	repository := &lifecycleTestRepository{}
	recordID := mustLifecycleRecordID(t, lifecycleTestRecordOneText)
	generator := &lifecycleTestRecordGenerator{records: []DestinationTokenRecordID{recordID}}
	service, clock, keys := newLifecycleTestService(t, repository, bytes.NewReader(lifecycleEntropy(1)), generator)

	created, err := service.CreateStagedToken(context.Background(), mustLifecycleAudience(t), mustLifecycleDestinationID(t))
	if err != nil || created.RecordID() != recordID || created.Token().Value() != lifecycleGoldenToken {
		t.Fatal("lifecycle staged token golden result mismatch")
	}
	calls := repository.callSnapshot()
	if len(calls) != 1 || calls[0].operation != "create" || calls[0].now != lifecycleTestNow {
		t.Fatal("lifecycle create repository call mismatch")
	}
	candidate := calls[0].candidate
	if candidate.AudienceID() != mustLifecycleAudience(t) || candidate.DestinationID() != mustLifecycleDestinationID(t) ||
		candidate.RecordID() != recordID || candidate.VerifierKeyID() != mustLifecycleKeyID(t) ||
		candidate.CreatedAt() != lifecycleTestNow || candidate.ExpiresAt() != lifecycleTestNow.Add(48*time.Hour) ||
		candidate.StagedCleanupDeadline() != lifecycleTestNow.Add(12*time.Hour) {
		t.Fatal("lifecycle staged candidate metadata mismatch")
	}
	expectedVerifier, decodeErr := hex.DecodeString(lifecycleGoldenVerifier)
	if decodeErr != nil {
		t.Fatal("lifecycle verifier expectation setup failed")
	}
	actualVerifier := candidate.Verifier().Bytes()
	if !bytes.Equal(actualVerifier[:], expectedVerifier) {
		t.Fatal("lifecycle verifier golden vector changed")
	}
	rawToken, parseErr := ParseOpaqueDestinationToken(lifecycleGoldenToken)
	if parseErr != nil {
		t.Fatal("lifecycle golden token setup failed")
	}
	wrongKeyMaterial := make([]byte, 32)
	for index := range wrongKeyMaterial {
		wrongKeyMaterial[index] = byte(index + 1)
	}
	wrongKey, keyErr := NewDestinationVerifierKey(wrongKeyMaterial)
	if keyErr != nil {
		t.Fatal("lifecycle wrong-key setup failed")
	}
	wrongKeyVerifier, verifierErr := ComputeDestinationTokenVerifier(mustLifecycleAudience(t), rawToken, wrongKey)
	if verifierErr != nil || wrongKeyVerifier == candidate.Verifier() {
		t.Fatal("lifecycle verifier did not bind its key")
	}
	wrongTokenBytes := rawToken.Bytes()
	wrongTokenBytes[0] ^= 1
	wrongTokenText := opaqueTokenPrefix + base64.RawURLEncoding.EncodeToString(wrongTokenBytes[:])
	wrongToken, parseErr := ParseOpaqueDestinationToken(wrongTokenText)
	if parseErr != nil {
		t.Fatal("lifecycle wrong-token setup failed")
	}
	wrongTokenVerifier, verifierErr := ComputeDestinationTokenVerifier(mustLifecycleAudience(t), wrongToken, mustLifecycleKey(t))
	if verifierErr != nil || wrongTokenVerifier == candidate.Verifier() {
		t.Fatal("lifecycle verifier did not bind its token")
	}
	if clock.callCount() != 1 || generator.calls != 1 || keys.calls != 1 || keys.audience != mustLifecycleAudience(t) || keys.keyID != mustLifecycleKeyID(t) {
		t.Fatal("lifecycle create dependency call count mismatch")
	}
	for _, formatted := range []string{fmt.Sprintf("%v", created), fmt.Sprintf("%+v", created.Token()), fmt.Sprintf("%#v", candidate)} {
		if formatted != "[redacted]" {
			t.Fatal("lifecycle sensitive value formatting was not redacted")
		}
	}
}

func TestDestinationLifecycleCreateFailuresReturnNoPartialToken(t *testing.T) {
	private := errors.New(lifecyclePrivateMarker)
	audience := mustLifecycleAudience(t)
	destination := mustLifecycleDestinationID(t)
	recordID := mustLifecycleRecordID(t, lifecycleTestRecordOneText)

	for _, test := range []struct {
		name      string
		random    io.Reader
		generator *lifecycleTestRecordGenerator
		keyErr    error
		repoErr   error
		want      error
		repoCalls int
	}{
		{name: "record generator", random: bytes.NewReader(lifecycleEntropy(1)), generator: &lifecycleTestRecordGenerator{err: private}, want: ErrDestinationLifecycleUnavailable},
		{name: "random failure", random: lifecycleErrorReader{err: private}, generator: &lifecycleTestRecordGenerator{records: []DestinationTokenRecordID{recordID}}, want: ErrDestinationLifecycleUnavailable},
		{name: "random short read", random: bytes.NewReader(make([]byte, 31)), generator: &lifecycleTestRecordGenerator{records: []DestinationTokenRecordID{recordID}}, want: ErrDestinationLifecycleUnavailable},
		{name: "key source", random: bytes.NewReader(lifecycleEntropy(1)), generator: &lifecycleTestRecordGenerator{records: []DestinationTokenRecordID{recordID}}, keyErr: private, want: ErrDestinationLifecycleUnavailable},
		{name: "repository conflict", random: bytes.NewReader(lifecycleEntropy(1)), generator: &lifecycleTestRecordGenerator{records: []DestinationTokenRecordID{recordID}}, repoErr: fmt.Errorf("wrapped: %w", ErrDestinationLifecycleConflict), want: ErrDestinationLifecycleConflict, repoCalls: 1},
		{name: "outcome unknown", random: bytes.NewReader(lifecycleEntropy(1)), generator: &lifecycleTestRecordGenerator{records: []DestinationTokenRecordID{recordID}}, repoErr: fmt.Errorf("wrapped: %w", ErrDestinationLifecycleOutcomeUnknown), want: ErrDestinationLifecycleOutcomeUnknown, repoCalls: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			repository := &lifecycleTestRepository{err: test.repoErr}
			service, _, keys := newLifecycleTestService(t, repository, test.random, test.generator)
			keys.err = test.keyErr
			created, err := service.CreateStagedToken(context.Background(), audience, destination)
			if !errors.Is(err, test.want) || !created.RecordID().IsZero() || !created.Token().IsZero() || len(repository.callSnapshot()) != test.repoCalls {
				t.Fatal("lifecycle create failure returned a partial result or wrong classification")
			}
			if strings.Contains(err.Error(), lifecyclePrivateMarker) || errors.Is(err, private) {
				t.Fatal("lifecycle create failure exposed dependency detail")
			}
		})
	}
}

func TestDestinationLifecycleOperationsUseOneClockSnapshot(t *testing.T) {
	audience := mustLifecycleAudience(t)
	destination := mustLifecycleDestinationID(t)
	first := mustLifecycleRecordID(t, lifecycleTestRecordOneText)
	second := mustLifecycleRecordID(t, lifecycleTestRecordTwoText)
	repository := &lifecycleTestRepository{snapshot: DestinationLifecycleSnapshot{audienceID: audience, destinationID: destination, status: LifecycleUnprovisioned}}
	service, clock, _ := newLifecycleTestService(t, repository, bytes.NewReader(lifecycleEntropy(1)), &lifecycleTestRecordGenerator{records: []DestinationTokenRecordID{first}})

	if err := service.ActivateInitialToken(context.Background(), audience, destination, first); err != nil {
		t.Fatal("lifecycle initial activation dispatch failed")
	}
	if err := service.ActivateRotation(context.Background(), audience, destination, first, second); err != nil {
		t.Fatal("lifecycle rotation activation dispatch failed")
	}
	if err := service.AbortStagedToken(context.Background(), audience, destination, first); err != nil {
		t.Fatal("lifecycle staged abort dispatch failed")
	}
	if err := service.RollbackRotation(context.Background(), audience, destination, first, second); err != nil {
		t.Fatal("lifecycle rollback dispatch failed")
	}
	if err := service.FinalizeRotation(context.Background(), audience, destination, first, second, RotationVerifiedAndDrained); err != nil {
		t.Fatal("lifecycle finalize dispatch failed")
	}
	if _, err := service.InspectLifecycleState(context.Background(), audience, destination); err != nil {
		t.Fatal("lifecycle inspection dispatch failed")
	}

	calls := repository.callSnapshot()
	if len(calls) != 6 || clock.callCount() != 6 {
		t.Fatal("lifecycle operation did not use exactly one clock read")
	}
	expected := []string{"activate-initial", "activate-rotation", "abort", "rollback", "finalize", "inspect"}
	for index, call := range calls {
		if call.operation != expected[index] || call.audience != audience || call.dest != destination || call.now != lifecycleTestNow {
			t.Fatal("lifecycle operation repository arguments mismatch")
		}
	}
	if calls[1].first != first || calls[1].second != second || calls[1].deadline != lifecycleTestNow.Add(6*time.Hour) ||
		calls[4].reason != RotationVerifiedAndDrained {
		t.Fatal("lifecycle pair operation metadata mismatch")
	}
}

func TestDestinationLifecycleInputCancellationAndSafeErrors(t *testing.T) {
	audience := mustLifecycleAudience(t)
	destination := mustLifecycleDestinationID(t)
	record := mustLifecycleRecordID(t, lifecycleTestRecordOneText)
	private := errors.New(lifecyclePrivateMarker)

	for _, test := range []struct {
		name string
		ctx  context.Context
		err  error
		want error
	}{
		{name: "unknown dependency", ctx: context.Background(), err: private, want: ErrDestinationLifecycleUnavailable},
		{name: "repository cancellation", ctx: context.Background(), err: context.Canceled, want: ErrDestinationLifecycleCanceled},
		{name: "repository deadline", ctx: context.Background(), err: context.DeadlineExceeded, want: ErrDestinationLifecycleDeadline},
		{name: "fixed repository cancellation", ctx: context.Background(), err: fmt.Errorf("outer: %w", ErrDestinationLifecycleCanceled), want: ErrDestinationLifecycleCanceled},
		{name: "fixed repository deadline", ctx: context.Background(), err: fmt.Errorf("outer: %w", ErrDestinationLifecycleDeadline), want: ErrDestinationLifecycleDeadline},
	} {
		t.Run(test.name, func(t *testing.T) {
			repository := &lifecycleTestRepository{err: test.err}
			service, _, _ := newLifecycleTestService(t, repository, bytes.NewReader(lifecycleEntropy(1)), &lifecycleTestRecordGenerator{records: []DestinationTokenRecordID{record}})
			err := service.ActivateInitialToken(test.ctx, audience, destination, record)
			if !errors.Is(err, test.want) || strings.Contains(err.Error(), lifecyclePrivateMarker) || errors.Is(err, private) {
				t.Fatal("lifecycle dependency error was not safely classified")
			}
		})
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	repository := &lifecycleTestRepository{}
	service, clock, _ := newLifecycleTestService(t, repository, bytes.NewReader(lifecycleEntropy(1)), &lifecycleTestRecordGenerator{records: []DestinationTokenRecordID{record}})
	if err := service.ActivateInitialToken(canceled, audience, destination, record); !errors.Is(err, ErrDestinationLifecycleCanceled) || len(repository.callSnapshot()) != 0 || clock.callCount() != 0 {
		t.Fatal("pre-canceled lifecycle operation reached dependencies")
	}
	if err := service.ActivateRotation(context.Background(), audience, destination, record, record); !errors.Is(err, ErrDestinationLifecycleInvalid) {
		t.Fatal("same-record lifecycle pair was accepted")
	}
	if err := service.FinalizeRotation(context.Background(), audience, destination, record, mustLifecycleRecordID(t, lifecycleTestRecordTwoText), RotationCompletionReason(99)); !errors.Is(err, ErrDestinationLifecycleInvalid) {
		t.Fatal("unknown lifecycle completion reason was accepted")
	}

	repository = &lifecycleTestRepository{err: errors.Join(ErrDestinationLifecycleConflict, private)}
	service, _, _ = newLifecycleTestService(t, repository, bytes.NewReader(lifecycleEntropy(1)), &lifecycleTestRecordGenerator{records: []DestinationTokenRecordID{record}})
	if err := service.ActivateInitialToken(context.Background(), audience, destination, record); !errors.Is(err, ErrDestinationLifecycleUnavailable) || errors.Is(err, ErrDestinationLifecycleConflict) || errors.Is(err, private) {
		t.Fatal("ambiguous multi-cause lifecycle error did not fail closed")
	}
	for _, test := range []struct {
		dependency error
		want       error
	}{
		{dependency: ErrDestinationLifecycleCanceled, want: ErrDestinationLifecycleCanceled},
		{dependency: ErrDestinationLifecycleDeadline, want: ErrDestinationLifecycleDeadline},
	} {
		repository = &lifecycleTestRepository{err: test.dependency}
		service, _, _ = newLifecycleTestService(t, repository, bytes.NewReader(lifecycleEntropy(1)), &lifecycleTestRecordGenerator{records: []DestinationTokenRecordID{record}})
		if err := service.ActivateInitialToken(context.Background(), audience, destination, record); !errors.Is(err, test.want) || err != test.want {
			t.Fatal("fixed lifecycle cancellation sentinel was not preserved")
		}
	}
	canceledAfterOutcome, cancelAfterOutcome := context.WithCancel(context.Background())
	cancelAfterOutcome()
	if err := classifyDestinationLifecycleError(canceledAfterOutcome, ErrDestinationLifecycleOutcomeUnknown); err != ErrDestinationLifecycleOutcomeUnknown {
		t.Fatal("cancellation obscured lifecycle outcome unknown")
	}

	for _, test := range []struct {
		name       string
		dependency error
		want       error
		unwanted   error
	}{
		{
			name:       "outer wrapped ambiguous conflict",
			dependency: fmt.Errorf("outer: %w", errors.Join(ErrDestinationLifecycleConflict, private)),
			want:       ErrDestinationLifecycleUnavailable, unwanted: ErrDestinationLifecycleConflict,
		},
		{
			name:       "joined same conflict sentinel",
			dependency: errors.Join(ErrDestinationLifecycleConflict, ErrDestinationLifecycleConflict),
			want:       ErrDestinationLifecycleUnavailable, unwanted: ErrDestinationLifecycleConflict,
		},
		{
			name:       "joined outcome unknown",
			dependency: errors.Join(ErrDestinationLifecycleOutcomeUnknown, private),
			want:       ErrDestinationLifecycleOutcomeUnknown,
		},
		{
			name:       "joined context cancellation",
			dependency: errors.Join(context.Canceled, private),
			want:       ErrDestinationLifecycleCanceled,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := classifyDestinationLifecycleError(context.Background(), test.dependency)
			if err != test.want || (test.unwanted != nil && errors.Is(err, test.unwanted)) ||
				errors.Is(err, private) || strings.Contains(err.Error(), lifecyclePrivateMarker) {
				t.Fatal("ambiguous lifecycle classifier result was not fixed and content-free")
			}
		})
	}
}

func TestDestinationLifecycleSnapshotClassificationAndBoundaries(t *testing.T) {
	audience := mustLifecycleAudience(t)
	destinationID := mustLifecycleDestinationID(t)
	destination, err := NewDestination(audience, destinationID, DestinationEnabled, lifecycleTestNow.Add(-time.Hour), lifecycleTestNow.Add(-time.Hour))
	if err != nil {
		t.Fatal("lifecycle snapshot destination setup failed")
	}
	staged := lifecycleTestToken(t, destination, mustLifecycleRecordID(t, lifecycleTestRecordOneText), DestinationTokenStaged, lifecycleTestNow.Add(-time.Minute), time.Time{})
	active := lifecycleTestToken(t, destination, mustLifecycleRecordID(t, lifecycleTestRecordOneText), DestinationTokenActive, lifecycleTestNow.Add(-time.Minute), time.Time{})
	oldRetiring := lifecycleTestToken(t, destination, mustLifecycleRecordID(t, lifecycleTestRecordTwoText), DestinationTokenRetiring, lifecycleTestNow.Add(-10*time.Minute), lifecycleTestNow.Add(6*time.Hour))
	rotationStaged := lifecycleTestToken(t, destination, mustLifecycleRecordID(t, lifecycleTestRecordTwoText), DestinationTokenStaged, lifecycleTestNow.Add(-time.Minute), time.Time{})

	for _, test := range []struct {
		name   string
		tokens []DestinationToken
		want   DestinationLifecycleStatus
	}{
		{name: "unprovisioned", want: LifecycleUnprovisioned},
		{name: "staged initial", tokens: []DestinationToken{staged}, want: LifecycleStagedInitial},
		{name: "active", tokens: []DestinationToken{active}, want: LifecycleActive},
		{name: "active staged", tokens: []DestinationToken{active, rotationStaged}, want: LifecycleActiveWithStaged},
		{name: "active retiring", tokens: []DestinationToken{active, oldRetiring}, want: LifecycleActiveWithRetiring},
	} {
		t.Run(test.name, func(t *testing.T) {
			snapshot, snapshotErr := NewDestinationLifecycleSnapshot(destination, test.tokens, lifecycleTestNow)
			if snapshotErr != nil || snapshot.Status() != test.want {
				t.Fatal("lifecycle snapshot classification mismatch")
			}
			if fmt.Sprintf("%v", snapshot) != "[redacted]" {
				t.Fatal("lifecycle snapshot formatting was not redacted")
			}
		})
	}

	staleStaged := lifecycleTestToken(t, destination, mustLifecycleRecordID(t, lifecycleTestRecordOneText), DestinationTokenStaged, lifecycleTestNow.Add(-12*time.Hour), time.Time{})
	stale, err := NewDestinationLifecycleSnapshot(destination, []DestinationToken{staleStaged}, lifecycleTestNow)
	if err != nil || stale.Status() != LifecycleReconciliationRequired {
		t.Fatal("stale lifecycle state did not require reconciliation")
	}
	if _, err := NewDestinationLifecycleSnapshot(destination, []DestinationToken{staged, rotationStaged}, lifecycleTestNow); !errors.Is(err, ErrDestinationLifecycleReconciliation) {
		t.Fatal("ambiguous lifecycle state was accepted")
	}
	if _, err := NewDestinationLifecycleSnapshot(destination, []DestinationToken{staged, oldRetiring}, lifecycleTestNow); !errors.Is(err, ErrDestinationLifecycleReconciliation) {
		t.Fatal("staged plus retiring lifecycle state was accepted")
	}
	duplicateRole := lifecycleTestToken(t, destination, mustLifecycleRecordID(t, lifecycleTestRecordOneText), DestinationTokenStaged, lifecycleTestNow.Add(-time.Minute), time.Time{})
	if _, err := NewDestinationLifecycleSnapshot(destination, []DestinationToken{active, duplicateRole}, lifecycleTestNow); !errors.Is(err, ErrDestinationLifecycleReconciliation) {
		t.Fatal("duplicate lifecycle record identity across roles was accepted")
	}
	future := lifecycleTestToken(t, destination, mustLifecycleRecordID(t, lifecycleTestRecordTwoText), DestinationTokenStaged, lifecycleTestNow.Add(time.Minute), time.Time{})
	futureSnapshot, err := NewDestinationLifecycleSnapshot(destination, []DestinationToken{future}, lifecycleTestNow)
	if err != nil || futureSnapshot.Status() != LifecycleReconciliationRequired {
		t.Fatal("future lifecycle timestamp did not require reconciliation")
	}
	changedDestination, err := NewDestination(audience, destinationID, DestinationEnabled, lifecycleTestNow.Add(-time.Hour), lifecycleTestNow.Add(-30*time.Minute))
	if err != nil {
		t.Fatal("lifecycle nested destination mismatch setup failed")
	}
	misbound := lifecycleTestToken(t, changedDestination, mustLifecycleRecordID(t, lifecycleTestRecordTwoText), DestinationTokenStaged, lifecycleTestNow.Add(-time.Minute), time.Time{})
	if _, err := NewDestinationLifecycleSnapshot(destination, []DestinationToken{misbound}, lifecycleTestNow); !errors.Is(err, ErrDestinationLifecycleReconciliation) {
		t.Fatal("mismatched nested lifecycle destination was accepted")
	}
	disabled, err := NewDestination(audience, destinationID, DestinationDisabled, lifecycleTestNow.Add(-time.Hour), lifecycleTestNow.Add(-time.Hour))
	if err != nil {
		t.Fatal("disabled lifecycle destination setup failed")
	}
	disabledSnapshot, err := NewDestinationLifecycleSnapshot(disabled, nil, lifecycleTestNow)
	if err != nil || disabledSnapshot.Status() != LifecycleReconciliationRequired {
		t.Fatal("disabled empty destination was classified as provisionable")
	}

	for _, test := range []struct {
		name   string
		mutate func(*DestinationToken, *DestinationToken)
	}{
		{name: "active activated", mutate: func(active, _ *DestinationToken) {
			active.spec.ActivatedAt = active.spec.ActivatedAt.Add(-time.Second)
		}},
		{name: "active state changed", mutate: func(active, _ *DestinationToken) {
			active.spec.StateChangedAt = active.spec.StateChangedAt.Add(-time.Second)
		}},
		{name: "retiring started", mutate: func(_, retiring *DestinationToken) {
			retiring.spec.RetirementStartedAt = retiring.spec.RetirementStartedAt.Add(-time.Second)
		}},
		{name: "retiring state changed", mutate: func(_, retiring *DestinationToken) {
			retiring.spec.StateChangedAt = retiring.spec.StateChangedAt.Add(-time.Second)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			changedActive := active
			changedRetiring := oldRetiring
			test.mutate(&changedActive, &changedRetiring)
			if _, err := NewDestinationLifecycleSnapshot(destination, []DestinationToken{changedActive, changedRetiring}, lifecycleTestNow); !errors.Is(err, ErrDestinationLifecycleReconciliation) {
				t.Fatal("inconsistent rotation history was accepted")
			}
		})
	}
}

func TestDestinationLifecycleInspectionBindsRequest(t *testing.T) {
	audience := mustLifecycleAudience(t)
	destination := mustLifecycleDestinationID(t)
	record := mustLifecycleRecordID(t, lifecycleTestRecordOneText)
	otherDestination, err := ParseDestinationID("77777777-8888-9999-8aaa-bbbbbbbbbbbb")
	if err != nil {
		t.Fatal("lifecycle inspection binding setup failed")
	}
	repository := &lifecycleTestRepository{snapshot: DestinationLifecycleSnapshot{
		audienceID: audience, destinationID: otherDestination, status: LifecycleUnprovisioned,
	}}
	service, _, _ := newLifecycleTestService(t, repository, bytes.NewReader(lifecycleEntropy(1)), &lifecycleTestRecordGenerator{records: []DestinationTokenRecordID{record}})
	if snapshot, err := service.InspectLifecycleState(context.Background(), audience, destination); !errors.Is(err, ErrDestinationLifecycleReconciliation) || snapshot.Status() != 0 {
		t.Fatal("lifecycle service accepted an inspection result for another request")
	}
	otherAudience, err := ParseGatewayAudienceID("22222222-3333-4444-8555-666666666666")
	if err != nil {
		t.Fatal("lifecycle inspection audience binding setup failed")
	}
	repository = &lifecycleTestRepository{snapshot: DestinationLifecycleSnapshot{
		audienceID: otherAudience, destinationID: destination, status: LifecycleUnprovisioned,
	}}
	service, _, _ = newLifecycleTestService(t, repository, bytes.NewReader(lifecycleEntropy(1)), &lifecycleTestRecordGenerator{records: []DestinationTokenRecordID{record}})
	if snapshot, err := service.InspectLifecycleState(context.Background(), audience, destination); !errors.Is(err, ErrDestinationLifecycleReconciliation) || snapshot.Status() != 0 {
		t.Fatal("lifecycle service accepted an inspection result for another audience")
	}
}

func lifecycleTestToken(t *testing.T, destination Destination, recordID DestinationTokenRecordID, state DestinationTokenState, createdAt, retirementDeadline time.Time) DestinationToken {
	t.Helper()
	verifier, err := NewTokenVerifier(make([]byte, 32))
	if err != nil {
		t.Fatal("lifecycle token verifier setup failed")
	}
	spec := DestinationTokenSpec{
		AudienceID: destination.AudienceID(), Destination: destination, RecordID: recordID,
		Verifier: verifier, VerifierKeyID: mustLifecycleKeyID(t), State: state,
		CreatedAt: createdAt, ExpiresAt: lifecycleTestNow.Add(48 * time.Hour),
		StagedCleanupDeadline: createdAt.Add(12 * time.Hour), StateChangedAt: createdAt,
	}
	switch state {
	case DestinationTokenActive:
		spec.ActivatedAt = lifecycleTestNow.Add(-time.Minute)
		spec.StateChangedAt = spec.ActivatedAt
	case DestinationTokenRetiring:
		spec.ActivatedAt = lifecycleTestNow.Add(-2 * time.Minute)
		spec.RetirementStartedAt = lifecycleTestNow.Add(-time.Minute)
		spec.RetirementDeadline = retirementDeadline
		spec.StateChangedAt = spec.RetirementStartedAt
	}
	token, err := NewDestinationToken(spec)
	if err != nil {
		t.Fatal("lifecycle token setup failed")
	}
	return token
}

func TestDestinationLifecycleConcurrentCreateUsesDistinctMaterial(t *testing.T) {
	const callers = 16
	records := make([]DestinationTokenRecordID, callers)
	for index := range records {
		var raw [16]byte
		raw[0] = byte(index + 1)
		raw[6] = 0x40
		raw[8] = 0x80
		records[index] = DestinationTokenRecordID(raw)
	}
	repository := &lifecycleTestRepository{}
	generator := &lifecycleTestRecordGenerator{records: records}
	service, clock, _ := newLifecycleTestService(t, repository, bytes.NewReader(lifecycleEntropy(callers)), generator)
	audience := mustLifecycleAudience(t)
	destination := mustLifecycleDestinationID(t)

	results := make(chan CreatedStagedToken, callers)
	errorsFound := make(chan error, callers)
	start := make(chan struct{})
	var wait sync.WaitGroup
	wait.Add(callers)
	for range callers {
		go func() {
			defer wait.Done()
			<-start
			created, err := service.CreateStagedToken(context.Background(), audience, destination)
			results <- created
			errorsFound <- err
		}()
	}
	close(start)
	wait.Wait()
	close(results)
	close(errorsFound)
	for err := range errorsFound {
		if err != nil {
			t.Fatal("concurrent lifecycle create failed")
		}
	}
	seenTokens := make(map[string]struct{}, callers)
	seenRecords := make(map[DestinationTokenRecordID]struct{}, callers)
	for result := range results {
		if result.Token().IsZero() || result.RecordID().IsZero() {
			t.Fatal("concurrent lifecycle create returned a zero value")
		}
		seenTokens[result.Token().Value()] = struct{}{}
		seenRecords[result.RecordID()] = struct{}{}
	}
	if len(seenTokens) != callers || len(seenRecords) != callers || len(repository.callSnapshot()) != callers || clock.callCount() != callers {
		t.Fatal("concurrent lifecycle create reused generated material")
	}
}
