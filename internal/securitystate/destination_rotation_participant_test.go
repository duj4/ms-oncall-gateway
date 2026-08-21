package securitystate

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

const rotationPrivateMarker = "rotation-test-only-private-marker"

type rotationMutableContext struct {
	context.Context
	mu  sync.Mutex
	err error
}

func newRotationMutableContext() *rotationMutableContext {
	return &rotationMutableContext{Context: context.Background()}
}

func (ctx *rotationMutableContext) Err() error {
	ctx.mu.Lock()
	defer ctx.mu.Unlock()
	return ctx.err
}

func (ctx *rotationMutableContext) set(err error) {
	ctx.mu.Lock()
	ctx.err = err
	ctx.mu.Unlock()
}

type rotationTestResolver struct {
	mu          sync.Mutex
	destination DestinationID
	err         error
	calls       int
	order       *[]string
	hook        func()
}

func (resolver *rotationTestResolver) Resolve(
	_ context.Context,
	_ GatewayAudienceID,
	_ OpaqueDestinationToken,
	_ time.Time,
) (DestinationID, error) {
	resolver.mu.Lock()
	resolver.calls++
	if resolver.order != nil {
		*resolver.order = append(*resolver.order, "resolve")
	}
	destination, err, hook := resolver.destination, resolver.err, resolver.hook
	resolver.mu.Unlock()
	if hook != nil {
		hook()
	}
	return destination, err
}

type rotationTestIdentifier struct {
	mu       sync.Mutex
	identity DestinationTokenRotationTokenIdentity
	err      error
	calls    int
	hook     func()
}

func (identifier *rotationTestIdentifier) IdentifyRotationToken(
	context.Context,
	GatewayAudienceID,
	DestinationID,
	OpaqueDestinationToken,
	DestinationTokenRecordID,
	DestinationTokenRecordID,
	time.Time,
) (DestinationTokenRotationTokenIdentity, error) {
	identifier.mu.Lock()
	identifier.calls++
	identity, err, hook := identifier.identity, identifier.err, identifier.hook
	identifier.mu.Unlock()
	if hook != nil {
		hook()
	}
	return identity, err
}

type rotationTestInspector struct {
	mu       sync.Mutex
	snapshot DestinationTokenRotationAttemptSnapshot
	err      error
	calls    int
	hook     func()
}

func (inspector *rotationTestInspector) InspectRotationAttempt(
	context.Context,
	GatewayAudienceID,
	DestinationID,
	DestinationTokenRecordID,
	DestinationTokenRecordID,
	time.Time,
) (DestinationTokenRotationAttemptSnapshot, error) {
	inspector.mu.Lock()
	inspector.calls++
	snapshot, err, hook := inspector.snapshot, inspector.err, inspector.hook
	inspector.mu.Unlock()
	if hook != nil {
		hook()
	}
	return snapshot, err
}

type rotationTestLifecycle struct {
	mu             sync.Mutex
	snapshot       DestinationLifecycleSnapshot
	created        CreatedStagedToken
	inspectErr     error
	createErr      error
	activateErr    error
	activation     DestinationTokenRotationActivationReceipt
	activationSet  bool
	abortErr       error
	rollbackErr    error
	finalizeErr    error
	inspectHook    func()
	createHook     func()
	activateHook   func()
	rollbackHook   func()
	finalizeHook   func()
	abortContext   error
	order          *[]string
	inspectCalls   int
	createCalls    int
	activateCalls  int
	abortCalls     int
	rollbackCalls  int
	finalizeCalls  int
	activateFirst  DestinationTokenRecordID
	activateSecond DestinationTokenRecordID
	createExpected DestinationTokenRecordID
	createCurrent  OpaqueDestinationToken
	rollbackFirst  DestinationTokenRecordID
	rollbackSecond DestinationTokenRecordID
	finalizeFirst  DestinationTokenRecordID
	finalizeSecond DestinationTokenRecordID
	finalizeReason RotationCompletionReason
}

func (lifecycle *rotationTestLifecycle) add(operation string) {
	if lifecycle.order != nil {
		*lifecycle.order = append(*lifecycle.order, operation)
	}
}

func (lifecycle *rotationTestLifecycle) CreateStagedToken(
	context.Context,
	GatewayAudienceID,
	DestinationID,
) (CreatedStagedToken, error) {
	lifecycle.mu.Lock()
	lifecycle.createCalls++
	lifecycle.add("create")
	created, err, hook := lifecycle.created, lifecycle.createErr, lifecycle.createHook
	lifecycle.mu.Unlock()
	if hook != nil {
		hook()
	}
	return created, err
}

func (lifecycle *rotationTestLifecycle) CreateRotationStagedToken(
	_ context.Context,
	_ GatewayAudienceID,
	_ DestinationID,
	expectedActive DestinationTokenRecordID,
	currentToken OpaqueDestinationToken,
) (CreatedStagedToken, error) {
	lifecycle.mu.Lock()
	lifecycle.createCalls++
	lifecycle.createExpected = expectedActive
	lifecycle.createCurrent = currentToken
	lifecycle.add("create")
	created, err, hook := lifecycle.created, lifecycle.createErr, lifecycle.createHook
	lifecycle.mu.Unlock()
	if hook != nil {
		hook()
	}
	return created, err
}

func (*rotationTestLifecycle) ActivateInitialToken(
	context.Context,
	GatewayAudienceID,
	DestinationID,
	DestinationTokenRecordID,
) error {
	return ErrDestinationLifecycleInvalid
}

func (lifecycle *rotationTestLifecycle) ActivateRotation(
	_ context.Context,
	_ GatewayAudienceID,
	_ DestinationID,
	first DestinationTokenRecordID,
	second DestinationTokenRecordID,
) (DestinationTokenRotationActivationReceipt, error) {
	lifecycle.mu.Lock()
	lifecycle.activateCalls++
	lifecycle.activateFirst = first
	lifecycle.activateSecond = second
	lifecycle.add("activate")
	hook := lifecycle.activateHook
	err := lifecycle.activateErr
	activation := lifecycle.activation
	if !lifecycle.activationSet {
		activation = DestinationTokenRotationActivationReceipt{
			activatedAt: lifecycleTestNow, retirementDeadline: lifecycleTestNow.Add(6 * time.Hour),
		}
	}
	lifecycle.mu.Unlock()
	if hook != nil {
		hook()
	}
	return activation, err
}

func (lifecycle *rotationTestLifecycle) AbortStagedToken(
	ctx context.Context,
	_ GatewayAudienceID,
	_ DestinationID,
	_ DestinationTokenRecordID,
) error {
	lifecycle.mu.Lock()
	defer lifecycle.mu.Unlock()
	lifecycle.abortCalls++
	lifecycle.abortContext = ctx.Err()
	lifecycle.add("abort")
	return lifecycle.abortErr
}

func (lifecycle *rotationTestLifecycle) RollbackRotation(
	_ context.Context,
	_ GatewayAudienceID,
	_ DestinationID,
	first DestinationTokenRecordID,
	second DestinationTokenRecordID,
) error {
	lifecycle.mu.Lock()
	lifecycle.rollbackCalls++
	lifecycle.rollbackFirst = first
	lifecycle.rollbackSecond = second
	err, hook := lifecycle.rollbackErr, lifecycle.rollbackHook
	lifecycle.mu.Unlock()
	if hook != nil {
		hook()
	}
	return err
}

func (lifecycle *rotationTestLifecycle) FinalizeRotation(
	_ context.Context,
	_ GatewayAudienceID,
	_ DestinationID,
	first DestinationTokenRecordID,
	second DestinationTokenRecordID,
	reason RotationCompletionReason,
) error {
	lifecycle.mu.Lock()
	lifecycle.finalizeCalls++
	lifecycle.finalizeFirst = first
	lifecycle.finalizeSecond = second
	lifecycle.finalizeReason = reason
	err, hook := lifecycle.finalizeErr, lifecycle.finalizeHook
	lifecycle.mu.Unlock()
	if hook != nil {
		hook()
	}
	return err
}

func (lifecycle *rotationTestLifecycle) InspectLifecycleState(
	context.Context,
	GatewayAudienceID,
	DestinationID,
) (DestinationLifecycleSnapshot, error) {
	lifecycle.mu.Lock()
	lifecycle.inspectCalls++
	lifecycle.add("inspect")
	snapshot, err, hook := lifecycle.snapshot, lifecycle.inspectErr, lifecycle.inspectHook
	lifecycle.mu.Unlock()
	if hook != nil {
		hook()
	}
	return snapshot, err
}

func rotationTestDestination(t *testing.T) Destination {
	t.Helper()
	destination, err := NewDestination(
		mustLifecycleAudience(t), mustLifecycleDestinationID(t), DestinationEnabled,
		lifecycleTestNow.Add(-24*time.Hour), lifecycleTestNow.Add(-24*time.Hour),
	)
	if err != nil {
		t.Fatal("rotation destination setup failed")
	}
	return destination
}

func rotationTestRawToken(t *testing.T) OpaqueDestinationToken {
	t.Helper()
	token, err := ParseOpaqueDestinationToken(lifecycleGoldenToken)
	if err != nil {
		t.Fatal("rotation raw token setup failed")
	}
	return token
}

func rotationTestRequest(t *testing.T) DestinationTokenRotationRequest {
	t.Helper()
	request, err := NewDestinationTokenRotationRequest(
		mustLifecycleAudience(t), mustLifecycleDestinationID(t), rotationTestRawToken(t),
	)
	if err != nil {
		t.Fatal("rotation request setup failed")
	}
	return request
}

func rotationTestActiveSnapshot(t *testing.T) DestinationLifecycleSnapshot {
	t.Helper()
	destination := rotationTestDestination(t)
	oldActive := lifecycleTestToken(
		t, destination, mustLifecycleRecordID(t, lifecycleTestRecordOneText),
		DestinationTokenActive, lifecycleTestNow.Add(-time.Hour), time.Time{},
	)
	snapshot, err := NewDestinationLifecycleSnapshot(destination, []DestinationToken{oldActive}, lifecycleTestNow)
	if err != nil || snapshot.Status() != LifecycleActive || !snapshot.DestinationEnabled() {
		t.Fatal("rotation active snapshot setup failed")
	}
	return snapshot
}

func rotationTestCreated(t *testing.T) CreatedStagedToken {
	t.Helper()
	return CreatedStagedToken{
		recordID: mustLifecycleRecordID(t, lifecycleTestRecordTwoText),
		token:    OneTimeDestinationToken{encoded: lifecycleGoldenToken},
	}
}

func rotationTestHandle(t *testing.T) DestinationTokenRotationHandle {
	t.Helper()
	return DestinationTokenRotationHandle{
		audienceID:          mustLifecycleAudience(t),
		destination:         mustLifecycleDestinationID(t),
		newActiveRecordID:   mustLifecycleRecordID(t, lifecycleTestRecordTwoText),
		oldRetiringRecordID: mustLifecycleRecordID(t, lifecycleTestRecordOneText),
	}
}

func rotationTestService(
	t *testing.T,
	lifecycle DestinationTokenLifecycle,
) (*DestinationTokenRotationParticipantService, *rotationTestResolver, *rotationTestIdentifier, *rotationTestInspector) {
	t.Helper()
	resolver := &rotationTestResolver{destination: mustLifecycleDestinationID(t)}
	identifier := &rotationTestIdentifier{identity: DestinationTokenRotationTokenNew}
	inspector := &rotationTestInspector{}
	service, err := NewDestinationTokenRotationParticipantService(DestinationTokenRotationParticipantConfig{
		Clock:    DestinationLifecycleClockFunc(func() time.Time { return lifecycleTestNow }),
		Resolver: resolver, Identifier: identifier, AttemptInspector: inspector,
		Lifecycle: lifecycle, CompensationTimeout: time.Second,
	})
	if err != nil {
		t.Fatal("rotation participant setup failed")
	}
	return service, resolver, identifier, inspector
}

func TestDestinationTokenRotationBeginOrderAndResult(t *testing.T) {
	order := []string{}
	lifecycle := &rotationTestLifecycle{
		snapshot: rotationTestActiveSnapshot(t), created: rotationTestCreated(t), order: &order,
	}
	service, resolver, _, _ := rotationTestService(t, lifecycle)
	resolver.order = &order
	request := rotationTestRequest(t)

	attempt, err := service.BeginRotation(context.Background(), request)
	if err != nil {
		t.Fatal("rotation begin failed")
	}
	if fmt.Sprint(order) != "[resolve inspect create activate]" {
		t.Fatal("rotation begin dependency order changed")
	}
	handle := attempt.Handle()
	if handle.AudienceID() != mustLifecycleAudience(t) ||
		handle.DestinationID() != mustLifecycleDestinationID(t) ||
		handle.NewActiveRecordID() != mustLifecycleRecordID(t, lifecycleTestRecordTwoText) ||
		handle.OldRetiringRecordID() != mustLifecycleRecordID(t, lifecycleTestRecordOneText) ||
		attempt.ActivatedAt() != lifecycleTestNow ||
		attempt.RetirementDeadline() != lifecycleTestNow.Add(6*time.Hour) ||
		attempt.NewToken().Value() != lifecycleGoldenToken {
		t.Fatal("rotation begin result binding mismatch")
	}
	if lifecycle.activateFirst != handle.NewActiveRecordID() ||
		lifecycle.activateSecond != handle.OldRetiringRecordID() ||
		lifecycle.createExpected != handle.OldRetiringRecordID() ||
		lifecycle.createCurrent != request.CurrentToken() || lifecycle.abortCalls != 0 {
		t.Fatal("rotation begin did not activate the exact pair")
	}
	requestTokenBytes := request.CurrentToken().Bytes()
	requestTokenBytes[0] ^= 0xff
	if request.CurrentToken().Bytes() == requestTokenBytes {
		t.Fatal("rotation request token accessor aliased protected state")
	}
	returnedToken := attempt.NewToken()
	returnedToken.encoded = "changed"
	if attempt.NewToken().Value() != lifecycleGoldenToken {
		t.Fatal("rotation attempt token accessor aliased protected state")
	}
	returnedHandle := attempt.Handle()
	returnedHandle.newActiveRecordID = DestinationTokenRecordID{}
	if attempt.Handle().NewActiveRecordID().IsZero() {
		t.Fatal("rotation attempt handle accessor aliased protected state")
	}
	activationReceipt, err := NewDestinationTokenRotationActivationReceipt(
		lifecycleTestNow,
		lifecycleTestNow.Add(6*time.Hour),
	)
	if err != nil {
		t.Fatal("rotation activation receipt setup failed")
	}
	for _, value := range []any{
		request, attempt, handle, attempt.NewToken(), service,
		activationReceipt, DestinationTokenRotationParticipantConfig{}, DestinationTokenRotationObservation{},
	} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X"} {
			if fmt.Sprintf(format, value) != "[redacted]" {
				t.Fatal("rotation value formatting exposed protected state")
			}
		}
	}
}

func TestDestinationTokenRotationBeginAcceptsCanonicalAllZeroToken(t *testing.T) {
	lifecycle := &rotationTestLifecycle{
		snapshot: rotationTestActiveSnapshot(t), created: rotationTestCreated(t),
	}
	service, resolver, _, _ := rotationTestService(t, lifecycle)
	request, err := NewDestinationTokenRotationRequest(
		mustLifecycleAudience(t), mustLifecycleDestinationID(t), OpaqueDestinationToken{},
	)
	if err != nil {
		t.Fatal("canonical all-zero rotation request setup failed")
	}

	attempt, err := service.BeginRotation(context.Background(), request)
	if err != nil {
		t.Fatal("canonical all-zero rotation token was rejected by begin")
	}
	if attempt.Handle() != rotationTestHandle(t) || attempt.NewToken().Value() != lifecycleGoldenToken ||
		resolver.calls != 1 || lifecycle.inspectCalls != 1 || lifecycle.createCalls != 1 ||
		lifecycle.activateCalls != 1 || lifecycle.abortCalls != 0 {
		t.Fatal("canonical all-zero rotation begin did not complete the exact participant sequence")
	}
}

func TestDestinationTokenRotationBeginPreMutationFailures(t *testing.T) {
	private := errors.New(rotationPrivateMarker)
	for _, test := range []struct {
		name       string
		configure  func(*rotationTestResolver, *rotationTestLifecycle)
		want       error
		wantCreate int
		wantHandle bool
	}{
		{name: "token not found", configure: func(resolver *rotationTestResolver, _ *rotationTestLifecycle) {
			resolver.err = ErrDestinationNotFound
		}, want: ErrDestinationTokenRotationConflict},
		{name: "joined token not found", configure: func(resolver *rotationTestResolver, _ *rotationTestLifecycle) {
			resolver.err = errors.Join(ErrDestinationNotFound, private)
		}, want: ErrDestinationTokenRotationUnavailable},
		{name: "resolver unavailable", configure: func(resolver *rotationTestResolver, _ *rotationTestLifecycle) {
			resolver.err = private
		}, want: ErrDestinationTokenRotationUnavailable},
		{name: "lifecycle conflict", configure: func(_ *rotationTestResolver, lifecycle *rotationTestLifecycle) {
			lifecycle.inspectErr = ErrDestinationLifecycleConflict
		}, want: ErrDestinationTokenRotationConflict},
		{name: "lifecycle ambiguous", configure: func(_ *rotationTestResolver, lifecycle *rotationTestLifecycle) {
			lifecycle.inspectErr = errors.Join(ErrDestinationLifecycleConflict, private)
		}, want: ErrDestinationTokenRotationUnavailable},
		{name: "not exactly active", configure: func(_ *rotationTestResolver, lifecycle *rotationTestLifecycle) {
			destination := rotationTestDestination(t)
			active := lifecycleTestToken(t, destination, mustLifecycleRecordID(t, lifecycleTestRecordOneText), DestinationTokenActive, lifecycleTestNow.Add(-time.Hour), time.Time{})
			staged := lifecycleTestToken(t, destination, mustLifecycleRecordID(t, lifecycleTestRecordTwoText), DestinationTokenStaged, lifecycleTestNow.Add(-time.Minute), time.Time{})
			lifecycle.snapshot, _ = NewDestinationLifecycleSnapshot(destination, []DestinationToken{active, staged}, lifecycleTestNow)
		}, want: ErrDestinationTokenRotationConflict},
		{name: "create conflict", configure: func(_ *rotationTestResolver, lifecycle *rotationTestLifecycle) {
			lifecycle.createErr = ErrDestinationLifecycleConflict
		}, want: ErrDestinationTokenRotationConflict, wantCreate: 1},
		{name: "create outcome unknown", configure: func(_ *rotationTestResolver, lifecycle *rotationTestLifecycle) {
			lifecycle.createErr = ErrDestinationLifecycleOutcomeUnknown
		}, want: ErrDestinationTokenRotationReconciliation, wantCreate: 1, wantHandle: true},
		{name: "create unknown", configure: func(_ *rotationTestResolver, lifecycle *rotationTestLifecycle) {
			lifecycle.createErr = private
		}, want: ErrDestinationTokenRotationReconciliation, wantCreate: 1, wantHandle: true},
		{name: "create joined", configure: func(_ *rotationTestResolver, lifecycle *rotationTestLifecycle) {
			lifecycle.createErr = errors.Join(ErrDestinationLifecycleConflict, private)
		}, want: ErrDestinationTokenRotationReconciliation, wantCreate: 1, wantHandle: true},
		{name: "create returned old record identity", configure: func(_ *rotationTestResolver, lifecycle *rotationTestLifecycle) {
			lifecycle.created.recordID = mustLifecycleRecordID(t, lifecycleTestRecordOneText)
		}, want: ErrDestinationTokenRotationReconciliation, wantCreate: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			lifecycle := &rotationTestLifecycle{snapshot: rotationTestActiveSnapshot(t), created: rotationTestCreated(t)}
			service, resolver, _, _ := rotationTestService(t, lifecycle)
			test.configure(resolver, lifecycle)
			attempt, err := service.BeginRotation(context.Background(), rotationTestRequest(t))
			if err != test.want || !attempt.NewToken().IsZero() ||
				!attempt.ActivatedAt().IsZero() || !attempt.RetirementDeadline().IsZero() ||
				lifecycle.createCalls != test.wantCreate ||
				lifecycle.activateCalls != 0 || lifecycle.abortCalls != 0 ||
				validRotationHandle(attempt.Handle()) != test.wantHandle {
				t.Fatal("rotation pre-mutation failure classification mismatch")
			}
			if err != nil && (stringsContain(err.Error(), rotationPrivateMarker) || errors.Is(err, private)) {
				t.Fatal("rotation error exposed dependency detail")
			}
		})
	}
}

func TestDestinationTokenRotationBeginDependencyErrorWinsConcurrentContext(t *testing.T) {
	private := errors.New(rotationPrivateMarker)
	for _, test := range []struct {
		name       string
		contextErr error
		configure  func(*rotationMutableContext, *rotationTestResolver, *rotationTestLifecycle)
		want       error
		wantHandle bool
	}{
		{
			name: "resolver mixed plus cancellation", contextErr: context.Canceled,
			configure: func(ctx *rotationMutableContext, resolver *rotationTestResolver, _ *rotationTestLifecycle) {
				resolver.err = errors.Join(ErrDestinationNotFound, private)
				resolver.hook = func() { ctx.set(context.Canceled) }
			}, want: ErrDestinationTokenRotationUnavailable,
		},
		{
			name: "resolver exact conflict plus deadline", contextErr: context.DeadlineExceeded,
			configure: func(ctx *rotationMutableContext, resolver *rotationTestResolver, _ *rotationTestLifecycle) {
				resolver.err = ErrDestinationNotFound
				resolver.hook = func() { ctx.set(context.DeadlineExceeded) }
			}, want: ErrDestinationTokenRotationConflict,
		},
		{
			name: "inspection mixed plus deadline", contextErr: context.DeadlineExceeded,
			configure: func(ctx *rotationMutableContext, _ *rotationTestResolver, lifecycle *rotationTestLifecycle) {
				lifecycle.inspectErr = errors.Join(ErrDestinationLifecycleConflict, private)
				lifecycle.inspectHook = func() { ctx.set(context.DeadlineExceeded) }
			}, want: ErrDestinationTokenRotationUnavailable,
		},
		{
			name: "create mixed plus cancellation keeps handle", contextErr: context.Canceled,
			configure: func(ctx *rotationMutableContext, _ *rotationTestResolver, lifecycle *rotationTestLifecycle) {
				lifecycle.createErr = errors.Join(ErrDestinationLifecycleConflict, private)
				lifecycle.createHook = func() { ctx.set(context.Canceled) }
			}, want: ErrDestinationTokenRotationReconciliation, wantHandle: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := newRotationMutableContext()
			lifecycle := &rotationTestLifecycle{snapshot: rotationTestActiveSnapshot(t), created: rotationTestCreated(t)}
			service, resolver, _, _ := rotationTestService(t, lifecycle)
			test.configure(ctx, resolver, lifecycle)
			attempt, err := service.BeginRotation(ctx, rotationTestRequest(t))
			if err != test.want || !attempt.NewToken().IsZero() ||
				!attempt.ActivatedAt().IsZero() || !attempt.RetirementDeadline().IsZero() ||
				validRotationHandle(attempt.Handle()) != test.wantHandle ||
				ctx.Err() != test.contextErr || lifecycle.abortCalls != 0 {
				t.Fatal("concurrent context changed dependency error classification")
			}
		})
	}
}

func TestDestinationTokenRotationActivationAndAbortMatrix(t *testing.T) {
	private := errors.New(rotationPrivateMarker)
	for _, test := range []struct {
		name          string
		activateErr   error
		abortErr      error
		want          error
		wantAbort     int
		wantHandle    bool
		cancelOnStart bool
		contextErr    error
		activation    DestinationTokenRotationActivationReceipt
		activationSet bool
	}{
		{name: "confirmed conflict cleaned", activateErr: ErrDestinationLifecycleConflict, want: ErrDestinationTokenRotationConflict, wantAbort: 1},
		{name: "confirmed unavailable cleaned", activateErr: ErrDestinationLifecycleUnavailable, want: ErrDestinationTokenRotationUnavailable, wantAbort: 1},
		{name: "canceled cleaned with detached context", activateErr: ErrDestinationLifecycleCanceled, want: ErrDestinationTokenRotationCanceled, wantAbort: 1, cancelOnStart: true},
		{name: "activation outcome unknown", activateErr: ErrDestinationLifecycleOutcomeUnknown, want: ErrDestinationTokenRotationReconciliation, wantHandle: true},
		{name: "activation joined", activateErr: errors.Join(ErrDestinationLifecycleConflict, private), want: ErrDestinationTokenRotationReconciliation, wantHandle: true},
		{name: "activation joined with concurrent cancel", activateErr: errors.Join(ErrDestinationLifecycleConflict, private), contextErr: context.Canceled, want: ErrDestinationTokenRotationReconciliation, wantHandle: true},
		{name: "activation mixed outcome with concurrent deadline", activateErr: errors.Join(ErrDestinationLifecycleOutcomeUnknown, private), contextErr: context.DeadlineExceeded, want: ErrDestinationTokenRotationReconciliation, wantHandle: true},
		{name: "activation unknown", activateErr: private, want: ErrDestinationTokenRotationReconciliation, wantHandle: true},
		{name: "confirmed activation with zero receipt", activationSet: true, want: ErrDestinationTokenRotationReconciliation, wantHandle: true},
		{
			name: "confirmed activation with elapsed receipt",
			activation: DestinationTokenRotationActivationReceipt{
				activatedAt: lifecycleTestNow.Add(-2 * time.Hour), retirementDeadline: lifecycleTestNow.Add(-time.Hour),
			},
			activationSet: true, want: ErrDestinationTokenRotationReconciliation, wantHandle: true,
		},
		{
			name: "confirmed activation exactly at deadline",
			activation: DestinationTokenRotationActivationReceipt{
				activatedAt: lifecycleTestNow.Add(-time.Hour), retirementDeadline: lifecycleTestNow,
			},
			activationSet: true, want: ErrDestinationTokenRotationReconciliation, wantHandle: true,
		},
		{name: "confirmed activation plus concurrent cancel", contextErr: context.Canceled, want: ErrDestinationTokenRotationReconciliation, wantHandle: true},
		{name: "confirmed activation plus concurrent deadline", contextErr: context.DeadlineExceeded, want: ErrDestinationTokenRotationReconciliation, wantHandle: true},
		{name: "abort conflict", activateErr: ErrDestinationLifecycleConflict, abortErr: ErrDestinationLifecycleConflict, want: ErrDestinationTokenRotationReconciliation, wantAbort: 1, wantHandle: true},
		{name: "abort outcome unknown", activateErr: ErrDestinationLifecycleConflict, abortErr: ErrDestinationLifecycleOutcomeUnknown, want: ErrDestinationTokenRotationReconciliation, wantAbort: 1, wantHandle: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			lifecycle := &rotationTestLifecycle{
				snapshot: rotationTestActiveSnapshot(t), created: rotationTestCreated(t),
				activateErr: test.activateErr, activation: test.activation,
				activationSet: test.activationSet, abortErr: test.abortErr,
			}
			ctx := context.Background()
			if test.contextErr != nil {
				mutable := newRotationMutableContext()
				ctx = mutable
				lifecycle.activateHook = func() { mutable.set(test.contextErr) }
			}
			if test.cancelOnStart {
				cancelCtx, cancel := context.WithCancel(ctx)
				ctx = cancelCtx
				lifecycle.activateHook = cancel
			}
			service, _, _, _ := rotationTestService(t, lifecycle)
			attempt, err := service.BeginRotation(ctx, rotationTestRequest(t))
			if err != test.want || lifecycle.activateCalls != 1 || lifecycle.abortCalls != test.wantAbort ||
				!attempt.NewToken().IsZero() || !attempt.ActivatedAt().IsZero() ||
				!attempt.RetirementDeadline().IsZero() {
				t.Fatal("rotation activation cleanup matrix mismatch")
			}
			if test.wantAbort == 1 && test.cancelOnStart && lifecycle.abortContext != nil {
				t.Fatal("rotation abort inherited caller cancellation")
			}
			handle := attempt.Handle()
			if test.wantHandle != validRotationHandle(handle) {
				t.Fatal("rotation reconciliation handle presence mismatch")
			}
			if test.wantHandle && (handle.NewActiveRecordID() != rotationTestCreated(t).RecordID() ||
				handle.OldRetiringRecordID() != mustLifecycleRecordID(t, lifecycleTestRecordOneText)) {
				t.Fatal("rotation reconciliation handle lost exact pair")
			}
		})
	}
}

func TestDestinationTokenRotationInspectTerminalProofsAndMutations(t *testing.T) {
	handle := rotationTestHandle(t)
	for _, status := range []DestinationTokenRotationStatus{
		DestinationTokenRotationActiveWithRetiring,
		DestinationTokenRotationRolledBack,
		DestinationTokenRotationCompleted,
	} {
		t.Run(fmt.Sprint(uint8(status)), func(t *testing.T) {
			lifecycle := &rotationTestLifecycle{snapshot: rotationTestActiveSnapshot(t)}
			service, _, _, inspector := rotationTestService(t, lifecycle)
			inspector.snapshot = rotationTestAttemptSnapshot(t, status)
			observation, err := service.ObserveRotation(context.Background(), handle, rotationTestRawToken(t))
			if err != nil || observation.Status() != status ||
				observation.TokenIdentity() != DestinationTokenRotationTokenNew || inspector.calls != 1 {
				t.Fatal("rotation exact attempt inspection mismatch")
			}
			if status == DestinationTokenRotationActiveWithRetiring {
				if observation.ObservedAt() != lifecycleTestNow ||
					observation.RetirementDeadline() != lifecycleTestNow.Add(6*time.Hour) {
					t.Fatal("active rotation observation omitted its authoritative clock snapshot")
				}
			} else if !observation.ObservedAt().IsZero() ||
				!observation.RetirementDeadline().IsZero() {
				t.Fatal("terminal rotation observation carried active-pair timing metadata")
			}
		})
	}

	lifecycle := &rotationTestLifecycle{snapshot: rotationTestActiveSnapshot(t)}
	service, _, _, inspector := rotationTestService(t, lifecycle)
	inspector.snapshot = rotationTestAttemptSnapshot(t, DestinationTokenRotationActiveWithRetiring)
	if err := service.RollbackRotation(context.Background(), handle); err != nil {
		t.Fatal("exact rotation rollback failed")
	}
	if lifecycle.rollbackCalls != 1 || lifecycle.rollbackFirst != handle.NewActiveRecordID() ||
		lifecycle.rollbackSecond != handle.OldRetiringRecordID() {
		t.Fatal("rotation rollback did not preserve exact pair")
	}
	inspector.snapshot = rotationTestAttemptSnapshot(t, DestinationTokenRotationRolledBack)
	if err := service.RollbackRotation(context.Background(), handle); err != ErrDestinationTokenRotationConflict ||
		lifecycle.rollbackCalls != 1 {
		t.Fatal("duplicate rotation rollback was treated as success")
	}

	deadlineClock := DestinationLifecycleClockFunc(func() time.Time { return lifecycleTestNow.Add(7 * time.Hour) })
	service.clock = deadlineClock
	inspector.snapshot = rotationTestAttemptSnapshotAt(t, DestinationTokenRotationActiveWithRetiring, lifecycleTestNow.Add(7*time.Hour))
	if err := service.FinalizeRotation(context.Background(), handle); err != nil {
		t.Fatal("deadline rotation finalization failed")
	}
	if lifecycle.finalizeCalls != 1 || lifecycle.finalizeFirst != handle.NewActiveRecordID() ||
		lifecycle.finalizeSecond != handle.OldRetiringRecordID() ||
		lifecycle.finalizeReason != RotationDeadlineElapsed {
		t.Fatal("rotation finalization did not use exact pair and deadline-only reason")
	}
	service.clock = DestinationLifecycleClockFunc(func() time.Time { return lifecycleTestNow })
	inspector.snapshot = rotationTestAttemptSnapshot(t, DestinationTokenRotationActiveWithRetiring)
	if err := service.FinalizeRotation(context.Background(), handle); err != ErrDestinationTokenRotationConflict ||
		lifecycle.finalizeCalls != 1 {
		t.Fatal("early rotation finalization was permitted")
	}
}

func TestDestinationTokenRotationRollbackFinalizeBoundaryRaceAndStaleHandle(t *testing.T) {
	for _, test := range []struct {
		name         string
		now          time.Time
		rollbackWant error
		finalizeWant error
	}{
		{name: "before deadline", now: lifecycleTestNow, finalizeWant: ErrDestinationTokenRotationConflict},
		{name: "at deadline", now: lifecycleTestNow.Add(6 * time.Hour), rollbackWant: ErrDestinationTokenRotationConflict},
	} {
		t.Run(test.name, func(t *testing.T) {
			lifecycle := &rotationTestLifecycle{snapshot: rotationTestActiveSnapshot(t)}
			service, _, _, inspector := rotationTestService(t, lifecycle)
			service.clock = DestinationLifecycleClockFunc(func() time.Time { return test.now })
			inspector.snapshot = rotationTestAttemptSnapshotAt(t, DestinationTokenRotationActiveWithRetiring, test.now)
			handle := rotationTestHandle(t)
			start := make(chan struct{})
			var wait sync.WaitGroup
			var rollbackErr, finalizeErr error
			wait.Add(2)
			go func() {
				defer wait.Done()
				<-start
				rollbackErr = service.RollbackRotation(context.Background(), handle)
			}()
			go func() {
				defer wait.Done()
				<-start
				finalizeErr = service.FinalizeRotation(context.Background(), handle)
			}()
			close(start)
			wait.Wait()
			if rollbackErr != test.rollbackWant || finalizeErr != test.finalizeWant ||
				lifecycle.rollbackCalls+lifecycle.finalizeCalls != 1 {
				t.Fatal("deadline partition admitted both rollback and finalize mutations")
			}
		})
	}

	lifecycle := &rotationTestLifecycle{snapshot: rotationTestActiveSnapshot(t)}
	service, _, _, inspector := rotationTestService(t, lifecycle)
	inspector.snapshot = rotationTestAttemptSnapshot(t, DestinationTokenRotationActiveWithRetiring)
	stale := rotationTestHandle(t)
	stale.newActiveRecordID, stale.oldRetiringRecordID = stale.oldRetiringRecordID, stale.newActiveRecordID
	if err := service.RollbackRotation(context.Background(), stale); err != ErrDestinationTokenRotationReconciliation ||
		lifecycle.rollbackCalls != 0 {
		t.Fatal("stale swapped rotation handle reached mutation")
	}
}

func TestDestinationTokenRotationAttemptObservationRejectsUnsafeSnapshots(t *testing.T) {
	handle := rotationTestHandle(t)
	base := rotationTestAttemptSnapshot(t, DestinationTokenRotationActiveWithRetiring)
	for _, test := range []struct {
		name       string
		observedAt time.Time
		mutate     func(*DestinationTokenRotationAttemptSnapshot)
	}{
		{name: "disabled destination", mutate: func(snapshot *DestinationTokenRotationAttemptSnapshot) {
			snapshot.lifecycle.destinationEnabled = false
			snapshot.lifecycle.status = LifecycleReconciliationRequired
		}},
		{name: "active expired", mutate: func(snapshot *DestinationTokenRotationAttemptSnapshot) {
			snapshot.newToken.expiresAt = lifecycleTestNow
			snapshot.lifecycle.active.expiresAt = lifecycleTestNow
			snapshot.lifecycle.status = LifecycleReconciliationRequired
		}},
		{name: "future active state", mutate: func(snapshot *DestinationTokenRotationAttemptSnapshot) {
			snapshot.newToken.stateChangedAt = lifecycleTestNow.Add(time.Second)
			snapshot.lifecycle.active.stateChangedAt = lifecycleTestNow.Add(time.Second)
			snapshot.lifecycle.status = LifecycleReconciliationRequired
		}},
		{name: "deadline not before old expiry", mutate: func(snapshot *DestinationTokenRotationAttemptSnapshot) {
			snapshot.oldToken.expiresAt = snapshot.oldToken.retirementDeadline
			snapshot.lifecycle.retiring.expiresAt = snapshot.lifecycle.retiring.retirementDeadline
			snapshot.lifecycle.status = LifecycleReconciliationRequired
		}},
		{name: "deadline not before new expiry", mutate: func(snapshot *DestinationTokenRotationAttemptSnapshot) {
			snapshot.newToken.expiresAt = snapshot.oldToken.retirementDeadline
			snapshot.lifecycle.active.expiresAt = snapshot.lifecycle.retiring.retirementDeadline
			snapshot.lifecycle.status = LifecycleReconciliationRequired
		}},
		{name: "reconciliation before deadline", mutate: func(snapshot *DestinationTokenRotationAttemptSnapshot) {
			snapshot.lifecycle.status = LifecycleReconciliationRequired
		}},
		{name: "terminal counterpart omitted", mutate: func(snapshot *DestinationTokenRotationAttemptSnapshot) {
			snapshot.oldToken = LifecycleTokenView{}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			snapshot := base
			test.mutate(&snapshot)
			observation, err := classifyRotationSnapshot(snapshot, handle, lifecycleTestNow)
			if err == nil || observation.Status().Valid() {
				t.Fatal("unsafe rotation attempt snapshot was accepted")
			}
		})
	}
}

func TestDestinationTokenRotationAbortAndTerminalHistoryProofs(t *testing.T) {
	handle := rotationTestHandle(t)

	aborted := rotationTestAbortedStagedAttemptAfterPriorRollback(t)
	observation, err := classifyRotationSnapshot(aborted, handle, lifecycleTestNow)
	if err != nil || observation.Status() != DestinationTokenRotationRolledBack {
		t.Fatal("abort after a prior old-token rollback was not recognized")
	}

	oldChangedAfterAbort := aborted
	oldChangedAfterAbort.oldToken.stateChangedAt = aborted.newToken.revokedAt.Add(time.Nanosecond)
	oldChangedAfterAbort.lifecycle.active.stateChangedAt = oldChangedAfterAbort.oldToken.stateChangedAt
	if observation, err = classifyRotationSnapshot(oldChangedAfterAbort, handle, lifecycleTestNow); err == nil || observation.Status().Valid() {
		t.Fatal("abort terminal accepted an old-token change from a later attempt")
	}
	oldChangedWhileStaged := aborted
	oldChangedWhileStaged.oldToken.stateChangedAt = aborted.newToken.createdAt.Add(time.Microsecond)
	oldChangedWhileStaged.lifecycle.active.stateChangedAt = oldChangedWhileStaged.oldToken.stateChangedAt
	if observation, err = classifyRotationSnapshot(oldChangedWhileStaged, handle, lifecycleTestNow); err == nil || observation.Status().Valid() {
		t.Fatal("abort terminal accepted an old-token change while the candidate was staged")
	}

	prepared := rotationTestPreparedAttemptSnapshot(t)
	if observation, err = classifyRotationSnapshot(prepared, handle, lifecycleTestNow); err != ErrDestinationTokenRotationReconciliation || observation.Status().Valid() {
		t.Fatal("prepared no-activation attempt was not left for explicit reconciliation")
	}

	rolledBackWithRetirement := rotationTestAttemptSnapshot(t, DestinationTokenRotationRolledBack)
	rolledBackWithRetirement.newToken.retirementStartedAt = lifecycleTestNow.Add(-45 * time.Second)
	rolledBackWithRetirement.newToken.retirementDeadline = lifecycleTestNow.Add(time.Hour)
	if observation, err = classifyRotationSnapshot(rolledBackWithRetirement, handle, lifecycleTestNow); err == nil || observation.Status().Valid() {
		t.Fatal("rollback with new-token retirement history was accepted")
	}

	for _, test := range []struct {
		name     string
		duration time.Duration
	}{
		{name: "immediate activated rollback", duration: 0},
		{name: "activated rollback one microsecond before maximum overlap", duration: MaximumRetiringOverlapDuration - time.Microsecond},
	} {
		t.Run(test.name, func(t *testing.T) {
			valid := rotationTestAttemptSnapshot(t, DestinationTokenRotationRolledBack)
			rollbackAt := valid.newToken.activatedAt.Add(test.duration)
			valid.newToken.revokedAt = rollbackAt
			valid.newToken.stateChangedAt = rollbackAt
			valid.oldToken.stateChangedAt = rollbackAt
			valid.lifecycle.active.stateChangedAt = rollbackAt
			observedAt := lifecycleTestNow
			if rollbackAt.After(observedAt) {
				observedAt = rollbackAt
			}
			observation, err := classifyRotationSnapshot(valid, handle, observedAt)
			if err != nil || observation.Status() != DestinationTokenRotationRolledBack {
				t.Fatal("valid activated rollback boundary was not recognized")
			}
		})
	}

	for _, test := range []struct {
		name       string
		observedAt time.Time
		mutate     func(*DestinationTokenRotationAttemptSnapshot)
	}{
		{name: "revocation at new expiry", mutate: func(snapshot *DestinationTokenRotationAttemptSnapshot) {
			snapshot.newToken.expiresAt = snapshot.newToken.revokedAt
		}},
		{name: "revocation after new expiry", mutate: func(snapshot *DestinationTokenRotationAttemptSnapshot) {
			snapshot.newToken.expiresAt = snapshot.newToken.revokedAt.Add(-time.Nanosecond)
		}},
		{name: "revocation at maximum overlap", observedAt: lifecycleTestNow.Add(MaximumRetiringOverlapDuration), mutate: func(snapshot *DestinationTokenRotationAttemptSnapshot) {
			rollbackAt := snapshot.newToken.activatedAt.Add(MaximumRetiringOverlapDuration)
			snapshot.newToken.revokedAt = rollbackAt
			snapshot.newToken.stateChangedAt = rollbackAt
			snapshot.oldToken.stateChangedAt = rollbackAt
			snapshot.lifecycle.active.stateChangedAt = rollbackAt
		}},
		{name: "revocation beyond maximum overlap", observedAt: lifecycleTestNow.Add(MaximumRetiringOverlapDuration), mutate: func(snapshot *DestinationTokenRotationAttemptSnapshot) {
			rollbackAt := snapshot.newToken.activatedAt.Add(MaximumRetiringOverlapDuration + time.Nanosecond)
			snapshot.newToken.revokedAt = rollbackAt
			snapshot.newToken.stateChangedAt = rollbackAt
			snapshot.oldToken.stateChangedAt = rollbackAt
			snapshot.lifecycle.active.stateChangedAt = rollbackAt
		}},
		{name: "new activation before old activation", mutate: func(snapshot *DestinationTokenRotationAttemptSnapshot) {
			snapshot.newToken.activatedAt = snapshot.oldToken.activatedAt.Add(-time.Microsecond)
		}},
		{name: "old restoration does not match new revocation", mutate: func(snapshot *DestinationTokenRotationAttemptSnapshot) {
			snapshot.oldToken.stateChangedAt = snapshot.newToken.revokedAt.Add(-time.Microsecond)
			snapshot.lifecycle.active.stateChangedAt = snapshot.oldToken.stateChangedAt
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			invalid := rotationTestAttemptSnapshot(t, DestinationTokenRotationRolledBack)
			test.mutate(&invalid)
			observedAt := test.observedAt
			if observedAt.IsZero() {
				observedAt = lifecycleTestNow
			}
			observation, err := classifyRotationSnapshot(invalid, handle, observedAt)
			if err == nil || observation.Status().Valid() {
				t.Fatal("invalid activated rollback history was accepted")
			}
		})
	}

	completedAtOldExpiry := rotationTestAttemptSnapshot(t, DestinationTokenRotationCompleted)
	completedAtOldExpiry.oldToken.expiresAt = completedAtOldExpiry.oldToken.retirementDeadline
	if observation, err = classifyRotationSnapshot(completedAtOldExpiry, handle, lifecycleTestNow); err == nil || observation.Status().Valid() {
		t.Fatal("completion whose deadline was not before old expiry was accepted")
	}
}

func TestDestinationTokenRotationActivatedAttemptHistoryBoundaries(t *testing.T) {
	handle := rotationTestHandle(t)
	for _, status := range []DestinationTokenRotationStatus{
		DestinationTokenRotationActiveWithRetiring,
		DestinationTokenRotationRolledBack,
		DestinationTokenRotationCompleted,
	} {
		for _, test := range []struct {
			name   string
			valid  bool
			mutate func(*DestinationTokenRotationAttemptSnapshot)
		}{
			{name: "activation one microsecond before staged cleanup", valid: true, mutate: func(snapshot *DestinationTokenRotationAttemptSnapshot) {
				snapshot.newToken.stagedCleanupDeadline = snapshot.newToken.activatedAt.Add(time.Microsecond)
			}},
			{name: "new created before old activation", mutate: func(snapshot *DestinationTokenRotationAttemptSnapshot) {
				snapshot.newToken.createdAt = snapshot.oldToken.activatedAt.Add(-time.Microsecond)
			}},
			{name: "activation at staged cleanup", mutate: func(snapshot *DestinationTokenRotationAttemptSnapshot) {
				snapshot.newToken.stagedCleanupDeadline = snapshot.newToken.activatedAt
			}},
			{name: "activation after staged cleanup", mutate: func(snapshot *DestinationTokenRotationAttemptSnapshot) {
				snapshot.newToken.stagedCleanupDeadline = snapshot.newToken.activatedAt.Add(-time.Microsecond)
			}},
		} {
			t.Run(fmt.Sprintf("%d/%s", status, test.name), func(t *testing.T) {
				snapshot := rotationTestAttemptSnapshot(t, status)
				test.mutate(&snapshot)
				if snapshot.lifecycle.hasActive &&
					snapshot.lifecycle.active.RecordID() == snapshot.newToken.RecordID() {
					snapshot.lifecycle.active = snapshot.newToken
				}
				observation, err := classifyRotationSnapshot(snapshot, handle, lifecycleTestNow)
				if test.valid {
					if err != nil || observation.Status() != status {
						t.Fatal("valid activated-attempt history boundary was not recognized")
					}
				} else if err == nil || observation.Status().Valid() {
					t.Fatal("malformed activated-attempt history was accepted")
				}
			})
		}
	}
}

func TestDestinationTokenRotationMutationAndIdentificationFailures(t *testing.T) {
	handle := rotationTestHandle(t)
	lifecycle := &rotationTestLifecycle{snapshot: rotationTestActiveSnapshot(t)}
	service, _, identifier, inspector := rotationTestService(t, lifecycle)
	inspector.snapshot = rotationTestAttemptSnapshot(t, DestinationTokenRotationActiveWithRetiring)

	for _, test := range []struct{ dependency, want error }{
		{ErrDestinationLifecycleConflict, ErrDestinationTokenRotationConflict},
		{ErrDestinationLifecycleOutcomeUnknown, ErrDestinationTokenRotationOutcomeUnknown},
		{errors.Join(ErrDestinationLifecycleConflict, errors.New(rotationPrivateMarker)), ErrDestinationTokenRotationOutcomeUnknown},
	} {
		lifecycle.rollbackErr = test.dependency
		if err := service.RollbackRotation(context.Background(), handle); err != test.want {
			t.Fatal("rotation rollback failure classification mismatch")
		}
	}

	identifier.identity = DestinationTokenRotationTokenOld
	observation, err := service.ObserveRotation(context.Background(), handle, rotationTestRawToken(t))
	if err != nil || observation.TokenIdentity() != DestinationTokenRotationTokenOld ||
		observation.Status() != DestinationTokenRotationActiveWithRetiring {
		t.Fatal("rotation token identity was not returned")
	}
	identifier.identity = 0
	if _, err := service.ObserveRotation(context.Background(), handle, rotationTestRawToken(t)); err != ErrDestinationTokenRotationReconciliation {
		t.Fatal("invalid rotation token identity did not fail closed")
	}
	identifier.identity = DestinationTokenRotationTokenNeither
	identifier.err = errors.New(rotationPrivateMarker)
	if _, err := service.ObserveRotation(context.Background(), handle, rotationTestRawToken(t)); err != ErrDestinationTokenRotationReconciliation {
		t.Fatal("rotation token identity read failure did not require reconciliation")
	}
}

func TestDestinationTokenRotationMutationErrorContextMatrix(t *testing.T) {
	private := errors.New(rotationPrivateMarker)
	for _, operation := range []string{"rollback", "finalize"} {
		for _, test := range []struct {
			name       string
			dependency error
			contextErr error
			want       error
		}{
			{name: "exact conflict plus cancel", dependency: ErrDestinationLifecycleConflict, contextErr: context.Canceled, want: ErrDestinationTokenRotationConflict},
			{name: "exact unavailable plus deadline", dependency: ErrDestinationLifecycleUnavailable, contextErr: context.DeadlineExceeded, want: ErrDestinationTokenRotationUnavailable},
			{name: "exact canceled plus deadline", dependency: ErrDestinationLifecycleCanceled, contextErr: context.DeadlineExceeded, want: ErrDestinationTokenRotationCanceled},
			{name: "exact deadline plus cancel", dependency: ErrDestinationLifecycleDeadline, contextErr: context.Canceled, want: ErrDestinationTokenRotationDeadline},
			{name: "outcome unknown plus cancel", dependency: ErrDestinationLifecycleOutcomeUnknown, contextErr: context.Canceled, want: ErrDestinationTokenRotationOutcomeUnknown},
			{name: "joined conflict plus deadline", dependency: errors.Join(ErrDestinationLifecycleConflict, private), contextErr: context.DeadlineExceeded, want: ErrDestinationTokenRotationOutcomeUnknown},
			{name: "joined outcome plus cancel", dependency: errors.Join(ErrDestinationLifecycleOutcomeUnknown, private), contextErr: context.Canceled, want: ErrDestinationTokenRotationOutcomeUnknown},
			{name: "private plus deadline", dependency: private, contextErr: context.DeadlineExceeded, want: ErrDestinationTokenRotationOutcomeUnknown},
		} {
			t.Run(operation+"/"+test.name, func(t *testing.T) {
				ctx := newRotationMutableContext()
				lifecycle := &rotationTestLifecycle{snapshot: rotationTestActiveSnapshot(t)}
				service, _, _, inspector := rotationTestService(t, lifecycle)
				handle := rotationTestHandle(t)
				if operation == "rollback" {
					inspector.snapshot = rotationTestAttemptSnapshot(t, DestinationTokenRotationActiveWithRetiring)
					lifecycle.rollbackErr = test.dependency
					lifecycle.rollbackHook = func() { ctx.set(test.contextErr) }
					if err := service.RollbackRotation(ctx, handle); err != test.want || lifecycle.rollbackCalls != 1 {
						t.Fatal("rollback dependency error was downgraded by concurrent context")
					}
				} else {
					now := lifecycleTestNow.Add(7 * time.Hour)
					service.clock = DestinationLifecycleClockFunc(func() time.Time { return now })
					inspector.snapshot = rotationTestAttemptSnapshotAt(t, DestinationTokenRotationActiveWithRetiring, now)
					lifecycle.finalizeErr = test.dependency
					lifecycle.finalizeHook = func() { ctx.set(test.contextErr) }
					if err := service.FinalizeRotation(ctx, handle); err != test.want || lifecycle.finalizeCalls != 1 {
						t.Fatal("finalize dependency error was downgraded by concurrent context")
					}
				}
				if ctx.Err() != test.contextErr {
					t.Fatal("mutation hook did not establish the concurrent context condition")
				}
			})
		}
	}
}

func TestDestinationTokenRotationConcurrentBeginAllowsOneRotation(t *testing.T) {
	const callers = 24
	lifecycle := newConcurrentRotationLifecycle(t)
	service, _, _, _ := rotationTestService(t, lifecycle)

	start := make(chan struct{})
	results := make(chan error, callers)
	var wait sync.WaitGroup
	for range callers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			_, err := service.BeginRotation(context.Background(), rotationTestRequest(t))
			results <- err
		}()
	}
	close(start)
	wait.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
			continue
		}
		if err != ErrDestinationTokenRotationConflict {
			t.Fatal("concurrent rotation returned unexpected classification")
		}
	}
	if successes != 1 || lifecycle.successfulActivations != 1 {
		t.Fatal("concurrent rotation admitted more than one attempt")
	}
}

type concurrentRotationLifecycle struct {
	*rotationTestLifecycle
	state                 DestinationLifecycleStatus
	successfulActivations int
}

func newConcurrentRotationLifecycle(t *testing.T) *concurrentRotationLifecycle {
	return &concurrentRotationLifecycle{
		rotationTestLifecycle: &rotationTestLifecycle{
			snapshot: rotationTestActiveSnapshot(t), created: rotationTestCreated(t),
		},
		state: LifecycleActive,
	}
}

func (lifecycle *concurrentRotationLifecycle) InspectLifecycleState(
	context.Context,
	GatewayAudienceID,
	DestinationID,
) (DestinationLifecycleSnapshot, error) {
	lifecycle.mu.Lock()
	defer lifecycle.mu.Unlock()
	if lifecycle.state != LifecycleActive {
		return DestinationLifecycleSnapshot{
			audienceID: mustConcurrentAudience(), destinationID: mustConcurrentDestination(),
			destinationEnabled: true, status: LifecycleActiveWithRetiring,
		}, nil
	}
	return lifecycle.snapshot, nil
}

func (lifecycle *concurrentRotationLifecycle) CreateRotationStagedToken(
	context.Context,
	GatewayAudienceID,
	DestinationID,
	DestinationTokenRecordID,
	OpaqueDestinationToken,
) (CreatedStagedToken, error) {
	lifecycle.mu.Lock()
	defer lifecycle.mu.Unlock()
	if lifecycle.state != LifecycleActive {
		return CreatedStagedToken{}, ErrDestinationLifecycleConflict
	}
	lifecycle.state = LifecycleActiveWithStaged
	return lifecycle.created, nil
}

func (lifecycle *concurrentRotationLifecycle) ActivateRotation(
	context.Context,
	GatewayAudienceID,
	DestinationID,
	DestinationTokenRecordID,
	DestinationTokenRecordID,
) (DestinationTokenRotationActivationReceipt, error) {
	lifecycle.mu.Lock()
	defer lifecycle.mu.Unlock()
	if lifecycle.state != LifecycleActiveWithStaged {
		return DestinationTokenRotationActivationReceipt{}, ErrDestinationLifecycleConflict
	}
	lifecycle.state = LifecycleActiveWithRetiring
	lifecycle.successfulActivations++
	return DestinationTokenRotationActivationReceipt{
		activatedAt: lifecycleTestNow, retirementDeadline: lifecycleTestNow.Add(6 * time.Hour),
	}, nil
}

func rotationTestAttemptSnapshot(
	t *testing.T,
	status DestinationTokenRotationStatus,
) DestinationTokenRotationAttemptSnapshot {
	return rotationTestAttemptSnapshotAt(t, status, lifecycleTestNow)
}

func rotationTestAttemptSnapshotAt(
	t *testing.T,
	status DestinationTokenRotationStatus,
	now time.Time,
) DestinationTokenRotationAttemptSnapshot {
	t.Helper()
	destination := rotationTestDestination(t)
	newID := mustLifecycleRecordID(t, lifecycleTestRecordTwoText)
	oldID := mustLifecycleRecordID(t, lifecycleTestRecordOneText)
	rotationStarted := lifecycleTestNow.Add(-time.Minute)
	retirementDeadline := lifecycleTestNow.Add(6 * time.Hour)

	newSpec := rotationTokenSpec(t, destination, newID, DestinationTokenActive)
	newSpec.CreatedAt = rotationStarted.Add(-time.Minute)
	newSpec.ActivatedAt = rotationStarted
	newSpec.StateChangedAt = rotationStarted
	oldSpec := rotationTokenSpec(t, destination, oldID, DestinationTokenRetiring)
	oldSpec.ActivatedAt = lifecycleTestNow.Add(-time.Hour)
	oldSpec.RetirementStartedAt = rotationStarted
	oldSpec.RetirementDeadline = retirementDeadline
	oldSpec.StateChangedAt = rotationStarted

	switch status {
	case DestinationTokenRotationRolledBack:
		rollbackAt := lifecycleTestNow.Add(-30 * time.Second)
		newSpec.State = DestinationTokenRevoked
		newSpec.RevokedAt = rollbackAt
		newSpec.StateChangedAt = rollbackAt
		oldSpec.State = DestinationTokenActive
		oldSpec.RetirementStartedAt = time.Time{}
		oldSpec.RetirementDeadline = time.Time{}
		oldSpec.StateChangedAt = rollbackAt
	case DestinationTokenRotationCompleted:
		finalizationStarted := lifecycleTestNow.Add(-2 * time.Hour)
		deadline := lifecycleTestNow.Add(-time.Hour)
		finalizedAt := lifecycleTestNow.Add(-30 * time.Minute)
		newSpec.CreatedAt = finalizationStarted
		newSpec.ActivatedAt = finalizationStarted
		newSpec.StateChangedAt = finalizationStarted
		oldSpec.State = DestinationTokenRevoked
		oldSpec.CreatedAt = lifecycleTestNow.Add(-4 * time.Hour)
		oldSpec.ActivatedAt = lifecycleTestNow.Add(-3 * time.Hour)
		oldSpec.RetirementStartedAt = finalizationStarted
		oldSpec.RetirementDeadline = deadline
		oldSpec.RevokedAt = finalizedAt
		oldSpec.StateChangedAt = finalizedAt
	}
	newToken, err := NewDestinationToken(newSpec)
	if err != nil {
		t.Fatal("rotation new token snapshot setup failed")
	}
	oldToken, err := NewDestinationToken(oldSpec)
	if err != nil {
		t.Fatal("rotation old token snapshot setup failed")
	}
	live := []DestinationToken{newToken, oldToken}
	if status == DestinationTokenRotationRolledBack {
		live = []DestinationToken{oldToken}
	} else if status == DestinationTokenRotationCompleted {
		live = []DestinationToken{newToken}
	}
	lifecycle, err := NewDestinationLifecycleSnapshot(destination, live, now)
	if err != nil {
		t.Fatal("rotation lifecycle snapshot setup failed")
	}
	attempt, err := NewDestinationTokenRotationAttemptSnapshot(
		lifecycle, newToken, oldToken, newID, oldID, now,
	)
	if err != nil {
		t.Fatal("rotation attempt snapshot setup failed")
	}
	return attempt
}

func rotationTestPreparedAttemptSnapshot(t *testing.T) DestinationTokenRotationAttemptSnapshot {
	t.Helper()
	destination := rotationTestDestination(t)
	newID := mustLifecycleRecordID(t, lifecycleTestRecordTwoText)
	oldID := mustLifecycleRecordID(t, lifecycleTestRecordOneText)
	preparedAt := lifecycleTestNow.Add(-time.Minute)

	newSpec := rotationTokenSpec(t, destination, newID, DestinationTokenStaged)
	newSpec.CreatedAt = preparedAt
	newSpec.StateChangedAt = preparedAt
	oldSpec := rotationTokenSpec(t, destination, oldID, DestinationTokenActive)
	oldSpec.ActivatedAt = lifecycleTestNow.Add(-time.Hour)
	oldSpec.StateChangedAt = oldSpec.ActivatedAt
	newToken, err := NewDestinationToken(newSpec)
	if err != nil {
		t.Fatal("rotation prepared token snapshot setup failed")
	}
	oldToken, err := NewDestinationToken(oldSpec)
	if err != nil {
		t.Fatal("rotation prepared old token snapshot setup failed")
	}
	lifecycle, err := NewDestinationLifecycleSnapshot(
		destination, []DestinationToken{oldToken, newToken}, lifecycleTestNow,
	)
	if err != nil || lifecycle.Status() != LifecycleActiveWithStaged {
		t.Fatal("rotation prepared lifecycle snapshot setup failed")
	}
	attempt, err := NewDestinationTokenRotationAttemptSnapshot(
		lifecycle, newToken, oldToken, newID, oldID, lifecycleTestNow,
	)
	if err != nil {
		t.Fatal("rotation prepared attempt snapshot setup failed")
	}
	return attempt
}

func rotationTestAbortedStagedAttemptAfterPriorRollback(t *testing.T) DestinationTokenRotationAttemptSnapshot {
	t.Helper()
	destination := rotationTestDestination(t)
	newID := mustLifecycleRecordID(t, lifecycleTestRecordTwoText)
	oldID := mustLifecycleRecordID(t, lifecycleTestRecordOneText)
	priorRollbackAt := lifecycleTestNow.Add(-10 * time.Minute)
	abortedAt := lifecycleTestNow.Add(-30 * time.Second)

	newSpec := rotationTokenSpec(t, destination, newID, DestinationTokenRevoked)
	newSpec.CreatedAt = lifecycleTestNow.Add(-5 * time.Minute)
	newSpec.RevokedAt = abortedAt
	newSpec.StateChangedAt = abortedAt
	oldSpec := rotationTokenSpec(t, destination, oldID, DestinationTokenActive)
	oldSpec.CreatedAt = lifecycleTestNow.Add(-4 * time.Hour)
	oldSpec.ActivatedAt = lifecycleTestNow.Add(-3 * time.Hour)
	oldSpec.StateChangedAt = priorRollbackAt
	newToken, err := NewDestinationToken(newSpec)
	if err != nil {
		t.Fatal("rotation prior-rollback aborted token setup failed")
	}
	oldToken, err := NewDestinationToken(oldSpec)
	if err != nil {
		t.Fatal("rotation prior-rollback old token setup failed")
	}
	lifecycle, err := NewDestinationLifecycleSnapshot(
		destination, []DestinationToken{oldToken}, lifecycleTestNow,
	)
	if err != nil || lifecycle.Status() != LifecycleActive {
		t.Fatal("rotation prior-rollback aborted lifecycle setup failed")
	}
	attempt, err := NewDestinationTokenRotationAttemptSnapshot(
		lifecycle, newToken, oldToken, newID, oldID, lifecycleTestNow,
	)
	if err != nil {
		t.Fatal("rotation prior-rollback aborted attempt setup failed")
	}
	return attempt
}

func rotationTokenSpec(
	t *testing.T,
	destination Destination,
	recordID DestinationTokenRecordID,
	state DestinationTokenState,
) DestinationTokenSpec {
	t.Helper()
	verifier, err := NewTokenVerifier(make([]byte, 32))
	if err != nil {
		t.Fatal("rotation verifier setup failed")
	}
	return DestinationTokenSpec{
		AudienceID: destination.AudienceID(), Destination: destination, RecordID: recordID,
		Verifier: verifier, VerifierKeyID: mustLifecycleKeyID(t), State: state,
		CreatedAt:             lifecycleTestNow.Add(-2 * time.Hour),
		ExpiresAt:             lifecycleTestNow.Add(48 * time.Hour),
		StagedCleanupDeadline: lifecycleTestNow.Add(10 * time.Hour),
	}
}

func mustConcurrentAudience() GatewayAudienceID {
	value, _ := ParseGatewayAudienceID(lifecycleTestAudienceText)
	return value
}

func mustConcurrentDestination() DestinationID {
	value, _ := ParseDestinationID(lifecycleTestDestinationText)
	return value
}

func stringsContain(value, part string) bool {
	for index := 0; index+len(part) <= len(value); index++ {
		if value[index:index+len(part)] == part {
			return true
		}
	}
	return false
}

func TestDestinationTokenRotationConfigurationAndErrors(t *testing.T) {
	lifecycle := &rotationTestLifecycle{snapshot: rotationTestActiveSnapshot(t), created: rotationTestCreated(t)}
	service, resolver, identifier, inspector := rotationTestService(t, lifecycle)
	valid := DestinationTokenRotationParticipantConfig{
		Clock: service.clock, Resolver: resolver, Identifier: identifier,
		AttemptInspector: inspector, Lifecycle: lifecycle, CompensationTimeout: time.Second,
	}
	invalid := []DestinationTokenRotationParticipantConfig{
		{},
		func() DestinationTokenRotationParticipantConfig { value := valid; value.Clock = nil; return value }(),
		func() DestinationTokenRotationParticipantConfig { value := valid; value.Resolver = nil; return value }(),
		func() DestinationTokenRotationParticipantConfig { value := valid; value.Identifier = nil; return value }(),
		func() DestinationTokenRotationParticipantConfig {
			value := valid
			value.AttemptInspector = nil
			return value
		}(),
		func() DestinationTokenRotationParticipantConfig { value := valid; value.Lifecycle = nil; return value }(),
		func() DestinationTokenRotationParticipantConfig {
			value := valid
			value.CompensationTimeout = 0
			return value
		}(),
		func() DestinationTokenRotationParticipantConfig {
			value := valid
			value.CompensationTimeout = MaximumDestinationTokenRotationCompensationDuration + time.Nanosecond
			return value
		}(),
	}
	for _, config := range invalid {
		if created, err := NewDestinationTokenRotationParticipantService(config); created != nil ||
			err != ErrDestinationTokenRotationInvalid {
			t.Fatal("invalid rotation participant configuration was accepted")
		}
	}
	if DestinationTokenRotationTokenNew != 1 || DestinationTokenRotationTokenOld != 2 ||
		DestinationTokenRotationTokenNeither != 3 || DestinationTokenRotationTokenIdentity(0).Valid() ||
		DestinationTokenRotationTokenIdentity(4).Valid() {
		t.Fatal("rotation token identity wire values changed")
	}
	validAttempt := DestinationTokenRotationAttempt{
		handle:             rotationTestHandle(t),
		newToken:           rotationTestCreated(t).Token(),
		activatedAt:        lifecycleTestNow,
		retirementDeadline: lifecycleTestNow.Add(6 * time.Hour),
	}
	if !validRotationAttempt(validAttempt, true) || validRotationAttempt(validAttempt, false) {
		t.Fatal("confirmed rotation attempt timing contract was rejected")
	}
	handleOnly := rotationReconciliationAttempt(
		rotationTestRequest(t),
		mustLifecycleRecordID(t, lifecycleTestRecordTwoText),
		mustLifecycleRecordID(t, lifecycleTestRecordOneText),
	)
	if !validRotationAttempt(handleOnly, false) || validRotationAttempt(handleOnly, true) {
		t.Fatal("handle-only rotation attempt timing contract was rejected")
	}
	for _, malformed := range []DestinationTokenRotationAttempt{
		func() DestinationTokenRotationAttempt {
			value := validAttempt
			value.activatedAt = time.Time{}
			return value
		}(),
		func() DestinationTokenRotationAttempt {
			value := validAttempt
			value.retirementDeadline = value.activatedAt
			return value
		}(),
		func() DestinationTokenRotationAttempt {
			value := handleOnly
			value.activatedAt = lifecycleTestNow
			return value
		}(),
	} {
		if validRotationAttempt(malformed, true) || validRotationAttempt(malformed, false) {
			t.Fatal("malformed rotation attempt timing metadata was accepted")
		}
	}
	activeObservation := DestinationTokenRotationObservation{
		status:        DestinationTokenRotationActiveWithRetiring,
		tokenIdentity: DestinationTokenRotationTokenNew,
		observedAt:    lifecycleTestNow, retirementDeadline: lifecycleTestNow.Add(6 * time.Hour),
	}
	terminalObservation := DestinationTokenRotationObservation{
		status:        DestinationTokenRotationCompleted,
		tokenIdentity: DestinationTokenRotationTokenOld,
	}
	if !validRotationObservation(activeObservation, true) ||
		!validRotationObservation(terminalObservation, true) {
		t.Fatal("valid rotation observation timing contract was rejected")
	}
	activeObservation.observedAt = time.Time{}
	terminalObservation.retirementDeadline = lifecycleTestNow
	if validRotationObservation(activeObservation, true) ||
		validRotationObservation(terminalObservation, true) {
		t.Fatal("malformed rotation observation timing metadata was accepted")
	}
	if request, err := NewDestinationTokenRotationRequest(
		mustLifecycleAudience(t), mustLifecycleDestinationID(t), OpaqueDestinationToken{},
	); err != nil || request.CurrentToken() != (OpaqueDestinationToken{}) {
		t.Fatal("canonical all-zero rotation token value was rejected")
	}
	if handle, err := NewDestinationTokenRotationHandle(
		mustLifecycleAudience(t), mustLifecycleDestinationID(t),
		mustLifecycleRecordID(t, lifecycleTestRecordOneText),
		mustLifecycleRecordID(t, lifecycleTestRecordOneText),
	); err != ErrDestinationTokenRotationInvalid || handle != (DestinationTokenRotationHandle{}) {
		t.Fatal("same-record rotation handle was accepted")
	}
	inspector.snapshot = rotationTestAttemptSnapshot(t, DestinationTokenRotationActiveWithRetiring)
	if observation, err := service.ObserveRotation(
		context.Background(), rotationTestHandle(t), OpaqueDestinationToken{},
	); err != nil || observation.TokenIdentity() != DestinationTokenRotationTokenNew ||
		identifier.calls != 1 || inspector.calls != 1 {
		t.Fatal("canonical all-zero observation token was rejected")
	}
	for _, err := range []error{
		ErrDestinationTokenRotationInvalid,
		ErrDestinationTokenRotationConflict,
		ErrDestinationTokenRotationUnavailable,
		ErrDestinationTokenRotationOutcomeUnknown,
		ErrDestinationTokenRotationReconciliation,
		ErrDestinationTokenRotationCanceled,
		ErrDestinationTokenRotationDeadline,
	} {
		if errors.Unwrap(err) != nil || stringsContain(err.Error(), rotationPrivateMarker) {
			t.Fatal("rotation sentinel was wrapped or content-bearing")
		}
	}
}
