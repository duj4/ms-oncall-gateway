package intake

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/duj4/ms-oncall-gateway/internal/durable"
	"github.com/duj4/ms-oncall-gateway/internal/httpapi"
	"github.com/duj4/ms-oncall-gateway/internal/protection"
)

const (
	testPrincipal    = "core-principal-test"
	testDestination  = "destination-test"
	testIdentityText = "00112233-4455-4677-8899-aabbccddeeff"
)

type protectorFunc func(
	context.Context,
	string,
	string,
	durable.DeliveryIdentity,
	httpapi.CanonicalEvent,
) (durable.PreparedAcceptance, error)

func (function protectorFunc) Prepare(
	ctx context.Context,
	principal string,
	destination string,
	identity durable.DeliveryIdentity,
	event httpapi.CanonicalEvent,
) (durable.PreparedAcceptance, error) {
	return function(ctx, principal, destination, identity, event)
}

type storeFunc func(context.Context, durable.PreparedAcceptance) (durable.Result, error)

func (function storeFunc) Accept(ctx context.Context, acceptance durable.PreparedAcceptance) (durable.Result, error) {
	return function(ctx, acceptance)
}

type nilProtector struct{}

func (*nilProtector) Prepare(
	context.Context,
	string,
	string,
	durable.DeliveryIdentity,
	httpapi.CanonicalEvent,
) (durable.PreparedAcceptance, error) {
	panic("typed-nil protector was called")
}

type nilStore struct{}

func (*nilStore) Accept(context.Context, durable.PreparedAcceptance) (durable.Result, error) {
	panic("typed-nil store was called")
}

type nilContext struct{}

func (*nilContext) Deadline() (time.Time, bool) { return time.Time{}, false }
func (*nilContext) Done() <-chan struct{}       { return nil }
func (*nilContext) Err() error                  { panic("typed-nil context was called") }
func (*nilContext) Value(any) any               { return nil }

type unsupportedEvent struct{}

func (unsupportedEvent) Kind() httpapi.EventType { return httpapi.EventTypeTest }

func baseRequest() Request {
	return Request{
		CorePrincipalID:  testPrincipal,
		DestinationID:    testDestination,
		DeliveryIdentity: testIdentityText,
		Event:            httpapi.TestEvent{AppName: "MS OnCall"},
	}
}

func mustIdentity(t *testing.T, value string) durable.DeliveryIdentity {
	t.Helper()
	identity, err := durable.ParseDeliveryIdentity(value)
	if err != nil {
		t.Fatal("delivery identity test setup failed")
	}
	return identity
}

func testReceipt(seed byte) durable.ReceiptID {
	var receipt durable.ReceiptID
	for index := range receipt {
		receipt[index] = seed + byte(index)
	}
	return receipt
}

func testProtected(t *testing.T, label string) durable.ProtectedValue {
	t.Helper()
	value, err := durable.NewProtectedValue([]byte("ciphertext-"+label), []byte("nonce-"+label))
	if err != nil {
		t.Fatal("protected value test setup failed")
	}
	return value
}

func mustCanonical(t *testing.T, event httpapi.Event) httpapi.CanonicalEvent {
	t.Helper()
	canonical, err := httpapi.CanonicalizeEvent(event)
	if err != nil {
		t.Fatal("canonical event test setup failed")
	}
	return canonical
}

func mustPrepared(
	t *testing.T,
	principal string,
	destination string,
	identity durable.DeliveryIdentity,
	canonical httpapi.CanonicalEvent,
) durable.PreparedAcceptance {
	t.Helper()
	prepared, err := durable.NewPreparedAcceptance(
		principal,
		destination,
		identity,
		canonical.FormatVersion(),
		testProtected(t, "event"),
		testProtected(t, "digest"),
		"key-test",
		durable.CanonicalDigest(canonical.Digest()),
	)
	if err != nil {
		t.Fatal("prepared acceptance test setup failed")
	}
	return prepared
}

func mustPreparedWith(
	t *testing.T,
	principal string,
	destination string,
	identity durable.DeliveryIdentity,
	formatVersion int64,
	digest durable.CanonicalDigest,
) durable.PreparedAcceptance {
	t.Helper()
	prepared, err := durable.NewPreparedAcceptance(
		principal,
		destination,
		identity,
		formatVersion,
		testProtected(t, "event"),
		testProtected(t, "digest"),
		"key-test",
		digest,
	)
	if err != nil {
		t.Fatal("prepared mismatch test setup failed")
	}
	return prepared
}

func preparedEqual(left, right durable.PreparedAcceptance) bool {
	return left.CorePrincipalID() == right.CorePrincipalID() &&
		left.DestinationID() == right.DestinationID() &&
		left.DeliveryIdentity() == right.DeliveryIdentity() &&
		left.FormatVersion() == right.FormatVersion() &&
		bytes.Equal(left.CanonicalEvent().Ciphertext(), right.CanonicalEvent().Ciphertext()) &&
		bytes.Equal(left.CanonicalEvent().Nonce(), right.CanonicalEvent().Nonce()) &&
		bytes.Equal(left.ProtectedDigest().Ciphertext(), right.ProtectedDigest().Ciphertext()) &&
		bytes.Equal(left.ProtectedDigest().Nonce(), right.ProtectedDigest().Nonce()) &&
		left.EncryptionKeyID() == right.EncryptionKeyID() &&
		left.EquivalenceDigest() == right.EquivalenceDigest()
}

func resultIsZero(result durable.Result) bool {
	return result.Disposition == 0 && result.ReceiptID.IsZero()
}

func mustDigest(t *testing.T, encoded string) durable.CanonicalDigest {
	t.Helper()
	decoded, err := hex.DecodeString(encoded)
	if err != nil || len(decoded) != len(durable.CanonicalDigest{}) {
		t.Fatal("canonical digest test setup failed")
	}
	var digest durable.CanonicalDigest
	copy(digest[:], decoded)
	return digest
}

func acceptingProtector(t *testing.T) protectorFunc {
	t.Helper()
	return func(
		_ context.Context,
		principal string,
		destination string,
		identity durable.DeliveryIdentity,
		canonical httpapi.CanonicalEvent,
	) (durable.PreparedAcceptance, error) {
		return mustPrepared(t, principal, destination, identity, canonical), nil
	}
}

func rejectingStore(t *testing.T) storeFunc {
	t.Helper()
	return func(context.Context, durable.PreparedAcceptance) (durable.Result, error) {
		t.Fatal("durable store was called")
		return durable.Result{}, nil
	}
}

func TestAcceptSequenceAndExactHandoff(t *testing.T) {
	request := baseRequest()
	identity := mustIdentity(t, testIdentityText)
	wantBytes := []byte(`{"AppName":"MS OnCall","Type":"Test"}`)
	wantDigest := mustDigest(t, "f2af9dcf05005b12331273216cda1a0696f0381460c570f39a5165d9f97056bf")
	wantReceipt := testReceipt(10)
	var sequence []string
	var handedOff durable.PreparedAcceptance
	var protected durable.PreparedAcceptance

	protector := protectorFunc(func(
		_ context.Context,
		principal string,
		destination string,
		gotIdentity durable.DeliveryIdentity,
		canonical httpapi.CanonicalEvent,
	) (durable.PreparedAcceptance, error) {
		sequence = append(sequence, "protect")
		if principal != testPrincipal || destination != testDestination || gotIdentity != identity {
			t.Fatal("protector context mismatch")
		}
		if canonical.FormatVersion() != httpapi.CanonicalEventFormatVersion ||
			!bytes.Equal(canonical.Bytes(), wantBytes) ||
			durable.CanonicalDigest(canonical.Digest()) != wantDigest {
			t.Fatal("canonical handoff differs from hard-coded vector")
		}
		protected = mustPrepared(t, principal, destination, gotIdentity, canonical)
		return protected, nil
	})
	store := storeFunc(func(_ context.Context, prepared durable.PreparedAcceptance) (durable.Result, error) {
		sequence = append(sequence, "store")
		if !preparedEqual(prepared, protected) {
			t.Fatal("durable store received a different prepared acceptance")
		}
		handedOff = prepared
		return durable.Result{Disposition: durable.AcceptedNew, ReceiptID: wantReceipt}, nil
	})

	result, err := NewService(protector, store).Accept(context.Background(), request)
	if err != nil {
		t.Fatal("acceptance pipeline failed")
	}
	if result.Disposition != durable.AcceptedNew || result.ReceiptID != wantReceipt {
		t.Fatal("new acceptance result invariant failed")
	}
	if len(sequence) != 2 || sequence[0] != "protect" || sequence[1] != "store" {
		t.Fatal("pipeline dependency order mismatch")
	}
	if handedOff.CorePrincipalID() != testPrincipal ||
		handedOff.DestinationID() != testDestination ||
		handedOff.DeliveryIdentity() != identity ||
		handedOff.FormatVersion() != httpapi.CanonicalEventFormatVersion ||
		handedOff.EquivalenceDigest() != wantDigest {
		t.Fatal("durable prepared handoff mismatch")
	}
}

func TestAcceptValidResultInvariants(t *testing.T) {
	receipt := testReceipt(20)
	tests := []struct {
		name string
		want durable.Result
	}{
		{name: "new", want: durable.Result{Disposition: durable.AcceptedNew, ReceiptID: receipt}},
		{name: "duplicate", want: durable.Result{Disposition: durable.AcceptedDuplicate, ReceiptID: receipt}},
		{name: "conflict", want: durable.Result{Disposition: durable.IdentityConflict}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := NewService(acceptingProtector(t), storeFunc(func(context.Context, durable.PreparedAcceptance) (durable.Result, error) {
				return test.want, nil
			}))
			result, err := service.Accept(context.Background(), baseRequest())
			if err != nil || result != test.want {
				t.Fatal("valid durable result was rejected")
			}
		})
	}
}

func TestAcceptRejectsInvalidServiceAndRequest(t *testing.T) {
	validProtector := acceptingProtector(t)
	validStore := storeFunc(func(context.Context, durable.PreparedAcceptance) (durable.Result, error) {
		return durable.Result{Disposition: durable.AcceptedNew, ReceiptID: testReceipt(30)}, nil
	})
	request := baseRequest()

	var nilService *Service
	result, err := nilService.Accept(context.Background(), request)
	if err != ErrInvalidRequest || !resultIsZero(result) {
		t.Fatal("nil receiver was not rejected safely")
	}

	var typedNilProtector *nilProtector
	var typedNilStore *nilStore
	var typedNilContext *nilContext
	invalidServices := []struct {
		name    string
		service *Service
		ctx     context.Context
	}{
		{name: "nil protector", service: NewService(nil, validStore), ctx: context.Background()},
		{name: "typed nil protector", service: NewService(typedNilProtector, validStore), ctx: context.Background()},
		{name: "nil store", service: NewService(validProtector, nil), ctx: context.Background()},
		{name: "typed nil store", service: NewService(validProtector, typedNilStore), ctx: context.Background()},
		{name: "nil context", service: NewService(validProtector, validStore)},
		{name: "typed nil context", service: NewService(validProtector, validStore), ctx: typedNilContext},
	}
	for _, test := range invalidServices {
		t.Run(test.name, func(t *testing.T) {
			result, err := test.service.Accept(test.ctx, request)
			if err != ErrInvalidRequest || !resultIsZero(result) {
				t.Fatal("invalid pipeline dependency was not rejected safely")
			}
		})
	}

	var typedNilEvent *httpapi.TestEvent
	invalidRequests := []struct {
		name   string
		mutate func(*Request)
	}{
		{name: "empty principal", mutate: func(value *Request) { value.CorePrincipalID = "" }},
		{name: "empty destination", mutate: func(value *Request) { value.DestinationID = "" }},
		{name: "empty identity", mutate: func(value *Request) { value.DeliveryIdentity = "" }},
		{name: "malformed identity", mutate: func(value *Request) { value.DeliveryIdentity = "not-a-uuid" }},
		{name: "uppercase identity", mutate: func(value *Request) { value.DeliveryIdentity = strings.ToUpper(testIdentityText) }},
		{name: "unhyphenated identity", mutate: func(value *Request) { value.DeliveryIdentity = strings.ReplaceAll(testIdentityText, "-", "") }},
		{name: "zero identity", mutate: func(value *Request) { value.DeliveryIdentity = "00000000-0000-0000-0000-000000000000" }},
		{name: "nil event", mutate: func(value *Request) { value.Event = nil }},
		{name: "typed nil event", mutate: func(value *Request) { value.Event = typedNilEvent }},
	}
	for _, test := range invalidRequests {
		t.Run(test.name, func(t *testing.T) {
			candidate := request
			test.mutate(&candidate)
			protectorCalls := 0
			storeCalls := 0
			service := NewService(
				protectorFunc(func(context.Context, string, string, durable.DeliveryIdentity, httpapi.CanonicalEvent) (durable.PreparedAcceptance, error) {
					protectorCalls++
					return durable.PreparedAcceptance{}, nil
				}),
				storeFunc(func(context.Context, durable.PreparedAcceptance) (durable.Result, error) {
					storeCalls++
					return durable.Result{}, nil
				}),
			)
			result, err := service.Accept(context.Background(), candidate)
			if err != ErrInvalidRequest || !resultIsZero(result) || protectorCalls != 0 || storeCalls != 0 {
				t.Fatal("invalid request crossed the pipeline boundary")
			}
		})
	}
}

func TestAcceptCancellationBoundaries(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	protectorCalls := 0
	service := NewService(
		protectorFunc(func(context.Context, string, string, durable.DeliveryIdentity, httpapi.CanonicalEvent) (durable.PreparedAcceptance, error) {
			protectorCalls++
			return durable.PreparedAcceptance{}, nil
		}),
		rejectingStore(t),
	)
	result, err := service.Accept(ctx, baseRequest())
	if err != ErrCanceled || !resultIsZero(result) || protectorCalls != 0 {
		t.Fatal("already-canceled context crossed the protection boundary")
	}

	ctx, cancel = context.WithCancel(context.Background())
	service = NewService(
		protectorFunc(func(
			_ context.Context,
			principal string,
			destination string,
			identity durable.DeliveryIdentity,
			canonical httpapi.CanonicalEvent,
		) (durable.PreparedAcceptance, error) {
			prepared := mustPrepared(t, principal, destination, identity, canonical)
			cancel()
			return prepared, nil
		}),
		rejectingStore(t),
	)
	result, err = service.Accept(ctx, baseRequest())
	if err != ErrCanceled || !resultIsZero(result) {
		t.Fatal("post-protection cancellation did not fail closed")
	}
}

func TestAcceptCanonicalizationFailureStopsDependencies(t *testing.T) {
	protectorCalls := 0
	storeCalls := 0
	service := NewService(
		protectorFunc(func(context.Context, string, string, durable.DeliveryIdentity, httpapi.CanonicalEvent) (durable.PreparedAcceptance, error) {
			protectorCalls++
			return durable.PreparedAcceptance{}, nil
		}),
		storeFunc(func(context.Context, durable.PreparedAcceptance) (durable.Result, error) {
			storeCalls++
			return durable.Result{}, nil
		}),
	)
	request := baseRequest()
	request.Event = unsupportedEvent{}
	result, err := service.Accept(context.Background(), request)
	if err != httpapi.ErrCanonicalEvent || !resultIsZero(result) || protectorCalls != 0 || storeCalls != 0 {
		t.Fatal("canonicalization failure crossed the dependency boundary")
	}
}

func TestAcceptProtectionErrorsAreSafeAndDiscardPartialAcceptance(t *testing.T) {
	privateError := errors.New("private protection provider detail")
	tests := []struct {
		name string
		err  error
		want error
	}{
		{name: "invalid", err: errors.Join(protection.ErrProtectionInvalid, privateError), want: protection.ErrProtectionInvalid},
		{name: "key unavailable", err: errors.Join(protection.ErrProtectionKeyUnavailable, privateError), want: protection.ErrProtectionKeyUnavailable},
		{name: "random unavailable", err: errors.Join(protection.ErrProtectionRandom, privateError), want: protection.ErrProtectionRandom},
		{name: "protection failed", err: errors.Join(protection.ErrProtectionFailed, privateError), want: protection.ErrProtectionFailed},
		{name: "digest unreadable", err: errors.Join(protection.ErrProtectedDigestUnreadable, privateError), want: protection.ErrProtectedDigestUnreadable},
		{name: "unknown", err: privateError, want: protection.ErrProtectionFailed},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			storeCalls := 0
			service := NewService(
				protectorFunc(func(
					_ context.Context,
					principal string,
					destination string,
					identity durable.DeliveryIdentity,
					canonical httpapi.CanonicalEvent,
				) (durable.PreparedAcceptance, error) {
					return mustPrepared(t, principal, destination, identity, canonical), test.err
				}),
				storeFunc(func(context.Context, durable.PreparedAcceptance) (durable.Result, error) {
					storeCalls++
					return durable.Result{}, nil
				}),
			)
			result, err := service.Accept(context.Background(), baseRequest())
			if err != test.want || !resultIsZero(result) || storeCalls != 0 || strings.Contains(err.Error(), "private") {
				t.Fatal("protection failure was not safely classified")
			}
		})
	}
}

func TestAcceptRejectsMismatchedOrInvalidPreparedAcceptance(t *testing.T) {
	request := baseRequest()
	identity := mustIdentity(t, testIdentityText)
	canonical := mustCanonical(t, request.Event)
	digest := durable.CanonicalDigest(canonical.Digest())
	wrongDigest := digest
	wrongDigest[0] ^= 1
	wrongIdentity := identity
	wrongIdentity[0] ^= 1

	tests := []struct {
		name     string
		prepared durable.PreparedAcceptance
	}{
		{name: "principal", prepared: mustPreparedWith(t, "other-principal", testDestination, identity, canonical.FormatVersion(), digest)},
		{name: "destination", prepared: mustPreparedWith(t, testPrincipal, "other-destination", identity, canonical.FormatVersion(), digest)},
		{name: "identity", prepared: mustPreparedWith(t, testPrincipal, testDestination, wrongIdentity, canonical.FormatVersion(), digest)},
		{name: "format", prepared: mustPreparedWith(t, testPrincipal, testDestination, identity, canonical.FormatVersion()+1, digest)},
		{name: "digest", prepared: mustPreparedWith(t, testPrincipal, testDestination, identity, canonical.FormatVersion(), wrongDigest)},
		{name: "protected values and key", prepared: durable.PreparedAcceptance{}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			storeCalls := 0
			service := NewService(
				protectorFunc(func(context.Context, string, string, durable.DeliveryIdentity, httpapi.CanonicalEvent) (durable.PreparedAcceptance, error) {
					return test.prepared, nil
				}),
				storeFunc(func(context.Context, durable.PreparedAcceptance) (durable.Result, error) {
					storeCalls++
					return durable.Result{}, nil
				}),
			)
			result, err := service.Accept(context.Background(), request)
			if err != protection.ErrProtectionFailed || !resultIsZero(result) || storeCalls != 0 {
				t.Fatal("invalid prepared acceptance reached durable storage")
			}
		})
	}
}

func TestAcceptStoreErrorsAreSafeAndDiscardPartialResult(t *testing.T) {
	privateError := errors.New("private durable adapter detail")
	receipt := testReceipt(40)
	tests := []struct {
		name string
		err  error
		want error
	}{
		{name: "invalid acceptance", err: errors.Join(durable.ErrInvalidAcceptance, privateError), want: durable.ErrInvalidAcceptance},
		{name: "receipt generation", err: errors.Join(durable.ErrReceiptGeneration, privateError), want: durable.ErrReceiptGeneration},
		{name: "unavailable", err: errors.Join(durable.ErrStoreUnavailable, privateError), want: durable.ErrStoreUnavailable},
		{name: "outcome unknown", err: errors.Join(durable.ErrStoreOutcomeUnknown, privateError), want: durable.ErrStoreOutcomeUnknown},
		{name: "canceled", err: errors.Join(durable.ErrStoreCanceled, privateError), want: durable.ErrStoreCanceled},
		{name: "failure", err: errors.Join(durable.ErrStoreFailure, privateError), want: durable.ErrStoreFailure},
		{name: "record unreadable", err: errors.Join(durable.ErrStoredRecordUnreadable, privateError), want: durable.ErrStoredRecordUnreadable},
		{name: "unknown", err: privateError, want: durable.ErrStoreFailure},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := NewService(acceptingProtector(t), storeFunc(func(context.Context, durable.PreparedAcceptance) (durable.Result, error) {
				return durable.Result{Disposition: durable.AcceptedNew, ReceiptID: receipt}, test.err
			}))
			result, err := service.Accept(context.Background(), baseRequest())
			if err != test.want || !resultIsZero(result) || strings.Contains(err.Error(), "private") {
				t.Fatal("durable failure was not safely classified")
			}
		})
	}
}

func TestAcceptRejectsInvalidDurableResults(t *testing.T) {
	receipt := testReceipt(50)
	tests := []struct {
		name   string
		result durable.Result
	}{
		{name: "unknown disposition", result: durable.Result{Disposition: durable.Disposition(99), ReceiptID: receipt}},
		{name: "new missing receipt", result: durable.Result{Disposition: durable.AcceptedNew}},
		{name: "duplicate missing receipt", result: durable.Result{Disposition: durable.AcceptedDuplicate}},
		{name: "conflict with receipt", result: durable.Result{Disposition: durable.IdentityConflict, ReceiptID: receipt}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := NewService(acceptingProtector(t), storeFunc(func(context.Context, durable.PreparedAcceptance) (durable.Result, error) {
				return test.result, nil
			}))
			result, err := service.Accept(context.Background(), baseRequest())
			if err != durable.ErrStoreFailure || !resultIsZero(result) {
				t.Fatal("invalid durable result did not fail closed")
			}
		})
	}
}

func TestAcceptDoesNotMutateRequestOrMeta(t *testing.T) {
	meta := map[string]string{"zeta": "last", "alpha": "first"}
	event := httpapi.AlertEvent{
		AppName:     "MS OnCall",
		AlertID:     42,
		Summary:     "summary",
		Details:     "details",
		ServiceID:   "11111111-2222-4333-8444-555555555555",
		ServiceName: "Fixture Service",
		Meta:        meta,
	}
	request := baseRequest()
	request.Event = event
	originalMeta := map[string]string{"zeta": "last", "alpha": "first"}

	service := NewService(
		protectorFunc(func(
			_ context.Context,
			principal string,
			destination string,
			identity durable.DeliveryIdentity,
			canonical httpapi.CanonicalEvent,
		) (durable.PreparedAcceptance, error) {
			copyOfBytes := canonical.Bytes()
			copyOfBytes[0] ^= 1
			return mustPrepared(t, principal, destination, identity, canonical), nil
		}),
		storeFunc(func(_ context.Context, prepared durable.PreparedAcceptance) (durable.Result, error) {
			ciphertext := prepared.CanonicalEvent().Ciphertext()
			ciphertext[0] ^= 1
			return durable.Result{Disposition: durable.AcceptedNew, ReceiptID: testReceipt(60)}, nil
		}),
	)
	if _, err := service.Accept(context.Background(), request); err != nil {
		t.Fatal("immutable request test failed")
	}
	if request.CorePrincipalID != testPrincipal ||
		request.DestinationID != testDestination ||
		request.DeliveryIdentity != testIdentityText {
		t.Fatal("pipeline mutated request fields")
	}
	returnedEvent, ok := request.Event.(httpapi.AlertEvent)
	if !ok ||
		returnedEvent.AppName != event.AppName ||
		returnedEvent.AlertID != event.AlertID ||
		returnedEvent.Summary != event.Summary ||
		returnedEvent.Details != event.Details ||
		returnedEvent.ServiceID != event.ServiceID ||
		returnedEvent.ServiceName != event.ServiceName {
		t.Fatal("pipeline mutated event fields")
	}
	if len(meta) != len(originalMeta) || meta["zeta"] != originalMeta["zeta"] || meta["alpha"] != originalMeta["alpha"] {
		t.Fatal("pipeline mutated event metadata")
	}
}

type memoryKeySource struct {
	key protection.Key
}

func (source memoryKeySource) ActiveKey(context.Context) (protection.Key, error) {
	return source.key, nil
}

func (source memoryKeySource) KeyByID(context.Context, string) (protection.Key, error) {
	return source.key, nil
}

type acceptanceKey struct {
	principal   string
	destination string
	identity    durable.DeliveryIdentity
}

type memoryRepository struct {
	mu      sync.Mutex
	records map[acceptanceKey]durable.StoredAcceptance
}

func newMemoryRepository() *memoryRepository {
	return &memoryRepository{records: make(map[acceptanceKey]durable.StoredAcceptance)}
}

func (repository *memoryRepository) InsertOrLoad(
	_ context.Context,
	candidate durable.Candidate,
) (durable.PersistenceResult, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()

	key := acceptanceKey{
		principal:   candidate.Acceptance.CorePrincipalID(),
		destination: candidate.Acceptance.DestinationID(),
		identity:    candidate.Acceptance.DeliveryIdentity(),
	}
	if stored, ok := repository.records[key]; ok {
		return durable.PersistenceResult{Stored: stored}, nil
	}
	stored := durable.StoredAcceptance{
		ReceiptID:       candidate.ReceiptID,
		FormatVersion:   candidate.Acceptance.FormatVersion(),
		ProtectedDigest: candidate.Acceptance.ProtectedDigest(),
		EncryptionKeyID: candidate.Acceptance.EncryptionKeyID(),
	}
	repository.records[key] = stored
	return durable.PersistenceResult{Inserted: true, Stored: stored}, nil
}

func (repository *memoryRepository) count() int {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	return len(repository.records)
}

func realPipeline(t *testing.T) (*Service, *memoryRepository) {
	t.Helper()
	material := make([]byte, 32)
	for index := range material {
		material[index] = byte(index + 1)
	}
	key, err := protection.NewKey("test-key", material)
	if err != nil {
		t.Fatal("payload key test setup failed")
	}
	protector := protection.NewService(memoryKeySource{key: key})
	repository := newMemoryRepository()
	store := durable.NewService(repository, protector)
	return NewService(protector, store), repository
}

func TestAcceptRealInMemoryCompositionNewDuplicateAndConflict(t *testing.T) {
	service, repository := realPipeline(t)
	request := baseRequest()

	first, err := service.Accept(context.Background(), request)
	if err != nil || first.Disposition != durable.AcceptedNew || first.ReceiptID.IsZero() {
		t.Fatal("real composition did not accept a new event")
	}
	duplicate, err := service.Accept(context.Background(), request)
	if err != nil || duplicate.Disposition != durable.AcceptedDuplicate || duplicate.ReceiptID != first.ReceiptID {
		t.Fatal("real composition did not return the stable duplicate receipt")
	}
	request.Event = httpapi.TestEvent{AppName: "MS OnCall Alternate"}
	conflict, err := service.Accept(context.Background(), request)
	if err != nil || conflict.Disposition != durable.IdentityConflict || !conflict.ReceiptID.IsZero() {
		t.Fatal("real composition did not return an identity conflict")
	}
	if repository.count() != 1 {
		t.Fatal("real composition persisted an unexpected record count")
	}
}

func TestAcceptConcurrentIdenticalRequests(t *testing.T) {
	service, repository := realPipeline(t)
	const calls = 24
	results := make([]durable.Result, calls)
	errorsFound := make([]error, calls)
	var wait sync.WaitGroup
	for index := 0; index < calls; index++ {
		wait.Add(1)
		go func(position int) {
			defer wait.Done()
			results[position], errorsFound[position] = service.Accept(context.Background(), baseRequest())
		}(index)
	}
	wait.Wait()

	newCount := 0
	duplicateCount := 0
	var receipt durable.ReceiptID
	for index := range results {
		if errorsFound[index] != nil || results[index].ReceiptID.IsZero() {
			t.Fatal("concurrent pipeline call failed")
		}
		if receipt.IsZero() {
			receipt = results[index].ReceiptID
		}
		if results[index].ReceiptID != receipt {
			t.Fatal("concurrent duplicate receipt was unstable")
		}
		switch results[index].Disposition {
		case durable.AcceptedNew:
			newCount++
		case durable.AcceptedDuplicate:
			duplicateCount++
		default:
			t.Fatal("concurrent result disposition was invalid")
		}
	}
	if newCount != 1 || duplicateCount != calls-1 || repository.count() != 1 {
		t.Fatal("concurrent acceptance counts were invalid")
	}
}

func TestRuntimeRemainsUnavailable(t *testing.T) {
	request := httptest.NewRequest(
		http.MethodPost,
		"/v1/goalert/contact-method/synthetic-routing-token",
		strings.NewReader(`{"AppName":"MS OnCall","Type":"Test"}`),
	)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", testIdentityText)
	response := httptest.NewRecorder()
	httpapi.NewHandler(httpapi.UnavailableSink{}, nil).ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable || response.Header().Get("Retry-After") == "" {
		t.Fatal("runtime no longer fails safely with unavailable sink")
	}
}
