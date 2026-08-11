package intake

import (
	"context"
	"crypto/subtle"
	"errors"
	"reflect"

	"github.com/duj4/ms-oncall-gateway/internal/durable"
	"github.com/duj4/ms-oncall-gateway/internal/httpapi"
	"github.com/duj4/ms-oncall-gateway/internal/protection"
)

// Request contains only the authenticated and resolved context required by
// durable acceptance. Raw routing tokens and transport credentials do not
// belong in this boundary.
type Request struct {
	CorePrincipalID  string
	DestinationID    string
	DeliveryIdentity string
	Event            httpapi.Event
}

type Protector interface {
	Prepare(
		context.Context,
		string,
		string,
		durable.DeliveryIdentity,
		httpapi.CanonicalEvent,
	) (durable.PreparedAcceptance, error)
}

type Service struct {
	protector Protector
	store     durable.Store
}

func NewService(protector Protector, store durable.Store) *Service {
	return &Service{protector: protector, store: store}
}

// Accept canonicalizes, protects, and durably accepts one validated typed
// event. Every failure returns a zero result and a fixed safe error.
func (service *Service) Accept(ctx context.Context, request Request) (durable.Result, error) {
	if service == nil || isNilInterface(service.protector) || isNilInterface(service.store) || isNilInterface(ctx) {
		return durable.Result{}, ErrInvalidRequest
	}
	if ctx.Err() != nil {
		return durable.Result{}, ErrCanceled
	}
	if request.CorePrincipalID == "" || request.DestinationID == "" || isNilInterface(request.Event) {
		return durable.Result{}, ErrInvalidRequest
	}

	deliveryIdentity, err := durable.ParseDeliveryIdentity(request.DeliveryIdentity)
	if err != nil || deliveryIdentity.String() != request.DeliveryIdentity {
		return durable.Result{}, ErrInvalidRequest
	}

	canonicalEvent, err := httpapi.CanonicalizeEvent(request.Event)
	if err != nil {
		return durable.Result{}, httpapi.ErrCanonicalEvent
	}
	if ctx.Err() != nil {
		return durable.Result{}, ErrCanceled
	}

	prepared, err := service.protector.Prepare(
		ctx,
		request.CorePrincipalID,
		request.DestinationID,
		deliveryIdentity,
		canonicalEvent,
	)
	if err != nil {
		return durable.Result{}, classifyProtectionError(err)
	}
	if !preparedMatchesRequest(prepared, request, deliveryIdentity, canonicalEvent) {
		return durable.Result{}, protection.ErrProtectionFailed
	}
	if ctx.Err() != nil {
		return durable.Result{}, ErrCanceled
	}

	result, err := service.store.Accept(ctx, prepared)
	if err != nil {
		return durable.Result{}, classifyStoreError(err)
	}
	if !validResult(result) {
		return durable.Result{}, durable.ErrStoreFailure
	}
	return result, nil
}

func preparedMatchesRequest(
	prepared durable.PreparedAcceptance,
	request Request,
	deliveryIdentity durable.DeliveryIdentity,
	canonicalEvent httpapi.CanonicalEvent,
) bool {
	if prepared.CorePrincipalID() != request.CorePrincipalID ||
		prepared.DestinationID() != request.DestinationID ||
		prepared.DeliveryIdentity() != deliveryIdentity ||
		prepared.FormatVersion() != canonicalEvent.FormatVersion() ||
		prepared.EncryptionKeyID() == "" {
		return false
	}

	protectedEvent := prepared.CanonicalEvent()
	protectedDigest := prepared.ProtectedDigest()
	if len(protectedEvent.Ciphertext()) == 0 || len(protectedEvent.Nonce()) == 0 ||
		len(protectedDigest.Ciphertext()) == 0 || len(protectedDigest.Nonce()) == 0 {
		return false
	}

	canonicalDigest := durable.CanonicalDigest(canonicalEvent.Digest())
	preparedDigest := prepared.EquivalenceDigest()
	return subtle.ConstantTimeCompare(preparedDigest[:], canonicalDigest[:]) == 1
}

func validResult(result durable.Result) bool {
	switch result.Disposition {
	case durable.AcceptedNew, durable.AcceptedDuplicate:
		return !result.ReceiptID.IsZero()
	case durable.IdentityConflict:
		return result.ReceiptID.IsZero()
	default:
		return false
	}
}

func classifyProtectionError(err error) error {
	for _, safe := range []error{
		protection.ErrProtectionInvalid,
		protection.ErrProtectionKeyUnavailable,
		protection.ErrProtectionRandom,
		protection.ErrProtectionFailed,
		protection.ErrProtectedDigestUnreadable,
	} {
		if errors.Is(err, safe) {
			return safe
		}
	}
	return protection.ErrProtectionFailed
}

func classifyStoreError(err error) error {
	for _, safe := range []error{
		durable.ErrInvalidAcceptance,
		durable.ErrReceiptGeneration,
		durable.ErrStoreUnavailable,
		durable.ErrStoreOutcomeUnknown,
		durable.ErrStoreCanceled,
		durable.ErrStoreFailure,
		durable.ErrStoredRecordUnreadable,
	} {
		if errors.Is(err, safe) {
			return safe
		}
	}
	return durable.ErrStoreFailure
}

func isNilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
