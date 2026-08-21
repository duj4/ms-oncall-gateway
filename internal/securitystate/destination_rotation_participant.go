package securitystate

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"time"
)

const MaximumDestinationTokenRotationCompensationDuration = 30 * time.Second

type DestinationTokenRotationTokenIdentity uint8

const (
	DestinationTokenRotationTokenNew DestinationTokenRotationTokenIdentity = iota + 1
	DestinationTokenRotationTokenOld
	DestinationTokenRotationTokenNeither
)

func (identity DestinationTokenRotationTokenIdentity) Valid() bool {
	return identity == DestinationTokenRotationTokenNew ||
		identity == DestinationTokenRotationTokenOld ||
		identity == DestinationTokenRotationTokenNeither
}

type DestinationTokenRotationStatus uint8

const (
	DestinationTokenRotationActiveWithRetiring DestinationTokenRotationStatus = iota + 1
	DestinationTokenRotationRolledBack
	DestinationTokenRotationCompleted
)

func (status DestinationTokenRotationStatus) Valid() bool {
	return status == DestinationTokenRotationActiveWithRetiring ||
		status == DestinationTokenRotationRolledBack ||
		status == DestinationTokenRotationCompleted
}

type DestinationTokenRotationRequest struct {
	audienceID   GatewayAudienceID
	destination  DestinationID
	currentToken OpaqueDestinationToken
}

func NewDestinationTokenRotationRequest(
	audience GatewayAudienceID,
	destination DestinationID,
	currentToken OpaqueDestinationToken,
) (DestinationTokenRotationRequest, error) {
	if !validRotationBinding(audience, destination) {
		return DestinationTokenRotationRequest{}, ErrDestinationTokenRotationInvalid
	}
	return DestinationTokenRotationRequest{
		audienceID: audience, destination: destination, currentToken: currentToken,
	}, nil
}

func (value DestinationTokenRotationRequest) AudienceID() GatewayAudienceID { return value.audienceID }
func (value DestinationTokenRotationRequest) DestinationID() DestinationID  { return value.destination }
func (value DestinationTokenRotationRequest) CurrentToken() OpaqueDestinationToken {
	return value.currentToken
}
func (DestinationTokenRotationRequest) Format(state fmt.State, verb rune) { writeRedacted(state) }

type DestinationTokenRotationHandle struct {
	audienceID          GatewayAudienceID
	destination         DestinationID
	newActiveRecordID   DestinationTokenRecordID
	oldRetiringRecordID DestinationTokenRecordID
}

func NewDestinationTokenRotationHandle(
	audience GatewayAudienceID,
	destination DestinationID,
	newActiveRecordID DestinationTokenRecordID,
	oldRetiringRecordID DestinationTokenRecordID,
) (DestinationTokenRotationHandle, error) {
	handle := DestinationTokenRotationHandle{
		audienceID: audience, destination: destination,
		newActiveRecordID: newActiveRecordID, oldRetiringRecordID: oldRetiringRecordID,
	}
	if !validRotationHandle(handle) {
		return DestinationTokenRotationHandle{}, ErrDestinationTokenRotationInvalid
	}
	return handle, nil
}

func (value DestinationTokenRotationHandle) AudienceID() GatewayAudienceID { return value.audienceID }
func (value DestinationTokenRotationHandle) DestinationID() DestinationID  { return value.destination }
func (value DestinationTokenRotationHandle) NewActiveRecordID() DestinationTokenRecordID {
	return value.newActiveRecordID
}
func (value DestinationTokenRotationHandle) OldRetiringRecordID() DestinationTokenRecordID {
	return value.oldRetiringRecordID
}
func (DestinationTokenRotationHandle) Format(state fmt.State, verb rune) { writeRedacted(state) }

type DestinationTokenRotationAttempt struct {
	handle             DestinationTokenRotationHandle
	newToken           OneTimeDestinationToken
	activatedAt        time.Time
	retirementDeadline time.Time
}

func (value DestinationTokenRotationAttempt) Handle() DestinationTokenRotationHandle {
	return value.handle
}
func (value DestinationTokenRotationAttempt) NewToken() OneTimeDestinationToken {
	return cloneOneTimeDestinationToken(value.newToken)
}
func (value DestinationTokenRotationAttempt) ActivatedAt() time.Time {
	return value.activatedAt
}
func (value DestinationTokenRotationAttempt) RetirementDeadline() time.Time {
	return value.retirementDeadline
}
func (DestinationTokenRotationAttempt) Format(state fmt.State, verb rune) { writeRedacted(state) }

type DestinationTokenRotationObservation struct {
	status             DestinationTokenRotationStatus
	tokenIdentity      DestinationTokenRotationTokenIdentity
	observedAt         time.Time
	retirementDeadline time.Time
}

func (value DestinationTokenRotationObservation) Status() DestinationTokenRotationStatus {
	return value.status
}
func (value DestinationTokenRotationObservation) TokenIdentity() DestinationTokenRotationTokenIdentity {
	return value.tokenIdentity
}
func (value DestinationTokenRotationObservation) ObservedAt() time.Time {
	return value.observedAt
}
func (value DestinationTokenRotationObservation) RetirementDeadline() time.Time {
	return value.retirementDeadline
}
func (DestinationTokenRotationObservation) Format(state fmt.State, verb rune) { writeRedacted(state) }

type DestinationTokenRotationParticipant interface {
	BeginRotation(context.Context, DestinationTokenRotationRequest) (DestinationTokenRotationAttempt, error)
	RollbackRotation(context.Context, DestinationTokenRotationHandle) error
	ObserveRotation(context.Context, DestinationTokenRotationHandle, OpaqueDestinationToken) (DestinationTokenRotationObservation, error)
	FinalizeRotation(context.Context, DestinationTokenRotationHandle) error
}

type DestinationTokenRotationParticipantConfig struct {
	Clock               DestinationLifecycleClock
	Resolver            DestinationResolver
	Identifier          DestinationRotationTokenIdentifier
	AttemptInspector    DestinationTokenRotationAttemptInspector
	Lifecycle           DestinationTokenLifecycle
	CompensationTimeout time.Duration
}

func (DestinationTokenRotationParticipantConfig) Format(state fmt.State, verb rune) {
	writeRedacted(state)
}

type DestinationTokenRotationParticipantService struct {
	clock               DestinationLifecycleClock
	resolver            DestinationResolver
	identifier          DestinationRotationTokenIdentifier
	attemptInspector    DestinationTokenRotationAttemptInspector
	lifecycle           DestinationTokenLifecycle
	compensationTimeout time.Duration
}

var _ DestinationTokenRotationParticipant = (*DestinationTokenRotationParticipantService)(nil)

func (*DestinationTokenRotationParticipantService) Format(state fmt.State, verb rune) {
	writeRedacted(state)
}

func NewDestinationTokenRotationParticipantService(
	config DestinationTokenRotationParticipantConfig,
) (*DestinationTokenRotationParticipantService, error) {
	if nilRotationDependency(config.Clock) || nilRotationDependency(config.Resolver) ||
		nilRotationDependency(config.Identifier) || nilRotationDependency(config.Lifecycle) ||
		nilRotationDependency(config.AttemptInspector) ||
		config.CompensationTimeout <= 0 ||
		config.CompensationTimeout > MaximumDestinationTokenRotationCompensationDuration {
		return nil, ErrDestinationTokenRotationInvalid
	}
	return &DestinationTokenRotationParticipantService{
		clock: config.Clock, resolver: config.Resolver, identifier: config.Identifier,
		attemptInspector: config.AttemptInspector,
		lifecycle:        config.Lifecycle, compensationTimeout: config.CompensationTimeout,
	}, nil
}

func (service *DestinationTokenRotationParticipantService) BeginRotation(
	ctx context.Context,
	request DestinationTokenRotationRequest,
) (DestinationTokenRotationAttempt, error) {
	now, err := service.beginInput(ctx, request)
	if err != nil {
		return DestinationTokenRotationAttempt{}, err
	}

	resolved, resolveErr := service.resolver.Resolve(
		ctx, request.audienceID, request.currentToken, now,
	)
	if resolveErr != nil {
		return DestinationTokenRotationAttempt{}, classifyRotationResolverError(ctx, resolveErr)
	}
	if cancellation := rotationContextError(ctx); cancellation != nil {
		return DestinationTokenRotationAttempt{}, cancellation
	}
	if resolved != request.destination {
		return DestinationTokenRotationAttempt{}, ErrDestinationTokenRotationConflict
	}

	snapshot, inspectErr := service.lifecycle.InspectLifecycleState(
		ctx, request.audienceID, request.destination,
	)
	if inspectErr != nil {
		return DestinationTokenRotationAttempt{}, classifyRotationPreMutationLifecycleError(ctx, inspectErr)
	}
	if cancellation := rotationContextError(ctx); cancellation != nil {
		return DestinationTokenRotationAttempt{}, cancellation
	}
	oldActive, stateErr := rotationBeginActive(snapshot, request.audienceID, request.destination)
	if stateErr != nil {
		return DestinationTokenRotationAttempt{}, stateErr
	}

	created, createErr := service.lifecycle.CreateRotationStagedToken(
		ctx,
		request.audienceID,
		request.destination,
		oldActive.RecordID(),
		request.currentToken,
	)
	if createErr != nil {
		classified := classifyRotationCreateError(ctx, createErr)
		if classified == ErrDestinationTokenRotationReconciliation {
			attempt := rotationReconciliationAttempt(request, created.RecordID(), oldActive.RecordID())
			if validRotationHandle(attempt.handle) {
				return attempt, classified
			}
		}
		return DestinationTokenRotationAttempt{}, classified
	}
	if created.RecordID().IsZero() {
		return DestinationTokenRotationAttempt{}, ErrDestinationTokenRotationReconciliation
	}
	handle := DestinationTokenRotationHandle{
		audienceID: request.audienceID, destination: request.destination,
		newActiveRecordID: created.RecordID(), oldRetiringRecordID: oldActive.RecordID(),
	}
	if !validRotationHandle(handle) {
		return DestinationTokenRotationAttempt{}, ErrDestinationTokenRotationReconciliation
	}
	if created.Token().IsZero() {
		if service.abortCreatedStaged(ctx, request, created.RecordID()) != nil {
			return rotationReconciliationAttempt(request, created.RecordID(), oldActive.RecordID()),
				ErrDestinationTokenRotationReconciliation
		}
		return DestinationTokenRotationAttempt{}, ErrDestinationTokenRotationUnavailable
	}
	if cancellation := rotationContextError(ctx); cancellation != nil {
		if service.abortCreatedStaged(ctx, request, created.RecordID()) != nil {
			return rotationReconciliationAttempt(request, created.RecordID(), oldActive.RecordID()),
				ErrDestinationTokenRotationReconciliation
		}
		return DestinationTokenRotationAttempt{}, cancellation
	}

	activation, activateErr := service.lifecycle.ActivateRotation(
		ctx,
		request.audienceID,
		request.destination,
		created.RecordID(),
		oldActive.RecordID(),
	)
	if activateErr != nil {
		safeErr, definitelyNotCommitted := classifyRotationActivationError(ctx, activateErr)
		if !definitelyNotCommitted {
			return rotationReconciliationAttempt(request, created.RecordID(), oldActive.RecordID()),
				ErrDestinationTokenRotationReconciliation
		}
		if service.abortCreatedStaged(ctx, request, created.RecordID()) != nil {
			return rotationReconciliationAttempt(request, created.RecordID(), oldActive.RecordID()),
				ErrDestinationTokenRotationReconciliation
		}
		return DestinationTokenRotationAttempt{}, safeErr
	}
	if !activation.valid() {
		return rotationReconciliationAttempt(request, created.RecordID(), oldActive.RecordID()),
			ErrDestinationTokenRotationReconciliation
	}
	confirmedAt := service.clock.Now()
	if !activation.validAt(confirmedAt) || rotationContextError(ctx) != nil {
		return rotationReconciliationAttempt(request, created.RecordID(), oldActive.RecordID()),
			ErrDestinationTokenRotationReconciliation
	}

	attempt := DestinationTokenRotationAttempt{
		handle: handle, newToken: cloneOneTimeDestinationToken(created.Token()),
		activatedAt:        activation.ActivatedAt(),
		retirementDeadline: activation.RetirementDeadline(),
	}
	if !validRotationAttempt(attempt, true) {
		return rotationReconciliationAttempt(request, created.RecordID(), oldActive.RecordID()),
			ErrDestinationTokenRotationReconciliation
	}
	return attempt, nil
}

func (service *DestinationTokenRotationParticipantService) RollbackRotation(
	ctx context.Context,
	handle DestinationTokenRotationHandle,
) error {
	now, err := service.operationNow(ctx, handle)
	if err != nil {
		return err
	}
	inspection, err := service.inspectRotation(ctx, handle, now)
	if err != nil {
		return err
	}
	if inspection.status != DestinationTokenRotationActiveWithRetiring {
		return ErrDestinationTokenRotationConflict
	}
	if !now.Before(inspection.retirementDeadline) {
		return ErrDestinationTokenRotationConflict
	}
	if cancellation := rotationContextError(ctx); cancellation != nil {
		return cancellation
	}
	err = service.lifecycle.RollbackRotation(
		ctx, handle.audienceID, handle.destination,
		handle.newActiveRecordID, handle.oldRetiringRecordID,
	)
	return classifyRotationMutationError(ctx, err)
}

func (service *DestinationTokenRotationParticipantService) ObserveRotation(
	ctx context.Context,
	handle DestinationTokenRotationHandle,
	token OpaqueDestinationToken,
) (DestinationTokenRotationObservation, error) {
	now, err := service.operationNow(ctx, handle)
	if err != nil {
		return DestinationTokenRotationObservation{}, err
	}
	identity, identifyErr := service.identifier.IdentifyRotationToken(
		ctx, handle.audienceID, handle.destination, token,
		handle.newActiveRecordID, handle.oldRetiringRecordID, now,
	)
	if identifyErr != nil || !identity.Valid() {
		return DestinationTokenRotationObservation{}, ErrDestinationTokenRotationReconciliation
	}
	if cancellation := rotationContextError(ctx); cancellation != nil {
		return DestinationTokenRotationObservation{}, cancellation
	}
	inspection, inspectErr := service.inspectRotation(ctx, handle, now)
	if inspectErr != nil {
		return DestinationTokenRotationObservation{}, ErrDestinationTokenRotationReconciliation
	}
	inspection.tokenIdentity = identity
	if !validRotationObservation(inspection, true) {
		return DestinationTokenRotationObservation{}, ErrDestinationTokenRotationReconciliation
	}
	return inspection, nil
}

func (service *DestinationTokenRotationParticipantService) FinalizeRotation(
	ctx context.Context,
	handle DestinationTokenRotationHandle,
) error {
	now, err := service.operationNow(ctx, handle)
	if err != nil {
		return err
	}
	inspection, err := service.inspectRotation(ctx, handle, now)
	if err != nil {
		return err
	}
	if inspection.status != DestinationTokenRotationActiveWithRetiring ||
		now.Before(inspection.retirementDeadline) {
		return ErrDestinationTokenRotationConflict
	}
	if cancellation := rotationContextError(ctx); cancellation != nil {
		return cancellation
	}
	err = service.lifecycle.FinalizeRotation(
		ctx, handle.audienceID, handle.destination,
		handle.newActiveRecordID, handle.oldRetiringRecordID,
		RotationDeadlineElapsed,
	)
	return classifyRotationMutationError(ctx, err)
}

func (service *DestinationTokenRotationParticipantService) inspectRotation(
	ctx context.Context,
	handle DestinationTokenRotationHandle,
	now time.Time,
) (DestinationTokenRotationObservation, error) {
	snapshot, err := service.attemptInspector.InspectRotationAttempt(
		ctx, handle.audienceID, handle.destination,
		handle.newActiveRecordID, handle.oldRetiringRecordID, now,
	)
	if err != nil {
		return DestinationTokenRotationObservation{}, ErrDestinationTokenRotationReconciliation
	}
	if cancellation := rotationContextError(ctx); cancellation != nil {
		return DestinationTokenRotationObservation{}, cancellation
	}
	return classifyRotationSnapshot(snapshot, handle, now)
}

func classifyRotationSnapshot(
	attempt DestinationTokenRotationAttemptSnapshot,
	handle DestinationTokenRotationHandle,
	now time.Time,
) (DestinationTokenRotationObservation, error) {
	snapshot := attempt.Lifecycle()
	if snapshot.AudienceID() != handle.audienceID || snapshot.DestinationID() != handle.destination ||
		!snapshot.DestinationEnabled() {
		return DestinationTokenRotationObservation{}, ErrDestinationTokenRotationReconciliation
	}
	newToken := attempt.NewToken()
	oldToken := attempt.OldToken()
	if newToken.RecordID() != handle.newActiveRecordID ||
		oldToken.RecordID() != handle.oldRetiringRecordID {
		return DestinationTokenRotationObservation{}, ErrDestinationTokenRotationReconciliation
	}
	staged, hasStaged := snapshot.Staged()
	active, hasActive := snapshot.Active()
	retiring, hasRetiring := snapshot.Retiring()

	if hasActive && hasRetiring && !hasStaged &&
		active.RecordID() == handle.newActiveRecordID &&
		retiring.RecordID() == handle.oldRetiringRecordID &&
		viewsEqual(active, newToken) && viewsEqual(retiring, oldToken) &&
		validRotationPairViews(active, retiring, now) &&
		(snapshot.Status() == LifecycleActiveWithRetiring ||
			snapshot.Status() == LifecycleReconciliationRequired &&
				!now.Before(retiring.RetirementDeadline())) {
		return DestinationTokenRotationObservation{
			status:             DestinationTokenRotationActiveWithRetiring,
			observedAt:         now,
			retirementDeadline: retiring.RetirementDeadline(),
		}, nil
	}
	if snapshot.Status() == LifecycleActiveWithStaged && hasActive && hasStaged && !hasRetiring &&
		staged.RecordID() == handle.newActiveRecordID &&
		active.RecordID() == handle.oldRetiringRecordID &&
		viewsEqual(staged, newToken) && viewsEqual(active, oldToken) {
		// Create acknowledgement ambiguity may leave the exact new record
		// durably prepared but not activated. Observation reports reconciliation;
		// it never guesses whether to retry activation or abort the record.
		return DestinationTokenRotationObservation{}, ErrDestinationTokenRotationReconciliation
	}
	if snapshot.Status() == LifecycleActive && hasActive && !hasStaged && !hasRetiring &&
		active.State() == DestinationTokenActive && now.Before(active.ExpiresAt()) &&
		!active.ActivatedAt().After(now) && !active.StateChangedAt().After(now) {
		switch active.RecordID() {
		case handle.oldRetiringRecordID:
			if viewsEqual(active, oldToken) && exactRolledBackAttempt(newToken, oldToken, now) {
				return DestinationTokenRotationObservation{status: DestinationTokenRotationRolledBack}, nil
			}
		case handle.newActiveRecordID:
			if viewsEqual(active, newToken) && exactCompletedAttempt(newToken, oldToken, now) {
				return DestinationTokenRotationObservation{status: DestinationTokenRotationCompleted}, nil
			}
		}
	}
	if snapshot.Status() == LifecycleReconciliationRequired {
		return DestinationTokenRotationObservation{}, ErrDestinationTokenRotationReconciliation
	}
	return DestinationTokenRotationObservation{}, ErrDestinationTokenRotationConflict
}

func validRotationObservation(value DestinationTokenRotationObservation, requireIdentity bool) bool {
	if requireIdentity && !value.tokenIdentity.Valid() {
		return false
	}
	switch value.status {
	case DestinationTokenRotationActiveWithRetiring:
		return !value.observedAt.IsZero() && !value.retirementDeadline.IsZero()
	case DestinationTokenRotationRolledBack, DestinationTokenRotationCompleted:
		return value.observedAt.IsZero() && value.retirementDeadline.IsZero()
	default:
		return false
	}
}

func viewsEqual(first, second LifecycleTokenView) bool {
	return first.recordID == second.recordID && first.state == second.state &&
		first.createdAt.Equal(second.createdAt) &&
		first.expiresAt.Equal(second.expiresAt) &&
		first.stagedCleanupDeadline.Equal(second.stagedCleanupDeadline) &&
		first.activatedAt.Equal(second.activatedAt) &&
		first.retirementStartedAt.Equal(second.retirementStartedAt) &&
		first.retirementDeadline.Equal(second.retirementDeadline) &&
		first.revokedAt.Equal(second.revokedAt) &&
		first.stateChangedAt.Equal(second.stateChangedAt)
}

func exactRolledBackAttempt(newToken, oldToken LifecycleTokenView, now time.Time) bool {
	if newToken.State() != DestinationTokenRevoked || oldToken.State() != DestinationTokenActive ||
		newToken.RevokedAt().IsZero() || !newToken.RevokedAt().Equal(newToken.StateChangedAt()) ||
		newToken.CreatedAt().IsZero() || newToken.CreatedAt().After(newToken.RevokedAt()) ||
		newToken.RevokedAt().After(now) ||
		!newToken.RetirementStartedAt().IsZero() || !newToken.RetirementDeadline().IsZero() ||
		!oldToken.RetirementStartedAt().IsZero() || !oldToken.RetirementDeadline().IsZero() ||
		!oldToken.RevokedAt().IsZero() || oldToken.ActivatedAt().IsZero() ||
		oldToken.ActivatedAt().After(oldToken.StateChangedAt()) || oldToken.StateChangedAt().After(now) {
		return false
	}
	if newToken.ActivatedAt().IsZero() {
		// A staged abort never changes the stable old-active row. That row may
		// legitimately retain a later state-changed timestamp from a rotation
		// which restored it before this candidate was staged. The exact aborted
		// row must therefore have been created no earlier than the old row's last
		// stable change. Requiring equality with its original activation would reject
		// that valid history, while accepting a change after candidate creation would
		// conflate this abort with another attempt. The common guard also proves C <= R.
		return !newToken.CreatedAt().Before(oldToken.StateChangedAt())
	}
	// A confirmed rollback clears the old row's retirement timestamps, so this
	// terminal snapshot no longer contains the attempt's recorded deadline. The
	// strict R < G proof therefore comes from the lifecycle repository being the
	// sole serialized writer and rejecting rollback at or after G before sending
	// either mutation. The interval and expiry checks below are additional
	// history-corruption guards; a sub-24-hour interval is not a substitute for
	// comparing R with that erased deadline.
	rollbackDuration := newToken.RevokedAt().Sub(newToken.ActivatedAt())
	return validActivatedRotationHistory(newToken, oldToken) &&
		rollbackDuration >= 0 && rollbackDuration < MaximumRetiringOverlapDuration &&
		newToken.RevokedAt().Before(newToken.ExpiresAt()) &&
		newToken.RevokedAt().Equal(oldToken.StateChangedAt())
}

func exactCompletedAttempt(newToken, oldToken LifecycleTokenView, now time.Time) bool {
	return newToken.State() == DestinationTokenActive && oldToken.State() == DestinationTokenRevoked &&
		validActivatedRotationHistory(newToken, oldToken) &&
		!oldToken.RevokedAt().IsZero() && oldToken.RevokedAt().Equal(oldToken.StateChangedAt()) &&
		!oldToken.ActivatedAt().IsZero() && !oldToken.RetirementStartedAt().IsZero() &&
		!oldToken.RetirementDeadline().IsZero() &&
		!oldToken.ActivatedAt().After(oldToken.RetirementStartedAt()) &&
		!oldToken.RevokedAt().Before(oldToken.RetirementDeadline()) &&
		oldToken.RetirementDeadline().Before(newToken.ExpiresAt()) &&
		oldToken.RetirementDeadline().Before(oldToken.ExpiresAt()) &&
		newToken.ActivatedAt().Equal(newToken.StateChangedAt()) &&
		newToken.ActivatedAt().Equal(oldToken.RetirementStartedAt()) &&
		oldToken.RetirementStartedAt().Before(oldToken.RetirementDeadline()) &&
		!oldToken.RevokedAt().After(now)
}

func validRotationPairViews(active, retiring LifecycleTokenView, now time.Time) bool {
	return active.State() == DestinationTokenActive && retiring.State() == DestinationTokenRetiring &&
		validActivatedRotationHistory(active, retiring) &&
		!active.ActivatedAt().IsZero() && !retiring.ActivatedAt().IsZero() &&
		!retiring.RetirementStartedAt().IsZero() &&
		now.Before(active.ExpiresAt()) && !active.ActivatedAt().After(now) &&
		!active.StateChangedAt().After(now) && !retiring.ActivatedAt().After(now) &&
		!retiring.RetirementStartedAt().After(now) && !retiring.StateChangedAt().After(now) &&
		active.ActivatedAt().Equal(active.StateChangedAt()) &&
		active.ActivatedAt().Equal(retiring.RetirementStartedAt()) &&
		retiring.RetirementStartedAt().Equal(retiring.StateChangedAt()) &&
		!retiring.RetirementDeadline().IsZero() &&
		retiring.RetirementDeadline().Before(active.ExpiresAt()) &&
		retiring.RetirementDeadline().Before(retiring.ExpiresAt())
}

func validActivatedRotationHistory(newToken, oldToken LifecycleTokenView) bool {
	return !newToken.CreatedAt().Before(oldToken.ActivatedAt()) &&
		!newToken.ActivatedAt().Before(oldToken.ActivatedAt()) &&
		newToken.ActivatedAt().Before(newToken.StagedCleanupDeadline())
}

func rotationBeginActive(
	snapshot DestinationLifecycleSnapshot,
	audience GatewayAudienceID,
	destination DestinationID,
) (LifecycleTokenView, error) {
	if snapshot.AudienceID() != audience || snapshot.DestinationID() != destination ||
		!snapshot.DestinationEnabled() {
		return LifecycleTokenView{}, ErrDestinationTokenRotationReconciliation
	}
	active, hasActive := snapshot.Active()
	_, hasStaged := snapshot.Staged()
	_, hasRetiring := snapshot.Retiring()
	if snapshot.Status() == LifecycleReconciliationRequired {
		return LifecycleTokenView{}, ErrDestinationTokenRotationReconciliation
	}
	if snapshot.Status() != LifecycleActive || !hasActive || hasStaged || hasRetiring ||
		active.State() != DestinationTokenActive || active.RecordID().IsZero() {
		return LifecycleTokenView{}, ErrDestinationTokenRotationConflict
	}
	return active, nil
}

func (service *DestinationTokenRotationParticipantService) abortCreatedStaged(
	ctx context.Context,
	request DestinationTokenRotationRequest,
	recordID DestinationTokenRecordID,
) error {
	cleanupCtx, cancel := rotationCompensationContext(ctx, service.compensationTimeout)
	defer cancel()
	return service.lifecycle.AbortStagedToken(
		cleanupCtx, request.audienceID, request.destination, recordID,
	)
}

func rotationCompensationContext(parent context.Context, limit time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(parent), limit)
}

func (service *DestinationTokenRotationParticipantService) beginInput(
	ctx context.Context,
	request DestinationTokenRotationRequest,
) (time.Time, error) {
	if service == nil || nilRotationDependency(ctx) || nilRotationDependency(service.clock) ||
		nilRotationDependency(service.resolver) || nilRotationDependency(service.identifier) ||
		nilRotationDependency(service.attemptInspector) ||
		nilRotationDependency(service.lifecycle) ||
		service.compensationTimeout <= 0 ||
		service.compensationTimeout > MaximumDestinationTokenRotationCompensationDuration ||
		!validRotationBinding(request.audienceID, request.destination) {
		return time.Time{}, ErrDestinationTokenRotationInvalid
	}
	if cancellation := rotationContextError(ctx); cancellation != nil {
		return time.Time{}, cancellation
	}
	now := service.clock.Now()
	if now.IsZero() {
		return time.Time{}, ErrDestinationTokenRotationInvalid
	}
	return now, nil
}

func (service *DestinationTokenRotationParticipantService) operationNow(
	ctx context.Context,
	handle DestinationTokenRotationHandle,
) (time.Time, error) {
	if service == nil || nilRotationDependency(ctx) || nilRotationDependency(service.clock) ||
		nilRotationDependency(service.identifier) || nilRotationDependency(service.attemptInspector) ||
		nilRotationDependency(service.lifecycle) ||
		service.compensationTimeout <= 0 ||
		service.compensationTimeout > MaximumDestinationTokenRotationCompensationDuration ||
		!validRotationHandle(handle) {
		return time.Time{}, ErrDestinationTokenRotationInvalid
	}
	if cancellation := rotationContextError(ctx); cancellation != nil {
		return time.Time{}, cancellation
	}
	now := service.clock.Now()
	if now.IsZero() {
		return time.Time{}, ErrDestinationTokenRotationInvalid
	}
	return now, nil
}

func validRotationBinding(audience GatewayAudienceID, destination DestinationID) bool {
	if audience.IsZero() || destination.IsZero() {
		return false
	}
	parsedAudience, audienceErr := ParseGatewayAudienceID(audience.String())
	parsedDestination, destinationErr := ParseDestinationID(destination.String())
	return audienceErr == nil && destinationErr == nil &&
		parsedAudience == audience && parsedDestination == destination
}

func validRotationHandle(handle DestinationTokenRotationHandle) bool {
	if !validRotationBinding(handle.audienceID, handle.destination) ||
		handle.newActiveRecordID.IsZero() || handle.oldRetiringRecordID.IsZero() ||
		handle.newActiveRecordID == handle.oldRetiringRecordID {
		return false
	}
	parsedNew, newErr := ParseDestinationTokenRecordID(handle.newActiveRecordID.String())
	parsedOld, oldErr := ParseDestinationTokenRecordID(handle.oldRetiringRecordID.String())
	return newErr == nil && oldErr == nil &&
		parsedNew == handle.newActiveRecordID && parsedOld == handle.oldRetiringRecordID
}

func validRotationAttempt(value DestinationTokenRotationAttempt, confirmed bool) bool {
	if !validRotationHandle(value.handle) {
		return false
	}
	receipt := DestinationTokenRotationActivationReceipt{
		activatedAt: value.activatedAt, retirementDeadline: value.retirementDeadline,
	}
	if confirmed {
		return !value.newToken.IsZero() && receipt.valid()
	}
	return value.newToken.IsZero() && value.activatedAt.IsZero() && value.retirementDeadline.IsZero()
}

func classifyRotationResolverError(_ context.Context, err error) error {
	if rotationSingleCauseMatches(err, context.Canceled) {
		return ErrDestinationTokenRotationCanceled
	}
	if rotationSingleCauseMatches(err, context.DeadlineExceeded) {
		return ErrDestinationTokenRotationDeadline
	}
	if rotationSingleCauseMatches(err, ErrDestinationNotFound) {
		return ErrDestinationTokenRotationConflict
	}
	return ErrDestinationTokenRotationUnavailable
}

func classifyRotationPreMutationLifecycleError(_ context.Context, err error) error {
	result, known, _ := classifyRotationLifecycleError(err)
	if known {
		return result
	}
	return ErrDestinationTokenRotationUnavailable
}

func classifyRotationCreateError(_ context.Context, err error) error {
	result, known, outcomeUnknown := classifyRotationLifecycleError(err)
	if outcomeUnknown || !known {
		return ErrDestinationTokenRotationReconciliation
	}
	return result
}

func classifyRotationActivationError(_ context.Context, err error) (error, bool) {
	result, known, outcomeUnknown := classifyRotationLifecycleError(err)
	if outcomeUnknown || !known {
		return ErrDestinationTokenRotationReconciliation, false
	}
	return result, true
}

func classifyRotationMutationError(_ context.Context, err error) error {
	if err == nil {
		return nil
	}
	result, known, outcomeUnknown := classifyRotationLifecycleError(err)
	if outcomeUnknown || !known {
		return ErrDestinationTokenRotationOutcomeUnknown
	}
	return result
}

func classifyRotationLifecycleError(err error) (error, bool, bool) {
	if err == nil {
		return nil, true, false
	}
	if rotationSingleCauseMatches(err, ErrDestinationLifecycleOutcomeUnknown) {
		return ErrDestinationTokenRotationOutcomeUnknown, true, true
	}
	for _, item := range []struct{ lifecycle, rotation error }{
		{ErrDestinationLifecycleCanceled, ErrDestinationTokenRotationCanceled},
		{ErrDestinationLifecycleDeadline, ErrDestinationTokenRotationDeadline},
		{ErrDestinationLifecycleInvalid, ErrDestinationTokenRotationInvalid},
		{ErrDestinationLifecycleConflict, ErrDestinationTokenRotationConflict},
		{ErrDestinationLifecycleReconciliation, ErrDestinationTokenRotationReconciliation},
		{ErrDestinationLifecycleUnavailable, ErrDestinationTokenRotationUnavailable},
	} {
		if rotationSingleCauseMatches(err, item.lifecycle) {
			return item.rotation, true, false
		}
	}
	return nil, false, false
}

func rotationContextError(ctx context.Context) error {
	if !nilRotationDependency(ctx) && errors.Is(ctx.Err(), context.Canceled) {
		return ErrDestinationTokenRotationCanceled
	}
	if !nilRotationDependency(ctx) && errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return ErrDestinationTokenRotationDeadline
	}
	return nil
}

func rotationSingleCauseMatches(err, target error) bool {
	for current, depth := err, 0; current != nil && depth < 64; depth++ {
		if nilRotationDependency(current) {
			return false
		}
		if _, ambiguous := current.(interface{ Unwrap() []error }); ambiguous {
			return false
		}
		if reflect.TypeOf(current).Comparable() && current == target {
			return true
		}
		current = errors.Unwrap(current)
	}
	return false
}

func nilRotationDependency(value any) bool {
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

func cloneOneTimeDestinationToken(token OneTimeDestinationToken) OneTimeDestinationToken {
	if token.encoded == "" {
		return OneTimeDestinationToken{}
	}
	return OneTimeDestinationToken{encoded: string([]byte(token.encoded))}
}

func rotationReconciliationAttempt(
	request DestinationTokenRotationRequest,
	newActiveRecordID DestinationTokenRecordID,
	oldRetiringRecordID DestinationTokenRecordID,
) DestinationTokenRotationAttempt {
	return DestinationTokenRotationAttempt{handle: DestinationTokenRotationHandle{
		audienceID: request.audienceID, destination: request.destination,
		newActiveRecordID: newActiveRecordID, oldRetiringRecordID: oldRetiringRecordID,
	}}
}
