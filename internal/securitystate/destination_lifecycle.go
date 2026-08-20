package securitystate

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"reflect"
	"sync"
	"time"
)

const (
	MaximumDestinationTokenLifetime = 90 * 24 * time.Hour
	MaximumStagedCleanupDuration    = 24 * time.Hour
	MaximumRetiringOverlapDuration  = 24 * time.Hour
)

type RotationCompletionReason uint8

const (
	RotationVerifiedAndDrained RotationCompletionReason = iota + 1
	RotationDeadlineElapsed
)

func (reason RotationCompletionReason) Valid() bool {
	return reason == RotationVerifiedAndDrained || reason == RotationDeadlineElapsed
}

type DestinationLifecycleStatus uint8

const (
	LifecycleUnprovisioned DestinationLifecycleStatus = iota + 1
	LifecycleStagedInitial
	LifecycleActive
	LifecycleActiveWithStaged
	LifecycleActiveWithRetiring
	LifecycleReconciliationRequired
)

type LifecycleTokenView struct {
	recordID              DestinationTokenRecordID
	state                 DestinationTokenState
	createdAt             time.Time
	expiresAt             time.Time
	stagedCleanupDeadline time.Time
	activatedAt           time.Time
	retirementStartedAt   time.Time
	retirementDeadline    time.Time
	revokedAt             time.Time
	stateChangedAt        time.Time
}

func (value LifecycleTokenView) RecordID() DestinationTokenRecordID { return value.recordID }
func (value LifecycleTokenView) State() DestinationTokenState       { return value.state }
func (value LifecycleTokenView) CreatedAt() time.Time               { return value.createdAt }
func (value LifecycleTokenView) ExpiresAt() time.Time               { return value.expiresAt }
func (value LifecycleTokenView) StagedCleanupDeadline() time.Time   { return value.stagedCleanupDeadline }
func (value LifecycleTokenView) ActivatedAt() time.Time             { return value.activatedAt }
func (value LifecycleTokenView) RetirementStartedAt() time.Time     { return value.retirementStartedAt }
func (value LifecycleTokenView) RetirementDeadline() time.Time      { return value.retirementDeadline }
func (value LifecycleTokenView) RevokedAt() time.Time               { return value.revokedAt }
func (value LifecycleTokenView) StateChangedAt() time.Time          { return value.stateChangedAt }
func (LifecycleTokenView) Format(state fmt.State, verb rune)        { writeRedacted(state) }

type DestinationLifecycleSnapshot struct {
	audienceID                        GatewayAudienceID
	destinationID                     DestinationID
	destinationEnabled                bool
	status                            DestinationLifecycleStatus
	staged                            LifecycleTokenView
	active                            LifecycleTokenView
	retiring                          LifecycleTokenView
	hasStaged, hasActive, hasRetiring bool
}

func (value DestinationLifecycleSnapshot) Status() DestinationLifecycleStatus { return value.status }
func (value DestinationLifecycleSnapshot) AudienceID() GatewayAudienceID      { return value.audienceID }
func (value DestinationLifecycleSnapshot) DestinationID() DestinationID       { return value.destinationID }
func (value DestinationLifecycleSnapshot) DestinationEnabled() bool           { return value.destinationEnabled }
func (value DestinationLifecycleSnapshot) Staged() (LifecycleTokenView, bool) {
	return value.staged, value.hasStaged
}
func (value DestinationLifecycleSnapshot) Active() (LifecycleTokenView, bool) {
	return value.active, value.hasActive
}
func (value DestinationLifecycleSnapshot) Retiring() (LifecycleTokenView, bool) {
	return value.retiring, value.hasRetiring
}
func (DestinationLifecycleSnapshot) Format(state fmt.State, verb rune) { writeRedacted(state) }

// NewDestinationLifecycleSnapshot validates and classifies the complete set of
// database rows whose state is staged, active, or retiring. Callers must never
// filter expired or overdue rows before invoking it.
func NewDestinationLifecycleSnapshot(
	destination Destination,
	tokens []DestinationToken,
	now time.Time,
) (DestinationLifecycleSnapshot, error) {
	if destination.id.IsZero() || destination.audienceID.IsZero() || now.IsZero() || len(tokens) > 3 {
		return DestinationLifecycleSnapshot{}, ErrDestinationLifecycleReconciliation
	}

	result := DestinationLifecycleSnapshot{
		audienceID:         destination.audienceID,
		destinationID:      destination.id,
		destinationEnabled: destination.Enabled(),
	}
	// A disabled destination is not provisionable, even when it has no token
	// rows. Inspection must not collapse that state into the enabled-empty
	// LifecycleUnprovisioned state that permits staged-token creation.
	stale := !destination.Enabled()
	seen := make(map[DestinationTokenRecordID]struct{}, len(tokens))
	for _, token := range tokens {
		if token.spec.AudienceID != destination.audienceID || token.spec.Destination.id != destination.id ||
			token.spec.Destination != destination {
			return DestinationLifecycleSnapshot{}, ErrDestinationLifecycleReconciliation
		}
		if _, duplicate := seen[token.spec.RecordID]; duplicate {
			return DestinationLifecycleSnapshot{}, ErrDestinationLifecycleReconciliation
		}
		seen[token.spec.RecordID] = struct{}{}
		view := lifecycleTokenView(token)
		stale = stale || token.spec.CreatedAt.After(now) || token.spec.StateChangedAt.After(now)
		switch token.spec.State {
		case DestinationTokenStaged:
			if result.hasStaged {
				return DestinationLifecycleSnapshot{}, ErrDestinationLifecycleReconciliation
			}
			result.staged, result.hasStaged = view, true
			stale = stale || !now.Before(token.spec.ExpiresAt) || !now.Before(token.spec.StagedCleanupDeadline)
		case DestinationTokenActive:
			if result.hasActive {
				return DestinationLifecycleSnapshot{}, ErrDestinationLifecycleReconciliation
			}
			result.active, result.hasActive = view, true
			stale = stale || !token.UsableAt(now)
		case DestinationTokenRetiring:
			if result.hasRetiring {
				return DestinationLifecycleSnapshot{}, ErrDestinationLifecycleReconciliation
			}
			result.retiring, result.hasRetiring = view, true
			stale = stale || !token.UsableAt(now)
		default:
			return DestinationLifecycleSnapshot{}, ErrDestinationLifecycleReconciliation
		}
	}

	if result.hasStaged && result.hasRetiring || result.hasRetiring && !result.hasActive {
		return DestinationLifecycleSnapshot{}, ErrDestinationLifecycleReconciliation
	}
	if result.hasActive && result.hasRetiring &&
		(!result.active.activatedAt.Equal(result.retiring.retirementStartedAt) ||
			!result.active.stateChangedAt.Equal(result.active.activatedAt) ||
			!result.retiring.stateChangedAt.Equal(result.retiring.retirementStartedAt)) {
		return DestinationLifecycleSnapshot{}, ErrDestinationLifecycleReconciliation
	}
	if stale {
		result.status = LifecycleReconciliationRequired
		return result, nil
	}
	switch {
	case !result.hasStaged && !result.hasActive && !result.hasRetiring:
		result.status = LifecycleUnprovisioned
	case result.hasStaged && !result.hasActive:
		result.status = LifecycleStagedInitial
	case result.hasActive && !result.hasStaged && !result.hasRetiring:
		result.status = LifecycleActive
	case result.hasActive && result.hasStaged && !result.hasRetiring:
		result.status = LifecycleActiveWithStaged
	case result.hasActive && result.hasRetiring && !result.hasStaged:
		result.status = LifecycleActiveWithRetiring
	default:
		return DestinationLifecycleSnapshot{}, ErrDestinationLifecycleReconciliation
	}
	return result, nil
}

func lifecycleTokenView(token DestinationToken) LifecycleTokenView {
	return LifecycleTokenView{
		recordID: token.spec.RecordID, state: token.spec.State,
		createdAt: token.spec.CreatedAt, expiresAt: token.spec.ExpiresAt,
		stagedCleanupDeadline: token.spec.StagedCleanupDeadline,
		activatedAt:           token.spec.ActivatedAt, retirementStartedAt: token.spec.RetirementStartedAt,
		retirementDeadline: token.spec.RetirementDeadline, revokedAt: token.spec.RevokedAt,
		stateChangedAt: token.spec.StateChangedAt,
	}
}

// DestinationTokenRotationAttemptSnapshot contains only bounded lifecycle
// metadata. The verifier, verifier key and raw token are deliberately absent.
type DestinationTokenRotationAttemptSnapshot struct {
	lifecycle DestinationLifecycleSnapshot
	newToken  LifecycleTokenView
	oldToken  LifecycleTokenView
}

func NewDestinationTokenRotationAttemptSnapshot(
	lifecycle DestinationLifecycleSnapshot,
	newToken DestinationToken,
	oldToken DestinationToken,
	newActiveRecordID DestinationTokenRecordID,
	oldRetiringRecordID DestinationTokenRecordID,
	now time.Time,
) (DestinationTokenRotationAttemptSnapshot, error) {
	if lifecycle.audienceID.IsZero() || lifecycle.destinationID.IsZero() || now.IsZero() ||
		newActiveRecordID.IsZero() || oldRetiringRecordID.IsZero() ||
		newActiveRecordID == oldRetiringRecordID ||
		newToken.spec.RecordID != newActiveRecordID || oldToken.spec.RecordID != oldRetiringRecordID ||
		newToken.spec.AudienceID != lifecycle.audienceID || oldToken.spec.AudienceID != lifecycle.audienceID ||
		newToken.spec.Destination.id != lifecycle.destinationID || oldToken.spec.Destination.id != lifecycle.destinationID ||
		newToken.spec.CreatedAt.After(now) || oldToken.spec.CreatedAt.After(now) ||
		newToken.spec.StateChangedAt.After(now) || oldToken.spec.StateChangedAt.After(now) ||
		(!newToken.spec.RevokedAt.IsZero() && newToken.spec.RevokedAt.After(now)) ||
		(!oldToken.spec.RevokedAt.IsZero() && oldToken.spec.RevokedAt.After(now)) {
		return DestinationTokenRotationAttemptSnapshot{}, ErrDestinationLifecycleReconciliation
	}
	return DestinationTokenRotationAttemptSnapshot{
		lifecycle: lifecycle,
		newToken:  lifecycleTokenView(newToken),
		oldToken:  lifecycleTokenView(oldToken),
	}, nil
}

func (value DestinationTokenRotationAttemptSnapshot) Lifecycle() DestinationLifecycleSnapshot {
	return value.lifecycle
}
func (value DestinationTokenRotationAttemptSnapshot) NewToken() LifecycleTokenView {
	return value.newToken
}
func (value DestinationTokenRotationAttemptSnapshot) OldToken() LifecycleTokenView {
	return value.oldToken
}
func (DestinationTokenRotationAttemptSnapshot) Format(state fmt.State, verb rune) {
	writeRedacted(state)
}

type StagedTokenCandidate struct {
	audienceID                                  GatewayAudienceID
	destination                                 DestinationID
	recordID                                    DestinationTokenRecordID
	verifier                                    TokenVerifier
	verifierKeyID                               DestinationVerifierKeyID
	createdAt, expiresAt, stagedCleanupDeadline time.Time
}

func NewStagedTokenCandidate(
	audience GatewayAudienceID,
	destination DestinationID,
	recordID DestinationTokenRecordID,
	verifier TokenVerifier,
	keyID DestinationVerifierKeyID,
	createdAt, expiresAt, cleanupDeadline time.Time,
) (StagedTokenCandidate, error) {
	if audience.IsZero() || destination.IsZero() || recordID.IsZero() || verifier.IsZero() || keyID.IsZero() ||
		createdAt.IsZero() || !expiresAt.After(createdAt) || expiresAt.Sub(createdAt) > MaximumDestinationTokenLifetime ||
		!cleanupDeadline.After(createdAt) || cleanupDeadline.Sub(createdAt) > MaximumStagedCleanupDuration {
		return StagedTokenCandidate{}, ErrDestinationLifecycleInvalid
	}
	return StagedTokenCandidate{audienceID: audience, destination: destination, recordID: recordID,
		verifier: verifier, verifierKeyID: keyID, createdAt: createdAt, expiresAt: expiresAt,
		stagedCleanupDeadline: cleanupDeadline}, nil
}

func (value StagedTokenCandidate) AudienceID() GatewayAudienceID      { return value.audienceID }
func (value StagedTokenCandidate) DestinationID() DestinationID       { return value.destination }
func (value StagedTokenCandidate) RecordID() DestinationTokenRecordID { return value.recordID }
func (value StagedTokenCandidate) Verifier() TokenVerifier            { return value.verifier }
func (value StagedTokenCandidate) VerifierKeyID() DestinationVerifierKeyID {
	return value.verifierKeyID
}
func (value StagedTokenCandidate) CreatedAt() time.Time { return value.createdAt }
func (value StagedTokenCandidate) ExpiresAt() time.Time { return value.expiresAt }
func (value StagedTokenCandidate) StagedCleanupDeadline() time.Time {
	return value.stagedCleanupDeadline
}
func (StagedTokenCandidate) Format(state fmt.State, verb rune) { writeRedacted(state) }

// CreateRotationStagedTokenCommand binds creation of a rotation candidate to
// the exact active record observed by the participant. It deliberately carries
// neither the current nor generated raw token.
type CreateRotationStagedTokenCommand struct {
	candidate              StagedTokenCandidate
	expectedActiveRecordID DestinationTokenRecordID
	now                    time.Time
}

func NewCreateRotationStagedTokenCommand(
	candidate StagedTokenCandidate,
	expectedActiveRecordID DestinationTokenRecordID,
	now time.Time,
) (CreateRotationStagedTokenCommand, error) {
	validated, err := NewStagedTokenCandidate(
		candidate.AudienceID(),
		candidate.DestinationID(),
		candidate.RecordID(),
		candidate.Verifier(),
		candidate.VerifierKeyID(),
		candidate.CreatedAt(),
		candidate.ExpiresAt(),
		candidate.StagedCleanupDeadline(),
	)
	if err != nil || validated.RecordID() != candidate.RecordID() ||
		expectedActiveRecordID.IsZero() || expectedActiveRecordID == candidate.RecordID() ||
		now.IsZero() || !candidate.CreatedAt().Equal(now) {
		return CreateRotationStagedTokenCommand{}, ErrDestinationLifecycleInvalid
	}
	return CreateRotationStagedTokenCommand{
		candidate:              validated,
		expectedActiveRecordID: expectedActiveRecordID,
		now:                    now,
	}, nil
}

func (value CreateRotationStagedTokenCommand) Candidate() StagedTokenCandidate {
	return value.candidate
}
func (value CreateRotationStagedTokenCommand) ExpectedActiveRecordID() DestinationTokenRecordID {
	return value.expectedActiveRecordID
}
func (value CreateRotationStagedTokenCommand) Now() time.Time { return value.now }
func (CreateRotationStagedTokenCommand) Format(state fmt.State, verb rune) {
	writeRedacted(state)
}

type ActivateRotationCommand struct {
	AudienceID        GatewayAudienceID
	DestinationID     DestinationID
	StagedRecordID    DestinationTokenRecordID
	OldActiveRecordID DestinationTokenRecordID
	Now               time.Time
	OverlapDeadline   time.Time
}

// DestinationTokenRotationActivationReceipt is returned only after the
// repository has confirmed the exact rotation activation. Its immutable
// activation time and retirement deadline are the same values supplied to the
// committed repository command.
type DestinationTokenRotationActivationReceipt struct {
	activatedAt        time.Time
	retirementDeadline time.Time
}

func NewDestinationTokenRotationActivationReceipt(
	activatedAt time.Time,
	retirementDeadline time.Time,
) (DestinationTokenRotationActivationReceipt, error) {
	receipt := DestinationTokenRotationActivationReceipt{
		activatedAt: activatedAt, retirementDeadline: retirementDeadline,
	}
	if !receipt.valid() {
		return DestinationTokenRotationActivationReceipt{}, ErrDestinationLifecycleInvalid
	}
	return receipt, nil
}

func (value DestinationTokenRotationActivationReceipt) RetirementDeadline() time.Time {
	return value.retirementDeadline
}

func (value DestinationTokenRotationActivationReceipt) ActivatedAt() time.Time {
	return value.activatedAt
}

func (value DestinationTokenRotationActivationReceipt) valid() bool {
	return !value.activatedAt.IsZero() &&
		value.activatedAt.Equal(canonicalDestinationLifecycleTimestamp(value.activatedAt)) &&
		value.retirementDeadline.Equal(canonicalDestinationLifecycleTimestamp(value.retirementDeadline)) &&
		value.retirementDeadline.After(value.activatedAt) &&
		value.retirementDeadline.Sub(value.activatedAt) <= MaximumRetiringOverlapDuration
}

func (value DestinationTokenRotationActivationReceipt) validAt(now time.Time) bool {
	return value.valid() && !now.IsZero() && !now.Before(value.activatedAt) &&
		now.Before(value.retirementDeadline)
}

func (DestinationTokenRotationActivationReceipt) Format(state fmt.State, verb rune) {
	writeRedacted(state)
}

type RollbackRotationCommand struct {
	AudienceID          GatewayAudienceID
	DestinationID       DestinationID
	NewActiveRecordID   DestinationTokenRecordID
	OldRetiringRecordID DestinationTokenRecordID
	Now                 time.Time
}

type FinalizeRotationCommand struct {
	AudienceID          GatewayAudienceID
	DestinationID       DestinationID
	NewActiveRecordID   DestinationTokenRecordID
	OldRetiringRecordID DestinationTokenRecordID
	Reason              RotationCompletionReason
	Now                 time.Time
}

func (ActivateRotationCommand) Format(state fmt.State, verb rune) { writeRedacted(state) }
func (RollbackRotationCommand) Format(state fmt.State, verb rune) { writeRedacted(state) }
func (FinalizeRotationCommand) Format(state fmt.State, verb rune) { writeRedacted(state) }

type OneTimeDestinationToken struct{ encoded string }

func (value OneTimeDestinationToken) Value() string               { return value.encoded }
func (value OneTimeDestinationToken) IsZero() bool                { return value.encoded == "" }
func (OneTimeDestinationToken) Format(state fmt.State, verb rune) { writeRedacted(state) }

type CreatedStagedToken struct {
	recordID DestinationTokenRecordID
	token    OneTimeDestinationToken
}

func (value CreatedStagedToken) RecordID() DestinationTokenRecordID { return value.recordID }
func (value CreatedStagedToken) Token() OneTimeDestinationToken     { return value.token }
func (CreatedStagedToken) Format(state fmt.State, verb rune)        { writeRedacted(state) }

type DestinationLifecycleClock interface{ Now() time.Time }

type DestinationLifecycleClockFunc func() time.Time

func (clock DestinationLifecycleClockFunc) Now() time.Time { return clock() }

type UUIDv4DestinationTokenRecordIDGenerator struct {
	reader io.Reader
	mu     sync.Mutex
}

func NewUUIDv4DestinationTokenRecordIDGenerator(reader io.Reader) *UUIDv4DestinationTokenRecordIDGenerator {
	return &UUIDv4DestinationTokenRecordIDGenerator{reader: reader}
}

func (generator *UUIDv4DestinationTokenRecordIDGenerator) NewDestinationTokenRecordID(context.Context) (DestinationTokenRecordID, error) {
	if generator == nil {
		return DestinationTokenRecordID{}, ErrDestinationLifecycleInvalid
	}
	generator.mu.Lock()
	defer generator.mu.Unlock()
	reader := generator.reader
	if reader == nil {
		reader = rand.Reader
	}
	var value [16]byte
	if _, err := io.ReadFull(reader, value[:]); err != nil {
		return DestinationTokenRecordID{}, ErrDestinationLifecycleUnavailable
	}
	value[6] = value[6]&0x0f | 0x40
	value[8] = value[8]&0x3f | 0x80
	if value == [16]byte{} {
		return DestinationTokenRecordID{}, ErrDestinationLifecycleUnavailable
	}
	return DestinationTokenRecordID(value), nil
}

type DestinationTokenLifecycleConfig struct {
	Clock                 DestinationLifecycleClock
	Random                io.Reader
	RecordIDs             DestinationTokenRecordIDGenerator
	Repository            DestinationTokenLifecycleRepository
	VerifierKeys          DestinationVerifierKeySource
	ActiveVerifierKeyID   DestinationVerifierKeyID
	TokenLifetime         time.Duration
	StagedCleanupDuration time.Duration
	RetiringOverlap       time.Duration
}

func (DestinationTokenLifecycleConfig) Format(state fmt.State, verb rune) { writeRedacted(state) }

type DestinationTokenLifecycleService struct {
	clock                                           DestinationLifecycleClock
	random                                          io.Reader
	recordIDs                                       DestinationTokenRecordIDGenerator
	repository                                      DestinationTokenLifecycleRepository
	keys                                            DestinationVerifierKeySource
	activeKeyID                                     DestinationVerifierKeyID
	tokenLifetime, cleanupDuration, overlapDuration time.Duration
	generationMu                                    sync.Mutex
}

var _ DestinationTokenLifecycle = (*DestinationTokenLifecycleService)(nil)

func (*DestinationTokenLifecycleService) Format(state fmt.State, verb rune) { writeRedacted(state) }

func NewDestinationTokenLifecycleService(config DestinationTokenLifecycleConfig) (*DestinationTokenLifecycleService, error) {
	if nilLifecycleDependency(config.Clock) || nilLifecycleDependency(config.Random) ||
		nilLifecycleDependency(config.RecordIDs) || nilLifecycleDependency(config.Repository) ||
		nilLifecycleDependency(config.VerifierKeys) || config.ActiveVerifierKeyID.IsZero() ||
		config.TokenLifetime <= 0 || config.TokenLifetime > MaximumDestinationTokenLifetime ||
		config.StagedCleanupDuration <= 0 || config.StagedCleanupDuration > MaximumStagedCleanupDuration ||
		config.RetiringOverlap <= 0 || config.RetiringOverlap > MaximumRetiringOverlapDuration ||
		config.TokenLifetime <= config.RetiringOverlap {
		return nil, ErrDestinationLifecycleInvalid
	}
	parsedKeyID, err := NewDestinationVerifierKeyID(config.ActiveVerifierKeyID.Value())
	if err != nil || parsedKeyID != config.ActiveVerifierKeyID {
		return nil, ErrDestinationLifecycleInvalid
	}
	return &DestinationTokenLifecycleService{
		clock: config.Clock, random: config.Random, recordIDs: config.RecordIDs,
		repository: config.Repository, keys: config.VerifierKeys, activeKeyID: parsedKeyID,
		tokenLifetime: config.TokenLifetime, cleanupDuration: config.StagedCleanupDuration,
		overlapDuration: config.RetiringOverlap,
	}, nil
}

func (service *DestinationTokenLifecycleService) CreateStagedToken(ctx context.Context, audience GatewayAudienceID, destination DestinationID) (CreatedStagedToken, error) {
	return service.createStagedToken(ctx, audience, destination, DestinationTokenRecordID{}, OpaqueDestinationToken{}, false)
}

// CreateRotationStagedToken creates a candidate only while the exact active
// record observed by the participant remains authoritative. The current raw
// token is compared in constant time before any repository call and is never
// passed to persistence.
func (service *DestinationTokenLifecycleService) CreateRotationStagedToken(
	ctx context.Context,
	audience GatewayAudienceID,
	destination DestinationID,
	expectedActiveRecordID DestinationTokenRecordID,
	currentToken OpaqueDestinationToken,
) (CreatedStagedToken, error) {
	if expectedActiveRecordID.IsZero() {
		return CreatedStagedToken{}, ErrDestinationLifecycleInvalid
	}
	return service.createStagedToken(ctx, audience, destination, expectedActiveRecordID, currentToken, true)
}

func (service *DestinationTokenLifecycleService) createStagedToken(
	ctx context.Context,
	audience GatewayAudienceID,
	destination DestinationID,
	expectedActiveRecordID DestinationTokenRecordID,
	currentToken OpaqueDestinationToken,
	rotation bool,
) (CreatedStagedToken, error) {
	now, err := service.operationInput(ctx, audience, destination)
	if err != nil {
		return CreatedStagedToken{}, err
	}

	service.generationMu.Lock()
	recordID, recordErr := service.recordIDs.NewDestinationTokenRecordID(ctx)
	var entropy [32]byte
	if recordErr == nil && !recordID.IsZero() {
		_, recordErr = io.ReadFull(service.random, entropy[:])
	}
	service.generationMu.Unlock()
	if cancellation := lifecycleCancellation(ctx, recordErr); cancellation != nil {
		return CreatedStagedToken{}, cancellation
	}
	if recordErr != nil || recordID.IsZero() {
		return CreatedStagedToken{}, ErrDestinationLifecycleUnavailable
	}

	encoded := opaqueTokenPrefix + base64.RawURLEncoding.EncodeToString(entropy[:])
	rawToken, err := ParseOpaqueDestinationToken(encoded)
	if err != nil {
		return CreatedStagedToken{}, ErrDestinationLifecycleUnavailable
	}
	if rotation {
		generatedBytes := rawToken.Bytes()
		currentBytes := currentToken.Bytes()
		if subtle.ConstantTimeCompare(generatedBytes[:], currentBytes[:]) == 1 {
			return CreatedStagedToken{}, ErrDestinationLifecycleConflict
		}
	}
	key, keyErr := service.keys.DestinationVerifierKey(ctx, audience, service.activeKeyID)
	if cancellation := lifecycleCancellation(ctx, keyErr); cancellation != nil {
		return CreatedStagedToken{}, cancellation
	}
	if keyErr != nil {
		return CreatedStagedToken{}, ErrDestinationLifecycleUnavailable
	}
	verifier, verifierErr := ComputeDestinationTokenVerifier(audience, rawToken, key)
	if verifierErr != nil {
		return CreatedStagedToken{}, ErrDestinationLifecycleUnavailable
	}
	candidate, candidateErr := NewStagedTokenCandidate(audience, destination, recordID, verifier, service.activeKeyID,
		now, now.Add(service.tokenLifetime), now.Add(service.cleanupDuration))
	if candidateErr != nil {
		return CreatedStagedToken{}, ErrDestinationLifecycleInvalid
	}
	var repositoryErr error
	if rotation {
		command, commandErr := NewCreateRotationStagedTokenCommand(candidate, expectedActiveRecordID, now)
		if commandErr != nil {
			return CreatedStagedToken{}, ErrDestinationLifecycleInvalid
		}
		repositoryErr = service.repository.CreateRotationStagedToken(ctx, command)
	} else {
		repositoryErr = service.repository.CreateStagedToken(ctx, candidate, now)
	}
	if repositoryErr != nil {
		classified := classifyDestinationLifecycleError(ctx, repositoryErr)
		if classified == ErrDestinationLifecycleOutcomeUnknown {
			// The generated record identity is safe to retain for exact
			// reconciliation, but the one-time token must never escape when the
			// insert acknowledgement is ambiguous.
			return CreatedStagedToken{recordID: recordID}, classified
		}
		return CreatedStagedToken{}, classified
	}
	return CreatedStagedToken{recordID: recordID, token: OneTimeDestinationToken{encoded: encoded}}, nil
}

func (service *DestinationTokenLifecycleService) ActivateInitialToken(ctx context.Context, audience GatewayAudienceID, destination DestinationID, staged DestinationTokenRecordID) error {
	now, err := service.recordOperationInput(ctx, audience, destination, staged)
	if err != nil {
		return err
	}
	return classifyDestinationLifecycleError(ctx, service.repository.ActivateInitialToken(ctx, audience, destination, staged, now))
}

func (service *DestinationTokenLifecycleService) ActivateRotation(
	ctx context.Context,
	audience GatewayAudienceID,
	destination DestinationID,
	staged DestinationTokenRecordID,
	oldActive DestinationTokenRecordID,
) (DestinationTokenRotationActivationReceipt, error) {
	now, err := service.pairOperationInput(ctx, audience, destination, staged, oldActive)
	if err != nil {
		return DestinationTokenRotationActivationReceipt{}, err
	}
	// pgx encodes PostgreSQL timestamps at microsecond precision. Canonicalize
	// both values from the same raw clock snapshot before either the repository
	// command or its receipt is constructed.
	activatedAt := canonicalDestinationLifecycleTimestamp(now)
	retirementDeadline := canonicalDestinationLifecycleTimestamp(now.Add(service.overlapDuration))
	receipt, err := NewDestinationTokenRotationActivationReceipt(activatedAt, retirementDeadline)
	if err != nil {
		return DestinationTokenRotationActivationReceipt{}, ErrDestinationLifecycleInvalid
	}
	err = classifyDestinationLifecycleError(ctx, service.repository.ActivateRotation(ctx, ActivateRotationCommand{
		AudienceID: audience, DestinationID: destination, StagedRecordID: staged,
		OldActiveRecordID: oldActive, Now: activatedAt, OverlapDeadline: retirementDeadline,
	}))
	if err != nil {
		return DestinationTokenRotationActivationReceipt{}, err
	}
	return receipt, nil
}

func canonicalDestinationLifecycleTimestamp(value time.Time) time.Time {
	return value.Truncate(time.Microsecond)
}

func (service *DestinationTokenLifecycleService) AbortStagedToken(ctx context.Context, audience GatewayAudienceID, destination DestinationID, staged DestinationTokenRecordID) error {
	now, err := service.recordOperationInput(ctx, audience, destination, staged)
	if err != nil {
		return err
	}
	return classifyDestinationLifecycleError(ctx, service.repository.AbortStagedToken(ctx, audience, destination, staged, now))
}

func (service *DestinationTokenLifecycleService) RollbackRotation(ctx context.Context, audience GatewayAudienceID, destination DestinationID, newActive, oldRetiring DestinationTokenRecordID) error {
	now, err := service.pairOperationInput(ctx, audience, destination, newActive, oldRetiring)
	if err != nil {
		return err
	}
	return classifyDestinationLifecycleError(ctx, service.repository.RollbackRotation(ctx, RollbackRotationCommand{
		AudienceID: audience, DestinationID: destination, NewActiveRecordID: newActive,
		OldRetiringRecordID: oldRetiring, Now: now,
	}))
}

func (service *DestinationTokenLifecycleService) FinalizeRotation(ctx context.Context, audience GatewayAudienceID, destination DestinationID, newActive, oldRetiring DestinationTokenRecordID, reason RotationCompletionReason) error {
	now, err := service.pairOperationInput(ctx, audience, destination, newActive, oldRetiring)
	if err != nil || !reason.Valid() {
		if err != nil {
			return err
		}
		return ErrDestinationLifecycleInvalid
	}
	return classifyDestinationLifecycleError(ctx, service.repository.FinalizeRotation(ctx, FinalizeRotationCommand{
		AudienceID: audience, DestinationID: destination, NewActiveRecordID: newActive,
		OldRetiringRecordID: oldRetiring, Reason: reason, Now: now,
	}))
}

func (service *DestinationTokenLifecycleService) InspectLifecycleState(ctx context.Context, audience GatewayAudienceID, destination DestinationID) (DestinationLifecycleSnapshot, error) {
	now, err := service.operationInput(ctx, audience, destination)
	if err != nil {
		return DestinationLifecycleSnapshot{}, err
	}
	snapshot, repositoryErr := service.repository.InspectLifecycleState(ctx, audience, destination, now)
	if repositoryErr != nil {
		return DestinationLifecycleSnapshot{}, classifyDestinationLifecycleInspectionError(repositoryErr)
	}
	if snapshot.status == 0 || snapshot.audienceID != audience || snapshot.destinationID != destination {
		return DestinationLifecycleSnapshot{}, ErrDestinationLifecycleReconciliation
	}
	return snapshot, nil
}

func (service *DestinationTokenLifecycleService) operationInput(ctx context.Context, audience GatewayAudienceID, destination DestinationID) (time.Time, error) {
	if service == nil || nilLifecycleDependency(ctx) || nilLifecycleDependency(service.clock) || nilLifecycleDependency(service.repository) ||
		audience.IsZero() || destination.IsZero() {
		return time.Time{}, ErrDestinationLifecycleInvalid
	}
	if cancellation := lifecycleCancellation(ctx, nil); cancellation != nil {
		return time.Time{}, cancellation
	}
	now := service.clock.Now()
	if now.IsZero() {
		return time.Time{}, ErrDestinationLifecycleInvalid
	}
	return now, nil
}

func (service *DestinationTokenLifecycleService) recordOperationInput(ctx context.Context, audience GatewayAudienceID, destination DestinationID, record DestinationTokenRecordID) (time.Time, error) {
	now, err := service.operationInput(ctx, audience, destination)
	if err != nil {
		return time.Time{}, err
	}
	if record.IsZero() {
		return time.Time{}, ErrDestinationLifecycleInvalid
	}
	return now, nil
}

func (service *DestinationTokenLifecycleService) pairOperationInput(ctx context.Context, audience GatewayAudienceID, destination DestinationID, first, second DestinationTokenRecordID) (time.Time, error) {
	now, err := service.recordOperationInput(ctx, audience, destination, first)
	if err != nil {
		return time.Time{}, err
	}
	if second.IsZero() || first == second {
		return time.Time{}, ErrDestinationLifecycleInvalid
	}
	return now, nil
}

func classifyDestinationLifecycleError(_ context.Context, err error) error {
	if err == nil {
		return nil
	}
	// A possibly committed mutation is more specific than cancellation. The
	// caller must reconcile it and must never replay merely because its context
	// also expired while PostgreSQL's acknowledgement was lost.
	if lifecycleSingleCauseMatches(err, ErrDestinationLifecycleOutcomeUnknown) {
		return ErrDestinationLifecycleOutcomeUnknown
	}
	if lifecycleSingleCauseMatches(err, context.Canceled) {
		return ErrDestinationLifecycleCanceled
	}
	if lifecycleSingleCauseMatches(err, context.DeadlineExceeded) {
		return ErrDestinationLifecycleDeadline
	}
	if lifecycleSingleCauseMatches(err, ErrDestinationLifecycleCanceled) {
		return ErrDestinationLifecycleCanceled
	}
	if lifecycleSingleCauseMatches(err, ErrDestinationLifecycleDeadline) {
		return ErrDestinationLifecycleDeadline
	}
	for _, safe := range []error{ErrDestinationLifecycleInvalid, ErrDestinationLifecycleConflict,
		ErrDestinationLifecycleReconciliation, ErrDestinationLifecycleUnavailable,
	} {
		if lifecycleSingleCauseMatches(err, safe) {
			return safe
		}
	}
	return ErrDestinationLifecycleOutcomeUnknown
}

func classifyDestinationLifecycleInspectionError(err error) error {
	if err == nil {
		return nil
	}
	for _, safe := range []error{
		ErrDestinationLifecycleCanceled,
		ErrDestinationLifecycleDeadline,
		ErrDestinationLifecycleInvalid,
		ErrDestinationLifecycleConflict,
		ErrDestinationLifecycleReconciliation,
		ErrDestinationLifecycleUnavailable,
	} {
		if lifecycleSingleCauseMatches(err, safe) {
			return safe
		}
	}
	if lifecycleSingleCauseMatches(err, context.Canceled) {
		return ErrDestinationLifecycleCanceled
	}
	if lifecycleSingleCauseMatches(err, context.DeadlineExceeded) {
		return ErrDestinationLifecycleDeadline
	}
	return ErrDestinationLifecycleUnavailable
}

func lifecycleSingleCauseMatches(err, target error) bool {
	for current, depth := err, 0; current != nil && depth < 64; depth++ {
		if nilLifecycleDependency(current) {
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

func lifecycleCancellation(ctx context.Context, err error) error {
	if err != nil {
		if lifecycleSingleCauseMatches(err, context.Canceled) {
			return ErrDestinationLifecycleCanceled
		}
		if lifecycleSingleCauseMatches(err, context.DeadlineExceeded) {
			return ErrDestinationLifecycleDeadline
		}
		return nil
	}
	if !nilLifecycleDependency(ctx) && ctx.Err() == context.Canceled {
		return ErrDestinationLifecycleCanceled
	}
	if !nilLifecycleDependency(ctx) && ctx.Err() == context.DeadlineExceeded {
		return ErrDestinationLifecycleDeadline
	}
	return nil
}

func nilLifecycleDependency(value any) bool {
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
