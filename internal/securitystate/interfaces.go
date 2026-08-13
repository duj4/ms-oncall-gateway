package securitystate

import (
	"context"
	"time"
)

type AudienceBindingStore interface {
	BoundAudience(context.Context) (GatewayAudienceID, error)
}

type CredentialRegistry interface {
	Credential(context.Context, GatewayAudienceID, CredentialID) (Credential, error)
}

type AuthenticationSecretSource interface {
	AuthenticationSecret(context.Context, GatewayAudienceID, CredentialID) (AuthenticationSecret, error)
}

type PrincipalRegistry interface {
	Principal(context.Context, GatewayAudienceID, CorePrincipalID) (Principal, error)
}

type ReplayReservationDisposition uint8

const (
	ReplayReserved ReplayReservationDisposition = iota + 1
	ReplayDuplicate
)

type ReplayReservationStore interface {
	Reserve(context.Context, CredentialRecordID, ReplayNonce, time.Time) (ReplayReservationDisposition, error)
}

type DestinationResolver interface {
	Resolve(context.Context, GatewayAudienceID, OpaqueDestinationToken, time.Time) (DestinationID, error)
}

type DestinationVerifierKeySource interface {
	DestinationVerifierKey(context.Context, GatewayAudienceID, DestinationVerifierKeyID) (DestinationVerifierKey, error)
}

type DestinationTokenRecordIDGenerator interface {
	NewDestinationTokenRecordID(context.Context) (DestinationTokenRecordID, error)
}

type DestinationTokenLifecycleRepository interface {
	CreateStagedToken(context.Context, StagedTokenCandidate, time.Time) error
	ActivateInitialToken(context.Context, GatewayAudienceID, DestinationID, DestinationTokenRecordID, time.Time) error
	ActivateRotation(context.Context, ActivateRotationCommand) error
	AbortStagedToken(context.Context, GatewayAudienceID, DestinationID, DestinationTokenRecordID, time.Time) error
	RollbackRotation(context.Context, RollbackRotationCommand) error
	FinalizeRotation(context.Context, FinalizeRotationCommand) error
	InspectLifecycleState(context.Context, GatewayAudienceID, DestinationID, time.Time) (DestinationLifecycleSnapshot, error)
}

type DestinationTokenLifecycle interface {
	CreateStagedToken(context.Context, GatewayAudienceID, DestinationID) (CreatedStagedToken, error)
	ActivateInitialToken(context.Context, GatewayAudienceID, DestinationID, DestinationTokenRecordID) error
	ActivateRotation(context.Context, GatewayAudienceID, DestinationID, DestinationTokenRecordID, DestinationTokenRecordID) error
	AbortStagedToken(context.Context, GatewayAudienceID, DestinationID, DestinationTokenRecordID) error
	RollbackRotation(context.Context, GatewayAudienceID, DestinationID, DestinationTokenRecordID, DestinationTokenRecordID) error
	FinalizeRotation(context.Context, GatewayAudienceID, DestinationID, DestinationTokenRecordID, DestinationTokenRecordID, RotationCompletionReason) error
	InspectLifecycleState(context.Context, GatewayAudienceID, DestinationID) (DestinationLifecycleSnapshot, error)
}
