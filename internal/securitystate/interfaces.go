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
