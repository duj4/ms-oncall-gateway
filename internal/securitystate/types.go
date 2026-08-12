package securitystate

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	replayNonceEncodedLength = 22
	opaqueTokenPrefix        = "mso1_"
	opaqueTokenBodyLength    = 43
	keyIDMaxBytes            = 128
	credentialMaxLifetime    = 90 * 24 * time.Hour
	credentialMaxOverlap     = 24 * time.Hour
	tokenMaxLifetime         = 90 * 24 * time.Hour
	tokenMaxCleanup          = 24 * time.Hour
	tokenMaxOverlap          = 24 * time.Hour
)

type GatewayAudienceID [16]byte
type CorePrincipalID [16]byte
type CredentialSlotID [16]byte
type CredentialRecordID [16]byte
type CredentialID [16]byte
type DestinationID [16]byte
type DestinationTokenRecordID [16]byte

func ParseGatewayAudienceID(value string) (GatewayAudienceID, error) {
	parsed, err := parseUUID(value, false)
	return GatewayAudienceID(parsed), err
}

func ParseCorePrincipalID(value string) (CorePrincipalID, error) {
	parsed, err := parseUUID(value, false)
	return CorePrincipalID(parsed), err
}

func ParseCredentialSlotID(value string) (CredentialSlotID, error) {
	parsed, err := parseUUID(value, false)
	return CredentialSlotID(parsed), err
}

func ParseCredentialRecordID(value string) (CredentialRecordID, error) {
	parsed, err := parseUUID(value, false)
	return CredentialRecordID(parsed), err
}

func ParseCredentialID(value string) (CredentialID, error) {
	parsed, err := parseUUID(value, true)
	return CredentialID(parsed), err
}

func ParseDestinationID(value string) (DestinationID, error) {
	parsed, err := parseUUID(value, false)
	return DestinationID(parsed), err
}

func ParseDestinationTokenRecordID(value string) (DestinationTokenRecordID, error) {
	parsed, err := parseUUID(value, false)
	return DestinationTokenRecordID(parsed), err
}

func (value GatewayAudienceID) String() string        { return formatUUID(value) }
func (value CorePrincipalID) String() string          { return formatUUID(value) }
func (value CredentialSlotID) String() string         { return formatUUID(value) }
func (value CredentialRecordID) String() string       { return formatUUID(value) }
func (value CredentialID) String() string             { return formatUUID(value) }
func (value DestinationID) String() string            { return formatUUID(value) }
func (value DestinationTokenRecordID) String() string { return formatUUID(value) }

func (value GatewayAudienceID) Format(state fmt.State, verb rune)        { writeRedacted(state) }
func (value CorePrincipalID) Format(state fmt.State, verb rune)          { writeRedacted(state) }
func (value CredentialSlotID) Format(state fmt.State, verb rune)         { writeRedacted(state) }
func (value CredentialRecordID) Format(state fmt.State, verb rune)       { writeRedacted(state) }
func (value CredentialID) Format(state fmt.State, verb rune)             { writeRedacted(state) }
func (value DestinationID) Format(state fmt.State, verb rune)            { writeRedacted(state) }
func (value DestinationTokenRecordID) Format(state fmt.State, verb rune) { writeRedacted(state) }

func (value GatewayAudienceID) IsZero() bool        { return value == GatewayAudienceID{} }
func (value CorePrincipalID) IsZero() bool          { return value == CorePrincipalID{} }
func (value CredentialSlotID) IsZero() bool         { return value == CredentialSlotID{} }
func (value CredentialRecordID) IsZero() bool       { return value == CredentialRecordID{} }
func (value CredentialID) IsZero() bool             { return value == CredentialID{} }
func (value DestinationID) IsZero() bool            { return value == DestinationID{} }
func (value DestinationTokenRecordID) IsZero() bool { return value == DestinationTokenRecordID{} }

type ReplayNonce struct{ bytes [16]byte }

func ParseReplayNonce(value string) (ReplayNonce, error) {
	var nonce ReplayNonce
	if len(value) != replayNonceEncodedLength || strings.Contains(value, "=") {
		return nonce, ErrInvalidState
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) != len(nonce.bytes) || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return ReplayNonce{}, ErrInvalidState
	}
	copy(nonce.bytes[:], decoded)
	return nonce, nil
}

func (value ReplayNonce) Bytes() [16]byte                   { return value.bytes }
func (value ReplayNonce) Format(state fmt.State, verb rune) { writeRedacted(state) }

type OpaqueDestinationToken struct{ bytes [32]byte }

func ParseOpaqueDestinationToken(value string) (OpaqueDestinationToken, error) {
	var token OpaqueDestinationToken
	if len(value) != len(opaqueTokenPrefix)+opaqueTokenBodyLength || !strings.HasPrefix(value, opaqueTokenPrefix) {
		return token, ErrInvalidState
	}
	body := value[len(opaqueTokenPrefix):]
	decoded, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil || len(decoded) != len(token.bytes) || base64.RawURLEncoding.EncodeToString(decoded) != body {
		return OpaqueDestinationToken{}, ErrInvalidState
	}
	copy(token.bytes[:], decoded)
	return token, nil
}

func (value OpaqueDestinationToken) Bytes() [32]byte                   { return value.bytes }
func (value OpaqueDestinationToken) Format(state fmt.State, verb rune) { writeRedacted(state) }

type TokenVerifier struct {
	bytes   [32]byte
	present bool
}

func NewTokenVerifier(value []byte) (TokenVerifier, error) {
	var verifier TokenVerifier
	if len(value) != len(verifier.bytes) {
		return verifier, ErrInvalidState
	}
	copy(verifier.bytes[:], value)
	verifier.present = true
	return verifier, nil
}

func (value TokenVerifier) Bytes() [32]byte                   { return value.bytes }
func (value TokenVerifier) IsZero() bool                      { return !value.present }
func (value TokenVerifier) Format(state fmt.State, verb rune) { writeRedacted(state) }

type AuthenticationSecret struct{ bytes [32]byte }

func NewAuthenticationSecret(value []byte) (AuthenticationSecret, error) {
	var secret AuthenticationSecret
	if len(value) != len(secret.bytes) {
		return secret, ErrInvalidState
	}
	copy(secret.bytes[:], value)
	return secret, nil
}

func (value AuthenticationSecret) Bytes() [32]byte                   { return value.bytes }
func (value AuthenticationSecret) Format(state fmt.State, verb rune) { writeRedacted(state) }

type DestinationVerifierKey struct{ bytes []byte }

func NewDestinationVerifierKey(value []byte) (DestinationVerifierKey, error) {
	if len(value) < 32 {
		return DestinationVerifierKey{}, ErrInvalidState
	}
	return DestinationVerifierKey{bytes: append([]byte(nil), value...)}, nil
}

func (value DestinationVerifierKey) Bytes() []byte                     { return append([]byte(nil), value.bytes...) }
func (value DestinationVerifierKey) Format(state fmt.State, verb rune) { writeRedacted(state) }

type AuthenticationKeyID struct{ value string }
type DestinationVerifierKeyID struct{ value string }

func NewAuthenticationKeyID(value string) (AuthenticationKeyID, error) {
	if !validKeyID(value) {
		return AuthenticationKeyID{}, ErrInvalidState
	}
	return AuthenticationKeyID{value: value}, nil
}

func NewDestinationVerifierKeyID(value string) (DestinationVerifierKeyID, error) {
	if !validKeyID(value) {
		return DestinationVerifierKeyID{}, ErrInvalidState
	}
	return DestinationVerifierKeyID{value: value}, nil
}

func (value AuthenticationKeyID) Value() string                          { return value.value }
func (value DestinationVerifierKeyID) Value() string                     { return value.value }
func (value AuthenticationKeyID) IsZero() bool                           { return value.value == "" }
func (value DestinationVerifierKeyID) IsZero() bool                      { return value.value == "" }
func (value AuthenticationKeyID) Format(state fmt.State, verb rune)      { writeRedacted(state) }
func (value DestinationVerifierKeyID) Format(state fmt.State, verb rune) { writeRedacted(state) }

type Principal struct {
	audienceID       GatewayAudienceID
	id               CorePrincipalID
	enabled          bool
	intakeAuthorized bool
	createdAt        time.Time
	stateChangedAt   time.Time
}

func NewPrincipal(audienceID GatewayAudienceID, id CorePrincipalID, enabled, intakeAuthorized bool, createdAt, stateChangedAt time.Time) (Principal, error) {
	value := Principal{audienceID: audienceID, id: id, enabled: enabled, intakeAuthorized: intakeAuthorized, createdAt: createdAt, stateChangedAt: stateChangedAt}
	if audienceID.IsZero() || id.IsZero() || createdAt.IsZero() || stateChangedAt.Before(createdAt) {
		return Principal{}, ErrInvalidState
	}
	return value, nil
}

func (value Principal) AudienceID() GatewayAudienceID { return value.audienceID }
func (value Principal) ID() CorePrincipalID           { return value.id }
func (value Principal) Enabled() bool                 { return value.enabled }
func (value Principal) IntakeAuthorized() bool        { return value.intakeAuthorized }
func (value Principal) AuthorizesIntake(audienceID GatewayAudienceID) bool {
	return !audienceID.IsZero() && audienceID == value.audienceID && value.enabled && value.intakeAuthorized
}

type CredentialSlot struct {
	audienceID  GatewayAudienceID
	principalID CorePrincipalID
	id          CredentialSlotID
	createdAt   time.Time
}

func NewCredentialSlot(audienceID GatewayAudienceID, principal Principal, id CredentialSlotID, createdAt time.Time) (CredentialSlot, error) {
	if audienceID.IsZero() || principal.audienceID != audienceID || principal.id.IsZero() || id.IsZero() || createdAt.IsZero() {
		if !audienceID.IsZero() && !principal.audienceID.IsZero() && principal.audienceID != audienceID {
			return CredentialSlot{}, ErrAudienceMismatch
		}
		return CredentialSlot{}, ErrInvalidState
	}
	return CredentialSlot{audienceID: audienceID, principalID: principal.id, id: id, createdAt: createdAt}, nil
}

func (value CredentialSlot) AudienceID() GatewayAudienceID { return value.audienceID }
func (value CredentialSlot) PrincipalID() CorePrincipalID  { return value.principalID }
func (value CredentialSlot) ID() CredentialSlotID          { return value.id }

type CredentialState uint8

const (
	CredentialDisabled CredentialState = iota + 1
	CredentialActive
	CredentialRetiring
	CredentialRevoked
)

type CredentialSpec struct {
	AudienceID          GatewayAudienceID
	Principal           Principal
	Slot                CredentialSlot
	RecordID            CredentialRecordID
	PublicID            CredentialID
	State               CredentialState
	NotBefore           time.Time
	ExpiresAt           time.Time
	ActivatedAt         time.Time
	RetirementStartedAt time.Time
	RetirementDeadline  time.Time
	RevokedAt           time.Time
	CreatedAt           time.Time
	StateChangedAt      time.Time
}

type Credential struct{ spec CredentialSpec }

func NewCredential(spec CredentialSpec) (Credential, error) {
	if err := validateCredentialSpec(spec); err != nil {
		return Credential{}, err
	}
	return Credential{spec: spec}, nil
}

func (value Credential) AudienceID() GatewayAudienceID { return value.spec.AudienceID }
func (value Credential) PrincipalID() CorePrincipalID  { return value.spec.Principal.id }
func (value Credential) SlotID() CredentialSlotID      { return value.spec.Slot.id }
func (value Credential) RecordID() CredentialRecordID  { return value.spec.RecordID }
func (value Credential) PublicID() CredentialID        { return value.spec.PublicID }
func (value Credential) State() CredentialState        { return value.spec.State }
func (value Credential) UsableAt(now time.Time) bool {
	if value.spec.State != CredentialActive && value.spec.State != CredentialRetiring {
		return false
	}
	if now.Before(value.spec.NotBefore) || !now.Before(value.spec.ExpiresAt) {
		return false
	}
	return value.spec.State != CredentialRetiring || now.Before(value.spec.RetirementDeadline)
}

func validateCredentialSpec(spec CredentialSpec) error {
	if spec.AudienceID.IsZero() || spec.Principal.audienceID != spec.AudienceID || spec.Slot.audienceID != spec.AudienceID || spec.Slot.principalID != spec.Principal.id {
		if !spec.AudienceID.IsZero() && ((!spec.Principal.audienceID.IsZero() && spec.Principal.audienceID != spec.AudienceID) || (!spec.Slot.audienceID.IsZero() && spec.Slot.audienceID != spec.AudienceID)) {
			return ErrAudienceMismatch
		}
		return ErrInvalidState
	}
	if spec.RecordID.IsZero() || spec.PublicID.IsZero() || spec.Slot.id.IsZero() || spec.CreatedAt.IsZero() || spec.NotBefore.Before(spec.CreatedAt) || !spec.ExpiresAt.After(spec.NotBefore) || spec.ExpiresAt.Sub(spec.NotBefore) > credentialMaxLifetime || (!spec.ActivatedAt.IsZero() && spec.ActivatedAt.Before(spec.CreatedAt)) || spec.StateChangedAt.Before(spec.CreatedAt) {
		return ErrInvalidState
	}
	switch spec.State {
	case CredentialDisabled:
		if !spec.RevokedAt.IsZero() {
			return ErrInvalidState
		}
	case CredentialActive:
		if spec.ActivatedAt.IsZero() || !spec.RetirementStartedAt.IsZero() || !spec.RetirementDeadline.IsZero() || !spec.RevokedAt.IsZero() {
			return ErrInvalidState
		}
	case CredentialRetiring:
		if spec.ActivatedAt.IsZero() || spec.RetirementStartedAt.Before(spec.ActivatedAt) || !spec.RetirementDeadline.After(spec.RetirementStartedAt) || spec.RetirementDeadline.Sub(spec.RetirementStartedAt) > credentialMaxOverlap || !spec.RevokedAt.IsZero() {
			return ErrInvalidState
		}
	case CredentialRevoked:
		if spec.RevokedAt.Before(spec.CreatedAt) {
			return ErrInvalidState
		}
	default:
		return ErrInvalidState
	}
	return nil
}

type DestinationState uint8

const (
	DestinationEnabled DestinationState = iota + 1
	DestinationDisabled
)

type Destination struct {
	audienceID     GatewayAudienceID
	id             DestinationID
	state          DestinationState
	createdAt      time.Time
	stateChangedAt time.Time
}

func NewDestination(audienceID GatewayAudienceID, id DestinationID, state DestinationState, createdAt, stateChangedAt time.Time) (Destination, error) {
	if audienceID.IsZero() || id.IsZero() || (state != DestinationEnabled && state != DestinationDisabled) || createdAt.IsZero() || stateChangedAt.Before(createdAt) {
		return Destination{}, ErrInvalidState
	}
	return Destination{audienceID: audienceID, id: id, state: state, createdAt: createdAt, stateChangedAt: stateChangedAt}, nil
}

func (value Destination) AudienceID() GatewayAudienceID { return value.audienceID }
func (value Destination) ID() DestinationID             { return value.id }
func (value Destination) Enabled() bool                 { return value.state == DestinationEnabled }

type DestinationTokenState uint8

const (
	DestinationTokenStaged DestinationTokenState = iota + 1
	DestinationTokenActive
	DestinationTokenRetiring
	DestinationTokenRevoked
)

type DestinationTokenSpec struct {
	AudienceID            GatewayAudienceID
	Destination           Destination
	RecordID              DestinationTokenRecordID
	Verifier              TokenVerifier
	VerifierKeyID         DestinationVerifierKeyID
	State                 DestinationTokenState
	CreatedAt             time.Time
	ActivatedAt           time.Time
	RetirementStartedAt   time.Time
	RevokedAt             time.Time
	ExpiresAt             time.Time
	StagedCleanupDeadline time.Time
	RetirementDeadline    time.Time
	StateChangedAt        time.Time
}

type DestinationToken struct{ spec DestinationTokenSpec }

func NewDestinationToken(spec DestinationTokenSpec) (DestinationToken, error) {
	if err := validateDestinationTokenSpec(spec); err != nil {
		return DestinationToken{}, err
	}
	return DestinationToken{spec: spec}, nil
}

func (value DestinationToken) AudienceID() GatewayAudienceID      { return value.spec.AudienceID }
func (value DestinationToken) DestinationID() DestinationID       { return value.spec.Destination.id }
func (value DestinationToken) RecordID() DestinationTokenRecordID { return value.spec.RecordID }
func (value DestinationToken) State() DestinationTokenState       { return value.spec.State }
func (value DestinationToken) UsableAt(now time.Time) bool {
	if !value.spec.Destination.Enabled() || (value.spec.State != DestinationTokenActive && value.spec.State != DestinationTokenRetiring) || now.Before(value.spec.ActivatedAt) || !now.Before(value.spec.ExpiresAt) {
		return false
	}
	return value.spec.State != DestinationTokenRetiring || now.Before(value.spec.RetirementDeadline)
}

func validateDestinationTokenSpec(spec DestinationTokenSpec) error {
	if spec.AudienceID.IsZero() || spec.Destination.audienceID != spec.AudienceID {
		if !spec.AudienceID.IsZero() && !spec.Destination.audienceID.IsZero() && spec.Destination.audienceID != spec.AudienceID {
			return ErrAudienceMismatch
		}
		return ErrInvalidState
	}
	if spec.Destination.id.IsZero() || spec.RecordID.IsZero() || spec.Verifier.IsZero() || spec.VerifierKeyID.IsZero() || spec.CreatedAt.IsZero() || !spec.ExpiresAt.After(spec.CreatedAt) || spec.ExpiresAt.Sub(spec.CreatedAt) > tokenMaxLifetime || !spec.StagedCleanupDeadline.After(spec.CreatedAt) || spec.StagedCleanupDeadline.Sub(spec.CreatedAt) > tokenMaxCleanup || spec.StateChangedAt.Before(spec.CreatedAt) {
		return ErrInvalidState
	}
	switch spec.State {
	case DestinationTokenStaged:
		if !spec.ActivatedAt.IsZero() || !spec.RetirementStartedAt.IsZero() || !spec.RetirementDeadline.IsZero() || !spec.RevokedAt.IsZero() {
			return ErrInvalidState
		}
	case DestinationTokenActive:
		if spec.ActivatedAt.Before(spec.CreatedAt) || !spec.RetirementStartedAt.IsZero() || !spec.RetirementDeadline.IsZero() || !spec.RevokedAt.IsZero() {
			return ErrInvalidState
		}
	case DestinationTokenRetiring:
		if spec.ActivatedAt.Before(spec.CreatedAt) || spec.RetirementStartedAt.Before(spec.ActivatedAt) || !spec.RetirementDeadline.After(spec.RetirementStartedAt) || spec.RetirementDeadline.Sub(spec.RetirementStartedAt) > tokenMaxOverlap || !spec.RevokedAt.IsZero() {
			return ErrInvalidState
		}
	case DestinationTokenRevoked:
		if spec.RevokedAt.Before(spec.CreatedAt) {
			return ErrInvalidState
		}
	default:
		return ErrInvalidState
	}
	return nil
}

func validKeyID(value string) bool {
	return value != "" && utf8.ValidString(value) && len(value) <= keyIDMaxBytes
}

func writeRedacted(state fmt.State) {
	_, _ = state.Write([]byte("[redacted]"))
}

func formatUUID[T ~[16]byte](value T) string {
	var encoded [36]byte
	hex.Encode(encoded[0:8], value[0:4])
	encoded[8] = '-'
	hex.Encode(encoded[9:13], value[4:6])
	encoded[13] = '-'
	hex.Encode(encoded[14:18], value[6:8])
	encoded[18] = '-'
	hex.Encode(encoded[19:23], value[8:10])
	encoded[23] = '-'
	hex.Encode(encoded[24:36], value[10:16])
	return string(encoded[:])
}

func parseUUID(value string, requireV4 bool) ([16]byte, error) {
	var result [16]byte
	if len(value) != 36 || value != strings.ToLower(value) || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return result, ErrInvalidState
	}
	compact := value[:8] + value[9:13] + value[14:18] + value[19:23] + value[24:]
	decoded, err := hex.DecodeString(compact)
	if err != nil || len(decoded) != len(result) {
		return result, ErrInvalidState
	}
	copy(result[:], decoded)
	if result == [16]byte{} || (requireV4 && (result[6]>>4 != 4 || result[8]>>6 != 2)) {
		return [16]byte{}, ErrInvalidState
	}
	return result, nil
}
