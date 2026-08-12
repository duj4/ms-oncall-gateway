package securitystate

import "errors"

var (
	ErrInvalidState           = errors.New("security state invalid")
	ErrAudienceMismatch       = errors.New("security state audience mismatch")
	ErrAudienceUnavailable    = errors.New("security realm unavailable")
	ErrCredentialNotFound     = errors.New("authentication credential not found")
	ErrSecretUnavailable      = errors.New("authentication secret unavailable")
	ErrPrincipalNotAuthorized = errors.New("core principal not authorized")
	ErrReplayUnavailable      = errors.New("replay reservation unavailable")
	ErrReplayOutcomeUnknown   = errors.New("replay reservation outcome unknown")
	ErrDestinationNotFound    = errors.New("destination not found")
	ErrVerifierKeyUnavailable = errors.New("destination verifier key unavailable")
)
