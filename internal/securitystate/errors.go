package securitystate

import "errors"

var (
	ErrInvalidState                       = errors.New("security state invalid")
	ErrAudienceMismatch                   = errors.New("security state audience mismatch")
	ErrAudienceUnavailable                = errors.New("security realm unavailable")
	ErrCredentialNotFound                 = errors.New("authentication credential not found")
	ErrSecretUnavailable                  = errors.New("authentication secret unavailable")
	ErrPrincipalNotAuthorized             = errors.New("core principal not authorized")
	ErrReplayUnavailable                  = errors.New("replay reservation unavailable")
	ErrReplayOutcomeUnknown               = errors.New("replay reservation outcome unknown")
	ErrDestinationNotFound                = errors.New("destination not found")
	ErrVerifierKeyUnavailable             = errors.New("destination verifier key unavailable")
	ErrDestinationLifecycleInvalid        = errors.New("destination token lifecycle invalid")
	ErrDestinationLifecycleConflict       = errors.New("destination token lifecycle conflict")
	ErrDestinationLifecycleReconciliation = errors.New("destination token lifecycle reconciliation required")
	ErrDestinationLifecycleUnavailable    = errors.New("destination token lifecycle unavailable")
	ErrDestinationLifecycleOutcomeUnknown = errors.New("destination token lifecycle outcome unknown")
	ErrDestinationLifecycleCanceled       = errors.New("destination token lifecycle canceled")
	ErrDestinationLifecycleDeadline       = errors.New("destination token lifecycle deadline exceeded")
)
