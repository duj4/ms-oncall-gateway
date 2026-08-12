package authentication

import "errors"

var (
	ErrConfigurationInvalid = errors.New("authentication configuration invalid")
	ErrRequestInvalid       = errors.New("authentication request invalid")
	ErrAuthenticationFailed = errors.New("authentication failed")
	ErrForbidden            = errors.New("authentication forbidden")
	ErrUnavailable          = errors.New("authentication unavailable")
	ErrCanceled             = errors.New("authentication canceled")
)
