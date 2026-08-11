package protection

import "errors"

var (
	ErrProtectionInvalid         = errors.New("payload protection invalid")
	ErrProtectionKeyUnavailable  = errors.New("payload protection key unavailable")
	ErrProtectionRandom          = errors.New("payload protection randomness unavailable")
	ErrProtectionFailed          = errors.New("payload protection failed")
	ErrProtectedDigestUnreadable = errors.New("protected digest unreadable")
)
