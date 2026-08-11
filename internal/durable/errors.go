package durable

import "errors"

var (
	ErrInvalidAcceptance      = errors.New("durable acceptance invalid")
	ErrReceiptGeneration      = errors.New("durable receipt generation failed")
	ErrStoreUnavailable       = errors.New("durable store unavailable")
	ErrStoreOutcomeUnknown    = errors.New("durable store outcome unknown")
	ErrStoreCanceled          = errors.New("durable store operation canceled")
	ErrStoreFailure           = errors.New("durable store operation failed")
	ErrStoredRecordUnreadable = errors.New("durable stored record unreadable")
)
