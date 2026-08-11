package intake

import "errors"

var (
	ErrInvalidRequest = errors.New("acceptance pipeline request invalid")
	ErrCanceled       = errors.New("acceptance pipeline canceled")
)
