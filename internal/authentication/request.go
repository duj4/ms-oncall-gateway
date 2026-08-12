package authentication

import (
	"fmt"
	"io"

	"github.com/duj4/ms-oncall-gateway/internal/securitystate"
)

// Request contains only the transport values covered by Authentication V1.
// It deliberately has no caller-provided audience, principal, or destination.
type Request struct {
	method              string
	path                string
	deliveryIdentity    string
	authorizationValues []string
	timestampValues     []string
	nonceValues         []string
	rawBody             []byte
}

// NewRequest defensively copies header value collections and the exact raw
// request body. Validation is performed by Service before any dependency call.
func NewRequest(
	method string,
	path string,
	deliveryIdentity string,
	authorizationValues []string,
	timestampValues []string,
	nonceValues []string,
	rawBody []byte,
) Request {
	return Request{
		method:              method,
		path:                path,
		deliveryIdentity:    deliveryIdentity,
		authorizationValues: append([]string(nil), authorizationValues...),
		timestampValues:     append([]string(nil), timestampValues...),
		nonceValues:         append([]string(nil), nonceValues...),
		rawBody:             append([]byte(nil), rawBody...),
	}
}

func (Request) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "[redacted]")
}

// Result contains only the trusted Core principal derived from the verified
// credential record.
type Result struct {
	corePrincipalID securitystate.CorePrincipalID
}

func (result Result) CorePrincipalID() securitystate.CorePrincipalID {
	return result.corePrincipalID
}

func (Result) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "[redacted]")
}
