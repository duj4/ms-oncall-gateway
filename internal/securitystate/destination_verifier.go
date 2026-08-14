package securitystate

import (
	"crypto/hmac"
	"crypto/sha256"
)

const destinationTokenVerifierDomain = "MS_ONCALL_GATEWAY_DESTINATION_TOKEN_V1"

// ComputeDestinationTokenVerifier is the single implementation of the
// Resolver V1 domain-separated token verifier. Callers must never persist or
// log the raw token or key material.
func ComputeDestinationTokenVerifier(audience GatewayAudienceID, token OpaqueDestinationToken, key DestinationVerifierKey) (TokenVerifier, error) {
	keyBytes := key.Bytes()
	if audience.IsZero() || len(keyBytes) < sha256.Size {
		return TokenVerifier{}, ErrInvalidState
	}
	mac := hmac.New(sha256.New, keyBytes)
	_, _ = mac.Write([]byte(destinationTokenVerifierDomain))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(audience.String()))
	_, _ = mac.Write([]byte{0})
	tokenBytes := token.Bytes()
	_, _ = mac.Write(tokenBytes[:])
	return NewTokenVerifier(mac.Sum(nil))
}
