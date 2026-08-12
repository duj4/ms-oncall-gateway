package authentication

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/duj4/ms-oncall-gateway/internal/durable"
	"github.com/duj4/ms-oncall-gateway/internal/securitystate"
)

const (
	authenticationScheme        = "MSOnCall-HMAC-SHA256"
	authorizationCredential     = " Credential="
	authorizationSignature      = ", Signature="
	canonicalPathPrefix         = "/v1/goalert/contact-method/"
	canonicalSigningDomain      = "MS_ONCALL_GATEWAY_REQUEST_V1"
	maximumTimestampDifference  = uint64(60)
	maximumDependencyErrorDepth = 64
)

type Service struct {
	configuredAudience securitystate.GatewayAudienceID
	audienceBinding    securitystate.AudienceBindingStore
	credentials        securitystate.CredentialRegistry
	secrets            securitystate.AuthenticationSecretSource
	principals         securitystate.PrincipalRegistry
	replay             securitystate.ReplayReservationStore
	clock              func() time.Time
}

// NewService creates the transport-independent Authentication V1 service.
func NewService(
	configuredAudience securitystate.GatewayAudienceID,
	audienceBinding securitystate.AudienceBindingStore,
	credentials securitystate.CredentialRegistry,
	secrets securitystate.AuthenticationSecretSource,
	principals securitystate.PrincipalRegistry,
	replay securitystate.ReplayReservationStore,
	clock func() time.Time,
) (*Service, error) {
	if configuredAudience.IsZero() ||
		isNilInterface(audienceBinding) ||
		isNilInterface(credentials) ||
		isNilInterface(secrets) ||
		isNilInterface(principals) ||
		isNilInterface(replay) ||
		clock == nil {
		return nil, ErrConfigurationInvalid
	}
	return &Service{
		configuredAudience: configuredAudience,
		audienceBinding:    audienceBinding,
		credentials:        credentials,
		secrets:            secrets,
		principals:         principals,
		replay:             replay,
		clock:              clock,
	}, nil
}

type parsedRequest struct {
	path             string
	deliveryIdentity string
	credentialID     securitystate.CredentialID
	signature        [sha256.Size]byte
	timestampText    string
	timestamp        uint64
	nonceText        string
	nonce            securitystate.ReplayNonce
	rawBody          []byte
}

// Authenticate verifies one exact Core request and returns only its trusted
// principal. Every failure is mapped to a fixed, content-free error.
func (service *Service) Authenticate(ctx context.Context, request Request) (Result, error) {
	if service == nil ||
		service.configuredAudience.IsZero() ||
		isNilInterface(service.audienceBinding) ||
		isNilInterface(service.credentials) ||
		isNilInterface(service.secrets) ||
		isNilInterface(service.principals) ||
		isNilInterface(service.replay) ||
		service.clock == nil {
		return Result{}, ErrConfigurationInvalid
	}
	if isNilInterface(ctx) {
		return Result{}, ErrRequestInvalid
	}
	if contextDone(ctx) {
		return Result{}, ErrCanceled
	}

	parsed, err := parseRequest(request)
	if err != nil {
		return Result{}, err
	}

	now := service.clock()
	if now.IsZero() || now.Unix() < 0 {
		return Result{}, ErrConfigurationInvalid
	}
	if contextDone(ctx) {
		return Result{}, ErrCanceled
	}

	boundAudience, dependencyErr := service.audienceBinding.BoundAudience(ctx)
	if dependencyCanceled(ctx, dependencyErr) {
		return Result{}, ErrCanceled
	}
	if dependencyErr != nil || boundAudience.IsZero() || boundAudience != service.configuredAudience {
		return Result{}, ErrUnavailable
	}

	credential, dependencyErr := service.credentials.Credential(ctx, service.configuredAudience, parsed.credentialID)
	if dependencyCanceled(ctx, dependencyErr) {
		return Result{}, ErrCanceled
	}
	if dependencyErr != nil {
		if singleCauseMatches(dependencyErr, securitystate.ErrCredentialNotFound) {
			return Result{}, ErrAuthenticationFailed
		}
		return Result{}, ErrUnavailable
	}
	if !credentialRecordValid(credential, service.configuredAudience, parsed.credentialID) {
		return Result{}, ErrUnavailable
	}
	if !credential.UsableAt(now) {
		return Result{}, ErrAuthenticationFailed
	}

	secret, dependencyErr := service.secrets.AuthenticationSecret(ctx, service.configuredAudience, parsed.credentialID)
	if dependencyCanceled(ctx, dependencyErr) {
		return Result{}, ErrCanceled
	}
	if dependencyErr != nil {
		return Result{}, ErrUnavailable
	}

	expectedMAC := requestMAC(
		service.configuredAudience.String(),
		parsed,
		secret.Bytes(),
	)
	if subtle.ConstantTimeCompare(expectedMAC[:], parsed.signature[:]) != 1 {
		return Result{}, ErrAuthenticationFailed
	}
	if !timestampWithinWindow(uint64(now.Unix()), parsed.timestamp) {
		return Result{}, ErrAuthenticationFailed
	}
	if contextDone(ctx) {
		return Result{}, ErrCanceled
	}

	disposition, dependencyErr := service.replay.Reserve(ctx, credential.RecordID(), parsed.nonce, now)
	if dependencyCanceled(ctx, dependencyErr) {
		return Result{}, ErrCanceled
	}
	if dependencyErr != nil {
		return Result{}, ErrUnavailable
	}
	switch disposition {
	case securitystate.ReplayDuplicate:
		return Result{}, ErrAuthenticationFailed
	case securitystate.ReplayReserved:
		// Continue only after the nonce has been durably reserved.
	default:
		return Result{}, ErrUnavailable
	}

	principal, dependencyErr := service.principals.Principal(ctx, service.configuredAudience, credential.PrincipalID())
	if dependencyCanceled(ctx, dependencyErr) {
		return Result{}, ErrCanceled
	}
	if dependencyErr != nil {
		if singleCauseMatches(dependencyErr, securitystate.ErrPrincipalNotAuthorized) {
			return Result{}, ErrForbidden
		}
		return Result{}, ErrUnavailable
	}
	if principal.ID().IsZero() ||
		principal.AudienceID().IsZero() ||
		principal.ID() != credential.PrincipalID() ||
		principal.AudienceID() != service.configuredAudience {
		return Result{}, ErrUnavailable
	}
	if !principal.Enabled() || !principal.IntakeAuthorized() {
		return Result{}, ErrForbidden
	}

	return Result{corePrincipalID: principal.ID()}, nil
}

func parseRequest(request Request) (parsedRequest, error) {
	if request.method != "POST" || !validCanonicalPath(request.path) {
		return parsedRequest{}, ErrRequestInvalid
	}
	deliveryIdentity, err := durable.ParseDeliveryIdentity(request.deliveryIdentity)
	if err != nil || deliveryIdentity.String() != request.deliveryIdentity {
		return parsedRequest{}, ErrRequestInvalid
	}

	authorization, ok := exactlyOne(request.authorizationValues)
	if !ok {
		return parsedRequest{}, ErrAuthenticationFailed
	}
	timestampText, ok := exactlyOne(request.timestampValues)
	if !ok {
		return parsedRequest{}, ErrAuthenticationFailed
	}
	nonceText, ok := exactlyOne(request.nonceValues)
	if !ok {
		return parsedRequest{}, ErrAuthenticationFailed
	}

	credentialID, signature, ok := parseAuthorization(authorization)
	if !ok {
		return parsedRequest{}, ErrAuthenticationFailed
	}
	timestamp, ok := parseTimestamp(timestampText)
	if !ok {
		return parsedRequest{}, ErrAuthenticationFailed
	}
	nonce, err := securitystate.ParseReplayNonce(nonceText)
	if err != nil {
		return parsedRequest{}, ErrAuthenticationFailed
	}

	return parsedRequest{
		path:             request.path,
		deliveryIdentity: request.deliveryIdentity,
		credentialID:     credentialID,
		signature:        signature,
		timestampText:    timestampText,
		timestamp:        timestamp,
		nonceText:        nonceText,
		nonce:            nonce,
		rawBody:          request.rawBody,
	}, nil
}

func validCanonicalPath(path string) bool {
	if !strings.HasPrefix(path, canonicalPathPrefix) {
		return false
	}
	tokenText := path[len(canonicalPathPrefix):]
	_, err := securitystate.ParseOpaqueDestinationToken(tokenText)
	return err == nil
}

func exactlyOne(values []string) (string, bool) {
	if len(values) != 1 || values[0] == "" || strings.TrimSpace(values[0]) != values[0] || strings.ContainsAny(values[0], "\r\n") {
		return "", false
	}
	return values[0], true
}

func parseAuthorization(value string) (securitystate.CredentialID, [sha256.Size]byte, bool) {
	var signature [sha256.Size]byte
	prefix := authenticationScheme + authorizationCredential
	if !strings.HasPrefix(value, prefix) {
		return securitystate.CredentialID{}, signature, false
	}
	remainder := value[len(prefix):]
	separatorIndex := strings.Index(remainder, authorizationSignature)
	if separatorIndex <= 0 || strings.Index(remainder[separatorIndex+len(authorizationSignature):], authorizationSignature) >= 0 {
		return securitystate.CredentialID{}, signature, false
	}
	credentialText := remainder[:separatorIndex]
	signatureText := remainder[separatorIndex+len(authorizationSignature):]
	credentialID, err := securitystate.ParseCredentialID(credentialText)
	if err != nil || credentialID.String() != credentialText {
		return securitystate.CredentialID{}, signature, false
	}
	if len(signatureText) != 43 || strings.Contains(signatureText, "=") {
		return securitystate.CredentialID{}, signature, false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(signatureText)
	if err != nil || len(decoded) != len(signature) || base64.RawURLEncoding.EncodeToString(decoded) != signatureText {
		return securitystate.CredentialID{}, signature, false
	}
	copy(signature[:], decoded)
	return credentialID, signature, true
}

func parseTimestamp(value string) (uint64, bool) {
	if value == "" || (len(value) > 1 && value[0] == '0') {
		return 0, false
	}
	for index := range value {
		if value[index] < '0' || value[index] > '9' {
			return 0, false
		}
	}
	parsed, err := strconv.ParseUint(value, 10, 64)
	return parsed, err == nil
}

func credentialRecordValid(
	credential securitystate.Credential,
	audience securitystate.GatewayAudienceID,
	publicID securitystate.CredentialID,
) bool {
	if credential.PublicID() != publicID ||
		credential.AudienceID() != audience ||
		credential.PrincipalID().IsZero() ||
		credential.SlotID().IsZero() ||
		credential.RecordID().IsZero() {
		return false
	}
	switch credential.State() {
	case securitystate.CredentialDisabled,
		securitystate.CredentialActive,
		securitystate.CredentialRetiring,
		securitystate.CredentialRevoked:
		return true
	default:
		return false
	}
}

func requestMAC(audience string, request parsedRequest, secret [sha256.Size]byte) [sha256.Size]byte {
	bodyDigest := sha256.Sum256(request.rawBody)
	signingInput := strings.Join([]string{
		canonicalSigningDomain,
		audience,
		"POST",
		request.path,
		request.credentialID.String(),
		request.deliveryIdentity,
		request.timestampText,
		request.nonceText,
		hex.EncodeToString(bodyDigest[:]),
	}, "\n")
	mac := hmac.New(sha256.New, secret[:])
	_, _ = mac.Write([]byte(signingInput))
	var result [sha256.Size]byte
	copy(result[:], mac.Sum(nil))
	return result
}

func timestampWithinWindow(now, signed uint64) bool {
	if signed > now {
		return signed-now <= maximumTimestampDifference
	}
	return now-signed <= maximumTimestampDifference
}

func contextDone(ctx context.Context) bool {
	err := ctx.Err()
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

func dependencyCanceled(ctx context.Context, dependencyErr error) bool {
	return contextDone(ctx) || errors.Is(dependencyErr, context.Canceled) || errors.Is(dependencyErr, context.DeadlineExceeded)
}

func singleCauseMatches(err, target error) bool {
	for current, depth := err, 0; current != nil && depth < maximumDependencyErrorDepth; depth++ {
		if isNilInterface(current) {
			return false
		}
		if _, ambiguous := current.(interface{ Unwrap() []error }); ambiguous {
			return false
		}
		if reflect.TypeOf(current).Comparable() && current == target {
			return true
		}
		current = errors.Unwrap(current)
	}
	return false
}

func isNilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
