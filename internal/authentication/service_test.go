package authentication

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/duj4/ms-oncall-gateway/internal/securitystate"
)

const (
	testOnlyAudience         = "123e4567-e89b-12d3-a456-426614174000"
	testOnlyOtherAudience    = "223e4567-e89b-12d3-a456-426614174000"
	testOnlyCredential       = "01234567-89ab-4def-8123-456789abcdef"
	testOnlyOtherCredential  = "11234567-89ab-4def-8123-456789abcdef"
	testOnlyPrincipal        = "22222222-3333-4444-8555-666666666666"
	testOnlyOtherPrincipal   = "32222222-3333-4444-8555-666666666666"
	testOnlySlot             = "33333333-4444-5555-8666-777777777777"
	testOnlyRecord           = "44444444-5555-6666-8777-888888888888"
	testOnlyTimestamp        = "1700000000"
	testOnlyNonce            = "EBESExQVFhcYGRobHB0eHw"
	testOnlyPath             = "/v1/goalert/contact-method/mso1_AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
	testOnlyDeliveryIdentity = "11111111-2222-4333-8444-555555555555"
	testOnlyBody             = `{"AppName":"GoAlert","Type":"Test"}`
	testOnlyBodyDigest       = "a31863e52c5bb004054421a191fd6c1f0f7184bf92312a03e4b5eae298a2a2f1"
	testOnlySignature        = "Lmxexoh8H9V0wAtro_hqBgRr0XoJnA8yVZW0Ug3MtBk"
	testOnlySignatureBytes   = "2e6c5ec6887c1fd574c00b6ba3f86a06046bd17a099c0f325595b4520dccb419"
	testOnlyAuthorization    = "MSOnCall-HMAC-SHA256 Credential=" + testOnlyCredential + ", Signature=" + testOnlySignature
	testOnlyCanonicalInput   = "MS_ONCALL_GATEWAY_REQUEST_V1\n" + testOnlyAudience + "\nPOST\n" + testOnlyPath + "\n" + testOnlyCredential + "\n" + testOnlyDeliveryIdentity + "\n" + testOnlyTimestamp + "\n" + testOnlyNonce + "\n" + testOnlyBodyDigest
	testOnlyDependencyMarker = "dependency-sensitive-test-marker"
	testOnlyRequestMarker    = "request-sensitive-test-marker"
)

var testOnlySecret = [sha256.Size]byte{
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
}

type audienceBindingFunc func(context.Context) (securitystate.GatewayAudienceID, error)

func (function audienceBindingFunc) BoundAudience(ctx context.Context) (securitystate.GatewayAudienceID, error) {
	return function(ctx)
}

type credentialRegistryFunc func(context.Context, securitystate.GatewayAudienceID, securitystate.CredentialID) (securitystate.Credential, error)

func (function credentialRegistryFunc) Credential(ctx context.Context, audience securitystate.GatewayAudienceID, id securitystate.CredentialID) (securitystate.Credential, error) {
	return function(ctx, audience, id)
}

type secretSourceFunc func(context.Context, securitystate.GatewayAudienceID, securitystate.CredentialID) (securitystate.AuthenticationSecret, error)

func (function secretSourceFunc) AuthenticationSecret(ctx context.Context, audience securitystate.GatewayAudienceID, id securitystate.CredentialID) (securitystate.AuthenticationSecret, error) {
	return function(ctx, audience, id)
}

type principalRegistryFunc func(context.Context, securitystate.GatewayAudienceID, securitystate.CorePrincipalID) (securitystate.Principal, error)

func (function principalRegistryFunc) Principal(ctx context.Context, audience securitystate.GatewayAudienceID, id securitystate.CorePrincipalID) (securitystate.Principal, error) {
	return function(ctx, audience, id)
}

type replayStoreFunc func(context.Context, securitystate.CredentialRecordID, securitystate.ReplayNonce, time.Time) (securitystate.ReplayReservationDisposition, error)

func (function replayStoreFunc) Reserve(ctx context.Context, id securitystate.CredentialRecordID, nonce securitystate.ReplayNonce, now time.Time) (securitystate.ReplayReservationDisposition, error) {
	return function(ctx, id, nonce, now)
}

type typedNilBinding struct{}

func (*typedNilBinding) BoundAudience(context.Context) (securitystate.GatewayAudienceID, error) {
	panic("typed-nil dependency called")
}

type typedNilContext struct{}

func (*typedNilContext) Deadline() (time.Time, bool) { panic("typed-nil context called") }
func (*typedNilContext) Done() <-chan struct{}       { panic("typed-nil context called") }
func (*typedNilContext) Err() error                  { panic("typed-nil context called") }
func (*typedNilContext) Value(any) any               { panic("typed-nil context called") }

type testFixture struct {
	mutex              sync.Mutex
	order              []string
	clockCalls         int
	now                time.Time
	audience           securitystate.GatewayAudienceID
	boundAudience      securitystate.GatewayAudienceID
	audienceErr        error
	credential         securitystate.Credential
	credentialErr      error
	secret             securitystate.AuthenticationSecret
	secretErr          error
	replayResult       securitystate.ReplayReservationDisposition
	replayErr          error
	principal          securitystate.Principal
	principalErr       error
	replayRecord       securitystate.CredentialRecordID
	replayNonce        securitystate.ReplayNonce
	replayTime         time.Time
	credentialAudience securitystate.GatewayAudienceID
	credentialArg      securitystate.CredentialID
	secretAudience     securitystate.GatewayAudienceID
	secretArg          securitystate.CredentialID
	principalAudience  securitystate.GatewayAudienceID
	principalArg       securitystate.CorePrincipalID
	replayOverride     replayStoreFunc
}

func newTestFixture(t *testing.T) *testFixture {
	t.Helper()
	now := time.Unix(1700000000, 0).UTC()
	audience := mustAudience(t, testOnlyAudience)
	principal := mustPrincipal(t, audience, testOnlyPrincipal, true, true, now)
	credential := mustCredential(t, audience, principal, testOnlyCredential, securitystate.CredentialActive, now)
	secret, err := securitystate.NewAuthenticationSecret(testOnlySecret[:])
	if err != nil {
		t.Fatal("test-only authentication secret setup failed")
	}
	return &testFixture{
		now:           now,
		audience:      audience,
		boundAudience: audience,
		credential:    credential,
		secret:        secret,
		replayResult:  securitystate.ReplayReserved,
		principal:     principal,
	}
}

func (fixture *testFixture) record(step string) {
	fixture.mutex.Lock()
	defer fixture.mutex.Unlock()
	fixture.order = append(fixture.order, step)
}

func (fixture *testFixture) service(t *testing.T) *Service {
	t.Helper()
	service, err := NewService(
		fixture.audience,
		audienceBindingFunc(func(context.Context) (securitystate.GatewayAudienceID, error) {
			fixture.record("audience")
			fixture.mutex.Lock()
			defer fixture.mutex.Unlock()
			return fixture.boundAudience, fixture.audienceErr
		}),
		credentialRegistryFunc(func(_ context.Context, audience securitystate.GatewayAudienceID, id securitystate.CredentialID) (securitystate.Credential, error) {
			fixture.record("credential")
			fixture.mutex.Lock()
			defer fixture.mutex.Unlock()
			fixture.credentialAudience = audience
			fixture.credentialArg = id
			return fixture.credential, fixture.credentialErr
		}),
		secretSourceFunc(func(_ context.Context, audience securitystate.GatewayAudienceID, id securitystate.CredentialID) (securitystate.AuthenticationSecret, error) {
			fixture.record("secret")
			fixture.mutex.Lock()
			defer fixture.mutex.Unlock()
			fixture.secretAudience = audience
			fixture.secretArg = id
			return fixture.secret, fixture.secretErr
		}),
		principalRegistryFunc(func(_ context.Context, audience securitystate.GatewayAudienceID, id securitystate.CorePrincipalID) (securitystate.Principal, error) {
			fixture.record("principal")
			fixture.mutex.Lock()
			defer fixture.mutex.Unlock()
			fixture.principalAudience = audience
			fixture.principalArg = id
			return fixture.principal, fixture.principalErr
		}),
		replayStoreFunc(func(ctx context.Context, id securitystate.CredentialRecordID, nonce securitystate.ReplayNonce, now time.Time) (securitystate.ReplayReservationDisposition, error) {
			fixture.record("replay")
			fixture.mutex.Lock()
			fixture.replayRecord = id
			fixture.replayNonce = nonce
			fixture.replayTime = now
			override := fixture.replayOverride
			result := fixture.replayResult
			err := fixture.replayErr
			fixture.mutex.Unlock()
			if override != nil {
				return override(ctx, id, nonce, now)
			}
			return result, err
		}),
		func() time.Time {
			fixture.record("clock")
			fixture.mutex.Lock()
			defer fixture.mutex.Unlock()
			fixture.clockCalls++
			return fixture.now
		},
	)
	if err != nil {
		t.Fatal("authentication service setup failed")
	}
	return service
}

func (fixture *testFixture) recordedOrder() []string {
	fixture.mutex.Lock()
	defer fixture.mutex.Unlock()
	return append([]string(nil), fixture.order...)
}

func mustAudience(t *testing.T, text string) securitystate.GatewayAudienceID {
	t.Helper()
	value, err := securitystate.ParseGatewayAudienceID(text)
	if err != nil {
		t.Fatal("test-only audience setup failed")
	}
	return value
}

func mustPrincipal(t *testing.T, audience securitystate.GatewayAudienceID, text string, enabled, authorized bool, now time.Time) securitystate.Principal {
	t.Helper()
	id, err := securitystate.ParseCorePrincipalID(text)
	if err != nil {
		t.Fatal("test-only principal setup failed")
	}
	value, err := securitystate.NewPrincipal(audience, id, enabled, authorized, now.Add(-3*time.Hour), now.Add(-2*time.Hour))
	if err != nil {
		t.Fatal("test-only principal state setup failed")
	}
	return value
}

func mustCredential(t *testing.T, audience securitystate.GatewayAudienceID, principal securitystate.Principal, publicText string, state securitystate.CredentialState, now time.Time) securitystate.Credential {
	t.Helper()
	slotID, err := securitystate.ParseCredentialSlotID(testOnlySlot)
	if err != nil {
		t.Fatal("test-only credential slot setup failed")
	}
	slot, err := securitystate.NewCredentialSlot(audience, principal, slotID, now.Add(-2*time.Hour))
	if err != nil {
		t.Fatal("test-only credential slot state setup failed")
	}
	recordID, err := securitystate.ParseCredentialRecordID(testOnlyRecord)
	if err != nil {
		t.Fatal("test-only credential record setup failed")
	}
	publicID, err := securitystate.ParseCredentialID(publicText)
	if err != nil {
		t.Fatal("test-only credential public ID setup failed")
	}
	spec := securitystate.CredentialSpec{
		AudienceID:     audience,
		Principal:      principal,
		Slot:           slot,
		RecordID:       recordID,
		PublicID:       publicID,
		State:          state,
		NotBefore:      now.Add(-90 * time.Minute),
		ExpiresAt:      now.Add(90 * time.Minute),
		CreatedAt:      now.Add(-2 * time.Hour),
		StateChangedAt: now.Add(-time.Hour),
	}
	switch state {
	case securitystate.CredentialActive:
		spec.ActivatedAt = now.Add(-time.Hour)
	case securitystate.CredentialRetiring:
		spec.ActivatedAt = now.Add(-time.Hour)
		spec.RetirementStartedAt = now.Add(-30 * time.Minute)
		spec.RetirementDeadline = now.Add(30 * time.Minute)
		spec.StateChangedAt = spec.RetirementStartedAt
	case securitystate.CredentialRevoked:
		spec.ActivatedAt = now.Add(-time.Hour)
		spec.RevokedAt = now.Add(-30 * time.Minute)
		spec.StateChangedAt = spec.RevokedAt
	}
	value, err := securitystate.NewCredential(spec)
	if err != nil {
		t.Fatal("test-only credential state setup failed")
	}
	return value
}

func goldenRequest() Request {
	return NewRequest(
		"POST",
		testOnlyPath,
		testOnlyDeliveryIdentity,
		[]string{testOnlyAuthorization},
		[]string{testOnlyTimestamp},
		[]string{testOnlyNonce},
		[]byte(testOnlyBody),
	)
}

func testSignedRequest(t *testing.T, audience, credential, path, delivery, timestamp, nonce string, body []byte, secret [sha256.Size]byte) Request {
	t.Helper()
	digest := sha256.Sum256(body)
	input := strings.Join([]string{
		canonicalSigningDomain,
		audience,
		"POST",
		path,
		credential,
		delivery,
		timestamp,
		nonce,
		hex.EncodeToString(digest[:]),
	}, "\n")
	mac := hmac.New(sha256.New, secret[:])
	_, _ = mac.Write([]byte(input))
	authorization := authenticationScheme + authorizationCredential + credential + authorizationSignature + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return NewRequest("POST", path, delivery, []string{authorization}, []string{timestamp}, []string{nonce}, body)
}

func TestCoreGatewayGoldenVector(t *testing.T) {
	digest := sha256.Sum256([]byte(testOnlyBody))
	if hex.EncodeToString(digest[:]) != testOnlyBodyDigest {
		t.Fatal("test-only golden body digest mismatch")
	}
	mac := hmac.New(sha256.New, testOnlySecret[:])
	_, _ = mac.Write([]byte(testOnlyCanonicalInput))
	if base64.RawURLEncoding.EncodeToString(mac.Sum(nil)) != testOnlySignature {
		t.Fatal("test-only golden signature mismatch")
	}
	decodedSignature, err := base64.RawURLEncoding.DecodeString(testOnlySignature)
	if err != nil || len(decodedSignature) != sha256.Size || hex.EncodeToString(decodedSignature) != testOnlySignatureBytes {
		t.Fatal("test-only golden signature decoding failed")
	}
	if testOnlyAuthorization != authenticationScheme+authorizationCredential+testOnlyCredential+authorizationSignature+testOnlySignature {
		t.Fatal("test-only golden authorization mismatch")
	}

	fixture := newTestFixture(t)
	result, err := fixture.service(t).Authenticate(context.Background(), goldenRequest())
	if err != nil {
		t.Fatal("test-only golden request was rejected")
	}
	if result.CorePrincipalID() != fixture.principal.ID() {
		t.Fatal("trusted principal result mismatch")
	}
	if got := fixture.recordedOrder(); !equalStrings(got, []string{"clock", "audience", "credential", "secret", "replay", "principal"}) {
		t.Fatal("authentication dependency order mismatch")
	}
}

func TestRequestValidationStopsBeforeDependencies(t *testing.T) {
	valid := goldenRequest()
	tests := []struct {
		name     string
		mutate   func(*Request)
		expected error
	}{
		{name: "zero", mutate: func(value *Request) { *value = Request{} }, expected: ErrRequestInvalid},
		{name: "method", mutate: func(value *Request) { value.method = "post" }, expected: ErrRequestInvalid},
		{name: "full URL", mutate: func(value *Request) { value.path = "https://gateway.invalid" + testOnlyPath }, expected: ErrRequestInvalid},
		{name: "wrong prefix", mutate: func(value *Request) {
			value.path = "/v1/goalert/contact-method/Mso1_" + strings.TrimPrefix(testOnlyPath, canonicalPathPrefix+"mso1_")
		}, expected: ErrRequestInvalid},
		{name: "percent encoding", mutate: func(value *Request) { value.path = strings.Replace(testOnlyPath, "AA", "%41A", 1) }, expected: ErrRequestInvalid},
		{name: "duplicate slash", mutate: func(value *Request) { value.path = strings.Replace(testOnlyPath, "/mso1_", "//mso1_", 1) }, expected: ErrRequestInvalid},
		{name: "dot segment", mutate: func(value *Request) {
			value.path = canonicalPathPrefix + "../" + strings.TrimPrefix(testOnlyPath, canonicalPathPrefix)
		}, expected: ErrRequestInvalid},
		{name: "token padding", mutate: func(value *Request) { value.path += "=" }, expected: ErrRequestInvalid},
		{name: "token short", mutate: func(value *Request) { value.path = value.path[:len(value.path)-1] }, expected: ErrRequestInvalid},
		{name: "token alphabet", mutate: func(value *Request) { value.path = value.path[:len(value.path)-1] + "+" }, expected: ErrRequestInvalid},
		{name: "path suffix", mutate: func(value *Request) { value.path += "/suffix" }, expected: ErrRequestInvalid},
		{name: "query", mutate: func(value *Request) { value.path += "?x=1" }, expected: ErrRequestInvalid},
		{name: "fragment", mutate: func(value *Request) { value.path += "#x" }, expected: ErrRequestInvalid},
		{name: "zero delivery", mutate: func(value *Request) { value.deliveryIdentity = "00000000-0000-0000-0000-000000000000" }, expected: ErrRequestInvalid},
		{name: "uppercase delivery", mutate: func(value *Request) { value.deliveryIdentity = "AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE" }, expected: ErrRequestInvalid},
		{name: "delivery without hyphens", mutate: func(value *Request) { value.deliveryIdentity = strings.ReplaceAll(testOnlyDeliveryIdentity, "-", "") }, expected: ErrRequestInvalid},
		{name: "missing authorization", mutate: func(value *Request) { value.authorizationValues = nil }, expected: ErrAuthenticationFailed},
		{name: "empty authorization", mutate: func(value *Request) { value.authorizationValues = []string{""} }, expected: ErrAuthenticationFailed},
		{name: "duplicate authorization", mutate: func(value *Request) {
			value.authorizationValues = []string{testOnlyAuthorization, testOnlyAuthorization}
		}, expected: ErrAuthenticationFailed},
		{name: "missing timestamp", mutate: func(value *Request) { value.timestampValues = nil }, expected: ErrAuthenticationFailed},
		{name: "empty timestamp", mutate: func(value *Request) { value.timestampValues = []string{""} }, expected: ErrAuthenticationFailed},
		{name: "duplicate timestamp", mutate: func(value *Request) { value.timestampValues = []string{testOnlyTimestamp, testOnlyTimestamp} }, expected: ErrAuthenticationFailed},
		{name: "combined timestamp", mutate: func(value *Request) { value.timestampValues = []string{testOnlyTimestamp + "," + testOnlyTimestamp} }, expected: ErrAuthenticationFailed},
		{name: "missing nonce", mutate: func(value *Request) { value.nonceValues = nil }, expected: ErrAuthenticationFailed},
		{name: "empty nonce", mutate: func(value *Request) { value.nonceValues = []string{""} }, expected: ErrAuthenticationFailed},
		{name: "duplicate nonce", mutate: func(value *Request) { value.nonceValues = []string{testOnlyNonce, testOnlyNonce} }, expected: ErrAuthenticationFailed},
		{name: "combined nonce", mutate: func(value *Request) { value.nonceValues = []string{testOnlyNonce + "," + testOnlyNonce} }, expected: ErrAuthenticationFailed},
		{name: "authorization case", mutate: func(value *Request) {
			value.authorizationValues[0] = "msoncall-HMAC-SHA256" + strings.TrimPrefix(testOnlyAuthorization, authenticationScheme)
		}, expected: ErrAuthenticationFailed},
		{name: "authorization spacing", mutate: func(value *Request) {
			value.authorizationValues[0] = strings.Replace(testOnlyAuthorization, ", Signature=", ",  Signature=", 1)
		}, expected: ErrAuthenticationFailed},
		{name: "authorization CRLF", mutate: func(value *Request) { value.authorizationValues[0] += "\r\n" }, expected: ErrAuthenticationFailed},
		{name: "authorization parameter", mutate: func(value *Request) { value.authorizationValues[0] += ", Extra=x" }, expected: ErrAuthenticationFailed},
		{name: "credential uppercase", mutate: func(value *Request) {
			value.authorizationValues[0] = strings.Replace(testOnlyAuthorization, testOnlyCredential, strings.ToUpper(testOnlyCredential), 1)
		}, expected: ErrAuthenticationFailed},
		{name: "credential not v4", mutate: func(value *Request) {
			value.authorizationValues[0] = strings.Replace(testOnlyAuthorization, testOnlyCredential, "01234567-89ab-1def-8123-456789abcdef", 1)
		}, expected: ErrAuthenticationFailed},
		{name: "credential wrong variant", mutate: func(value *Request) {
			value.authorizationValues[0] = strings.Replace(testOnlyAuthorization, testOnlyCredential, "01234567-89ab-4def-7123-456789abcdef", 1)
		}, expected: ErrAuthenticationFailed},
		{name: "signature padded", mutate: func(value *Request) { value.authorizationValues[0] += "=" }, expected: ErrAuthenticationFailed},
		{name: "signature short", mutate: func(value *Request) {
			value.authorizationValues[0] = strings.TrimSuffix(testOnlyAuthorization, testOnlySignature) + testOnlySignature[:42]
		}, expected: ErrAuthenticationFailed},
		{name: "signature alphabet", mutate: func(value *Request) {
			value.authorizationValues[0] = strings.TrimSuffix(testOnlyAuthorization, testOnlySignature) + "+" + testOnlySignature[1:]
		}, expected: ErrAuthenticationFailed},
		{name: "signature noncanonical", mutate: func(value *Request) {
			value.authorizationValues[0] = strings.TrimSuffix(testOnlyAuthorization, testOnlySignature) + testOnlySignature[:42] + "l"
		}, expected: ErrAuthenticationFailed},
		{name: "timestamp leading zero", mutate: func(value *Request) { value.timestampValues[0] = "01700000000" }, expected: ErrAuthenticationFailed},
		{name: "timestamp signed", mutate: func(value *Request) { value.timestampValues[0] = "+1700000000" }, expected: ErrAuthenticationFailed},
		{name: "timestamp space", mutate: func(value *Request) { value.timestampValues[0] = " 1700000000" }, expected: ErrAuthenticationFailed},
		{name: "timestamp decimal", mutate: func(value *Request) { value.timestampValues[0] = "1700000000.0" }, expected: ErrAuthenticationFailed},
		{name: "timestamp overflow", mutate: func(value *Request) { value.timestampValues[0] = "18446744073709551616" }, expected: ErrAuthenticationFailed},
		{name: "nonce padded", mutate: func(value *Request) { value.nonceValues[0] += "=" }, expected: ErrAuthenticationFailed},
		{name: "nonce short", mutate: func(value *Request) { value.nonceValues[0] = testOnlyNonce[:21] }, expected: ErrAuthenticationFailed},
		{name: "nonce alphabet", mutate: func(value *Request) { value.nonceValues[0] = "+" + testOnlyNonce[1:] }, expected: ErrAuthenticationFailed},
		{name: "nonce noncanonical", mutate: func(value *Request) { value.nonceValues[0] = testOnlyNonce[:21] + "x" }, expected: ErrAuthenticationFailed},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newTestFixture(t)
			request := valid
			request.authorizationValues = append([]string(nil), valid.authorizationValues...)
			request.timestampValues = append([]string(nil), valid.timestampValues...)
			request.nonceValues = append([]string(nil), valid.nonceValues...)
			test.mutate(&request)
			_, err := fixture.service(t).Authenticate(context.Background(), request)
			if !errors.Is(err, test.expected) {
				t.Fatal("invalid request error classification mismatch")
			}
			if len(fixture.recordedOrder()) != 0 {
				t.Fatal("invalid request called a dependency")
			}
		})
	}
}

func TestRequestDefensiveCopiesAndRedactedFormatting(t *testing.T) {
	authorization := []string{testOnlyAuthorization}
	timestamps := []string{testOnlyTimestamp}
	nonces := []string{testOnlyNonce}
	body := []byte(testOnlyBody)
	request := NewRequest("POST", testOnlyPath, testOnlyDeliveryIdentity, authorization, timestamps, nonces, body)
	authorization[0] = testOnlyRequestMarker
	timestamps[0] = testOnlyRequestMarker
	nonces[0] = testOnlyRequestMarker
	body[0] ^= 0xff

	fixture := newTestFixture(t)
	result, err := fixture.service(t).Authenticate(context.Background(), request)
	if err != nil || result.CorePrincipalID().IsZero() {
		t.Fatal("defensively copied request was not authenticated")
	}
	values := []any{request, &request, result, &result, fixture.secret, mustReplayNonce(t, testOnlyNonce)}
	for _, value := range values {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			if fmt.Sprintf(format, value) != "[redacted]" {
				t.Fatal("sensitive value formatting was not redacted")
			}
		}
	}
}

func TestServiceConfigurationAndContextFailClosed(t *testing.T) {
	fixture := newTestFixture(t)
	validService := fixture.service(t)
	var typedNil *typedNilBinding
	validBinding := audienceBindingFunc(func(context.Context) (securitystate.GatewayAudienceID, error) { return fixture.audience, nil })
	validCredential := credentialRegistryFunc(func(context.Context, securitystate.GatewayAudienceID, securitystate.CredentialID) (securitystate.Credential, error) {
		return fixture.credential, nil
	})
	validSecret := secretSourceFunc(func(context.Context, securitystate.GatewayAudienceID, securitystate.CredentialID) (securitystate.AuthenticationSecret, error) {
		return fixture.secret, nil
	})
	validPrincipal := principalRegistryFunc(func(context.Context, securitystate.GatewayAudienceID, securitystate.CorePrincipalID) (securitystate.Principal, error) {
		return fixture.principal, nil
	})
	validReplay := replayStoreFunc(func(context.Context, securitystate.CredentialRecordID, securitystate.ReplayNonce, time.Time) (securitystate.ReplayReservationDisposition, error) {
		return securitystate.ReplayReserved, nil
	})
	var nilCredential credentialRegistryFunc
	var nilSecret secretSourceFunc
	var nilPrincipal principalRegistryFunc
	var nilReplay replayStoreFunc
	configurations := []struct {
		binding    securitystate.AudienceBindingStore
		credential securitystate.CredentialRegistry
		secret     securitystate.AuthenticationSecretSource
		principal  securitystate.PrincipalRegistry
		replay     securitystate.ReplayReservationStore
		clock      func() time.Time
	}{
		{binding: typedNil, credential: validCredential, secret: validSecret, principal: validPrincipal, replay: validReplay, clock: func() time.Time { return fixture.now }},
		{binding: validBinding, credential: nilCredential, secret: validSecret, principal: validPrincipal, replay: validReplay, clock: func() time.Time { return fixture.now }},
		{binding: validBinding, credential: validCredential, secret: nilSecret, principal: validPrincipal, replay: validReplay, clock: func() time.Time { return fixture.now }},
		{binding: validBinding, credential: validCredential, secret: validSecret, principal: nilPrincipal, replay: validReplay, clock: func() time.Time { return fixture.now }},
		{binding: validBinding, credential: validCredential, secret: validSecret, principal: validPrincipal, replay: nilReplay, clock: func() time.Time { return fixture.now }},
		{binding: validBinding, credential: validCredential, secret: validSecret, principal: validPrincipal, replay: validReplay},
	}
	for _, configuration := range configurations {
		service, err := NewService(fixture.audience, configuration.binding, configuration.credential, configuration.secret, configuration.principal, configuration.replay, configuration.clock)
		if service != nil || !errors.Is(err, ErrConfigurationInvalid) {
			t.Fatal("nil or typed-nil configuration was accepted")
		}
	}
	if service, err := NewService(securitystate.GatewayAudienceID{}, validBinding, validCredential, validSecret, validPrincipal, validReplay, func() time.Time { return fixture.now }); service != nil || !errors.Is(err, ErrConfigurationInvalid) {
		t.Fatal("zero configured audience was accepted")
	}
	if _, err := (*Service)(nil).Authenticate(context.Background(), goldenRequest()); !errors.Is(err, ErrConfigurationInvalid) {
		t.Fatal("nil service classification mismatch")
	}
	if _, err := validService.Authenticate(nil, goldenRequest()); !errors.Is(err, ErrRequestInvalid) {
		t.Fatal("nil context classification mismatch")
	}
	var nilTypedContext *typedNilContext
	if _, err := validService.Authenticate(nilTypedContext, goldenRequest()); !errors.Is(err, ErrRequestInvalid) {
		t.Fatal("typed-nil context classification mismatch")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := validService.Authenticate(ctx, goldenRequest()); !errors.Is(err, ErrCanceled) {
		t.Fatal("canceled context classification mismatch")
	}
	deadlineContext, deadlineCancel := context.WithDeadline(context.Background(), time.Unix(1, 0))
	defer deadlineCancel()
	if _, err := validService.Authenticate(deadlineContext, goldenRequest()); !errors.Is(err, ErrCanceled) {
		t.Fatal("deadline context classification mismatch")
	}
}

func TestCancellationBetweenDependenciesStopsAuthentication(t *testing.T) {
	fixture := newTestFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	credentialCalls := 0
	service, err := NewService(
		fixture.audience,
		audienceBindingFunc(func(context.Context) (securitystate.GatewayAudienceID, error) {
			cancel()
			return fixture.audience, errors.New(testOnlyDependencyMarker)
		}),
		credentialRegistryFunc(func(context.Context, securitystate.GatewayAudienceID, securitystate.CredentialID) (securitystate.Credential, error) {
			credentialCalls++
			return fixture.credential, nil
		}),
		secretSourceFunc(func(context.Context, securitystate.GatewayAudienceID, securitystate.CredentialID) (securitystate.AuthenticationSecret, error) {
			return fixture.secret, nil
		}),
		principalRegistryFunc(func(context.Context, securitystate.GatewayAudienceID, securitystate.CorePrincipalID) (securitystate.Principal, error) {
			return fixture.principal, nil
		}),
		replayStoreFunc(func(context.Context, securitystate.CredentialRecordID, securitystate.ReplayNonce, time.Time) (securitystate.ReplayReservationDisposition, error) {
			return securitystate.ReplayReserved, nil
		}),
		func() time.Time { return fixture.now },
	)
	if err != nil {
		t.Fatal("cancellation test service setup failed")
	}
	if _, err := service.Authenticate(ctx, goldenRequest()); !errors.Is(err, ErrCanceled) || strings.Contains(err.Error(), testOnlyDependencyMarker) {
		t.Fatal("between-dependency cancellation classification mismatch")
	}
	if credentialCalls != 0 {
		t.Fatal("canceled authentication called the next dependency")
	}
}

func TestAudienceCredentialAndSecretBoundaries(t *testing.T) {
	tests := []struct {
		name          string
		configure     func(*testing.T, *testFixture)
		expected      error
		expectedOrder []string
	}{
		{name: "binding unavailable", configure: func(_ *testing.T, fixture *testFixture) { fixture.audienceErr = errors.New(testOnlyDependencyMarker) }, expected: ErrUnavailable, expectedOrder: []string{"clock", "audience"}},
		{name: "binding zero", configure: func(_ *testing.T, fixture *testFixture) { fixture.boundAudience = securitystate.GatewayAudienceID{} }, expected: ErrUnavailable, expectedOrder: []string{"clock", "audience"}},
		{name: "binding mismatch", configure: func(t *testing.T, fixture *testFixture) {
			fixture.boundAudience = mustAudience(t, testOnlyOtherAudience)
		}, expected: ErrUnavailable, expectedOrder: []string{"clock", "audience"}},
		{name: "credential unknown", configure: func(_ *testing.T, fixture *testFixture) { fixture.credentialErr = securitystate.ErrCredentialNotFound }, expected: ErrAuthenticationFailed, expectedOrder: []string{"clock", "audience", "credential"}},
		{name: "credential repository unavailable", configure: func(_ *testing.T, fixture *testFixture) { fixture.credentialErr = errors.New(testOnlyDependencyMarker) }, expected: ErrUnavailable, expectedOrder: []string{"clock", "audience", "credential"}},
		{name: "credential public mismatch", configure: func(t *testing.T, fixture *testFixture) {
			fixture.credential = mustCredential(t, fixture.audience, fixture.principal, testOnlyOtherCredential, securitystate.CredentialActive, fixture.now)
		}, expected: ErrAuthenticationFailed, expectedOrder: []string{"clock", "audience", "credential"}},
		{name: "credential audience mismatch", configure: func(t *testing.T, fixture *testFixture) {
			otherAudience := mustAudience(t, testOnlyOtherAudience)
			otherPrincipal := mustPrincipal(t, otherAudience, testOnlyPrincipal, true, true, fixture.now)
			fixture.credential = mustCredential(t, otherAudience, otherPrincipal, testOnlyCredential, securitystate.CredentialActive, fixture.now)
		}, expected: ErrAuthenticationFailed, expectedOrder: []string{"clock", "audience", "credential"}},
		{name: "credential malformed", configure: func(_ *testing.T, fixture *testFixture) {
			fixture.credential = securitystate.Credential{}
		}, expected: ErrAuthenticationFailed, expectedOrder: []string{"clock", "audience", "credential"}},
		{name: "credential disabled", configure: func(t *testing.T, fixture *testFixture) {
			fixture.credential = mustCredential(t, fixture.audience, fixture.principal, testOnlyCredential, securitystate.CredentialDisabled, fixture.now)
		}, expected: ErrAuthenticationFailed, expectedOrder: []string{"clock", "audience", "credential"}},
		{name: "credential revoked", configure: func(t *testing.T, fixture *testFixture) {
			fixture.credential = mustCredential(t, fixture.audience, fixture.principal, testOnlyCredential, securitystate.CredentialRevoked, fixture.now)
		}, expected: ErrAuthenticationFailed, expectedOrder: []string{"clock", "audience", "credential"}},
		{name: "secret unavailable", configure: func(_ *testing.T, fixture *testFixture) { fixture.secretErr = errors.New(testOnlyDependencyMarker) }, expected: ErrUnavailable, expectedOrder: []string{"clock", "audience", "credential", "secret"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newTestFixture(t)
			test.configure(t, fixture)
			service, err := NewService(fixture.audience,
				audienceBindingFunc(func(context.Context) (securitystate.GatewayAudienceID, error) {
					fixture.record("audience")
					return fixture.boundAudience, fixture.audienceErr
				}),
				credentialRegistryFunc(func(context.Context, securitystate.GatewayAudienceID, securitystate.CredentialID) (securitystate.Credential, error) {
					fixture.record("credential")
					return fixture.credential, fixture.credentialErr
				}),
				secretSourceFunc(func(context.Context, securitystate.GatewayAudienceID, securitystate.CredentialID) (securitystate.AuthenticationSecret, error) {
					fixture.record("secret")
					return fixture.secret, fixture.secretErr
				}),
				principalRegistryFunc(func(context.Context, securitystate.GatewayAudienceID, securitystate.CorePrincipalID) (securitystate.Principal, error) {
					fixture.record("principal")
					return fixture.principal, fixture.principalErr
				}),
				replayStoreFunc(func(context.Context, securitystate.CredentialRecordID, securitystate.ReplayNonce, time.Time) (securitystate.ReplayReservationDisposition, error) {
					fixture.record("replay")
					return fixture.replayResult, fixture.replayErr
				}),
				func() time.Time { fixture.record("clock"); return fixture.now },
			)
			if errors.Is(test.expected, ErrConfigurationInvalid) {
				if service != nil || !errors.Is(err, test.expected) {
					t.Fatal("configuration error classification mismatch")
				}
				return
			}
			if err != nil {
				t.Fatal("test service construction failed")
			}
			_, err = service.Authenticate(context.Background(), goldenRequest())
			if !errors.Is(err, test.expected) || errors.Is(err, errors.New(testOnlyDependencyMarker)) {
				t.Fatal("dependency error classification mismatch")
			}
			if !equalStrings(fixture.recordedOrder(), test.expectedOrder) {
				t.Fatal("dependency stop boundary mismatch")
			}
		})
	}
}

func TestCredentialLifecycleBoundaries(t *testing.T) {
	tests := []struct {
		name       string
		mutateSpec func(*securitystate.CredentialSpec, time.Time)
		wantOK     bool
	}{
		{name: "not before exact", mutateSpec: func(spec *securitystate.CredentialSpec, now time.Time) { spec.NotBefore = now }, wantOK: true},
		{name: "not before future", mutateSpec: func(spec *securitystate.CredentialSpec, now time.Time) { spec.NotBefore = now.Add(time.Second) }},
		{name: "activation exact", mutateSpec: func(spec *securitystate.CredentialSpec, now time.Time) {
			spec.ActivatedAt = now
			spec.StateChangedAt = now
		}, wantOK: true},
		{name: "expiry exact", mutateSpec: func(spec *securitystate.CredentialSpec, now time.Time) { spec.ExpiresAt = now }},
		{name: "retirement exact", mutateSpec: func(spec *securitystate.CredentialSpec, now time.Time) {
			spec.State = securitystate.CredentialRetiring
			spec.RetirementStartedAt = now.Add(-time.Minute)
			spec.RetirementDeadline = now
			spec.StateChangedAt = spec.RetirementStartedAt
		}},
		{name: "retiring before deadline", mutateSpec: func(spec *securitystate.CredentialSpec, now time.Time) {
			spec.State = securitystate.CredentialRetiring
			spec.RetirementStartedAt = now.Add(-time.Minute)
			spec.RetirementDeadline = now.Add(time.Second)
			spec.StateChangedAt = spec.RetirementStartedAt
		}, wantOK: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newTestFixture(t)
			spec := baseCredentialSpec(t, fixture.audience, fixture.principal, fixture.now)
			test.mutateSpec(&spec, fixture.now)
			credential, err := securitystate.NewCredential(spec)
			if err != nil {
				t.Fatal("credential lifecycle test setup failed")
			}
			fixture.credential = credential
			_, err = fixture.service(t).Authenticate(context.Background(), goldenRequest())
			if test.wantOK && err != nil {
				t.Fatal("valid credential boundary was rejected")
			}
			if !test.wantOK && !errors.Is(err, ErrAuthenticationFailed) {
				t.Fatal("invalid credential boundary was accepted")
			}
		})
	}
}

func TestHMACAndTimestampBoundaries(t *testing.T) {
	tests := []struct {
		name       string
		offset     int64
		mutate     func(*Request)
		wantOK     bool
		wantReplay bool
	}{
		{name: "minus sixty", offset: -60, wantOK: true, wantReplay: true},
		{name: "plus sixty", offset: 60, wantOK: true, wantReplay: true},
		{name: "minus sixty one", offset: -61},
		{name: "plus sixty one", offset: 61},
		{name: "body byte changed", mutate: func(request *Request) { request.rawBody[0] ^= 1 }},
		{name: "canonical path changed", mutate: func(request *Request) { request.path = strings.Replace(testOnlyPath, "AAE", "AQE", 1) }},
		{name: "delivery changed", mutate: func(request *Request) { request.deliveryIdentity = "21111111-2222-4333-8444-555555555555" }},
		{name: "nonce changed", mutate: func(request *Request) { request.nonceValues[0] = "ERITFBUWFxgZGhscHR4fIA" }},
		{name: "timestamp changed after signing", mutate: func(request *Request) { request.timestampValues[0] = "1700000001" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newTestFixture(t)
			timestamp := fmt.Sprintf("%d", fixture.now.Unix()+test.offset)
			request := testSignedRequest(t, testOnlyAudience, testOnlyCredential, testOnlyPath, testOnlyDeliveryIdentity, timestamp, testOnlyNonce, []byte(testOnlyBody), testOnlySecret)
			if test.mutate != nil {
				test.mutate(&request)
			}
			_, err := fixture.service(t).Authenticate(context.Background(), request)
			if test.wantOK && err != nil {
				t.Fatal("valid HMAC boundary was rejected")
			}
			if !test.wantOK && !errors.Is(err, ErrAuthenticationFailed) {
				t.Fatal("invalid HMAC boundary was accepted")
			}
			order := fixture.recordedOrder()
			hasReplay := containsString(order, "replay")
			if hasReplay != test.wantReplay {
				t.Fatal("HMAC or timestamp failure crossed replay boundary")
			}
			if fixture.clockCalls != 1 {
				t.Fatal("authentication attempt did not use one clock snapshot")
			}
		})
	}
}

func TestTimestampZeroIsCanonicalButOutsideCurrentWindow(t *testing.T) {
	fixture := newTestFixture(t)
	request := testSignedRequest(t, testOnlyAudience, testOnlyCredential, testOnlyPath, testOnlyDeliveryIdentity, "0", testOnlyNonce, []byte(testOnlyBody), testOnlySecret)
	_, err := fixture.service(t).Authenticate(context.Background(), request)
	if !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatal("canonical zero timestamp classification mismatch")
	}
	if got := fixture.recordedOrder(); !equalStrings(got, []string{"clock", "audience", "credential", "secret"}) {
		t.Fatal("zero timestamp was not checked after valid HMAC")
	}
}

func TestReplayAndPrincipalBoundaries(t *testing.T) {
	tests := []struct {
		name          string
		configure     func(*testing.T, *testFixture)
		expected      error
		principalCall bool
	}{
		{name: "duplicate", configure: func(_ *testing.T, fixture *testFixture) { fixture.replayResult = securitystate.ReplayDuplicate }, expected: ErrAuthenticationFailed},
		{name: "replay unavailable", configure: func(_ *testing.T, fixture *testFixture) { fixture.replayErr = securitystate.ErrReplayUnavailable }, expected: ErrUnavailable},
		{name: "replay unknown", configure: func(_ *testing.T, fixture *testFixture) { fixture.replayErr = securitystate.ErrReplayOutcomeUnknown }, expected: ErrUnavailable},
		{name: "illegal replay result", configure: func(_ *testing.T, fixture *testFixture) { fixture.replayResult = 99 }, expected: ErrUnavailable},
		{name: "principal disabled", configure: func(t *testing.T, fixture *testFixture) {
			fixture.principal = mustPrincipal(t, fixture.audience, testOnlyPrincipal, false, true, fixture.now)
		}, expected: ErrForbidden, principalCall: true},
		{name: "principal unauthorized", configure: func(t *testing.T, fixture *testFixture) {
			fixture.principal = mustPrincipal(t, fixture.audience, testOnlyPrincipal, true, false, fixture.now)
		}, expected: ErrForbidden, principalCall: true},
		{name: "principal ID mismatch", configure: func(t *testing.T, fixture *testFixture) {
			fixture.principal = mustPrincipal(t, fixture.audience, testOnlyOtherPrincipal, true, true, fixture.now)
		}, expected: ErrForbidden, principalCall: true},
		{name: "principal audience mismatch", configure: func(t *testing.T, fixture *testFixture) {
			fixture.principal = mustPrincipal(t, mustAudience(t, testOnlyOtherAudience), testOnlyPrincipal, true, true, fixture.now)
		}, expected: ErrForbidden, principalCall: true},
		{name: "principal unavailable", configure: func(_ *testing.T, fixture *testFixture) { fixture.principalErr = errors.New(testOnlyDependencyMarker) }, expected: ErrUnavailable, principalCall: true},
		{name: "principal explicitly forbidden", configure: func(_ *testing.T, fixture *testFixture) {
			fixture.principalErr = securitystate.ErrPrincipalNotAuthorized
		}, expected: ErrForbidden, principalCall: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newTestFixture(t)
			test.configure(t, fixture)
			_, err := fixture.service(t).Authenticate(context.Background(), goldenRequest())
			if !errors.Is(err, test.expected) {
				t.Fatal("replay or principal classification mismatch")
			}
			order := fixture.recordedOrder()
			if containsString(order, "principal") != test.principalCall {
				t.Fatal("principal lookup boundary mismatch")
			}
			if test.principalCall && (!containsString(order, "replay") || indexOf(order, "replay") > indexOf(order, "principal")) {
				t.Fatal("principal lookup occurred before reservation")
			}
		})
	}
}

func TestReplayUsesInternalRecordDecodedNonceAndClockSnapshot(t *testing.T) {
	fixture := newTestFixture(t)
	_, err := fixture.service(t).Authenticate(context.Background(), goldenRequest())
	if err != nil {
		t.Fatal("valid request was rejected")
	}
	if fixture.replayRecord != fixture.credential.RecordID() || fixture.replayTime != fixture.now {
		t.Fatal("replay reservation identity or time mismatch")
	}
	if fixture.replayNonce.Bytes() != mustReplayNonce(t, testOnlyNonce).Bytes() {
		t.Fatal("replay reservation nonce mismatch")
	}
	if fixture.credentialAudience != fixture.audience || fixture.secretAudience != fixture.audience || fixture.principalAudience != fixture.audience ||
		fixture.credentialArg != fixture.credential.PublicID() || fixture.secretArg != fixture.credential.PublicID() || fixture.principalArg != fixture.credential.PrincipalID() {
		t.Fatal("credential or principal lookup key mismatch")
	}
}

func TestAuthenticationDoesNotDecodeRawBody(t *testing.T) {
	fixture := newTestFixture(t)
	body := []byte{0x00, 0xff, '{', '\n'}
	request := testSignedRequest(t, testOnlyAudience, testOnlyCredential, testOnlyPath, testOnlyDeliveryIdentity, testOnlyTimestamp, testOnlyNonce, body, testOnlySecret)
	if _, err := fixture.service(t).Authenticate(context.Background(), request); err != nil {
		t.Fatal("exact non-JSON raw body was not authenticated")
	}
}

func TestConcurrentReplayAllowsAtMostOneSuccess(t *testing.T) {
	fixture := newTestFixture(t)
	var reserved bool
	var replayMutex sync.Mutex
	fixture.replayOverride = func(context.Context, securitystate.CredentialRecordID, securitystate.ReplayNonce, time.Time) (securitystate.ReplayReservationDisposition, error) {
		replayMutex.Lock()
		defer replayMutex.Unlock()
		if reserved {
			return securitystate.ReplayDuplicate, nil
		}
		reserved = true
		return securitystate.ReplayReserved, nil
	}
	service := fixture.service(t)
	const attempts = 24
	var successes atomic.Int32
	var failures atomic.Int32
	var wait sync.WaitGroup
	wait.Add(attempts)
	for range attempts {
		go func() {
			defer wait.Done()
			_, err := service.Authenticate(context.Background(), goldenRequest())
			switch {
			case err == nil:
				successes.Add(1)
			case errors.Is(err, ErrAuthenticationFailed):
				failures.Add(1)
			default:
				failures.Add(1000)
			}
		}()
	}
	wait.Wait()
	if successes.Load() != 1 || failures.Load() != attempts-1 {
		t.Fatal("concurrent replay reservation result mismatch")
	}
}

func TestSafeErrorsDiscardDependencyAndRequestContent(t *testing.T) {
	markerError := errors.New(testOnlyDependencyMarker)
	tests := []struct {
		name      string
		configure func(*testFixture)
		expected  error
	}{
		{name: "audience", configure: func(fixture *testFixture) { fixture.audienceErr = markerError }, expected: ErrUnavailable},
		{name: "credential", configure: func(fixture *testFixture) { fixture.credentialErr = markerError }, expected: ErrUnavailable},
		{name: "secret", configure: func(fixture *testFixture) { fixture.secretErr = markerError }, expected: ErrUnavailable},
		{name: "replay", configure: func(fixture *testFixture) { fixture.replayErr = markerError }, expected: ErrUnavailable},
		{name: "principal", configure: func(fixture *testFixture) { fixture.principalErr = markerError }, expected: ErrUnavailable},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newTestFixture(t)
			test.configure(fixture)
			_, err := fixture.service(t).Authenticate(context.Background(), goldenRequest())
			if !errors.Is(err, test.expected) || errors.Is(err, markerError) || strings.Contains(err.Error(), testOnlyDependencyMarker) {
				t.Fatal("dependency content leaked through safe error")
			}
		})
	}
	request := goldenRequest()
	request.path = "/" + testOnlyRequestMarker
	_, err := newTestFixture(t).service(t).Authenticate(context.Background(), request)
	if !errors.Is(err, ErrRequestInvalid) || strings.Contains(err.Error(), testOnlyRequestMarker) {
		t.Fatal("request content leaked through safe error")
	}
}

func baseCredentialSpec(t *testing.T, audience securitystate.GatewayAudienceID, principal securitystate.Principal, now time.Time) securitystate.CredentialSpec {
	t.Helper()
	slotID, err := securitystate.ParseCredentialSlotID(testOnlySlot)
	if err != nil {
		t.Fatal("test-only slot setup failed")
	}
	slot, err := securitystate.NewCredentialSlot(audience, principal, slotID, now.Add(-2*time.Hour))
	if err != nil {
		t.Fatal("test-only slot state setup failed")
	}
	recordID, err := securitystate.ParseCredentialRecordID(testOnlyRecord)
	if err != nil {
		t.Fatal("test-only record setup failed")
	}
	publicID, err := securitystate.ParseCredentialID(testOnlyCredential)
	if err != nil {
		t.Fatal("test-only public credential setup failed")
	}
	return securitystate.CredentialSpec{
		AudienceID:     audience,
		Principal:      principal,
		Slot:           slot,
		RecordID:       recordID,
		PublicID:       publicID,
		State:          securitystate.CredentialActive,
		NotBefore:      now.Add(-90 * time.Minute),
		ExpiresAt:      now.Add(90 * time.Minute),
		ActivatedAt:    now.Add(-time.Hour),
		CreatedAt:      now.Add(-2 * time.Hour),
		StateChangedAt: now.Add(-time.Hour),
	}
}

func mustReplayNonce(t *testing.T, text string) securitystate.ReplayNonce {
	t.Helper()
	nonce, err := securitystate.ParseReplayNonce(text)
	if err != nil {
		t.Fatal("test-only nonce setup failed")
	}
	return nonce
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func containsString(values []string, target string) bool {
	return indexOf(values, target) >= 0
}

func indexOf(values []string, target string) int {
	for index, value := range values {
		if value == target {
			return index
		}
	}
	return -1
}
