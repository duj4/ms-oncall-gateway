package securitystate

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	testAudienceID       = "11111111-2222-3333-8444-555555555555"
	testPrincipalID      = "22222222-3333-4444-8555-666666666666"
	testCredentialSlotID = "33333333-4444-5555-8666-777777777777"
	testCredentialRecord = "44444444-5555-6666-8777-888888888888"
	testCredentialID     = "55555555-6666-4777-8888-999999999999"
	testDestinationID    = "66666666-7777-8888-8999-aaaaaaaaaaaa"
	testTokenRecordID    = "77777777-8888-9999-8aaa-bbbbbbbbbbbb"
)

func TestUUIDValueTypes(t *testing.T) {
	tests := []struct {
		name      string
		canonical string
		parse     func(string) (string, error)
	}{
		{name: "audience", canonical: testAudienceID, parse: func(input string) (string, error) {
			value, err := ParseGatewayAudienceID(input)
			return value.String(), err
		}},
		{name: "principal", canonical: testPrincipalID, parse: func(input string) (string, error) {
			value, err := ParseCorePrincipalID(input)
			return value.String(), err
		}},
		{name: "slot", canonical: testCredentialSlotID, parse: func(input string) (string, error) {
			value, err := ParseCredentialSlotID(input)
			return value.String(), err
		}},
		{name: "credential record", canonical: testCredentialRecord, parse: func(input string) (string, error) {
			value, err := ParseCredentialRecordID(input)
			return value.String(), err
		}},
		{name: "credential", canonical: testCredentialID, parse: func(input string) (string, error) { value, err := ParseCredentialID(input); return value.String(), err }},
		{name: "destination", canonical: testDestinationID, parse: func(input string) (string, error) {
			value, err := ParseDestinationID(input)
			return value.String(), err
		}},
		{name: "token record", canonical: testTokenRecordID, parse: func(input string) (string, error) {
			value, err := ParseDestinationTokenRecordID(input)
			return value.String(), err
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got, err := test.parse(test.canonical); err != nil || got != test.canonical {
				t.Fatal("canonical UUID did not round trip")
			}
			for _, invalid := range []string{
				"A" + test.canonical[1:],
				"00000000-0000-0000-0000-000000000000",
				strings.ReplaceAll(test.canonical, "-", ""),
				"not-a-uuid",
			} {
				if _, err := test.parse(invalid); !errors.Is(err, ErrInvalidState) {
					t.Fatal("invalid UUID was accepted")
				}
			}
		})
	}
}

func TestCredentialIDRequiresUUIDv4AndRFCVariant(t *testing.T) {
	if _, err := ParseCredentialID(testCredentialID); err != nil {
		t.Fatal("valid credential UUIDv4 was rejected")
	}
	for _, invalid := range []string{
		"55555555-6666-1777-8888-999999999999",
		"55555555-6666-4777-7888-999999999999",
	} {
		if _, err := ParseCredentialID(invalid); !errors.Is(err, ErrInvalidState) {
			t.Fatal("invalid credential UUID version or variant was accepted")
		}
	}
}

func TestReplayNonceCanonicalEncodingAndDefensiveValue(t *testing.T) {
	raw := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	encoded := base64.RawURLEncoding.EncodeToString(raw[:])
	nonce, err := ParseReplayNonce(encoded)
	if err != nil || nonce.Bytes() != raw {
		t.Fatal("canonical replay nonce was rejected")
	}
	copyValue := nonce.Bytes()
	copyValue[0] ^= 0xff
	if nonce.Bytes() != raw {
		t.Fatal("replay nonce value was mutable through accessor")
	}
	for _, invalid := range []string{encoded + "=", encoded[:21], "%" + encoded[1:]} {
		if _, err := ParseReplayNonce(invalid); !errors.Is(err, ErrInvalidState) {
			t.Fatal("noncanonical replay nonce was accepted")
		}
	}
}

func TestOpaqueDestinationTokenCanonicalEncoding(t *testing.T) {
	raw := [32]byte{}
	for index := range raw {
		raw[index] = byte(index + 1)
	}
	body := base64.RawURLEncoding.EncodeToString(raw[:])
	token, err := ParseOpaqueDestinationToken(opaqueTokenPrefix + body)
	if err != nil || token.Bytes() != raw {
		t.Fatal("canonical opaque token was rejected")
	}
	copyValue := token.Bytes()
	copyValue[0] ^= 0xff
	if token.Bytes() != raw {
		t.Fatal("opaque token value was mutable through accessor")
	}
	for _, invalid := range []string{
		"MSO1_" + body,
		opaqueTokenPrefix + body + "=",
		opaqueTokenPrefix + body[:42],
		opaqueTokenPrefix + "%" + body[1:],
		"mso2_" + body,
	} {
		if _, err := ParseOpaqueDestinationToken(invalid); !errors.Is(err, ErrInvalidState) {
			t.Fatal("noncanonical opaque token was accepted")
		}
	}
}

func TestSensitiveValuesAreDefensivelyCopiedAndRedacted(t *testing.T) {
	marker := []byte("sensitive-test-marker-123456789")
	material := make([]byte, 32)
	copy(material, marker)
	verifier, err := NewTokenVerifier(material)
	if err != nil {
		t.Fatal("token verifier construction failed")
	}
	secret, err := NewAuthenticationSecret(material)
	if err != nil {
		t.Fatal("authentication secret construction failed")
	}
	keyMaterial := append(append([]byte(nil), material...), 1, 2, 3, 4)
	key, err := NewDestinationVerifierKey(keyMaterial)
	if err != nil {
		t.Fatal("destination verifier key construction failed")
	}
	authenticationKeyID, err := NewAuthenticationKeyID("sensitive-test-marker")
	if err != nil {
		t.Fatal("authentication key ID construction failed")
	}
	verifierKeyID, err := NewDestinationVerifierKeyID("sensitive-test-marker")
	if err != nil {
		t.Fatal("verifier key ID construction failed")
	}
	nonceBytes := make([]byte, 16)
	copy(nonceBytes, marker)
	nonce, err := ParseReplayNonce(base64.RawURLEncoding.EncodeToString(nonceBytes))
	if err != nil {
		t.Fatal("replay nonce construction failed")
	}
	tokenBytes := make([]byte, 32)
	copy(tokenBytes, marker)
	token, err := ParseOpaqueDestinationToken(opaqueTokenPrefix + base64.RawURLEncoding.EncodeToString(tokenBytes))
	if err != nil {
		t.Fatal("opaque token construction failed")
	}

	material[0] ^= 0xff
	keyMaterial[0] ^= 0xff
	if verifier.Bytes()[0] == material[0] || secret.Bytes()[0] == material[0] || key.Bytes()[0] == keyMaterial[0] {
		t.Fatal("constructor retained mutable input")
	}
	returned := key.Bytes()
	returned[0] ^= 0xff
	if returned[0] == key.Bytes()[0] {
		t.Fatal("destination verifier key accessor exposed mutable storage")
	}

	values := []any{
		mustAudience(t), mustPrincipalID(t), mustCredentialSlotID(t),
		mustCredentialRecordID(t), mustCredentialID(t), mustDestinationID(t),
		mustDestinationTokenRecordID(t), nonce, token, verifier, secret, key,
		authenticationKeyID, verifierKeyID,
	}
	for _, value := range values {
		for _, formatted := range []string{fmt.Sprintf("%v", value), fmt.Sprintf("%+v", value), fmt.Sprintf("%#v", value)} {
			if formatted != "[redacted]" || strings.Contains(formatted, "sensitive-test-marker") {
				t.Fatal("sensitive value formatting was not redacted")
			}
		}
		formattedError := fmt.Errorf("security state failure: %v", value)
		if formattedError.Error() != "security state failure: [redacted]" || strings.Contains(formattedError.Error(), "sensitive-test-marker") {
			t.Fatal("sensitive value error formatting was not redacted")
		}
	}
}

func TestSensitiveValueSizeAndKeyIDValidation(t *testing.T) {
	if verifier, err := NewTokenVerifier(make([]byte, 32)); err != nil || verifier.IsZero() {
		t.Fatal("exact-size all-zero verifier was not represented as present")
	}
	for _, size := range []int{0, 31, 33} {
		if _, err := NewTokenVerifier(make([]byte, size)); !errors.Is(err, ErrInvalidState) {
			t.Fatal("invalid token verifier size was accepted")
		}
		if _, err := NewAuthenticationSecret(make([]byte, size)); !errors.Is(err, ErrInvalidState) {
			t.Fatal("invalid authentication secret size was accepted")
		}
	}
	if _, err := NewDestinationVerifierKey(make([]byte, 31)); !errors.Is(err, ErrInvalidState) {
		t.Fatal("short destination verifier key was accepted")
	}
	for _, invalid := range []string{"", strings.Repeat("k", keyIDMaxBytes+1), string([]byte{0xff})} {
		if _, err := NewAuthenticationKeyID(invalid); !errors.Is(err, ErrInvalidState) {
			t.Fatal("invalid authentication key ID was accepted")
		}
		if _, err := NewDestinationVerifierKeyID(invalid); !errors.Is(err, ErrInvalidState) {
			t.Fatal("invalid verifier key ID was accepted")
		}
	}
}

func TestPrincipalAndAudienceBinding(t *testing.T) {
	audience := mustAudience(t)
	principalID := mustPrincipalID(t)
	now := time.Unix(1_800_000_000, 0).UTC()
	principal, err := NewPrincipal(audience, principalID, true, true, now, now)
	if err != nil || !principal.AuthorizesIntake(audience) {
		t.Fatal("enabled intake principal was not authorized")
	}
	differentAudience, err := ParseGatewayAudienceID("88888888-9999-aaaa-8bbb-cccccccccccc")
	if err != nil {
		t.Fatal("test audience construction failed")
	}
	if principal.AuthorizesIntake(differentAudience) {
		t.Fatal("principal authorized a different audience")
	}
	for _, flags := range [][2]bool{{false, true}, {true, false}, {false, false}} {
		value, createErr := NewPrincipal(audience, principalID, flags[0], flags[1], now, now)
		if createErr != nil || value.AuthorizesIntake(audience) {
			t.Fatal("disabled or unauthorized principal authorized intake")
		}
	}
	if _, err := NewPrincipal(GatewayAudienceID{}, principalID, true, true, now, now); !errors.Is(err, ErrInvalidState) {
		t.Fatal("zero-audience principal was accepted")
	}
}

func TestZeroValueRecordsAndInvalidTimeOrderingFailClosed(t *testing.T) {
	audience := mustAudience(t)
	principalID := mustPrincipalID(t)
	created := time.Unix(1_800_000_000, 0).UTC()

	if _, err := NewPrincipal(audience, principalID, true, true, created, created.Add(-time.Nanosecond)); !errors.Is(err, ErrInvalidState) {
		t.Fatal("principal with invalid state time was accepted")
	}
	principal := mustPrincipal(t, audience)
	if _, err := NewCredentialSlot(audience, principal, CredentialSlotID{}, created); !errors.Is(err, ErrInvalidState) {
		t.Fatal("zero credential slot record was accepted")
	}
	if _, err := NewDestination(audience, DestinationID{}, DestinationEnabled, created, created); !errors.Is(err, ErrInvalidState) {
		t.Fatal("zero destination record was accepted")
	}
	if _, err := NewDestination(audience, mustDestinationID(t), DestinationState(255), created, created); !errors.Is(err, ErrInvalidState) {
		t.Fatal("destination with invalid state was accepted")
	}
	if _, err := NewDestination(audience, mustDestinationID(t), DestinationEnabled, created, created.Add(-time.Nanosecond)); !errors.Is(err, ErrInvalidState) {
		t.Fatal("destination with invalid state time was accepted")
	}

	credential := validCredentialSpec(t, CredentialActive)
	credential.NotBefore = credential.CreatedAt.Add(-time.Nanosecond)
	if _, err := NewCredential(credential); !errors.Is(err, ErrInvalidState) {
		t.Fatal("credential with invalid not-before ordering was accepted")
	}
	credential = validCredentialSpec(t, CredentialActive)
	credential.ExpiresAt = credential.NotBefore
	if _, err := NewCredential(credential); !errors.Is(err, ErrInvalidState) {
		t.Fatal("credential with nonpositive lifetime was accepted")
	}
	credential = validCredentialSpec(t, CredentialActive)
	credential.StateChangedAt = credential.CreatedAt.Add(-time.Nanosecond)
	if _, err := NewCredential(credential); !errors.Is(err, ErrInvalidState) {
		t.Fatal("credential with invalid state time was accepted")
	}
	for _, state := range []CredentialState{CredentialActive, CredentialRetiring} {
		credential = validCredentialSpec(t, state)
		credential.ActivatedAt = credential.CreatedAt.Add(-time.Nanosecond)
		if _, err := NewCredential(credential); !errors.Is(err, ErrInvalidState) {
			t.Fatal("credential activated before creation was accepted")
		}
	}

	token := validTokenSpec(t, DestinationTokenActive)
	token.ExpiresAt = token.CreatedAt
	if _, err := NewDestinationToken(token); !errors.Is(err, ErrInvalidState) {
		t.Fatal("token with nonpositive lifetime was accepted")
	}
	token = validTokenSpec(t, DestinationTokenActive)
	token.StagedCleanupDeadline = token.CreatedAt
	if _, err := NewDestinationToken(token); !errors.Is(err, ErrInvalidState) {
		t.Fatal("token with nonpositive staged cleanup interval was accepted")
	}
	token = validTokenSpec(t, DestinationTokenActive)
	token.StateChangedAt = token.CreatedAt.Add(-time.Nanosecond)
	if _, err := NewDestinationToken(token); !errors.Is(err, ErrInvalidState) {
		t.Fatal("token with invalid state time was accepted")
	}
}

func TestCredentialStaticInvariantsAndTimeBoundaries(t *testing.T) {
	base := validCredentialSpec(t, CredentialActive)
	credential, err := NewCredential(base)
	if err != nil {
		t.Fatal("valid active credential was rejected")
	}
	if credential.UsableAt(base.NotBefore.Add(-time.Nanosecond)) || !credential.UsableAt(base.NotBefore) || credential.UsableAt(base.ExpiresAt) {
		t.Fatal("credential not-before or expiry boundary is incorrect")
	}

	maxLifetime := base
	maxLifetime.ExpiresAt = maxLifetime.NotBefore.Add(credentialMaxLifetime)
	if _, err := NewCredential(maxLifetime); err != nil {
		t.Fatal("inclusive credential lifetime maximum was rejected")
	}
	tooLong := maxLifetime
	tooLong.ExpiresAt = tooLong.ExpiresAt.Add(time.Nanosecond)
	if _, err := NewCredential(tooLong); !errors.Is(err, ErrInvalidState) {
		t.Fatal("credential lifetime above maximum was accepted")
	}

	retiring := validCredentialSpec(t, CredentialRetiring)
	value, err := NewCredential(retiring)
	if err != nil || !value.UsableAt(retiring.RetirementDeadline.Add(-time.Nanosecond)) || value.UsableAt(retiring.RetirementDeadline) {
		t.Fatal("credential retirement boundary is incorrect")
	}
	retiring.RetirementDeadline = retiring.RetirementStartedAt.Add(credentialMaxOverlap + time.Nanosecond)
	if _, err := NewCredential(retiring); !errors.Is(err, ErrInvalidState) {
		t.Fatal("credential overlap above maximum was accepted")
	}

	for _, state := range []CredentialState{CredentialDisabled, CredentialRevoked} {
		value, createErr := NewCredential(validCredentialSpec(t, state))
		if createErr != nil || value.UsableAt(base.NotBefore) {
			t.Fatal("disabled or revoked credential was usable")
		}
	}
	invalid := base
	invalid.State = CredentialState(255)
	if _, err := NewCredential(invalid); !errors.Is(err, ErrInvalidState) {
		t.Fatal("invalid credential state was accepted")
	}
}

func TestCredentialRejectsAudienceMismatchAndZeroRecords(t *testing.T) {
	spec := validCredentialSpec(t, CredentialActive)
	other, err := ParseGatewayAudienceID("88888888-9999-aaaa-8bbb-cccccccccccc")
	if err != nil {
		t.Fatal("test audience construction failed")
	}
	spec.AudienceID = other
	if _, err := NewCredential(spec); !errors.Is(err, ErrAudienceMismatch) {
		t.Fatal("credential audience mismatch was not rejected")
	}
	spec = validCredentialSpec(t, CredentialActive)
	spec.RecordID = CredentialRecordID{}
	if _, err := NewCredential(spec); !errors.Is(err, ErrInvalidState) {
		t.Fatal("zero credential record was accepted")
	}
}

func TestDestinationAndTokenStaticInvariants(t *testing.T) {
	active := validTokenSpec(t, DestinationTokenActive)
	token, err := NewDestinationToken(active)
	if err != nil || token.UsableAt(active.ActivatedAt.Add(-time.Nanosecond)) || !token.UsableAt(active.ActivatedAt) || token.UsableAt(active.ExpiresAt) {
		t.Fatal("active token time boundaries are incorrect")
	}

	maxLifetime := active
	maxLifetime.ExpiresAt = maxLifetime.CreatedAt.Add(tokenMaxLifetime)
	if _, err := NewDestinationToken(maxLifetime); err != nil {
		t.Fatal("inclusive token lifetime maximum was rejected")
	}
	tooLong := maxLifetime
	tooLong.ExpiresAt = tooLong.ExpiresAt.Add(time.Nanosecond)
	if _, err := NewDestinationToken(tooLong); !errors.Is(err, ErrInvalidState) {
		t.Fatal("token lifetime above maximum was accepted")
	}

	maxCleanup := active
	maxCleanup.StagedCleanupDeadline = maxCleanup.CreatedAt.Add(tokenMaxCleanup)
	if _, err := NewDestinationToken(maxCleanup); err != nil {
		t.Fatal("inclusive staged cleanup maximum was rejected")
	}
	tooLateCleanup := maxCleanup
	tooLateCleanup.StagedCleanupDeadline = tooLateCleanup.StagedCleanupDeadline.Add(time.Nanosecond)
	if _, err := NewDestinationToken(tooLateCleanup); !errors.Is(err, ErrInvalidState) {
		t.Fatal("staged cleanup above maximum was accepted")
	}

	retiring := validTokenSpec(t, DestinationTokenRetiring)
	retiringToken, err := NewDestinationToken(retiring)
	if err != nil || !retiringToken.UsableAt(retiring.RetirementDeadline.Add(-time.Nanosecond)) || retiringToken.UsableAt(retiring.RetirementDeadline) {
		t.Fatal("retiring token overlap boundary is incorrect")
	}
	retiring.RetirementDeadline = retiring.RetirementStartedAt.Add(tokenMaxOverlap + time.Nanosecond)
	if _, err := NewDestinationToken(retiring); !errors.Is(err, ErrInvalidState) {
		t.Fatal("token overlap above maximum was accepted")
	}

	for _, state := range []DestinationTokenState{DestinationTokenStaged, DestinationTokenRevoked} {
		value, createErr := NewDestinationToken(validTokenSpec(t, state))
		if createErr != nil || value.UsableAt(active.ActivatedAt) {
			t.Fatal("staged or revoked token was usable")
		}
	}
}

func TestDestinationTokenRejectsAudienceMismatchMissingVerifierAndInvalidState(t *testing.T) {
	spec := validTokenSpec(t, DestinationTokenActive)
	other, err := ParseGatewayAudienceID("88888888-9999-aaaa-8bbb-cccccccccccc")
	if err != nil {
		t.Fatal("test audience construction failed")
	}
	spec.AudienceID = other
	if _, err := NewDestinationToken(spec); !errors.Is(err, ErrAudienceMismatch) {
		t.Fatal("token audience mismatch was not rejected")
	}
	spec = validTokenSpec(t, DestinationTokenActive)
	spec.Verifier = TokenVerifier{}
	if _, err := NewDestinationToken(spec); !errors.Is(err, ErrInvalidState) {
		t.Fatal("missing token verifier was accepted")
	}
	spec = validTokenSpec(t, DestinationTokenActive)
	spec.VerifierKeyID = DestinationVerifierKeyID{}
	if _, err := NewDestinationToken(spec); !errors.Is(err, ErrInvalidState) {
		t.Fatal("missing verifier key ID was accepted")
	}
	spec = validTokenSpec(t, DestinationTokenActive)
	spec.State = DestinationTokenState(255)
	if _, err := NewDestinationToken(spec); !errors.Is(err, ErrInvalidState) {
		t.Fatal("invalid token state was accepted")
	}
}

func TestConcurrentValueReadsAreRaceSafe(t *testing.T) {
	credential, err := NewCredential(validCredentialSpec(t, CredentialRetiring))
	if err != nil {
		t.Fatal("credential fixture construction failed")
	}
	token, err := NewDestinationToken(validTokenSpec(t, DestinationTokenRetiring))
	if err != nil {
		t.Fatal("token fixture construction failed")
	}
	now := time.Unix(1_800_000_100, 0).UTC()
	var wait sync.WaitGroup
	for range 16 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for range 100 {
				_ = credential.UsableAt(now)
				_ = token.UsableAt(now)
				_ = credential.RecordID()
				_ = token.RecordID()
			}
		}()
	}
	wait.Wait()
}

func TestSentinelErrorsAreFixedAndContentFree(t *testing.T) {
	for _, err := range []error{
		ErrInvalidState, ErrAudienceMismatch, ErrAudienceUnavailable,
		ErrCredentialNotFound, ErrSecretUnavailable, ErrPrincipalNotAuthorized,
		ErrReplayUnavailable, ErrReplayOutcomeUnknown, ErrDestinationNotFound,
		ErrVerifierKeyUnavailable,
	} {
		if err == nil || strings.Contains(err.Error(), "sensitive-test-marker") {
			t.Fatal("sentinel error was not fixed and content-free")
		}
	}
}

type interfaceFake struct{}

func (interfaceFake) BoundAudience(context.Context) (GatewayAudienceID, error) {
	return GatewayAudienceID{}, ErrAudienceUnavailable
}
func (interfaceFake) Credential(context.Context, GatewayAudienceID, CredentialID) (Credential, error) {
	return Credential{}, ErrCredentialNotFound
}
func (interfaceFake) AuthenticationSecret(context.Context, GatewayAudienceID, CredentialID) (AuthenticationSecret, error) {
	return AuthenticationSecret{}, ErrSecretUnavailable
}
func (interfaceFake) Principal(context.Context, GatewayAudienceID, CorePrincipalID) (Principal, error) {
	return Principal{}, ErrPrincipalNotAuthorized
}
func (interfaceFake) Reserve(context.Context, CredentialRecordID, ReplayNonce, time.Time) (ReplayReservationDisposition, error) {
	return 0, ErrReplayUnavailable
}
func (interfaceFake) Resolve(context.Context, GatewayAudienceID, OpaqueDestinationToken, time.Time) (DestinationID, error) {
	return DestinationID{}, ErrDestinationNotFound
}
func (interfaceFake) DestinationVerifierKey(context.Context, GatewayAudienceID, DestinationVerifierKeyID) (DestinationVerifierKey, error) {
	return DestinationVerifierKey{}, ErrVerifierKeyUnavailable
}

func TestNarrowInterfacesSupportTransportIndependentFakes(t *testing.T) {
	var _ AudienceBindingStore = interfaceFake{}
	var _ CredentialRegistry = interfaceFake{}
	var _ AuthenticationSecretSource = interfaceFake{}
	var _ PrincipalRegistry = interfaceFake{}
	var _ ReplayReservationStore = interfaceFake{}
	var _ DestinationResolver = interfaceFake{}
	var _ DestinationVerifierKeySource = interfaceFake{}
	if ReplayReserved == ReplayDuplicate || ReplayReserved == 0 || ReplayDuplicate == 0 {
		t.Fatal("replay reservation dispositions are invalid")
	}
}

func validCredentialSpec(t *testing.T, state CredentialState) CredentialSpec {
	t.Helper()
	audience := mustAudience(t)
	principal := mustPrincipal(t, audience)
	slotID, err := ParseCredentialSlotID(testCredentialSlotID)
	if err != nil {
		t.Fatal("credential slot ID fixture construction failed")
	}
	created := time.Unix(1_800_000_000, 0).UTC()
	slot, err := NewCredentialSlot(audience, principal, slotID, created)
	if err != nil {
		t.Fatal("credential slot fixture construction failed")
	}
	recordID, err := ParseCredentialRecordID(testCredentialRecord)
	if err != nil {
		t.Fatal("credential record fixture construction failed")
	}
	publicID, err := ParseCredentialID(testCredentialID)
	if err != nil {
		t.Fatal("credential public ID fixture construction failed")
	}
	spec := CredentialSpec{
		AudienceID:     audience,
		Principal:      principal,
		Slot:           slot,
		RecordID:       recordID,
		PublicID:       publicID,
		State:          state,
		CreatedAt:      created,
		NotBefore:      created,
		ExpiresAt:      created.Add(30 * 24 * time.Hour),
		StateChangedAt: created,
	}
	switch state {
	case CredentialActive:
		spec.ActivatedAt = created
	case CredentialRetiring:
		spec.ActivatedAt = created
		spec.RetirementStartedAt = created.Add(time.Hour)
		spec.RetirementDeadline = spec.RetirementStartedAt.Add(credentialMaxOverlap)
	case CredentialRevoked:
		spec.RevokedAt = created.Add(time.Hour)
	}
	return spec
}

func validTokenSpec(t *testing.T, state DestinationTokenState) DestinationTokenSpec {
	t.Helper()
	audience := mustAudience(t)
	destinationID, err := ParseDestinationID(testDestinationID)
	if err != nil {
		t.Fatal("destination ID fixture construction failed")
	}
	created := time.Unix(1_800_000_000, 0).UTC()
	destination, err := NewDestination(audience, destinationID, DestinationEnabled, created, created)
	if err != nil {
		t.Fatal("destination fixture construction failed")
	}
	recordID, err := ParseDestinationTokenRecordID(testTokenRecordID)
	if err != nil {
		t.Fatal("token record ID fixture construction failed")
	}
	verifierBytes := make([]byte, 32)
	for index := range verifierBytes {
		verifierBytes[index] = byte(index + 1)
	}
	verifier, err := NewTokenVerifier(verifierBytes)
	if err != nil {
		t.Fatal("token verifier fixture construction failed")
	}
	keyID, err := NewDestinationVerifierKeyID("test-only-key")
	if err != nil {
		t.Fatal("verifier key ID fixture construction failed")
	}
	spec := DestinationTokenSpec{
		AudienceID:            audience,
		Destination:           destination,
		RecordID:              recordID,
		Verifier:              verifier,
		VerifierKeyID:         keyID,
		State:                 state,
		CreatedAt:             created,
		ExpiresAt:             created.Add(30 * 24 * time.Hour),
		StagedCleanupDeadline: created.Add(tokenMaxCleanup),
		StateChangedAt:        created,
	}
	switch state {
	case DestinationTokenActive:
		spec.ActivatedAt = created
	case DestinationTokenRetiring:
		spec.ActivatedAt = created
		spec.RetirementStartedAt = created.Add(time.Hour)
		spec.RetirementDeadline = spec.RetirementStartedAt.Add(tokenMaxOverlap)
	case DestinationTokenRevoked:
		spec.RevokedAt = created.Add(time.Hour)
	}
	return spec
}

func mustAudience(t *testing.T) GatewayAudienceID {
	t.Helper()
	value, err := ParseGatewayAudienceID(testAudienceID)
	if err != nil {
		t.Fatal("audience fixture construction failed")
	}
	return value
}

func mustPrincipalID(t *testing.T) CorePrincipalID {
	t.Helper()
	value, err := ParseCorePrincipalID(testPrincipalID)
	if err != nil {
		t.Fatal("principal ID fixture construction failed")
	}
	return value
}

func mustCredentialSlotID(t *testing.T) CredentialSlotID {
	t.Helper()
	value, err := ParseCredentialSlotID(testCredentialSlotID)
	if err != nil {
		t.Fatal("credential slot ID fixture construction failed")
	}
	return value
}

func mustCredentialRecordID(t *testing.T) CredentialRecordID {
	t.Helper()
	value, err := ParseCredentialRecordID(testCredentialRecord)
	if err != nil {
		t.Fatal("credential record ID fixture construction failed")
	}
	return value
}

func mustCredentialID(t *testing.T) CredentialID {
	t.Helper()
	value, err := ParseCredentialID(testCredentialID)
	if err != nil {
		t.Fatal("credential ID fixture construction failed")
	}
	return value
}

func mustDestinationID(t *testing.T) DestinationID {
	t.Helper()
	value, err := ParseDestinationID(testDestinationID)
	if err != nil {
		t.Fatal("destination ID fixture construction failed")
	}
	return value
}

func mustDestinationTokenRecordID(t *testing.T) DestinationTokenRecordID {
	t.Helper()
	value, err := ParseDestinationTokenRecordID(testTokenRecordID)
	if err != nil {
		t.Fatal("destination token record ID fixture construction failed")
	}
	return value
}

func mustPrincipal(t *testing.T, audience GatewayAudienceID) Principal {
	t.Helper()
	now := time.Unix(1_800_000_000, 0).UTC()
	value, err := NewPrincipal(audience, mustPrincipalID(t), true, true, now, now)
	if err != nil {
		t.Fatal("principal fixture construction failed")
	}
	return value
}
