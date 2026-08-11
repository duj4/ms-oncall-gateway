package protection

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"io"
	"sync"
	"testing"

	"github.com/duj4/ms-oncall-gateway/internal/durable"
	"github.com/duj4/ms-oncall-gateway/internal/httpapi"
)

const (
	testPrincipal   = "core-test"
	testDestination = "destination-test"
	testKeyID       = "key-v1-test"
)

var testIdentity = durable.DeliveryIdentity{
	0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x46, 0x77,
	0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
}

type memoryKeySource struct {
	mu        sync.RWMutex
	active    Key
	byID      map[string]Key
	activeErr error
	lookupErr error
}

func (source *memoryKeySource) ActiveKey(context.Context) (Key, error) {
	source.mu.RLock()
	defer source.mu.RUnlock()
	return source.active, source.activeErr
}

func (source *memoryKeySource) KeyByID(_ context.Context, id string) (Key, error) {
	source.mu.RLock()
	defer source.mu.RUnlock()
	if source.lookupErr != nil {
		return Key{}, source.lookupErr
	}
	return source.byID[id], nil
}

func (source *memoryKeySource) setActive(key Key) {
	source.mu.Lock()
	defer source.mu.Unlock()
	source.active = key
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) {
	return 0, errors.New("sensitive random source detail")
}

func testKeyMaterial(seed byte) []byte {
	material := make([]byte, aes256KeySize)
	for index := range material {
		material[index] = seed + byte(index)
	}
	return material
}

func mustKey(t *testing.T, id string, material []byte) Key {
	t.Helper()
	key, err := NewKey(id, material)
	if err != nil {
		t.Fatal("test key setup failed")
	}
	return key
}

func mustCanonicalEvent(t *testing.T) httpapi.CanonicalEvent {
	t.Helper()
	event, err := httpapi.CanonicalizeEvent(httpapi.TestEvent{AppName: "MS OnCall"})
	if err != nil {
		t.Fatal("canonical event setup failed")
	}
	return event
}

func mustDecodeHex(t *testing.T, encoded string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(encoded)
	if err != nil {
		t.Fatal("golden vector setup failed")
	}
	return decoded
}

func newTestKeySource(t *testing.T) (*memoryKeySource, Key) {
	t.Helper()
	key := mustKey(t, testKeyID, testKeyMaterial(0))
	return &memoryKeySource{active: key, byID: map[string]Key{testKeyID: key}}, key
}

func deterministicNonces(first, second byte) []byte {
	data := make([]byte, gcmNonceSize*2)
	for index := 0; index < gcmNonceSize; index++ {
		data[index] = first + byte(index)
		data[gcmNonceSize+index] = second + byte(index)
	}
	return data
}

func mustPrepare(t *testing.T, service *Service) durable.PreparedAcceptance {
	t.Helper()
	prepared, err := service.Prepare(
		context.Background(),
		testPrincipal,
		testDestination,
		testIdentity,
		mustCanonicalEvent(t),
	)
	if err != nil {
		t.Fatal("payload protection setup failed")
	}
	return prepared
}

func digestOpenRequest(prepared durable.PreparedAcceptance) durable.DigestOpenRequest {
	return durable.DigestOpenRequest{
		ProtectedDigest:  prepared.ProtectedDigest(),
		EncryptionKeyID:  prepared.EncryptionKeyID(),
		CorePrincipalID:  prepared.CorePrincipalID(),
		DestinationID:    prepared.DestinationID(),
		DeliveryIdentity: prepared.DeliveryIdentity(),
		FormatVersion:    prepared.FormatVersion(),
	}
}

func preparedIsZero(prepared durable.PreparedAcceptance) bool {
	return prepared.CorePrincipalID() == "" &&
		prepared.DestinationID() == "" &&
		prepared.DeliveryIdentity().IsZero() &&
		prepared.FormatVersion() == 0 &&
		len(prepared.CanonicalEvent().Ciphertext()) == 0 &&
		len(prepared.ProtectedDigest().Ciphertext()) == 0 &&
		prepared.EncryptionKeyID() == "" &&
		prepared.EquivalenceDigest() == (durable.CanonicalDigest{})
}

func mutatedProtected(t *testing.T, value durable.ProtectedValue, mutateCiphertext bool) durable.ProtectedValue {
	t.Helper()
	ciphertext := value.Ciphertext()
	nonce := value.Nonce()
	if mutateCiphertext {
		ciphertext[0] ^= 1
	} else {
		nonce[0] ^= 1
	}
	mutated, err := durable.NewProtectedValue(ciphertext, nonce)
	if err != nil {
		t.Fatal("protected value mutation setup failed")
	}
	return mutated
}

func TestPayloadProtectionV1GoldenVector(t *testing.T) {
	keyMaterial := mustDecodeHex(t, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	key := mustKey(t, testKeyID, keyMaterial)
	keys := &memoryKeySource{active: key, byID: map[string]Key{testKeyID: key}}
	nonces := mustDecodeHex(t, "000102030405060708090a0b0c0d0e0f1011121314151617")
	service := NewServiceWithRandomSource(keys, bytes.NewReader(nonces))
	canonical := mustCanonicalEvent(t)

	prepared, err := service.Prepare(context.Background(), testPrincipal, testDestination, testIdentity, canonical)
	if err != nil {
		t.Fatal("golden vector preparation failed")
	}

	eventAAD, err := buildAAD(purposeEvent, canonical.FormatVersion(), testIdentity, testPrincipal, testDestination, testKeyID)
	if err != nil {
		t.Fatal("event AAD construction failed")
	}
	digestAAD, err := buildAAD(purposeDigest, canonical.FormatVersion(), testIdentity, testPrincipal, testDestination, testKeyID)
	if err != nil {
		t.Fatal("digest AAD construction failed")
	}
	expectedEventAAD := mustDecodeHex(t, "4d535f4f4e43414c4c5f474154455741595f5041594c4f41445f50524f54454354494f4e00000000000000000101000000000000000100112233445546778899aabbccddeeff00000009636f72652d746573740000001064657374696e6174696f6e2d746573740000000b6b65792d76312d74657374")
	expectedDigestAAD := mustDecodeHex(t, "4d535f4f4e43414c4c5f474154455741595f5041594c4f41445f50524f54454354494f4e00000000000000000102000000000000000100112233445546778899aabbccddeeff00000009636f72652d746573740000001064657374696e6174696f6e2d746573740000000b6b65792d76312d74657374")
	if !bytes.Equal(eventAAD, expectedEventAAD) || !bytes.Equal(digestAAD, expectedDigestAAD) || bytes.Equal(eventAAD, digestAAD) {
		t.Fatal("golden AAD mismatch")
	}

	expectedEventCiphertext := mustDecodeHex(t, "3c20976bb5aba376e863ada9fcba5822ed95e6589c59735e6c1e95e03f5322e66463daded2aeb8d926826580ae2aee3e9411bc09f5")
	expectedDigestCiphertext := mustDecodeHex(t, "6a51f4177a76a74104383bf4fd513ce1c3f3d5fa96b84b5901f39f391dd09645c65effb5e6d6df20de304073b76aa019")
	if !bytes.Equal(prepared.CanonicalEvent().Ciphertext(), expectedEventCiphertext) ||
		!bytes.Equal(prepared.ProtectedDigest().Ciphertext(), expectedDigestCiphertext) {
		t.Fatal("golden ciphertext mismatch")
	}
	if !bytes.Equal(prepared.CanonicalEvent().Nonce(), nonces[:gcmNonceSize]) ||
		!bytes.Equal(prepared.ProtectedDigest().Nonce(), nonces[gcmNonceSize:]) ||
		bytes.Equal(prepared.CanonicalEvent().Nonce(), prepared.ProtectedDigest().Nonce()) {
		t.Fatal("golden nonce mismatch")
	}
	if len(prepared.CanonicalEvent().Ciphertext()) != len(canonical.Bytes())+16 ||
		len(prepared.ProtectedDigest().Ciphertext()) != len(canonical.Digest())+16 {
		t.Fatal("GCM authentication tag size mismatch")
	}

	eventPlaintext, err := openProtected(key, prepared.CanonicalEvent(), eventAAD)
	if err != nil || !bytes.Equal(eventPlaintext, canonical.Bytes()) {
		t.Fatal("canonical event plaintext mismatch")
	}
	openedDigest, err := service.OpenDigest(context.Background(), digestOpenRequest(prepared))
	if err != nil || openedDigest != durable.CanonicalDigest(canonical.Digest()) ||
		prepared.EquivalenceDigest() != durable.CanonicalDigest(canonical.Digest()) {
		t.Fatal("literal digest mismatch")
	}
}

func TestKeyValidationAndDefensiveCopies(t *testing.T) {
	material := testKeyMaterial(3)
	original := append([]byte(nil), material...)
	key := mustKey(t, testKeyID, material)
	material[0] ^= 1
	if !bytes.Equal(key.materialCopy(), original) {
		t.Fatal("key constructor exposed mutable material")
	}
	returned := key.materialCopy()
	returned[0] ^= 1
	if !bytes.Equal(key.materialCopy(), original) {
		t.Fatal("key material copy exposed internal state")
	}
	if key.ID() != testKeyID {
		t.Fatal("key identifier mismatch")
	}

	invalid := [][]byte{nil, make([]byte, aes256KeySize-1), make([]byte, aes256KeySize+1)}
	for _, material := range invalid {
		if _, err := NewKey(testKeyID, material); !errors.Is(err, ErrProtectionInvalid) {
			t.Fatal("invalid key length was accepted")
		}
	}
	if _, err := NewKey("", original); !errors.Is(err, ErrProtectionInvalid) {
		t.Fatal("empty key identifier was accepted")
	}
	if _, err := NewKey(string([]byte{0xff}), original); !errors.Is(err, ErrProtectionInvalid) {
		t.Fatal("invalid key identifier encoding was accepted")
	}
}

func TestPrepareValidationRandomFailuresAndNoPartialResult(t *testing.T) {
	keys, _ := newTestKeySource(t)
	canonical := mustCanonicalEvent(t)
	canceled, cancel := context.WithCancel(context.Background())
	cancel()

	tests := []struct {
		name      string
		service   *Service
		ctx       context.Context
		principal string
		dest      string
		identity  durable.DeliveryIdentity
		event     httpapi.CanonicalEvent
		want      error
	}{
		{name: "nil receiver", ctx: context.Background(), principal: testPrincipal, dest: testDestination, identity: testIdentity, event: canonical, want: ErrProtectionInvalid},
		{name: "nil key source", service: NewService(nil), ctx: context.Background(), principal: testPrincipal, dest: testDestination, identity: testIdentity, event: canonical, want: ErrProtectionInvalid},
		{name: "nil random source", service: NewServiceWithRandomSource(keys, nil), ctx: context.Background(), principal: testPrincipal, dest: testDestination, identity: testIdentity, event: canonical, want: ErrProtectionInvalid},
		{name: "nil context", service: NewService(keys), principal: testPrincipal, dest: testDestination, identity: testIdentity, event: canonical, want: ErrProtectionInvalid},
		{name: "canceled context", service: NewService(keys), ctx: canceled, principal: testPrincipal, dest: testDestination, identity: testIdentity, event: canonical, want: ErrProtectionFailed},
		{name: "zero canonical event", service: NewService(keys), ctx: context.Background(), principal: testPrincipal, dest: testDestination, identity: testIdentity, want: ErrProtectionInvalid},
		{name: "empty principal", service: NewService(keys), ctx: context.Background(), dest: testDestination, identity: testIdentity, event: canonical, want: ErrProtectionInvalid},
		{name: "empty destination", service: NewService(keys), ctx: context.Background(), principal: testPrincipal, identity: testIdentity, event: canonical, want: ErrProtectionInvalid},
		{name: "zero delivery identity", service: NewService(keys), ctx: context.Background(), principal: testPrincipal, dest: testDestination, event: canonical, want: ErrProtectionInvalid},
		{name: "invalid principal encoding", service: NewService(keys), ctx: context.Background(), principal: string([]byte{0xff}), dest: testDestination, identity: testIdentity, event: canonical, want: ErrProtectionInvalid},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var prepared durable.PreparedAcceptance
			var err error
			if test.service == nil {
				var service *Service
				prepared, err = service.Prepare(test.ctx, test.principal, test.dest, test.identity, test.event)
			} else {
				prepared, err = test.service.Prepare(test.ctx, test.principal, test.dest, test.identity, test.event)
			}
			if !errors.Is(err, test.want) || !preparedIsZero(prepared) {
				t.Fatal("invalid preparation did not fail closed")
			}
		})
	}

	randomTests := []struct {
		name   string
		reader io.Reader
	}{
		{name: "random source error", reader: errorReader{}},
		{name: "random source short read", reader: bytes.NewReader(make([]byte, gcmNonceSize*2-1))},
		{name: "repeated nonce", reader: bytes.NewReader(bytes.Repeat([]byte{7}, gcmNonceSize*2))},
	}
	for _, test := range randomTests {
		t.Run(test.name, func(t *testing.T) {
			prepared, err := NewServiceWithRandomSource(keys, test.reader).Prepare(
				context.Background(), testPrincipal, testDestination, testIdentity, canonical,
			)
			if !errors.Is(err, ErrProtectionRandom) || !preparedIsZero(prepared) ||
				stringsContainSensitiveDetail(err) {
				t.Fatal("randomness failure did not fail closed")
			}
		})
	}
}

func TestPrepareKeyFailuresAreRedacted(t *testing.T) {
	privateError := errors.New("provider-sensitive-key-detail")
	source := &memoryKeySource{activeErr: privateError}
	prepared, err := NewService(source).Prepare(
		context.Background(), testPrincipal, testDestination, testIdentity, mustCanonicalEvent(t),
	)
	if !errors.Is(err, ErrProtectionKeyUnavailable) || errors.Is(err, privateError) ||
		!preparedIsZero(prepared) || stringsContainSensitiveDetail(err) {
		t.Fatal("key provider failure was not safely classified")
	}

	source = &memoryKeySource{}
	prepared, err = NewService(source).Prepare(
		context.Background(), testPrincipal, testDestination, testIdentity, mustCanonicalEvent(t),
	)
	if !errors.Is(err, ErrProtectionKeyUnavailable) || !preparedIsZero(prepared) {
		t.Fatal("invalid active key did not fail closed")
	}
}

func TestPrepareUsesIndependentNoncesAndPreservesInputs(t *testing.T) {
	keys, _ := newTestKeySource(t)
	randomData := append(deterministicNonces(1, 21), deterministicNonces(41, 61)...)
	service := NewServiceWithRandomSource(keys, bytes.NewReader(randomData))
	canonical := mustCanonicalEvent(t)
	before := canonical.Bytes()
	first, err := service.Prepare(context.Background(), testPrincipal, testDestination, testIdentity, canonical)
	if err != nil {
		t.Fatal("first preparation failed")
	}
	second, err := service.Prepare(context.Background(), testPrincipal, testDestination, testIdentity, canonical)
	if err != nil {
		t.Fatal("second preparation failed")
	}
	if bytes.Equal(first.CanonicalEvent().Nonce(), first.ProtectedDigest().Nonce()) ||
		bytes.Equal(second.CanonicalEvent().Nonce(), second.ProtectedDigest().Nonce()) ||
		bytes.Equal(first.CanonicalEvent().Ciphertext(), second.CanonicalEvent().Ciphertext()) ||
		bytes.Equal(first.ProtectedDigest().Ciphertext(), second.ProtectedDigest().Ciphertext()) {
		t.Fatal("nonce or ciphertext separation failed")
	}
	if !bytes.Equal(before, canonical.Bytes()) {
		t.Fatal("canonical event input was modified")
	}

	returnedCiphertext := first.CanonicalEvent().Ciphertext()
	returnedNonce := first.CanonicalEvent().Nonce()
	returnedCiphertext[0] ^= 1
	returnedNonce[0] ^= 1
	if bytes.Equal(returnedCiphertext, first.CanonicalEvent().Ciphertext()) ||
		bytes.Equal(returnedNonce, first.CanonicalEvent().Nonce()) {
		t.Fatal("protected value getter exposed mutable state")
	}
}

func TestOpenDigestRotationAndHistoricalKeys(t *testing.T) {
	oldKey := mustKey(t, "old-test-key", testKeyMaterial(1))
	newKey := mustKey(t, "new-test-key", testKeyMaterial(33))
	keys := &memoryKeySource{
		active: oldKey,
		byID: map[string]Key{
			oldKey.ID(): oldKey,
			newKey.ID(): newKey,
		},
	}
	service := NewServiceWithRandomSource(keys, bytes.NewReader(append(
		deterministicNonces(1, 21), deterministicNonces(41, 61)...,
	)))
	oldPrepared := mustPrepare(t, service)
	keys.setActive(newKey)
	newPrepared := mustPrepare(t, service)
	if oldPrepared.EncryptionKeyID() != oldKey.ID() || newPrepared.EncryptionKeyID() != newKey.ID() {
		t.Fatal("active key selection failed")
	}
	opened, err := service.OpenDigest(context.Background(), digestOpenRequest(oldPrepared))
	if err != nil || opened != oldPrepared.EquivalenceDigest() {
		t.Fatal("historical key did not reopen digest")
	}
}

func TestOpenDigestRejectsContextAndProtectedValueMutation(t *testing.T) {
	keys, key := newTestKeySource(t)
	service := NewServiceWithRandomSource(keys, bytes.NewReader(deterministicNonces(1, 21)))
	prepared := mustPrepare(t, service)
	base := digestOpenRequest(prepared)

	secondKeyID := "second-test-key"
	secondKey := mustKey(t, secondKeyID, key.materialCopy())
	keys.byID[secondKeyID] = secondKey

	otherIdentity := testIdentity
	otherIdentity[len(otherIdentity)-1] ^= 1
	tests := []struct {
		name   string
		mutate func(durable.DigestOpenRequest) durable.DigestOpenRequest
	}{
		{name: "principal", mutate: func(request durable.DigestOpenRequest) durable.DigestOpenRequest {
			request.CorePrincipalID = "other-core"
			return request
		}},
		{name: "destination", mutate: func(request durable.DigestOpenRequest) durable.DigestOpenRequest {
			request.DestinationID = "other-destination"
			return request
		}},
		{name: "delivery identity", mutate: func(request durable.DigestOpenRequest) durable.DigestOpenRequest {
			request.DeliveryIdentity = otherIdentity
			return request
		}},
		{name: "canonical format version", mutate: func(request durable.DigestOpenRequest) durable.DigestOpenRequest {
			request.FormatVersion++
			return request
		}},
		{name: "key identifier", mutate: func(request durable.DigestOpenRequest) durable.DigestOpenRequest {
			request.EncryptionKeyID = secondKeyID
			return request
		}},
		{name: "ciphertext", mutate: func(request durable.DigestOpenRequest) durable.DigestOpenRequest {
			request.ProtectedDigest = mutatedProtected(t, request.ProtectedDigest, true)
			return request
		}},
		{name: "nonce", mutate: func(request durable.DigestOpenRequest) durable.DigestOpenRequest {
			request.ProtectedDigest = mutatedProtected(t, request.ProtectedDigest, false)
			return request
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := service.OpenDigest(context.Background(), test.mutate(base)); !errors.Is(err, ErrProtectedDigestUnreadable) {
				t.Fatal("modified digest context was accepted")
			}
		})
	}

	eventAAD, err := buildAAD(purposeEvent, prepared.FormatVersion(), prepared.DeliveryIdentity(), prepared.CorePrincipalID(), prepared.DestinationID(), prepared.EncryptionKeyID())
	if err != nil {
		t.Fatal("event AAD setup failed")
	}
	if _, err := openProtected(key, mutatedProtected(t, prepared.CanonicalEvent(), true), eventAAD); err == nil {
		t.Fatal("modified event ciphertext was accepted")
	}
	if _, err := openProtected(key, mutatedProtected(t, prepared.CanonicalEvent(), false), eventAAD); err == nil {
		t.Fatal("modified event nonce was accepted")
	}
	digestAAD, err := buildAAD(purposeDigest, prepared.FormatVersion(), prepared.DeliveryIdentity(), prepared.CorePrincipalID(), prepared.DestinationID(), prepared.EncryptionKeyID())
	if err != nil {
		t.Fatal("digest AAD setup failed")
	}
	if _, err := openProtected(key, prepared.CanonicalEvent(), digestAAD); err == nil {
		t.Fatal("modified purpose was accepted")
	}
	versionAAD, err := buildAADForVersion(2, purposeEvent, prepared.FormatVersion(), prepared.DeliveryIdentity(), prepared.CorePrincipalID(), prepared.DestinationID(), prepared.EncryptionKeyID())
	if err != nil {
		t.Fatal("protection version AAD setup failed")
	}
	if _, err := openProtected(key, prepared.CanonicalEvent(), versionAAD); err == nil {
		t.Fatal("modified protection version was accepted")
	}
}

func TestOpenDigestKeyAndPlaintextFailuresAreIndistinguishable(t *testing.T) {
	keys, key := newTestKeySource(t)
	service := NewServiceWithRandomSource(keys, bytes.NewReader(deterministicNonces(1, 21)))
	prepared := mustPrepare(t, service)
	request := digestOpenRequest(prepared)
	privateError := errors.New("provider-sensitive-key-detail")

	tests := []struct {
		name   string
		source *memoryKeySource
	}{
		{name: "missing historical key", source: &memoryKeySource{byID: map[string]Key{}}},
		{name: "retired historical key", source: &memoryKeySource{byID: map[string]Key{}, lookupErr: privateError}},
		{name: "wrong key material", source: &memoryKeySource{byID: map[string]Key{testKeyID: mustKey(t, testKeyID, testKeyMaterial(99))}}},
		{name: "returned key identifier mismatch", source: &memoryKeySource{byID: map[string]Key{testKeyID: mustKey(t, "other-test-key", key.materialCopy())}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewService(test.source).OpenDigest(context.Background(), request)
			if !errors.Is(err, ErrProtectedDigestUnreadable) || errors.Is(err, privateError) || stringsContainSensitiveDetail(err) {
				t.Fatal("digest key failure was distinguishable")
			}
		})
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	invalidRequests := []struct {
		name    string
		service *Service
		ctx     context.Context
		request durable.DigestOpenRequest
	}{
		{name: "nil receiver", ctx: context.Background(), request: request},
		{name: "nil key source", service: NewService(nil), ctx: context.Background(), request: request},
		{name: "nil context", service: service, request: request},
		{name: "canceled context", service: service, ctx: canceled, request: request},
		{name: "empty request", service: service, ctx: context.Background()},
	}
	for _, test := range invalidRequests {
		t.Run(test.name, func(t *testing.T) {
			var err error
			if test.service == nil {
				var nilService *Service
				_, err = nilService.OpenDigest(test.ctx, test.request)
			} else {
				_, err = test.service.OpenDigest(test.ctx, test.request)
			}
			if !errors.Is(err, ErrProtectedDigestUnreadable) {
				t.Fatal("invalid digest request did not fail closed")
			}
		})
	}

	aad, err := buildAAD(purposeDigest, request.FormatVersion, request.DeliveryIdentity, request.CorePrincipalID, request.DestinationID, request.EncryptionKeyID)
	if err != nil {
		t.Fatal("short plaintext AAD setup failed")
	}
	shortProtected, err := sealProtected(key, deterministicNonces(4, 24)[:gcmNonceSize], []byte("short"), aad)
	if err != nil {
		t.Fatal("short plaintext setup failed")
	}
	request.ProtectedDigest = shortProtected
	if _, err := service.OpenDigest(context.Background(), request); !errors.Is(err, ErrProtectedDigestUnreadable) {
		t.Fatal("short digest plaintext was accepted")
	}
}

func TestAADValidation(t *testing.T) {
	if _, err := buildAAD(0xff, 1, testIdentity, testPrincipal, testDestination, testKeyID); !errors.Is(err, ErrProtectionInvalid) {
		t.Fatal("unknown AAD purpose was accepted")
	}
	if _, err := buildAAD(purposeEvent, 0, testIdentity, testPrincipal, testDestination, testKeyID); !errors.Is(err, ErrProtectionInvalid) {
		t.Fatal("invalid canonical format version was accepted")
	}
	if _, err := buildAADForVersion(0, purposeEvent, 1, testIdentity, testPrincipal, testDestination, testKeyID); !errors.Is(err, ErrProtectionInvalid) {
		t.Fatal("invalid protection format version was accepted")
	}
	if _, err := buildAAD(purposeEvent, 1, durable.DeliveryIdentity{}, testPrincipal, testDestination, testKeyID); !errors.Is(err, ErrProtectionInvalid) {
		t.Fatal("zero AAD delivery identity was accepted")
	}
}

func TestServiceConcurrentPrepareAndOpen(t *testing.T) {
	keys, _ := newTestKeySource(t)
	service := NewService(keys)
	canonical := mustCanonicalEvent(t)
	const callers = 32
	type outcome struct {
		prepared durable.PreparedAcceptance
		digest   durable.CanonicalDigest
		err      error
	}
	outcomes := make(chan outcome, callers)
	var wait sync.WaitGroup
	wait.Add(callers)
	for range callers {
		go func() {
			defer wait.Done()
			prepared, err := service.Prepare(context.Background(), testPrincipal, testDestination, testIdentity, canonical)
			if err != nil {
				outcomes <- outcome{err: err}
				return
			}
			digest, err := service.OpenDigest(context.Background(), digestOpenRequest(prepared))
			outcomes <- outcome{prepared: prepared, digest: digest, err: err}
		}()
	}
	wait.Wait()
	close(outcomes)

	nonces := make(map[string]struct{}, callers*2)
	for result := range outcomes {
		if result.err != nil || result.digest != durable.CanonicalDigest(canonical.Digest()) {
			t.Fatal("concurrent protection operation failed")
		}
		for _, nonce := range [][]byte{result.prepared.CanonicalEvent().Nonce(), result.prepared.ProtectedDigest().Nonce()} {
			key := string(nonce)
			if _, exists := nonces[key]; exists {
				t.Fatal("concurrent protection reused a nonce")
			}
			nonces[key] = struct{}{}
		}
	}
	if len(nonces) != callers*2 {
		t.Fatal("concurrent protection nonce count mismatch")
	}
}

func stringsContainSensitiveDetail(err error) bool {
	if err == nil {
		return false
	}
	return bytes.Contains([]byte(err.Error()), []byte("sensitive"))
}
