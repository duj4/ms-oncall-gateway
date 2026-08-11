package protection

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"io"
	"math"
	"reflect"
	"sync"
	"unicode/utf8"

	"github.com/duj4/ms-oncall-gateway/internal/durable"
	"github.com/duj4/ms-oncall-gateway/internal/httpapi"
)

const PayloadProtectionFormatVersion int64 = 1

const (
	protectionDomainTag = "MS_ONCALL_GATEWAY_PAYLOAD_PROTECTION"
	purposeEvent        = byte(0x01)
	purposeDigest       = byte(0x02)
	gcmNonceSize        = 12
)

type Service struct {
	keys     KeySource
	random   io.Reader
	randomMu sync.Mutex
}

func NewService(keys KeySource) *Service {
	return NewServiceWithRandomSource(keys, rand.Reader)
}

func NewServiceWithRandomSource(keys KeySource, random io.Reader) *Service {
	return &Service{keys: keys, random: random}
}

func (service *Service) Prepare(
	ctx context.Context,
	corePrincipalID string,
	destinationID string,
	deliveryIdentity durable.DeliveryIdentity,
	canonicalEvent httpapi.CanonicalEvent,
) (durable.PreparedAcceptance, error) {
	if service == nil || isNilInterface(service.keys) || isNilInterface(service.random) || isNilInterface(ctx) {
		return durable.PreparedAcceptance{}, ErrProtectionInvalid
	}
	if ctx.Err() != nil {
		return durable.PreparedAcceptance{}, ErrProtectionFailed
	}

	canonicalBytes := canonicalEvent.Bytes()
	canonicalDigest := durable.CanonicalDigest(canonicalEvent.Digest())
	if err := validatePrepareInput(
		corePrincipalID,
		destinationID,
		deliveryIdentity,
		canonicalEvent.FormatVersion(),
		canonicalBytes,
		canonicalDigest,
	); err != nil {
		return durable.PreparedAcceptance{}, ErrProtectionInvalid
	}

	key, err := service.keys.ActiveKey(ctx)
	if err != nil || !key.valid() {
		return durable.PreparedAcceptance{}, ErrProtectionKeyUnavailable
	}
	if ctx.Err() != nil {
		return durable.PreparedAcceptance{}, ErrProtectionFailed
	}

	eventNonce, digestNonce, err := service.nonces()
	if err != nil {
		return durable.PreparedAcceptance{}, ErrProtectionRandom
	}
	if subtle.ConstantTimeCompare(eventNonce, digestNonce) == 1 {
		return durable.PreparedAcceptance{}, ErrProtectionRandom
	}
	if ctx.Err() != nil {
		return durable.PreparedAcceptance{}, ErrProtectionFailed
	}

	eventAAD, err := buildAAD(
		purposeEvent,
		canonicalEvent.FormatVersion(),
		deliveryIdentity,
		corePrincipalID,
		destinationID,
		key.ID(),
	)
	if err != nil {
		return durable.PreparedAcceptance{}, ErrProtectionInvalid
	}
	protectedEvent, err := sealProtected(key, eventNonce, canonicalBytes, eventAAD)
	if err != nil {
		return durable.PreparedAcceptance{}, ErrProtectionFailed
	}

	digestAAD, err := buildAAD(
		purposeDigest,
		canonicalEvent.FormatVersion(),
		deliveryIdentity,
		corePrincipalID,
		destinationID,
		key.ID(),
	)
	if err != nil {
		return durable.PreparedAcceptance{}, ErrProtectionInvalid
	}
	protectedDigest, err := sealProtected(key, digestNonce, canonicalDigest[:], digestAAD)
	if err != nil {
		return durable.PreparedAcceptance{}, ErrProtectionFailed
	}

	prepared, err := durable.NewPreparedAcceptance(
		corePrincipalID,
		destinationID,
		deliveryIdentity,
		canonicalEvent.FormatVersion(),
		protectedEvent,
		protectedDigest,
		key.ID(),
		canonicalDigest,
	)
	if err != nil {
		return durable.PreparedAcceptance{}, ErrProtectionFailed
	}
	return prepared, nil
}

func (service *Service) OpenDigest(ctx context.Context, request durable.DigestOpenRequest) (durable.CanonicalDigest, error) {
	if service == nil || isNilInterface(service.keys) || isNilInterface(ctx) || ctx.Err() != nil {
		return durable.CanonicalDigest{}, ErrProtectedDigestUnreadable
	}
	if err := validateDigestOpenRequest(request); err != nil {
		return durable.CanonicalDigest{}, ErrProtectedDigestUnreadable
	}

	key, err := service.keys.KeyByID(ctx, request.EncryptionKeyID)
	if err != nil || !key.valid() || key.ID() != request.EncryptionKeyID || ctx.Err() != nil {
		return durable.CanonicalDigest{}, ErrProtectedDigestUnreadable
	}

	aad, err := buildAAD(
		purposeDigest,
		request.FormatVersion,
		request.DeliveryIdentity,
		request.CorePrincipalID,
		request.DestinationID,
		request.EncryptionKeyID,
	)
	if err != nil {
		return durable.CanonicalDigest{}, ErrProtectedDigestUnreadable
	}
	plaintext, err := openProtected(key, request.ProtectedDigest, aad)
	if err != nil || len(plaintext) != sha256.Size {
		return durable.CanonicalDigest{}, ErrProtectedDigestUnreadable
	}

	var digest durable.CanonicalDigest
	copy(digest[:], plaintext)
	return digest, nil
}

func (service *Service) nonces() ([]byte, []byte, error) {
	service.randomMu.Lock()
	defer service.randomMu.Unlock()

	eventNonce := make([]byte, gcmNonceSize)
	digestNonce := make([]byte, gcmNonceSize)
	if _, err := io.ReadFull(service.random, eventNonce); err != nil {
		return nil, nil, ErrProtectionRandom
	}
	if _, err := io.ReadFull(service.random, digestNonce); err != nil {
		return nil, nil, ErrProtectionRandom
	}
	return eventNonce, digestNonce, nil
}

func validatePrepareInput(
	corePrincipalID string,
	destinationID string,
	deliveryIdentity durable.DeliveryIdentity,
	formatVersion int64,
	canonicalBytes []byte,
	canonicalDigest durable.CanonicalDigest,
) error {
	if corePrincipalID == "" || destinationID == "" || deliveryIdentity.IsZero() || formatVersion <= 0 || len(canonicalBytes) == 0 {
		return ErrProtectionInvalid
	}
	if err := validateAADString(corePrincipalID); err != nil {
		return err
	}
	if err := validateAADString(destinationID); err != nil {
		return err
	}
	expected := durable.CanonicalDigest(sha256.Sum256(canonicalBytes))
	if subtle.ConstantTimeCompare(expected[:], canonicalDigest[:]) != 1 {
		return ErrProtectionInvalid
	}
	return nil
}

func validateDigestOpenRequest(request durable.DigestOpenRequest) error {
	if request.EncryptionKeyID == "" ||
		request.CorePrincipalID == "" ||
		request.DestinationID == "" ||
		request.DeliveryIdentity.IsZero() ||
		request.FormatVersion <= 0 ||
		len(request.ProtectedDigest.Ciphertext()) == 0 ||
		len(request.ProtectedDigest.Nonce()) != gcmNonceSize {
		return ErrProtectionInvalid
	}
	for _, value := range []string{request.EncryptionKeyID, request.CorePrincipalID, request.DestinationID} {
		if err := validateAADString(value); err != nil {
			return err
		}
	}
	return nil
}

func buildAAD(
	purpose byte,
	canonicalFormatVersion int64,
	deliveryIdentity durable.DeliveryIdentity,
	corePrincipalID string,
	destinationID string,
	keyID string,
) ([]byte, error) {
	return buildAADForVersion(
		PayloadProtectionFormatVersion,
		purpose,
		canonicalFormatVersion,
		deliveryIdentity,
		corePrincipalID,
		destinationID,
		keyID,
	)
}

func buildAADForVersion(
	protectionFormatVersion int64,
	purpose byte,
	canonicalFormatVersion int64,
	deliveryIdentity durable.DeliveryIdentity,
	corePrincipalID string,
	destinationID string,
	keyID string,
) ([]byte, error) {
	if protectionFormatVersion <= 0 ||
		canonicalFormatVersion <= 0 ||
		deliveryIdentity.IsZero() ||
		(purpose != purposeEvent && purpose != purposeDigest) {
		return nil, ErrProtectionInvalid
	}
	for _, value := range []string{corePrincipalID, destinationID, keyID} {
		if value == "" {
			return nil, ErrProtectionInvalid
		}
		if err := validateAADString(value); err != nil {
			return nil, err
		}
	}

	aad := append([]byte(nil), protectionDomainTag...)
	aad = append(aad, 0)
	aad = binary.BigEndian.AppendUint64(aad, uint64(protectionFormatVersion))
	aad = append(aad, purpose)
	aad = binary.BigEndian.AppendUint64(aad, uint64(canonicalFormatVersion))
	aad = append(aad, deliveryIdentity[:]...)
	aad = appendAADString(aad, corePrincipalID)
	aad = appendAADString(aad, destinationID)
	aad = appendAADString(aad, keyID)
	return aad, nil
}

func validateAADString(value string) error {
	if !utf8.ValidString(value) || uint64(len(value)) > math.MaxUint32 {
		return ErrProtectionInvalid
	}
	return nil
}

func appendAADString(aad []byte, value string) []byte {
	aad = binary.BigEndian.AppendUint32(aad, uint32(len(value)))
	return append(aad, value...)
}

func sealProtected(key Key, nonce, plaintext, aad []byte) (durable.ProtectedValue, error) {
	aead, err := newGCM(key)
	if err != nil || len(nonce) != aeadNonceSize(aead) {
		return durable.ProtectedValue{}, ErrProtectionFailed
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, aad)
	protected, err := durable.NewProtectedValue(ciphertext, nonce)
	if err != nil {
		return durable.ProtectedValue{}, ErrProtectionFailed
	}
	return protected, nil
}

func openProtected(key Key, protected durable.ProtectedValue, aad []byte) ([]byte, error) {
	aead, err := newGCM(key)
	if err != nil {
		return nil, ErrProtectionFailed
	}
	nonce := protected.Nonce()
	if len(nonce) != aeadNonceSize(aead) {
		return nil, ErrProtectionFailed
	}
	plaintext, err := aead.Open(nil, nonce, protected.Ciphertext(), aad)
	if err != nil {
		return nil, ErrProtectionFailed
	}
	return plaintext, nil
}

func newGCM(key Key) (cipher.AEAD, error) {
	if !key.valid() {
		return nil, ErrProtectionFailed
	}
	block, err := aes.NewCipher(key.materialCopy())
	if err != nil {
		return nil, ErrProtectionFailed
	}
	aead, err := cipher.NewGCM(block)
	if err != nil || aead.NonceSize() != gcmNonceSize {
		return nil, ErrProtectionFailed
	}
	return aead, nil
}

func aeadNonceSize(aead cipher.AEAD) int {
	if aead == nil {
		return 0
	}
	return aead.NonceSize()
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
