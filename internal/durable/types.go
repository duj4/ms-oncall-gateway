package durable

import "encoding/hex"

type ReceiptID [16]byte

func (id ReceiptID) IsZero() bool {
	return id == ReceiptID{}
}

func (id ReceiptID) String() string {
	return formatUUID(id)
}

func ParseReceiptID(value string) (ReceiptID, error) {
	parsed, err := parseUUID(value)
	return ReceiptID(parsed), err
}

type DeliveryIdentity [16]byte

func (id DeliveryIdentity) IsZero() bool {
	return id == DeliveryIdentity{}
}

func (id DeliveryIdentity) String() string {
	return formatUUID(id)
}

func ParseDeliveryIdentity(value string) (DeliveryIdentity, error) {
	parsed, err := parseUUID(value)
	return DeliveryIdentity(parsed), err
}

type CanonicalDigest [32]byte

type ProtectedValue struct {
	ciphertext []byte
	nonce      []byte
}

func NewProtectedValue(ciphertext, nonce []byte) (ProtectedValue, error) {
	if len(ciphertext) == 0 || len(nonce) == 0 {
		return ProtectedValue{}, ErrInvalidAcceptance
	}
	return ProtectedValue{
		ciphertext: append([]byte(nil), ciphertext...),
		nonce:      append([]byte(nil), nonce...),
	}, nil
}

func (value ProtectedValue) Ciphertext() []byte {
	return append([]byte(nil), value.ciphertext...)
}

func (value ProtectedValue) Nonce() []byte {
	return append([]byte(nil), value.nonce...)
}

func (value ProtectedValue) valid() bool {
	return len(value.ciphertext) > 0 && len(value.nonce) > 0
}

type PreparedAcceptance struct {
	corePrincipalID   string
	destinationID     string
	deliveryIdentity  DeliveryIdentity
	formatVersion     int64
	canonicalEvent    ProtectedValue
	protectedDigest   ProtectedValue
	encryptionKeyID   string
	equivalenceDigest CanonicalDigest
}

func NewPreparedAcceptance(
	corePrincipalID string,
	destinationID string,
	deliveryIdentity DeliveryIdentity,
	formatVersion int64,
	canonicalEvent ProtectedValue,
	protectedDigest ProtectedValue,
	encryptionKeyID string,
	equivalenceDigest CanonicalDigest,
) (PreparedAcceptance, error) {
	acceptance := PreparedAcceptance{
		corePrincipalID:   corePrincipalID,
		destinationID:     destinationID,
		deliveryIdentity:  deliveryIdentity,
		formatVersion:     formatVersion,
		canonicalEvent:    cloneProtectedValue(canonicalEvent),
		protectedDigest:   cloneProtectedValue(protectedDigest),
		encryptionKeyID:   encryptionKeyID,
		equivalenceDigest: equivalenceDigest,
	}
	if err := acceptance.validate(); err != nil {
		return PreparedAcceptance{}, err
	}
	return acceptance, nil
}

func (acceptance PreparedAcceptance) CorePrincipalID() string {
	return acceptance.corePrincipalID
}

func (acceptance PreparedAcceptance) DestinationID() string {
	return acceptance.destinationID
}

func (acceptance PreparedAcceptance) DeliveryIdentity() DeliveryIdentity {
	return acceptance.deliveryIdentity
}

func (acceptance PreparedAcceptance) FormatVersion() int64 {
	return acceptance.formatVersion
}

func (acceptance PreparedAcceptance) CanonicalEvent() ProtectedValue {
	return cloneProtectedValue(acceptance.canonicalEvent)
}

func (acceptance PreparedAcceptance) ProtectedDigest() ProtectedValue {
	return cloneProtectedValue(acceptance.protectedDigest)
}

func (acceptance PreparedAcceptance) EncryptionKeyID() string {
	return acceptance.encryptionKeyID
}

func (acceptance PreparedAcceptance) EquivalenceDigest() CanonicalDigest {
	return acceptance.equivalenceDigest
}

func (acceptance PreparedAcceptance) validate() error {
	if acceptance.corePrincipalID == "" ||
		acceptance.destinationID == "" ||
		acceptance.deliveryIdentity.IsZero() ||
		acceptance.formatVersion <= 0 ||
		!acceptance.canonicalEvent.valid() ||
		!acceptance.protectedDigest.valid() ||
		acceptance.encryptionKeyID == "" {
		return ErrInvalidAcceptance
	}
	return nil
}

func cloneProtectedValue(value ProtectedValue) ProtectedValue {
	return ProtectedValue{
		ciphertext: append([]byte(nil), value.ciphertext...),
		nonce:      append([]byte(nil), value.nonce...),
	}
}

func formatUUID[T ~[16]byte](value T) string {
	var encoded [36]byte
	hex.Encode(encoded[0:8], value[0:4])
	encoded[8] = '-'
	hex.Encode(encoded[9:13], value[4:6])
	encoded[13] = '-'
	hex.Encode(encoded[14:18], value[6:8])
	encoded[18] = '-'
	hex.Encode(encoded[19:23], value[8:10])
	encoded[23] = '-'
	hex.Encode(encoded[24:36], value[10:16])
	return string(encoded[:])
}

func parseUUID(value string) ([16]byte, error) {
	var result [16]byte
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return result, ErrInvalidAcceptance
	}
	compact := value[0:8] + value[9:13] + value[14:18] + value[19:23] + value[24:36]
	decoded, err := hex.DecodeString(compact)
	if err != nil || len(decoded) != len(result) {
		return result, ErrInvalidAcceptance
	}
	copy(result[:], decoded)
	if result == [16]byte{} {
		return result, ErrInvalidAcceptance
	}
	return result, nil
}
