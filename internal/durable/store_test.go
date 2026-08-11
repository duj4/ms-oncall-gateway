package durable

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
)

type repositoryFunc func(context.Context, Candidate) (PersistenceResult, error)

func (function repositoryFunc) InsertOrLoad(ctx context.Context, candidate Candidate) (PersistenceResult, error) {
	return function(ctx, candidate)
}

type openerFunc func(context.Context, DigestOpenRequest) (CanonicalDigest, error)

func (function openerFunc) OpenDigest(ctx context.Context, request DigestOpenRequest) (CanonicalDigest, error) {
	return function(ctx, request)
}

type generatorFunc func() (ReceiptID, error)

func (function generatorFunc) NewReceiptID() (ReceiptID, error) {
	return function()
}

func testReceipt(seed byte) ReceiptID {
	var receipt ReceiptID
	for index := range receipt {
		receipt[index] = seed + byte(index)
	}
	return receipt
}

func testIdentity(seed byte) DeliveryIdentity {
	var identity DeliveryIdentity
	for index := range identity {
		identity[index] = seed + byte(index)
	}
	return identity
}

func testDigest(seed byte) CanonicalDigest {
	var digest CanonicalDigest
	for index := range digest {
		digest[index] = seed + byte(index)
	}
	return digest
}

func testProtected(t *testing.T, value string) ProtectedValue {
	t.Helper()
	protected, err := NewProtectedValue([]byte("ciphertext-"+value), []byte("nonce-"+value))
	if err != nil {
		t.Fatal("protected value test setup failed")
	}
	return protected
}

func testAcceptance(t *testing.T, version int64, digest CanonicalDigest) PreparedAcceptance {
	t.Helper()
	acceptance, err := NewPreparedAcceptance(
		"principal",
		"destination",
		testIdentity(1),
		version,
		testProtected(t, "event"),
		testProtected(t, "digest"),
		"key-1",
		digest,
	)
	if err != nil {
		t.Fatal("prepared acceptance test setup failed")
	}
	return acceptance
}

func TestUUIDv4GeneratorVersionVariantAndFailure(t *testing.T) {
	input := bytes.Repeat([]byte{0xff}, 16)
	receipt, err := (UUIDv4Generator{Reader: bytes.NewReader(input)}).NewReceiptID()
	if err != nil {
		t.Fatal("receipt generation failed")
	}
	if version := receipt[6] >> 4; version != 4 {
		t.Error("UUID version mismatch")
	}
	if variant := receipt[8] >> 6; variant != 2 {
		t.Error("UUID variant mismatch")
	}
	if _, err := (UUIDv4Generator{Reader: io.LimitReader(bytes.NewReader(input), 15)}).NewReceiptID(); !errors.Is(err, ErrReceiptGeneration) {
		t.Fatal("short receipt random source was not rejected")
	}
}

func TestPreparedAcceptanceValidationAndDefensiveCopies(t *testing.T) {
	ciphertext := []byte("event-ciphertext")
	nonce := []byte("event-nonce")
	event, err := NewProtectedValue(ciphertext, nonce)
	if err != nil {
		t.Fatal("event protection test setup failed")
	}
	digest := testDigest(3)
	acceptance, err := NewPreparedAcceptance(
		"principal",
		"destination",
		testIdentity(2),
		1,
		event,
		testProtected(t, "digest"),
		"key",
		digest,
	)
	if err != nil {
		t.Fatal("prepared acceptance construction failed")
	}
	ciphertext[0] = 'X'
	nonce[0] = 'X'
	returned := acceptance.CanonicalEvent()
	if string(returned.Ciphertext()) != "event-ciphertext" || string(returned.Nonce()) != "event-nonce" {
		t.Fatal("constructor did not defensively copy protected bytes")
	}
	copyFromGetter := returned.Ciphertext()
	copyFromGetter[0] = 'Y'
	if string(acceptance.CanonicalEvent().Ciphertext()) != "event-ciphertext" {
		t.Fatal("getter exposed mutable protected bytes")
	}

	validEvent := testProtected(t, "event")
	validDigest := testProtected(t, "digest")
	tests := []struct {
		name        string
		principal   string
		destination string
		identity    DeliveryIdentity
		version     int64
		event       ProtectedValue
		digest      ProtectedValue
		keyID       string
	}{
		{name: "missing principal", destination: "d", identity: testIdentity(1), version: 1, event: validEvent, digest: validDigest, keyID: "k"},
		{name: "missing destination", principal: "p", identity: testIdentity(1), version: 1, event: validEvent, digest: validDigest, keyID: "k"},
		{name: "missing delivery identity", principal: "p", destination: "d", version: 1, event: validEvent, digest: validDigest, keyID: "k"},
		{name: "nonpositive version", principal: "p", destination: "d", identity: testIdentity(1), event: validEvent, digest: validDigest, keyID: "k"},
		{name: "missing event", principal: "p", destination: "d", identity: testIdentity(1), version: 1, digest: validDigest, keyID: "k"},
		{name: "missing digest", principal: "p", destination: "d", identity: testIdentity(1), version: 1, event: validEvent, keyID: "k"},
		{name: "missing key", principal: "p", destination: "d", identity: testIdentity(1), version: 1, event: validEvent, digest: validDigest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewPreparedAcceptance(test.principal, test.destination, test.identity, test.version, test.event, test.digest, test.keyID, CanonicalDigest{})
			if !errors.Is(err, ErrInvalidAcceptance) {
				t.Fatal("invalid acceptance was not rejected")
			}
		})
	}
	if _, err := NewProtectedValue(nil, []byte("nonce")); !errors.Is(err, ErrInvalidAcceptance) {
		t.Error("empty ciphertext was not rejected")
	}
	if _, err := NewProtectedValue([]byte("ciphertext"), nil); !errors.Is(err, ErrInvalidAcceptance) {
		t.Error("empty nonce was not rejected")
	}
}

func TestServiceNewGeneratesExactlyOneCandidateReceipt(t *testing.T) {
	generated := 0
	receipt := testReceipt(10)
	repositoryCalls := 0
	service := NewServiceWithReceiptGenerator(
		repositoryFunc(func(_ context.Context, candidate Candidate) (PersistenceResult, error) {
			repositoryCalls++
			if candidate.ReceiptID != receipt {
				t.Error("candidate receipt mismatch")
			}
			return PersistenceResult{Inserted: true, Stored: StoredAcceptance{ReceiptID: receipt}}, nil
		}),
		openerFunc(func(context.Context, DigestOpenRequest) (CanonicalDigest, error) {
			t.Fatal("opener called for new acceptance")
			return CanonicalDigest{}, nil
		}),
		generatorFunc(func() (ReceiptID, error) {
			generated++
			return receipt, nil
		}),
	)
	result, err := service.Accept(context.Background(), testAcceptance(t, 1, testDigest(1)))
	if err != nil {
		t.Fatal("new acceptance failed")
	}
	if result.Disposition != AcceptedNew || result.ReceiptID != receipt {
		t.Error("new acceptance result mismatch")
	}
	if generated != 1 || repositoryCalls != 1 {
		t.Errorf("generator/repository calls = %d/%d, want 1/1", generated, repositoryCalls)
	}
}

func TestServiceDuplicateConflictAndUnreadableRecord(t *testing.T) {
	requestDigest := testDigest(7)
	acceptance := testAcceptance(t, 2, requestDigest)
	existingReceipt := testReceipt(20)
	storedProtected := testProtected(t, "stored-digest")
	const storedKeyID = "different-key-and-protected-bytes-are-allowed"

	tests := []struct {
		name          string
		storedVersion int64
		openedDigest  CanonicalDigest
		openErr       error
		want          Disposition
		wantReceipt   ReceiptID
		wantErr       error
	}{
		{name: "equivalent duplicate", storedVersion: 2, openedDigest: requestDigest, want: AcceptedDuplicate, wantReceipt: existingReceipt},
		{name: "format mismatch", storedVersion: 1, openedDigest: requestDigest, want: IdentityConflict},
		{name: "digest mismatch", storedVersion: 2, openedDigest: testDigest(8), want: IdentityConflict},
		{name: "missing or retired key", storedVersion: 2, openErr: errors.New("sensitive key provider detail"), wantErr: ErrStoredRecordUnreadable},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := NewServiceWithReceiptGenerator(
				repositoryFunc(func(context.Context, Candidate) (PersistenceResult, error) {
					return PersistenceResult{Stored: StoredAcceptance{
						ReceiptID:       existingReceipt,
						FormatVersion:   test.storedVersion,
						ProtectedDigest: storedProtected,
						EncryptionKeyID: storedKeyID,
					}}, nil
				}),
				openerFunc(func(_ context.Context, request DigestOpenRequest) (CanonicalDigest, error) {
					if string(request.ProtectedDigest.Ciphertext()) != string(storedProtected.Ciphertext()) ||
						string(request.ProtectedDigest.Nonce()) != string(storedProtected.Nonce()) ||
						request.EncryptionKeyID != storedKeyID ||
						request.CorePrincipalID != acceptance.CorePrincipalID() ||
						request.DestinationID != acceptance.DestinationID() ||
						request.DeliveryIdentity != acceptance.DeliveryIdentity() ||
						request.FormatVersion != test.storedVersion {
						t.Fatal("opener request context mismatch")
					}
					return test.openedDigest, test.openErr
				}),
				generatorFunc(func() (ReceiptID, error) { return testReceipt(30), nil }),
			)
			result, err := service.Accept(context.Background(), acceptance)
			if !errors.Is(err, test.wantErr) {
				t.Fatal("durable disposition error mismatch")
			}
			if test.wantErr != nil && (err == nil || strings.Contains(err.Error(), "sensitive")) {
				t.Fatal("unsafe opener error was not redacted")
			}
			if result.Disposition != test.want || result.ReceiptID != test.wantReceipt {
				t.Error("durable disposition result mismatch")
			}
			if test.want == IdentityConflict && !result.ReceiptID.IsZero() {
				t.Error("identity conflict returned a receipt")
			}
		})
	}
}

func TestServiceFailsClosedAndRedactsRepositoryAndGeneratorErrors(t *testing.T) {
	privateText := "principal destination delivery receipt ciphertext nonce digest key DSN host username certificate SQL"
	acceptance := testAcceptance(t, 1, testDigest(1))
	tests := []struct {
		name    string
		repoErr error
		want    error
	}{
		{name: "unavailable", repoErr: errors.Join(ErrStoreUnavailable, errors.New(privateText)), want: ErrStoreUnavailable},
		{name: "outcome unknown", repoErr: errors.Join(ErrStoreOutcomeUnknown, errors.New(privateText)), want: ErrStoreOutcomeUnknown},
		{name: "canceled", repoErr: errors.Join(ErrStoreCanceled, errors.New(privateText)), want: ErrStoreCanceled},
		{name: "ordinary", repoErr: errors.New(privateText), want: ErrStoreFailure},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := NewServiceWithReceiptGenerator(
				repositoryFunc(func(context.Context, Candidate) (PersistenceResult, error) {
					return PersistenceResult{}, test.repoErr
				}),
				openerFunc(func(context.Context, DigestOpenRequest) (CanonicalDigest, error) { return CanonicalDigest{}, nil }),
				generatorFunc(func() (ReceiptID, error) { return testReceipt(1), nil }),
			)
			_, err := service.Accept(context.Background(), acceptance)
			if !errors.Is(err, test.want) || strings.Contains(err.Error(), privateText) {
				t.Fatal("repository error classification was unsafe")
			}
		})
	}

	service := NewServiceWithReceiptGenerator(
		repositoryFunc(func(context.Context, Candidate) (PersistenceResult, error) {
			t.Fatal("repository called after receipt generation failure")
			return PersistenceResult{}, nil
		}),
		openerFunc(func(context.Context, DigestOpenRequest) (CanonicalDigest, error) { return CanonicalDigest{}, nil }),
		generatorFunc(func() (ReceiptID, error) { return ReceiptID{}, errors.New(privateText) }),
	)
	if _, err := service.Accept(context.Background(), acceptance); !errors.Is(err, ErrReceiptGeneration) || strings.Contains(err.Error(), privateText) {
		t.Fatal("receipt error classification was unsafe")
	}
}

func TestServiceDoesNotReplayUnknownOutcomeAndLaterCallMayInspect(t *testing.T) {
	acceptance := testAcceptance(t, 1, testDigest(4))
	existingReceipt := testReceipt(60)
	repositoryCalls := 0
	generatorCalls := 0
	service := NewServiceWithReceiptGenerator(
		repositoryFunc(func(context.Context, Candidate) (PersistenceResult, error) {
			repositoryCalls++
			if repositoryCalls == 1 {
				return PersistenceResult{}, ErrStoreOutcomeUnknown
			}
			return PersistenceResult{Stored: StoredAcceptance{
				ReceiptID:       existingReceipt,
				FormatVersion:   1,
				ProtectedDigest: testProtected(t, "stored-after-unknown"),
				EncryptionKeyID: "key-after-unknown",
			}}, nil
		}),
		openerFunc(func(context.Context, DigestOpenRequest) (CanonicalDigest, error) {
			return testDigest(4), nil
		}),
		generatorFunc(func() (ReceiptID, error) {
			generatorCalls++
			return testReceipt(byte(70 + generatorCalls)), nil
		}),
	)

	if _, err := service.Accept(context.Background(), acceptance); !errors.Is(err, ErrStoreOutcomeUnknown) {
		t.Fatal("unknown outcome classification mismatch")
	}
	if repositoryCalls != 1 || generatorCalls != 1 {
		t.Fatalf("unknown outcome was replayed: repository/generator calls = %d/%d", repositoryCalls, generatorCalls)
	}
	result, err := service.Accept(context.Background(), acceptance)
	if err != nil || result.Disposition != AcceptedDuplicate || result.ReceiptID != existingReceipt {
		t.Fatal("later duplicate inspection failed")
	}
	if repositoryCalls != 2 || generatorCalls != 2 {
		t.Fatalf("top-level calls did not each use one attempt/candidate: %d/%d", repositoryCalls, generatorCalls)
	}
}

func TestDigestComparisonPath(t *testing.T) {
	left := testDigest(1)
	right := left
	if !digestsEqual(left, right) {
		t.Fatal("equal fixed-length digests did not match")
	}
	right[len(right)-1] ^= 1
	if digestsEqual(left, right) {
		t.Fatal("different fixed-length digests matched")
	}
}
