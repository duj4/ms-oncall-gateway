package durable

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"io"
)

type Disposition uint8

const (
	AcceptedNew Disposition = iota + 1
	AcceptedDuplicate
	IdentityConflict
)

type Result struct {
	Disposition Disposition
	ReceiptID   ReceiptID
}

type Store interface {
	Accept(context.Context, PreparedAcceptance) (Result, error)
}

type Candidate struct {
	ReceiptID  ReceiptID
	Acceptance PreparedAcceptance
}

type StoredAcceptance struct {
	ReceiptID       ReceiptID
	FormatVersion   int64
	ProtectedDigest ProtectedValue
	EncryptionKeyID string
}

type PersistenceResult struct {
	Inserted bool
	Stored   StoredAcceptance
}

type Repository interface {
	InsertOrLoad(context.Context, Candidate) (PersistenceResult, error)
}

type DigestOpener interface {
	OpenDigest(context.Context, ProtectedValue, string) (CanonicalDigest, error)
}

type ReceiptGenerator interface {
	NewReceiptID() (ReceiptID, error)
}

type UUIDv4Generator struct {
	Reader io.Reader
}

func (generator UUIDv4Generator) NewReceiptID() (ReceiptID, error) {
	reader := generator.Reader
	if reader == nil {
		reader = rand.Reader
	}
	var receipt ReceiptID
	if _, err := io.ReadFull(reader, receipt[:]); err != nil {
		return ReceiptID{}, ErrReceiptGeneration
	}
	receipt[6] = (receipt[6] & 0x0f) | 0x40
	receipt[8] = (receipt[8] & 0x3f) | 0x80
	return receipt, nil
}

type Service struct {
	repository Repository
	opener     DigestOpener
	receipts   ReceiptGenerator
}

func NewService(repository Repository, opener DigestOpener) *Service {
	return NewServiceWithReceiptGenerator(repository, opener, UUIDv4Generator{})
}

func NewServiceWithReceiptGenerator(repository Repository, opener DigestOpener, receipts ReceiptGenerator) *Service {
	return &Service{repository: repository, opener: opener, receipts: receipts}
}

func (service *Service) Accept(ctx context.Context, acceptance PreparedAcceptance) (Result, error) {
	if service == nil || service.repository == nil || service.opener == nil || service.receipts == nil {
		return Result{}, ErrStoreFailure
	}
	if err := acceptance.validate(); err != nil {
		return Result{}, ErrInvalidAcceptance
	}

	receipt, err := service.receipts.NewReceiptID()
	if err != nil || receipt.IsZero() {
		return Result{}, ErrReceiptGeneration
	}
	persisted, err := service.repository.InsertOrLoad(ctx, Candidate{
		ReceiptID:  receipt,
		Acceptance: acceptance,
	})
	if err != nil {
		return Result{}, classifyRepositoryError(err)
	}
	if persisted.Inserted {
		if persisted.Stored.ReceiptID != receipt {
			return Result{}, ErrStoreFailure
		}
		return Result{Disposition: AcceptedNew, ReceiptID: receipt}, nil
	}

	stored := persisted.Stored
	if stored.ReceiptID.IsZero() || stored.FormatVersion <= 0 || !stored.ProtectedDigest.valid() || stored.EncryptionKeyID == "" {
		return Result{}, ErrStoredRecordUnreadable
	}
	storedDigest, err := service.opener.OpenDigest(ctx, cloneProtectedValue(stored.ProtectedDigest), stored.EncryptionKeyID)
	if err != nil {
		return Result{}, ErrStoredRecordUnreadable
	}
	if stored.FormatVersion == acceptance.formatVersion && digestsEqual(storedDigest, acceptance.equivalenceDigest) {
		return Result{Disposition: AcceptedDuplicate, ReceiptID: stored.ReceiptID}, nil
	}
	return Result{Disposition: IdentityConflict}, nil
}

func digestsEqual(left, right CanonicalDigest) bool {
	return subtle.ConstantTimeCompare(left[:], right[:]) == 1
}

func classifyRepositoryError(err error) error {
	for _, safe := range []error{
		ErrStoreUnavailable,
		ErrStoreOutcomeUnknown,
		ErrStoreCanceled,
		ErrStoreFailure,
		ErrStoredRecordUnreadable,
	} {
		if errors.Is(err, safe) {
			return safe
		}
	}
	return ErrStoreFailure
}
