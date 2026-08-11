package protection

import (
	"context"
)

const aes256KeySize = 32

type Key struct {
	id       string
	material []byte
}

func NewKey(id string, material []byte) (Key, error) {
	if id == "" || validateAADString(id) != nil || len(material) != aes256KeySize {
		return Key{}, ErrProtectionInvalid
	}
	return Key{id: id, material: append([]byte(nil), material...)}, nil
}

func (key Key) ID() string {
	return key.id
}

func (key Key) valid() bool {
	return key.id != "" && validateAADString(key.id) == nil && len(key.material) == aes256KeySize
}

func (key Key) materialCopy() []byte {
	return append([]byte(nil), key.material...)
}

type KeySource interface {
	ActiveKey(context.Context) (Key, error)
	KeyByID(context.Context, string) (Key, error)
}
