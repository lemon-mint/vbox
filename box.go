package vbox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"

	"github.com/zeebo/blake3"
	"golang.org/x/crypto/chacha20poly1305"
)

type BlackBox struct {
	key [64]byte

	aead0 cipher.AEAD
	aead1 cipher.AEAD
}

func NewBlackBox(key []byte) *BlackBox {
	box := &BlackBox{
		key: blake3.Sum512(key),
	}
	chapoly, err := chacha20poly1305.NewX(box.key[:32])
	if err != nil {
		panic(err)
	}
	aesc, err := aes.NewCipher(box.key[32:])
	if err != nil {
		panic(err)
	}
	aesgcm, err := cipher.NewGCM(aesc)
	if err != nil {
		panic(err)
	}
	box.aead0 = chapoly
	box.aead1 = aesgcm
	return box
}

func (b *BlackBox) Seal(src []byte) []byte {
	nonce0 := make([]byte, b.aead0.NonceSize())
	nonce1 := make([]byte, b.aead1.NonceSize())
	n, err := rand.Read(nonce0)
	if err != nil || n != len(nonce0) {
		panic(err)
	}
	n, err = rand.Read(nonce1)
	if err != nil || n != len(nonce1) {
		panic(err)
	}
	data := b.aead0.Seal(nonce0, nonce0, src, nil)
	return b.aead1.Seal(nonce1, nonce1, data, nil)
}

func (b *BlackBox) Open(src []byte) ([]byte, bool) {
	if len(src) < b.aead1.NonceSize() {
		return nil, false
	}
	nonce1 := src[:b.aead1.NonceSize()]
	data, err := b.aead1.Open(nil, nonce1, src[b.aead1.NonceSize():], nil)
	if err != nil {
		return nil, false
	}
	if len(data) < b.aead0.NonceSize() {
		return nil, false
	}
	nonce0 := data[:b.aead0.NonceSize()]
	data, err = b.aead0.Open(nil, nonce0, data[b.aead0.NonceSize():], nil)
	if err != nil {
		return nil, false
	}
	return data, true
}
