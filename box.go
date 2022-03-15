package vbox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20poly1305"
)

type BlackBox struct {
	key [64]byte

	aead0 cipher.AEAD
	aead1 cipher.AEAD
}

func NewBlackBox(key []byte) *BlackBox {
	box := &BlackBox{
		key: blake2b.Sum512(key),
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

// Seal allocates a new slice and copies the encrypted data into it.
func (b *BlackBox) Seal(src []byte) []byte {
	var noncesize0, noncesize1 int = b.aead0.NonceSize(), b.aead1.NonceSize()
	var overhead0, overhead1 int = b.aead0.Overhead(), b.aead1.Overhead()
	outputbuf := make([]byte, noncesize0+noncesize1+len(src)+overhead0+overhead1)

	n, err := rand.Read(outputbuf[:noncesize0+noncesize1])
	if err != nil || n != noncesize0+noncesize1 {
		panic(err)
	}
	b.aead0.Seal(outputbuf[:noncesize0+noncesize1], outputbuf[noncesize1:noncesize0+noncesize1], src, nil)
	return b.aead1.Seal(outputbuf[:noncesize1], outputbuf[:noncesize1], outputbuf[noncesize1:noncesize0+noncesize1+len(src)+overhead0], nil)
}

// Open allocates a new slice and copies the decrypted data into it.
func (b *BlackBox) Open(src []byte) ([]byte, bool) {
	return b.openDst(nil, src)
}

// OpenOverWrite overwrites the input slice with the decrypted data.
// Better Performance than Open. But the input slice will be overwritten.
func (b *BlackBox) OpenOverWrite(src []byte) ([]byte, bool) {
	return b.openDst(src[b.aead1.NonceSize():], src)
}

func (b *BlackBox) openDst(dst, src []byte) ([]byte, bool) {
	var noncesize0, noncesize1 int = b.aead0.NonceSize(), b.aead1.NonceSize()
	var overhead0, overhead1 int = b.aead0.Overhead(), b.aead1.Overhead()
	if len(src) < noncesize0+noncesize1+overhead0+overhead1 {
		return nil, false
	}
	nonce1 := src[:noncesize1]
	dst, err := b.aead1.Open(dst[:0], nonce1, src[noncesize1:], nil)
	if err != nil {
		return nil, false
	}
	nonce0 := dst[:noncesize0]
	dst, err = b.aead0.Open(dst[noncesize0:noncesize0], nonce0, dst[noncesize0:], nil)
	if err != nil {
		return nil, false
	}
	return dst, true
}

// Base64Seal Seal and encode the data to base64 raw URL encoding.
func (b *BlackBox) Base64Seal(src []byte) string {
	return base64.RawURLEncoding.EncodeToString(b.Seal(src))
}

// Base64Open decode the data from base64 raw URL encoding and Open it.
func (b *BlackBox) Base64Open(src string) ([]byte, bool) {
	data, err := base64.RawURLEncoding.DecodeString(src)
	if err != nil {
		return nil, false
	}
	return b.Open(data)
}
