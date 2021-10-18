package vbox

import (
	"bytes"
	"testing"
)

var plaintext = []byte(`
Hello, world!

This is a super-secret message.
do not share!

This message is encrypted with the AES256-GCM cipher and XChaCha20-Poly1305.
So, it is highly encrypted!

The key of the this message are hashed with blake3-512 Alogrithm.
`)

func TestBlackBox(t *testing.T) {
	box := NewBlackBox([]byte("test"))
	sealed := box.Seal(plaintext)
	opened, ok := box.Open(sealed)
	if !ok {
		t.Error("Failed to open sealed message")
	}
	if !bytes.Equal(plaintext, opened) {
		t.Error("Failed to open sealed message")
	}
}

func BenchmarkBlackBoxSeal(b *testing.B) {
	box := NewBlackBox([]byte("test"))
	b.RunParallel(func(p *testing.PB) {
		for p.Next() {
			box.Seal(plaintext)
		}
	})
}

func BenchmarkBlackBoxOpen(b *testing.B) {
	box := NewBlackBox([]byte("test"))
	sealed := box.Seal(plaintext)
	b.RunParallel(func(p *testing.PB) {
		for p.Next() {
			box.Open(sealed)
		}
	})
}
