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
	if len(plaintext) != len(opened) || !bytes.Equal(plaintext, opened) {
		t.Error("Failed to open sealed message")
	}
}

func TestSealAndOpenOverWrite(t *testing.T) {
	box := NewBlackBox([]byte("test"))
	sealed := box.Seal(plaintext)
	opened, ok := box.OpenOverWrite(sealed)
	if !ok {
		t.Error("Failed to open sealed message")
	}
	if len(plaintext) != len(opened) || !bytes.Equal(plaintext, opened) {
		t.Error("Failed to open sealed message")
	}
}

func TestBase64SealAndBase64Open(t *testing.T) {
	box := NewBlackBox([]byte("test"))
	sealed := box.Base64Seal(plaintext)
	opened, ok := box.Base64Open(sealed)
	if !ok {
		t.Error("Failed to open sealed message")
	}
	if len(plaintext) != len(opened) || !bytes.Equal(plaintext, opened) {
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

func BenchmarkBlackBoxSealAndOpen(b *testing.B) {
	box := NewBlackBox([]byte("test"))
	b.RunParallel(func(p *testing.PB) {
		for p.Next() {
			sealed := box.Seal(plaintext)
			box.Open(sealed)
		}
	})
}

func BenchmarkBlackBoxSealAndOpenOverWrite(b *testing.B) {
	box := NewBlackBox([]byte("test"))
	b.RunParallel(func(p *testing.PB) {
		for p.Next() {
			sealed := box.Seal(plaintext)
			box.OpenOverWrite(sealed)
		}
	})
}

func TestInvalidLen(t *testing.T) {
	box := NewBlackBox([]byte("Hello, World!"))
	for i := 0; i < 128; i++ {
		a := make([]byte, i)
		_, ok := box.Open(a)
		if ok {
			panic("ok")
		}
		_, ok = box.OpenOverWrite(a)
		if ok {
			panic("ok")
		}
	}
}
