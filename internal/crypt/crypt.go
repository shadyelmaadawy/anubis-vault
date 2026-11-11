//go:build windows

package crypt

import (
	"crypto/rand"

	"golang.org/x/crypto/chacha20poly1305"
)
// Fill populates the provided byte slice with cryptographically secure random bytes.
func Fill(data []byte) error {
	_, err := rand.Read(data)
	return err
}

// Seal encrypts and authenticates data in-place using XChaCha20-Poly1305.
// The data slice must have enough underlying capacity to accommodate the 16-byte authentication tag.

func Seal(data, key, nonce []byte) error {

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return err 
	}
	aead.Seal(data[:0], nonce, data, nil)

	return nil
}
// Open decrypts and verifies authenticated data in-place using XChaCha20-Poly1305.
func Open(data, key, nonce []byte) error {

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return err
	}

	if _, err := aead.Open(data[:0], nonce, data, nil); err != nil {
		return err
	}

	return nil
}