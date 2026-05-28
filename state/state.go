package state

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

var MasterKey = []byte("thisis32bytekeythisis32bytekey!!")

// EncryptAES encrypts plaintext using AES-256-GCM
func EncryptAES(plaintext []byte, key []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("key must be exactly 32 bytes for AES-256")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())

	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// nonce is prepended to ciphertext
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	return ciphertext, nil
}

// DecryptAES decrypts AES-256-GCM encrypted data
func DecryptAES(ciphertext []byte, key []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("key must be exactly 32 bytes for AES-256")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()

	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce := ciphertext[:nonceSize]
	actualCiphertext := ciphertext[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, actualCiphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}
