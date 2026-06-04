package state

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
)

func EncryptKMS(plaintext []byte) ([]byte, error) {
	ctx := context.Background()

	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion("ap-south-1"))
	if err != nil {
		panic(err)
	}

	client := kms.NewFromConfig(cfg)
	keyID := os.Getenv("KMS_KEY_ID")
	result, err := client.Encrypt(ctx, &kms.EncryptInput{
		KeyId:     &keyID,
		Plaintext: plaintext,
	})
	if err != nil {
		return nil, err
	}

	return result.CiphertextBlob, nil
}

func DecryptKMS(ciphertext []byte) ([]byte, error) {
	ctx := context.Background()

	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion("ap-south-1"))
	if err != nil {
		log.Println("Error config", err)
		panic(err)
	}

	client := kms.NewFromConfig(cfg)
	keyID := os.Getenv("KMS_KEY_ID")
	result, err := client.Decrypt(ctx, &kms.DecryptInput{
		KeyId:          &keyID,
		CiphertextBlob: ciphertext,
	})
	if err != nil {
		log.Println("")
		return nil, err
	}

	return result.Plaintext, nil
}

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
