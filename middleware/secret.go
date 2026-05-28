package middleware

import (
	"crypto/rand"
	cryptoRand "crypto/rand"
	"encoding/json"
	"log"
	"secretsvault/db"
	"secretsvault/models"
	"secretsvault/state"
	"secretsvault/utils"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5/pgxpool"
)

func WriteSecret(conn *pgxpool.Pool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		bearer := c.Get("Authorization")
		parts := strings.Split(bearer, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid authorization header"})
		}

		claims, err := utils.ValidateJWT(parts[1])
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid token"})
		}
		if claims.ServiceRole == "RD" {
			return c.JSON(fiber.Map{"Error": "Permission denied"})
		} else {
			rawKEK := make([]byte, 32)
			if _, err := cryptoRand.Read(rawKEK); err != nil {
				log.Fatalln("Failed to generate raw KEK")
			}

			encryptedKEK, err := state.EncryptAES(rawKEK, []byte(state.MasterKey))
			if err != nil {
				log.Fatalln("KEK encryption failed")
			}

			kek := models.KeyEncryptionKey{
				KeyEncryptionKey: encryptedKEK,
				Nonce:            []byte(rand.Text()),
			}
			db.InsertKEK(conn, kek)

			rawDEK := make([]byte, 32)
			if _, err := cryptoRand.Read(rawDEK); err != nil {
				log.Fatalln("Failed to generate raw DEK")
			}

			// 4. Encrypt the raw DEK using the RAW KEK (not the encrypted 48-byte one!)
			encryptedDEK, err := state.EncryptAES(rawDEK, rawKEK)
			if err != nil {
				log.Fatalln("DEK encryption failed")
			}
			kekId, err := db.FetchKEK(conn, kek)

			dek := models.DataEncryptionKey{
				DataEncryptionKey: encryptedDEK, // Saved as 48 bytes in DB
				Nonce:             []byte(rand.Text()),
				KekIdFK:           kekId,
			}
			db.InsertDEK(conn, dek)

			dekId, err := db.FetchDEK(conn, dek)
			var secretRequest models.SecretRequest
			if err := c.BodyParser(&secretRequest); err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "cannot parse request body"})
			}

			// 6. Encrypt the SecretKey string
			encryptedSecretKey, err := state.EncryptAES([]byte(secretRequest.SecretKey), rawDEK)
			if err != nil {
				log.Println("Secret key encryption failed:", err)
				return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal server error"})
			}

			// 7. Marshal SecretValue (any) to JSON bytes so it can be encrypted
			valueBytes, err := json.Marshal(secretRequest.SecretValue)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid secret value format"})
			}

			encryptedSecretValue, err := state.EncryptAES(valueBytes, rawDEK)
			if err != nil {
				log.Println("Secret value encryption failed:", err)
				return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal server error"})
			}

			secretData := models.Secret{
				SecretKey:   encryptedSecretKey,
				SecretValue: encryptedSecretValue,
				Nonce:       []byte(rand.Text()),
				DekIdFK:     dekId,
			}

			db.InsertSecret(conn, secretData)
			return c.JSON(fiber.Map{"message": "Write successful"})

		}
	}
}
