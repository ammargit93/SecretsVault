package middleware

import (
	"crypto/rand"
	cryptoRand "crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"secretsvault/db"
	"secretsvault/models"
	"secretsvault/state"
	"secretsvault/utils"
	"strings"
	"time"

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
		serviceName := claims.ServiceName
		if claims.ServiceRole == "RD" {
			return c.JSON(fiber.Map{"Error": "Permission denied"})
		} else {

			rawKEK := make([]byte, 32)
			if _, err := cryptoRand.Read(rawKEK); err != nil {
				log.Println("Failed to generate raw KEK:", err)
				return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal error"})
			}

			encryptedKEK, err := utils.EncryptKMS(rawKEK)
			if err != nil {
				log.Println("KEK encryption failed:", err)
				return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal error"})
			}

			kek := models.KeyEncryptionKey{
				KeyEncryptionKey: encryptedKEK,
				Nonce:            []byte(rand.Text()),
			}

			kekId, err := db.InsertKEK(conn, kek)
			if err != nil {
				log.Println("Failed to insert KEK into DB:", err)
				return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "database error"})
			}

			// 2. Generate and encrypt DEK
			rawDEK := make([]byte, 32)
			if _, err := cryptoRand.Read(rawDEK); err != nil {
				log.Println("Failed to generate raw DEK:", err)
				return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal error"})
			}

			encryptedDEK, err := utils.EncryptAES(rawDEK, rawKEK)
			if err != nil {
				log.Println("DEK encryption failed:", err)
				return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal error"})
			}

			dek := models.DataEncryptionKey{
				DataEncryptionKey: encryptedDEK,
				Nonce:             []byte(rand.Text()),
				KekIdFK:           kekId, // Uses guaranteed KEK ID
			}

			// Capture the ID directly from the insert!
			dekId, err := db.InsertDEK(conn, dek)
			if err != nil {
				log.Println("Failed to insert DEK into DB:", err)
				return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "database error"})
			}

			// 3. Parse and process Secret payload
			var secretRequest models.SecretRequest
			if err := c.BodyParser(&secretRequest); err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "cannot parse request body"})
			}

			valueBytes, err := json.Marshal(secretRequest.SecretValue)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid secret value format"})
			}

			encryptedSecretValue, err := utils.EncryptAES(valueBytes, rawDEK)
			if err != nil {
				log.Println("Secret value encryption failed:", err)
				return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal error"})
			}

			serviceId, err := db.FetchServiceId(conn, serviceName)
			secretData := models.Secret{
				SecretKey:   secretRequest.SecretKey,
				SecretValue: encryptedSecretValue,
				Nonce:       []byte(rand.Text()),
				DekIdFK:     dekId, // Uses guaranteed DEK ID
				ServiceId:   serviceId,
			}

			if err := db.InsertSecret(conn, secretData); err != nil {
				log.Println("Failed to insert secret:", secretData.SecretKey, err)
				return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to save secret"})
			}
			msg := fmt.Sprintf(
				"%s %s %s %s WR",
				time.Now().Format("2006-01-02 15:04:05"),
				secretRequest.SecretKey,
				serviceName,
				claims.ServiceRole,
			)
			state.Channel <- msg
			return c.JSON(fiber.Map{"message": secretRequest.SecretKey})
		}
	}
}

func ReadSecret(conn *pgxpool.Pool) fiber.Handler {
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
		serviceName := claims.ServiceName
		if claims.ServiceRole == "WR" {
			return c.JSON(fiber.Map{"Error": "Permission denied"})
		} else {
			rawBody := c.Body()
			var bodyMap map[string]string
			json.Unmarshal(rawBody, &bodyMap)

			secretKey, exists := bodyMap["secret_key"]
			if !exists {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "missing secret_key"})
			}
			secretsList, err := db.FetchSecretsForService(conn, serviceName)
			if err != nil || len(secretsList) == 0 {
				log.Println("Failed to fetch secrets for service: ", serviceName)
				return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to fetch secrets"})
			}
			flag := false
			for _, s := range secretsList {
				if s == secretKey {
					flag = true
					break
				}
			}
			if !flag {
				return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "secret not found"})
			}
			msg := fmt.Sprintf(
				"%s %s %s %s RD",
				time.Now().Format("2006-01-02 15:04:05"),
				secretKey,
				serviceName,
				claims.ServiceRole,
			)
			skc, exists := Cache[secretKey]
			if exists {
				for _, v := range skc {
					if v.ServiceName == serviceName {
						state.Channel <- msg
						return c.JSON(fiber.Map{"secret_value": json.RawMessage(v.SecretValue)})
					}
				}
			}
			descPayload, err := db.FetchSecretDecryptionPayload(conn, secretKey, serviceName)
			if err != nil {
				log.Println("Failed to fetch payload:", err)
				return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "secret not found"})
			}

			decryptedKEK, err := utils.DecryptKMS(descPayload.EncryptedKEK)
			if err != nil {
				log.Fatalln("Failed to decrypt KEK:", err)
			}

			decryptedDEK, err := utils.DecryptAES(descPayload.EncryptedDEK, decryptedKEK)
			if err != nil {
				log.Fatalln("Failed to decrypt DEK:", err)
			}

			decryptedSecretValue, err := utils.DecryptAES(descPayload.EncryptedSecretValue, decryptedDEK)
			if err != nil {
				log.Fatalln("Failed to decrypt Secret Value:", err)
			}
			Cache[secretKey] = append(Cache[secretKey], CacheStruct{
				ServiceName: serviceName,
				SecretValue: decryptedSecretValue,
			})

			state.Channel <- msg
			return c.JSON(fiber.Map{"secret_value": json.RawMessage(decryptedSecretValue)})
		}
	}
}
