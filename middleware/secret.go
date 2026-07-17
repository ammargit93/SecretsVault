package middleware

import (
	"context"
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

	"github.com/go-redis/redis/v8"
	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5/pgxpool"
)

func WriteSecret(conn *pgxpool.Pool, rdb *redis.Client) fiber.Handler {
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
			var secretRequest models.SecretRequest
			if err := c.BodyParser(&secretRequest); err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "cannot parse request body"})
			}

			serviceId, err := db.FetchServiceId(conn, serviceName)
			if err != nil {
				log.Println("Failed to fetch service ID:", err)
				return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "service not found"})
			}

			var dekId int
			var rawDEK []byte

			existingDekId, err := db.FetchActiveDekIdForService(conn, serviceId)
			if err == nil {
				dekId = existingDekId
				payload, err := db.FetchDEKAndKEKByDekId(conn, dekId)
				if err != nil {
					log.Println("Failed to fetch shared DEK and KEK:", err)
					return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal error"})
				}
				decryptedKEK, err := utils.DecryptKMS(payload.EncryptedKEK)
				if err != nil {
					log.Println("Failed to decrypt KEK:", err)
					return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal error"})
				}
				rawDEK, err = utils.DecryptAES(payload.EncryptedDEK, decryptedKEK)
				if err != nil {
					log.Println("Failed to decrypt DEK:", err)
					return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal error"})
				}
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

				rawDEK = make([]byte, 32)
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
					KekIdFK:           kekId,
				}

				dekId, err = db.InsertDEK(conn, dek)
				if err != nil {
					log.Println("Failed to insert DEK into DB:", err)
					return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "database error"})
				}
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

			secretData := models.Secret{
				SecretKey:   secretRequest.SecretKey,
				SecretValue: encryptedSecretValue,
				Nonce:       []byte(rand.Text()),
				DekIdFK:     dekId,
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

func ReadSecret(conn *pgxpool.Pool, rdb *redis.Client) fiber.Handler {
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
			cacheKey := fmt.Sprintf("secret:%s:%s", serviceName, secretKey)
			msg := fmt.Sprintf(
				"%s %s %s %s RD",
				time.Now().Format("2006-01-02 15:04:05"),
				secretKey,
				serviceName,
				claims.ServiceRole,
			)

			val, err := rdb.Get(context.Background(), cacheKey).Result()
			if err == nil {
				state.Channel <- msg
				return c.JSON(fiber.Map{"secret_value": json.RawMessage(val)})
			}

			secretsList, err := db.FetchSecretsForService(conn, serviceName)
			if err != nil {
				log.Println("Failed to fetch secrets for service:", serviceName, "err:", err)
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

			descPayload, err := db.FetchSecretDecryptionPayload(conn, secretKey, serviceName)
			if err != nil {
				log.Println("Failed to fetch payload:", err)
				return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "secret not found"})
			}

			decryptedKEK, err := utils.DecryptKMS(descPayload.EncryptedKEK)
			if err != nil {
				return c.Status(500).JSON(fiber.Map{"error": "failed to decrypt KEK"})
			}

			decryptedDEK, err := utils.DecryptAES(descPayload.EncryptedDEK, decryptedKEK)
			if err != nil {
				return c.Status(500).JSON(fiber.Map{"error": "failed to decrypt KEK"})
			}

			decryptedSecretValue, err := utils.DecryptAES(descPayload.EncryptedSecretValue, decryptedDEK)
			if err != nil {
				return c.Status(500).JSON(fiber.Map{"error": "failed to decrypt secret value"})
			}

			// Store in Redis (namespaced, with 24 hours TTL)
			err = rdb.Set(context.Background(), cacheKey, decryptedSecretValue, 24*time.Hour).Err()
			if err != nil {
				log.Println("Failed to cache secret in Redis:", err)
			}

			state.Channel <- msg
			return c.JSON(fiber.Map{"secret_value": json.RawMessage(decryptedSecretValue)})
		}
	}
}

func UpdateSecret(conn *pgxpool.Pool, rdb *redis.Client) fiber.Handler {
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
		}

		var secretRequest models.SecretRequest
		if err := c.BodyParser(&secretRequest); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "cannot parse request body"})
		}

		// Security check: Verify if the service owns this secret
		secretsList, err := db.FetchSecretsForService(conn, serviceName)
		if err != nil || len(secretsList) == 0 {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "secret not found"})
		}
		flag := false
		for _, s := range secretsList {
			if s == secretRequest.SecretKey {
				flag = true
				break
			}
		}
		if !flag {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "secret not found"})
		}

		descPayload, err := db.FetchSecretDecryptionPayload(conn, secretRequest.SecretKey, serviceName)
		if err != nil {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "secret not found"})
		}

		decryptedKEK, err := utils.DecryptKMS(descPayload.EncryptedKEK)
		if err != nil {
			log.Println("Failed to decrypt KEK:", err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal error"})
		}

		decryptedDEK, err := utils.DecryptAES(descPayload.EncryptedDEK, decryptedKEK)
		if err != nil {
			log.Println("Failed to decrypt DEK:", err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal error"})
		}

		valueBytes, err := json.Marshal(secretRequest.SecretValue)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid secret value format"})
		}

		encryptedSecretValue, err := utils.EncryptAES(valueBytes, decryptedDEK)
		if err != nil {
			log.Println("Secret value encryption failed:", err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal error"})
		}

		newNonce := []byte(rand.Text())
		err = db.UpdateSecret(conn, secretRequest.SecretKey, serviceName, encryptedSecretValue, newNonce)
		if err != nil {
			log.Println("Failed to update secret in DB:", err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "database error"})
		}

		// Invalidate cache
		cacheKey := fmt.Sprintf("secret:%s:%s", serviceName, secretRequest.SecretKey)
		rdb.Del(context.Background(), cacheKey)

		msg := fmt.Sprintf(
			"%s %s %s %s UP",
			time.Now().Format("2006-01-02 15:04:05"),
			secretRequest.SecretKey,
			serviceName,
			claims.ServiceRole,
		)
		state.Channel <- msg

		return c.JSON(fiber.Map{"message": "updated", "secret_key": secretRequest.SecretKey})
	}
}

func DeleteSecret(conn *pgxpool.Pool, rdb *redis.Client) fiber.Handler {
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
		}

		rawBody := c.Body()
		var bodyMap map[string]string
		json.Unmarshal(rawBody, &bodyMap)

		secretKey, exists := bodyMap["secret_key"]
		if !exists {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "missing secret_key"})
		}

		// Security check: Verify if the service owns this secret
		secretsList, err := db.FetchSecretsForService(conn, serviceName)
		if err != nil || len(secretsList) == 0 {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "secret not found"})
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

		err = db.DeleteSecret(conn, secretKey, serviceName)
		if err != nil {
			log.Println("Failed to delete secret:", err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to delete secret"})
		}

		// Invalidate cache
		cacheKey := fmt.Sprintf("secret:%s:%s", serviceName, secretKey)
		rdb.Del(context.Background(), cacheKey)

		msg := fmt.Sprintf(
			"%s %s %s %s DL",
			time.Now().Format("2006-01-02 15:04:05"),
			secretKey,
			serviceName,
			claims.ServiceRole,
		)
		state.Channel <- msg

		return c.JSON(fiber.Map{"message": "deleted", "secret_key": secretKey})
	}
}
