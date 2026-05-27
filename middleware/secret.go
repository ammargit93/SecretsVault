package middleware

import (
	"crypto/rand"
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
		if claims.ServiceRole == "RD" {
			return c.JSON(fiber.Map{"Error": "Permission denied"})
		} else {
			timestamp := time.Now().UTC().Format(time.RFC3339)
			KeyEncryptionKey, err := state.EncryptAES([]byte(timestamp), []byte(state.MasterKey))
			if err != nil {
				log.Fatalln("KEK generation failed")
			}
			kek := models.KeyEncryptionKey{
				KeyEncryptionKey: KeyEncryptionKey,
				Nonce:            []byte(rand.Text()),
			}
			db.InsertKEK(conn, kek)

			DataEncryptionKey, err := state.EncryptAES([]byte(timestamp), kek.KeyEncryptionKey)
			if err != nil {
				log.Fatalln("DEK generation failed")
			}
			dek := models.DataEncryptionKey{
				DataEncryptionKey: DataEncryptionKey,
				Nonce:             []byte(rand.Text()),
			}
			db.InsertDEK(conn, dek)
		}
		return c.JSON(fiber.Map{"claims": claims})
	}
}
