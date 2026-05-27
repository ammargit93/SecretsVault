package middleware

import (
	"secretsvault/db"
	"secretsvault/models"
	"secretsvault/utils"

	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5/pgxpool"
)

func Register(conn *pgxpool.Pool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		var serviceRequest models.ServiceRequest

		c.BodyParser(&serviceRequest)
		serviceAPIKey := utils.GenerateAPIKey()
		hashedAPIKey, err := utils.HashPassword(serviceAPIKey)

		var service models.Service
		service.ServiceAPIKey = hashedAPIKey
		service.ServiceName = serviceRequest.ServiceName
		service.ServiceRole = serviceRequest.ServiceRole

		err = db.InsertService(conn, service)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{
				"error": "DB write fail",
			})
		}
		return c.Status(201).JSON(fiber.Map{
			"API_KEY": serviceAPIKey,
		})
	}
}

func Login(conn *pgxpool.Pool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		var serviceRequest models.ServiceRequest

		c.BodyParser(&serviceRequest)
		serviceAPIKey := c.Get("SV-API-KEY")
		fetchedAPIKey, err := db.FetchService(conn, serviceRequest.ServiceName, serviceRequest.ServiceRole)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{
				"error": "API_KEY mismatch",
			})
		}
		if utils.CheckPasswordHash(serviceAPIKey, fetchedAPIKey) {
			jwtToken, err := utils.GenerateJWT(
				serviceRequest.ServiceName,
				serviceRequest.ServiceRole,
			)
			if err != nil {
				return c.Status(500).JSON(fiber.Map{
					"error": "failed to generate jwt",
				})
			}
			return c.JSON(fiber.Map{
				"token": jwtToken,
			})
		}

		return c.Status(500).JSON(fiber.Map{
			"error": "DB write fail",
		})
	}
}
