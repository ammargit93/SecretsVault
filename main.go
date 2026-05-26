package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log"

	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

type Service struct {
	ServiceName   string
	ServiceAPIKey string
	ServiceRole   string
}

type ServiceRequest struct {
	ServiceName string `json:"service_name"`
	ServiceRole string `json:"service_role"`
}

func InitDB() *pgxpool.Pool {
	conn, err := pgxpool.New(
		context.Background(),
		"postgres://ammar:1234@localhost:5432/secretsvault",
	)
	if err != nil {
		log.Fatal(err)
	}
	return conn
}

func InsertService(db *pgxpool.Pool, service Service) error {
	_, err := db.Exec(context.Background(),
		`
		INSERT INTO services(service_name, service_api_key, service_role)
		VALUES($1, $2, $3)
		`,
		service.ServiceName, service.ServiceAPIKey, service.ServiceRole,
	)
	return err
}

func fetchService(db *pgxpool.Pool, serviceName, serviceRole string) (string, error) {
	var serviceAPIKey string
	err := db.QueryRow(
		context.Background(),
		`
		select service_api_key from services where service_name=$1 and service_role=$2
		`,
		serviceName, serviceRole,
	).Scan(&serviceAPIKey)
	return serviceAPIKey, err
}

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func generateAPIKey() string {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		log.Fatal(err)
	}
	return "sv_" + hex.EncodeToString(bytes)
}

func InvalidJSON(c *fiber.Ctx) error {
	return c.Status(400).JSON(fiber.Map{
		"error": "invalid json",
	})
}

func main() {
	app := fiber.New()

	db := InitDB()
	defer db.Close()

	app.Post("/register", func(c *fiber.Ctx) error {
		var serviceRequest ServiceRequest

		c.BodyParser(&serviceRequest)
		serviceAPIKey := generateAPIKey()
		hashedAPIKey, err := hashPassword(serviceAPIKey)

		var service Service
		service.ServiceAPIKey = hashedAPIKey
		service.ServiceName = serviceRequest.ServiceName
		service.ServiceRole = serviceRequest.ServiceRole

		err = InsertService(db, service)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{
				"error": "DB write fail",
			})
		}
		return c.Status(201).JSON(fiber.Map{
			"API_KEY": serviceAPIKey,
		})
	})

	app.Post("/login", func(c *fiber.Ctx) error {
		var serviceRequest ServiceRequest

		c.BodyParser(&serviceRequest)
		serviceAPIKey := c.Get("SV_API_KEY")
		fetchedAPIKey, err := fetchService(db, serviceRequest.ServiceName, serviceRequest.ServiceRole)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{
				"error": "API_KEY mismatch",
			})
		}
		if checkPasswordHash(serviceAPIKey, fetchedAPIKey) {
			return c.Status(201).JSON(fiber.Map{
				"message": "Sucessfully Authenticated",
			})
		}

		return c.Status(500).JSON(fiber.Map{
			"error": "DB write fail",
		})

	})

	log.Fatal(app.Listen(":8080"))
}
