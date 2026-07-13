package main

import (
	"log"
	"secretsvault/db"
	"secretsvault/middleware"
	"secretsvault/state"

	"github.com/gofiber/fiber/v2"
	"github.com/joho/godotenv"
)

func main() {
	app := fiber.New()

	conn := db.InitDB()
	defer conn.Close()
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
	app.Get("/health", func(c *fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	app.Post("/register", middleware.Register(conn))

	app.Post("/login", middleware.Login(conn))

	app.Post("/secret/write", middleware.WriteSecret(conn))

	app.Post("/secret/read", middleware.ReadSecret(conn))

	app.Post("/secret/update", middleware.UpdateSecret(conn))

	app.Post("/secret/delete", middleware.DeleteSecret(conn))

	go state.SaveLog()
	log.Fatal(app.Listen(":8080"))
}
