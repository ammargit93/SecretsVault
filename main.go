package main

import (
	"log"
	"secretsvault/db"
	"secretsvault/middleware"

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

	app.Post("/register", middleware.Register(conn))

	app.Post("/login", middleware.Login(conn))

	app.Post("/secret/write", middleware.WriteSecret(conn))

	app.Post("/secret/read", middleware.ReadSecret(conn))

	log.Fatal(app.Listen(":8080"))
}
