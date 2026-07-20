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
	err := godotenv.Load()
	if err != nil {
		log.Println("Error loading .env file:", err)
	}

	app := fiber.New(fiber.Config{
		Concurrency: 100,
	})

	conn := db.InitDB()
	defer conn.Close()
	redisConn := db.InitRedis()
	defer redisConn.Close()
	app.Get("/health", func(c *fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	app.Post("/register", middleware.Register(conn))

	app.Post("/login", middleware.Login(conn))

	app.Post("/secret/write", middleware.WriteSecret(conn, redisConn))

	app.Post("/secret/read", middleware.ReadSecret(conn, redisConn))

	app.Post("/secret/update", middleware.UpdateSecret(conn, redisConn))

	app.Post("/secret/delete", middleware.DeleteSecret(conn, redisConn))

	go state.SaveLog()
	log.Fatal(app.Listen(":8080"))
}
