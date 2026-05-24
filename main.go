package main

import (
	"context"
	"log"

	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
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

func InsertUser(db *pgxpool.Pool, username string, password string) error {
	_, err := db.Exec(
		context.Background(),
		`
		INSERT INTO users(username, password)
		VALUES($1, $2)
		`,
		username,
		password,
	)
	return err
}
func fetchUser(db *pgxpool.Pool, username string) (User, error) {
	var user User
	err := db.QueryRow(
		context.Background(),
		`
		select username,password from users where username=$1
		`,
		username,
	).Scan(&user.Username, &user.Password)
	return user, err
}

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
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

	app.Get("/hi", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"message": "hello from fiber",
		})
	})

	app.Post("/auth/register", func(c *fiber.Ctx) error {
		var user User
		if err := c.BodyParser(&user); err != nil {
			return InvalidJSON(c)
		}
		passwordHash, err := hashPassword(user.Password)

		err = InsertUser(db, user.Username, passwordHash)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{
				"error": "DB write fail",
			})
		}
		return c.Status(201).JSON(fiber.Map{
			"message": "user created",
		})
	})

	app.Post("/auth/login", func(c *fiber.Ctx) error {
		var user User
		if err := c.BodyParser(&user); err != nil {
			return InvalidJSON(c)
		}
		fetchedUser, err := fetchUser(db, user.Username)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{
				"error": "Failed to fetch user",
			})
		}
		if checkPasswordHash(user.Password, fetchedUser.Password) {
			return c.Status(200).JSON(fiber.Map{"message": "Successfully authenticated"})
		} else {
			return c.Status(200).JSON(fiber.Map{"message": "Wrong password or username"})
		}
	})

	log.Fatal(app.Listen(":8080"))
}
