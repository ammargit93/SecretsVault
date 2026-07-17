package tests

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"secretsvault/middleware"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Helper to register and login a service
func registerAndLogin(t *testing.T, app *fiber.App, serviceName, role string) string {
	registerBody := map[string]string{
		"service_name": serviceName,
		"service_role": role,
	}
	bodyBytes, _ := json.Marshal(registerBody)

	req := httptest.NewRequest("POST", "/register", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, -1)
	if err != nil {
		t.Fatalf("Registration request failed: %v", err)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("Expected registration status 201, got %d", resp.StatusCode)
	}

	var registerResp map[string]string
	respBodyBytes, _ := io.ReadAll(resp.Body)
	json.Unmarshal(respBodyBytes, &registerResp)
	apiKey := registerResp["API_KEY"]

	req = httptest.NewRequest("POST", "/login", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("SV-API-KEY", apiKey)
	resp, err = app.Test(req, -1)
	if err != nil {
		t.Fatalf("Login request failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected login status 200, got %d", resp.StatusCode)
	}

	var loginResp map[string]string
	respBodyBytes, _ = io.ReadAll(resp.Body)
	json.Unmarshal(respBodyBytes, &loginResp)
	return loginResp["token"]
}

// setupApp helper initializes Fiber and connects to the DB
func setupApp(conn *pgxpool.Pool) *fiber.App {
	app := fiber.New()

	app.Post("/register", middleware.Register(conn))
	app.Post("/login", middleware.Login(conn))
	app.Post("/secret/write", middleware.WriteSecret(conn))
	app.Post("/secret/read", middleware.ReadSecret(conn))
	app.Post("/secret/update", middleware.UpdateSecret(conn))
	app.Post("/secret/delete", middleware.DeleteSecret(conn))

	return app
}
