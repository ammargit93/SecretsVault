package tests

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"secretsvault/db"
	"testing"
)

// TestAuthenticationErrors verifies error cases for missing / malformed API Key and JWT tokens
func TestAuthenticationErrors(t *testing.T) {
	conn := db.InitDB()
	defer conn.Close()
	rdb := db.InitRedis()
	defer rdb.Close()

	app := setupApp(conn, rdb)

	// 1. Missing SV-API-KEY in login
	loginBody := map[string]string{
		"service_name": "any_svc",
		"service_role": "RDWR",
	}
	bodyBytes, _ := json.Marshal(loginBody)
	req := httptest.NewRequest("POST", "/login", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	resp, _ := app.Test(req, -1)
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("Expected login with missing API Key to return 500, got %d", resp.StatusCode)
	}

	// 2. Missing authorization header
	req = httptest.NewRequest("POST", "/secret/write", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	resp, _ = app.Test(req, -1)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("Expected missing Authorization header to return 401, got %d", resp.StatusCode)
	}

	// 3. Invalid JWT token
	req = httptest.NewRequest("POST", "/secret/write", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer invalid_token_value_here")
	resp, _ = app.Test(req, -1)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("Expected invalid JWT token to return 401, got %d", resp.StatusCode)
	}
}
