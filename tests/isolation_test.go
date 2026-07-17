package tests

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"secretsvault/db"
	"strconv"
	"testing"
	"time"
)

// TestTenantIsolation ensures Service A cannot read or edit Service B's secrets
func TestTenantIsolation(t *testing.T) {
	conn := db.InitDB()
	defer conn.Close()
	rdb := db.InitRedis()
	defer rdb.Close()

	app := setupApp(conn, rdb)

	// Register two services
	svcA := "svcA_" + strconv.FormatInt(time.Now().UnixNano(), 10)
	svcB := "svcB_" + strconv.FormatInt(time.Now().UnixNano(), 10)

	tokenA := registerAndLogin(t, app, svcA, "RDWR")
	tokenB := registerAndLogin(t, app, svcB, "RDWR")

	// Service A writes a secret
	secretKey := "shared_key_" + strconv.FormatInt(time.Now().UnixNano(), 10)
	writeBody := map[string]interface{}{
		"secret_key":   secretKey,
		"secret_value": "data_for_a",
	}
	bodyBytes, _ := json.Marshal(writeBody)
	req := httptest.NewRequest("POST", "/secret/write", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tokenA)
	resp, _ := app.Test(req, -1)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Service A write secret failed")
	}

	// Service B attempts to read Service A's secret -> 401 Unauthorized (secret not found)
	readBody := map[string]string{"secret_key": secretKey}
	bodyBytes, _ = json.Marshal(readBody)
	req = httptest.NewRequest("POST", "/secret/read", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tokenB)
	resp, _ = app.Test(req, -1)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("Expected B read Service A's secret to fail with 401, got %d", resp.StatusCode)
	}

	// Service B attempts to update Service A's secret -> 401 Unauthorized (secret not found)
	updateBody := map[string]interface{}{
		"secret_key":   secretKey,
		"secret_value": "malicious_update",
	}
	bodyBytes, _ = json.Marshal(updateBody)
	req = httptest.NewRequest("POST", "/secret/update", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tokenB)
	resp, _ = app.Test(req, -1)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("Expected B update Service A's secret to fail with 401, got %d", resp.StatusCode)
	}

	// Service B attempts to delete Service A's secret -> 401 Unauthorized (secret not found)
	req = httptest.NewRequest("POST", "/secret/delete", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tokenB)
	resp, _ = app.Test(req, -1)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("Expected B delete Service A's secret to fail with 401, got %d", resp.StatusCode)
	}
}
