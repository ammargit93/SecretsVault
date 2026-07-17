package tests

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"secretsvault/db"
	"strconv"
	"testing"
	"time"
)

// TestSuccessFlow validates the normal happy path (RDWR role)
func TestSuccessFlow(t *testing.T) {
	conn := db.InitDB()
	defer conn.Close()

	app := setupApp(conn)

	serviceName := "success_svc_" + strconv.FormatInt(time.Now().UnixNano(), 10)
	token := registerAndLogin(t, app, serviceName, "RDWR")

	secretKey := "success_key_" + strconv.FormatInt(time.Now().UnixNano(), 10)

	// Write
	writeBody := map[string]interface{}{
		"secret_key":   secretKey,
		"secret_value": "secret_data",
	}
	bodyBytes, _ := json.Marshal(writeBody)
	req := httptest.NewRequest("POST", "/secret/write", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, _ := app.Test(req, -1)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Write secret failed: expected 200, got %d", resp.StatusCode)
	}

	// Read
	readBody := map[string]string{"secret_key": secretKey}
	bodyBytes, _ = json.Marshal(readBody)
	req = httptest.NewRequest("POST", "/secret/read", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, _ = app.Test(req, -1)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Read secret failed: expected 200, got %d", resp.StatusCode)
	}
	var readResp map[string]interface{}
	respBodyBytes, _ := io.ReadAll(resp.Body)
	json.Unmarshal(respBodyBytes, &readResp)
	if readResp["secret_value"] != "secret_data" {
		t.Errorf("Expected secret value 'secret_data', got %v", readResp["secret_value"])
	}

	// Update
	updateBody := map[string]interface{}{
		"secret_key":   secretKey,
		"secret_value": "new_secret_data",
	}
	bodyBytes, _ = json.Marshal(updateBody)
	req = httptest.NewRequest("POST", "/secret/update", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, _ = app.Test(req, -1)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Update secret failed: expected 200, got %d", resp.StatusCode)
	}

	// Read again to verify update
	req = httptest.NewRequest("POST", "/secret/read", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, _ = app.Test(req, -1)
	respBodyBytes, _ = io.ReadAll(resp.Body)
	json.Unmarshal(respBodyBytes, &readResp)
	if readResp["secret_value"] != "new_secret_data" {
		t.Errorf("Expected updated secret value 'new_secret_data', got %v", readResp["secret_value"])
	}

	// Delete
	req = httptest.NewRequest("POST", "/secret/delete", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, _ = app.Test(req, -1)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Delete secret failed: expected 200, got %d", resp.StatusCode)
	}
}
