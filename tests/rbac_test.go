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

// TestRoleBasedAccessControl ensures RD and WR roles restrict actions properly
func TestRoleBasedAccessControl(t *testing.T) {
	conn := db.InitDB()
	defer conn.Close()
	rdb := db.InitRedis()
	defer rdb.Close()

	app := setupApp(conn, rdb)

	// 1. RD (Read Only) role assertions
	rdSvcName := "rd_svc_" + strconv.FormatInt(time.Now().UnixNano(), 10)
	rdToken := registerAndLogin(t, app, rdSvcName, "RD")

	// Try write secret -> Permission Denied (status 200 but has Error body)
	writeBody := map[string]interface{}{
		"secret_key":   "rd_test_key",
		"secret_value": "data",
	}
	bodyBytes, _ := json.Marshal(writeBody)
	req := httptest.NewRequest("POST", "/secret/write", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+rdToken)
	resp, _ := app.Test(req, -1)

	var errResp map[string]string
	respBodyBytes, _ := io.ReadAll(resp.Body)
	json.Unmarshal(respBodyBytes, &errResp)
	if errResp["Error"] != "Permission denied" {
		t.Errorf("Expected write permission denied error, got %v", errResp)
	}

	// 2. WR (Write Only) role assertions
	wrSvcName := "wr_svc_" + strconv.FormatInt(time.Now().UnixNano(), 10)
	wrToken := registerAndLogin(t, app, wrSvcName, "WR")

	// Try write secret -> Allowed
	secretKey := "wr_key_" + strconv.FormatInt(time.Now().UnixNano(), 10)
	writeBody["secret_key"] = secretKey
	bodyBytes, _ = json.Marshal(writeBody)
	req = httptest.NewRequest("POST", "/secret/write", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+wrToken)
	resp, _ = app.Test(req, -1)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Write expected to succeed for WR role, got status %d", resp.StatusCode)
	}

	// Try read secret -> Permission Denied
	readBody := map[string]string{"secret_key": secretKey}
	bodyBytes, _ = json.Marshal(readBody)
	req = httptest.NewRequest("POST", "/secret/read", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+wrToken)
	resp, _ = app.Test(req, -1)

	respBodyBytes, _ = io.ReadAll(resp.Body)
	errResp = nil
	json.Unmarshal(respBodyBytes, &errResp)
	if errResp["Error"] != "Permission denied" {
		t.Errorf("Expected read permission denied error, got %v", errResp)
	}
}
