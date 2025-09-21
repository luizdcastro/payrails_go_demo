package controllers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"time"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
)

var cachedToken string
var tokenExpiry time.Time

func init() {
	// Load .env locally if it exists
	_ = godotenv.Load()
}

func getEnv(key string) string {
	return os.Getenv(key)
}

func getBearerToken() (string, error) {
	clientId := getEnv("PAYRAILS_CLIENT_ID")
	apiKey := getEnv("PAYRAILS_API_KEY")
	baseUrl := getEnv("PAYRAILS_BASE_URL")

	if clientId == "" || apiKey == "" || baseUrl == "" {
		return "", fmt.Errorf("clientId, apiKey, or baseUrl missing")
	}

	if cachedToken != "" && time.Now().Before(tokenExpiry) {
		return cachedToken, nil
	}

	url := fmt.Sprintf("%s/auth/token/%s", baseUrl, clientId)
	req, _ := http.NewRequest("POST", url, nil)
	req.Header.Set("accept", "application/json")
	req.Header.Set("x-api-key", apiKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to fetch token: %s", string(body))
	}

	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return "", err
	}

	token, ok := data["access_token"].(string)
	if !ok {
		return "", fmt.Errorf("access_token not found")
	}

	cachedToken = token
	tokenExpiry = time.Now().Add(9 * time.Minute)
	return token, nil
}

func InitSDK(c *gin.Context) {
	token, err := getBearerToken()
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	baseUrl := getEnv("PAYRAILS_BASE_URL")
	url := fmt.Sprintf("%s/merchant/client/init", baseUrl)
	idempotencyKey := uuid.NewString()

	var payload map[string]interface{}
	if err := c.ShouldBindJSON(&payload); err != nil || len(payload) == 0 {
		payload = map[string]interface{}{
			"type":             "dropIn",
			"workflowCode":     "payment-acceptance",
			"merchantReference": uuid.NewString(),
			"holderReference":   uuid.NewString(),
			"amount": map[string]string{"value": "999", "currency": "EUR"},
		}
	}

	bodyData, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", url, bytes.NewBuffer(bodyData))
	req.Header.Set("accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-idempotency-key", idempotencyKey)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	defer resp.Body.Close()

	respBody, _ := ioutil.ReadAll(resp.Body)
	var respData map[string]interface{}
	_ = json.Unmarshal(respBody, &respData)

	c.JSON(resp.StatusCode, gin.H{
		"status": "success",
		"data":   respData,
	})
}