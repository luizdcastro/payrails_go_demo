package controllers

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

var cachedToken string
var tokenExpiry time.Time

func getEnv(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

func getBearerToken() (string, error) {
	clientId := getEnv("PAYRAILS_CLIENT_ID", "")
	apiKey := getEnv("PAYRAILS_API_KEY", "")
	baseUrl := getEnv("PAYRAILS_BASE_URL", "https://rc-api.staging.payrails.io")

	if clientId == "" || apiKey == "" {
		return "", fmt.Errorf("clientId or apiKey not set in environment variables")
	}

	if cachedToken != "" && time.Now().Before(tokenExpiry) {
		return cachedToken, nil
	}

	url := fmt.Sprintf("%s/auth/token/%s", baseUrl, clientId)
	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("accept", "application/json")
	req.Header.Set("x-api-key", apiKey)

	client := &http.Client{}
	resp, err := client.Do(req)
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

	accessToken, ok := data["access_token"].(string)
	if !ok {
		return "", fmt.Errorf("access_token not found in response")
	}

	cachedToken = accessToken
	tokenExpiry = time.Now().Add(9 * time.Minute)
	return accessToken, nil
}

func createMTLSClient() (*http.Client, error) {
	certFile := os.Getenv("MTLS_CLIENT_CERT")
	keyFile := os.Getenv("MTLS_CLIENT_KEY")

	if certFile == "" || keyFile == "" {
		return nil, fmt.Errorf("mTLS certificate paths not set in environment variables")
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load client certificate/key: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	return &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsConfig},
	}, nil
}

func InitSDK(c *gin.Context) {
	accessToken, err := getBearerToken()
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	idempotencyKey := uuid.NewString()
	baseUrl := getEnv("PAYRAILS_BASE_URL", "https://rc-api.staging.payrails.io")
	url := fmt.Sprintf("%s/merchant/client/init", baseUrl)

	var payload map[string]interface{}
	if err := c.ShouldBindJSON(&payload); err != nil || payload == nil || len(payload) == 0 {
		// Use default payload if body is empty or invalid
		payload = map[string]interface{}{
			"type":            "dropIn",
			"workflowCode":    "payment-acceptance",
			"merchantReference": uuid.NewString(),
			"holderReference":   uuid.NewString(),
			"amount": map[string]string{
				"value":    "999",
				"currency": "EUR",
			},
			"meta": map[string]interface{}{
				"customer": map[string]interface{}{
					"email": "test@example.com",
					"country": map[string]string{
						"code": "DE",
					},
				},
				"CIT": true,
				"order": map[string]interface{}{
					"lines": []map[string]interface{}{
						{
							"id":       "line_demo_1",
							"name":     "Basic Package",
							"quantity": 1,
							"unitPrice": map[string]string{
								"currency": "EUR",
								"value":    "999",
							},
						},
					},
				},
			},
		}
		fmt.Println("[InitSDK] Using default demo payload with random IDs")
	} else {
		fmt.Println("[InitSDK] Using client-provided payload")
	}

	jsonPayload, _ := json.Marshal(payload)
	client, err := createMTLSClient()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonPayload))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create request"})
		return
	}

	req.Header.Set("accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-idempotency-key", idempotencyKey)
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := client.Do(req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		c.JSON(resp.StatusCode, gin.H{"error": string(body)})
		return
	}

	var responseData map[string]interface{}
	if err := json.Unmarshal(body, &responseData); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to parse response"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status": "success",
		"data":   responseData,
	})
}