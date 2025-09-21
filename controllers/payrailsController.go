package controllers

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type Config struct {
	ClientID string
	APIKey   string
	BaseURL  string
	CertB64  string
	KeyB64   string
}

func LoadConfig() *Config {
	return &Config{
		ClientID: os.Getenv("PAYRAILS_CLIENT_ID"),
		APIKey:   os.Getenv("PAYRAILS_API_KEY"),
		BaseURL:  os.Getenv("PAYRAILS_BASE_URL"),
		CertB64:  os.Getenv("MTLS_CLIENT_CERT"),
		KeyB64:   os.Getenv("MTLS_CLIENT_KEY"),
	}
}

var (
	cachedToken string
	tokenExpiry time.Time
	tokenMutex  sync.Mutex
)

func getBearerToken(cfg *Config, client *http.Client) (string, error) {
	if cfg.ClientID == "" || cfg.APIKey == "" || cfg.BaseURL == "" {
		return "", fmt.Errorf("clientId, apiKey, or baseUrl missing")
	}

	tokenMutex.Lock()
	defer tokenMutex.Unlock()

	if cachedToken != "" && time.Now().Before(tokenExpiry) {
		return cachedToken, nil
	}

	url := fmt.Sprintf("%s/auth/token/%s", cfg.BaseURL, cfg.ClientID)

	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("x-api-key", cfg.APIKey)

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
		return "", fmt.Errorf("invalid JSON in token response: %v", err)
	}

	token, ok := data["access_token"].(string)
	if !ok || token == "" {
		return "", fmt.Errorf("access_token missing in response")
	}

	cachedToken = token
	tokenExpiry = time.Now().Add(9 * time.Minute)
	return cachedToken, nil
}

func createMTLSClientFromBase64(certB64, keyB64 string) (*http.Client, error) {
	if certB64 == "" || keyB64 == "" {
		return http.DefaultClient, nil
	}

	certPEM, err := base64.StdEncoding.DecodeString(certB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode certificate: %v", err)
	}

	keyPEM, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode key: %v", err)
	}

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to load X509 key pair: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}, nil
}

func InitSDK(c *gin.Context) {
	cfg := LoadConfig()

	client, err := createMTLSClientFromBase64(cfg.CertB64, cfg.KeyB64)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	token, err := getBearerToken(cfg, client)
	if err != nil {
		c.JSON(401, gin.H{"error": err.Error()})
		return
	}

	idempotencyKey := uuid.NewString()
	url := fmt.Sprintf("%s/merchant/client/init", cfg.BaseURL)

	var payload map[string]interface{}
if err := c.ShouldBindJSON(&payload); err != nil || len(payload) == 0 {
	payload = map[string]interface{}{
		"type":             "dropIn",
		"workflowCode":     "payment-acceptance",
		"merchantReference": uuid.NewString(),
		"holderReference":   uuid.NewString(),
		"amount": map[string]string{
			"value":    "100",
			"currency": "EUR",
		},
		"meta": map[string]interface{}{
			"source": "portal",
			"customer": map[string]string{
				"name":      "John",
				"lastName":  "Doe",
				"email":     "john.doe@payrails.com",
				"reference": uuid.NewString(),
			},
			"billingAddress": map[string]interface{}{
				"city":       "Berlin",
				"country":    map[string]string{"code": "DE"},
				"postalCode": "10405",
				"street":     "Straßburger Straße",
				"doorNumber": "1",
			},
			"order": map[string]interface{}{
				"deliveryAddress": map[string]interface{}{
					"city":       "Berlin",
					"country":    map[string]string{"code": "DE"},
					"postalCode": "10405",
					"street":     "Straßburger Straße",
					"doorNumber": "1",
				},
				"billingAddress": map[string]interface{}{
					"city":       "Berlin",
					"country":    map[string]string{"code": "DE"},
					"postalCode": "10405",
					"street":     "Straßburger Straße",
					"doorNumber": "1",
					"name":       "John",
					"lastName":   "Doe",
					"email":      "john.doe@payrails.com",
				},
				"lines": []map[string]interface{}{
					{
						"id": "2c3263d9-4223-4fcb-8c4e-2559884c33b6",
						"quantity": 1,
						"name": "fce35d2a-6a38-49d7-ab9d-a1c91f8e0c25",
						"unitPrice": map[string]string{
							"value":    "100",
							"currency": "EUR",
						},
					},
				},
			},
			"clientContext": map[string]interface{}{
				"ipAddress":        "217.110.239.132",
				"osType":           "web",
				"userAgent":        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
				"acceptHeader":     "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
				"language":         "en-US",
				"colorDepth":       24,
				"screenHeight":     723,
				"screenWidth":      1536,
				"timeZoneOffset":   0,
				"javaEnabled":      false,
				"javaScriptEnabled": false,
			},
			"subscription": map[string]string{
				"chargeFrequency": "P2D",
				"expiration":      "2040-09-01",
			},
		},
	}
}


	jsonPayload, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", url, bytes.NewBuffer(jsonPayload))
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-idempotency-key", idempotencyKey)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
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