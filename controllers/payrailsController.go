package controllers

import (
    "bytes"
    "crypto/tls"
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
    CertPath string
    KeyPath  string
}

func LoadConfig() *Config {
    return &Config{
        ClientID: os.Getenv("PAYRAILS_CLIENT_ID"),
        APIKey:   os.Getenv("PAYRAILS_API_KEY"),
        BaseURL:  os.Getenv("PAYRAILS_BASE_URL"),
        CertPath: os.Getenv("MTLS_CLIENT_CERT"),
        KeyPath:  os.Getenv("MTLS_CLIENT_KEY"),
    }
}

var (
    cachedToken  string
    tokenExpiry  time.Time
    tokenMutex   sync.Mutex
)

func getBearerToken(cfg *Config) (string, error) {
    if cfg.ClientID == "" || cfg.APIKey == "" || cfg.BaseURL == "" {
        return "", fmt.Errorf("clientId, apiKey, or baseUrl missing")
    }

    tokenMutex.Lock()
    defer tokenMutex.Unlock()

    if cachedToken != "" && time.Now().Before(tokenExpiry) {
        return cachedToken, nil
    }

    url := fmt.Sprintf("%s/auth/token/%s", cfg.BaseURL, cfg.ClientID)
    req, _ := http.NewRequest("POST", url, nil)
    req.Header.Set("accept", "application/json")
    req.Header.Set("x-api-key", cfg.APIKey)

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
    _ = json.Unmarshal(body, &data)
    token, ok := data["access_token"].(string)
    if !ok {
        return "", fmt.Errorf("access_token missing in response")
    }

    cachedToken = token
    tokenExpiry = time.Now().Add(9 * time.Minute)
    return cachedToken, nil
}

func createMTLSClient(cfg *Config) (*http.Client, error) {
    if cfg.CertPath == "" || cfg.KeyPath == "" {
        return http.DefaultClient, nil 
    }
    cert, err := tls.LoadX509KeyPair(cfg.CertPath, cfg.KeyPath)
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
    cfg := LoadConfig()
    token, err := getBearerToken(cfg)
    if err != nil {
        c.JSON(401, gin.H{"error": err.Error()})
        return
    }

    idempotencyKey := uuid.NewString()
    url := fmt.Sprintf("%s/merchant/client/init", cfg.BaseURL)

    var payload map[string]interface{}
    if err := c.ShouldBindJSON(&payload); err != nil || len(payload) == 0 {
        // Default payload if none provided
        payload = map[string]interface{}{
            "type":             "dropIn",
            "workflowCode":     "payment-acceptance",
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
        fmt.Println("[InitSDK] Using default payload with random IDs")
    }

    jsonPayload, _ := json.Marshal(payload)
    client, err := createMTLSClient(cfg)
    if err != nil {
        c.JSON(500, gin.H{"error": err.Error()})
        return
    }

    req, _ := http.NewRequest("POST", url, bytes.NewBuffer(jsonPayload))
    req.Header.Set("accept", "application/json")
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