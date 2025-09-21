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
)

var cachedToken string
var tokenExpiry time.Time

func getBearerToken() (string, error) {
    clientId := os.Getenv("PAYRAILS_CLIENT_ID")
    apiKey := os.Getenv("PAYRAILS_API_KEY")
    baseUrl := os.Getenv("PAYRAILS_BASE_URL")

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
    _ = json.Unmarshal(body, &data)
    token, ok := data["access_token"].(string)
    if !ok {
        return "", fmt.Errorf("access_token missing in response")
    }

    cachedToken = token
    tokenExpiry = time.Now().Add(9 * time.Minute)
    return cachedToken, nil
}

func InitSDK(c *gin.Context) {
    token, err := getBearerToken()
    if err != nil {
        c.JSON(401, gin.H{"error": err.Error()})
        return
    }

    baseUrl := os.Getenv("PAYRAILS_BASE_URL")
    idempotencyKey := uuid.NewString()
    url := fmt.Sprintf("%s/merchant/client/init", baseUrl)

    payload := map[string]interface{}{
        "type":            "dropIn",
        "workflowCode":    "payment-acceptance",
        "merchantReference": uuid.NewString(),
        "holderReference":   uuid.NewString(),
        "amount": map[string]string{
            "value":    "999",
            "currency": "EUR",
        },
    }

    bodyBytes, _ := json.Marshal(payload)
    req, _ := http.NewRequest("POST", url, bytes.NewBuffer(bodyBytes))
    req.Header.Set("accept", "application/json")
    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("x-idempotency-key", idempotencyKey)
    req.Header.Set("Authorization", "Bearer "+token)

    resp, err := http.DefaultClient.Do(req)
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