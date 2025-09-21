package main

import (
    "github.com/gin-gonic/gin"
    "log"
    "os"

    "github.com/joho/godotenv"
    "payrails-server-demo/controllers"
)

func main() {
    // Load .env file locally, ignored in Railway
    if err := godotenv.Load(); err != nil {
        log.Println("No .env file found, relying on system env variables")
    }

    r := gin.Default()

    // Payrails SDK route
    r.POST("/payrails/sdk", controllers.InitSDK)

    // Debug route to verify environment variables
    r.GET("/env", func(c *gin.Context) {
        c.JSON(200, gin.H{
            "clientId": os.Getenv("PAYRAILS_CLIENT_ID"),
            "apiKey":   os.Getenv("PAYRAILS_API_KEY"),
            "baseUrl":  os.Getenv("PAYRAILS_BASE_URL"),
        })
    })

    port := os.Getenv("PORT")
    if port == "" {
        port = "5000"
    }

    r.Run(":" + port)
}
