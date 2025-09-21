package main

import (
    "log"
    "os"

    "github.com/gin-gonic/gin"
    "github.com/joho/godotenv"
    "payrails-server-demo/controllers"
)

func main() {
    if err := godotenv.Load(); err != nil {
        log.Println("No .env file found, relying on system env variables")
    }

    r := gin.Default()

    r.POST("/payrails/sdk", controllers.InitSDK)

    port := os.Getenv("PORT")
    if port == "" {
        port = "5000"
    }

    log.Printf("Starting server on port %s...", port)
    if err := r.Run(":" + port); err != nil {
        log.Fatalf("Failed to start server: %v", err)
    }
}
