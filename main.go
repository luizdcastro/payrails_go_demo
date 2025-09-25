package main

import (
    "log"
    "os"
    "time"

    "github.com/gin-contrib/cors"
    "github.com/gin-gonic/gin"
    "github.com/joho/godotenv"
    "payrails-server-demo/controllers"
)

func main() {
    if err := godotenv.Load(); err != nil {
        log.Println("No .env file found, relying on system env variables")
    }

    r := gin.Default()

 r.Use(cors.New(cors.Config{
    AllowAllOrigins:  true,
    AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
    AllowHeaders:     []string{"Origin", "Content-Type", "Authorization", "x-client-key"},
    ExposeHeaders:    []string{"Content-Length"},
    AllowCredentials: true,
    MaxAge: 12 * time.Hour,
}))

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