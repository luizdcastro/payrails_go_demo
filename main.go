package main

import (
	"log"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"payrails-server-demo/controllers"
)

func main() {
	_ = godotenv.Load()

	r := gin.Default()

	r.POST("/payrails/sdk", controllers.InitSDK)

	port := os.Getenv("PORT")
	if port == "" {
		port = "5000"
	}

	log.Printf("Server running on port %s", port)
	r.Run(":" + port)
}