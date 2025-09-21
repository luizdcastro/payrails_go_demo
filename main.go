package main

import (
	"github.com/gin-gonic/gin"
	"payrails-server-demo/routes"
)

func main() {
	r := gin.Default()

	routes.PayrailsRoutes(r)

	r.Run(":5000")
}
