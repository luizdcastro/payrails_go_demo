package routes

import (
	"github.com/gin-gonic/gin"
	"payrails-server-demo/controllers"
)

func PayrailsRoutes(r *gin.Engine) {
	payrails := r.Group("/payrails")
	{
		payrails.POST("/sdk", controllers.InitSDK)
	}
}
