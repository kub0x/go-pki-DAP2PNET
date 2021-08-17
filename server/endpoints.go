package server

import (
	"dap2pnet/handlers"
	"dap2pnet/middlewares"

	"github.com/gin-gonic/gin"
)

func InitPKIEndpoints(router *gin.RouterGroup) {
	router.POST("/register", middlewares.ValidatePKCS10(), handlers.OnPKCS10Signing())
}
