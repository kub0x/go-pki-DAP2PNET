package server

import (
	"dap2pnet/handlers"
	"dap2pnet/middlewares"
	"dap2pnet/pki"

	"github.com/gin-gonic/gin"
)

func InitPKIEndpoints(router *gin.RouterGroup, pkcs7 *pki.PKCS7) {
	router.POST("/register", middlewares.ValidatePKCS10(), handlers.OnPKCS10Signing(pkcs7))
}
