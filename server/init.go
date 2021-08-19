package server

import (
	"dap2pnet/middlewares"
	"dap2pnet/pki"
	"log"

	"github.com/gin-gonic/gin"
)

func Initialize() error {

	pkcs7, err := pki.NewCA()

	if err != nil {
		log.Fatal("cannot initialize pki: " + err.Error())
	}

	gin.ForceConsoleColor()
	router := gin.New()
	router.LoadHTMLGlob("templates/*")
	router.Use(gin.Recovery(), gin.LoggerWithFormatter(middlewares.Logger))

	pkiGroup := router.Group("/pki")
	InitPKIEndpoints(pkiGroup, pkcs7)

	if gin.IsDebugging() {
		keyGroup := router.Group("/keys")
		InitKeyEndpoints(keyGroup)
	}

	return router.RunTLS(":6666", pki.CACertPath, pki.PrivCAKeyPath)

}
