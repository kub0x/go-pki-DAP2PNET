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
	router.Use(gin.Recovery(), gin.LoggerWithFormatter(middlewares.Logger))
	group := router.Group("/pki")
	InitPKIEndpoints(group, pkcs7)

	return router.Run(":6667")
}
