package server

import (
	"dap2pnet/middlewares"
	"dap2pnet/pki"

	"github.com/pkg/errors"

	"github.com/gin-gonic/gin"
)

type ServerConfig struct {
	PKCS7   *pki.PKCS7
	Version string
}

func Run() error {
	pkcs7, err := pki.NewCA()

	if err != nil {
		return errors.New("cannot initialize pki: " + err.Error())
	}

	servConfig := &ServerConfig{
		PKCS7:   pkcs7,
		Version: "v1.0",
	}

	return InitializeEndpoints(servConfig)

}

func InitializeEndpoints(servConfig *ServerConfig) error {
	gin.ForceConsoleColor()
	router := gin.New()
	router.LoadHTMLGlob("templates/*")
	router.Use(gin.Recovery(), gin.LoggerWithFormatter(middlewares.Logger))

	InitInfoEndpoints(router.Group("/"), servConfig.Version)

	pkiGroup := router.Group("/pki")
	InitPKIEndpoints(pkiGroup, servConfig.PKCS7)

	if gin.IsDebugging() {
		keyGroup := router.Group("/keys")
		InitKeyEndpoints(keyGroup)
	}

	return router.RunTLS(":6666", pki.CACertPath, pki.PrivCAKeyPath)

}
