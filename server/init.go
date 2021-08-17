package server

import (
	"github.com/gin-gonic/gin"
)

func Initialize() {
	router := gin.New()
	group := router.Group("/pki")
	InitPKIEndpoints(group)

	router.Run(":6666")
}
