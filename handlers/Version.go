package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func GetVersion(version string) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Data(http.StatusOK, "text/html", []byte(version))
	}
}
