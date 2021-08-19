package handlers

import (
	"dap2pnet/pki"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
)

var (
	KeyListMiddlewareErrReadDir = errors.New("error reading the directory")
)

func OnKeyList() gin.HandlerFunc {
	return func(c *gin.Context) {
		dir, err := os.ReadDir(pki.ClientsKeyPath)
		if err != nil {
			c.AbortWithError(http.StatusInternalServerError, errors.Wrap(KeyListMiddlewareErrReadDir, err.Error()))
			return
		}

		c.HTML(http.StatusOK, "KeyList.tmpl", gin.H{
			"dir": dir,
		})

		c.Status(http.StatusOK)
	}
}
