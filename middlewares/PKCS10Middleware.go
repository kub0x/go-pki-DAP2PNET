package middlewares

import (
	"crypto/x509"
	"encoding/pem"
	"net/http"

	"github.com/pkg/errors"

	"github.com/gin-gonic/gin"
)

var (
	PKCS10MiddlewareErrDecodingCSRPEM = errors.New("failed to decode the .pem of the csr")
	PKCS10MiddlewareErrParsingCSR     = errors.New("failed to parse the csr")
	PKCS10MiddlewareErrInternal       = errors.New("internal error in pkcs10 middleware")
)

func ValidatePKCS10() gin.HandlerFunc {
	return func(c *gin.Context) {
		payload, err := c.GetRawData()
		if err != nil {
			c.AbortWithError(http.StatusInternalServerError, errors.Wrap(PKCS10MiddlewareErrInternal, err.Error()))
			return
		}

		block, _ := pem.Decode(payload)
		if block == nil || block.Type != "CERTIFICATE REQUEST" {
			c.AbortWithError(http.StatusBadRequest, PKCS10MiddlewareErrDecodingCSRPEM)
			return
		}

		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			c.AbortWithError(http.StatusBadRequest, errors.Wrap(PKCS10MiddlewareErrParsingCSR, err.Error()))
			return
		}

		c.Set("certReq", csr)

	}
}
