package handlers

import (
	"crypto/x509"
	"dap2pnet/pki"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
)

var (
	PKCS10HandlerErrCSRNotInContext = errors.New("csr not in context")
	PKCS10HandlerErrSigningCSR      = errors.New("failed signing the csr")
)

func OnPKCS10Signing(pkcs7 *pki.PKCS7) gin.HandlerFunc {
	return func(c *gin.Context) {
		csrI, exists := c.Get("certReq")
		if !exists {
			c.AbortWithError(http.StatusForbidden, PKCS10HandlerErrCSRNotInContext)
			return
		}

		csr := csrI.(*x509.CertificateRequest)
		certPem, err := pkcs7.SignPKCS10(csr)
		if err != nil {
			c.AbortWithError(http.StatusForbidden, errors.Wrap(PKCS10HandlerErrSigningCSR, err.Error()))
			return
		}

		c.JSON(http.StatusOK, certPem)
	}
}
