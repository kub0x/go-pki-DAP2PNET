package handlers

import (
	"crypto/x509"
	"dap2pnet/pki"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
)

func OnPKCS10Signing(pkcs7 *pki.PKCS7) gin.HandlerFunc {
	return func(c *gin.Context) {
		csrI, exists := c.Get("reqCSR")
		if !exists {
			log.Fatal("certificate request not in context")
		}
		csr := csrI.(x509.CertificateRequest)
		certPem, err := pkcs7.SignPKCS10(csr)
		if err != nil {
			println(err.Error())
			c.Status(http.StatusForbidden)
			return
		}

		c.JSON(http.StatusOK, certPem)
	}
}
