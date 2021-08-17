package handlers

import (
	"crypto/x509"
	"dap2pnet/pki"
	"log"

	"github.com/gin-gonic/gin"
)

func OnPKCS10Signing() gin.HandlerFunc {
	return func(c *gin.Context) {
		csrI, exists := c.Get("reqCSR")
		if !exists {
			log.Fatal("certificate request not in context")
		}
		csr := csrI.(x509.CertificateRequest)
		pki.SignPKCS10(csr)
	}
}
