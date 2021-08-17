package middlewares

import (
	"crypto/x509"
	"encoding/pem"
	"log"

	"github.com/gin-gonic/gin"
)

func ValidatePKCS10() gin.HandlerFunc {
	return func(c *gin.Context) {
		payload, err := c.GetRawData()
		if err != nil {

		}
		block, _ := pem.Decode(payload)
		if block == nil || block.Type != "CERTIFICATE REQUEST" {
			log.Fatal("failted to decode the certificate signing request")
		}

		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			log.Fatal(err)
		}

		c.Set("certReq", csr)

	}
}
