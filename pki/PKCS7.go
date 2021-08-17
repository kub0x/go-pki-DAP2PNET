package pki

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"time"
)

var (
	organization = "daP2Pnet"
	country      = "ES"
	province     = "Bizkaia"
	locality     = "Bilbao"
	address      = "Deusto"
	code         = "48015"
	keyLen       = 4096
)

// func encodePEM(pemInfo []byte, pemType string) {
// 	buff := new(bytes.Buffer)
// 	pem.Encode(buff, &pem.Block{
// 		Type:  pemType,
// 		Bytes: x509.MarshalPKCS1PrivateKey(pemInfo),
// 	})
// }

func CreateRootCA() (string, string, error) {
	now := time.Now()

	ca := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization:  []string{organization},
			Country:       []string{country},
			Province:      []string{province},
			Locality:      []string{locality},
			StreetAddress: []string{address},
			PostalCode:    []string{code},
		},
		NotBefore:             now,
		NotAfter:              now.AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	caPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader) //csrng
	if err != nil {
		return "", "", err
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return "", "", err
	}

	privBytes, err := x509.MarshalECPrivateKey(caPrivKey)
	if err != nil {
		return "", "", err
	}

	privPEM := new(bytes.Buffer)
	err = pem.Encode(privPEM, &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privBytes,
	})
	if err != nil {
		return "", "", err
	}

	caPEM := new(bytes.Buffer)
	err = pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})
	if err != nil {
		return "", "", err
	}

	return string(caPEM.Bytes()), string(privPEM.Bytes()), nil

}
