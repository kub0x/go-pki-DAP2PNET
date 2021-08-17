package pki

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"time"
)

type PKCS7 struct {
	caCert  *x509.Certificate
	privKey *ecdsa.PrivateKey
}

var (
	organization  = "daP2Pnet"
	country       = "ES"
	province      = "Bizkaia"
	locality      = "Bilbao"
	address       = "Deusto"
	code          = "48015"
	keyLen        = 4096
	CACertPath    = "./certs/ca_cert.pem"
	privCAKeyPath = "./certs/ca_key.pem"
)

// func encodePEM(pemInfo []byte, pemType string) {
// 	buff := new(bytes.Buffer)
// 	pem.Encode(buff, &pem.Block{
// 		Type:  pemType,
// 		Bytes: x509.MarshalPKCS1PrivateKey(pemInfo),
// 	})
// }

func NewCA() (*PKCS7, error) {
	pkcs7 := &PKCS7{}
	var caPem, privPem string
	caCert, privKey, err := pkcs7.loadCA()
	if err != nil {
		println(err.Error())
		caCert, privKey, caPem, privPem, err = pkcs7.createRootCA()
		if err != nil {
			return nil, err
		}

		err = ioutil.WriteFile(CACertPath, []byte(caPem), 0400)
		if err != nil {
			return nil, err
		}

		err = ioutil.WriteFile(privCAKeyPath, []byte(privPem), 0400)
		if err != nil {
			return nil, err
		}

	}

	pkcs7.caCert = caCert
	pkcs7.privKey = privKey

	return pkcs7, nil

}

func (pkcs7 *PKCS7) loadCA() (*x509.Certificate, *ecdsa.PrivateKey, error) {
	caBytes, err := os.ReadFile(CACertPath)
	if err != nil {
		return nil, nil, err
	}
	block, _ := pem.Decode(caBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		log.Fatal("failted to decode ca certificate")
	}

	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, err
	}

	privBytes, err := os.ReadFile(privCAKeyPath)
	if err != nil {
		return nil, nil, err
	}
	block, _ = pem.Decode(privBytes)
	if block == nil || block.Type != "EC PRIVATE KEY" {
		log.Fatal("failted to decode ca private key")
	}

	privKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, err
	}

	return caCert, privKey, nil

}

func (pkcs7 *PKCS7) createRootCA() (*x509.Certificate, *ecdsa.PrivateKey, string, string, error) {
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
		return nil, nil, "", "", err
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, nil, "", "", err
	}

	privBytes, err := x509.MarshalECPrivateKey(caPrivKey)
	if err != nil {
		return nil, nil, "", "", err
	}

	privPEM := new(bytes.Buffer)
	err = pem.Encode(privPEM, &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privBytes,
	})
	if err != nil {
		return nil, nil, "", "", err
	}

	caPEM := new(bytes.Buffer)
	err = pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})
	if err != nil {
		return nil, nil, "", "", err
	}

	return ca, caPrivKey, string(caPEM.Bytes()), string(privPEM.Bytes()), nil

}

func (pkcs7 *PKCS7) SignPKCS10(csr *x509.CertificateRequest) (string, error) {

	now := time.Now()

	bigCNID, _ := rand.Int(rand.Reader, big.NewInt(1000*1000*10000))
	CNID := bigCNID.Text(16)
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization:  csr.Subject.Organization,
			Country:       csr.Subject.Country,
			Province:      csr.Subject.Province,
			Locality:      csr.Subject.Locality,
			StreetAddress: csr.Subject.StreetAddress,
			PostalCode:    csr.Subject.PostalCode,
			Names:         csr.Subject.Names,
			CommonName:    CNID,
			SerialNumber:  csr.Subject.SerialNumber,
		},
		PublicKeyAlgorithm:    csr.PublicKeyAlgorithm,
		PublicKey:             csr.PublicKey,
		NotBefore:             now,
		NotAfter:              now.AddDate(10, 0, 0),
		IsCA:                  false,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: false,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, pkcs7.caCert, csr.PublicKey, pkcs7.privKey)
	if err != nil {
		return "", err
	}

	certPem := new(bytes.Buffer)
	err = pem.Encode(certPem, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	if err != nil {
		return "", err
	}

	ioutil.WriteFile("./certs/clients/"+cert.Subject.CommonName+".pem", certPem.Bytes(), 0400)

	return string(certPem.Bytes()), nil
}
