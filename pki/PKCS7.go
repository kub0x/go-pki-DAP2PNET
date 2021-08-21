package pki

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
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
	organization   = "dap2pnet"
	country        = "ES"
	province       = "Bizkaia"
	locality       = "Bilbao"
	address        = "Deusto"
	code           = "48015"
	CACertPath     = "./certs/ca.pem"
	CAKeyPath      = "./certs/ca.key"
	TLSCertPath    = "./certs/pki.dap2p.net.pem"
	TLSKeyPath     = "./certs/pki.dap2p.net.key"
	ClientsKeyPath = "./certs/clients"
)

func NewCA() (*PKCS7, error) {
	pkcs7 := &PKCS7{}
	err := pkcs7.loadCA()
	if err != nil {
		err = pkcs7.createRootCA()
		if err != nil {
			return nil, err
		}

		err = pkcs7.generateInternalCertificate("rendezvous.dap2p.net")
		if err != nil {
			return nil, err
		}

		err = pkcs7.generateInternalCertificate("pki.dap2p.net")
		if err != nil {
			return nil, err
		}

	}

	return pkcs7, nil

}

func (pkcs7 *PKCS7) loadCA() error {
	caBytes, err := os.ReadFile(CACertPath)
	if err != nil {
		return err
	}
	block, _ := pem.Decode(caBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		log.Fatal("failted to decode ca certificate")
	}

	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}

	privBytes, err := os.ReadFile(CAKeyPath)
	if err != nil {
		return err
	}
	block, _ = pem.Decode(privBytes)
	if block == nil || block.Type != "EC PRIVATE KEY" {
		log.Fatal("failted to decode ca private key")
	}

	privKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return err
	}

	pkcs7.caCert = caCert
	pkcs7.privKey = privKey

	return nil

}

func (pkcs7 *PKCS7) certChainWithCA(certDER []byte) ([]byte, error) {

	caBytes, err := ioutil.ReadFile(CACertPath)
	if err != nil {
		return nil, err
	}

	certPEM := new(bytes.Buffer)
	err = pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})
	if err != nil {
		return nil, err
	}

	return append(certPEM.Bytes(), caBytes...), nil

}

func (pkcs7 *PKCS7) generateInternalCertificate(CN string) error {
	serial := make([]byte, 20)
	_, err := rand.Read(serial)
	if err != nil {
		return err
	}

	now := time.Now()
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(0).SetBytes(serial),
		Subject: pkix.Name{
			Organization:  []string{organization},
			Country:       []string{country},
			Province:      []string{province},
			Locality:      []string{locality},
			StreetAddress: []string{address},
			PostalCode:    []string{code},
			CommonName:    CN,
		},
		NotBefore:             now,
		NotAfter:              now.AddDate(10, 0, 0),
		IsCA:                  false,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: false,
	}

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader) //csrng
	if err != nil {
		return err
	}

	certDER, err := x509.CreateCertificate(rand.Reader, cert, pkcs7.caCert, &ecKey.PublicKey, pkcs7.privKey)
	if err != nil {
		return err
	}

	privBytes, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		return err
	}

	privPEM := new(bytes.Buffer)
	err = pem.Encode(privPEM, &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privBytes,
	})
	if err != nil {
		return err
	}

	err = ioutil.WriteFile("./certs/"+CN+".key", privPEM.Bytes(), 0400)
	if err != nil {
		return err
	}

	certChain, err := pkcs7.certChainWithCA(certDER)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile("./certs/"+CN+".pem", certChain, 0400)
	if err != nil {
		return err
	}

	return nil
}

func (pkcs7 *PKCS7) createRootCA() error {

	serial := make([]byte, 20)
	_, err := rand.Read(serial)
	if err != nil {
		return err
	}

	now := time.Now()
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(0).SetBytes(serial),
		Subject: pkix.Name{
			Organization:  []string{organization},
			Country:       []string{country},
			Province:      []string{province},
			Locality:      []string{locality},
			StreetAddress: []string{address},
			PostalCode:    []string{code},
			CommonName:    "CA",
		},
		NotBefore:             now,
		NotAfter:              now.AddDate(10, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	caPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader) //csrng
	if err != nil {
		return err
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return err
	}

	privBytes, err := x509.MarshalECPrivateKey(caPrivKey)
	if err != nil {
		return err
	}

	privPEM := new(bytes.Buffer)
	err = pem.Encode(privPEM, &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privBytes,
	})
	if err != nil {
		return err
	}

	caPEM := new(bytes.Buffer)
	err = pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(CACertPath, caPEM.Bytes(), 0400)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(CAKeyPath, privPEM.Bytes(), 0400)
	if err != nil {
		return err
	}

	pkcs7.caCert = ca
	pkcs7.privKey = caPrivKey

	println("Created CA certificate with CN " + ca.Subject.CommonName + " having serial " + ca.SerialNumber.String())

	return nil

}

func (pkcs7 *PKCS7) SignPKCS10(csr *x509.CertificateRequest) ([]byte, error) {
	serial := make([]byte, 20)
	_, err := rand.Read(serial)
	if err != nil {
		return nil, err
	}

	CN := make([]byte, 32)
	_, err = rand.Read(CN)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	CNID := hex.EncodeToString(CN)

	cert := &x509.Certificate{
		SerialNumber: big.NewInt(0).SetBytes(serial),
		Subject: pkix.Name{
			Organization:  csr.Subject.Organization,
			Country:       csr.Subject.Country,
			Province:      csr.Subject.Province,
			Locality:      csr.Subject.Locality,
			StreetAddress: csr.Subject.StreetAddress,
			PostalCode:    csr.Subject.PostalCode,
			Names:         csr.Subject.Names,
			CommonName:    CNID,
		},
		PublicKeyAlgorithm:    csr.PublicKeyAlgorithm,
		PublicKey:             csr.PublicKey,
		NotBefore:             now,
		NotAfter:              now.AddDate(0, 0, 1),
		IsCA:                  false,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: false,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, pkcs7.caCert, csr.PublicKey, pkcs7.privKey)
	if err != nil {
		return nil, err
	}

	certChain, err := pkcs7.certChainWithCA(certBytes)
	if err != nil {
		return nil, err
	}

	err = ioutil.WriteFile(ClientsKeyPath+"/"+cert.Subject.CommonName+".pem", certChain, 0400)
	if err != nil {
		return nil, err
	}

	println("Issued certificate to " + cert.Subject.CommonName + " having serial " + cert.SerialNumber.String())

	return certChain, nil
}
