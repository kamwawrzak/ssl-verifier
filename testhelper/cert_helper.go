package testhelper

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"
)

var rsaKeyPath = "../../test-files/test-rsa-private-key.pem"


type CertificateGenerator struct {
	rootCertsPath string
	privRootKey *rsa.PrivateKey
	privKey *rsa.PrivateKey
	notBefore time.Time
	leafCertCN string
	leafNotAfter time.Time
}

func NewCertificateGenerator(rootCertsPath, leafCertCN string, leafNotAfter time.Time) (*CertificateGenerator, error) {
	privKey, err := GetRSAPrivateKeyFromFile(rsaKeyPath)
	if err != nil {
		return nil, err
	}

	return &CertificateGenerator{
		rootCertsPath: rootCertsPath,
		privRootKey: privKey,
		privKey: privKey,
		notBefore: time.Date(2024, 2, 1, 0, 0, 0, 0, time.UTC),
		leafCertCN: leafCertCN,
		leafNotAfter: leafNotAfter,
	}, nil
}

func (c *CertificateGenerator) GetCertChain(valid bool) ([]*x509.Certificate, error) {
	notAfter := time.Date(2100, 1, 30, 0, 0, 0, 0, time.UTC)
	rootTmpl, err := c.createRootCert()
	if err != nil {
		return  nil, err
	}

	interTmpl, err := c.createCert(2, "Intermediate Cert", notAfter, rootTmpl, c.privRootKey)
	if err != nil {
		return nil, err
	}

	
	leafTmpl, err := c.createCert(3, "Leaf Cert", c.leafNotAfter, interTmpl, c.privKey)
	if err != nil {
		return nil, err
	}

	// create certs chain
	if !valid {
		return []*x509.Certificate{leafTmpl, rootTmpl}, nil
	}

	return []*x509.Certificate{leafTmpl, interTmpl, rootTmpl}, nil
} 

// generated RootCert is common for all tests
func (c *CertificateGenerator) createRootCert() (*x509.Certificate, error) {
	notAfter := time.Date(2100, 1, 30, 0, 0, 0, 0, time.UTC)
	rootTmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Root CA"},
		},
		NotBefore:             c.notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &rootTmpl, &rootTmpl, &c.privRootKey.PublicKey, c.privRootKey)
	if err != nil {
		return nil, err
	}

	rootCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}

	// save cert to file
	err = saveCertToPEM(rootCert, c.rootCertsPath)
	if err != nil {
		return nil, err
	}

	return rootCert, nil
}

func (c *CertificateGenerator) createCert(serialNum int64, org_name string, expireAfter time.Time, parentCert *x509.Certificate, parentKey *rsa.PrivateKey) (*x509.Certificate, error) {
	certTmpl := x509.Certificate{
		SerialNumber: big.NewInt(serialNum),
		Subject: pkix.Name{
			CommonName: c.leafCertCN,
			Organization: []string{org_name},
		},
		NotBefore:             c.notBefore,
		NotAfter:              expireAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &certTmpl, parentCert, &c.privKey.PublicKey, c.privKey)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}


	return cert, nil
}
