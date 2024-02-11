package service

import (
	"crypto/tls"
	"time"

	"github.com/kamwawrzak/sslverifier/internal/model"
)

var expiredCertMessage = "The certificate is expired"
var trustedRootCAsPath = "./trusted-certs.pem"


type dialer interface {
	Dial(target string) (*tls.Conn, error)
}

type CertificateVerifier struct {
	dialer dialer
}

func NewCertificateVerifier(dialer dialer)*CertificateVerifier{
	return &CertificateVerifier{
		dialer: dialer,
	}
}

func (c *CertificateVerifier) Verify(url string) (*model.Result, error) {
	return c.verify(url)
}

func (c *CertificateVerifier) VerifyBatch(urls []string) ([]*model.Result, error) {
	results := make([]*model.Result, 0, len(urls))
	for _, url := range urls {
		res, err := c.verify(url)
		if err != nil {
			return nil, err
		}
		results = append(results, res)
	}
	return results, nil
}


func (c *CertificateVerifier) verify(url string) (*model.Result, error) {
	target, err := getTargetAddress(url)
	if err != nil {
		return nil, err
	}
	certs, err := getCertificates(target, c.dialer)
	if err != nil {
		return nil, err
	}

	// get leaf certificate
	cert := certs[0]

	isExpired := isExpired(cert.NotAfter, time.Now())
	isValid, validityError := verifyCertChain(certs, trustedRootCAsPath)
	daysToExpire := daysToExpire(cert.NotAfter, time.Now())

	fingerPrint, err := getCertSHA1Fingerprint(cert)
	if err != nil {
		return nil, err
	}

	result := model.NewResult(
		url,
		cert.Subject.CommonName, 
		cert.Issuer.CommonName,
		fingerPrint,
		cert.NotBefore,
		cert.NotAfter,
		daysToExpire,
		isValid,
		isExpired,
		cert.DNSNames,
		"",
	)

	if (isExpired) {
		result.Valid = false
		result.ErrorMessage = expiredCertMessage
	}

	if (!isValid) {
		result.ErrorMessage = validityError.Error()
	}

	return result, nil
}
