package service

import (
	"crypto/tls"
	"time"

	"github.com/kamwawrzak/sslverifier/internal/conn"
	"github.com/kamwawrzak/sslverifier/internal/model"
)

var expiredCertMessage = "The certificate is expired"

type dialer interface {
	Dial(target string) (conn.TlsConn, error)
	GetConnectionState(conn conn.TlsConn) tls.ConnectionState
}

type CertificateVerifier struct {
	trustedCertsPath string
	dialer dialer
}

func NewCertificateVerifier(dialer dialer, trustedCertsPath string)*CertificateVerifier{
	return &CertificateVerifier{
		trustedCertsPath: trustedCertsPath,
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
	isValid, validityError := verifyCertChain(certs, c.trustedCertsPath)
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
