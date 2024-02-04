package service

import (
	"time"

	"github.com/kamwawrzak/sslverifier/internal/model"
)

var expiredCertMessage = "The certificate is expired"

type certificateVerifier struct {}

func NewCertificateVerifier()*certificateVerifier{
	return &certificateVerifier{}
}

func (certificateVerifier) VerifySingle(url string) (*model.Result, error) {
	return verify(url)
}

func (certificateVerifier) VerifyBatch(urls []string) ([]*model.Result, error) {
	results := make([]*model.Result, 0, len(urls))
	for _, url := range urls {
		res, err := verify(url)
		if err != nil {
			return nil, err
		}
		results = append(results, res)
	}
	return results, nil
}


func verify(url string) (*model.Result, error) {
	target, err := getTargetAddress(url)
	if err != nil {
		return nil, err
	}
	certs, err := getCertificates(target)
	if err != nil {
		return nil, err
	}

	// get leaf certificate
	cert := certs[0]

	isExpired := isExpired(cert.NotAfter)
	isValid, validityError := verifyCertChain(certs)
	daysToExpire := daysToExpire(cert.NotAfter, time.Now)

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
