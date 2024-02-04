package service

import (
	"bytes"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"strings"
	"time"
)

var trustedRootCAsPath = "./trusted-certs.pem"

func getCertificates(target string) ([]*x509.Certificate, error) {
	connCfg := &tls.Config{
		InsecureSkipVerify: true,
	}
	
	conn, err := tls.Dial("tcp", target, connCfg)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	return conn.ConnectionState().PeerCertificates, nil
}


func verifyCertChain(certs []*x509.Certificate) (bool, error) {
	rootCAs, err := getTrustedRootCAs()
	if err != nil {
		return false, err
	}

	opts := x509.VerifyOptions{
		Roots: rootCAs,
		Intermediates: getIntermediateCerts(certs),
	}

	for _, cert := range certs {
		_, err = cert.Verify(opts)
		if err != nil {
			// ignore error casued by expired certificate
			if strings.Contains(err.Error(), "has expired") {
				continue
			}
			return false, err
		}
	}
	return true, nil
}

func getTrustedRootCAs() (*x509.CertPool, error) {
	rootCAs, err := x509.SystemCertPool()
	if err != nil {
		return nil, err
	}

	// if there are no RootCAs in SystemCertPool read it from file
	if len(rootCAs.Subjects()) < 1 {
		rootCAs, err = GetRootCAsFromFile(trustedRootCAsPath)
		if err != nil {
			return nil, err
		}
	}
	return rootCAs, nil
}

func getCertSHA1Fingerprint(cert *x509.Certificate) (string, error) {
	fp := sha1.Sum(cert.Raw)
	var buf bytes.Buffer
    for i, f := range fp {
        if i > 0 {
            fmt.Fprintf(&buf, ":")
        }
        fmt.Fprintf(&buf, "%02X", f)
    }

	return buf.String(), nil
}

func daysToExpire(validTo time.Time) int {
	durationToExpire := validTo.Sub(time.Now())
	return int(durationToExpire.Hours() / 24)
}

func isExpired(validTo time.Time) bool {
	return validTo.Before(time.Now())
}

func getIntermediateCerts(certs []*x509.Certificate) *x509.CertPool {
	interCerts := x509.NewCertPool()
	for _, cert := range certs[1:] {
		interCerts.AddCert(cert)
	
	}
	return interCerts
}