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


func verifyCertChain(certs []*x509.Certificate, rootCertsPath string) (bool, error) {
	rootCAs, err := getTrustedRootCAs(rootCertsPath)
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
			// ignore error caused by expired certificate
			if strings.Contains(err.Error(), "has expired") {
				continue
			}
			return false, err
		}
	}
	return true, nil
}

func getTrustedRootCAs(rootCAsPath string) (*x509.CertPool, error) {
	rootCAs, err := GetRootCAsFromFile(rootCAsPath)
	if err != nil {
		return nil, err
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

func daysToExpire(validTo, currentTime time.Time) int {
	durationToExpire := validTo.Sub(currentTime)
	return int(durationToExpire.Hours() / 24)
}

func isExpired(validTo, currentTime time.Time) bool {
	return validTo.Before(currentTime)
}

func getIntermediateCerts(certs []*x509.Certificate) *x509.CertPool {
	interCerts := x509.NewCertPool()
	for _, cert := range certs[1:] {
		interCerts.AddCert(cert)
	
	}
	return interCerts
}