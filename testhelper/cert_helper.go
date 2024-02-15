package testhelper

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
)

func GetCertificate(filePath string) (*x509.Certificate, error) {
	cerData, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(cerData)
	if block == nil {
		return nil, errors.New("failed decoding certificate")
	}

	return x509.ParseCertificate(block.Bytes)
}

func GetCertificatesChain(filePath string) ([]*x509.Certificate, error) {
	certData, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	var certsChain []*x509.Certificate

	for {
		var block *pem.Block
		block, certData = pem.Decode(certData)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, err
			}
			certsChain = append(certsChain, cert)
		}
	}

	return certsChain, nil
}
