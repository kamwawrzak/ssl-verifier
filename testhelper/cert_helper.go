package testhelper

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
)

func GetCertificate(filePath string) (*x509.Certificate, error) {
	cerData, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(cerData)
	if block == nil {
		return nil, errors.New("failed decoding certificate")
	}

	return x509.ParseCertificate(block.Bytes)
}
