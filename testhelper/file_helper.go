package testhelper

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/kamwawrzak/sslverifier/internal/model"
)

func GetResultsFromFile(path string) ([]*model.Result, error){
	file, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	
	var res []*model.Result
    err = json.Unmarshal(file, &res)
    if err != nil {
        return nil, fmt.Errorf("error during unmarshaling: %w", err)
    }

	return res, nil
}

func GetRSAPrivateKeyFromFile(path string) (*rsa.PrivateKey, error) {
    pemData, err := os.ReadFile(path)
    if err != nil {
        return nil, err
    }

    block, _ := pem.Decode(pemData)
    if block == nil {
        return nil, fmt.Errorf("failed to decode PEM block")
    }

    return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func CleanTestFile(path string) {
	os.Remove(path)
}
