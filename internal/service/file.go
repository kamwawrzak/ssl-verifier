package service

import (
	"crypto/x509"
	"encoding/json"
	"io/ioutil"

	"github.com/kamwawrzak/sslverifier/internal/model"
)

type URLs []string 

func GetUrls(path string) (URLs, error) {
	jsonData, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var urls URLs
	err = json.Unmarshal(jsonData, &urls)
	if err != nil {
		return nil, err
	}
	return urls, nil
}

func SaveResults(path string, results []*model.Result) error {
	jsonData, err := FormatJSON(results...)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(path, jsonData, 0644)
	if err != nil {
		return err
	}
	return nil
}

func GetRootCAsFromFile(path string) (*x509.CertPool, error) {
	caBundle, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	rootCAs := x509.NewCertPool()
	rootCAs.AppendCertsFromPEM(caBundle)

	return rootCAs, nil
}

func FormatJSON(results ...*model.Result) ([]byte, error){
	jsonData, err := json.MarshalIndent(results, "", "    ")
	if err != nil {
		return nil, err
	}
	return jsonData, nil
}
