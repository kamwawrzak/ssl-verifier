package service

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kamwawrzak/sslverifier/internal/model"
	"github.com/kamwawrzak/sslverifier/testhelper"
)

var (
	testUrlsPath = "../../test-files/test-urls.json"
	testResultsPath = "../../test-files/test-result-file.json"
)

func TestGetUrls(t *testing.T) {
	// arrange
	expected := URLs {
		"example.com:443",
		"https://google.com",
	}

	// act
	actual, err := GetUrls(testUrlsPath)

	// assert
	assert.NoError(t, err)
	assert.Equal(t, expected, actual)
}

func TestSaveResults(t *testing.T) {
	// arrange
	expected := []*model.Result{
		&model.Result{
			InputURL: "https://example.com",
			Domain: "www.example.org",
			Issuer: "DigiCert TLS RSA SHA256 2020 CA1",
		},
	}

	// act 
	err := SaveResults(testResultsPath, expected)
	require.NoError(t, err)
	
	defer testhelper.CleanTestFile(testResultsPath)

	actual, err := testhelper.GetResultsFromFile(testResultsPath)

	// assert
	assert.NoError(t, err)
	assert.Equal(t, expected, actual)

}
