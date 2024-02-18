package service

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/kamwawrzak/sslverifier/internal/model"
)

var trustedCerts = "./trusted-certs.pem"
var certChainPath = "../../test-certs/correct-chain-example.cer"

func TestVerifySuccess(t *testing.T) {
	// arrange
	dialer := NewDialerMock(certChainPath)
	verifier := NewCertificateVerifier(dialer, trustedCerts)

	expected := model.Result{
		InputURL: "example.com",
		Domain: "www.example.org",

	}

	// act
	actual, err := verifier.Verify("example.com")

	//assert
	assert.NoError(t, err)
	assert.Equal(t, expected.InputURL, actual.InputURL)
	assert.Equal(t, expected.Domain, actual.Domain)
}

func TestVerifyBatchSuccess(t *testing.T) {
	// arrange
	dialer := NewDialerMock(certChainPath)
	verifier := NewCertificateVerifier(dialer, "trusted-certs-path")
	inputUrls := []string{"example.com", "http://example.com"}
	expected := []model.Result{
		{
			InputURL: "example.com",
			Domain: "www.example.org",
		},
		{
			InputURL: "http://example.com",
			Domain: "www.example.org",
		},
		
	}
	// act
	actual, err := verifier.VerifyBatch(inputUrls)

	//assert
	assert.NoError(t, err)
	assert.Equal(t, len(expected), len(actual))
	assert.Equal(t, expected[1].InputURL, actual[1].InputURL)
	assert.Equal(t, expected[1].Domain, actual[1].Domain)
}
