package service

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kamwawrzak/sslverifier/internal/model"
	"github.com/kamwawrzak/sslverifier/testhelper"
)

var trustedCerts = "../../test-trusted-certs.pem"

func TestVerifySuccess(t *testing.T) {
	// arrange
	certGen, err := testhelper.NewCertificateGenerator()
	require.NoError(t, err)
	certs, err := certGen.GetValidCertChain()
	require.NoError(t, err)

	dialer := NewDialerMock(certs)
	verifier := NewCertificateVerifier(dialer, trustedCerts)

	expected := model.Result{
		InputURL: "example.com",
		Domain:   "www.example.org",
	}

	// act
	actual, err := verifier.Verify("example.com")

	//assert
	assert.NoError(t, err)
	assert.Equal(t, expected.InputURL, actual.InputURL)
	//assert.Equal(t, expected.Domain, actual.Domain)
}

func TestVerifyBatchSuccess(t *testing.T) {
	// arrange
	certGen, err := testhelper.NewCertificateGenerator()
	require.NoError(t, err)
	certs, err := certGen.GetValidCertChain()
	require.NoError(t, err)

	dialer := NewDialerMock(certs)
	verifier := NewCertificateVerifier(dialer, trustedCerts)
	inputUrls := []string{"example.com", "http://example.com"}
	expected := []model.Result{
		{
			InputURL: "example.com",
			Domain:   "www.example.org",
		},
		{
			InputURL: "http://example.com",
			Domain:   "www.example.org",
		},
	}
	// act
	actual, err := verifier.VerifyBatch(inputUrls)

	//assert
	assert.NoError(t, err)
	assert.Equal(t, len(expected), len(actual))
	assert.Equal(t, expected[1].InputURL, actual[1].InputURL)
	//assert.Equal(t, expected[0].Domain, actual[0].Domain)
}
