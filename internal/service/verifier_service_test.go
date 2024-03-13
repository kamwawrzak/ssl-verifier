package service

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kamwawrzak/sslverifier/internal/model"
	"github.com/kamwawrzak/sslverifier/mocks"
	"github.com/kamwawrzak/sslverifier/testhelper"
)

var trustedCerts = "../../test-trusted-certs.pem"

func TestVerifySuccess(t *testing.T) {
	// arrange
	notAfter := time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)
	certGen, err := testhelper.NewCertificateGenerator(trustedCertsPath, "www.example.org", notAfter)
	require.NoError(t, err)
	certs, err := certGen.GetCertChain(true)
	require.NoError(t, err)

	dialer := mocks.NewDialerMock(certs)
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
	assert.Equal(t, expected.Domain, actual.Domain)
}

func TestVerifyExpired(t *testing.T) {
	// arrange
	notAfter := time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)
	certGen, err := testhelper.NewCertificateGenerator(trustedCertsPath, "www.example.org", notAfter)
	require.NoError(t, err)
	certs, err := certGen.GetCertChain(true)
	require.NoError(t, err)

	dialer := mocks.NewDialerMock(certs)
	verifier := NewCertificateVerifier(dialer, trustedCerts)

	expected := model.Result{
		InputURL: "example.com",
		Domain:   "www.example.org",
		Expired: true,
		Valid: false,
	}

	// act
	actual, err := verifier.Verify("example.com")

	//assert
	assert.NoError(t, err)
	assert.Equal(t, expected.InputURL, actual.InputURL)
	assert.Equal(t, expected.Domain, actual.Domain)
	assert.Equal(t, expected.Expired, actual.Expired)
	assert.Equal(t, expected.Valid, actual.Valid)
}

func TestVerifyBatchSuccess(t *testing.T) {
	// arrange
	notAfter := time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)
	certGen, err := testhelper.NewCertificateGenerator(trustedCertsPath, "www.example.org", notAfter)
	require.NoError(t, err)
	certs, err := certGen.GetCertChain(true)
	require.NoError(t, err)

	dialer := mocks.NewDialerMock(certs)
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
	assert.Equal(t, expected[0].Domain, actual[0].Domain)
}
