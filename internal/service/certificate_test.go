package service

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kamwawrzak/sslverifier/testhelper"
)

const (
	trustedCertsPath = "../../test-files/test-trusted-certs.pem"
) 

func TestGetCertSHA1Fingerprint(t *testing.T) {
	// arrange
	notAfter := time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)
	certGen, err := testhelper.NewCertificateGenerator(trustedCertsPath, "www.example.com", notAfter)
	require.NoError(t, err)
	certs, err := certGen.GetCertChain(true)
	require.NoError(t, err)

	expectedFp := "4A:44:02:CA:57:EF:77:25:14:62:E7:BC:A2:48:8E:90:2D:0B:F4:32"

	// act
	actualFp, err := getCertSHA1Fingerprint(certs[0])

	// assert
	assert.NoError(t, err)
	assert.Equal(t, expectedFp, actualFp)
}

func TestGetDaysToExpire(t *testing.T) {
	// arrange
	testCases :=  map[string]struct {
		currentTime time.Time
		expected int
	} {
		"valid certificate": {time.Date(2024, time.May, 4, 0, 0, 0, 0, time.UTC), 31},
		"expired certificate": {time.Date(2025, time.May, 4, 0, 0, 0, 0, time.UTC), -334},
	}
	validToDate := time.Date(2024, time.June, 4, 0, 0, 0, 0, time.UTC)
	
	for _, tc := range testCases {
		// act
		actual := daysToExpire(validToDate, tc.currentTime)

		// assert
		assert.Equal(t, tc.expected, actual)
	}

}

func TestIsExpired(t *testing.T) {
	// arrange
	expected := false

	validToDate := time.Date(2024, time.June, 4, 0, 0, 0, 0, time.UTC)
	currentDate := time.Date(2024, time.May, 4, 0, 0, 0, 0, time.UTC)

	// act
	actual := isExpired(validToDate, currentDate)

	// assert
	assert.Equal(t, expected, actual)
}

func TestGetIntermediateCerts(t *testing.T) {
	// arrange
	notAfter := time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)
	certGen, err := testhelper.NewCertificateGenerator(trustedCertsPath, "www.example.com", notAfter)
	require.NoError(t, err)
	certs, err := certGen.GetCertChain(true)
	require.NoError(t, err)

	// act
	actual := getIntermediateCerts(certs)

	// assert
	assert.Equal(t, 2, len(actual.Subjects())) // nolint - certs don't come from SystemCertPool
}

func TestGetRootCAs(t *testing.T) {
	// arrange
	expectedLen := 1

	// act
	rootCAs, err := getTrustedRootCAs(trustedCertsPath)

	// assert
	assert.NoError(t, err)
	assert.Equal(t, expectedLen, len(rootCAs.Subjects())) // nolint - certs don't come from SystemCertPool
}

func TestVerifyCertsChainCorrectChain(t *testing.T) {
	// arrange
	notAfter := time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)
	certGen, err := testhelper.NewCertificateGenerator(trustedCertsPath, "www.example.com", notAfter)
	require.NoError(t, err)
	certs, err := certGen.GetCertChain(true)
	require.NoError(t, err)

	expected := true

	// act
	actual, err := verifyCertChain(certs, trustedCertsPath)

	// assert
	assert.NoError(t, err)
	assert.Equal(t, expected, actual)
}

func TestVerifyCertsChainInvalidChain(t *testing.T) {
	// arrange
	notAfter := time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)
	certGen, err := testhelper.NewCertificateGenerator(trustedCertsPath, "www.example.com", notAfter)
	require.NoError(t, err)
	certs, err := certGen.GetCertChain(false)
	require.NoError(t, err)

	expected := false

	// act
	actual, err := verifyCertChain(certs, trustedCertsPath)

	// assert
	assert.Error(t, err)
	assert.Equal(t, expected, actual)
}
