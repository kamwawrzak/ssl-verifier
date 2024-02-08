package service

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kamwawrzak/sslverifier/testhelper"
)

const (
	correctCertPath = "../../test-certs/correct-example.cer"
	correctCertChainPath = "../../test-certs/correct-chain-example.cer"
	incompleteCertChainPath = "../../test-certs/incomplete-chain-example.cer"
	trustedCertsPath = "../../trusted-certs.pem"
) 

func TestGetCertSHA1Fingerprint(t *testing.T) {
	// arrange
	cert, err := testhelper.GetCertificate(correctCertPath)
	require.NoError(t, err)

	expectedFp := "4D:A2:5A:6D:5E:F6:2C:5F:95:C7:BD:0A:73:EA:3C:17:7B:36:99:9D"

	// act
	actualFp, err := getCertSHA1Fingerprint(cert)

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
	certs, err := testhelper.GetCertificatesChain(correctCertChainPath)
	require.NoError(t, err)

	// act
	actual := getIntermediateCerts(certs)

	// assert
	assert.Equal(t, 2, len(actual.Subjects()))
}

func TestGetRootCAs(t *testing.T) {
	// arrange
	expectedLen := 140

	// act
	rootCAs, err := getTrustedRootCAs(trustedCertsPath)

	// assert
	assert.NoError(t, err)
	assert.Equal(t, expectedLen, len(rootCAs.Subjects()))
}

func TestVerifyCertsChainCorrectChain(t *testing.T) {
	// arrange
	certs, err := testhelper.GetCertificatesChain(correctCertChainPath)
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
	certs, err := testhelper.GetCertificatesChain(incompleteCertChainPath)
	require.NoError(t, err)

	expected := false

	// act
	actual, err := verifyCertChain(certs, trustedCertsPath)

	// assert
	assert.Error(t, err)
	assert.Equal(t, expected, actual)
}