package service

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/kamwawrzak/sslverifier/testhelper"
)

var correctCertPath = "../../test-certs/correct-example.cer"

func TestGetCertSHA1Fingerprint(t *testing.T) {
	// arrange
	cert, err := testhelper.GetCertificate(correctCertPath)
	assert.NoError(t, err)

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
		currentTime func() time.Time
		expected int
	} {
		"valid certificate": {func() time.Time {return time.Date(2024, time.May, 4, 0, 0, 0, 0, time.UTC)}, 31},
		"expired certificate": {func() time.Time {return time.Date(2025, time.May, 4, 0, 0, 0, 0, time.UTC)}, -334},
	}
	validToDate := time.Date(2024, time.June, 4, 0, 0, 0, 0, time.UTC)
	
	for _, tc := range testCases {
		// act
		actual := daysToExpire(validToDate, tc.currentTime)

		// assert
		assert.Equal(t, tc.expected, actual)
	}

}