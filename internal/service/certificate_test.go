package service

import (
	"testing"

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
