package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kamwawrzak/sslverifier/internal/service"
)

var certChainPath = "../../test-certs/correct-chain-example.cer"
var trustedRootCAsPath = "../../trusted-certs.pem"

func TestVerifyCertificate(t *testing.T){
	// arrange
	dialer := service.NewDialerMock(certChainPath)
	verifier := service.NewCertificateVerifier(dialer, trustedRootCAsPath)
	handler := NewVerifyHandler(verifier)

	reqInput := requestInput{Urls: []string{"example.com"}}
	jsonBody, err := json.Marshal(reqInput)
	if err != nil {
		require.NoError(t, err)
	}
	req, err := http.NewRequest("POST", "/verify", bytes.NewBuffer(jsonBody))
	if err != nil {
		require.NoError(t, err)
	}

	recorder := httptest.NewRecorder()
	handlerWrapper := http.HandlerFunc(handler.verifyCertificate)

	expectedBody := "{\"results\":[{\"input_url\":\"example.com\",\"domain\":\"www.example.org\",\"issuer\":\"DigiCert Global G2 TLS RSA SHA256 2020 CA1\",\"sha1\":\"4D:A2:5A:6D:5E:F6:2C:5F:95:C7:BD:0A:73:EA:3C:17:7B:36:99:9D\",\"valid_from\":\"2024-01-30T00:00:00Z\",\"valid_to\":\"2025-03-01T23:59:59Z\",\"days_to_expire\":377,\"valid\":true,\"expired\":false,\"DNS_names\":[\"www.example.org\",\"example.net\",\"example.edu\",\"example.com\",\"example.org\",\"www.example.com\",\"www.example.edu\",\"www.example.net\"]}]}\n"

	// act
	handlerWrapper.ServeHTTP(recorder, req)

	// assert
	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.Equal(t, expectedBody, recorder.Body.String())
	
}
