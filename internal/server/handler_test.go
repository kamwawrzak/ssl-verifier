package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kamwawrzak/sslverifier/internal/model"
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

	expected := response{
		Results: []*model.Result{
			{
				InputURL: "example.com",
				Domain: "www.example.org",
				Valid: true,
			},
		},
	}

	// act
	handlerWrapper.ServeHTTP(recorder, req)

	var actual response
	err = json.NewDecoder(recorder.Body).Decode(&actual)
	require.NoError(t, err)

	// assert
	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.Equal(t, expected.Results[0].InputURL, actual.Results[0].InputURL)
	assert.Equal(t, expected.Results[0].Domain, actual.Results[0].Domain)
	assert.Equal(t, expected.Results[0].Valid, actual.Results[0].Valid)
}
