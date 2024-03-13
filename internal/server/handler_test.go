package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kamwawrzak/sslverifier/internal/model"
	"github.com/kamwawrzak/sslverifier/internal/service"
	"github.com/kamwawrzak/sslverifier/testhelper"

)

var trustedCertsPath = "../../test-files/test-trusted-certs.pem"

func TestVerifyValidCertificate(t *testing.T){
	// arrange
	notAfter := time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)
	certGen, err := testhelper.NewCertificateGenerator(trustedCertsPath, "www.example.org", notAfter)
	require.NoError(t, err)
	certs, err := certGen.GetCertChain(true)
	require.NoError(t, err)

	dialer := service.NewDialerMock(certs)
	verifier := service.NewCertificateVerifier(dialer, trustedCertsPath)
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
