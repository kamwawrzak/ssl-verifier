package service

import (
	"crypto/tls"
	"log"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/kamwawrzak/sslverifier/internal/model"
	"github.com/kamwawrzak/sslverifier/mocks"
	"github.com/kamwawrzak/sslverifier/testhelper"
)

var certChainPath = "../../test-certs/correct-chain-example.cer"

type dialerMock struct {
	certChainPath string
	localAddr *net.TCPAddr
	remoteAddr *net.TCPAddr
}

func NewDialerMock(certChainPath string) *dialerMock {
	return &dialerMock{ 
		certChainPath: certChainPath,
		localAddr: &net.TCPAddr{IP: net.IPv4(0, 0, 0, 0), Port: 443},
		remoteAddr: &net.TCPAddr{IP: net.IPv4(0, 0, 0, 0), Port: 443},
	}
}	

func (d dialerMock) Dial(target string) (tlsConn, error){
	return mocks.NewMockTLSConn(d.localAddr, d.remoteAddr), nil
}

func (d dialerMock) GetConnectionState(conn tlsConn) tls.ConnectionState {
	certs, err := testhelper.GetCertificatesChain(d.certChainPath)
	if err != nil {
		log.Printf("Error during reading certs chain: %v", err)
		return tls.ConnectionState{}
	}
	return tls.ConnectionState{PeerCertificates: certs}
}

func TestVerifySuccess(t *testing.T) {
	// arrange
	dialer := NewDialerMock(certChainPath)
	verifier := NewCertificateVerifier(dialer)

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
	verifier := NewCertificateVerifier(dialer)
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
