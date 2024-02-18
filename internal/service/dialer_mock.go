package service

import (
	"crypto/tls"
	"log"
	"net"

	"github.com/kamwawrzak/sslverifier/mocks"
	"github.com/kamwawrzak/sslverifier/testhelper"
)


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
