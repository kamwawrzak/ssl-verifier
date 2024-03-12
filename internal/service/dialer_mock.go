package service

import (
	"crypto/tls"
	"crypto/x509"
	"net"

	"github.com/kamwawrzak/sslverifier/mocks"
)


type dialerMock struct {
	certsChain []*x509.Certificate
	localAddr *net.TCPAddr
	remoteAddr *net.TCPAddr
}

func NewDialerMock(certs []*x509.Certificate) *dialerMock {
	return &dialerMock{
		certsChain: certs,
		localAddr: &net.TCPAddr{IP: net.IPv4(0, 0, 0, 0), Port: 443},
		remoteAddr: &net.TCPAddr{IP: net.IPv4(0, 0, 0, 0), Port: 443},
	}
}	

func (d dialerMock) Dial(target string) (tlsConn, error){
	return mocks.NewMockTLSConn(d.localAddr, d.remoteAddr), nil
}

func (d dialerMock) GetConnectionState(conn tlsConn) tls.ConnectionState {
	return tls.ConnectionState{PeerCertificates: d.certsChain}
}
