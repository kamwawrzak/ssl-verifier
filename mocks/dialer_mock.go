package mocks

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	
	"github.com/kamwawrzak/sslverifier/internal/conn"
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

func (d dialerMock) Dial(target string) (conn.TlsConn, error){
	return NewMockTLSConn(d.localAddr, d.remoteAddr), nil
}

func (d dialerMock) GetConnectionState(conn conn.TlsConn) tls.ConnectionState {
	return tls.ConnectionState{PeerCertificates: d.certsChain}
}
