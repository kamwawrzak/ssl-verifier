package service

import (
	"crypto/tls"
	"net"
	"time"
)

type tlsConn interface {
	Read(b []byte) (int, error)
	Write(b []byte) (int, error)
	Close() error
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
	SetDeadline(t time.Time) error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
	ConnectionState() tls.ConnectionState
}

type tcpDialer struct {
	protocol string
	cfg *tls.Config
}

func NewTcpDialer(protocol string) *tcpDialer {
	return &tcpDialer{
		protocol: protocol,
		cfg: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
}

func (t *tcpDialer) Dial(target string) (tlsConn, error){
	return tls.Dial(t.protocol, target, t.cfg)
}

func (t *tcpDialer) GetConnectionState(conn tlsConn) tls.ConnectionState {
	return conn.ConnectionState()
}
