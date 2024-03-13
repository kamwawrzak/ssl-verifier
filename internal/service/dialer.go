package service

import (
	"crypto/tls"

	"github.com/kamwawrzak/sslverifier/internal/conn"
)


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

func (t *tcpDialer) Dial(target string) (conn.TlsConn, error){
	return tls.Dial(t.protocol, target, t.cfg)
}

func (t *tcpDialer) GetConnectionState(conn conn.TlsConn) tls.ConnectionState {
	return conn.ConnectionState()
}
