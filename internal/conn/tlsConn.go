package conn

import (
	"crypto/tls"
	"net"
	"time"
)

type TlsConn interface {
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
