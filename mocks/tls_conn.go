package mocks

import (
	"crypto/tls"
	"errors"
	"net"
	"time"
)


type MockTLSConn struct {
	closed     bool
	localAddr  net.Addr
	remoteAddr net.Addr
	connectionState tls.ConnectionState
}

func NewMockTLSConn(localAddr, remoteAddr net.Addr) *MockTLSConn {
	return &MockTLSConn{
		localAddr:  localAddr,
		remoteAddr: remoteAddr,
	}
}

func (c *MockTLSConn) Read(b []byte) (int, error) {
	return 0, nil
}

func (c *MockTLSConn) Write(b []byte) (int, error) {
	return 0, nil
}

func (c *MockTLSConn) Close() error {
	if c.closed {
		return errors.New("connection already closed")
	}
	c.closed = true
	return nil
}

func (c *MockTLSConn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *MockTLSConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *MockTLSConn) SetDeadline(t time.Time) error {
	return nil
}
func (c *MockTLSConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *MockTLSConn) SetWriteDeadline(t time.Time) error {
	return nil
}

func (c *MockTLSConn) ConnectionState() tls.ConnectionState {
	return c.connectionState
}
