package service

import "crypto/tls"

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

func (t *tcpDialer) Dial(target string) (*tls.Conn, error){
	return tls.Dial(t.protocol, target, t.cfg)
}
