package main

import (
	"flag"

	"github.com/sirupsen/logrus"

	"github.com/kamwawrzak/sslverifier/internal/server"
	"github.com/kamwawrzak/sslverifier/internal/service"
)

var defaultPort = 8080
var trustedRootCAsPath = "./trusted-certs.pem"

func main() {
	var port int
	flag.IntVar(&port, "port", defaultPort, "http server port" )
	flag.Parse()

	log := logrus.New()

	dialer := service.NewTcpDialer("tcp")
	verifier := service.NewCertificateVerifier(dialer, trustedRootCAsPath)

	handler := server.NewVerifyHandler(log, verifier)
	server := server.NewServer(port, handler)

	log.WithField("port", port).Info("Starting http server")
	err := server.Start()
	if err != nil {
		log.WithError(err).Fatal("Starting server failed")
	}
}