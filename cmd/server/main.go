package main

import (
	"flag"
	"log"

	"github.com/kamwawrzak/sslverifier/internal/server"
	"github.com/kamwawrzak/sslverifier/internal/service"
)

var defaultPort = 8080
var trustedRootCAsPath = "./trusted-certs.pem"

func main() {
	var port int
	flag.IntVar(&port, "port", defaultPort, "http server port" )
	flag.Parse()

	dialer := service.NewTcpDialer("tcp")
	verifier := service.NewCertificateVerifier(dialer, trustedRootCAsPath)

	handler := server.NewVerifyHandler(verifier)
	server := server.NewServer(port, handler)

	log.Printf("Starting http server on port: %d ...", port)
	err := server.Start()
	if err != nil {
		log.Println(err)
	}
}