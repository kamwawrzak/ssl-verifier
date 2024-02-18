package main

import (
		"flag"
		"log"

		"github.com/kamwawrzak/sslverifier/internal/server"
		"github.com/kamwawrzak/sslverifier/internal/service"
)

var defaultPort = 8080
var trustedRootCAsPath = "./trusted-certs.pem"

func main(){
	var serverFlag bool
	var port int

	url := flag.String("url", "", "url address to test ssl")
	input := flag.String("input", "", "path to input json file")
	output := flag.String("output", "", "path for outoput json file")
	flag.BoolVar(&serverFlag, "server", false, "start http server")
	flag.IntVar(&port, "port", defaultPort, "http server port" )
	flag.Parse()

	dialer := service.NewTcpDialer("tcp")
	verifier := service.NewCertificateVerifier(dialer, trustedRootCAsPath)

	if serverFlag {
		handler := server.NewVerifyHandler(verifier)
		server := server.NewServer(port, handler)
		log.Printf("Starting http server on port: %d ...", port)
		err := server.Start()
		if err != nil {
			log.Println(err)
		}
		return
	}

	if (*url != "") {
		result, err := verifier.Verify(*url)
		if err != nil {
			log.Println(err)
		}

		jsonData, err := service.FormatJSON(result)
		if err != nil {
			log.Println("Error: ", err)
			return
		}

		log.Println(string(jsonData))
		return 
	}

	if (*input != ""){
		urls, err := service.GetUrls(*input)
		if err != nil {
			log.Println(err)
		}
		results, err := verifier.VerifyBatch(urls)
		if err != nil {
			log.Println(err)
		}
		err = service.SaveResults(*output, results)
		if err != nil {
			log.Println(err)
		}
		
		log.Printf("Results saved to file: %s", *output)
		return
	}
}