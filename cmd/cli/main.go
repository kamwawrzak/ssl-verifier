package main

import (
	"flag"
	"fmt"

	"github.com/sirupsen/logrus"

	"github.com/kamwawrzak/sslverifier/internal/service"
)

var trustedRootCAsPath = "./trusted-certs.pem"

func main(){
	url := flag.String("url", "", "url address to test ssl")
	input := flag.String("input", "", "path to input json file")
	output := flag.String("output", "", "path for outoput json file")
	flag.Parse()

	log := logrus.New()

	dialer := service.NewTcpDialer("tcp")
	verifier := service.NewCertificateVerifier(dialer, trustedRootCAsPath)


	if (*url != "") {
		result, err := verifier.Verify(*url)
		if err != nil {
			log.WithError(err).Error("Certificate verification failed")
		}

		jsonData, err := service.FormatJSON(result)
		if err != nil {
			log.WithError(err).Error("Parsing result to JSON failed")
			return
		}

		fmt.Println("============= Result =============")
		fmt.Println(string(jsonData))
		return 
	}

	if (*input != ""){
		urls, err := service.GetUrls(*input)
		if err != nil {
			log.WithError(err).Error("Reading URLs from file failed")
			return
		}
		results, err := verifier.VerifyBatch(urls)
		if err != nil {
			log.WithError(err).Error("Certificates verification failed")
			return
		}
		err = service.SaveResults(*output, results)
		if err != nil {
			log.WithError(err).Error("Saving results to file failed")
			return
		}
		
		log.WithField("filename", *output).Info("Results saved to file")
		return
	}
}
