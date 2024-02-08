package service

import (
	"fmt"
	"regexp"
	"net/url"
)

var defaultPort = "443"

func getHostAndPort(rawURL string) (host string, port string, err error) {
	// imitate scheme to satisfy url parser
	if !hasScheme(rawURL) {
		rawURL = "//" + rawURL
	}
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return "", "", fmt.Errorf("failed to parse URL: %s", rawURL)
	}
	return parsedURL.Hostname(), parsedURL.Port(), nil
}

func hasScheme(url string) bool {
	pattern := regexp.MustCompile(`^\w+://`)
	return pattern.MatchString(url)
}

func getTargetAddress(url string) (string, error) {
	host, port, err := getHostAndPort(url)
	if err != nil {
		return "", err
	}

	if port == "" {
		return fmt.Sprintf("%s:%s", host, defaultPort), nil
	} else {
		return fmt.Sprintf("%s:%s", host, port), nil
	}
}
