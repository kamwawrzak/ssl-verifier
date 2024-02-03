package model

import (
	"time"
)

type Result struct {
	InputURL string `json:"input_url"`
	Domain string `json:"domain"`
	Issuer string	`json:"issuer"`
	CertificateSHA1 string `json:"sha1"`
	ValidFrom time.Time	`json:"valid_from"`
	ValidTo time.Time	`json:"valid_to"`
	DaysToExpire int	`json:"days_to_expire"`
	Valid bool	`json:"valid"`
	Expired bool `json:"expired"`
	DnsNames []string `json:"DNS_names"`
	ErrorMessage string `json:"error_message,omitempty"`
}

func NewResult(url, domain, issuer string,
		certificateSHA1 string,
		validFrom, ValidTo time.Time,
		daysToExpire int,
		valid, expired bool,
		dnsNames []string,
		errorMsg string,
) *Result {
		return &Result{
			InputURL: url,
			Domain: domain,
			Issuer: issuer,
			CertificateSHA1: certificateSHA1,
			ValidFrom: validFrom,
			ValidTo: ValidTo,
			DaysToExpire: daysToExpire,
			Valid: valid,
			Expired: expired,
			DnsNames: dnsNames,
			ErrorMessage: errorMsg,
		}
	}