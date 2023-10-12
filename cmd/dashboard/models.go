package main

import (
	"strings"

	"github.com/theadell/dns-api/internal/dnsclient"
)

type NginxConfig struct {
	Domain          string
	SSLCert         string
	SSLKey          string
	ServerIP        string
	ServerPort      string
	IPv6            *string
	UseHttp2        bool
	AddWsHeaders    bool
	EnableRateLimit bool
	EnableLogging   bool
}

func convertToTemplateConfig(aRecord dnsclient.Record, aaaaRecord *dnsclient.Record) NginxConfig {
	cleanFQDN := strings.TrimSuffix(aRecord.FQDN, ".")
	config := NginxConfig{
		Domain:          cleanFQDN,
		SSLCert:         "/etc/letsencrypt/live/" + cleanFQDN + "/fullchain.pem",
		SSLKey:          "/etc/letsencrypt/live/" + cleanFQDN + "/privkey.pem",
		ServerIP:        "localhost",
		ServerPort:      "8080",
		UseHttp2:        true,
		AddWsHeaders:    true,
		EnableRateLimit: true,
		EnableLogging:   true,
	}

	if aaaaRecord != nil {
		config.IPv6 = &aaaaRecord.IP
	}
	return config
}
