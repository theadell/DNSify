package main

import (
	"strings"

	"github.com/theadell/dns-api/internal/dnsclient"
)

type NginxConfig struct {
	Hash                  string
	Domain                string
	SSLCert               string
	SSLKey                string
	IPv4                  string
	IPv6                  *string
	Addr                  string
	UseHttp2              bool
	AddWsHeaders          bool
	EnableRateLimit       bool
	EnableLogging         bool
	EnableHSTS            bool
	IncludeSubDomains     bool
	UseGooglePublicDNS    bool
	UseCloudflareResolver bool
}

func NewNginxConfig(aRecord dnsclient.Record, aaaaRecord *dnsclient.Record, addr string) NginxConfig {
	cleanFQDN := strings.TrimSuffix(aRecord.FQDN, ".")
	config := NginxConfig{
		Hash:    aRecord.Hash,
		Domain:  cleanFQDN,
		Addr:    addr,
		IPv4:    aRecord.IP,
		SSLCert: "/etc/letsencrypt/live/" + cleanFQDN + "/fullchain.pem",
		SSLKey:  "/etc/letsencrypt/live/" + cleanFQDN + "/privkey.pem",
	}

	if aaaaRecord != nil {
		config.IPv6 = &aaaaRecord.IP
	}
	return config
}
