package main

import (
	"strings"

	"github.com/theadell/dnsify/internal/dnsservice"
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

func NewNginxConfig(aRecord dnsservice.Record, aaaaRecord *dnsservice.Record, addr string) NginxConfig {
	cleanFQDN := strings.TrimSuffix(aRecord.Name, ".")
	config := NginxConfig{
		Hash:    aRecord.Hash,
		Domain:  cleanFQDN,
		Addr:    addr,
		IPv4:    aRecord.Data.Value(),
		SSLCert: "/etc/letsencrypt/live/" + cleanFQDN + "/fullchain.pem",
		SSLKey:  "/etc/letsencrypt/live/" + cleanFQDN + "/privkey.pem",
	}

	if aaaaRecord != nil {
		ipv6 := aaaaRecord.Data.Value()
		config.IPv6 = &ipv6
	}
	return config
}

type HTMXDeleteDuplicateRowEvent struct {
	DeleteDuplicateRow struct {
		Hash string `json:"hash"`
	} `json:"deleteDuplicateRow"`
}
