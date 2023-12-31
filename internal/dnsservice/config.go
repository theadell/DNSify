package dnsservice

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
)

type DNSConfig struct {
	ServerConfig `mapstructure:"server"`
	ClientConfig `mapstructure:"client"`
}

type ServerConfig struct {
	Addr       string
	Zone       string
	TsigKey    string
	TsigSecret string
}

type ClientConfig struct {
	SyncInterval        int
	HealthCheckInterval int
	Ipv4                string
	Ipv6                string
	Guards              RecordGuards
}

func validateConfig(config *DNSConfig) error {
	if err := validateAddress(config.Addr); err != nil {
		return err
	}
	if config.Zone == "" {
		return fmt.Errorf("zone must be specified")
	}
	if config.TsigKey == "" || config.TsigSecret == "" {
		return fmt.Errorf("TSIGKey and TSIGSecret must be specified")
	}
	if config.SyncInterval <= 0 {
		config.SyncInterval = 30
	}
	if config.HealthCheckInterval <= 0 {
		config.HealthCheckInterval = 60
	}
	if config.Ipv4 == "" {
		config.Ipv4 = "172.0.0.1"
	} else {
		if net.ParseIP(config.Ipv4) == nil {
			return fmt.Errorf("%s is not a valid IPv4 Address", config.Ipv4)
		}
	}
	if config.Ipv6 == "" {
		config.Ipv6 = "::1"
	} else {
		if net.ParseIP(config.Ipv6) == nil {
			return fmt.Errorf("%s is not a valid IPv6 Address", config.Ipv6)
		}
	}
	return nil
}

func validateAddress(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
		port = ""
	}

	if net.ParseIP(host) == nil && !isValidDomain(host) {
		return fmt.Errorf("invalid host: %s", host)
	}

	if port != "" {
		portInt, err := strconv.Atoi(port)
		if err != nil || portInt <= 0 || portInt > 65535 {
			return fmt.Errorf("invalid port: %s", port)
		}
	}

	return nil
}

func isValidDomain(domain string) bool {
	if strings.HasSuffix(domain, ".") {
		domain = domain[:len(domain)-1] // Remove trailing dot if exists
	}

	const domainPattern = `^(?:[a-zA-Z0-9-]{1,63}\.?)+[a-zA-Z0-9-]{1,63}$`
	matched, _ := regexp.MatchString(domainPattern, domain)
	return matched
}
