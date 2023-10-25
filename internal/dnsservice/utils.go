package dnsservice

import (
	"fmt"
	"strings"
)

func toFQDN(subdomain, zone string) string {
	if subdomain == "@" {
		return zone
	}
	return fmt.Sprintf("%s.%s", subdomain, zone)
}

func extractSubdomain(fqdn, zone string) string {
	subdomain := strings.TrimSuffix(fqdn, "."+zone)
	return strings.TrimSuffix(subdomain, ".")
}
