package dnsservice

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
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

func isValidFQDN(fqdn string) bool {
	re := regexp.MustCompile(`^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\.$`)
	return re.MatchString(fqdn) && len(fqdn) <= 255
}

func isValidHostname(hostname string) bool {
	re := regexp.MustCompile(`^[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$`)
	if !re.MatchString(hostname) || len(hostname) > 100 {
		return false
	}
	return true
}

func validateARecord(value string) error {
	if net.ParseIP(value) == nil || net.ParseIP(value).To4() == nil {
		return fmt.Errorf("invalid IPv4 address: %s", value)
	}
	return nil
}

func validateAAAARecord(value string) error {
	if net.ParseIP(value) == nil || net.ParseIP(value).To16() == nil || net.ParseIP(value).To4() != nil {
		return fmt.Errorf("invalid IPv6 address: %s", value)
	}
	return nil
}

func validateMXRecord(value string) error {
	parts := strings.Split(value, ":")
	if len(parts) != 2 {
		return fmt.Errorf("invalid MX record format: %s", value)
	}
	_, err := strconv.Atoi(parts[0]) // Validate priority
	if err != nil {
		return fmt.Errorf("invalid MX record priority: %s", parts[0])
	}
	if !isValidFQDN(parts[1]) {
		return fmt.Errorf("invalid MX record mail server: %s", parts[1])
	}
	return nil
}

func validateNSRecord(value string) error {
	if !isValidFQDN(value) {
		return fmt.Errorf("invalid NS record: %s", value)
	}
	return nil
}

func validateCNAMERecord(value string) error {
	if !isValidFQDN(value) {
		return fmt.Errorf("invalid CNAME record: %s", value)
	}
	return nil
}

func validateTXTRecord(value string) error {
	// For TXT records, you might want to validate the length or the content format
	if len(value) == 0 || len(value) > 255 {
		return fmt.Errorf("invalid TXT record length: %d", len(value))
	}
	return nil
}

func validateSRVRecord(value string) error {
	parts := strings.Split(value, ":")
	if len(parts) != 4 {
		return fmt.Errorf("invalid SRV record format: %s", value)
	}

	if _, err := strconv.Atoi(parts[0]); err != nil { // Validate priority
		return fmt.Errorf("invalid SRV record priority: %s", parts[0])
	}

	if _, err := strconv.Atoi(parts[1]); err != nil { // Validate weight
		return fmt.Errorf("invalid SRV record weight: %s", parts[1])
	}

	if _, err := strconv.Atoi(parts[2]); err != nil { // Validate port
		return fmt.Errorf("invalid SRV record port: %s", parts[2])
	}

	if !isValidFQDN(parts[3]) { // Validate target
		return fmt.Errorf("invalid SRV record target: %s", parts[3])
	}

	return nil
}
