package dnsservice

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const (
	maxRetries    = 3
	retryInterval = 5 * time.Second
	cmdTimeout    = 10 * time.Second
	sleepDuration = 5 * time.Second
)

func hashRecord(record Record) string {
	data := record.Type + record.FQDN + record.IP + strconv.FormatUint(uint64(record.TTL), 10)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

func validateConfig(config *DNSClientConfig) error {
	if net.ParseIP(config.Host) == nil || net.ParseIP(config.Host).IsUnspecified() {
		return fmt.Errorf("invalid or unspecified IP address")
	}
	if config.Port == 0 {
		return fmt.Errorf("port must be specified")
	}
	if config.Zone == "" {
		return fmt.Errorf("zone must be specified")
	}
	if config.TSIGKey == "" || config.TSIGSecret == "" {
		return fmt.Errorf("TSIGKey and TSIGSecret must be specified")
	}
	if config.Port == 0 {
		config.Port = 53
	}
	if config.SyncInterval <= 0 {
		config.SyncInterval = 30
	}

	return nil
}

func (c *Client) isServerReachable() bool {
	m := new(dns.Msg)
	m.SetQuestion(c.zone, dns.TypeSOA)
	r, _, err := c.client.Exchange(m, c.serverAddr)
	return err == nil && len(r.Answer) > 0
}

func (c *Client) toFQDN(subdomain string) string {
	return fmt.Sprintf("%s.%s", subdomain, c.zone)
}

func (c *Client) extractSubdomain(fqdn string) string {
	subdomain := strings.TrimSuffix(fqdn, "."+c.zone)
	return strings.TrimSuffix(subdomain, ".")
}

func (c *Client) isImmutable(fqdn string) bool {
	subdomain := c.extractSubdomain(fqdn)
	for _, r := range c.guards.Immutable {
		if r == subdomain {
			return true
		}
	}
	return false
}

func (c *Client) isAdminEditable(fqdn string) bool {
	subdomain := c.extractSubdomain(fqdn)
	for _, r := range c.guards.AdminEditable {
		if r == subdomain {
			return true
		}
	}
	return false
}
