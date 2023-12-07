package dnsservice

import (
	"testing"
)

func TestNewRecordFromRaw(t *testing.T) {
	zone := "example.com."
	validTTL := "3600"

	testCases := []struct {
		name       string
		recordType string
		hostname   string
		value      string
		ttlStr     string
		wantErr    bool
	}{
		{"Valid A Record", "A", "www", "192.0.2.1", validTTL, false},
		{"Invalid A Record", "A", "www", "invalid-ip", validTTL, true},
		{"Valid AAAA Record", "AAAA", "www", "::1", validTTL, false},
		{"Invalid AAAA Record", "AAAA", "www", "invalid-ipv6", validTTL, true},
		{"Valid MX Record", "MX", "mail", "10:mail.example.com.", validTTL, false},
		{"Invalid MX Record - Bad Format", "MX", "mail", "invalid-format", validTTL, true},
		{"Valid NS Record", "NS", "ns1", "ns1.example.com.", validTTL, false},
		{"Invalid NS Record", "NS", "ns1", "invalid-ns", validTTL, true},
		{"Valid CNAME Record", "CNAME", "www", "example.com.", validTTL, false},
		{"Invalid CNAME Record", "CNAME", "www", "invalid-cname", validTTL, true},
		{"Valid TXT Record", "TXT", "txt", "valid text", validTTL, false},
		{"Invalid TXT Record", "TXT", "txt", "", validTTL, true},
		{"Valid SRV Record", "SRV", "_sip._tcp.www", "10:20:5060:sipserver.example.com.", validTTL, false},
		{"Invalid SRV Record - Bad Format", "SRV", "_sip._tcp.www", "invalid-srv", validTTL, true},
		{"Invalid SRV Record - Bad Weight", "SRV", "_sip._tcp.www", "10:bad:5060:sipserver.example.com.", validTTL, true},
		{"Invalid SRV Record - Bad Target", "SRV", "_sip._tcp.www", "10:20:5060:invalid-target", validTTL, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewRecordFromRaw(tc.recordType, tc.hostname, tc.value, tc.ttlStr, zone)
			if (err != nil) != tc.wantErr {
				t.Errorf("NewRecordFromRaw() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}
