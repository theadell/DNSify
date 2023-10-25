package dnsservice

import (
	"log/slog"
	"regexp"
	"strings"
)

const guardPattern = `^(?i)(\*|A|AAAA|SOA|NS|CNAME|DNAME|CAA|MX)/(([a-zA-Z0-9-]+\.)*[a-zA-Z0-9-]+|@)$`

var (
	guardRegex     = regexp.MustCompile(guardPattern)
	supportedTypes = [...]string{"SOA", "NS", "MX", "CNAME", "DNAME", "CAA", "A", "AAAA"}
)

type RecordGuards struct {
	Immutable     []string `mapstructure:"immutable"`
	AdminEditable []string `mapstructure:"admin_only"`
}

type RecordGuard struct {
	Type string
	FQDN string
}

type GuardMap struct {
	Immutable map[RecordGuard]bool
	AdminOnly map[RecordGuard]bool
}

func NewRecordGuard(t, fqdn string) RecordGuard {
	return RecordGuard{Type: t, FQDN: fqdn}
}

func parseGuards(guardList RecordGuards, zone string) GuardMap {
	var guardMap GuardMap

	guardMap.Immutable = make(map[RecordGuard]bool)
	guardMap.AdminOnly = make(map[RecordGuard]bool)

	for _, guardStr := range guardList.Immutable {
		guard, ok := parseGuardString(guardStr, zone)
		if !ok {
			slog.Debug("Guard is invalid", "guard", guardStr, "pattern", guardPattern)
			continue
		}
		guardMap.Immutable[guard] = true
	}

	for _, guardStr := range guardList.AdminEditable {
		guard, ok := parseGuardString(guardStr, zone)
		if !ok {
			slog.Debug("Guard is invalid", "guard", guardStr, "pattern", guardPattern)
			continue
		}
		guardMap.AdminOnly[guard] = true

	}
	return guardMap
}

func parseGuardString(guardStr, zone string) (RecordGuard, bool) {
	if !isValidGuard(guardStr) {
		return RecordGuard{}, false
	}

	parts := strings.SplitN(guardStr, "/", 2)

	if len(parts) != 2 {
		return RecordGuard{}, false
	}

	recordType := parts[0]
	fqdn := toFQDN(parts[1], zone)
	recordType = strings.ToUpper(recordType)

	return RecordGuard{Type: recordType, FQDN: fqdn}, true
}

func isValidGuard(guardStr string) bool {
	return guardRegex.MatchString(guardStr)
}

func splitGuard(guard string) (recordType, subdomain string) {
	parts := strings.SplitN(guard, "/", 2)
	if len(parts) != 2 {
		return "", ""
	}
	return parts[0], parts[1]
}
