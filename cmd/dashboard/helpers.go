package main

import (
	"net"
	"regexp"
	"strconv"
)

func isValidHostname(hostname string) bool {
	re := regexp.MustCompile(`^[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$`)
	if !re.MatchString(hostname) || len(hostname) > 100 {
		return false
	}
	return true
}

func isValidIP(ip string) bool {
	parsedIP := net.ParseIP(ip)
	return parsedIP != nil && parsedIP.To4() != nil
}

func isValidTTL(ttl string) bool {
	ttlValue, err := strconv.Atoi(ttl)
	if err != nil {
		return false
	}
	return ttlValue >= 60
}
