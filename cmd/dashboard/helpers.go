package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

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

func isValidIPv4(ip string) bool {
	parsedIP := net.ParseIP(ip)
	return parsedIP != nil && parsedIP.To4() != nil
}

func isValidIPv6(ip string) bool {
	parsedIP := net.ParseIP(ip)
	return parsedIP != nil && parsedIP.To4() == nil && parsedIP.To16() != nil
}

func isValidTTL(ttl string) bool {
	ttlValue, err := strconv.Atoi(ttl)
	if err != nil {
		return false
	}
	return ttlValue >= 60
}
func isValidType(recordType string) bool {
	return recordType == "A" || recordType == "AAAA"
}
func GenerateSecureRandom(l uint8) (string, error) {
	verifierBytes := make([]byte, l)
	_, err := rand.Read(verifierBytes)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(verifierBytes), nil
}

func GenerateCodeChallenge(verifier string) string {
	hash := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

func stringToUint(s string) (uint, error) {
	// First, convert the string to uint64
	u64, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, err
	}

	// Convert uint64 to uint
	return uint(u64), nil
}

func getRealIP(r *http.Request) string {
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	if ips := r.Header.Get("X-Forwarded-For"); ips != "" {
		splitIps := strings.Split(ips, ",")
		return strings.TrimSpace(splitIps[0])
	}
	return strings.Split(r.RemoteAddr, ":")[0]
}
