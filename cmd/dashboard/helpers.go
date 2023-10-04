package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
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
