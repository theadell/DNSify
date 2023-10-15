package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"regexp"
	"runtime/debug"
	"strconv"
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
func validateRecordReq(hostname, ip, ttl, recordType string) error {
	if !isValidType(recordType) {
		return errors.New("Invalid record type")
	}
	if !isValidHostname(hostname) {
		return errors.New("Invalid hostname")
	}
	if recordType == "A" && !isValidIPv4(ip) || recordType == "AAAA" && !isValidIPv6(ip) {
		return errors.New("Invalid IP address")
	}
	if !isValidTTL(ttl) {
		return errors.New("Invalid ttl")
	}
	return nil
}
func httpError(w http.ResponseWriter, message string, code int) {
	slog.Error(message)
	http.Error(w, message, code)
}

func (app *App) render(w http.ResponseWriter, status int, page string, data any) {
	ts, ok := app.templateCache[page]
	if !ok {
		err := fmt.Errorf("the template %s does not exist", page)
		app.serverError(w, err)
		return
	}

	buf := new(bytes.Buffer)

	if err := ts.Execute(buf, data); err != nil {
		app.serverError(w, err)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)

	// Write the buffer content to the response writer
	buf.WriteTo(w)
}
func (app *App) serverError(w http.ResponseWriter, err error) {
	trace := fmt.Sprintf("%s\n%s", err.Error(), debug.Stack())

	slog.Error("server error encountered",
		"error", err.Error(),
		"trace", trace,
	)
	http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
}
