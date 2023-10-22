package main

import (
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
	"strings"

	"github.com/theadell/dnsify/internal/dnsservice"
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
func (app *App) serverError(w http.ResponseWriter, err error) {
	trace := fmt.Sprintf("%s\n%s", err.Error(), debug.Stack())

	slog.Error("server error encountered",
		"error", err.Error(),
		"trace", trace,
	)
	http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
}
func (app *App) clientError(w http.ResponseWriter, status int, messages ...string) {
	if len(messages) == 0 {
		http.Error(w, http.StatusText(status), status)
		return
	}
	combinedMessage := strings.Join(messages, "; ")
	http.Error(w, combinedMessage, status)
}

func (app *App) createNginxConfigFromForm(r *http.Request, record *dnsservice.Record) *NginxConfig {
	aaaaRecord := app.dnsClient.GetRecordForFQDN(record.FQDN, "AAAA")
	listenAddress := r.FormValue("listen_address")

	c := NewNginxConfig(*record, aaaaRecord, listenAddress)
	c.UseGooglePublicDNS = app.parseFormBool(r, "google_public_dns")
	c.UseCloudflareResolver = app.parseFormBool(r, "cloudflare_resolver")
	c.EnableHSTS = app.parseFormBool(r, "strict_transport")
	c.IncludeSubDomains = app.parseFormBool(r, "include_subdomains")
	c.EnableLogging = app.parseFormBool(r, "enable_logging")
	c.EnableRateLimit = app.parseFormBool(r, "enable_rate_limiting")
	c.UseHttp2 = app.parseFormBool(r, "use_http2")
	c.AddWsHeaders = app.parseFormBool(r, "ws_headers")

	return &c
}

func (app *App) parseFormBool(r *http.Request, key string) bool {
	return r.FormValue(key) == "on"
}
