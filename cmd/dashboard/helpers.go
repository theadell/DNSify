package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"runtime/debug"
	"strconv"
	"strings"

	"github.com/theadell/dnsify/internal/dnsservice"
)

func stringToUint(s string) (uint, error) {
	// First, convert the string to uint64
	u64, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, err
	}

	// Convert uint64 to uint
	return uint(u64), nil
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
	aaaaRecord := app.dnsClient.GetRecordForFQDN(record.Name, "AAAA")
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

func handleDNSError(err error, w http.ResponseWriter, app *App) {
	switch err {
	case dnsservice.ErrImmutableRecord:
		app.clientError(w, http.StatusBadRequest, "This record is read only")
	case dnsservice.ErrNotAuthorized:
		app.clientError(w, http.StatusUnauthorized, "You do not have the required permissions to perform this action.")
	default:
		app.serverError(w, err)
	}
}
