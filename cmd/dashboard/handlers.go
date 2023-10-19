package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/theadell/dnsify/internal/dnsclient"
)

var excludedFQDNs = map[string]struct{}{
	"rusty-leipzig.com.":     {},
	"ns1.rusty-leipzig.com.": {},
	"ns2.rusty-leipzig.com.": {},
	"www.rusty-leipzig.com.": {},
	"dns.rusty-leipzig.com.": {},
}

func (app *App) IndexHandler(w http.ResponseWriter, r *http.Request) {
	app.render(w, http.StatusOK, "index", nil)
}
func (app *App) DashboardHandler(w http.ResponseWriter, r *http.Request) {
	allRecords := app.bindClient.GetRecords()

	var filteredRecords []dnsclient.Record
	for _, record := range allRecords {
		if _, excluded := excludedFQDNs[record.FQDN]; !excluded {
			filteredRecords = append(filteredRecords, record)
		}
	}
	app.render(w, http.StatusOK, "dashboard", filteredRecords)
}

func (app *App) configHandler(w http.ResponseWriter, r *http.Request) {
	hash := r.FormValue("hash")
	if hash == "" {
		app.clientError(w, http.StatusBadRequest, "Invalid or empty record id/hash was submitted")
		return
	}
	record := app.bindClient.GetRecordByHash(hash)
	if record == nil {
		app.clientError(w, http.StatusBadRequest, "No matching record found")
		return
	}
	aaaaRecord := app.bindClient.GetRecordForFQDN(record.FQDN, "AAAA")
	c := NewNginxConfig(*record, aaaaRecord, "http://localhost:8080")
	app.render(w, http.StatusOK, "nginx-config", c)
}
func (app *App) configAdjusterHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		app.clientError(w, http.StatusBadRequest)
		return
	}

	hash := r.FormValue("hash")
	if hash == "" {
		app.clientError(w, http.StatusBadRequest, "Invalid or empty record id/hash was submitted")
		return
	}

	record := app.bindClient.GetRecordByHash(hash)
	if record == nil {
		app.clientError(w, http.StatusBadRequest, "No matching record found")
		return
	}
	c := app.createNginxConfigFromForm(r, record)
	app.render(w, http.StatusOK, "nginx", c)
}

func (app *App) AddRecordHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		app.clientError(w, http.StatusBadRequest)
		return
	}

	hostname, ip, ttl, recordType := r.FormValue("hostname"), r.FormValue("ip"), r.FormValue("ttl"), r.FormValue("type")

	if ip == "@" {
		ip = "157.230.106.145"
	}

	if err := validateRecordReq(hostname, ip, ttl, recordType); err != nil {
		slog.Error("Invalid record request", "error", err)
		app.clientError(w, http.StatusBadRequest, err.Error())
		return
	}

	ttlNum, err := stringToUint(ttl)
	if err != nil {
		app.clientError(w, http.StatusBadRequest, "Invalid TTL", err.Error())
		return
	}

	record := dnsclient.NewRecord(recordType, fmt.Sprintf("%s.%s.", hostname, "rusty-leipzig.com"), ip, ttlNum)

	if _, excluded := excludedFQDNs[record.FQDN]; excluded {
		app.clientError(w, http.StatusForbidden, "Addition of this record is not allowed")
		return
	}

	if app.bindClient.GetRecordByHash(record.Hash) != nil {
		app.clientError(w, http.StatusBadRequest, "Duplication Error", "Record Already Exists")
		return
	}

	// update existing record
	if dr := app.bindClient.GetRecordByFQDNAndType(record.FQDN, record.Type); dr != nil {
		if app.bindClient.RemoveRecord(*dr) != nil {
			app.serverError(w, err)
			return
		}

		slog.Info("Successfully deleted DNS record.", "record", record)
		err = app.bindClient.AddRecord(record)
		if err != nil {
			app.serverError(w, err)
			return
		}

		slog.Info("Successfully added a new DNS record.", "record", record)
		payload := HTMXDeleteDuplicateRowEvent{}
		payload.DeleteDuplicateRow.Hash = dr.Hash
		jsonHeader, err := json.Marshal(payload)
		if err != nil {
			app.serverError(w, err)
			return
		}
		// instruct htmx to remove the old record
		w.Header().Set("HX-Trigger", string(jsonHeader))
		app.renderTemplateFragment(w, http.StatusOK, "dashboard", "records", record)
		return
	}

	err = app.bindClient.AddRecord(record)
	if err != nil {
		app.serverError(w, err)
	}

	slog.Info("Successfully added a new DNS record.", "record", record)
	app.renderTemplateFragment(w, http.StatusOK, "dashboard", "records", &record)
}

func (app *App) notFoundHandler(w http.ResponseWriter, r *http.Request) {
	app.render(w, http.StatusNotFound, "error", nil)
}

func (app *App) DeleteRecordHandler(w http.ResponseWriter, r *http.Request) {

	recordType := strings.TrimSpace(r.URL.Query().Get("Type"))
	fqdn := strings.TrimSpace(r.URL.Query().Get("FQDN"))
	ip := strings.TrimSpace(r.URL.Query().Get("IP"))
	ttl := strings.TrimSpace(r.URL.Query().Get("TTL"))

	if !isValidType(recordType) {
		app.clientError(w, http.StatusBadRequest, "Invalid DNS Record Type")
		return
	}

	if !isValidFQDN(fqdn) || (recordType == "A" && !isValidIPv4(ip) || recordType == "AAAA" && !isValidIPv6(ip)) || !isValidTTL(ttl) {
		app.clientError(w, http.StatusBadRequest, "Invalid record")
		return
	}

	record := dnsclient.Record{
		Type: recordType,
		FQDN: fqdn,
		IP:   ip,
	}

	if _, excluded := excludedFQDNs[record.FQDN]; excluded {
		app.clientError(w, http.StatusForbidden, "Deletion of this record is not allowed")
		return
	}
	err := app.bindClient.RemoveRecord(record)
	if err != nil {
		slog.Error("Failed to delete record")
		app.serverError(w, err)
	}
	slog.Info("Successfully deleted a dns record.", "record", record)
	w.WriteHeader(http.StatusOK)
}
