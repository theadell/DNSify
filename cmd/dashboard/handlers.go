package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/theadell/dnsify/internal/dnsservice"
)

func (app *App) IndexHandler(w http.ResponseWriter, r *http.Request) {
	app.render(w, http.StatusOK, "index", nil)
}
func (app *App) DashboardHandler(w http.ResponseWriter, r *http.Request) {
	records := app.dnsClient.GetRecords()

	app.render(w, http.StatusOK, "dashboard", records)
}

func (app *App) configHandler(w http.ResponseWriter, r *http.Request) {
	hash := r.FormValue("hash")
	if hash == "" {
		app.clientError(w, http.StatusBadRequest, "Invalid or empty record id/hash was submitted")
		return
	}
	record := app.dnsClient.GetRecordByHash(hash)
	if record == nil {
		app.clientError(w, http.StatusBadRequest, "No matching record found")
		return
	}
	aaaaRecord := app.dnsClient.GetRecordForFQDN(record.FQDN, "AAAA")
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

	record := app.dnsClient.GetRecordByHash(hash)
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

	record := dnsservice.NewRecord(recordType, fmt.Sprintf("%s.%s.", hostname, "rusty-leipzig.com"), ip, ttlNum)
	if app.dnsClient.GetRecordByHash(record.Hash) != nil {
		app.clientError(w, http.StatusBadRequest, "Duplication Error", "Record Already Exists")
		return
	}

	// update existing record
	if dr := app.dnsClient.GetRecordByFQDNAndType(record.FQDN, record.Type); dr != nil {
		if app.dnsClient.RemoveRecord(*dr) != nil {
			app.serverError(w, err)
			return
		}

		slog.Info("Successfully deleted DNS record.", "record", record)
		err = app.dnsClient.AddRecord(record)
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

	err = app.dnsClient.AddRecord(record)
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

	record := dnsservice.Record{
		Type: recordType,
		FQDN: fqdn,
		IP:   ip,
	}

	err := app.dnsClient.RemoveRecord(record)
	if err != nil {
		slog.Error("Failed to delete record")
		app.serverError(w, err)
	}
	slog.Info("Successfully deleted a dns record.", "record", record)
	w.WriteHeader(http.StatusOK)
}

func (app *App) StatusSSEHandler(w http.ResponseWriter, r *http.Request) {
	// SSE HEADERS
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	// event id
	id := 0
	rc := http.NewResponseController(w)
	// Avoid connection timeout by setting longer deadline
	rc.SetReadDeadline(time.Now().Add(1 * time.Hour))
	rc.SetWriteDeadline(time.Now().Add(1 * time.Hour))

	ts, ok := app.templateCache["infobar"]
	if !ok {
		slog.Error("couldn't find the `infobar` template")
		return
	}
	for {
		b, err := ConstructSSEMessage(ts, app.dnsClient.HealthCheck(), "message", id)
		if err != nil {
			slog.Error("Failed to execute infobar template", "error", err)
			return
		}
		_, err = w.Write(b)
		if err != nil {
			slog.Error("Failed to write bytes to SSE connection", "error", err)
			return
		}

		// flush data immediately to client
		err = rc.Flush()
		if err != nil {
			slog.Error("Failed to flush data to client", "error", err)
			return
		}
		id++
		time.Sleep(5 * time.Second)
	}
}
