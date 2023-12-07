package main

import (
	"log/slog"
	"net/http"
	"slices"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/theadell/dnsify/internal/auth"
	"github.com/theadell/dnsify/internal/dnsservice"
)

func (app *App) IndexHandler(w http.ResponseWriter, r *http.Request) {
	errorMsg := app.sessionManager.PopString(r.Context(), auth.LoginErrKey)

	data := LoginTemplateData{
		LoginPromptData: app.idp.LoginPromptData,
		ErrorMessage:    errorMsg,
	}
	app.render(w, http.StatusOK, "index", data)
}
func (app *App) DashboardHandler(w http.ResponseWriter, r *http.Request) {
	records := app.dnsClient.GetRecords()
	records = slices.DeleteFunc(records, func(r dnsservice.Record) bool {
		return r.Data.RecordType() != "A"
	})
	data := DashboardPageData{
		Zone:    app.dnsClient.GetZone(),
		Records: records,
	}
	app.render(w, http.StatusOK, "dashboard", data)
}
func (app *App) SettingsHandler(w http.ResponseWriter, r *http.Request) {
	user := app.sessionManager.GetString(r.Context(), "email")
	keys, _ := app.keyManager.GetKeys(r.Context(), user)
	app.render(w, http.StatusOK, "apikeys", keys)
}

func (app *App) CreateAPIKeyHandler(w http.ResponseWriter, r *http.Request) {
	label := r.FormValue("label")
	if len(label) < 4 {
		app.clientError(w, http.StatusBadRequest, "Label Must have at least 4 chars")
		return
	}

	user := app.sessionManager.GetString(r.Context(), "email")
	key, err := app.keyManager.CreateKey(r.Context(), user, label)
	if err != nil {
		app.serverError(w, err)
		return
	}
	app.renderTemplateFragment(w, http.StatusOK, "apikeys", "key-row", key)
}
func (app *App) DeleteAPIKeyHandler(w http.ResponseWriter, r *http.Request) {
	keyLabel := chi.URLParam(r, "label")
	if len(keyLabel) < 4 {
		app.clientError(w, http.StatusBadRequest, "Label Must have at least 4 chars")
		return
	}

	user := app.sessionManager.GetString(r.Context(), "email")
	app.keyManager.DeleteKey(r.Context(), user, keyLabel)

	w.WriteHeader(http.StatusOK)
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
	aaaaRecord := app.dnsClient.GetRecordForFQDN(record.Name, "AAAA")
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

func (app *App) GetRecordsHandler(w http.ResponseWriter, r *http.Request) {
	recordType := r.URL.Query().Get("type")
	if !slices.Contains(dnsservice.SupportedTypes, recordType) {
		app.clientError(w, http.StatusBadRequest, "Unsupported record type")
		return
	}
	records := app.dnsClient.GetRecords()
	records = slices.DeleteFunc(records, func(r dnsservice.Record) bool {
		return r.Data.RecordType() != recordType
	})
	app.renderTemplateFragment(w, http.StatusOK, "dashboard", "record-rows", records)
}

func (app *App) AddRecordHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		app.clientError(w, http.StatusBadRequest)
		return
	}
	hostname, value, ttl, recordType := r.FormValue("hostname"), r.FormValue("value"), r.FormValue("ttl"), r.FormValue("type")
	record, err := dnsservice.NewRecordFromRaw(recordType, hostname, value, ttl, app.dnsClient.GetZone())
	if err != nil {
		app.clientError(w, http.StatusBadRequest, err.Error())
		return
	}
	err = app.dnsClient.AddRecord(*record)
	if err != nil {
		handleDNSError(err, w, app)
		return
	}
	app.renderTemplateFragment(w, http.StatusOK, "dashboard", "record-row", &record)
}

func (app *App) notFoundHandler(w http.ResponseWriter, r *http.Request) {
	app.render(w, http.StatusNotFound, "error", nil)
}

func (app *App) DeleteRecordHandler(w http.ResponseWriter, r *http.Request) {
	hostname, value, ttl, recordType := r.FormValue("hostname"), r.FormValue("value"), r.FormValue("ttl"), r.FormValue("type")
	record, err := dnsservice.NewRecordFromRaw(recordType, hostname, value, ttl, app.dnsClient.GetZone())
	if err != nil {
		app.clientError(w, http.StatusBadRequest, err.Error())
		return
	}
	err = app.dnsClient.RemoveRecord(*record)
	if err != nil {
		slog.Error("Failed to delete record")
		handleDNSError(err, w, app)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (app *App) StatusSSEHandler(w http.ResponseWriter, r *http.Request) {
	// Server-Sent Events (SSE) headers as per RFC 8895
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	// event id
	id := 0
	rc := http.NewResponseController(w)
	// Override default timeouts for this long-lived connection.
	noDeadline := time.Time{}
	rc.SetReadDeadline(noDeadline)
	rc.SetWriteDeadline(noDeadline)

	ts, ok := app.templateCache["infobar"]
	if !ok {
		slog.Error("couldn't find the `infobar` template")
		return
	}
	sendUpdate := func() {
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

		id++ // increment the message id
	}

	// Immediately send the current status when a client connects.
	sendUpdate()

	// Periodically send status updates at regular intervals.
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			sendUpdate()
		case <-r.Context().Done():
			return
		}

	}
}
