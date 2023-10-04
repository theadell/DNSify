package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"log/slog"
	"net/http"
	"strings"

	"github.com/theadell/dns-api/internal/dnsclient"
)

const (
	StateKey               string = "state"
	ClientIdKey            string = "client_id"
	CodeVerifierKey        string = "code_verifier"
	CodeChallengeKey       string = "code_challenge"
	CodeChallengeMethodKey string = "code_challenge_method"
	CodeKey                string = "code"
	IdTokenKey             string = "id_token"
	EmailKey               string = "email"
	NameKey                string = "name"
	AuthenticatedKey       string = "authenticated"
	SubjectKey             string = "sub"
	UserIdKey              string = "user_id"
)

func (app *App) IndexHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		app.notFoundHandler(w, r)
		return
	}
	tmpl, _ := app.templateCache["index.gohtmltmpl"]
	tmpl.Execute(w, nil)
}
func (app *App) DashboardHandler(w http.ResponseWriter, r *http.Request) {
	data := app.bindClient.GetRecords()
	tmpl, ok := app.templateCache["dashboard.gohtmltmpl"]

	if !ok {
		http.Error(w, "template was not found", http.StatusInternalServerError)
		return
	}
	tmpl.Execute(w, data)
}

func (app *App) AddRecordHandler(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		return
	}

	hostname := r.FormValue("hostname")
	ip := r.FormValue("ip")
	ttl := r.FormValue("ttl")

	if ip == "@" {
		ip = "157.230.106.145"
	}

	// Validate the form values
	if !isValidHostname(hostname) || !isValidIP(ip) || !isValidTTL(ttl) {
		http.Error(w, "Invalid input values", http.StatusBadRequest)
		return
	}
	record := dnsclient.Record{
		Type: "A",
		FQDN: fmt.Sprintf("%s.%s.", hostname, "rusty-leipzig.com"),
		IP:   ip,
	}

	err = app.bindClient.AddRecord(record)
	if err != nil {
		slog.Error("Failed to add record", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	const tpl = `<tr><td>{{.Type}}</td><td>{{.FQDN}}</td><td>{{.IP}}</td><td>{{.TTL}}</td><td>More</td></tr>`

	// Parse the template
	t, err := template.New("record").Parse(tpl)
	if err != nil {
		log.Fatalf("Error parsing template: %v", err)
	}

	// Execute the template directly to the ResponseWriter
	if err := t.Execute(w, record); err != nil {
		http.Error(w, fmt.Sprintf("Error executing response fragment: %s", err.Error()), http.StatusInternalServerError)
	}

}
func (app *App) SubmitHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		app.AddRecordHandler(w, r)
	case http.MethodDelete:
		app.DeleteRecordHandler(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
}
func (app *App) notFoundHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotFound)
	tmpl, _ := app.templateCache["error.gohtmltmpl"]
	tmpl.Execute(w, nil)
}

func (app *App) initiateOAuthProcess(w http.ResponseWriter, r *http.Request) {

	state, err := GenerateSecureRandom(32)
	if err != nil {
		http.Error(w, "Failed to generate state", http.StatusInternalServerError)
	}
	app.sessionManager.Put(r.Context(), StateKey, state)
	// codeVerifier, err := GenerateSecureRandom(32)
	// if err != nil {
	// 	http.Error(w, "Failed to generate code verifier", http.StatusInternalServerError)
	// 	return
	// }
	// app.SessionStore.Put(r.Context(), CodeVerifierKey, codeVerifier)
	// codeChallenge := GenerateCodeChallenge(codeVerifier)
	// url := app.OauthClient.AuthCodeURL(state, oauth2.SetAuthURLParam(CodeChallengeKey, codeChallenge), oauth2.SetAuthURLParam(CodeChallengeMethodKey, "S256"))
	url := app.oauthClient.AuthCodeURL(state)
	http.Redirect(w, r, url, http.StatusSeeOther)
}

func (app *App) handleOAuthCallback(w http.ResponseWriter, r *http.Request) {

	state := app.sessionManager.GetString(r.Context(), StateKey)

	if state == "" {
		http.Error(w, "No state found in session", http.StatusBadRequest)
		return
	}
	queryState := r.URL.Query().Get(StateKey)

	if state != queryState {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid session state"})
		return
	}

	code := r.URL.Query().Get("code")
	token, err := app.oauthClient.Exchange(r.Context(), code)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to exchange token"})
		return
	}
	if !token.Valid() {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Token is invalid"})
		return
	}
	app.sessionManager.Put(r.Context(), AuthenticatedKey, true)
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

func (app *App) DeleteRecordHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	recordType := strings.TrimSpace(r.URL.Query().Get("Type"))
	fqdn := strings.TrimSpace(r.URL.Query().Get("FQDN"))
	ip := strings.TrimSpace(r.URL.Query().Get("IP"))
	ttl := strings.TrimSpace(r.URL.Query().Get("TTL"))

	if !isValidType(recordType) {
		http.Error(w, "Invalid record type", http.StatusBadRequest)
		return
	}

	if !isValidFQDN(fqdn) || !isValidIP(ip) || !isValidTTL(ttl) {
		http.Error(w, "Invalid input values", http.StatusBadRequest)
		return
	}

	record := dnsclient.Record{
		Type: recordType,
		FQDN: fqdn,
		IP:   ip,
	}

	err := app.bindClient.RemoveRecord(record)
	if err != nil {
		slog.Error("Failed to delete record", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}
