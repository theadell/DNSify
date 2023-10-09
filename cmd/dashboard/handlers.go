package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
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

var excludedFQDNs = map[string]struct{}{
	"rusty-leipzig.com.":     {},
	"ns1.rusty-leipzig.com.": {},
	"ns2.rusty-leipzig.com.": {},
	"www.rusty-leipzig.com.": {},
	"dns.rusty-leipzig.com.": {},
}

func (app *App) IndexHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		app.notFoundHandler(w, r)
		return
	}
	tmpl, _ := app.templateCache["index"]
	tmpl.Execute(w, nil)
}
func (app *App) DashboardHandler(w http.ResponseWriter, r *http.Request) {
	allRecords := app.bindClient.GetRecords()

	var filteredRecords []dnsclient.Record
	for _, record := range allRecords {
		if _, excluded := excludedFQDNs[record.FQDN]; !excluded {
			filteredRecords = append(filteredRecords, record)
		}
	}
	tmpl, ok := app.templateCache["dashboard"]

	if !ok {
		http.Error(w, "template was not found", http.StatusInternalServerError)
		return
	}
	err := tmpl.Execute(w, filteredRecords)
	if err != nil {
		log.Printf("Error executing template: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}

func (app *App) AddRecordHandler(w http.ResponseWriter, r *http.Request) {

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		return
	}

	hostname, ip, ttl, recordType := r.FormValue("hostname"), r.FormValue("ip"), r.FormValue("ttl"), r.FormValue("type")

	if ip == "@" {
		ip = "157.230.106.145"
	}

	if !isValidType(recordType) {
		http.Error(w, "Invalid record type", http.StatusBadRequest)
		return
	}
	if !isValidHostname(hostname) {
		http.Error(w, "Invalid hostname", http.StatusBadRequest)
		return
	}
	if recordType == "A" && !isValidIPv4(ip) || recordType == "AAAA" && !isValidIPv6(ip) {
		http.Error(w, "Invalid IP address", http.StatusBadRequest)
		return
	}
	if !isValidTTL(ttl) {
		http.Error(w, "Invalid ttl", http.StatusBadRequest)
		return
	}

	ttlNum, err := stringToUint(ttl)
	if err != nil {
		http.Error(w, "Invalid ttl", http.StatusBadRequest)
		return
	}

	record := dnsclient.Record{
		Type: recordType,
		FQDN: fmt.Sprintf("%s.%s.", hostname, "rusty-leipzig.com"),
		IP:   ip,
		TTL:  ttlNum,
	}
	if _, excluded := excludedFQDNs[record.FQDN]; excluded {
		http.Error(w, "Addition of this record is not allowed", http.StatusBadRequest)
		return
	}

	err = app.bindClient.AddRecord(record)
	if err != nil {
		slog.Error("Failed to add record", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	tmpl, ok := app.templateCache["record_fragment"]
	if !ok {
		http.Error(w, "Couldn't find fragment", http.StatusInternalServerError)
	}
	if err := tmpl.Execute(w, record); err != nil {
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
	tmpl, _ := app.templateCache["error"]
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
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "No id_token field in oauth2 token."})
		return
	}

	parts := strings.Split(rawIDToken, ".")
	if len(parts) != 3 {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "ID token format is invalid."})
		return
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to decode payload of ID token."})
		return
	}
	var claims struct {
		UPN string `json:"upn"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to decode ID Token claims."})
		return
	}

	ip := getRealIP(r)

	slog.Info("User logged in", "upn", claims.UPN, "ip", ip)
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

	if !isValidFQDN(fqdn) || !isValidIPv4(ip) || !isValidTTL(ttl) {
		http.Error(w, "Invalid input values", http.StatusBadRequest)
		return
	}

	record := dnsclient.Record{
		Type: recordType,
		FQDN: fqdn,
		IP:   ip,
	}

	if _, excluded := excludedFQDNs[record.FQDN]; excluded {
		http.Error(w, "Deletion of this record is not allowed", http.StatusBadRequest)
		return
	}
	err := app.bindClient.RemoveRecord(record)
	if err != nil {
		slog.Error("Failed to delete record", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}
