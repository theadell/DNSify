package main

import (
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
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

	slog.Info("User logged in", "upn", claims.UPN, "ip", r.RemoteAddr)
	app.sessionManager.Put(r.Context(), AuthenticatedKey, true)
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}
