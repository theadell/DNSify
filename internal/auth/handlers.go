package auth

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"golang.org/x/oauth2"
)

const (
	stateKey               string = "state"
	codeVerifierKey        string = "code_verifier"
	codeChallengeKey       string = "code_challenge"
	codeChallengeMethodKey string = "code_challenge_method"
	codeKey                string = "code"
	idTokenKey             string = "id_token"
	emailKey               string = "email"
	nameKey                string = "name"
	authenticatedKey       string = "authenticated"
	subjectKey             string = "sub"
)

func (idp *Idp) RequestSignIn(w http.ResponseWriter, r *http.Request) {

	state, err := generateSecureRandom(32)
	if err != nil {
		http.Error(w, "Failed to generate state", http.StatusInternalServerError)
	}
	idp.sessionManager.Put(r.Context(), stateKey, state)
	codeVerifier, err := generateSecureRandom(32)
	if err != nil {
		http.Error(w, "Failed to generate code verifier", http.StatusInternalServerError)
		return
	}
	idp.sessionManager.Put(r.Context(), codeVerifierKey, codeVerifier)
	codeChallenge := generateCodeChallenge(codeVerifier)
	url := idp.AuthCodeURL(state, oauth2.SetAuthURLParam(codeChallengeKey, codeChallenge), oauth2.SetAuthURLParam(codeChallengeMethodKey, "S256"))
	http.Redirect(w, r, url, http.StatusSeeOther)
}

func (idp *Idp) HandleSignInCallback(w http.ResponseWriter, r *http.Request) {
	state := idp.sessionManager.GetString(r.Context(), stateKey)
	if state == "" {
		http.Error(w, "No state found in session", http.StatusBadRequest)
		return
	}

	queryState := r.URL.Query().Get(stateKey)

	if state != queryState {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid session state"})
		return
	}

	codeVerifier := idp.sessionManager.GetString(r.Context(), codeVerifierKey)
	if codeVerifier == "" {
		http.Error(w, "No code_verifier was found", http.StatusBadRequest)
		return
	}
	code := r.URL.Query().Get("code")
	token, err := idp.Exchange(r.Context(), code, oauth2.SetAuthURLParam(codeVerifierKey, codeVerifier))

	if err != nil {
		slog.Error("Failed to exchange the authorization code for a token", "Error", err.Error())
		http.Error(w, "Something went wrong!", http.StatusInternalServerError)
		return
	}
	if !token.Valid() {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Token is invalid"})
		return
	}
	idToken, err := decodeToken(token)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to decode ID Token"})
		return
	}
	slog.Info("User logged in", emailKey, idToken.GetString(emailKey), "ip", r.RemoteAddr)
	idp.sessionManager.Put(r.Context(), authenticatedKey, true)
	idp.sessionManager.Put(r.Context(), emailKey, idToken.GetString(emailKey))
	idp.sessionManager.Put(r.Context(), subjectKey, idToken.GetString(subjectKey))
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

func (idp *Idp) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	err := idp.sessionManager.Destroy(r.Context())
	if err != nil {
		slog.Error("Failed to destroy user session", "error", err.Error())
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
