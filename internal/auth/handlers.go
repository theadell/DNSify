package auth

import (
	"errors"
	"log/slog"
	"net/http"

	"golang.org/x/oauth2"
)

const (
	stateKey               string = "state"
	codeVerifierKey        string = "code_verifier"
	codeChallengeKey       string = "code_challenge"
	codeChallengeMethodKey string = "code_challenge_method"
	codeChallengeMethod    string = "S256"
	codeKey                string = "code"
	idTokenKey             string = "id_token"
	emailKey               string = "email"
	nameKey                string = "name"
	authenticatedKey       string = "authenticated"
	subjectKey             string = "sub"
	LoginErrKey            string = "loginError"
	errAccessForTeamOnly          = "Oops! Looks like you're not part of the DNSify squad yet. Company team members can log in here."
	genericLoginErrMsg            = "An error occurred during the login process. Please try again."
)

var (
	errStateNotFound                = errors.New("Missing 'state' parameter in session during OAuth callback.")
	errCodeVerifierNotFound         = errors.New("Missing 'code_verifier' in session during OAuth flow.")
	errStateGenerationFailed        = errors.New("Error generating 'state' parameter for OAuth request.")
	errCodeVerifierGenerationFailed = errors.New("Error generating 'code_verifier' for OAuth process.")
)

func (idp *Idp) handleLoginErr(w http.ResponseWriter, r *http.Request, clientMsg string, err error, fields ...slog.Attr) {
	if err != nil {

		errorFields := append([]slog.Attr{slog.String("error", err.Error())}, fields...)
		slog.ErrorContext(r.Context(), "OAuth error", errorFields)
	}
	idp.sessionManager.Put(r.Context(), LoginErrKey, clientMsg)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (idp *Idp) RequestSignIn(w http.ResponseWriter, r *http.Request) {

	state, err := generateSecureRandom(32)
	if err != nil {
		idp.handleLoginErr(w, r, genericLoginErrMsg, errors.Join(err, errStateGenerationFailed))
		return
	}
	idp.sessionManager.Put(r.Context(), stateKey, state)
	codeVerifier, err := generateSecureRandom(32)
	if err != nil {
		idp.handleLoginErr(w, r, genericLoginErrMsg, errors.Join(err, errCodeVerifierGenerationFailed))
		return
	}
	idp.sessionManager.Put(r.Context(), codeVerifierKey, codeVerifier)
	codeChallenge := generateCodeChallenge(codeVerifier)
	url := idp.AuthCodeURL(state, oauth2.SetAuthURLParam(codeChallengeKey, codeChallenge), oauth2.SetAuthURLParam(codeChallengeMethodKey, codeChallengeMethod))
	http.Redirect(w, r, url, http.StatusSeeOther)
}

func (idp *Idp) HandleSignInCallback(w http.ResponseWriter, r *http.Request) {
	state := idp.sessionManager.PopString(r.Context(), stateKey)
	if state == "" {
		idp.handleLoginErr(w, r, genericLoginErrMsg, errStateNotFound)
		return
	}

	queryState := r.URL.Query().Get(stateKey)

	if state != queryState {
		idp.handleLoginErr(w, r, genericLoginErrMsg, errors.New("Invalid state"))
		return
	}

	codeVerifier := idp.sessionManager.PopString(r.Context(), codeVerifierKey)
	if codeVerifier == "" {
		idp.handleLoginErr(w, r, genericLoginErrMsg, errCodeVerifierNotFound)
		return
	}
	code := r.URL.Query().Get("code")
	token, err := idp.Exchange(r.Context(), code, oauth2.SetAuthURLParam(codeVerifierKey, codeVerifier))
	if err != nil {
		idp.handleLoginErr(w, r, genericLoginErrMsg, err)
		return
	}
	if !token.Valid() {
		idp.handleLoginErr(w, r, genericLoginErrMsg, errors.New("Invalid OAuth 2.0 Token"))
		return
	}
	idToken, err := decodeToken(token)
	if err != nil {
		idp.handleLoginErr(w, r, genericLoginErrMsg, err)
		return
	}
	userEmail := idToken.GetString(emailKey)
	if !idp.isUserAuthorized(userEmail) {
		idp.handleLoginErr(w, r, errAccessForTeamOnly, errors.New("Authentication Error: user attempted to sign in with unauthorized email"), slog.String("user", userEmail), slog.Any("white list", idp.whiteList))
		return
	}
	slog.Info("User logged in", emailKey, userEmail, "ip", r.RemoteAddr)
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
