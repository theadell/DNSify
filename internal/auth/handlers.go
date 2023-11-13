package auth

import (
	"errors"
	"log/slog"
	"net/http"

	"golang.org/x/oauth2"
)

const (
	stateKey               string = "state"
	codeVerifierKey               = "code_verifier"
	codeChallengeKey              = "code_challenge"
	codeChallengeMethodKey        = "code_challenge_method"
	codeChallengeMethod           = "S256"
	codeKey                       = "code"
	idTokenKey                    = "id_token"
	emailKey                      = "email"
	nameKey                       = "name"
	authenticatedKey              = "authenticated"
	subjectKey                    = "sub"
	LoginErrKey                   = "loginError"
	errAccessForTeamOnly          = "Oops! Looks like you're not part of the DNSify squad yet. Company team members can log in here."
	genericLoginErrMsg            = "An error occurred during the login process. Please try again."
)

var (
	errStateNotFound                = errors.New("Missing 'state' parameter in session during OAuth callback.")
	errCodeVerifierNotFound         = errors.New("Missing 'code_verifier' in session during OAuth flow.")
	errStateGenerationFailed        = errors.New("Error generating 'state' parameter for OAuth request.")
	errCodeVerifierGenerationFailed = errors.New("Error generating 'code_verifier' for OAuth process.")
	loginEvt                        = slog.String("event", "user_login")
	loginEvtErr                     = slog.String("event", "user_login_rejected")
)

func (idp *Idp) handleLoginErr(w http.ResponseWriter, r *http.Request, clientMsg string, err error, logAttrs ...slog.Attr) {
	attrs := make([]any, 0, len(logAttrs)+1)
	attrs = append(attrs, loginEvtErr, slog.Any("error", err.Error()))
	for _, attr := range logAttrs {
		attrs = append(attrs, attr)
	}
	slog.ErrorContext(r.Context(), "Authentication event", attrs...)
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
	url := idp.AuthCodeURL(state, oauth2.AccessTypeOnline,
		oauth2.SetAuthURLParam(codeChallengeKey, codeChallenge),
		oauth2.SetAuthURLParam(codeChallengeMethodKey, codeChallengeMethod),
		oauth2.SetAuthURLParam("prompt", "select_account"),
		oauth2.SetAuthURLParam("hd", "*"),
	)
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
	if err := idp.CheckUserAuthorization(userEmail); err != nil {
		idp.handleLoginErr(w, r, errAccessForTeamOnly, err, slog.String(emailKey, userEmail))
		return
	}
	slog.Info("Authentication event", loginEvt, emailKey, userEmail, "ipAddress", r.RemoteAddr)
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
