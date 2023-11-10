package auth

import (
	"net/http"
	"strings"

	"github.com/theadell/dnsify/internal/apikeymanager"
)

func (idp *Idp) RequireAuthentication(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		isAuthenticated := idp.sessionManager.GetBool(r.Context(), authenticatedKey)
		if !isAuthenticated {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (idp *Idp) RedirectIfLoggedIn(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		isAuthenticated := idp.sessionManager.GetBool(r.Context(), authenticatedKey)
		if isAuthenticated {
			referer := "/dashboard"
			http.Redirect(w, r, referer, http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func APIKeyValidatorMiddleware(apiKeyMgr apikeymanager.APIKeyManager) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			parts := strings.SplitN(authHeader, " ", 2)

			if len(parts) != 2 || !strings.EqualFold(parts[0], "ApiKey") {
				http.Error(w, "Invalid or missing API Key", http.StatusUnauthorized)
				return
			}

			apiKey := parts[1]

			if err := apiKeyMgr.ValidateKey(r.Context(), apiKey); err != nil {
				http.Error(w, "Invalid API Key", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
