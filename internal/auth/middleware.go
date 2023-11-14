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

func SecureHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		//TODO: Get rid of unsafe-eval
		csp := "default-src 'self'; " +
			"script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net https://unpkg.com; " + // Allows scripts from the same origin, inline scripts, eval, and specific CDNs
			"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " + // Permits styles from the same origin, inline styles, and Google Fonts
			"img-src 'self' https://images.unsplash.com; " + // Allows images from the same origin and Unsplash
			"font-src 'self' https://fonts.gstatic.com; " + // Enables fonts from the same origin and Google Fonts
			"connect-src 'self'; " + // Limits AJAX, WebSocket, and EventSource to the same origin
			"frame-ancestors 'none'; " + // Prevents the page from being framed (clickjacking protection)
			"form-action 'self'; " + // Restricts where forms can submit to
			"base-uri 'self'; " + // Restricts the base URI for relative URLs
			"object-src 'none';" // Blocks plugins (Flash, Java, etc.)
		w.Header().Set("Content-Security-Policy", csp)

		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "0")

		next.ServeHTTP(w, r)
	})
}
