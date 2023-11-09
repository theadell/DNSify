package auth

import "net/http"

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
