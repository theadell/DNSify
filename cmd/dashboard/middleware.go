package main

import "net/http"

func (app *App) RequireAuthentication(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		isAuthenticated := app.sessionManager.GetBool(r.Context(), AuthenticatedKey)
		if !isAuthenticated {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	})
}
