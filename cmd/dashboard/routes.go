package main

import "net/http"

func (app *App) Routes() http.Handler {
	mux := http.NewServeMux()

	fs := http.FileServer(http.Dir("./ui/static"))
	mux.Handle("/static/", http.StripPrefix("/static/", fs))

	// Handlers
	mux.HandleFunc("/", app.redirectIfLoggedIn(app.IndexHandler))
	mux.HandleFunc("/login", app.redirectIfLoggedIn(app.initiateOAuthProcess))
	mux.HandleFunc("/oauth/callback", app.redirectIfLoggedIn(app.handleOAuthCallback))
	// Protected Routes
	mux.Handle("/dashboard", app.RequireAuthentication(http.HandlerFunc(app.DashboardHandler)))
	mux.Handle("/records", app.RequireAuthentication(http.HandlerFunc(app.SubmitHandler)))
	return mux
}
