package main

import "net/http"

func (app *App) Routes() http.Handler {
	mux := http.NewServeMux()

	fs := http.FileServer(http.Dir("./ui/static"))
	mux.Handle("/static/", http.StripPrefix("/static/", fs))

	// Handlers
	mux.HandleFunc("/", app.IndexHandler)
	mux.HandleFunc("/login", app.initiateOAuthProcess)
	mux.HandleFunc("/oauth/callback", app.handleOAuthCallback)
	// Protected Routes
	mux.Handle("/dashboard", app.RequireAuthentication(http.HandlerFunc(app.DashboardHandler)))
	mux.Handle("/records", app.RequireAuthentication(http.HandlerFunc(app.SubmitHandler)))
	return mux
}
