package main

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/theadell/dns-api/ui"
)

func (app *App) Routes() http.Handler {
	r := chi.NewRouter()

	// Middleware
	// r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(app.sessionManager.LoadAndSave)

	// static files
	fs := http.FileServer(http.FS(ui.StatifFS))
	r.Handle("/static/*", fs)

	// Handlers with redirectIfLoggedIn middleware
	r.With(app.redirectIfLoggedIn).HandleFunc("/", app.IndexHandler)
	r.With(app.redirectIfLoggedIn).HandleFunc("/login", app.initiateOAuthProcess)
	r.With(app.redirectIfLoggedIn).HandleFunc("/oauth/callback", app.handleOAuthCallback)

	// Protected Routes
	r.With(app.RequireAuthentication).HandleFunc("/dashboard", app.DashboardHandler)
	r.Route("/records", func(r chi.Router) {
		r.Post("/", app.AddRecordHandler)
		r.Delete("/", app.DeleteRecordHandler)
	})

	// Not found
	r.NotFound(app.notFoundHandler)

	return r
}
