package main

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/theadell/dnsify/ui"
)

func (app *App) Routes() http.Handler {
	r := chi.NewRouter()

	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(app.sessionManager.LoadAndSave)

	fs := http.FileServer(http.FS(ui.StatifFS))
	r.Handle("/static/*", fs)

	// public routes
	r.Group(func(r chi.Router) {
		r.Use(app.redirectIfLoggedIn)
		r.Get("/", app.IndexHandler)
		r.Get("/login", app.initiateOAuthProcess)
		r.Get("/oauth/callback", app.handleOAuthCallback)
	})

	// protected routes
	r.Group(func(r chi.Router) {
		r.Use(app.RequireAuthentication)

		r.Post("/logout", app.logoutHandler)

		r.HandleFunc("/status", app.StatusSSEHandler)
		r.Route("/dashboard", func(r chi.Router) {
			r.Get("/", app.DashboardHandler)
			r.Get("/apikeys", app.SettingsHandler)
			r.Post("/apikeys", app.CreateAPIKeyHandler)
			r.Delete("/apikeys/{label}", app.DeleteAPIKeyHandler)
			r.Post("/config/nginx", app.configHandler)
			r.Put("/config/nginx", app.configAdjusterHandler)
		})

		r.Route("/records", func(r chi.Router) {
			r.Get("/", app.GetRecordsHandler)
			r.Post("/", app.AddRecordHandler)
			r.Delete("/", app.DeleteRecordHandler)
		})
	})

	r.NotFound(app.notFoundHandler)

	return r
}
