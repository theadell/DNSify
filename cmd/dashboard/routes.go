package main

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/theadell/dnsify/internal/auth"
	"github.com/theadell/dnsify/ui"
)

func (app *App) Routes() http.Handler {
	router := chi.NewRouter()
	router.Use(middleware.Recoverer)
	router.Use(middleware.RealIP)

	// HTML Server
	htmlRouter := chi.NewRouter()
	htmlRouter.Use(auth.SecureHeadersMiddleware)
	htmlRouter.Use(app.sessionManager.LoadAndSave)

	fs := http.FileServer(http.FS(ui.StatifFS))
	htmlRouter.Handle("/static/*", fs)

	// public routes
	htmlRouter.Group(func(r chi.Router) {
		r.Use(app.idp.RedirectIfLoggedIn)
		r.Get("/", app.IndexHandler)
		r.Get("/login", app.idp.RequestSignIn)
		r.Get("/oauth/callback", app.idp.HandleSignInCallback)
	})

	// protected routes
	htmlRouter.Group(func(r chi.Router) {
		r.Use(app.idp.RequireAuthentication)

		r.Post("/logout", app.idp.LogoutHandler)

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

	htmlRouter.NotFound(app.notFoundHandler)

	// JSON Api
	apiRouter := chi.NewRouter()
	apiRouter.Use(auth.APIKeyValidatorMiddleware(app.keyManager))
	testHandler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}
	apiRouter.Get("/", testHandler)

	router.Mount("/", htmlRouter)
	router.Mount("/api", apiRouter)

	return router
}
