package main

import "net/http"

func (app *App) Routes() http.Handler {
	mux := http.NewServeMux()

	fs := http.FileServer(http.Dir("./ui/static"))
	mux.Handle("/static/", http.StripPrefix("/static/", fs))

	// Handlers
	mux.HandleFunc("/", app.HomeHandler)
	mux.HandleFunc("/records", app.SubmitHandler)
	return mux
}
