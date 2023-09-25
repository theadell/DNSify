package main

import (
	"log"
	"net/http"
	"time"
)

func (app *App) RunServer() {
	server := http.Server{
		Addr:         "localhost:8080",
		Handler:      app.Routes(),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}
	err := server.ListenAndServe()
	log.Fatal(err)
}
