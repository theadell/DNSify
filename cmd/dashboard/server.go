package main

import (
	"fmt"
	"log"
	"net/http"
	"time"
)

func (app *App) RunServer() {
	server := http.Server{
		Addr:         fmt.Sprintf("localhost:%d", app.Port),
		Handler:      app.SessionStore.LoadAndSave(app.Routes()),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}

	err := server.ListenAndServe()
	log.Fatal(err)
}
