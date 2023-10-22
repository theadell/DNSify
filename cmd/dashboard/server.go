package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"
)

func (app *App) RunServer() error {
	app.server = &http.Server{
		Addr:         fmt.Sprintf("%s:%d", app.config.Host, app.config.Port),
		Handler:      app.Routes(),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}

	return app.server.ListenAndServe()
}

func (app *App) GracefulShutdown() {
	// Create a timeout context for the shutdown.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Shutdown the server.
	if err := app.server.Shutdown(ctx); err != nil {
		log.Fatalf("Server Shutdown Failed:%+v", err)
	}

	// Close the DNS client
	app.dnsClient.Close()
}
