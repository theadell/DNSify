package main

import (
	"log"
	"net/http"
)

func main() {
	t, err := loadTemplates()
	if err != nil {
		log.Fatal(err)
	}
	templateCache = t
	mux := http.NewServeMux()

	fs := http.FileServer(http.Dir("./ui/static"))
	mux.Handle("/static/", http.StripPrefix("/static/", fs))

	// Handlers
	mux.HandleFunc("/", HomeHandler)
	mux.HandleFunc("/records", SubmitHandler)

	// Start Server
	http.ListenAndServe("localhost:8081", mux)

}
