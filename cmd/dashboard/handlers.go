package main

import (
	"net/http"

	"github.com/theadell/dns-api/internal/dns"
)

func (app *App) HomeHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		notFoundHandler(w, r)
		return
	}
	data, err := dns.ReadRecords(app.ZoneFilePath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tmpl, ok := templateCache["dashboard.gohtmltmpl"]
	if !ok {
		http.Error(w, "template was not found", http.StatusInternalServerError)
		return
	}
	tmpl.Execute(w, data)
}

func (app *App) SubmitHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(`<tr><td>A</td><td>example.com</td><td>127.0.0.1</td><td>3600</td><td>More</td></tr>`))

}
func notFoundHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotFound)
	tmpl, _ := templateCache["error.gohtmltmpl"]
	tmpl.Execute(w, nil)
}
