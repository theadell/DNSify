package main

import (
	"html/template"
	"log"
	"path/filepath"
)

func loadTemplates() map[string]*template.Template {
	cache := make(map[string]*template.Template)

	baseTemplatePath := "./ui/templates/base.gohtmltmpl"

	pages, err := filepath.Glob("./ui/templates/pages/*.gohtmltmpl")
	if err != nil {
		log.Fatal(err)
	}

	for _, page := range pages {
		name := filepath.Base(page)
		files := append([]string{baseTemplatePath}) // combine base and partials
		files = append(files, page)                 // add the current page template

		ts, err := template.ParseFiles(files...)
		if err != nil {
			log.Fatal(err)
		}

		cache[name] = ts
	}
	return cache
}
