package main

import (
	"fmt"
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
		fmt.Println(page)
		name := filepath.Base(page)
		fmt.Println(name)
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
