package main

import (
	"html/template"
	"log"
	"path/filepath"
	"strings"
)

func loadTemplates() map[string]*template.Template {
	cache := make(map[string]*template.Template)

	baseTemplate, err := template.New("base.gohtmltmpl").ParseFiles("./ui/templates/base.gohtmltmpl")
	if err != nil {
		log.Fatal(err)
	}

	fragments, err := filepath.Glob("./ui/templates/fragments/*.gohtmltmpl")
	if err != nil {
		log.Fatal(err)
	}

	for _, fragment := range fragments {
		fragmentName := stripExtension(filepath.Base(fragment))
		fragmentTemplate, err := template.New(fragmentName).ParseFiles(fragment)
		if err != nil {
			log.Fatal(err)
		}
		cache[fragmentName] = fragmentTemplate

		_, err = baseTemplate.New(fragmentName).ParseFiles(fragment)
		if err != nil {
			log.Fatal(err)
		}
	}

	pages, err := filepath.Glob("./ui/templates/pages/*.gohtmltmpl")
	if err != nil {
		log.Fatal(err)
	}

	for _, page := range pages {
		tmpl := template.Must(baseTemplate.Clone())
		pageName := stripExtension(filepath.Base(page))
		_, err := tmpl.New(pageName).ParseFiles(page)
		if err != nil {
			log.Fatal(err)
		}

		cache[pageName] = tmpl
	}

	return cache
}

func stripExtension(filename string) string {
	return strings.TrimSuffix(filename, filepath.Ext(filename))
}
