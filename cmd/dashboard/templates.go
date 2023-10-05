package main

import (
	"embed"
	"html/template"
	"log"
	"path/filepath"
	"strings"
)

func loadTemplates(tmplFS embed.FS) map[string]*template.Template {
	cache := make(map[string]*template.Template)

	baseTemplateContent, err := tmplFS.ReadFile("templates/base.gohtmltmpl")
	if err != nil {
		log.Fatal(err)
	}
	baseTemplate, err := template.New("base.gohtmltmpl").Parse(string(baseTemplateContent))
	if err != nil {
		log.Fatal(err)
	}

	fragments, err := tmplFS.ReadDir("templates/fragments")
	if err != nil {
		log.Fatal(err)
	}
	for _, fragment := range fragments {
		fragmentName := stripExtension(fragment.Name())
		fragmentContent, err := tmplFS.ReadFile("templates/fragments/" + fragment.Name())
		if err != nil {
			log.Fatal(err)
		}
		fragmentTemplate, err := template.New(fragmentName).Parse(string(fragmentContent))
		if err != nil {
			log.Fatal(err)
		}
		cache[fragmentName] = fragmentTemplate

		_, err = baseTemplate.New(fragmentName).Parse(string(fragmentContent))
		if err != nil {
			log.Fatal(err)
		}
	}

	pages, err := tmplFS.ReadDir("templates/pages")
	if err != nil {
		log.Fatal(err)
	}
	for _, page := range pages {
		tmpl := template.Must(baseTemplate.Clone())
		pageName := stripExtension(page.Name())
		pageContent, err := tmplFS.ReadFile("templates/pages/" + page.Name())
		if err != nil {
			log.Fatal(err)
		}
		_, err = tmpl.New(pageName).Parse(string(pageContent))
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
